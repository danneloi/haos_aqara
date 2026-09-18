"""Aqara U200 BLE authentication — cloud KDF client.

The Aqara U200 authentication uses a CLOUD-SIDE KDF, not a device-side one.
The lock and the Aqara cloud exchange ephemeral EC keys (SECP256R1); the
cloud computes ECDH + KDF server-side and returns the derived session
material (sessionKey, nonce, verifyData) to the app.

KDF flow (from Frida instrumentation of com.lumiunited.aqarahome.play v6905):
  1. App  → Cloud  POST /dev/bluetooth/login/assure/publickey
                   body: {"deviceId": "<did>"}
                   ← {"cloudPublicKey": "<65-byte hex uncompressed SECP256R1>",
                       "extraId": "lumi.<mac>", "mac": "<mac>"}
  2. App  → Lock   BLE write (char ff07): send cloudPublicKey in 5a-framed
                   fragments (65 bytes, 20-byte BLE packets).
  3. Lock → App    BLE notify (char ff08): lock's ephemeral pubkey in
                   da-framed fragments (65 bytes, uncompressed SECP256R1).
  4. App  → Cloud  POST /dev/bluetooth/login/assure/verify
                   body: {"deviceId": "<did>", "devicePublicKey": "<65-byte hex>"}
                   ← {"sessionKey": "<32 hex chars>",
                       "nonce":       "<26 hex chars>",
                       "verifyData":  "<16 hex chars>",
                       "mac":         "<16 hex chars>"}
  5. App  → Lock   BLE: verifyData proves the session to the lock.
  6. Lock → App    BLE: ack; subsequent data encrypted with AES-CCM
                   (sessionKey / nonce).

Session material shape (values are placeholders — real captures never ship):
    cloudPublicKey  = 04<...>            (65 bytes, uncompressed SECP256R1)
    lockPublicKey   = 04<...>            (65 bytes)
    sessionKey      = <...>              (16 bytes)
    nonce           = <...>              (13 bytes, fixed per session)
    verifyData      = <...>              (8 bytes)
    LTMK            = <...>              (32 bytes, server-side secret)
    Device DID      = matt.<...>
    Lock MAC        = <AA:BB:CC:DD:EE:FF>

Standard HKDF-SHA256 helpers are also exposed for local experimentation
(offline analysis of captured session data).

NOTE: this module is purely observational.  It never writes to the lock.
"""

from __future__ import annotations

import contextlib
import gzip
import json
import os
import secrets
import ssl
import sys
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast
from urllib import error as urlerror
from urllib import request as urlrequest

# Pure cloud crypto lives in cloud_crypto (feature 027): HKDF, the native Sign,
# the RSA login-password envelope and the x-aes128gcm body codec. This module is
# the HTTP client / orchestration layer that uses them.
from .cloud_crypto import (
    Signer,
    aes128gcm_decrypt_body,
    aes128gcm_encrypt_body,
    encrypt_login_password,
    make_local_signer,
)

# ---------------------------------------------------------------------------
# Aqara cloud API client
# ---------------------------------------------------------------------------

# Known region → base URL mapping
# Captured from Frida OkHttp hook (auth4.log, 2026-08-06):
#   rpc-ger.aqara.com → European/German server (area=EU)
# Full URL format: {base_url}/{path}
# Captured example: https://rpc-ger.aqara.com/app/v1.0/lumi/dev/bluetooth/login/assure/publickey
# Probed 2026-08-14 with a real login POST: EU and KR reach Aqara's application
# layer (they answer the `code=` envelope); US and CN answer an nginx HTTP 500,
# so those two inferred hostnames are WRONG or do not serve this path. RU is
# still untested. Do not treat the unverified ones as usable.
REGION_BASE_URLS: dict[str, str] = {
    "EU": "https://rpc-ger.aqara.com/app/v1.0/lumi",  # confirmed from auth4.log
    "US": "https://rpc-us.aqara.com/app/v1.0/lumi",  # WRONG: nginx 500 (2026-08-14)
    "CN": "https://rpc.aqara.com/app/v1.0/lumi",  # WRONG: nginx 500 (2026-08-14)
    "KR": "https://rpc-kr.aqara.com/app/v1.0/lumi",  # reaches the app layer (2026-08-14)
    "RU": "https://rpc-ru.aqara.com/app/v1.0/lumi",  # inferred pattern, untested
}

# API paths (relative; append to base URL)
_PATH_PUBLICKEY = "/dev/bluetooth/login/assure/publickey"
_PATH_VERIFY = "/dev/bluetooth/login/assure/verify"
#: Account device inventory (POST, empty body) → result: {data: [...], totalCount}.
_PATH_DEVICE_LIST = "/dev/query"
#: Offline-password batch fetch → result: {passwd: ["<6-digit code>", ...]}.
#: CONFIRMED BYTE-FOR-BYTE 2026-09-02 (getSignHead + SSL correlated capture,
#: paired by the shared `sign` value): this is a **POST** with a JSON body
#: ``{"did":"<did>"}``, NOT a GET. Using GET (any body shape) was the actual
#: cause of the persistent code=106 "Invalid sign" on this endpoint — the
#: sign was correct, the METHOD was wrong.
_PATH_OFFLINE_PASSWORD = "/dev/bluetooth/lock/passwd"
#: Offline-password issuance history → result: [{createTime, startTime,
#: endTime, did}, ...]. CONFIRMED BYTE-FOR-BYTE 2026-09-02 (same correlated
#: capture): the real path is ``/dev/lock/one/password/log/query`` (NOT
#: ``/dev/bluetooth/lock/password/log/query`` — that old path was wrong), a
#: **GET** whose Sign preimage body is the raw query string
#: ``did=<did>&endTime=<ms>&startTime=<ms>``.
_PATH_OFFLINE_PASSWORD_LOG = "/dev/lock/one/password/log/query"
#: Magic-pair / bluetooth query → result carries ``ltmk`` (the long-term master
#: key). The plugin's ``queryMagicPairInfo`` (``callSmartHomeGet``): a **GET**
#: to ``/dev/bluetooth/query?did=<did>``, so the Sign preimage body is the raw
#: query string ``did=<did>`` (see ``_request_json``).
_PATH_BLUETOOTH_QUERY = "/dev/bluetooth/query"
#: Credential table (users/passwords/fingerprints/NFC), cloud-only, no BLE.
#: PROVEN 2026-09 (docs/protocols/cloud-protocol.md §4.6) -- note the query
#: param is "deviceId", NOT "did" like every other endpoint in this module.
_PATH_LOCK_QUERY = "/dev/lock/query"
_REQUIRED_AUTH_HEADERS = (
    "Lang",
    "Cuty",
    "App-Version",
    "Phone-Model",
    "Sys-Type",
    "Sys-Version",
    "PhoneId",
    "Area",
    "Appid",
    "Appkey",
    "ClientId",
    "UserId",
    "Token",
)


_PATH_LOGIN = "/user/guard-code/login"


def login(
    account: str,
    password: str,
    *,
    appid: str,
    appkey: str,
    client_id: str,
    phone_id: str,
    district: str = "ES",
    region: str = "EU",
    area: str = "EU",
    guard_code: str = "",
    sign_token: str = "",
    user_id: str = "",
) -> dict[str, Any]:
    """Login: credenciales -> token (JWT).

    POST /user/guard-code/login. El body lleva DOBLE cifrado:
      1. `password` = RSA-1024 PKCS#1 v1.5 base64 (encryptType:2).
      2. El body JSON entero -> AES-128-GCM (Content-Encoding: x-aes128gcm),
         con clave = appkey[:16] y nonce = HKDF(salt, appkey).
    Es una peticion NO AUTENTICADA: sin `sign_token` no se envian Token, UserId
    ni Requestid, y el campo `Token=` se OMITE del preimage del Sign (ver
    `make_local_signer` y `compute_sign`).
    `sign_token`/`user_id` se aceptan por si una region exige firmar la peticion
    con una sesion viva.
    Devuelve el dict `result` (incluye el nuevo token) + clave 'token'.

    ESTADO (2026-08-14): FUNCIONA, verificado end-to-end contra el servidor EU
    real -> `code=0` + JWT valido con cuenta+contrasena, sin token previo ni
    movil.  El bug que lo bloqueaba estaba en `encrypt_login_password`: cifraba
    la contrasena EN CRUDO, cuando el plaintext del RSA es MD5(password) en hex
    minuscula (ver esa funcion).  Por eso el servidor contestaba `code=810`
    SIEMPRE -- con cualquier credencial, incluidas las validas -- y ese 810 se
    habia confundido con "envoltorio correcto, contrasena mala" (una cuenta
    inexistente devuelve el mismo 810, asi que no distinguia nada).
    """
    body = {
        "account": account,
        "district": district,
        "encryptType": 2,
        "guardCode": guard_code,
        "password": encrypt_login_password(password),
    }
    base = REGION_BASE_URLS.get(region, REGION_BASE_URLS["EU"])
    signer = make_local_signer(
        appid=appid,
        appkey=appkey,
        token=sign_token,
        user_id=user_id,
        client_id=client_id,
        phone_id=phone_id,
        area=area,
    )
    data = _post_json(
        base + _PATH_LOGIN,
        body,
        None,
        signer=signer,
        path_rel=_PATH_LOGIN,
        encrypt_appkey=appkey,
    )
    result = _unwrap_aqara_result(data, endpoint=_PATH_LOGIN)
    token = None
    if isinstance(result, dict):
        token = result.get("token") or result.get("accessToken") or result.get("loginToken")
    result = dict(result) if isinstance(result, dict) else {"raw": result}
    result["token"] = token
    return result


def build_cloud_auth_headers(
    *,
    lang: str,
    country: str,
    app_version: str,
    phone_model: str,
    time: str,
    sys_type: str,
    sys_version: str,
    nonce: str,
    phone_id: str,
    area: str,
    appid: str,
    appkey: str,
    client_id: str,
    user_id: str,
    token: str,
    request_id: str | None = None,
    sign: str | None = None,
) -> dict[str, str]:
    """Build the exact HTTP auth headers observed in the real Aqara app.

    The log shows the header name `Cuty` (not `Country`), so the builder keeps
    the observed casing to match the captured requests.
    """

    headers = {
        "Lang": lang,
        "Cuty": country,
        "App-Version": app_version,
        "Phone-Model": phone_model,
        "Time": time,
        "Sys-Type": sys_type,
        "Sys-Version": sys_version,
        "Nonce": nonce,
        "PhoneId": phone_id,
        "Area": area,
        "Appid": appid,
        "Appkey": appkey,
        "ClientId": client_id,
        "UserId": user_id,
        "Token": token,
    }
    if request_id:
        headers["Requestid"] = request_id
    if sign:
        headers["Sign"] = sign
    return headers


# Headers that describe THIS Python request's transport and must never be
# replayed from a captured header block: they belong to the original okhttp
# connection (stale Content-Length, gzip negotiation, keep-alive, its Host).
# Leaking them makes the outgoing request self-inconsistent (e.g. a stale
# Content-Length truncates the body, or Accept-Encoding: gzip yields a gzipped
# response that json.loads cannot read).
_TRANSPORT_HEADERS = frozenset(
    h.lower()
    for h in (
        "Content-Length",
        "Host",
        "Connection",
        "Accept-Encoding",
        "Content-Encoding",
        "Transfer-Encoding",
        "User-Agent",
    )
)

# Transport security (feature 006). Cloud calls carry the material that opens a
# physical door, so certificates are verified by default. The opt-out exists for
# machines whose CA store is unusable (a fresh macOS Python install); it is an
# environment switch, never a parameter, so no call site can hard-code it.
_INSECURE_TLS_ENV = "U200_INSECURE_TLS"
# Fail-safe parsing: only these disable verification. A typo keeps it enabled.
_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes", "on"})


def _tls_context() -> ssl.SSLContext:
    """Build the TLS context for a cloud request.

    Verifies the certificate chain against the platform trust store and checks
    the hostname. Setting ``U200_INSECURE_TLS`` to ``1``/``true``/``yes``/``on``
    disables both and prints a warning — it removes protection against
    machine-in-the-middle interception and must never be used on an untrusted
    network.
    """

    context = ssl.create_default_context()
    if os.environ.get(_INSECURE_TLS_ENV, "").strip().lower() in _TRUTHY_ENV_VALUES:
        print(
            f"[U200] WARNING: TLS certificate verification is DISABLED "
            f"({_INSECURE_TLS_ENV}); this connection is not protected against "
            f"interception.",
            file=sys.stderr,
        )
        # Order matters: CPython rejects CERT_NONE while check_hostname is on.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


#: Headers never printed in the clear by the U200_DEBUG request log — they're
#: the request's actual authentication material, not useful for wire-shape
#: comparison against a live capture (Constitution I: no secret ever logged).
_SENSITIVE_DEBUG_HEADERS = frozenset({"sign", "token"})


def _request_json(
    method: str,
    url: str,
    payload: Mapping[str, Any] | None,
    auth_headers: Mapping[str, str] | None = None,
    timeout: float = 10,
    signer: Signer | None = None,
    path_rel: str | None = None,
    encrypt_appkey: str | None = None,
) -> dict[str, Any]:
    """Issue a signed Aqara cloud request. Shared by ``_post_json`` (POST,
    the historical name) and the GET-based endpoints (feature 038).

    What goes into the Sign preimage's body slot depends on WHERE the
    request's data actually lives, not on the HTTP method:

    - URL has a `?query`: CONFIRMED 2026-09-01 via a live-captured real
      Sign (native SSL hook + HTTP/2 HPACK decode of the app's own
      `GET .../position/device/query?positionId=...`, see
      docs/devices/u200/operations.md) — the preimage's body slot is the
      URL's raw query string (no leading `?`), and no bytes are sent on
      the wire as a body at all. Feeding that string into `compute_sign()`
      reproduced the app's real Sign byte-for-byte; feeding `""` (the
      original assumption) did not.
    - No query string, but a JSON `payload`: CONFIRMED 2026-08-31 via a
      live capture of a real, server-ACCEPTED
      `GET /dev/bluetooth/lock/passwd` request with body
      `{"did":"matt...."}` (see the same operations.md doc, "T018/T019
      live verification") — here the JSON body IS the wire body AND the
      Sign preimage's body slot. Do not special-case this away by method;
      an earlier same-night edit briefly assumed "GET never has a JSON
      body," which is false for this endpoint specifically and broke it
      (see cloud-signing-broken-2026-09-01 memory).
    - Neither: empty body slot, no bytes sent (e.g. `POST /dev/query`).
    """
    if "?" in url:
        body_str = url.split("?", 1)[1]
        data = None
    else:
        # Serialize compactly (no spaces) so the body matches the exact bytes
        # the Aqara app signs/sends; okhttp+gson emit `{"deviceId":"..."}`
        # with no space.
        body_str = json.dumps(payload, separators=(",", ":")) if payload else ""
        # El Sign SIEMPRE se calcula sobre el PLAINTEXT (body_str), aunque el
        # cuerpo viaje cifrado. Con cifrado x-aes128gcm se envia el BLOB pero
        # se firma el claro. Un body vacio no manda ni siquiera "{}".
        if not body_str:
            data = None
        elif encrypt_appkey is not None:
            data = aes128gcm_encrypt_body(body_str.encode("utf-8"), encrypt_appkey).encode("utf-8")
        else:
            data = body_str.encode("utf-8")
    if signer is not None:
        # El firmante devuelve cabeceras YA firmadas sobre el cuerpo en claro. El
        # Sign NO cubre la URL (solo cabeceras+body en claro).
        prepared = dict(signer(path_rel, body_str))
    else:
        if auth_headers is None:
            raise RuntimeError("_request_json necesita auth_headers o signer")
        prepared = prepare_runtime_cloud_auth_headers(auth_headers)
    request_headers = {
        key: value for key, value in prepared.items() if key.lower() not in _TRANSPORT_HEADERS
    }
    request_headers.setdefault("Accept", "application/json")
    if data is not None:
        request_headers.setdefault("Content-Type", "application/json; charset=utf-8")
    if encrypt_appkey is not None and data is not None:
        # Cuerpo cifrado: negociamos el mismo codec para peticion y respuesta.
        request_headers["Content-Encoding"] = "x-aes128gcm"
        request_headers["Accept-Encoding"] = "x-aes128gcm"
    else:
        # Ask for an unencoded body so response.read() is plain UTF-8 JSON; we
        # still gunzip defensively below in case the server ignores this.
        request_headers["Accept-Encoding"] = "identity"
    request = urlrequest.Request(url, data=data, headers=request_headers, method=method)
    if os.environ.get("U200_DEBUG"):
        redacted = {
            k: ("<redacted>" if k.lower() in _SENSITIVE_DEBUG_HEADERS else v)
            for k, v in request_headers.items()
        }
        print(f"[U200] {method} {url}", file=sys.stderr)
        print(f"[U200]   headers: {redacted}", file=sys.stderr)
    try:
        ssl_context = _tls_context()
        with urlrequest.urlopen(request, timeout=timeout, context=ssl_context) as response:
            raw = response.read()
            enc = response.headers.get("Content-Encoding", "").lower()
            if enc == "gzip":
                raw = gzip.decompress(raw)
                body = raw.decode("utf-8")
            elif enc == "x-aes128gcm" and encrypt_appkey is not None:
                body = aes128gcm_decrypt_body(raw.decode("ascii"), encrypt_appkey).decode("utf-8")
            else:
                body = raw.decode("utf-8")
    except urlerror.HTTPError as exc:
        raw = exc.read()
        enc = exc.headers.get("Content-Encoding", "").lower()
        if enc == "gzip":
            with contextlib.suppress(OSError):
                raw = gzip.decompress(raw)
            body = raw.decode("utf-8", "replace")
        elif enc == "x-aes128gcm" and encrypt_appkey is not None:
            try:
                body = aes128gcm_decrypt_body(raw.decode("ascii"), encrypt_appkey).decode("utf-8")
            except Exception:
                body = raw.decode("utf-8", "replace")
        else:
            body = raw.decode("utf-8", "replace")
        raise RuntimeError(f"{url} returned HTTP {exc.code}: {body[:200]}") from exc
    except urlerror.URLError as exc:
        # urlopen wraps a certificate failure in URLError.reason. Say what failed
        # and what the deliberate override is, instead of a bare ssl traceback.
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            raise RuntimeError(
                f"TLS certificate verification failed for {url}: {exc.reason}. "
                f"Either this machine's trust store is misconfigured or the "
                f"connection is being intercepted. If you accept the risk, set "
                f"{_INSECURE_TLS_ENV}=1 to skip verification."
            ) from exc
        raise RuntimeError(f"failed to contact {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise RuntimeError(f"timeout contacting {url}") from exc

    try:
        result = json.loads(body)
        if os.environ.get("U200_DEBUG"):
            print(f"[U200] {url} -> {result}", file=sys.stderr)
        return cast("dict[str, Any]", result)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{url} returned invalid JSON: {body[:200]}") from exc


def _post_json(
    url: str,
    payload: Mapping[str, Any],
    auth_headers: Mapping[str, str] | None = None,
    timeout: float = 10,
    signer: Signer | None = None,
    path_rel: str | None = None,
    encrypt_appkey: str | None = None,
) -> dict[str, Any]:
    """POST variant of :func:`_request_json` — kept as the historical name
    every existing call site already uses; behavior is unchanged.
    """
    return _request_json(
        "POST",
        url,
        payload,
        auth_headers,
        timeout,
        signer,
        path_rel,
        encrypt_appkey,
    )


class CloudServiceError(RuntimeError):
    """The Aqara cloud answered HTTP 200 with a non-zero service ``code``.

    Subclass of :class:`RuntimeError` so existing ``except RuntimeError`` handlers
    keep working; carries the parsed ``code`` so callers can branch on it (e.g.
    108 = token expired/renewable, 810 = wrong password / unregistered account)
    without parsing the message string.
    """

    def __init__(
        self,
        *,
        code: int | str,
        message: str | None,
        endpoint: str,
        details: Any = None,
    ) -> None:
        self.code = code
        self.message = message
        self.endpoint = endpoint
        self.details = details
        super().__init__(
            f"{endpoint} rejected by Aqara cloud: code={code} message={message} details={details}"
        )

    def is_code(self, value: int) -> bool:
        """True if this error's ``code`` equals ``value`` (int or str form)."""
        try:
            return int(self.code) == value
        except (TypeError, ValueError):
            return str(self.code) == str(value)


def _unwrap_aqara_result(payload: dict[str, Any], *, endpoint: str) -> dict[str, Any]:
    code = payload.get("code")
    if "code" in payload and code not in (0, "0", None):
        assert code is not None  # narrowed by the membership check above
        raise CloudServiceError(
            code=code,
            message=payload.get("message"),
            endpoint=endpoint,
            details=payload.get("msgDetails"),
        )
    result = payload.get("result")
    if isinstance(result, dict):
        return result
    return payload


def prepare_runtime_cloud_auth_headers(auth_headers: Mapping[str, str]) -> dict[str, str]:
    prepared = dict(auth_headers)
    has_sign = bool(prepared.get("Sign", "").strip())
    required_headers = tuple(
        key for key in _REQUIRED_AUTH_HEADERS if not (has_sign and key == "Appkey")
    )
    missing = [key for key in required_headers if not prepared.get(key)]
    if missing:
        raise RuntimeError(
            "Faltan cabeceras de auth obligatorias para Aqara cloud: " + ", ".join(missing)
        )
    placeholder_keys = []
    for key in ("Token", "Authorization", "Appid", "Appkey", "ClientId", "UserId"):
        if key not in prepared:
            continue
        if prepared.get(key, "").strip() in {"", "******", "REPLACE_ME", "<token>"}:
            placeholder_keys.append(key)
    if placeholder_keys:
        raise RuntimeError(
            "Cabeceras con valores de marcador detectadas. "
            f"Actualiza estos campos con valores reales capturados: {', '.join(placeholder_keys)}"
        )

    if has_sign:
        # Si llega una firma capturada, hay que mantener el mismo Time/Nonce/Requestid
        # para no invalidarla.
        for key in ("Time", "Nonce"):
            if not prepared.get(key):
                raise RuntimeError(
                    f"El header firmado incluye Sign pero falta {key}; no se puede reutilizar."
                )
    else:
        # Sin firma, renovamos campos volátiles para flujos donde el backend no la exige.
        prepared["Time"] = str(int(time.time() * 1000))
        prepared["Nonce"] = secrets.token_hex(16).upper()
        prepared["Requestid"] = str(uuid.uuid4())
    return prepared


def cloud_get_public_key(
    device_id: str,
    auth_headers: Mapping[str, str] | None,
    base_url: str,
    signer: Signer | None = None,
) -> str:
    """Step 1 of BLE auth: ask the cloud for an ephemeral EC public key.

    Args:
        device_id:    Lock DID, e.g. "matt.<...>".
        auth_headers: HTTP headers that authenticate the request to Aqara
                      cloud.  Build them from a real capture with
                      build_cloud_auth_headers().
        base_url:     Region base URL, e.g. REGION_BASE_URLS["EU"].

    Returns:
        cloudPublicKey as a hex string (130 hex chars, uncompressed SECP256R1,
        starting with "04").

    Raises:
        RuntimeError: if the cloud returns a non-200 status or missing key.
    """
    data = _post_json(
        f"{base_url}{_PATH_PUBLICKEY}",
        {"deviceId": device_id},
        auth_headers,
        signer=signer,
        path_rel=_PATH_PUBLICKEY,
    )

    unwrapped = _unwrap_aqara_result(data, endpoint=_PATH_PUBLICKEY)
    cloud_pub = unwrapped.get("cloudPublicKey") if isinstance(unwrapped, dict) else None
    if not cloud_pub:
        raise RuntimeError(f"No cloudPublicKey in response: {data}")
    return cast("str", cloud_pub)


def cloud_list_devices(
    auth_headers: Mapping[str, str] | None,
    base_url: str,
    signer: Signer | None = None,
) -> list[dict[str, Any]]:
    """List the account's devices (``POST /dev/query``).

    Returns the raw device dicts (``result.data``); each carries ``deviceId``
    (the ``matt.<...>`` DID), ``model``, ``name``, ``positionId``, etc. The DID is
    the value the BLE auth flow needs, so this is how a consumer resolves the lock
    from just an account + password — no manually supplied device id.
    """
    data = _post_json(
        f"{base_url}{_PATH_DEVICE_LIST}",
        {},
        auth_headers,
        signer=signer,
        path_rel=_PATH_DEVICE_LIST,
    )
    result = _unwrap_aqara_result(data, endpoint=_PATH_DEVICE_LIST)
    if isinstance(result, dict):
        devices = result.get("data")
        if isinstance(devices, list):
            return [d for d in devices if isinstance(d, dict)]
    return []


def cloud_device_mac(
    device_id: str,
    auth_headers: Mapping[str, str] | None,
    base_url: str,
    signer: Signer | None = None,
) -> str:
    """Return the lock's MAC for ``device_id`` (from the publickey response).

    Used to disambiguate when an account has more than one lock: match this
    against the MAC discovered over BLE.
    """
    data = _post_json(
        f"{base_url}{_PATH_PUBLICKEY}",
        {"deviceId": device_id},
        auth_headers,
        signer=signer,
        path_rel=_PATH_PUBLICKEY,
    )
    unwrapped = _unwrap_aqara_result(data, endpoint=_PATH_PUBLICKEY)
    mac = unwrapped.get("mac") if isinstance(unwrapped, dict) else None
    return cast("str", mac) if mac else ""


def cloud_verify(
    device_id: str,
    device_public_key_hex: str,
    auth_headers: Mapping[str, str] | None,
    base_url: str,
    signer: Signer | None = None,
) -> dict[str, str]:
    """Step 4 of BLE auth: send the lock's pubkey; receive session material.

    Args:
        device_id:             Lock DID.
        device_public_key_hex: Lock's ephemeral EC public key (130 hex chars,
                               uncompressed SECP256R1, starting with "04").
                               Captured from BLE da-framed notify packets.
        auth_headers:          Same auth headers as cloud_get_public_key.
        base_url:              Region base URL.

    Returns:
        Dict with keys:
          "sessionKey"  — 16-byte hex string (AES-128 key for AES-CCM)
          "nonce"       — 13-byte hex string (AES-CCM nonce)
          "verifyData"  — 8-byte hex string (sent to lock to prove session)
          "mac"         — 8-byte hex string (lock MAC bytes, little-endian)

    Raises:
        RuntimeError: on HTTP error or missing fields.
    """
    data = _post_json(
        f"{base_url}{_PATH_VERIFY}",
        {
            "deviceId": device_id,
            "devicePublicKey": device_public_key_hex,
        },
        auth_headers,
        signer=signer,
        path_rel=_PATH_VERIFY,
    )
    result: dict[str, Any] = _unwrap_aqara_result(data, endpoint=_PATH_VERIFY)
    for field in ("sessionKey", "nonce", "verifyData"):
        if field not in result:
            raise RuntimeError(f"Missing '{field}' in verify response: {data}")
    return {
        "sessionKey": result["sessionKey"],
        "nonce": result["nonce"],
        "verifyData": result["verifyData"],
        "mac": result.get("mac", ""),
    }


def get_session_material(
    device_id: str,
    device_public_key_hex: str,
    auth_headers: Mapping[str, str] | None = None,
    *,
    region: str = "EU",
    base_url: str | None = None,
    signer: Signer | None = None,
) -> dict[str, str]:
    """Convenience wrapper for step 4 only (caller already has cloudPublicKey).

    This is the typical call after BLE key exchange is complete:
      - cloud gave you cloudPublicKey (step 1)
      - you sent it to the lock (step 2)
      - the lock responded with its pubkey (step 3)
      - call this function with the lock's pubkey → get session material

    Args:
        device_id:             Lock DID.
        device_public_key_hex: Lock's ephemeral EC public key from BLE.
        auth_headers:          Aqara cloud auth headers built from a captured
                               runtime request.
        region:                Region code ("EU", "US", "CN", …).
        base_url:              Override base URL; inferred from region if None.

    Returns:
        Dict with sessionKey, nonce, verifyData, mac (all hex strings).
    """
    url = base_url or REGION_BASE_URLS.get(region, REGION_BASE_URLS["EU"])
    return cloud_verify(device_id, device_public_key_hex, auth_headers, url, signer=signer)


# ---------------------------------------------------------------------------
# Offline password ("Contraseña sin conexión") — feature 038
# ---------------------------------------------------------------------------
#
# Three sessions of RE assumed this 6-digit one-time code was computed
# LOCALLY on the phone from a per-lock seed (the patent's Hash(seed, period)
# design). It is not: the Aqara cloud pre-generates a batch of codes per
# 10-minute UTC-epoch-aligned window and the app just fetches them over
# HTTPS — confirmed live 2026-08-30 (the server's response contained the
# exact codes the app displayed). See docs/devices/u200/operations.md,
# section "2026-08-30 (resolved)", for the full evidence trail.
#
# No new crypto: compute_sign()/make_local_signer() already sign
# appid/nonce/time/token/body/appkey — never the HTTP method or path — so an
# empty-body GET signs with the exact same call already used for POSTs.


@dataclass(frozen=True)
class OfflinePasswordBatch:
    """The offline-password codes pending for the *current* 10-minute window.

    ``codes`` comes straight from the server's ``result.passwd`` — never
    convert to ``int`` (a code may have a leading zero). ``window_start_ms``/
    ``window_end_ms`` are NOT part of that response: they are derived
    locally as ``floor(now_ms / 600_000) * 600_000`` / ``+ 600_000``, a rule
    confirmed by evidence (three independent samples' server-reported
    startTime/endTime were exact multiples of 600000ms) but not literally
    present in this particular response — see research.md Decision 4.
    """

    codes: tuple[str, ...]
    window_start_ms: int
    window_end_ms: int


@dataclass(frozen=True)
class OfflinePasswordLogEntry:
    """One already-issued offline-password record, exactly as the server's
    history endpoint reports it — no derived fields here.
    """

    create_time_ms: int
    start_time_ms: int
    end_time_ms: int
    device_id: str


def fetch_offline_passwords(
    device_id: str,
    auth_headers: Mapping[str, str] | None,
    base_url: str,
    signer: Signer | None = None,
    *,
    _now_ms: Any = None,
) -> OfflinePasswordBatch:
    """Fetch the offline-password codes pending for the lock's current
    10-minute window (``POST /dev/bluetooth/lock/passwd``) — no BLE
    connection to the lock at any point, this is a pure cloud call.

    Args:
        device_id: Lock DID (``matt.<...>``). Rides as a JSON request
            **body**, ``{"did": "<device_id>"}``, on a **POST** — confirmed
            byte-for-byte 2026-09-02 by a getSignHead+SSL correlated capture
            paired on the shared ``sign`` value (see the
            cloud-signing-broken-2026-09-01 memory). The persistent
            ``code=106`` before this was NOT a sign bug (compute_sign is
            byte-perfect vs the app's real getSignHead) — it was this call
            using GET instead of POST.
        auth_headers: Same auth headers as the rest of this module's cloud
            calls.
        base_url: Region base URL, e.g. ``REGION_BASE_URLS["EU"]``.
        signer: Optional local signer (see ``make_local_signer``).
        _now_ms: Test-only hook to inject the current time; defaults to the
            real wall clock.

    Raises:
        CloudServiceError: the cloud answered with a non-zero ``code``.
    """
    data = _request_json(
        "POST",
        f"{base_url}{_PATH_OFFLINE_PASSWORD}",
        {"did": device_id},
        auth_headers,
        signer=signer,
        path_rel=_PATH_OFFLINE_PASSWORD,
    )
    result = _unwrap_aqara_result(data, endpoint=_PATH_OFFLINE_PASSWORD)
    codes_raw = result.get("passwd", []) if isinstance(result, dict) else []
    codes = tuple(str(c) for c in codes_raw) if isinstance(codes_raw, list) else ()

    now_ms = _now_ms() if _now_ms is not None else int(time.time() * 1000)
    window_start_ms = (now_ms // 600_000) * 600_000
    window_end_ms = window_start_ms + 600_000
    return OfflinePasswordBatch(
        codes=codes,
        window_start_ms=window_start_ms,
        window_end_ms=window_end_ms,
    )


def fetch_ltmk(
    device_id: str,
    auth_headers: Mapping[str, str] | None,
    base_url: str,
    signer: Signer | None = None,
) -> bytes:
    """Fetch the lock's LTMK (long-term master key) from the owner's cloud
    (``GET /dev/bluetooth/query?did=<did>`` — the plugin's
    ``queryMagicPairInfo``) — no BLE connection, a pure cloud call.

    The LTMK is the 32-byte secret the lock and cloud share. With it, session
    keys derive OFFLINE (``offline_login.derive_session_material``), so the BLE
    control channel no longer needs a per-operation cloud round-trip. This reads
    the owner's own device credential from the owner's own Aqara account.

    The Sign preimage body is the raw query string ``did=<did>`` (GET; see
    ``_request_json``). Returns the raw LTMK bytes (>= 32 bytes).

    Raises:
        CloudServiceError: the cloud answered with a non-zero ``code``.
        ValueError: the response carried no usable ``ltmk``.
    """
    query = f"did={device_id}"
    data = _request_json(
        "GET",
        f"{base_url}{_PATH_BLUETOOTH_QUERY}?{query}",
        None,
        auth_headers,
        signer=signer,
        path_rel=_PATH_BLUETOOTH_QUERY,
    )
    result = _unwrap_aqara_result(data, endpoint=_PATH_BLUETOOTH_QUERY)
    ltmk_hex = result.get("ltmk") if isinstance(result, dict) else None
    if not ltmk_hex or not isinstance(ltmk_hex, str):
        raise ValueError("no 'ltmk' in /dev/bluetooth/query response")
    try:
        ltmk = bytes.fromhex(ltmk_hex)
    except ValueError as exc:
        raise ValueError(f"malformed 'ltmk' hex ({len(ltmk_hex)} chars)") from exc
    if len(ltmk) < 32:
        raise ValueError(f"ltmk too short: {len(ltmk)} bytes (need >= 32)")
    return ltmk


def fetch_offline_password_log(
    device_id: str,
    start_time_ms: int,
    end_time_ms: int,
    auth_headers: Mapping[str, str] | None,
    base_url: str,
    signer: Signer | None = None,
) -> tuple[OfflinePasswordLogEntry, ...]:
    """Fetch the offline-password issuance history for ``device_id`` between
    ``start_time_ms`` and ``end_time_ms`` (``GET .../password/log/query``) —
    no BLE connection, pure cloud call.

    Entries missing any of the four required fields are dropped silently
    (never invented) rather than failing the whole call.

    CONFIRMED BYTE-FOR-BYTE 2026-09-02 (getSignHead+SSL correlated capture,
    paired on the shared ``sign`` value): this is a **GET** to
    ``/dev/lock/one/password/log/query`` whose Sign preimage body is the
    raw query string ``did=<did>&endTime=<ms>&startTime=<ms>`` (that exact
    key order), with the same query string on the URL. Earlier confusion
    (JSON body; the ``/dev/bluetooth/lock/...`` path) is superseded — both
    were wrong, see the cloud-signing-broken-2026-09-01 memory.

    Raises:
        CloudServiceError: the cloud answered with a non-zero ``code``.
    """
    # Order matters: the app signs did, then endTime, then startTime.
    query = f"did={device_id}&endTime={int(end_time_ms)}&startTime={int(start_time_ms)}"
    data = _request_json(
        "GET",
        f"{base_url}{_PATH_OFFLINE_PASSWORD_LOG}?{query}",
        None,
        auth_headers,
        signer=signer,
        path_rel=_PATH_OFFLINE_PASSWORD_LOG,
    )
    # _unwrap_aqara_result only special-cases a dict `result`; this
    # endpoint's `result` is a list, so read it directly from the raw payload.
    code = data.get("code")
    if "code" in data and code not in (0, "0", None):
        raise CloudServiceError(
            code=code,
            message=data.get("message"),
            endpoint=_PATH_OFFLINE_PASSWORD_LOG,
            details=data.get("msgDetails"),
        )
    raw_entries = data.get("result", [])
    entries: list[OfflinePasswordLogEntry] = []
    if isinstance(raw_entries, list):
        for item in raw_entries:
            if not isinstance(item, dict):
                continue
            try:
                entries.append(
                    OfflinePasswordLogEntry(
                        create_time_ms=int(item["createTime"]),
                        start_time_ms=int(item["startTime"]),
                        end_time_ms=int(item["endTime"]),
                        device_id=str(item["did"]),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue  # incomplete/malformed entry — drop, don't invent
    return tuple(entries)


@dataclass(frozen=True)
class LockCredential:
    """One row of the lock's cloud-side credential table, exactly as
    ``GET /dev/lock/query`` reports it -- no derived fields here (a
    consumer decides how to correlate ``user_code`` against a BLE-side
    slot/user id; see aqara_ble's access_log module and its docs).
    """

    group_name: str  # the person's own display name, e.g. "Mom" — PII, never logged
    type: int  # 1=fingerprint, 2=password, 3=NFC, 4=key, 6=face
    type_name: str  # the credential's own label, e.g. "Fingerprint 1"
    type_value: str  # credential id
    user_code: str  # the slot/user code
    valid_range: Any  # validity window, shape as returned by the server


def fetch_lock_credentials(
    device_id: str,
    auth_headers: Mapping[str, str] | None,
    base_url: str,
    signer: Signer | None = None,
) -> tuple[LockCredential, ...]:
    """Fetch the lock's full credential table from the cloud -- users,
    passwords, fingerprints, NFC -- with **no BLE connection and no keypad
    touch** (``GET /dev/lock/query?deviceId=<did>`` — note ``deviceId``, not
    ``did``, unlike every other endpoint in this module).

    PROVEN 2026-09 (docs/protocols/cloud-protocol.md §4.6): verified live
    (code=0), returning the owner's own password/fingerprint/NFC entries and
    a test password the library itself had written over BLE — cross-
    confirming both the read and an earlier write. The response never
    carries a PIN's plaintext, only credential metadata.

    Returns credential ROWS, not a name mapping — each row's
    ``group_name`` is a real person's display name as entered in the Aqara
    app. Callers must treat that as sensitive: never log it, never persist
    it into source-controlled files, only into runtime storage the caller
    controls (see this project's own Home Assistant integration for the
    pattern).

    Raises:
        CloudServiceError: the cloud answered with a non-zero ``code``.
    """
    query = f"deviceId={device_id}"
    data = _request_json(
        "GET",
        f"{base_url}{_PATH_LOCK_QUERY}?{query}",
        None,
        auth_headers,
        signer=signer,
        path_rel=_PATH_LOCK_QUERY,
    )
    code = data.get("code")
    if "code" in data and code not in (0, "0", None):
        raise CloudServiceError(
            code=code,
            message=data.get("message"),
            endpoint=_PATH_LOCK_QUERY,
            details=data.get("msgDetails"),
        )
    raw_rows = data.get("result", [])
    rows: list[LockCredential] = []
    if isinstance(raw_rows, list):
        for item in raw_rows:
            if not isinstance(item, dict):
                continue
            try:
                rows.append(
                    LockCredential(
                        group_name=str(item["typeGroupName"]),
                        type=int(item["type"]),
                        type_name=str(item.get("typeName", "")),
                        type_value=str(item.get("typeValue", "")),
                        user_code=str(item.get("userCode", "")),
                        valid_range=item.get("validRange"),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue  # incomplete/malformed row — drop, don't invent
    return tuple(rows)


# The auth header map is intentionally caller-provided.  Use
# build_cloud_auth_headers() to materialize the exact key casing from a capture
# and keep user-specific values (token, sign, request id) out of source.
