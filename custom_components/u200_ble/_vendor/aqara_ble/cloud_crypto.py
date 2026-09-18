"""Pure cloud crypto for the Aqara account/BLE login — no network I/O.

Extracted from ``kdf.py`` (feature 027) so the byte-exact cryptography lives
apart from the HTTP client: HKDF-SHA256, the native request ``Sign`` derivation,
the RSA-1024 login-password envelope, and the ``x-aes128gcm`` body codec. These
functions are deterministic (except where they draw fresh randomness) and never
touch the network, so they are unit-testable without any transport fake.

``kdf.py`` imports what it needs from here; nothing here imports ``kdf`` (or any
other package module), keeping this a leaf of the cloud layer.

Constitution Principle II — protocol fidelity: every value and algorithm here is
byte-identical to the pre-split ``kdf.py`` implementation and MUST stay so.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import uuid
from collections.abc import Callable, Mapping

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as _pad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_der_public_key

# A cloud request signer: (relative path, plaintext body) -> signed HTTP headers.
Signer = Callable[[str | None, str], Mapping[str, str]]

# ---------------------------------------------------------------------------
# HKDF-SHA256 primitives
# ---------------------------------------------------------------------------


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract using SHA-256."""

    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand using SHA-256."""

    if length <= 0:
        raise ValueError("length must be positive")
    digest_size = hashlib.sha256().digest_size
    if length > 255 * digest_size:
        raise ValueError("length too large for HKDF-SHA256")

    okm = bytearray()
    previous_block = b""
    counter = 1
    while len(okm) < length:
        previous_block = hmac.new(
            prk,
            previous_block + info + bytes((counter,)),
            hashlib.sha256,
        ).digest()
        okm.extend(previous_block)
        counter += 1
    return bytes(okm[:length])


def hkdf_sha256(
    ikm: bytes,
    salt: bytes = b"",
    info: bytes = b"",
    length: int = 32,
) -> bytes:
    """Convenience wrapper around HKDF-Extract and HKDF-Expand."""

    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


# ---------------------------------------------------------------------------
# Sign nativo reimplementado (autonomo, sin app/movil)
# ---------------------------------------------------------------------------
#
# Reverseado de com.lumi.external.http...DefaultInterceptorStrategy.assemblyHeaderSign
# + captura del input EXACTO al MD5 dentro de LumiDevSDK.getSignHead (Rust nativo,
# liblumidevsdk.so) via hook acotado de memcpy.  Validado contra la salida
# controlada del propio getSignHead y contra 3 firmas reales capturadas.
#
#   Nonce = MD5(Requestid).UPPERCASE
#   Sign  = MD5("Appid={appid}&Nonce={nonce}&Time={time}&Token={token}&{body}&{appkey}")
#
# OJO: body y appkey van SIN clave (solo "&valor"); nonce va en MAYUSCULAS.


def compute_nonce(request_id: str) -> str:
    """Nonce = MD5(Requestid) en mayusculas (como MD5Utils.getMD5 de la app)."""
    return hashlib.md5(request_id.encode("utf-8")).hexdigest().upper()


def compute_sign(
    *,
    appid: str,
    nonce: str,
    time: str,
    token: str,
    body: str,
    appkey: str,
) -> str:
    """Reimplementacion de LumiDevSDK.getSignHead (Rust nativo) en Python puro.

    `nonce` debe ser el valor del header Nonce (= MD5(Requestid).upper()).
    `body` es el cuerpo en CLARO (JSON compacto). Ojo: incluso cuando la
    peticion viaja cifrada (x-aes128gcm), el Sign se calcula sobre el PLAINTEXT.
    Cuando no hay token (p.ej. login), el campo `Token=` se OMITE por completo
    (verificado contra una firma real de login).
    """
    if token:
        pre = f"Appid={appid}&Nonce={nonce}&Time={time}&Token={token}&{body}&{appkey}"
    else:
        pre = f"Appid={appid}&Nonce={nonce}&Time={time}&{body}&{appkey}"
    return hashlib.md5(pre.encode("utf-8")).hexdigest()


def make_local_signer(
    *,
    appid: str,
    appkey: str,
    token: str,
    user_id: str,
    client_id: str,
    phone_id: str,
    area: str = "EU",
    lang: str = "es",
    country: str = "ES",
    app_version: str = "6.3.7",
    phone_model: str = "motorola edge 50 fusion##Mobile",
    sys_type: str = "1",
    sys_version: str = "16",
) -> Signer:
    """Devuelve un `signer(path_rel, body_str) -> headers` 100% local (sin movil).

    Compatible con el parametro `signer` de cloud_get_public_key / cloud_verify /
    get_session_material / run_authenticated_lock_operation.  Genera Requestid,
    Time y Nonce frescos y calcula el Sign con compute_sign().
    """

    def signer(path_rel: str | None, body_str: str) -> dict[str, str]:
        request_id = str(uuid.uuid4())
        nonce = compute_nonce(request_id)
        time_ms = str(int(time.time() * 1000))
        sign = compute_sign(
            appid=appid,
            nonce=nonce,
            time=time_ms,
            token=token,
            body=body_str,
            appkey=appkey,
        )
        # Cabeceras enviadas: como las reales, con Sign en lugar de Appkey.
        headers = {
            "Lang": lang,
            "Cuty": country,
            "App-Version": app_version,
            "Phone-Model": phone_model,
            "Sys-Type": sys_type,
            "Sys-Version": sys_version,
            "PhoneId": phone_id,
            "Area": area,
            "Appid": appid,
            "ClientId": client_id,
            "Time": time_ms,
            "Nonce": nonce,
            "Sign": sign,
        }
        if token:
            # Peticion autenticada: incluir identidad.
            headers["Token"] = token
            headers["UserId"] = user_id
            headers["Requestid"] = request_id
        # Sin token (login): la app NO envia Token/UserId/Requestid; el Nonce
        # ya codifica el Requestid y el Sign se calculo sin el campo Token.
        return headers

    return signer


# Clave publica RSA-1024 del login (encryptType:2). Se usa para cifrar la
# contrasena en POST /user/guard-code/login.
#
# RESUELTA 2026-08-12: extraida en runtime (NO estatica) via hook Frida sobre
# javax.crypto.Cipher.doFinal([B]) filtrando por output.length==128 (RSA-1024)
# + reflexion sobre el campo `spi` -> OpenSSLKey -> NativeCrypto.get_RSA_public_params
# (tools/capture_rsaspi2.js). Clave anterior (extraida estaticamente del dex /
# libdatajar.so) daba code=500 "Service impl error" -> NO era la del login.
# Esta SI es correcta: verificado end-to-end contra el servidor real con una
# contrasena deliberadamente falsa -> code=810 "Password incorrect" en vez del
# 500 de antes.
#
# CORRECCION 2026-08-14: ese 810 se interpreto como "el sobre es correcto, solo
# fallaba la contrasena". NO lo demuestra. Una cuenta inexistente
# (no-existe-...@example.invalid) devuelve exactamente el mismo 810, y tambien
# lo devuelven credenciales validas verificadas en la app oficial. O sea que el
# 810 es la respuesta a todo y no discrimina. Lo unico que si se puede afirmar
# es que esta clave hace que el servidor llegue a COMPARAR (antes ni eso: 500),
# lo que la hace mejor candidata que la anterior -- pero no confirmada. Ver el
# docstring de login().
_LOGIN_RSA_PUBKEY_DER_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCG46slB57013JJs4Vvj5cVyMpR9b+B2F+YJU6"
    "qhBEYbiEmIdWpFPpOuBikDs2FcPS19MiWq1IrmxJtkICGurqImRUt4lP688IWlEmqHfSxSRf2+a"
    "H0cH8VWZ2OaZn5DWSIHIPBF2kxM71q8stmoYiV0oZsrZzBHsMuBwA4LQdxBwIDAQAB"
)


def encrypt_login_password(password: str) -> str:
    """Cifra la contrasena para el login de cuenta -> base64.

    El plaintext del RSA NO es la contrasena en crudo: es el MD5 de la
    contrasena en HEX MINUSCULA (32 chars ASCII), y ESO es lo que se cifra con
    la RSA-1024 (PKCS#1 v1.5).

        password_field = base64( RSA_PKCS1v15( MD5(password).hexdigest() ) )

    Confirmado por captura Frida de `Cipher.doFinal` en la app real
    (alg=RSA/ECB/PKCS1Padding): para una contrasena de prueba, la entrada al RSA
    es su MD5 en hex minuscula (32 chars ASCII), no la contrasena en crudo, y la
    salida es el campo `password` del body. Ver docs/protocol/cloud-api.md.

    Historia del bug: hasta 2026-08-14 esta funcion cifraba la contrasena en
    crudo, por lo que el servidor descifraba, comparaba contra el MD5 esperado y
    devolvia `code=810` SIEMPRE -- con cualquier credencial, incluidas las
    validas. El doc de RE ya recogia el MD5 (login-cuenta.md §2), pero el codigo
    nunca lo aplico.
    """
    pub = load_der_public_key(base64.b64decode(_LOGIN_RSA_PUBKEY_DER_B64))
    if not isinstance(pub, rsa.RSAPublicKey):  # pragma: no cover - key is RSA-1024
        raise TypeError("login public key is not RSA")
    password_md5 = hashlib.md5(password.encode("utf-8")).hexdigest()
    ct = pub.encrypt(password_md5.encode("ascii"), _pad.PKCS1v15())
    return base64.b64encode(ct).decode("ascii")


# --- Content-Encoding: x-aes128gcm (esquema custom estilo RFC 8188) ----------
# El body del login (y la respuesta) van cifrados con AES-128-GCM.  Reversado por
# captura nativa (LumiDevSDK.aesEncryptedContent) + verificado con 2 muestras:
#   key   = appkey[:16]                          (AES-128, los 16 primeros bytes)
#   salt  = 16 bytes aleatorios
#   nonce = HKDF-SHA256(salt=salt, IKM=appkey, info=b"")[:12]
#   ct||tag = AES-128-GCM(key, nonce, plaintext)
#   wire  = base64(salt + 0x00) "-" base64(ct) "-" base64(tag)
# El server responde con el mismo formato (su propio salt) -> se descifra igual.


def _aes128gcm_nonce(salt: bytes, appkey: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=12, salt=salt, info=b"").derive(
        appkey.encode("ascii")
    )


def aes128gcm_encrypt_body(plaintext: bytes, appkey: str) -> str:
    """Cifra un cuerpo -> blob `b64(salt+00)-b64(ct)-b64(tag)` (x-aes128gcm)."""
    ak = appkey.encode("ascii")
    salt = secrets.token_bytes(16)
    nonce = _aes128gcm_nonce(salt, appkey)
    ct_tag = AESGCM(ak[:16]).encrypt(nonce, plaintext, None)
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    return "-".join(
        (
            base64.b64encode(salt + b"\x00").decode("ascii"),
            base64.b64encode(ct).decode("ascii"),
            base64.b64encode(tag).decode("ascii"),
        )
    )


def aes128gcm_decrypt_body(blob: str, appkey: str) -> bytes:
    """Descifra un blob x-aes128gcm -> bytes en claro."""
    ak = appkey.encode("ascii")
    parts = blob.strip().split("-")
    if len(parts) != 3:
        raise ValueError(f"blob x-aes128gcm invalido ({len(parts)} partes)")
    salt = base64.b64decode(parts[0])[:16]
    ct = base64.b64decode(parts[1])
    tag = base64.b64decode(parts[2])
    nonce = _aes128gcm_nonce(salt, appkey)
    return AESGCM(ak[:16]).decrypt(nonce, ct + tag, None)
