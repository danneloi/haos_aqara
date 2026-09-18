"""Authenticated BLE session helpers for Aqara U200."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sys
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from .auth import CloudAuthManager

# Pure wire framing (CRC + auth-message ser/deser) and the AES-CCM control codec
# live in leaf modules (feature 028); the orchestrator below uses them unchanged.
from .control_codec import decrypt_control_payload, encrypt_control_payload
from .framing import (
    assemble_auth_fragments,
    build_auth_message,
    fragment_auth_message,
    parse_auth_message,
)
from .gatt import GattClient

# GATT identity constants live in the leaf module ``gatt_uuids`` so the low-level
# transport can import them without depending on this (higher) module. Re-exported
# from here so ``from aqara_ble.session import AUTH_SERVICE_UUID`` etc. keep
# working. See gatt_uuids.py.
from .gatt_uuids import (
    AUTH_NOTIFY_UUID,
    AUTH_WRITE_UUID,
    AUX_NOTIFY_UUID,
    AUX_WRITE_UUID,
    CONTROL_NOTIFY2_UUID,
    CONTROL_NOTIFY_UUID,
    CONTROL_WRITE_UUID,
    GATT_CACHING_PREAMBLE_UUID16,
    PRE_AUTH_NOTIFY_ORDER,
)
from .kdf import (
    REGION_BASE_URLS,
    CloudServiceError,
    cloud_get_public_key,
    get_session_material,
)
from .lock_ops import LockOperation, LockOperationWrite, build_lock_operation_write
from .offline_login import derive_session_material as _derive_offline_session
from .offline_login import generate_ephemeral as _gen_ephemeral

logger = logging.getLogger(__name__)

_T = TypeVar("_T")


class OperationInProgressError(RuntimeError):
    """Raised when run_authenticated_lock_operation() is called during another operation."""

    pass


def _debug_report(channel: str, data: bytes) -> None:
    """Log a frame from a report channel (ff64/ff92) under U200_DEBUG (feature 022).

    These channels carry the lock's REPORT_* pushes (status/events). The auth flow
    subscribes to them but historically discarded their payloads; logging them here
    is how we discover whether the lock reports state/position spontaneously.
    """

    if os.environ.get("U200_DEBUG"):
        print(f"[BLE] report {channel}: {data.hex()}", file=sys.stderr)


async def _run_cloud_phase(phase: str, fn: Callable[..., _T], /, **kwargs: Any) -> _T:
    """Run a blocking cloud call in a worker thread with whitelisted DEBUG logging.

    Only non-sensitive telemetry is logged (Feature 012 FR-008): the operation
    phase, its duration, the worker thread id, the outcome, and — on failure —
    the *type* of the exception. URLs, headers, request/response bodies, device
    ids, auth/session/crypto material and raw exception messages are never
    logged.
    """

    logger.debug("cloud phase %s: started", phase)
    started = time.perf_counter()
    # Capture the worker thread id from INSIDE the worker execution context: after
    # the await we are back on the event-loop thread, so reading get_ident() there
    # would report the loop, not the worker (issue #3). Only this non-sensitive
    # integer crosses back for telemetry.
    worker_ident: dict[str, int] = {}

    def _traced(**call_kwargs: Any) -> _T:
        worker_ident["id"] = threading.get_ident()
        return fn(**call_kwargs)

    try:
        result = await asyncio.to_thread(_traced, **kwargs)
    except BaseException as exc:  # log the type only, then re-raise unchanged
        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.debug(
            "cloud phase %s: failed after %.0f ms (%s)",
            phase,
            elapsed_ms,
            type(exc).__name__,
        )
        raise
    elapsed_ms = (time.perf_counter() - started) * 1000
    logger.debug(
        "cloud phase %s: completed in %.0f ms (worker thread %d)",
        phase,
        elapsed_ms,
        worker_ident.get("id", -1),
    )
    return result


# NOTE: the GATT-caching preamble UUID16 tuple (Appearance + Database Hash) now
# lives in gatt_uuids.GATT_CACHING_PREAMBLE_UUID16; the constants below are the
# session-only tuning values that pair with it and stay here.

# HIPOTESIS PROBADA Y DESCARTADA (2026-08-12b): el preambulo GATT-caching (ahora
# en gatt_uuids.GATT_CACHING_PREAMBLE_UUID16) solo
# REPLICA LA LECTURA de Database Hash, pero nunca escribia `Client Supported
# Features` (0x2B29) -- la otra mitad del mecanismo de "Robust Caching"
# (Bluetooth Core Vol 3 Part G Sec 2.5.2; ver tambien la doc de Silicon Labs
# -el MISMO fabricante del SoC EFR32MG24 de la cerradura- en
# docs.silabs.com/bluetooth/.../gatt-caching). Una fuente AOSP real (commit de
# packages/modules/Bluetooth) confirma que Android "reads Server Supported
# Features and writes Client supported features after discovery" de forma
# AUTOMATICA a nivel de plataforma, fuera del control de cualquier app.
# Encajaba con todos los hechos observados (Android real funciona, macOS/
# bleak y ESP32/Bumble fallan igual) sin requerir secreto de vinculacion.
# PROBADO EN VIVO contra la cerradura real: la escritura se confirma (sin
# error, característica localizada y escrita), pero el ACK vacío PERSISTE
# idéntico (`000610ffff0000...`, body_len=0). DESCARTADO como causa única del
# muro. Se deja implementado (best-effort, no hace daño y es spec-compliant)
# por si combinado con otra pieza aporta algo, pero no es la solucion. Ver
# docs/reference/ para el detalle completo y los siguientes
# candidatos.
CLIENT_SUPPORTED_FEATURES_UUID16 = 0x2B29
CLIENT_SUPPORTED_FEATURES_ROBUST_CACHING_BIT = 0x01

# LE Data Length Change visto en el HCI snoop real justo tras el MTU exchange
# (subevent 0x07), ANTES del preambulo GATT caching. Valores exactos del lado
# del telefono en esa sesion: max_tx_octets=27/max_tx_time=328,
# max_rx_octets=251/max_rx_time=2120 (asimetrico: tx queda en el valor
# default sin extender, rx si se extiende). Se pide el valor RX (extendido)
# como tx_octets/tx_time propios al llamar set_data_length, que es lo mas
# parecido a "pedir la extension" desde el lado central. Sin confirmar aun
# si esto es necesario o si el propio controlador ya lo hace solo. Ver
# docs/reference/.
DATA_LENGTH_TX_OCTETS = 251
DATA_LENGTH_TX_TIME = 2120

# LE Connection Update visto en el HCI snoop real justo despues del preambulo
# GATT y ANTES de las CCCD: intervalo 36->12 (unidades de 1.25ms = 45ms->15ms),
# latencia 0, supervision_timeout 400 (unidades de 10ms = 4000ms). Ver
# docs/reference/ (sospechoso siguiente, sin confirmar aun
# si esto es necesario para que la cerradura responda con su pubkey real).
POST_AUTH_CONNECTION_INTERVAL_MS = 15.0
POST_AUTH_CONNECTION_LATENCY = 0
POST_AUTH_SUPERVISION_TIMEOUT_MS = 4000.0

# Low-power connection params for a HELD state-listening session: a long interval
# plus slave latency lets the lock's radio sleep between events, so keeping the
# session open costs little battery (the lock still wakes to push an ff62 report).
# supervision must exceed (1+latency)*interval*2 = 10 s, so 12 s is safe.
LOW_POWER_CONNECTION_INTERVAL_MS = 1000.0
LOW_POWER_CONNECTION_LATENCY = 4
LOW_POWER_SUPERVISION_TIMEOUT_MS = 12000.0

#: The lock stops pushing spontaneous ff62 reports ~30 s after the last keepalive.
#: During a `listen_after` window we re-send the confirmed keepalive on this
#: interval (the app does the same) so events keep flowing for the whole window.
LISTEN_KEEPALIVE_INTERVAL_S = 20.0

@dataclass(frozen=True)
class SessionMaterial:
    session_key_hex: str
    nonce_hex: str
    verify_data_hex: str
    lock_public_key_hex: str


async def _await_wor_ready(client: object, *, timeout: float = 3.0) -> None:
    """Gate a WRITE_WITHOUT_RESPONSE on macOS/CoreBluetooth readiness.

    CoreBluetooth silently DROPS write-without-response packets sent faster than
    the controller can take them, and bleak does not gate on the "ready to send"
    signal (its ``peripheralIsReadyToSendWriteWithoutResponse`` callback is never
    called in practice — bleak discussion #1589). Sending a large OTA in a tight
    loop therefore corrupts blocks (the lock NAKs) and can make macOS drop the
    link entirely. We poll ``CBPeripheral.canSendWriteWithoutResponse`` ourselves
    before each ff91 write. No-op on every other backend (bumble/BlueZ/WinRT do
    their own ACL flow control), so this is safe and transport-agnostic."""
    backend = getattr(client, "_backend", None)
    peripheral = getattr(backend, "_peripheral", None)
    ready = getattr(peripheral, "canSendWriteWithoutResponse", None)
    if ready is None:
        return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if ready():
                return
        except Exception:
            return
        await asyncio.sleep(0.002)


@dataclass
class PostAuthContext:
    """Handed to a ``post_auth`` hook once the aqara session is fully established
    (ECDH done, session key derived, CCCD enabled on ff62/ff64/ff92/ff08).

    It exposes exactly the primitives an out-of-band bulk transfer (the language
    voice-pack OTA on the AUX channel ff91/ff92) needs, without that logic having
    to re-implement the auth handshake. The wire evidence (2026-09-02) proved the
    OTA is NOT a standalone plaintext blast: it runs inside this authenticated,
    subscribed session, the lock block-acks on ff92, and the control channel must
    stay alive throughout (it goes quiet ~30 s after the last keepalive).

    - ``write_aux(frame)``   → one WRITE_WITHOUT_RESPONSE to ff91 (the OTA channel).
    - ``aux_reports``        → queue of ``(channel, bytes)``; ff92 (OTA acks) and
                               ff64 land here. Drain it to observe the lock's acks.
    - ``send_keepalive()``   → the encrypted 2f012f control keepalive on ff61, so
                               the session survives a long transfer.
    - ``send_control(pt)``   → encrypt a control plaintext and write it to ff61
                               (e.g. the pre-OTA arming reads SYNC_OTA_URL /
                               VOICE_OTA_INFO_GET the app issues before streaming).
    - ``read_control(...)``  → await + decrypt the next ff62 control response.
    """

    client: GattClient
    session_key_hex: str
    nonce_hex: str
    aux_reports: asyncio.Queue[tuple[str, bytes]]
    control_responses: asyncio.Queue[bytes]
    _keepalive_frame: bytes

    async def write_aux(self, frame: bytes, *, response: bool = False) -> None:
        await _await_wor_ready(self.client)
        # response=True (write-WITH-response) makes each fragment reliable and
        # self-pacing: the next write only goes once the previous one is confirmed
        # delivered over the link. Over an ESPHome proxy this is essential — the
        # macOS ``_await_wor_ready`` WoR flow-control gate is a no-op there, so a
        # free WoR blast overruns the proxy's BLE queue and silently drops a
        # fragment ~every 80 writes (a block CRC fail → 0x1115 NAK ~block 16).
        await self.client.write_gatt_char(AUX_WRITE_UUID, bytes(frame), response=response)

    async def send_keepalive(self) -> None:
        with contextlib.suppress(Exception):
            await self.client.write_gatt_char(
                CONTROL_WRITE_UUID, self._keepalive_frame, response=False
            )

    async def send_control(self, plaintext: bytes, *, write_prefix: int = 0x01) -> None:
        """Encrypt ``plaintext`` under the session key/nonce and write it to ff61,
        exactly like the normal control path (``write_prefix`` + AES-CCM payload)."""
        enc = encrypt_control_payload(
            self.session_key_hex, self.nonce_hex, plaintext=bytes(plaintext)
        )
        await self.client.write_gatt_char(
            CONTROL_WRITE_UUID, bytes((write_prefix,)) + enc, response=False
        )

    async def read_control(self, *, timeout: float) -> bytes | None:
        """Await the next ff62 control frame and return its decrypted plaintext
        (``None`` on timeout or a too-short frame)."""
        try:
            frame = await asyncio.wait_for(self.control_responses.get(), timeout=timeout)
        except (TimeoutError, asyncio.TimeoutError):
            return None
        if len(frame) < 2:
            return None
        with contextlib.suppress(Exception):
            return decrypt_control_payload(
                self.session_key_hex, self.nonce_hex, ciphertext=frame[1:]
            )
        return None


# Per-device concurrency tracking: one flag per device_id to prevent concurrent
# run_authenticated_lock_operation() calls on the same lock.
# Feature 012: Cloud I/O Async-Safe (fail-fast concurrency control)
_device_operation_in_progress: dict[str, bool] = {}


async def run_authenticated_lock_operation(
    *,
    client: GattClient,
    device_id: str,
    auth_headers: dict[str, str] | None,
    region: str,
    base_url: str | None,
    operation: LockOperation | str | LockOperationWrite,
    notify_timeout: float = 8.0,
    signer: Any = None,
    auth: CloudAuthManager | None = None,
    listen_after: float = 0.0,
    on_report: Callable[[str, bytes], None] | None = None,
    low_power_connection: bool = False,
    follow_up_ops: list[LockOperationWrite] | None = None,
    follow_up_out: list[tuple[Any, str | None]] | None = None,
    post_auth: Callable[[PostAuthContext], Awaitable[None]] | None = None,
    precomputed_cloud_pubkey: str | None = None,
    ltmk: bytes | None = None,
) -> tuple[SessionMaterial, LockOperationWrite, str | None]:
    """
    Authenticate with the lock, send a command, and receive the response.

    ``ltmk`` (optional, 32 bytes): when provided, the session is derived **offline**
    (cloud-cut) — our own ephemeral key + ECDH with the lock, session material =
    ``HKDF(ECDH_shared XOR LTMK, "aiot-login-salt", ...)`` (see offline_login). No
    cloud call is made for the session. When ``None``, the cloud path is used.

    ``post_auth`` (optional): once the session is fully authenticated and
    subscribed, this hook is awaited with a :class:`PostAuthContext` INSTEAD of
    sending ``operation`` on the control channel. It exists for out-of-band bulk
    transfers that must run inside the authenticated session — the language
    voice-pack OTA (ff91/ff92). When set, no lock control command is written and
    ``listen_after``/``follow_up_ops`` are ignored; the return's response hex is
    ``None``.

    ``listen_after`` (seconds) keeps the connection open after the command's first
    response and forwards every additional frame — control ff62 (decrypted),
    report ff64/ff92 (raw) — to ``on_report(channel, data)`` until the window
    expires (Feature 023, for spontaneous state/events). Default ``0.0`` keeps the
    exact prior "one command, one response, disconnect" behaviour.

    Credential mechanisms (provide at most one; passing **both is an error**):

    - ``auth``: a :class:`CloudAuthManager` (built by the consumer from its own
      secure credential storage). The flow logs in on demand, keeps the token in
      memory, and — if a cloud call fails with ``code 108`` (token expired) **before
      the actuator command is sent** — re-authenticates and re-runs the whole
      operation once (Feature 014). A ``code 810`` (bad credentials) or any error
      after actuation is never retried.
    - ``signer``: a pre-built static signer (legacy path, no auto-refresh). If
      neither is given, the legacy behaviour is preserved (the ``None`` signer is
      passed through, as before Feature 014).

    The token and credentials are never persisted or logged.
    """
    if signer is not None and auth is not None:
        raise ValueError(
            "run_authenticated_lock_operation accepts `signer` (static token) or "
            "`auth` (CloudAuthManager for auto-login), not both."
        )

    if auth is not None:
        active_signer: Any = await _run_cloud_phase("login", auth.build_signer)
    else:
        active_signer = signer

    max_reauth = 1 if auth is not None else 0
    for attempt in range(max_reauth + 1):
        actuation_state: dict[str, bool] = {"done": False}
        try:
            return await _run_authenticated_lock_operation_once(
                client=client,
                device_id=device_id,
                auth_headers=auth_headers,
                region=region,
                base_url=base_url,
                operation=operation,
                notify_timeout=notify_timeout,
                signer=active_signer,
                actuation_state=actuation_state,
                listen_after=listen_after,
                on_report=on_report,
                low_power_connection=low_power_connection,
                follow_up_ops=follow_up_ops,
                follow_up_out=follow_up_out,
                post_auth=post_auth,
                precomputed_cloud_pubkey=precomputed_cloud_pubkey,
                ltmk=ltmk,
            )
        except CloudServiceError as exc:
            can_retry = (
                auth is not None
                and exc.is_code(108)
                and not actuation_state["done"]
                and attempt < max_reauth
            )
            if not can_retry:
                raise
            assert auth is not None  # narrowed by can_retry
            active_signer = await _run_cloud_phase(
                "login_refresh", auth.build_signer, force_refresh=True
            )

    raise RuntimeError("run_authenticated_lock_operation: retry loop exhausted")


async def _run_authenticated_lock_operation_once(
    *,
    client: GattClient,
    device_id: str,
    auth_headers: dict[str, str] | None,
    region: str,
    base_url: str | None,
    operation: LockOperation | str | LockOperationWrite,
    notify_timeout: float = 8.0,
    signer: Any = None,
    actuation_state: dict[str, bool],
    listen_after: float = 0.0,
    on_report: Callable[[str, bytes], None] | None = None,
    low_power_connection: bool = False,
    follow_up_ops: list[LockOperationWrite] | None = None,
    follow_up_out: list[tuple[Any, str | None]] | None = None,
    post_auth: Callable[[PostAuthContext], Awaitable[None]] | None = None,
    precomputed_cloud_pubkey: str | None = None,
    ltmk: bytes | None = None,
) -> tuple[SessionMaterial, LockOperationWrite, str | None]:
    """
    Single attempt of the authenticated lock operation (see the public wrapper
    ``run_authenticated_lock_operation``). ``actuation_state["done"]`` is set to
    True immediately before the control (actuator) write so the wrapper can avoid
    retrying after the lock may have moved.

    Authenticate with lock, send command, and receive response (async-safe).

    Cloud I/O (key derivation, session material) executes in worker threads
    via asyncio.to_thread(), keeping the event loop responsive. BLE operations
    remain on the caller's event loop.

    Args:
        client: BLE GATT client for read/write operations
        device_id: Lock device identifier for cloud KDF and concurrency tracking
        auth_headers: Optional HTTP headers for cloud requests
        region: Cloud region (e.g., "EU", "CN")
        base_url: Optional custom cloud endpoint
        operation: Lock operation (e.g., "unlock", "lock")
        notify_timeout: Seconds to wait for control response (default 8.0)
        signer: Optional cloud request signer (e.g., RSA key for Akamai)

    Returns:
        tuple of:
            - SessionMaterial: Session keys, nonce, verify data, lock public key
            - LockOperationWrite: Operation details and encrypted payload
            - str | None: Decrypted control response hex, or None if timeout

    Raises:
        OperationInProgressError: Another operation is in progress on this device
        RuntimeError: Cloud call failure, BLE protocol violation, or crypto error
        asyncio.TimeoutError: BLE notification timeout

    Feature 012: Cloud I/O Async-Safe
        - Per-device concurrency control (fail-fast, non-blocking)
        - Cloud calls execute in worker threads (never block event loop)
        - Exceptions propagate unwrapped (original type preserved)
        - No credentials/keys logged (FR-008 compliance)
    """
    # Feature 012: Per-device concurrency control (T005+T006)
    # Fail-fast check: if operation already in progress for this device, reject immediately
    if _device_operation_in_progress.get(device_id, False):
        raise OperationInProgressError(
            f"Another lock operation is in progress for device {device_id}"
        )

    # Mark operation as in progress
    _device_operation_in_progress[device_id] = True

    try:
        auth_queue: asyncio.Queue[bytes] = asyncio.Queue()
        control_queue: asyncio.Queue[bytes] = asyncio.Queue()

        def on_auth_fragment(_: object, data: bytearray) -> None:
            auth_queue.put_nowait(bytes(data))

        def on_control_fragment(_: object, data: bytearray) -> None:
            control_queue.put_nowait(bytes(data))

        async def write_auth_message(message_payload: bytes) -> None:
            # ff07 es write-SIN-respuesta (write-with-response da "Not Permitted").
            # Sin pausa, CoreBluetooth pierde fragmentos y el lock recibe la clave
            # incompleta -> responde body vacio. La pausa asegura la entrega ordenada.
            for fragment in fragment_auth_message(message_payload, direction=0x5A):
                await client.write_gatt_char(AUTH_WRITE_UUID, fragment, response=False)
                await asyncio.sleep(0.04)

        async def read_full_auth_message() -> bytes:
            fragments: list[bytes] = []
            while True:
                fragment = await asyncio.wait_for(auth_queue.get(), timeout=notify_timeout)
                if not fragment:
                    continue
                fragments.append(fragment)
                if fragment[1] == 0xFF:
                    return assemble_auth_fragments(fragments, expected_direction=0xDA)

        report_queue: asyncio.Queue[tuple[str, bytes]] = asyncio.Queue()

        def on_report_notify(channel: str) -> Callable[[object, bytearray], None]:
            # ff64/ff92 carry the lock's REPORT_* pushes. We enable them because the
            # app does (PRE_AUTH_NOTIFY_ORDER). Log under U200_DEBUG (feature 022)
            # and queue them so a listen window can forward them (feature 023).
            def handler(_: object, data: bytearray) -> None:
                frame = bytes(data)
                _debug_report(channel, frame)
                report_queue.put_nowait((channel, frame))

            return handler

        callback_by_notify_uuid = {
            CONTROL_NOTIFY_UUID: on_control_fragment,
            CONTROL_NOTIFY2_UUID: on_report_notify("ff64"),
            AUX_NOTIFY_UUID: on_report_notify("ff92"),
            AUTH_NOTIFY_UUID: on_auth_fragment,
        }

        async def enable_cccd_in_app_order() -> None:
            """Habilita CCCD en el orden EXACTO capturado de la app: ff62, ff64,
            ff92, ff08 (ver PRE_AUTH_NOTIFY_ORDER). Tolera fallos por-característica
            (algunos transportes ya tienen el CCCD activo o no exponen esa char)."""
            for uuid in PRE_AUTH_NOTIFY_ORDER:
                try:
                    if os.environ.get("U200_DEBUG"):
                        print(f"[BLE] enabling CCCD for {uuid[-4:]}", file=sys.stderr)
                    await client.start_notify(uuid, callback_by_notify_uuid[uuid])
                    await asyncio.sleep(0.02)
                except Exception as exc:
                    if os.environ.get("U200_DEBUG"):
                        print(f"[BLE] CCCD enable failed for {uuid[-4:]}: {exc}", file=sys.stderr)

        async def request_remote_le_features() -> None:
            """HCI LE Read Remote Features -- ver
            bumble_transport.py::get_remote_le_features para la evidencia
            (btsnoop real, 2026-08-13). Best-effort; bleak no lo expone."""
            get_features = getattr(client, "get_remote_le_features", None)
            if get_features is None:
                if os.environ.get("U200_DEBUG"):
                    print("[BLE] adaptador sin get_remote_le_features; se omite", file=sys.stderr)
                return
            try:
                features = await get_features()
                if os.environ.get("U200_DEBUG"):
                    print(f"[BLE] LE Read Remote Features -> 0x{features:016x}", file=sys.stderr)
            except Exception as exc:
                if os.environ.get("U200_DEBUG"):
                    print(f"[BLE] LE Read Remote Features fallo: {exc}", file=sys.stderr)

        async def request_att_mtu() -> None:
            """ATT Exchange MTU Request -- PRIMER paso real tras conectar, ANTES
            de todo lo demas (ver docs/reference/ paso 2). Es la
            UNICA pieza de la secuencia pre-auth que este proyecto nunca habia
            reproducido con exito (un intento anterior colgo Bumble y se
            abandono sin reintentar, ver §6.3 y bumble_transport.py::request_mtu).
            Best-effort con timeout corto propio; bleak no expone esto (el SO
            decide) asi que se salta sin romper nada en ese adaptador."""
            request_mtu = getattr(client, "request_mtu", None)
            if request_mtu is None:
                if os.environ.get("U200_DEBUG"):
                    print("[BLE] adaptador sin request_mtu; se omite", file=sys.stderr)
                return
            try:
                negotiated = await request_mtu(247)
                if os.environ.get("U200_DEBUG"):
                    print(f"[BLE] ATT MTU negociado: {negotiated}", file=sys.stderr)
            except Exception as exc:
                if os.environ.get("U200_DEBUG"):
                    print(f"[BLE] ATT MTU exchange fallo: {exc}", file=sys.stderr)

        async def request_data_length_extension() -> None:
            """Replica el LE Data Length Change real, visto justo tras el MTU
            exchange y ANTES del preambulo GATT caching (ver
            DATA_LENGTH_TX_OCTETS/_TIME). Best-effort: bleak no expone esto (lo
            decide el SO); solo adaptadores de bajo nivel como Bumble pueden
            pedirlo explicitamente."""
            set_data_length = getattr(client, "set_data_length", None)
            if set_data_length is None:
                if os.environ.get("U200_DEBUG"):
                    print(
                        "[BLE] adaptador sin set_data_length; se omite",
                        file=sys.stderr,
                    )
                return
            try:
                await set_data_length(tx_octets=DATA_LENGTH_TX_OCTETS, tx_time=DATA_LENGTH_TX_TIME)
                if os.environ.get("U200_DEBUG"):
                    print(
                        f"[BLE] data length extension solicitada: "
                        f"tx_octets={DATA_LENGTH_TX_OCTETS} tx_time={DATA_LENGTH_TX_TIME}",
                        file=sys.stderr,
                    )
            except Exception as exc:
                if os.environ.get("U200_DEBUG"):
                    print(f"[BLE] data length extension fallo: {exc}", file=sys.stderr)

        async def run_gatt_caching_preamble() -> None:
            """Read By Type de Appearance (0x2A01) y Database Hash (0x2B2A),
            exactamente como hace Android antes de escribir la pubkey (ver
            GATT_CACHING_PREAMBLE_UUID16). Best-effort: el adaptador bleak
            estandar no expone read_by_type, asi que se salta sin romper nada."""
            read_by_type = getattr(client, "read_by_type", None)
            if read_by_type is None:
                if os.environ.get("U200_DEBUG"):
                    print(
                        "[BLE] adaptador sin read_by_type; se omite el preambulo "
                        "de GATT caching (0x2A01/0x2B2A)",
                        file=sys.stderr,
                    )
                return
            for uuid16 in GATT_CACHING_PREAMBLE_UUID16:
                try:
                    values = await read_by_type(uuid16)
                    if os.environ.get("U200_DEBUG"):
                        hexvals = [bytes(v).hex() for v in values]
                        print(f"[BLE] Read By Type 0x{uuid16:04x} -> {hexvals}", file=sys.stderr)
                except Exception as exc:
                    if os.environ.get("U200_DEBUG"):
                        print(f"[BLE] Read By Type 0x{uuid16:04x} fallo: {exc}", file=sys.stderr)

        async def write_client_supported_features() -> None:
            """Escribe el bit Robust Caching en Client Supported Features (0x2B29)
            -- ver CLIENT_SUPPORTED_FEATURES_UUID16 arriba para la hipotesis y las
            fuentes. Best-effort: solo adaptadores de bajo nivel (Bumble) exponen
            write_by_type; bleak/CoreBluetooth no lo necesitan porque el propio
            SO ya lo hace por su cuenta."""
            write_by_type = getattr(client, "write_by_type", None)
            if write_by_type is None:
                if os.environ.get("U200_DEBUG"):
                    print(
                        "[BLE] adaptador sin write_by_type; se omite Client "
                        "Supported Features (0x2B29)",
                        file=sys.stderr,
                    )
                return
            try:
                await write_by_type(
                    CLIENT_SUPPORTED_FEATURES_UUID16,
                    bytes((CLIENT_SUPPORTED_FEATURES_ROBUST_CACHING_BIT,)),
                )
                if os.environ.get("U200_DEBUG"):
                    print(
                        "[BLE] Client Supported Features (0x2B29) <- Robust Caching bit escrito",
                        file=sys.stderr,
                    )
            except Exception as exc:
                if os.environ.get("U200_DEBUG"):
                    msg = f"[BLE] Client Supported Features write failed: {exc}"
                    print(msg, file=sys.stderr)

        async def request_connection_update() -> None:
            """Replica el LE Connection Update real (45ms->15ms) visto justo tras
            el preambulo GATT y antes de las CCCD. Best-effort: bleak no expone
            esto (el SO decide los parametros de conexion); solo Bumble/adaptadores
            de bajo nivel pueden pedirlo explicitamente."""
            update = getattr(client, "update_connection_parameters", None)
            if update is None:
                if os.environ.get("U200_DEBUG"):
                    print(
                        "[BLE] adaptador sin update_connection_parameters; se omite",
                        file=sys.stderr,
                    )
                return
            if low_power_connection:
                interval_ms = LOW_POWER_CONNECTION_INTERVAL_MS
                latency = LOW_POWER_CONNECTION_LATENCY
                supervision_ms = LOW_POWER_SUPERVISION_TIMEOUT_MS
            else:
                interval_ms = POST_AUTH_CONNECTION_INTERVAL_MS
                latency = POST_AUTH_CONNECTION_LATENCY
                supervision_ms = POST_AUTH_SUPERVISION_TIMEOUT_MS
            try:
                await update(
                    interval_ms=interval_ms,
                    latency=latency,
                    supervision_timeout_ms=supervision_ms,
                )
                if os.environ.get("U200_DEBUG"):
                    print(
                        f"[BLE] connection update solicitado: interval={interval_ms}ms "
                        f"latency={latency} low_power={low_power_connection}",
                        file=sys.stderr,
                    )
            except Exception as exc:
                if os.environ.get("U200_DEBUG"):
                    print(f"[BLE] connection update fallo: {exc}", file=sys.stderr)

        await request_remote_le_features()
        await request_att_mtu()
        # request_data_length_extension() -- RETIRADO de la secuencia activa
        # 2026-08-13: verificado contra el btsnoop de hoy (frame 161047, evento
        # LE Data Length Change) que el HOST del movil NUNCA manda el comando
        # HCI "LE Set Data Length" para la conexion con la cerradura (se
        # comprobaron las 5 apariciones de ese comando en todo el archivo -- las
        # 5 son para OTROS connection_handle, ninguna para el de la cerradura).
        # La extension de longitud (27/251) ocurre sola, a nivel de controlador
        # (iniciada por el propio periferico), sin intervencion del host. Es
        # otra operacion "de mas" que hariamos nosotros y el movil real no hace
        # -- igual que Client Supported Features (§11.7). Se deja la funcion
        # definida por si hace falta en un adaptador que SI la necesite.
        await run_gatt_caching_preamble()
        # write_client_supported_features() -- RETIRADO de la secuencia activa
        # 2026-08-13: un btsnoop fresco (bugreport de hoy) confirma que Android
        # NO escribe 0x2B29 contra esta cerradura en absoluto -- 4 Write Request
        # totales en toda la fase pre-auth, los 4 son CCCD (0x0034/0x0039/0x003f/
        # 0x0023), ninguno a Client Supported Features. La funcion se deja
        # definida (ver docs/reference/) por si hace
        # falta reactivarla, pero mandarla es una operacion EXTRA que el flujo
        # real no hace -- se quita para que la secuencia sea un espejo exacto.
        await request_connection_update()
        await enable_cccd_in_app_order()
        try:
            resolved_base_url = base_url or REGION_BASE_URLS.get(region, REGION_BASE_URLS["EU"])
            # Prefer a cloud pubkey fetched BEFORE the BLE connect (see
            # ``precomputed_cloud_pubkey``): the OTA needs the keypad-touch presence
            # to still be active when this BLE auth completes, and doing the ~POST
            # /publickey round-trip here — between connect and the auth write — burns
            # that presence window (the lock then NAKs the OTA mid-stream). The call
            # only needs the device id + signer, nothing from the live link, so it can
            # be done up front and injected. Falls back to fetching inline.
            if ltmk is not None:
                # Offline (cloud-cut): OUR ephemeral is the "cloud" pubkey; the
                # session is derived locally (ECDH shared XOR LTMK), no cloud call.
                _offline_priv, cloud_public_key_hex = _gen_ephemeral()
            elif precomputed_cloud_pubkey is not None:
                _offline_priv = None
                cloud_public_key_hex = precomputed_cloud_pubkey
            else:
                _offline_priv = None
                cloud_public_key_hex = await _run_cloud_phase(
                    "cloud_get_public_key",
                    cloud_get_public_key,
                    device_id=device_id,
                    auth_headers=auth_headers,
                    base_url=resolved_base_url,
                    signer=signer,
                )
            app_token_key = int.from_bytes(os.urandom(2), "little")
            await write_auth_message(
                build_auth_message(
                    0x06,
                    body=bytes.fromhex(cloud_public_key_hex),
                    app_token=app_token_key,
                )
            )

            # La cerradura responde primero con un ACK 0x06 sin cuerpo y DESPUES envia
            # su clave publica efimera (65 bytes) en otro frame 0x06. Leemos hasta
            # obtener un 0x06 con cuerpo (la clave), tolerando ACKs vacios.
            if os.environ.get("U200_DEBUG"):
                print(f"[BLE] cloudPubKey={cloud_public_key_hex}", file=sys.stderr)
            lock_key_message = None
            for _ in range(6):
                lock_key_raw = await read_full_auth_message()
                msg = parse_auth_message(lock_key_raw)
                if os.environ.get("U200_DEBUG"):
                    print(
                        f"[BLE] frame type={msg.frame_type:#x} body_len={len(msg.body)} "
                        f"raw={lock_key_raw.hex()}",
                        file=sys.stderr,
                    )
                if msg.frame_type == 0x06 and len(msg.body) >= 33:
                    lock_key_message = msg
                    break
            if lock_key_message is None:
                raise RuntimeError(
                    "no se recibio la clave publica del lock (solo ACKs vacios); "
                    "reintenta con la cerradura despierta."
                )

            if ltmk is not None:
                # Offline: derive sessionKey/nonce/verifyData locally from our
                # ephemeral private key, the lock's pubkey and the LTMK.
                session = _derive_offline_session(
                    _offline_priv, lock_key_message.body.hex(), ltmk
                )
            else:
                session = await _run_cloud_phase(
                    "get_session_material",
                    get_session_material,
                    device_id=device_id,
                    device_public_key_hex=lock_key_message.body.hex(),
                    auth_headers=auth_headers,
                    region=region,
                    base_url=resolved_base_url,
                    signer=signer,
                )

            app_token_verify = int.from_bytes(os.urandom(2), "little")
            await write_auth_message(
                build_auth_message(
                    0x07,
                    body=bytes.fromhex(session["verifyData"]),
                    app_token=app_token_verify,
                )
            )
            auth_ack_raw = await read_full_auth_message()
            auth_ack = parse_auth_message(auth_ack_raw)
            if auth_ack.frame_type != 0x07:
                raise RuntimeError(f"se esperaba ACK auth 0x07 y llegó {auth_ack.frame_type:#x}")

            write = build_lock_operation_write(operation)

            # Out-of-band bulk transfer (language OTA on ff91/ff92): run INSIDE
            # this authenticated, subscribed session instead of writing a lock
            # control command. See PostAuthContext. This is a real device write,
            # so no reauth after it (FR-016).
            if post_auth is not None:
                actuation_state["done"] = True
                keepalive_frame = bytes((0x01,)) + encrypt_control_payload(
                    session["sessionKey"],
                    session["nonce"],
                    plaintext=bytes.fromhex("2f012f"),
                )
                ctx = PostAuthContext(
                    client=client,
                    session_key_hex=session["sessionKey"],
                    nonce_hex=session["nonce"],
                    aux_reports=report_queue,
                    control_responses=control_queue,
                    _keepalive_frame=keepalive_frame,
                )
                await post_auth(ctx)
                material = SessionMaterial(
                    session_key_hex=session["sessionKey"],
                    nonce_hex=session["nonce"],
                    verify_data_hex=session["verifyData"],
                    lock_public_key_hex=lock_key_message.body.hex(),
                )
                return material, write, None

            encrypted_payload = encrypt_control_payload(
                session["sessionKey"],
                session["nonce"],
                plaintext=write.payload,
            )
            control_write = bytes((write.write_prefix,)) + encrypted_payload
            # Point of no return: from here the lock may actuate, so the wrapper
            # must NOT retry/reauth even on a late token error (FR-016).
            actuation_state["done"] = True
            await client.write_gatt_char(CONTROL_WRITE_UUID, control_write, response=False)

            decrypted_response_hex: str | None = None
            try:
                control_frame = await asyncio.wait_for(control_queue.get(), timeout=notify_timeout)
            except TimeoutError:
                control_frame = b""
            if control_frame:
                if len(control_frame) < 2:
                    raise RuntimeError("respuesta de control cifrada demasiado corta")
                decrypted_response_hex = decrypt_control_payload(
                    session["sessionKey"],
                    session["nonce"],
                    ciphertext=control_frame[1:],
                ).hex()

            # Persistent session: send follow-up control frames on the SAME
            # authenticated session (one auth, many commands) — this mirrors the
            # official app, which reads every setting inside one wake session.
            # Settings like volume/language only answer within the lock's presence
            # window, so re-authenticating per command (a fresh session each time)
            # misses that window; keeping one session open reads them reliably.
            if follow_up_ops and follow_up_out is not None:
                loop = asyncio.get_event_loop()
                for fop in follow_up_ops:
                    fwrite = build_lock_operation_write(fop)
                    fenc = encrypt_control_payload(
                        session["sessionKey"], session["nonce"], plaintext=fwrite.payload
                    )
                    await client.write_gatt_char(
                        CONTROL_WRITE_UUID,
                        bytes((fwrite.write_prefix,)) + fenc,
                        response=False,
                    )
                    # Correlate the reply to THIS read by its opcode: the response
                    # to `<op> …` is `<op> 00 …`. The control notify channel also
                    # carries spontaneous state events (e.g. 0x1d/0xdd/0x15) that
                    # land in the same queue; matching by arrival order lets a
                    # stray event steal a read's slot and desync the whole burst.
                    # Drain until the opcode matches (or the window closes),
                    # forwarding non-matching frames to on_report if present.
                    want = fwrite.payload[0] if fwrite.payload else None
                    deadline = loop.time() + notify_timeout
                    fresp: str | None = None
                    while True:
                        remaining = deadline - loop.time()
                        if remaining <= 0:
                            break
                        try:
                            fframe = await asyncio.wait_for(
                                control_queue.get(), timeout=remaining
                            )
                        except TimeoutError:
                            break
                        if len(fframe) < 2:
                            continue
                        # A LONG (multi-fragment) reply is prefixed 0x3F on this
                        # Matter/MIOT lock — each fragment is `3f + dataType + seq +
                        # chunk`. REASSEMBLE the chunks (strip 3 header bytes each) up
                        # to seq==0xff, then do ONE CCM decrypt. Big reads (the
                        # user/credential table, SYNC_*_VALID_PERIOD) arrive this way.
                        # (An earlier 0xBF branch was dead code: the wire uses 0x3F.)
                        if fframe[0] == 0x3F:
                            chunks = [bytes(fframe[3:])]
                            last_seq = fframe[2] if len(fframe) >= 3 else 0xFF
                            while last_seq != 0xFF:
                                remaining = deadline - loop.time()
                                if remaining <= 0:
                                    break
                                try:
                                    nf = await asyncio.wait_for(
                                        control_queue.get(), timeout=remaining
                                    )
                                except TimeoutError:
                                    break
                                if len(nf) < 3 or nf[0] != 0x3F:
                                    continue
                                chunks.append(bytes(nf[3:]))
                                last_seq = nf[2]
                            try:
                                fresp = decrypt_control_payload(
                                    session["sessionKey"], session["nonce"],
                                    ciphertext=b"".join(chunks),
                                ).hex()
                            except Exception:
                                fresp = None
                            break
                        # SHORT (0x8x): single frame, strip 1 header byte. It may be
                        # the actual answer (e.g. finger-count) OR just a status ACK
                        # that precedes a LONG 0x3F data burst — keep it TENTATIVELY
                        # and keep draining for a 0x3F reply instead of returning here.
                        dec = decrypt_control_payload(
                            session["sessionKey"], session["nonce"], ciphertext=fframe[1:]
                        ).hex()
                        if want is None or dec[:2] == f"{want:02x}":
                            if fresp is None:
                                fresp = dec  # tentative; a 0x3F burst may still follow
                            continue
                        # spontaneous event / mismatched reply — don't lose it
                        if on_report is not None:
                            on_report("ff62", bytes.fromhex(dec))
                    follow_up_out.append((fwrite.operation, fresp))

            if listen_after > 0 and on_report is not None:
                # Feature 023: keep the connection open and forward every extra
                # frame — remaining control ff62 (decrypted) and report ff64/ff92
                # (raw) — until the window expires. This is how spontaneous state
                # reports / events (which arrive after the ACK, or on a manual /
                # keypad operation) become observable.
                loop = asyncio.get_running_loop()
                deadline = loop.time() + listen_after
                # Keep the lock pushing: it goes quiet ~30 s after the last
                # keepalive, so re-send the confirmed keepalive periodically (same
                # session key/nonce as the initial command). Its ACK echoes the
                # 0x2f opcode and is filtered out below so it never reaches consumers.
                keepalive_write = bytes((0x01,)) + encrypt_control_payload(
                    session["sessionKey"],
                    session["nonce"],
                    plaintext=bytes.fromhex("2f012f"),
                )
                next_keepalive = loop.time() + LISTEN_KEEPALIVE_INTERVAL_S
                while True:
                    now = loop.time()
                    remaining = deadline - now
                    if remaining <= 0:
                        break
                    if now >= next_keepalive:
                        with contextlib.suppress(Exception):
                            await client.write_gatt_char(
                                CONTROL_WRITE_UUID, keepalive_write, response=False
                            )
                        next_keepalive = now + LISTEN_KEEPALIVE_INTERVAL_S
                    wait_timeout = min(remaining, max(0.1, next_keepalive - now))
                    get_control = asyncio.ensure_future(control_queue.get())
                    get_report = asyncio.ensure_future(report_queue.get())
                    done, pending = await asyncio.wait(
                        {get_control, get_report},
                        timeout=wait_timeout,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for fut in pending:
                        fut.cancel()
                    if get_control in done:
                        frame = get_control.result()
                        if len(frame) >= 2:
                            decoded = decrypt_control_payload(
                                session["sessionKey"],
                                session["nonce"],
                                ciphertext=frame[1:],
                            )
                            # Drop the keepalive's own ACK (echoes 0x2f).
                            if not decoded or decoded[0] != 0x2F:
                                on_report("ff62", decoded)
                    if get_report in done:
                        channel, data = get_report.result()
                        on_report(channel, data)

            material = SessionMaterial(
                session_key_hex=session["sessionKey"],
                nonce_hex=session["nonce"],
                verify_data_hex=session["verifyData"],
                lock_public_key_hex=lock_key_message.body.hex(),
            )
            return material, write, decrypted_response_hex
        finally:
            for uuid in PRE_AUTH_NOTIFY_ORDER:
                with contextlib.suppress(Exception):
                    await client.stop_notify(uuid)
    finally:
        # Feature 012: Release concurrency control flag
        _device_operation_in_progress[device_id] = False
