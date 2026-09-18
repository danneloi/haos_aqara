"""High-level U200 client — the facade of the library (feature 015).

Composes the pieces that already exist into one flow, without touching the
protocol layer:

    login (CloudAuthManager, feature 014, incl. auto re-auth on code 108)
      → scan & identify (transport.scan → ScanCandidate, see scanner.py)
      → connect + GATT discovery (Transport.connect → GattClient)
      → operation (session.run_authenticated_lock_operation)

Usage::

    auth = CloudAuthManager(account=..., password=..., appid=..., appkey=...,
                            client_id=..., phone_id=..., region="EU")
    async with await U200Client.connect(auth=auth, transport=BleakTransport(),
                                        device_id="lumi1.xxxx") as lock:
        await lock.lock()

Every phase is bounded by a timeout and failures carry the phase they happened
in (`U200ClientError.phase`). No secret (password, token, session key) is ever
logged or shown in `repr`.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .auth import CloudAuthManager
from .errors import AmbiguousDeviceError, FlowPhase, NoDeviceFoundError, U200ClientError
from .gatt import GattClient
from .kdf import REGION_BASE_URLS, CloudServiceError, cloud_get_public_key
from .lock_ops import (
    LockOperation,
    LockOperationWrite,
    build_abort_enrol,
    build_add_visitor_password,
    build_control_query_write,
    build_delete_user,
    build_read_query_write,
    build_set_alarm_volume,
    build_set_alert_delay,
    build_set_alert_volume,
    build_set_auto_lock_on_close_delay_time,
    build_set_auto_lockup_delay_time,
    build_set_auxiliary_locking_on_close_enabled,
    build_set_auxiliary_locking_relock_enabled,
    build_set_language_deutsch,
    build_set_language_english,
    build_set_verify_fail_time,
    build_start_enrol,
    normalize_lock_operation,
)
from .lock_state import (
    SOURCE_BATTERY,
    SOURCE_KEEPALIVE,
    SOURCE_OPERATION,
    SOURCE_QUERY,
    LockEvent,
    LockSettings,
    LockState,
    decode_alarm_volume,
    decode_alert_volume,
    decode_assist_turn,
    decode_battery_info,
    decode_door_type,
    decode_event,
    decode_front_connection,
    decode_language,
    decode_lock_state,
    decode_lock_status,
    decode_lock_volume,
    decode_pull_spring,
    decode_state_report,
)
from .ota import VoicePackResult, run_voice_pack_ota
from .scanner import scan, select_preferred
from .session import (
    OperationInProgressError,
    PostAuthContext,
    SessionMaterial,
    run_authenticated_lock_operation,
)
from .transport import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_SCAN_TIMEOUT,
    DISCONNECT_TIMEOUT,
    ScanCandidate,
    Transport,
)

if TYPE_CHECKING:
    # Return-type-only; the runtime imports live inside the methods that use them
    # to keep them off the module-load path (see read_user_table / read_access_log).
    from .access_log import AccessLogEntry, SyncLogRecord
    from .user_table import UserCredential


@dataclass(frozen=True)
class OperationResult:
    """What one operation produced (returned by `U200Client.operate`)."""

    operation: LockOperation
    response_hex: str | None
    write: LockOperationWrite
    session: SessionMaterial
    #: Real bolt position observed on the ff62 report channel during a
    #: post-command listen window (True locked / False unlocked / None not seen).
    observed_locked: bool | None = None

    @property
    def state(self) -> LockState:
        """The lock's response to this operation, as a `LockState`."""

        raw = bytes.fromhex(self.response_hex) if self.response_hex else None
        return decode_lock_state(raw, source=SOURCE_OPERATION)


class U200Client:
    """A connected U200. Build it with `connect()` (full flow) or `from_gatt()`."""

    def __init__(
        self,
        *,
        auth: CloudAuthManager,
        transport: Transport | None,
        gatt_client: GattClient,
        device_id: str,
        region: str = "EU",
        base_url: str | None = None,
        notify_timeout: float = 10.0,
        candidate: ScanCandidate | None = None,
        ltmk: bytes | None = None,
    ) -> None:
        self.auth = auth
        self.transport = transport
        self.device_id = device_id
        self.region = region
        self.base_url = base_url
        self.notify_timeout = notify_timeout
        self.candidate = candidate
        # 32-byte LTMK → offline (cloud-cut) session derivation; None → cloud path.
        self._ltmk = ltmk
        self._gatt: GattClient | None = gatt_client
        self._closed = False

    # ── construction ────────────────────────────────────────────────────────

    @classmethod
    async def connect(
        cls,
        *,
        auth: CloudAuthManager,
        transport: Transport,
        device_id: str,
        mac: str | None = None,
        region: str = "EU",
        base_url: str | None = None,
        scan_timeout: float = DEFAULT_SCAN_TIMEOUT,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        notify_timeout: float = 10.0,
        login_first: bool = True,
        ltmk: bytes | None = None,
    ) -> U200Client:
        """Run login → scan/identify → connect/discover and return a ready client.

        ``mac`` given → the transport connects straight to that address (a
        transport that cannot connect by address, e.g. CoreBluetooth, scans
        internally filtering by it). Without ``mac`` the transport scans and
        `select_preferred` picks the lock by name/services; a device that only
        shares the manufacturer id is never chosen automatically.

        ``login_first`` validates the credentials up front (fase LOGIN) so a bad
        password fails before touching the radio; the operation flow re-uses the
        cached token and refreshes it on code 108 by itself.
        """

        if ltmk is not None:
            login_first = False  # offline (cloud-cut): no cloud login needed
        if login_first:
            try:
                await asyncio.to_thread(auth.build_signer)
            except CloudServiceError:
                raise
            except Exception as exc:
                raise U200ClientError(FlowPhase.LOGIN, str(exc)) from exc

        candidate: ScanCandidate | None = None
        target: ScanCandidate | str
        if mac is not None:
            target = mac
        else:
            try:
                candidates = await scan(transport, timeout=scan_timeout)
            except U200ClientError:
                raise
            except Exception as exc:
                raise U200ClientError(FlowPhase.SCAN, str(exc)) from exc
            candidate = select_preferred(candidates)
            target = candidate

        try:
            gatt = await asyncio.wait_for(
                transport.connect(target, timeout=connect_timeout),
                timeout=connect_timeout + 1.0,
            )
        except Exception as exc:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(transport.disconnect(), timeout=DISCONNECT_TIMEOUT)
            raise U200ClientError(
                FlowPhase.CONNECT, f"no se pudo conectar/descubrir ({transport.name}): {exc}"
            ) from exc

        return cls(
            auth=auth,
            transport=transport,
            gatt_client=gatt,
            device_id=device_id,
            region=region,
            base_url=base_url,
            notify_timeout=notify_timeout,
            candidate=candidate,
            ltmk=ltmk,
        )

    @classmethod
    def from_gatt(
        cls,
        *,
        auth: CloudAuthManager,
        gatt_client: GattClient,
        device_id: str,
        region: str = "EU",
        base_url: str | None = None,
        notify_timeout: float = 10.0,
        ltmk: bytes | None = None,
    ) -> U200Client:
        """Wrap an already-connected GATT client (tests, Home Assistant, …)."""

        return cls(
            auth=auth,
            transport=None,
            gatt_client=gatt_client,
            device_id=device_id,
            region=region,
            base_url=base_url,
            notify_timeout=notify_timeout,
            ltmk=ltmk,
        )

    # ── operations ──────────────────────────────────────────────────────────

    @property
    def connected(self) -> bool:
        return self._gatt is not None and not self._closed

    async def operate(
        self, operation: LockOperation | str, *, listen_after: float = 0.0
    ) -> OperationResult:
        """Run any catalogued `LockOperation` (by member, name or hex value).

        With ``listen_after > 0`` the session stays open that many seconds after
        the command and reads the lock's real bolt position from the ff62 report
        channel — ``OperationResult.observed_locked`` carries it (True/False, or
        None if nothing was pushed in the window).
        """

        if not self.connected or self._gatt is None:
            raise U200ClientError(
                FlowPhase.OPERATION, "el cliente está cerrado/desconectado; vuelve a conectar"
            )
        op = normalize_lock_operation(operation)
        observed: list[bool] = []

        def on_report(channel: str, data: bytes) -> None:
            if channel == "ff62":
                position = decode_state_report(data)
                if position is not None:
                    observed.append(position)

        try:
            material, write, response = await run_authenticated_lock_operation(
                client=self._gatt,
                device_id=self.device_id,
                auth_headers=None,
                region=self.region,
                base_url=self.base_url,
                operation=op,
                notify_timeout=self.notify_timeout,
                auth=self.auth,
                ltmk=self._ltmk,
                listen_after=listen_after,
                on_report=on_report if listen_after > 0 else None,
            )
        except (OperationInProgressError, CloudServiceError, U200ClientError):
            raise
        except Exception as exc:
            raise U200ClientError(FlowPhase.OPERATION, f"{op.name}: {exc}") from exc
        return OperationResult(
            operation=op,
            response_hex=response,
            write=write,
            session=material,
            observed_locked=observed[-1] if observed else None,
        )

    async def push_voice_pack_ota(
        self,
        blob: bytes,
        filename: str,
        *,
        arm: bool = True,
        data_delay: float = 0.006,
        window: int = 3,
        resume_from: int = 0,
        skip_manifest: bool = False,
        manifest_wait_s: float = 90.0,
        post_manifest_settle_s: float = 4.0,
        keepalive_every_s: float = 8.0,
        precomputed_cloud_pubkey: str | None = None,
        language_name: str | None = None,
        progress: Any = None,
    ) -> VoicePackResult:
        """Push a language voice-pack OTA FROM SCRATCH (not a replay) inside an
        authenticated session — builds the JSON handshake + manifest + XMODEM
        data stream from ``blob`` and drives :func:`run_voice_pack_ota`.
        ``filename`` is the CDN name (e.g. ``U200_ES_audio_burn.bin``)."""

        if not self.connected or self._gatt is None:
            raise U200ClientError(
                FlowPhase.OPERATION, "el cliente está cerrado/desconectado; vuelve a conectar"
            )

        result_box: list[VoicePackResult] = []

        async def _hook(ctx: PostAuthContext) -> None:
            result_box.append(
                await run_voice_pack_ota(
                    ctx, blob, filename, arm=arm, data_delay=data_delay, window=window,
                    resume_from=resume_from, skip_manifest=skip_manifest,
                    manifest_wait_s=manifest_wait_s, keepalive_every_s=keepalive_every_s,
                    post_manifest_settle_s=post_manifest_settle_s,
                    language_name=language_name, progress=progress
                )
            )

        try:
            await run_authenticated_lock_operation(
                client=self._gatt,
                device_id=self.device_id,
                auth_headers=None,
                region=self.region,
                base_url=self.base_url,
                operation=LockOperation.KEEPALIVE,  # placeholder; never sent (post_auth)
                notify_timeout=self.notify_timeout,
                auth=self.auth,
                ltmk=self._ltmk,
                post_auth=_hook,
                precomputed_cloud_pubkey=precomputed_cloud_pubkey,
            )
        except (OperationInProgressError, CloudServiceError, U200ClientError):
            raise
        except Exception as exc:
            raise U200ClientError(FlowPhase.OPERATION, f"voice-pack-ota: {exc}") from exc
        if not result_box:
            raise U200ClientError(FlowPhase.OPERATION, "voice-pack-ota: el hook no produjo resultado")
        return result_box[0]

    async def change_language(
        self, language: str, *, verify_md5: bool = True, **ota_kwargs: Any
    ) -> VoicePackResult:
        """Switch the lock's spoken-prompt language end-to-end, phone-free: look the
        pack up in the cloud voice list, download it from the CDN, then stream it to
        the lock with :meth:`push_voice_pack_ota`.

        ``language`` accepts the cloud code ("13"), the display name ("Español"), or
        the file-name code ("ES") — see :func:`aqara_ble.voice_ota.select_voice_pack`.
        Extra keyword args pass straight through to ``push_voice_pack_ota`` (e.g.
        ``data_delay``, ``window``, ``manifest_wait_s``).

        **Keypad presence is required and is the CALLER's job — not the library's.**
        A language change is a settings-class op: the lock only ACKs the manifest
        while a keypad key was pressed within its short presence window. The library
        does not (and cannot) press the keypad — pressing it is an external, physical
        act specific to the deployment (e.g. a fingerbot on the keypad, driven by Home
        Assistant). This call just holds the manifest handshake open for
        ``manifest_wait_s`` (default 90 s), re-sending it, so a single press landed
        anywhere in that window authorises the whole ~10-minute transfer. Arrange that
        press to happen after this coroutine starts and within ``manifest_wait_s``.
        """
        from .voice_ota import (  # noqa: PLC0415 - cloud/HTTP, only needed here
            cloud_get_voice_list,
            download_voice_pack,
            select_voice_pack,
        )

        signer = await asyncio.to_thread(self.auth.build_signer)
        base_url = self.base_url or REGION_BASE_URLS.get(self.region, REGION_BASE_URLS["EU"])
        rows = await asyncio.to_thread(cloud_get_voice_list, self.device_id, base_url, signer)
        pack = select_voice_pack(rows, language)
        blob = await asyncio.to_thread(download_voice_pack, pack, verify=verify_md5)
        # Pre-fetch the ephemeral cloud pubkey so the on-lock auth is instant once
        # connected — the manifest's keypad-presence window is short.
        pubkey = ota_kwargs.pop("precomputed_cloud_pubkey", None)
        if pubkey is None:
            pubkey = await asyncio.to_thread(
                cloud_get_public_key, self.device_id, None, base_url, signer
            )
        return await self.push_voice_pack_ota(
            blob, pack.file_name, language_name=pack.name or None,
            precomputed_cloud_pubkey=pubkey, **ota_kwargs
        )

    async def lock(self, *, listen_after: float = 0.0) -> str | None:
        return (await self.operate(LockOperation.LOCK, listen_after=listen_after)).response_hex

    async def unlock(self, *, listen_after: float = 0.0) -> str | None:
        return (await self.operate(LockOperation.UNLOCK, listen_after=listen_after)).response_hex

    async def status(self) -> LockState:
        """Read the lock state without actuating, via the confirmed keepalive poll.

        Sends only the read-only KEEPALIVE command (never an unconfirmed status
        opcode) and returns a `LockState` wrapping the decrypted response. Decoded
        fields stay ``None`` until confirmed by evidence — see `lock_state`.
        """

        result = await self.operate(LockOperation.KEEPALIVE)
        raw = bytes.fromhex(result.response_hex) if result.response_hex else None
        return decode_lock_state(raw, source=SOURCE_KEEPALIVE)

    async def listen(
        self,
        seconds: float = 15.0,
        *,
        on_state: Callable[[bool], None] | None = None,
        on_event: Callable[[LockEvent], None] | None = None,
        low_power: bool = False,
    ) -> list[tuple[str, str]]:
        """Keep the session open after a keepalive and collect spontaneous frames.

        Returns ``(channel, hex)`` for every extra frame the lock pushes within the
        window — control ff62 (decrypted), report ff64/ff92 (raw). Non-actuating
        (uses the keepalive poll).

        ``on_state`` fires **in real time** with the decoded bolt position each
        time the lock pushes an ff62 position report (0x1d/0xdd) — this is how a
        consumer keeps a persistent, real-time state session. ``low_power``
        requests a slow connection interval + slave latency, but **only transports
        that expose ``update_connection_parameters`` honour it** (the Bumble /
        ESP32-S3 central). Plain ``bleak`` — both CoreBluetooth and BlueZ — does
        not expose that call, so on a Home Assistant host the OS/controller (or a
        Bluetooth proxy) decides the interval; the request is a no-op there.
        """

        if not self.connected or self._gatt is None:
            raise U200ClientError(FlowPhase.OPERATION, "el cliente está cerrado; vuelve a conectar")
        reports: list[tuple[str, str]] = []

        def collect(channel: str, data: bytes) -> None:
            reports.append((channel, data.hex()))
            if channel != "ff62":
                return
            if on_state is not None:
                position = decode_state_report(data)
                if position is not None:
                    on_state(position)
            if on_event is not None:
                event = decode_event(data)
                if event is not None:
                    on_event(event)

        try:
            await run_authenticated_lock_operation(
                client=self._gatt,
                device_id=self.device_id,
                auth_headers=None,
                region=self.region,
                base_url=self.base_url,
                operation=LockOperation.KEEPALIVE,
                notify_timeout=self.notify_timeout,
                auth=self.auth,
                ltmk=self._ltmk,
                listen_after=seconds,
                on_report=collect,
                low_power_connection=low_power,
            )
        except (OperationInProgressError, CloudServiceError, U200ClientError):
            raise
        except Exception as exc:
            raise U200ClientError(FlowPhase.OPERATION, f"listen: {exc}") from exc
        return reports

    async def query(self, sub_cmd: int, data: bytes = b"") -> LockState:
        """Send a generic control opcode and return its decrypted response as state.

        Intended for probing **read-only** status opcodes (e.g. 0x07 LOCK_STATUS,
        0xE5 GET_DOOR_LOCK_STATUS) whose response may carry the bolt position,
        unlike the static keepalive/operate ACKs. The caller is responsible for
        sending only read-only opcodes (the CLI restricts this to a whitelist).
        """

        if not self.connected or self._gatt is None:
            raise U200ClientError(FlowPhase.OPERATION, "el cliente está cerrado; vuelve a conectar")
        write = build_control_query_write(sub_cmd, data)
        try:
            _material, _write, response = await run_authenticated_lock_operation(
                client=self._gatt,
                device_id=self.device_id,
                auth_headers=None,
                region=self.region,
                base_url=self.base_url,
                operation=write,
                notify_timeout=self.notify_timeout,
                auth=self.auth,
                ltmk=self._ltmk,
            )
        except (OperationInProgressError, CloudServiceError, U200ClientError):
            raise
        except Exception as exc:
            raise U200ClientError(FlowPhase.OPERATION, f"query 0x{sub_cmd:02x}: {exc}") from exc
        raw = bytes.fromhex(response) if response else None
        return decode_lock_state(raw, source=SOURCE_QUERY)

    async def battery(self) -> LockState:
        """Read the lock's battery over BLE (GET_BATTERY_INFO, 0xde).

        Sends the well-formed read frame `de 00 <trailer>` (see
        :func:`build_read_query_write`) and returns a :class:`LockState` whose
        ``battery_percent`` is decoded from the reply. Confirmed live: the lock
        answers `de0007000101300000c70a` → 48% (feature 030). Returns
        ``responded=False`` if the lock does not answer.
        """

        if not self.connected or self._gatt is None:
            raise U200ClientError(FlowPhase.OPERATION, "el cliente está cerrado; vuelve a conectar")
        write = build_read_query_write(0xDE)
        try:
            _material, _write, response = await run_authenticated_lock_operation(
                client=self._gatt,
                device_id=self.device_id,
                auth_headers=None,
                region=self.region,
                base_url=self.base_url,
                operation=write,
                notify_timeout=self.notify_timeout,
                auth=self.auth,
                ltmk=self._ltmk,
            )
        except (OperationInProgressError, CloudServiceError, U200ClientError):
            raise
        except Exception as exc:
            raise U200ClientError(FlowPhase.OPERATION, f"battery read: {exc}") from exc
        raw = bytes.fromhex(response) if response else None
        return LockState(
            raw_hex=raw.hex() if raw else None,
            source=SOURCE_BATTERY,
            responded=raw is not None,
            battery_percent=decode_battery_info(raw),
        )

    async def read_lock_status(self) -> LockState:
        """Read the real bolt position on demand over BLE (LOCK_STATUS, 0x07).

        Sends the well-formed read frame `07 00 <trailer>` and returns a
        :class:`LockState` whose ``locked`` is decoded from bit 0x02 of the status
        byte (confirmed live, correlated with ff62). Unlike :meth:`status`
        (keepalive, static), this reports the actual bolt position without waiting
        for a spontaneous ff62 report. Returns ``responded=False`` if unanswered.
        """

        if not self.connected or self._gatt is None:
            raise U200ClientError(FlowPhase.OPERATION, "el cliente está cerrado; vuelve a conectar")
        write = build_read_query_write(0x07)
        try:
            _material, _write, response = await run_authenticated_lock_operation(
                client=self._gatt,
                device_id=self.device_id,
                auth_headers=None,
                region=self.region,
                base_url=self.base_url,
                operation=write,
                notify_timeout=self.notify_timeout,
                auth=self.auth,
                ltmk=self._ltmk,
            )
        except (OperationInProgressError, CloudServiceError, U200ClientError):
            raise
        except Exception as exc:
            raise U200ClientError(FlowPhase.OPERATION, f"lock-status read: {exc}") from exc
        raw = bytes.fromhex(response) if response else None
        return LockState(
            raw_hex=raw.hex() if raw else None,
            source=SOURCE_QUERY,
            responded=raw is not None,
            locked=decode_lock_status(raw),
        )

    async def read(self, opcode: int) -> LockState:
        """Read any SYSTEM read opcode over BLE and return the decrypted response.

        Sends the well-formed read frame `<opcode> 00 <trailer>` and returns a
        :class:`LockState` with the raw hex; ``locked`` and ``battery_percent`` are
        filled in when ``opcode`` is LOCK_STATUS (0x07) / GET_BATTERY_INFO (0xde).
        Intended for **read-only** opcodes — see
        :func:`aqara_ble.operations_catalog.system_read_opcodes`; the caller is
        responsible for not passing a mutating opcode.
        """

        if not self.connected or self._gatt is None:
            raise U200ClientError(FlowPhase.OPERATION, "el cliente está cerrado; vuelve a conectar")
        write = build_read_query_write(opcode)
        try:
            _material, _write, response = await run_authenticated_lock_operation(
                client=self._gatt,
                device_id=self.device_id,
                auth_headers=None,
                region=self.region,
                base_url=self.base_url,
                operation=write,
                notify_timeout=self.notify_timeout,
                auth=self.auth,
                ltmk=self._ltmk,
            )
        except (OperationInProgressError, CloudServiceError, U200ClientError):
            raise
        except Exception as exc:
            raise U200ClientError(FlowPhase.OPERATION, f"read 0x{opcode:02x}: {exc}") from exc
        raw = bytes.fromhex(response) if response else None
        return LockState(
            raw_hex=raw.hex() if raw else None,
            source=SOURCE_QUERY,
            responded=raw is not None,
            locked=decode_lock_status(raw),
            battery_percent=decode_battery_info(raw),
        )

    async def _read_raw(self, opcode: int) -> bytes | None:
        st = await self.read(opcode)
        return bytes.fromhex(st.raw_hex) if st.raw_hex else None

    async def read_burst(self, frames_hex: list[str]) -> list[tuple[str, str | None]]:
        """Read many control frames in ONE authenticated session (persistent).

        Each item in ``frames_hex`` is a raw plaintext control frame in hex — the
        bytes fed to AES-CCM (e.g. ``"c3044301"`` = volume, opcode 0xc3 / kind 0x04).
        An item may carry an explicit **write-prefix** as ``"PP:frame"`` (hex),
        e.g. ``"03:200320"`` for finger count — the ff61 write byte differs per op
        family: volume/language/alarm/lock-setting use ``01`` (the default), while
        finger `0x20`, log-sync `0x13`, `0x1f` and voice-OTA `0xa6` use ``03`` (from
        the app's decrypted session). Authenticates once and sends them all on the
        same session, mirroring the official app. Returns ``(spec, response_hex_or_
        None)`` for each, in order. Run within ~40 s of a wake.
        """
        if not self.connected or self._gatt is None:
            raise U200ClientError(FlowPhase.OPERATION, "el cliente está cerrado; vuelve a conectar")
        if not frames_hex:
            return []
        from .lock_ops import LockOperationWrite  # noqa: PLC0415

        def _mk(spec: str) -> LockOperationWrite:
            prefix = 0x01
            fh = spec
            if ":" in spec:
                pfx, fh = spec.split(":", 1)
                prefix = int(pfx, 16)
            return LockOperationWrite(
                operation=f"burst:{spec}", payload=bytes.fromhex(fh), write_prefix=prefix
            )

        # Route EVERY read through the follow-up path, which correlates each reply
        # to its request by opcode and discards spontaneous state events (0x1d/
        # 0xdd/0x15) that share the notify channel. A harmless keepalive is the
        # primary op (its reply is not opcode-checked, so it must not be a real
        # read — otherwise a stray event could steal it).
        primary = _mk("2f012f")  # keepalive, never actuation
        follow_ups = [_mk(fh) for fh in frames_hex]
        follow_out: list[tuple[object, str | None]] = []
        try:
            await run_authenticated_lock_operation(
                client=self._gatt,
                device_id=self.device_id,
                auth_headers=None,
                region=self.region,
                base_url=self.base_url,
                operation=primary,
                notify_timeout=self.notify_timeout,
                auth=self.auth,
                ltmk=self._ltmk,
                follow_up_ops=follow_ups,
                follow_up_out=follow_out,
            )
        except (OperationInProgressError, CloudServiceError, U200ClientError):
            raise
        except Exception as exc:
            raise U200ClientError(FlowPhase.OPERATION, f"read_burst: {exc}") from exc
        out: list[tuple[str, str | None]] = []
        for fh, (_op, resp) in zip(frames_hex, follow_out, strict=False):
            out.append((fh, resp))
        return out

    async def read_settings(self) -> LockSettings:
        """Read the configuration settings over BLE in ONE persistent session.

        Reads volume (0xc3), language (0x68), alarm volume (0x84) and the
        lock-setting blob (0x1a — carries the alert volume) in a single
        opcode-correlated burst, mirroring the official app. Returns a
        :class:`LockSettings`; a field is ``None`` if that opcode did not answer.
        Requires a live connection (wake the lock's radio to connect; no per-read
        keypad touch is needed once connected).
        """
        frames = ["c3044301", "680168", "84020407", "1a011a"]
        results = dict(await self.read_burst(frames))

        def _raw(frame: str) -> bytes | None:
            resp = results.get(frame)
            return bytes.fromhex(resp) if resp else None

        return LockSettings(
            alert_volume=decode_alert_volume(_raw("1a011a")),
            system_volume=decode_lock_volume(_raw("c3044301")),
            language=decode_language(_raw("680168")),
            alarm_volume=decode_alarm_volume(_raw("84020407")),
            raw={f: results.get(f) for f in frames},
        )

    async def read_door_type(self) -> str | None:
        """Read the configured door-lock type over BLE ('eu'/'uk'/'us'; 0xe0)."""
        return decode_door_type(await self._read_raw(0xE0))

    async def read_assist_turn(self) -> bool | None:
        """Read whether turn-assist is enabled over BLE (0xe9)."""
        return decode_assist_turn(await self._read_raw(0xE9))

    async def read_pull_spring(self) -> tuple[bool, int] | None:
        """Read the pull-spring setting over BLE → (enabled, retraction_seconds) (0xe4)."""
        return decode_pull_spring(await self._read_raw(0xE4))

    async def read_front_connection(self) -> bool | None:
        """Is the keypad (front panel) present right now? (GET_FRONT_CONNECTION 0xdd).

        Read from the always-on lock — no keypad wake needed. ``True`` = keypad
        present/tunnel up (front_connection=01), ``False`` = absent. Use it before a
        voice OTA to decide whether a keypad press is even needed. Confirmed live
        2026-09-07 (0x00→0x01 on a fingerbot press).
        """
        return decode_front_connection(await self._read_raw(0xDD))

    async def read_user_table(self) -> list[UserCredential]:
        """Read the user/credential table over BLE (MIOT SYNC_USER_ID_VALID_PERIOD 0x1f).

        Returns the credential list (userId, type — fingerprint/password/NFC —,
        validity). The lock NEVER returns the PIN plaintext, only its id/type. The
        credential store lives in the sleeping front panel, so wake it first. Works
        over the OFFLINE session (no cloud) when the client carries an LTMK; the
        LONG (0x3f) reply is reassembled in session.py. Validated live against the
        cloud table (`/dev/lock/query`): same count and types.
        """
        from .user_table import USER_TABLE_FRAME, decode_user_table  # noqa: PLC0415

        results = dict(await self.read_burst([USER_TABLE_FRAME]))
        blob = results.get(USER_TABLE_FRAME)
        return decode_user_table(blob) if blob else []

    async def read_access_log(self, start: int = 0, end: int = 59) -> list[AccessLogEntry]:
        """Read the stored access log over BLE (SYNC_LOG 0x13) — offline-capable.

        The log is stored in the always-on lock (back panel), so this needs NO
        keypad/front-panel wake. Returns the decoded entries covering the
        requested index range, newest first: method (for credential opens),
        user id and timestamp. See ``access_log`` and the read-spec doc.

        CONFIRMED 2026-09-08: the lock's SYNC_LOG request needs a 2-byte
        trailer that is a function of the exact 30-record page — a
        non-page-aligned or trailer-less request (the old behaviour here) is
        silently answered with page 0 (the newest 30) no matter what ``end``
        was asked for, so ``read_access_log(0, 49)`` never actually saw
        records 30–48. This now always requests whole, trailer-complete
        pages (:func:`aqara_ble.access_log.iter_pages`) in ONE session and
        merges them — e.g. the default 0..59 fetches pages (0,29) and
        (30,59) together, covering the newest 60 records instead of being
        silently clamped to 30.
        """
        from .access_log import build_access_log_frame, decode_access_log, iter_pages  # noqa: PLC0415

        pages = iter_pages(start, end)
        specs = [build_access_log_frame(p_start, p_end) for p_start, p_end in pages]
        results = dict(await self.read_burst(specs))
        entries: list[AccessLogEntry] = []
        seen: set[str] = set()
        for spec in specs:
            reply = results.get(spec)
            if not reply:
                continue
            for entry in decode_access_log(reply):
                if entry.raw_hex in seen:
                    continue
                seen.add(entry.raw_hex)
                entries.append(entry)
        entries.sort(key=lambda e: e.timestamp, reverse=True)
        return entries

    async def read_recent_sync_log(self) -> list[SyncLogRecord]:
        """Legacy/compat wrapper: newest SYNC_LOG page as old-shape records.

        `haos_aqara` (the Home Assistant integration) was written against an
        earlier, page-oriented SYNC_LOG decoder (`SyncLogRecord`) before this
        library grew the more general `read_access_log()`/`AccessLogEntry`.
        Rather than have two competing decoders, this just fetches the
        newest page via `read_access_log(0, 29)` and adapts each entry — see
        `access_log.sync_log_record_from_entry`. Prefer `read_access_log()`
        directly in new code.
        """
        from .access_log import sync_log_record_from_entry  # noqa: PLC0415

        entries = await self.read_access_log(0, 29)
        return [sync_log_record_from_entry(e) for e in entries]

    # ── writes / settings (offline-capable app emulation) ────────────────────

    async def _send_write(self, write: LockOperationWrite) -> str | None:
        """Send one SET/enrol frame in an authenticated session; return its reply.

        Reuses ``read_burst`` (opcode-correlated) as the generic "send one frame,
        get its reply" primitive — a SET is answered the same way a read is. A
        ``None`` reply does not always mean failure (the lock's own state events
        share the notify channel), but a non-empty reply confirms the write
        landed. Works over the OFFLINE session when the client carries an LTMK.
        """
        spec = f"{write.write_prefix:02x}:{write.payload.hex()}"
        results = await self.read_burst([spec])
        return results[0][1] if results else None

    async def add_visitor_password(self, pin: str, group_id: int = 1) -> str | None:
        """Enrol a visitor PIN over BLE (offline-capable). Reply carries status 0x00."""
        return await self._send_write(build_add_visitor_password(pin, group_id))

    async def delete_user(self, user_id: int) -> str | None:
        """Delete a user + all their credentials over BLE (offline-capable).

        ``user_id`` is the lock's full 32-bit user id — the same value the cloud
        ``/dev/lock/query`` reports and the access log carries (LE-decoded). Removes
        the whole user entry (for a visitor password, its own user → deletes that
        PIN). Needs the keypad (front panel) AWAKE — the credential DB is fronted by
        the sleeping keypad panel, so add/delete/table-read all need a wake first
        (confirmed live: deletes with it asleep had no effect). The reply is not
        opcode-correlated (``None`` is normal); confirm via :meth:`read_user_table`.
        See :func:`aqara_ble.lock_ops.build_delete_user`.
        """
        return await self._send_write(build_delete_user(user_id))

    async def start_enrol(self, user_group_id: int, kind: str = "finger") -> str | None:
        """Send the ADD_USER start frame for a fingerprint/NFC enrol (low-level).

        Prefer :meth:`enrol_credential`, which also drives the report loop. See
        :func:`aqara_ble.lock_ops.build_start_enrol`.
        """
        return await self._send_write(build_start_enrol(user_group_id, kind))

    async def abort_enrol(self, user_group_id: int) -> str | None:
        """Cancel an in-progress enrol (QUITE_ADD_USER). See ``build_abort_enrol``."""
        return await self._send_write(build_abort_enrol(user_group_id))

    async def enrol_credential(
        self,
        user_group_id: int,
        kind: str = "finger",
        *,
        on_report: Callable[[object], None] | None = None,
        timeout: float = 60.0,
        chunk: float = 6.0,
    ) -> object | None:
        """Drive a fingerprint/NFC enrol: send start, decode the report loop.

        Sends ``ADD_USER`` then listens for the lock's interactive reports,
        decoding each with :func:`aqara_ble.enrol.decode_enrol_report` and passing
        it to ``on_report`` (progress presses, then completion). Returns the
        terminal ``EnrolReport`` (``kind`` ``"success"`` with the allocated
        ``credential_id``/``user_group_id``, else ``"failed"``/``"timeout"``), or
        ``None`` if nothing terminal arrived within ``timeout``.

        Interactive + physical: the front-panel sensor must be AWAKE and the person
        presents the finger (several times) or taps the card. On a caller cancel /
        no completion, sends the abort frame.

        ⚠️ Builders and the decoder are unit-tested, but this end-to-end driver is
        **not yet live-verified** — confirm against a real enrol before relying on
        the returned ``credential_id`` mapping.
        """
        from .enrol import decode_enrol_report  # noqa: PLC0415

        await self.start_enrol(user_group_id, kind)
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        terminal: object | None = None
        try:
            while loop.time() < deadline:
                frames = await self.listen(min(chunk, max(0.0, deadline - loop.time())))
                for _channel, data in frames:
                    report = decode_enrol_report(data)
                    if report is None:
                        continue
                    if on_report is not None:
                        on_report(report)
                    if report.kind in ("success", "failed", "timeout"):
                        terminal = report
                        return terminal
            return None
        finally:
            if terminal is None or getattr(terminal, "kind", None) != "success":
                with contextlib.suppress(Exception):
                    await self.abort_enrol(user_group_id)

    async def set_alert_volume(self, level: int) -> str | None:
        """Set the 4-level alert volume (1=Alto..4=Silencio)."""
        return await self._send_write(build_set_alert_volume(level))

    async def set_alarm_volume(self, *, silent: bool) -> str | None:
        """Set the alarm/siren volume (Normal or Silencio)."""
        return await self._send_write(build_set_alarm_volume(silent=silent))

    async def set_alert_delay(self, seconds: int) -> str | None:
        """Set the open-door alarm delay ("Retraso de alerta"), in seconds."""
        return await self._send_write(build_set_alert_delay(seconds))

    async def set_verify_fail_time(self, seconds: int) -> str | None:
        """Set the keypad-lockout duration after failed attempts, in seconds."""
        return await self._send_write(build_set_verify_fail_time(seconds))

    async def set_auto_lockup_delay(self, seconds: int) -> str | None:
        """Set the "Re-bloqueo de seguridad" auto re-lock delay, in seconds."""
        return await self._send_write(build_set_auto_lockup_delay_time(seconds))

    async def set_auto_lock_on_close_delay(self, seconds: int) -> str | None:
        """Set the "Bloqueo automático al cerrar" delay, in seconds."""
        return await self._send_write(build_set_auto_lock_on_close_delay_time(seconds))

    async def enable_auxiliary_locking_on_close(self) -> str | None:
        """Enable "Bloqueo automático al cerrar" (one-way; no disable frame captured)."""
        return await self._send_write(build_set_auxiliary_locking_on_close_enabled())

    async def enable_auxiliary_locking_relock(self) -> str | None:
        """Enable "Re-bloqueo de seguridad" (one-way; no disable frame captured)."""
        return await self._send_write(build_set_auxiliary_locking_relock_enabled())

    async def set_language_english(self) -> str | None:
        """Set the spoken-prompt language enum to English (0x03 code 0x02)."""
        return await self._send_write(build_set_language_english())

    async def set_language_deutsch(self) -> str | None:
        """Set the spoken-prompt language enum to German (0x03 code 0x09)."""
        return await self._send_write(build_set_language_deutsch())

    # ── lifecycle ───────────────────────────────────────────────────────────

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._gatt = None
        if self.transport is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.transport.disconnect(), timeout=DISCONNECT_TIMEOUT)

    async def __aenter__(self) -> U200Client:
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()

    def __repr__(self) -> str:
        transport = self.transport.name if self.transport is not None else "external"
        return (
            f"U200Client(device_id={self.device_id!r}, transport={transport!r}, "
            f"connected={self.connected})"
        )


__all__ = [
    "AmbiguousDeviceError",
    "FlowPhase",
    "NoDeviceFoundError",
    "OperationResult",
    "U200Client",
    "U200ClientError",
]
