"""Transport that drives the lock's BLE through an ESPHome ``bluetooth_proxy``.

Why this exists (2026-09-03, from a working capture): the language OTA is ~2 MB of
write-without-response traffic that must stream for ~8 minutes without the link
dropping. A capture of the official app doing it (``app_ota.log``) showed the two
things that make it work: a solid BLE stack that (a) holds the connection the whole
time and (b) paces WoR strictly — Android kept **0-1 ACL packets in flight** ~98% of
the time (never blasting, never overrunning the lock). macOS CoreBluetooth drops the
link at ~54 s; a raw ESP32-S3 HCI firmware corrupts ACL. An ESP32 running ESPHome
``bluetooth_proxy`` (NimBLE) is a solid stack like Android's.

Earlier this transport hand-rolled a UUID→handle adapter over raw aioesphomeapi and
got the v3 REMOTE_CACHING CCCD handling wrong (notifications never enabled → auth
timed out). This version instead drives the **reference client stack** every Home
Assistant proxy-BLE integration uses — ``bleak-esphome``'s ``ESPHomeClient`` (a real
:class:`bleak.BleakClient` backend) via ``habluetooth`` — so connection setup, MTU,
PHY, the v3 CCCD write, and notifications are all handled correctly. It hands back a
``BleakClient``, which the session layer already knows how to drive (same as the Mac
``bleak`` path), so ``run_authenticated_lock_operation`` / ``push_voice_pack_ota``
work over it unchanged.

Setup: the ESP32 runs ESPHome ``bluetooth_proxy`` (active connections) with API
encryption, positioned with decent BLE coverage to the lock (same as the phone must
be near the lock for the app). Provide ``AQARA_ESPHOME_HOST`` +
``AQARA_ESPHOME_NOISE_PSK``. Requires the ``bleak-esphome`` extra.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from .gatt import GattClient
from .transport import ScanCandidate


def mac_to_int(mac: str) -> int:
    """`AA:BB:CC:DD:EE:FF` → the 48-bit int aioesphomeapi expects."""
    return int(mac.replace(":", "").replace("-", ""), 16)


def _address_type_for(mac: str) -> int:
    """BLE address type for a MAC. The two most-significant bits of the first octet
    classify a random address: ``0b11`` = static random. The U200 advertises ``CA:…``
    (0b11) → static random (1); anything else → public (0)."""
    first = int(mac.split(":", maxsplit=1)[0], 16)
    return 1 if (first & 0xC0) == 0xC0 else 0


#: A habluetooth manager must be set exactly once per process; keep it here.
_MANAGER: Any = None


async def _ensure_manager() -> Any:
    """Bootstrap (once) the standalone ``habluetooth`` manager the ESPHome scanner
    registers into. HA ships its own subclass; a minimal one is enough here."""
    global _MANAGER  # noqa: PLW0603
    if _MANAGER is not None:
        return _MANAGER
    import habluetooth  # noqa: PLC0415
    from habluetooth import BluetoothManager  # noqa: PLC0415

    class _Manager(BluetoothManager):
        def _discover_service_info(self, service_info: Any) -> None:
            return None

    mgr = _Manager()
    await mgr.async_setup()
    habluetooth.set_manager(mgr)
    _MANAGER = mgr
    return mgr


class EsphomeProxyTransport:
    """Connect to the lock through an ESPHome ``bluetooth_proxy`` and hand back a
    real ``BleakClient`` (bleak-esphome's ``ESPHomeClient`` backend). Mirrors the
    ``BumbleTransport`` surface (``scan`` / ``connect`` / ``disconnect``)."""

    name = "esphome-proxy"

    def __init__(
        self,
        host: str,
        *,
        noise_psk: str | None = None,
        port: int = 6053,
        password: str = "",
        connect_timeout: float = 30.0,
        rssi_floor: int = -80,
    ) -> None:
        self._host = host
        self._noise_psk = noise_psk
        self._port = port
        self._password = password
        self._connect_timeout = connect_timeout
        # Connect only on an advert at/above this RSSI: a weak advert connects to an
        # unstable link that then fails GATT discovery (measured). A grace fallback
        # accepts any advert late so a consistently-weak lock still connects.
        self._rssi_floor = rssi_floor
        self._cli: Any = None
        self._scanner_data: Any = None
        self._unregister: Any = None
        self._client: Any = None

    async def scan(self, *, timeout: float = 30.0) -> list[ScanCandidate]:
        # The OTA path connects by MAC (U200Client.connect takes mac=), so the
        # advert-driven connect happens inside connect(); nothing to return here.
        return []

    async def _ensure_api(self) -> Any:
        if self._cli is not None:
            return self._cli
        from aioesphomeapi import APIClient  # noqa: PLC0415
        from bleak_esphome import connect_scanner  # noqa: PLC0415

        mgr = await _ensure_manager()
        cli = APIClient(self._host, self._port, self._password, noise_psk=self._noise_psk)
        await cli.connect(login=True)
        di = await cli.device_info()
        data = connect_scanner(cli, di, available=True)
        data.scanner.async_setup()
        self._unregister = mgr.async_register_scanner(data.scanner, connection_slots=3)
        self._cli = cli
        self._scanner_data = data
        return cli

    async def connect(self, target: ScanCandidate | str, *, timeout: float) -> GattClient:
        from habluetooth import HaBleakClientWrapper  # noqa: PLC0415

        mac = target.address if isinstance(target, ScanCandidate) else target
        mgr = await _ensure_manager()
        await self._ensure_api()

        # Wait for a strong advert of the lock (the scanner feeds the manager), then
        # let bleak-esphome connect over the proxy. HaBleakClientWrapper routes to the
        # ESPHomeClient backend, which does the v3 CCCD write, MTU 247 and 2M PHY.
        started = asyncio.get_running_loop().time()
        device = None
        deadline = started + timeout
        while asyncio.get_running_loop().time() < deadline:
            candidate = mgr.async_ble_device_from_address(mac, connectable=True)
            if candidate is not None:
                rssi = getattr(candidate, "rssi", None)
                grace = (asyncio.get_running_loop().time() - started) > (timeout * 0.6)
                if rssi is None or rssi >= self._rssi_floor or grace:
                    device = candidate
                    break
            await asyncio.sleep(0.5)
        if device is None:
            raise LookupError(f"lock {mac} not seen by the proxy (press the keypad / check coverage)")

        client = HaBleakClientWrapper(device)
        await asyncio.wait_for(client.connect(), timeout=self._connect_timeout)
        self._client = client

        # Dedicate the proxy's single radio to this connection for the ~8-minute
        # transfer: ACTIVE scanning (scan requests) time-shares the radio and
        # periodically corrupts blocks mid-stream → a 0x1115 NAK storm → abort
        # (~130-150 blocks in, reproducibly). The phone never has this because it
        # is not scanning while it streams. Drop the proxy to PASSIVE scanning for
        # the duration (restored on disconnect).
        with contextlib.suppress(Exception):
            from aioesphomeapi.model import BluetoothScannerMode  # noqa: PLC0415

            await self._cli.bluetooth_scanner_set_mode(BluetoothScannerMode.PASSIVE)
        # Pin a FAST connection interval (7.5-15 ms) for the transfer. This is THE
        # thing that makes the OTA stream survive over an ESPHome proxy: the ~2 MB is
        # WRITE_WITHOUT_RESPONSE, and the ESP32's gattc TX queue drains one write per
        # connection interval. At the idle 45 ms interval the queue fills faster than
        # it drains and the proxy silently drops a fragment ~80 writes (16 blocks) in
        # → block CRC fail → 0x1115 NAK → abort, reproducibly. The official app runs
        # the data phase at exactly these fast intervals (measured in the btsnoop:
        # LE connection interval = 6 and 12 units during streaming, 36 when idle), so
        # the queue never backs up. Units: interval x1.25 ms, timeout x10 ms.
        try:
            await self._cli.bluetooth_device_set_connection_params(
                mac_to_int(mac), min_interval=12, max_interval=12, latency=0, timeout=500,
            )
        except Exception as exc:
            # Non-fatal, but log it — a silently-swallowed failure here leaves the
            # link on the proxy's default params and it destabilises ~40 s in.
            print(f"[esphome] set_connection_params failed: {type(exc).__name__}: {exc}")
        return client

    async def disconnect(self) -> None:
        if self._cli is not None:
            with contextlib.suppress(Exception):
                from aioesphomeapi.model import BluetoothScannerMode  # noqa: PLC0415

                await self._cli.bluetooth_scanner_set_mode(BluetoothScannerMode.ACTIVE)
        if self._client is not None:
            with contextlib.suppress(Exception):
                await self._client.disconnect()
            self._client = None
        if self._unregister is not None:
            with contextlib.suppress(Exception):
                self._unregister()
            self._unregister = None
        if self._cli is not None:
            with contextlib.suppress(Exception):
                await self._cli.disconnect()
            self._cli = None
