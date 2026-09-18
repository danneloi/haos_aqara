"""Adaptador GATT sobre Bumble (dependencia opcional) para reutilizar
`run_authenticated_lock_operation` sin bleak.

Bumble se usa cuando el transporte real es un controlador BLE externo (p.ej.
un ESP32-S3 por HCI serie) en vez del Bluetooth nativo del sistema, y porque
expone primitivas GATT de bajo nivel (Read By Type Request) que bleak no
soporta y que la cerradura necesita en el preámbulo pre-auth (ver
`session.GATT_CACHING_PREAMBLE_UUID16` y docs/reference/).

Movido aquí desde `tools/bumble_lock.py` (2026-08-11) para que sea
reutilizable como parte de la librería en vez de vivir solo en un script.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - solo para tipado, no fuerza el import
    from bumble.device import Peer


class BumbleGattAdapter:
    """Presenta la interfaz bleak (write_gatt_char/start_notify/stop_notify/
    read_by_type) sobre un `Peer` de Bumble, para que
    `run_authenticated_lock_operation` funcione igual con Bumble que con
    bleak real."""

    def __init__(self, peer: Peer) -> None:
        self.peer = peer

    def _find(self, uuid: str) -> Any:
        short = uuid.split("-", maxsplit=1)[0][-4:].lower()  # p.ej. ff07
        for svc in self.peer.services:
            for ch in svc.characteristics:
                cu = str(ch.uuid).lower().replace("0x", "")
                if cu == short or short in cu:
                    return ch
        raise KeyError(f"característica {uuid} no encontrada")

    async def write_gatt_char(self, uuid: str, data: bytes, response: bool = False) -> None:
        ch = self._find(uuid)
        await self.peer.write_value(ch, bytes(data), with_response=response)

    async def start_notify(self, uuid: str, callback: Any) -> None:
        ch = self._find(uuid)
        await self.peer.subscribe(ch, lambda value: callback(None, bytearray(value)))

    async def stop_notify(self, uuid: str) -> None:
        try:
            ch = self._find(uuid)
            await self.peer.unsubscribe(ch)
        except Exception:
            pass

    async def read_by_type(self, uuid16: int) -> list[bytes]:
        """Read By Type Request (Vol 3 Part G 4.8.2) por UUID de 16 bits, sin
        pasar por handle. Es lo que Android hace de fábrica para Appearance
        (0x2A01) y Database Hash (0x2B2A) antes de tocar la cerradura (ver
        session.py::GATT_CACHING_PREAMBLE_UUID16). bleak no expone esto; con
        Bumble usamos el Client subyacente directamente."""
        from bumble.core import UUID  # noqa: PLC0415

        values = await self.peer.read_characteristics_by_uuid(UUID.from_16_bits(uuid16))
        return [bytes(v) for v in values]

    def _find_by_uuid16(self, uuid16: int) -> Any:
        needle = f"{uuid16:04x}"
        for svc in self.peer.services:
            for ch in svc.characteristics:
                cu = str(ch.uuid).lower().replace("0x", "")
                if cu == needle or needle in cu:
                    return ch
        raise KeyError(f"característica 0x{uuid16:04x} no encontrada en discovery")

    async def write_by_type(self, uuid16: int, data: bytes, response: bool = True) -> None:
        """Write Request (Vol 3 Part G 4.9.3/4.9.4) a una característica de
        16 bits estándar localizada en el discovery ya hecho (self.peer.services),
        sin necesitar su UUID vendor de 128 bits. Usado para
        `Client Supported Features` (0x2B29, ver session.py::write_client_supported_features)."""
        ch = self._find_by_uuid16(uuid16)
        await self.peer.write_value(ch, bytes(data), with_response=response)

    async def get_remote_le_features(self) -> int:
        """HCI LE Read Remote Features -- confirmado en btsnoop real
        (bugreport 2026-08-13) que Android lo manda SIEMPRE justo tras
        conectar, ANTES del intercambio de MTU. Nunca antes replicado en
        este proyecto (distinto de "Read Remote Version Information", que
        SI estaba ya descartado como bajo impacto -- este consulta el mapa
        de features LE del peer, no la version LMP). Bumble lo expone como
        Device.get_remote_le_features(), no automatico. Ver
        docs/reference/."""
        connection = self.peer.connection
        features = await asyncio.wait_for(
            connection.device.get_remote_le_features(connection), timeout=5.0
        )
        return int(features)

    async def request_mtu(self, mtu: int) -> int:
        """ATT Exchange MTU Request (Vol 3 Part F 3.4.2). Vol 3 Part G §3 dice
        que Android SIEMPRE hace este intercambio justo tras conectar, ANTES
        del preambulo GATT caching -- y es el UNICO paso de esa secuencia que
        este proyecto nunca ha reproducido con exito: un intento anterior
        (2026-08-11, ver docs/reference/) colgo el proceso
        para siempre cuando la cerradura desconectaba a mitad de la peticion
        (el semaforo interno de Client.send_request de Bumble no se libera ni
        con asyncio.wait_for por fuera). Se retiro entonces SIN volver a
        probarlo con cuidado. Aqui se reintenta con timeout corto propio
        (mismo patron que update_connection_parameters) + el timeout por fase
        de `client.py`/`transport.py` como red de seguridad si aun asi se cuelga."""
        return await asyncio.wait_for(self.peer.request_mtu(mtu), timeout=5.0)

    async def set_data_length(self, *, tx_octets: int, tx_time: int) -> None:
        """Pide LE Data Length Extension (Vol 6 Part B 4.5.10). Timeout
        propio corto: ver update_connection_parameters, misma cautela tras
        el colgado real de request_mtu (docs/reference/)."""
        connection = self.peer.connection
        await asyncio.wait_for(
            connection.set_data_length(tx_octets, tx_time),
            timeout=5.0,
        )

    async def update_connection_parameters(
        self, *, interval_ms: float, latency: int, supervision_timeout_ms: float
    ) -> None:
        """Pide un LE Connection Update (Vol 6 Part B 4.5.1). Con timeout
        corto propio: `peer.request_mtu()` demostro (2026-08-11, ver
        docs/reference/) que una peticion GATT pendiente
        puede quedarse colgada para siempre si la cerradura desconecta a
        mitad, incluso envuelta en asyncio.wait_for por fuera. Igual de
        importante aqui: nunca dejar esto sin cota de tiempo propia."""
        connection = self.peer.connection
        await asyncio.wait_for(
            connection.update_parameters(
                connection_interval_min=interval_ms,
                connection_interval_max=interval_ms,
                max_latency=latency,
                supervision_timeout=supervision_timeout_ms,
            ),
            timeout=5.0,
        )
