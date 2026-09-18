"""Observed Aqara U200 BLE protocol primitives."""

from __future__ import annotations

import binascii
from dataclasses import dataclass


@dataclass(frozen=True)
class ControlRequest:
    kind: int
    command: int
    body: bytes
    trailer: bytes

    def as_bytes(self) -> bytes:
        return bytes((self.kind, self.command)) + self.body + self.trailer


_COMMAND_NAMES = {
    0xD3: "voice-volume-alert",
    0xFE: "session-keepalive",
}


def control_command_name(command: int) -> str:
    return _COMMAND_NAMES.get(command, f"command-0x{command:02x}")


def parse_control_request(value: bytes) -> ControlRequest:
    if len(value) < 7 or value[0] not in (0x01, 0x03):
        raise ValueError("no es una solicitud de control reconocida")
    return ControlRequest(
        kind=value[0],
        command=value[1],
        body=value[2:-4],
        trailer=value[-4:],
    )


def valid_crc(data_with_crc: bytes) -> bool:
    if len(data_with_crc) < 2:
        return False
    expected = int.from_bytes(data_with_crc[-2:], "big")
    return binascii.crc_hqx(data_with_crc[:-2], 0) == expected
