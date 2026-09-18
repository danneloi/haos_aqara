"""BLE auth-frame framing for the U200 — pure, no I/O (feature 028).

Extracted from ``session.py`` so the byte-exact wire framing lives apart from the
handshake orchestrator: the CRC-16/ARC table + ``crc16_aqara``, the ``0610``/
``0710`` auth-message builder, and the 5a/da fragment (de)serialisers. These are
pure functions over bytes — no network, no radio, no other package import — and
are the fidelity-critical core (Constitution Principle II). Every value here is
byte-identical to the pre-split ``session.py`` implementation and MUST stay so.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthMessage:
    frame_type: int
    app_token: int
    lock_token: int
    body: bytes


# Tabla CRC-16/ARC (poly 0x8005 reflejado = 0xA001, init 0x0000) — extraída
# LITERAL del módulo Hermes `CrcUtils.ts` de la app (getCrc16String usa esta
# tabla exacta con el bucle reflejado `crc = (crc>>8) ^ tabla[(crc^b)&0xff]`).
# 2026-08-15: ESTE es el muro. El campo de 2 bytes del header del 0610/0710
# NO era un "app_token aleatorio" (asunción errónea de todo el proyecto) —
# es el CRC-16 de `body`, en little-endian. Verificado 130/133 contra el
# btsnoop real (los 3 fallos son artefactos de reensamblado de fragmentos).
# Mandarlo aleatorio hacía que el lock respondiera SIEMPRE status 01 (ACK
# vacío sin pubkey).
# Frozen protocol data (Constitution Article V): kept in its captured
# 16-per-row shape so it stays diffable against the app's table. One value
# per line would be 256 lines of noise that hides any future tampering.
# fmt: off
_CRC16_TABLE = (
    0, 49345, 49537, 320, 49921, 960, 640, 49729, 50689, 1728, 1920, 51009,
    1280, 50625, 50305, 1088, 52225, 3264, 3456, 52545, 3840, 53185, 52865,
    3648, 2560, 51905, 52097, 2880, 51457, 2496, 2176, 51265, 55297, 6336,
    6528, 55617, 6912, 56257, 55937, 6720, 7680, 57025, 57217, 8000, 56577,
    7616, 7296, 56385, 5120, 54465, 54657, 5440, 55041, 6080, 5760, 54849,
    53761, 4800, 4992, 54081, 4352, 53697, 53377, 4160, 61441, 12480, 12672,
    61761, 13056, 62401, 62081, 12864, 13824, 63169, 63361, 14144, 62721,
    13760, 13440, 62529, 15360, 64705, 64897, 15680, 65281, 16320, 16000,
    65089, 64001, 15040, 15232, 64321, 14592, 63937, 63617, 14400, 10240,
    59585, 59777, 10560, 60161, 11200, 10880, 59969, 60929, 11968, 12160,
    61249, 11520, 60865, 60545, 11328, 58369, 9408, 9600, 58689, 9984, 59329,
    59009, 9792, 8704, 58049, 58241, 9024, 57601, 8640, 8320, 57409, 40961,
    24768, 24960, 41281, 25344, 41921, 41601, 25152, 26112, 42689, 42881,
    26432, 42241, 26048, 25728, 42049, 27648, 44225, 44417, 27968, 44801,
    28608, 28288, 44609, 43521, 27328, 27520, 43841, 26880, 43457, 43137,
    26688, 30720, 47297, 47489, 31040, 47873, 31680, 31360, 47681, 48641,
    32448, 32640, 48961, 32000, 48577, 48257, 31808, 46081, 29888, 30080,
    46401, 30464, 47041, 46721, 30272, 29184, 45761, 45953, 29504, 45313,
    29120, 28800, 45121, 20480, 37057, 37249, 20800, 37633, 21440, 21120,
    37441, 38401, 22208, 22400, 38721, 21760, 38337, 38017, 21568, 39937,
    23744, 23936, 40257, 24320, 40897, 40577, 24128, 23040, 39617, 39809,
    23360, 39169, 22976, 22656, 38977, 34817, 18624, 18816, 35137, 19200,
    35777, 35457, 19008, 19968, 36545, 36737, 20288, 36097, 19904, 19584,
    35905, 17408, 33985, 34177, 17728, 34561, 18368, 18048, 34369, 33281,
    17088, 17280, 33601, 16640, 33217, 32897, 16448,
)
# fmt: on


def crc16_aqara(data: bytes) -> int:
    """CRC-16 exacto de la app (getCrc16String de CrcUtils.ts). Devuelve el
    valor entero; en la trama va en little-endian."""
    crc = 0
    for b in data:
        crc = (crc >> 8) ^ _CRC16_TABLE[(crc ^ b) & 0xFF]
        crc &= 0xFFFF
    return crc


def build_auth_message(
    frame_type: int,
    *,
    body: bytes,
    app_token: int | None = None,  # IGNORADO: se conserva por compatibilidad.
    lock_token: int = 0,
) -> bytes:
    if frame_type not in (0x06, 0x07):
        raise ValueError(f"frame_type no soportado: {frame_type:#x}")
    header = bytearray(18)
    header[0] = 0x00
    header[1] = frame_type
    header[2] = 0x10
    header[3] = 0x01
    header[4] = 0x00
    header[5:7] = len(body).to_bytes(2, "little")
    # header[7:9] = CRC-16 del body (NO un token aleatorio). Ver _CRC16_TABLE.
    header[7:9] = crc16_aqara(body).to_bytes(2, "little")
    header[9:11] = lock_token.to_bytes(2, "little")
    return bytes(header) + body


def fragment_auth_message(payload: bytes, direction: int = 0x5A) -> list[bytes]:
    if direction not in (0x5A, 0xDA):
        raise ValueError(f"dirección de fragmento no soportada: {direction:#x}")
    chunks = [payload[i : i + 18] for i in range(0, len(payload), 18)] or [b""]
    fragments: list[bytes] = []
    for index, chunk in enumerate(chunks):
        seq = 0xFF if index == len(chunks) - 1 else index
        fragments.append(bytes((direction, seq)) + chunk)
    return fragments


def assemble_auth_fragments(fragments: list[bytes], expected_direction: int) -> bytes:
    if not fragments:
        raise ValueError("no hay fragmentos para ensamblar")
    payload_parts: list[bytes] = []
    for index, fragment in enumerate(fragments):
        if len(fragment) < 2:
            raise ValueError("fragmento de auth demasiado corto")
        direction = fragment[0]
        seq = fragment[1]
        if direction != expected_direction:
            raise ValueError(
                f"dirección inesperada en auth: {direction:#x} != {expected_direction:#x}"
            )
        if index < len(fragments) - 1 and seq != index:
            raise ValueError(f"secuencia auth inesperada: {seq:#x} != {index:#x}")
        payload_parts.append(fragment[2:])
    return b"".join(payload_parts)


def parse_auth_message(message: bytes) -> AuthMessage:
    if len(message) < 18:
        raise ValueError("mensaje auth incompleto")
    frame_type = message[1]
    body_length = int.from_bytes(message[5:7], "little")
    app_token = int.from_bytes(message[7:9], "little")
    lock_token = int.from_bytes(message[9:11], "little")
    body = message[18 : 18 + body_length]
    if len(body) != body_length:
        raise ValueError("longitud de body auth no coincide")
    return AuthMessage(
        frame_type=frame_type,
        app_token=app_token,
        lock_token=lock_token,
        body=body,
    )
