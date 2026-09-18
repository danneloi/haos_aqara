"""Language voice-pack OTA — the PROVEN primitives (crypto + block framing).

This module holds the pieces of the language OTA that are byte-verified against
live/captured wire data (2026-09-02), kept pure (no I/O) so they are unit-tested
in isolation. The live orchestration (the JSON ``{"ID":n}`` command sequence)
lives in :mod:`aqara_ble.ota`; see ``docs/devices/u200/ota-0x90-investigation.md``
(top "RESOLVED") for how these were established.

What is proven here
-------------------
1. **The OTA crypto is the SAME AES-CCM as the control channel.** A live Frida
   hook on BouncyCastle ``CCMBlockCipher`` during a real voice download showed
   every CCM op — control keepalives AND the OTA JSON short-packs — used ONE
   ``AEADParameters``: the session key + the session nonce, empty AAD, 4-byte
   tag. Python ``AESCCM(key, tag_length=4).encrypt(nonce, pt, b"")`` reproduced
   the app's ciphertext byte-exact and decrypted the lock's frames. So there is
   NO separate ``expandedIv`` — it collapses to the session nonce we already
   derive in :mod:`aqara_ble.kdf`. :func:`ota_encrypt` / :func:`ota_decrypt` are
   thin, intent-named wrappers over :mod:`aqara_ble.control_codec`.

2. **The bulk `.bin` block framing.** The ff91 data stream (each ATT write is
   ``0x11`` + payload, concatenated) is, per 1024-byte block::

       [0x02, seq, 0xff-seq]  ||  block[<=1024]  ||  CRC16-XMODEM(block) big-endian

   seq = 1,2,3…; last block short. Verified 1625/1625 blocks against
   ``captures/ota/btsnoop_end.log`` + ``U200_FR_audio_burn.bin``
   (:func:`frame_data_block`, :func:`iter_data_frames`).

Two CRCs, do not confuse
------------------------
* :func:`crc16_xmodem` — the per-block FRAMING field (poly 0x1021, init 0x0000).
* :func:`crc16_mijia` — CRC-16/MODBUS (poly 0x8005, init 0xFFFF), the
  ``getMijiaCrc16String`` used inside the short-pack plaintext. (Distinct again
  from :func:`aqara_ble.framing.crc16_aqara`, the CRC-16/ARC of the auth/control
  framing.)
"""
from __future__ import annotations

from collections.abc import Iterator

from .control_codec import decrypt_control_payload, encrypt_control_payload

#: OTA data blocks are 1024 bytes (the last is short).
OTA_BLOCK_SIZE = 1024

#: ff91 write prefixes (mainCmd bytes, cleartext): 0x90 = encrypted control
#: short/long pack (JSON commands), 0x11 = plaintext data chunk.
OTA_CONTROL_PREFIX = 0x90
OTA_DATA_PREFIX = 0x11

#: sub-command byte prepended to a control short-pack's plaintext (before the
#: JSON and the 0x00 trailer), captured live 2026-09-02.
OTA_SUBCMD_ID = 0x04      # {"ID":n} session/handshake commands
OTA_SUBCMD_MANIFEST = 0x03  # {"MCU_role":...,"file_info":{…}}

#: default ATT payload per data write = MTU 247 - 3 (ATT header) - 1 (0x11 prefix).
OTA_DATA_MTU_PAYLOAD = 243


def crc16_xmodem(data: bytes) -> int:
    """CRC-16/XMODEM (poly 0x1021, init 0x0000, no reflection). The 2-byte
    big-endian field appended after each 1024-byte OTA data block."""
    crc = 0x0000
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def crc16_mijia(data: bytes) -> int:
    """CRC-16/MODBUS (poly 0x8005, init 0xFFFF, reflected) — the app's
    ``getMijiaCrc16String``. Returns the integer; on the wire it is little-endian."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if (crc & 1) else crc >> 1
    return crc


def frame_data_block(seq: int, block: bytes) -> bytes:
    """Build one OTA data segment (WITHOUT the leading ``0x11`` ff91 write prefix
    and before MTU fragmentation): ``[02 seq (0xff-seq)] block CRC16-XMODEM(be)``.

    ``seq`` is 1-based and wraps in one byte (the marker repeats every 256 blocks).
    """
    marker = bytes([0x02, seq & 0xFF, (0xFF - seq) & 0xFF])
    return marker + block + crc16_xmodem(block).to_bytes(2, "big")


def iter_data_frames(blob: bytes, *, block_size: int = OTA_BLOCK_SIZE) -> Iterator[bytes]:
    """Yield the framed data segments for a language ``.bin`` (from the CDN),
    in order. Each is ready to be ``0x11``-prefixed and MTU-fragmented onto ff91."""
    seq = 1
    for off in range(0, len(blob), block_size):
        block = blob[off:off + block_size]
        if len(block) < block_size:
            # The lock validates the whole received image against the declared MD5/
            # CRC and reports xfer_statu:"abort" (not "success") if it mismatches. The
            # app PADS the final partial block up to the full 1024 bytes with 0x1a
            # (verified in btsnoop_end.log: the tail block is real-data…0x1a…CRC), so
            # the on-wire image is a whole number of 1024-byte blocks. A short final
            # block passes its own CRC16 (the lock 0x1106-acks it) but fails the
            # overall image check → abort at progress 100. Pad to match the app.
            block = block + b"\x1a" * (block_size - len(block))
        yield frame_data_block(seq, block)
        seq += 1


def build_ota_file_info(name: str, blob: bytes) -> dict[str, object]:
    """Build the ``file_info`` manifest the OTA handshake sends, from a CDN
    ``.bin``. Captured shape (live Français download, 2026-09-02)::

        {"name": "U200_FR_audio_burn.bin", "size": 1664596, "crc32": "14711156"}

    ``crc32`` is the standard zlib CRC32 as a lowercase hex string (no ``0x``),
    verified byte-exact against the captured manifest.
    """
    import zlib  # noqa: PLC0415 - stdlib, only needed here

    return {
        "name": name,
        "size": len(blob),
        "crc32": format(zlib.crc32(blob) & 0xFFFFFFFF, "x"),
    }


def build_ota_control_frame(
    session_key_hex: str, nonce_hex: str, subcmd: int, json_bytes: bytes
) -> bytes:
    """Build one encrypted OTA control short/long-pack for ff91:
    ``0x90 || AES-CCM(session, subcmd || json || 0x00)``.

    Captured plaintext shape (live 2026-09-02): ``<subcmd> <utf8-json> 0x00`` —
    no Mijia CRC, just a 0x00 trailer. Verified byte-exact
    (``build_ota_control_frame(k,n,0x04,b'{"ID":255}')`` == the captured
    ``90 5067b566…`` frame)."""
    plaintext = bytes((subcmd,)) + bytes(json_bytes) + b"\x00"
    ct = ota_encrypt(session_key_hex, nonce_hex, plaintext)
    return bytes((OTA_CONTROL_PREFIX,)) + ct


def build_ota_manifest_json(name: str, blob: bytes) -> bytes:
    """The manifest JSON the OTA sends after the start command — compact, key
    order as captured: ``{"MCU_role":"receiver","file_info":{"name":…,"size":…,
    "crc32":…}}``."""
    fi = build_ota_file_info(name, blob)
    return (
        b'{"MCU_role":"receiver","file_info":{"name":"'
        + name.encode()
        + b'","size":'
        + str(fi["size"]).encode()
        + b',"crc32":"'
        + str(fi["crc32"]).encode()
        + b'"}}'
    )


#: init-frame payload is a fixed 128 bytes (filename + NUL + decimal size +
#: space, zero-padded), captured live 2026-09-02.
OTA_INIT_PAYLOAD_SIZE = 128


def build_ota_init_frame(name: str, blob: bytes) -> bytes:
    """The FIRST ff91 data write, before any block: ``0x11 || 01 00 ff ||
    payload128 || CRC16-XMODEM(payload128)`` where ``payload128`` is
    ``<filename> 0x00 <decimal-size> 0x20`` zero-padded to 128 bytes.

    Marker ``01 00 ff`` = init block (type 0x01, seq 0). Verified byte-exact vs
    the captured Français init frame (``…9071`` XMODEM trailer). Omitting this
    frame makes the lock abort the transfer right after the manifest."""
    payload = (name.encode() + b"\x00" + str(len(blob)).encode() + b" ").ljust(
        OTA_INIT_PAYLOAD_SIZE, b"\x00"
    )
    return (
        bytes((OTA_DATA_PREFIX, 0x01, 0x00, 0xFF))
        + payload
        + crc16_xmodem(payload).to_bytes(2, "big")
    )


def build_ota_data_plan(
    blob: bytes, name: str, *, mtu_payload: int = OTA_DATA_MTU_PAYLOAD
) -> tuple[bytes, list[list[bytes]]]:
    """Return ``(init_frame, block_write_groups)`` for a language ``.bin``:
    the init frame, then one list of ff91 writes per 1024-byte block (each block's
    XMODEM-framed segment sliced into ``0x11``-prefixed ``mtu_payload`` chunks).

    Lets a driver pace the transfer per block against the lock's ff92 flow-control
    acks (the lock aborts if blocks arrive faster than it acks them)."""
    init = build_ota_init_frame(name, blob)
    groups: list[list[bytes]] = []
    for seg in iter_data_frames(blob):
        group = [
            bytes((OTA_DATA_PREFIX,)) + seg[off:off + mtu_payload]
            for off in range(0, len(seg), mtu_payload)
        ]
        groups.append(group)
    return init, groups


def iter_ota_data_writes(
    blob: bytes, name: str, *, mtu_payload: int = OTA_DATA_MTU_PAYLOAD
) -> Iterator[bytes]:
    """Yield the ff91 data writes for a language ``.bin`` in wire order:

    1. the init frame (:func:`build_ota_init_frame`);
    2. for EACH XMODEM-framed 1024-byte block segment (``iter_data_frames``),
       that segment sliced into ``mtu_payload`` chunks, each prefixed ``0x11``.

    The per-segment slicing matters: the app chunks each block independently (a
    write never spans two blocks) — matching the captured cadence (5 writes per
    full block: 4x244 B + a short tail)."""
    yield build_ota_init_frame(name, blob)
    for seg in iter_data_frames(blob):
        for off in range(0, len(seg), mtu_payload):
            yield bytes((OTA_DATA_PREFIX,)) + seg[off:off + mtu_payload]


def ota_encrypt(session_key_hex: str, nonce_hex: str, plaintext: bytes) -> bytes:
    """Encrypt an OTA control short-pack payload. Byte-identical to the app's
    ``encryptAESCCM`` (AES-CCM, session key+nonce, empty AAD, 4-byte tag) —
    verified live 2026-09-02. Returns ciphertext ``||`` 4-byte tag."""
    return encrypt_control_payload(session_key_hex, nonce_hex, plaintext=plaintext)


def ota_decrypt(session_key_hex: str, nonce_hex: str, ciphertext: bytes) -> bytes:
    """Inverse of :func:`ota_encrypt` — decrypt an OTA control frame from the
    lock (ff92) into its plaintext (e.g. ``b'\\x10{"ID":0,"xfer_statu":...}'``)."""
    return decrypt_control_payload(session_key_hex, nonce_hex, ciphertext=ciphertext)
