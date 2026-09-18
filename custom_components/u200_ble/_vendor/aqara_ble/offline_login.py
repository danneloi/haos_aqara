"""Offline (cloud-free) derivation of the U200 BLE control session.

The normal login asks the cloud to generate the ephemeral key and to derive the
session material. This module does it locally, so no internet is needed — only
the BLE link to the lock and the device's **LTMK** (obtained once from the owner's
cloud via ``tools/cloud_get_ltmk.py`` and kept in ``.env``).

Model (reverse-engineered from the MG24 firmware and cross-checked by two
independent audits, 2026-09-06):
  The login thread ``lm_ble_login_auth`` @0x805b900 runs a SINGLE HKDF-SHA256
  (@0x805b560). Its IKM is the ECDH shared secret **XOR-ed with the LTMK**
  (the XOR is ``0x8059920`` @0x805b5c2, over 32 bytes). ``ctx+0x4c`` = the LTMK
  (64-byte OKM written by the bind's register-HKDF; the login uses its first 32).
  The salt/info are the constant strings; there is NO lumi_key and NO
  "register" HKDF stage in the login path (that was the bind path — earlier
  two-stage model here was WRONG).

  shared = ECDH(our_priv, lockPub)                    # P-256, 32-byte X
  ikm    = shared XOR LTMK[:32]                        # 32 B
  block  = HKDF-SHA256(IKM=ikm,
                       salt="aiot-login-salt\0"+0*16,  # 32 B
                       info="aiot-login-info\0"+0*16,  # 32 B
                       L=64)
  sessionKey = block[0:16]
  nonce      = block[20:33]                            # 13 B (firmware copies block[0:33])
  verifyData = AES-CCM(sessionKey, nonce,
                       pt=CRC32_BE(lockPub[1:65]), tag_len=4)   # 8 B

We already hold the LTMK (cloud-cutter), so this needs no bind and no lumi_key.

This module does NO I/O and never touches the cloud.
"""
from __future__ import annotations

import binascii
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_SALT = b"aiot-login-salt\x00" + b"\x00" * 16  # login-HKDF salt, 32 B
_INFO = b"aiot-login-info\x00" + b"\x00" * 16  # login-HKDF info, 32 B

_SESSION_KEY_SLICE = slice(0, 16)
_NONCE_SLICE = slice(20, 33)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def generate_ephemeral() -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Return (private key, our uncompressed public key as 130-hex, "04"+X+Y)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return priv, pub.hex()


def derive_session_material(
    priv: ec.EllipticCurvePrivateKey,
    lock_public_key_hex: str,
    ltmk: bytes,
    *,
    salt: bytes = _SALT,
    info: bytes = _INFO,
) -> dict[str, str]:
    """Derive {sessionKey, nonce, verifyData} from our ephemeral + lock pubkey + LTMK.

    ``ltmk`` is the 32-byte Long-Term Master Key (from the cloud, see module
    docstring). Same dict shape as ``kdf.get_session_material`` so it is a drop-in.
    """
    lock_pub = bytes.fromhex(lock_public_key_hex)
    if len(lock_pub) < 65 or lock_pub[0] != 0x04:
        raise ValueError(f"lockPub must be 65-byte uncompressed SEC1, got {lock_pub[:1].hex()} len {len(lock_pub)}")
    if len(ltmk) < 32:
        raise ValueError(f"LTMK must be >= 32 bytes, got {len(ltmk)}")

    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), lock_pub[:65])
    shared = priv.exchange(ec.ECDH(), peer)  # 32-byte X coordinate

    ikm = _xor(shared, ltmk[:32])
    block = hkdf_sha256(ikm, salt, info, 64)
    session_key = block[_SESSION_KEY_SLICE]
    nonce = block[_NONCE_SLICE]

    crc = (binascii.crc32(lock_pub[1:65]) & 0xFFFFFFFF).to_bytes(4, "big")
    verify_data = AESCCM(session_key, tag_length=4).encrypt(nonce, crc, None)

    return {
        "sessionKey": session_key.hex(),
        "nonce": nonce.hex(),
        "verifyData": verify_data.hex(),
    }
