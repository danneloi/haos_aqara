"""Decode the U200 user/credential table read over BLE.

The table is fetched with the MIOT command SYNC_USER_ID_VALID_PERIOD (LOG 0x1f);
the lock answers with a LONG (0x3f) multi-fragment reply that ``session.py``
reassembles and decrypts into the plaintext blob decoded here.

Observed live layout (2026-09-06), one fixed 10-byte record per credential —
validated against the cloud table (`/dev/lock/query`): 7 records = 7 credentials,
5 password / 1 fingerprint / 1 NFC. The lock NEVER returns the PIN plaintext (only
its id, type and validity); the cleartext PIN is only available at enrolment or via
the cloud offline-password endpoint.

Record (10 bytes):
  [0] group/slot   [1] flags   [2] type (1=finger,2=pwd,3=NFC,4=key,6=face)
  [3:5] userId (LE, u16)   [5] index   [6:10] createTime (LE, u32 unix)
The type byte is high-confidence (matches the cloud table); the other field
offsets are inferred from the live sample and may need refinement per firmware.
"""
from __future__ import annotations

from dataclasses import dataclass

CREDENTIAL_TYPES = {1: "fingerprint", 2: "password", 3: "NFC", 4: "key", 6: "face"}

#: read_burst spec for the user/credential table on this Matter/MIOT lock:
#: write-prefix 0x03 (LOG) + plaintext subCmd 0x1f + CRC (2B BUYPASS; for a 2-byte
#: input the CRC equals the input, hence "1f031f").
USER_TABLE_FRAME = "03:1f031f"


@dataclass(frozen=True)
class UserCredential:
    user_id: int
    type: int
    type_name: str
    index: int
    create_time: int
    raw_hex: str


def decode_user_table(blob_hex: str, *, record_len: int = 10) -> list[UserCredential]:
    """Decode the reassembled+decrypted table blob into credential records.

    ``record_len`` defaults to the 10-byte MIOT layout observed on the U200; it is
    parameterised because other firmware/protocol variants use wider records.
    """
    data = bytes.fromhex(blob_hex)
    out: list[UserCredential] = []
    for i in range(0, len(data) - record_len + 1, record_len):
        r = data[i : i + record_len]
        t = r[2]
        out.append(
            UserCredential(
                user_id=int.from_bytes(r[3:5], "little"),
                type=t,
                type_name=CREDENTIAL_TYPES.get(t, f"0x{t:02x}"),
                index=r[5],
                create_time=int.from_bytes(r[6:10], "little"),
                raw_hex=r.hex(),
            )
        )
    return out
