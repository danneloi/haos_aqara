"""Fingerprint / NFC credential enrolment (USER family ``ADD_USER`` 0x01).

Reversed from the app plugin (``sendAddFingerprintCmd`` / ``sendAddNFCCmd`` and the
``onFPBleEvent`` / ``onNFCBleAddUserEvent`` report dispatchers). Fingerprint and NFC
enrolment are the **same** ``ADD_USER`` frame, differing only in a 1-byte
``SourceType``; the lock then drives an interactive report loop on the notify
channel and finishes with a ``REPORT_USER_ID`` frame carrying the allocated
credential.

Enrolment is inherently interactive/physical: the person presents the finger
(several times) or taps the card at the lock's **front-panel** sensor, which must
be awake (see ``read_front_connection``). The library DRIVES it — sends the start
frame, decodes the progress/completion reports — but cannot make the physical
presentation.

⚠️ The frame builders and the report field offsets are reversed from the plugin and
covered by unit tests, but the end-to-end live enrol (and the exact mapping of the
2-byte ``credential_id`` here to the 32-bit id ``delete_user`` expects) still needs
one live capture to confirm — treat ``enrol_credential`` as unverified until then.
"""
from __future__ import annotations

from dataclasses import dataclass

#: SourceType byte per credential kind (admin variants clear bit 6).
#: finger 0x81 / admin 0x41, NFC 0x83 / admin 0x43 (password 0x82/0x42, key 0x84
#: exist but are not sensor-enrolled here).
SOURCE_TYPES: dict[str, int] = {
    "finger": 0x81,
    "finger_admin": 0x41,
    "nfc": 0x83,
    "nfc_admin": 0x43,
}

#: Credential subtype from the completion record's permission byte, low 3 bits.
_SUBTYPE_BY_CODE: dict[int, str] = {
    0b001: "fingerprint",
    0b010: "password",
    0b011: "nfc",
    0b100: "key",
}

#: Fingerprint per-press progress status bytes (USER ``FINGER_REGISTER`` 0x07).
FINGER_PRESS_OK = 0x20      #: one capture accepted ("present again, N/total")
FINGER_CAPTURE_DONE = 0x00  #: all captures done (id arrives in the 0x06 report)
FINGER_FAILED = 0x01        #: registration failed
FINGER_PRESS_TIMEOUT = 0x22  #: finger not presented in time


@dataclass(frozen=True)
class EnrolReport:
    """One decoded enrolment report from the notify channel.

    ``kind`` is the report class: ``"progress"`` (a fingerprint press update),
    ``"success"`` (completion, credential allocated), ``"failed"`` (add failed) or
    ``"timeout"`` (add-user timed out). Fields not relevant to a class are ``None``.
    """

    kind: str
    raw_hex: str
    #: progress: the FINGER_REGISTER status byte and the current press count.
    status: int | None = None
    press_count: int | None = None
    #: success: the allocated credential's ids + metadata.
    user_group_id: int | None = None
    credential_id: int | None = None
    credential_type: str | None = None
    timestamp: int | None = None
    ordinal: int | None = None


def decode_enrol_report(frame_hex: str | None) -> EnrolReport | None:  # noqa: PLR0911
    """Decode one **decrypted** notify frame from an enrol into an ``EnrolReport``.

    ``frame_hex`` is the plaintext ff62 payload (the library's session must have
    decrypted it, same path as the working credential writes). Returns ``None`` for
    a frame that is not a USER-family (mainCmd ``0x02``) enrol report.

    Report shapes (after the ``02 <subCmd>`` header):
    - ``07`` FINGER_REGISTER progress → ``status`` (byte[2]), ``press_count`` (byte[5]).
    - ``06`` REPORT_USER_ID / ``15`` REPORT_USER_ID_NEW → 10-byte completion record
      ``[status][perm][userGroupId][credentialId:2 BE][ts:4 BE][ordinal]``.
    - ``0c`` REPORT_ADD_USER_TIMEOUT → timeout.
    """
    if not frame_hex:
        return None
    try:
        b = bytes.fromhex(frame_hex)
    except ValueError:
        return None
    if len(b) < 2 or b[0] != 0x02:
        return None
    sub = b[1]

    if sub == 0x07:  # fingerprint per-press progress
        if len(b) < 6:
            return None
        return EnrolReport(
            kind="progress", raw_hex=frame_hex, status=b[2], press_count=b[5]
        )

    if sub in (0x06, 0x15):  # completion — credential allocated
        rec = b[2:12]
        if len(rec) < 10:
            return None
        if rec[0] != 0x00:
            return EnrolReport(kind="failed", raw_hex=frame_hex, status=rec[0])
        subtype = _SUBTYPE_BY_CODE.get(rec[1] & 0b111)
        return EnrolReport(
            kind="success",
            raw_hex=frame_hex,
            status=rec[0],
            user_group_id=rec[2],
            credential_id=int.from_bytes(rec[3:5], "big"),
            credential_type=subtype,
            timestamp=int.from_bytes(rec[5:9], "big"),
            ordinal=rec[9],
        )

    if sub == 0x0C:  # REPORT_ADD_USER_TIMEOUT
        return EnrolReport(kind="timeout", raw_hex=frame_hex)

    return None
