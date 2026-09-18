"""High-level lock operations captured from real U200 sessions.

The operations in this module are plaintext command payloads observed in
runtime traces before the app encryption layer.

**Provenance of the actuation commands (feature 009, 2026-08-14).** UNLOCK and
LOCK are the *exact* plaintexts the official app hands to `AqEdUtils.encryptAESCCM`
when you press Open / Close, captured live with a Frida gadget and then replayed
successfully from our own autonomous session (the lock opened, reply `74007706`).
They start with `0x74` (`BLE_OPEN_LOCK`); the 2nd byte is the direction
(`01` = open, `00` = close). The old `1f031f` / `200320` values shipped earlier
were **never** the real actuators — the lock is silent to them — and are kept
below only as clearly-marked legacy, not used by any alias.

**Command builder (trailer cracked, feature 009).** The frame is
``74 <dir> <seq:2 LE> <trailer:2 LE>`` where ``dir`` is ``01`` open / ``00``
close, ``seq`` is a 2-byte little-endian sequence, and the trailer is
**additive, not a CRC**: ``trailer = base_dir + seq`` (``base_open = 0x17b8``,
``base_close = 0x1238``). Cracked from nine live captures across a run of
presses — the trailer increments by exactly 1 with the sequence, which rules out
a CRC. ``build_operate_frame`` synthesises any command; ``UNLOCK`` / ``LOCK`` are
the ``seq=1`` case. The bases were derived from one device and could be
device-specific (unconfirmed on a second lock).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class LockOperation(str, Enum):
    """Observed operation payloads (plaintext, before AES-CCM session encryption).

    Actuation commands confirmed live (feature 009): captured from the app's
    `encryptAESCCM` input on a real button press and replayed to open the lock
    from our own session.
      - UNLOCK (open)  -> 74010100b917  (opcode 0x74, dir 0x01)
      - LOCK  (close)  -> 740002003a12  (opcode 0x74, dir 0x00)
    KEEPALIVE and STATE_SNAPSHOT were recovered from decrypted control traces.
    All are sent encrypted: control_write = write_prefix + AESCCM(sessionKey,nonce).
    """

    # Keepalive / status poll frame. The counter rotates; 2f012f is one sample.
    KEEPALIVE = "2f012f"
    # OPEN the lock — build_operate_frame(open=True, seq=1). Confirmed live.
    UNLOCK = "74010100b917"
    # CLOSE the lock — build_operate_frame(open=False, seq=1).
    LOCK = "740001003912"
    # Extended state payload observed around control-page interactions.
    STATE_SNAPSHOT = "334e74746a201c00003049"
    # LEGACY, NON-FUNCTIONAL: shipped as LOCK/UNLOCK before feature 009 but the
    # lock is silent to them — they are NOT the real actuators. Kept for
    # provenance only; no alias maps here.
    LEGACY_UNVERIFIED_1F031F = "1f031f"


# Operate-command builder (feature 009). frame = 74 <dir> <seq:2 LE> <trailer:2 LE>
# with trailer = base_dir + seq (additive, not a CRC). Bases derived from live
# captures on one device; may be device-specific.
_OPERATE_OPCODE = 0x74
_OPERATE_BASE = {True: 0x17B8, False: 0x1238}  # open / close


def build_operate_frame(*, open: bool, seq: int = 1) -> bytes:
    """Synthesise the plaintext for an open/close command with any sequence.

    ``open=True`` opens the bolt, ``open=False`` closes it. ``seq`` is the 2-byte
    little-endian sequence number (the lock does not validate it across sessions,
    so ``seq=1`` per fresh session is fine). The trailer is ``base_dir + seq``.
    """
    if not 0 <= seq <= 0xFFFF:
        raise ValueError("seq must fit in 2 bytes (0..65535)")
    direction = 0x01 if open else 0x00
    trailer = (_OPERATE_BASE[open] + seq) & 0xFFFF
    return (
        bytes([_OPERATE_OPCODE, direction])
        + seq.to_bytes(2, "little")
        + trailer.to_bytes(2, "little")
    )


def build_control_frame(sub_cmd: int, data: bytes = b"") -> bytes:
    """Build a generic control-frame plaintext: ``sub_cmd`` byte followed by data.

    The two commands confirmed on the real lock (operate ``0x74`` and keepalive
    ``0x2f``) both start with their **sub-command byte** — there is **no mainCmd
    byte on the wire**; the command family (SYSTEM/USER/…) in
    ``operations_catalog`` is an app-side grouping, not a wire prefix. This helper
    emits that confirmed shape.

    The exact ``data`` for non-confirmed commands is **unverified** (only ``0x74``
    and ``0x2f`` were captured). For the confirmed operate command use
    ``build_operate_frame`` — it has the additive-trailer structure that this
    generic ``sub_cmd + data`` form does not model.
    """
    if not 0 <= sub_cmd <= 0xFF:
        raise ValueError("sub_cmd must be a single byte (0..255)")
    return bytes([sub_cmd]) + data


def normalize_lock_operation(value: LockOperation | str) -> LockOperation:
    if isinstance(value, LockOperation):
        return value

    normalized = value.strip().lower().replace("_", "-")
    aliases = {
        "keepalive": LockOperation.KEEPALIVE,
        "keep-alive": LockOperation.KEEPALIVE,
        "heartbeat": LockOperation.KEEPALIVE,
        "lock": LockOperation.LOCK,
        "bloquear": LockOperation.LOCK,
        "cerrar": LockOperation.LOCK,
        "close": LockOperation.LOCK,
        "unlock": LockOperation.UNLOCK,
        "desbloquear": LockOperation.UNLOCK,
        "abrir": LockOperation.UNLOCK,
        "open": LockOperation.UNLOCK,
        "snapshot": LockOperation.STATE_SNAPSHOT,
        "state-snapshot": LockOperation.STATE_SNAPSHOT,
        "estado": LockOperation.STATE_SNAPSHOT,
    }
    try:
        return aliases[normalized]
    except KeyError as exc:
        raise ValueError(f"operación no soportada: {value}") from exc


@dataclass(frozen=True)
class LockOperationWrite:
    #: Either a catalogued `LockOperation` or a probe label like "query:0x07"
    #: (feature 021) for a generic control frame that has no enum member.
    operation: LockOperation | str
    payload: bytes
    write_prefix: int

    @property
    def hex_payload(self) -> str:
        return self.payload.hex()


# Read-query trailer (feature 030). A control read is `command + body +
# trailer(4B)` on the wire behind the `0x01` write-prefix (see
# docs/reference/control-channel.md). The 4-byte trailer is a session/sequence
# tail the lock does **not** validate for read queries: a captured cross-session
# value elicits a valid response. Confirmed live 2026-08-25 on this project's own
# lock — `0xde` GET_BATTERY_INFO returned `de0007000101300000c70a` (byte 6 = the
# battery %), and `0x4f` answered too, both with this exact trailer reused across
# fresh sessions. We reuse a known-good captured trailer so the frame has the
# required shape without recomputing a value the lock ignores.
READ_QUERY_TRAILER = bytes.fromhex("158b3609")


def build_read_query_write(sub_cmd: int, body: bytes = b"\x00") -> LockOperationWrite:
    """Build a well-formed **read** query: ``sub_cmd + body + trailer(4B)``.

    Unlike :func:`build_control_query_write` (which sent only the bare opcode and
    the lock silently ignores), this emits the full control-frame shape the lock
    actually parses, so status/info reads elicit a response. ``body`` defaults to
    a single ``0x00`` byte (the value the confirmed battery read used); the lock
    is insensitive to it for the reads probed so far. The write-prefix is ``0x01``
    (the ``kind`` byte, unencrypted on the wire).
    """

    return LockOperationWrite(
        operation=f"read:0x{sub_cmd:02x}",
        payload=bytes([sub_cmd]) + body + READ_QUERY_TRAILER,
        write_prefix=0x01,
    )


# SET-setting trailers (2026-08-28/29 sweeps). Captured live from the app
# while changing "Bloqueo de verificación" (0xAF) and BOTH auto-lock timers
# (0xD5) — see docs/devices/u200/operations.md. All frames are
# `<opcode> <seconds:N LE> <2B trailer>`; the last trailer byte (0xfe) is
# reused verbatim for the same reason READ_QUERY_TRAILER is: read trailers
# are known-ignored by the lock, and no CRC-16 variant tried
# (binascii.crc_hqx, the one this codebase already uses in protocol.valid_crc)
# matches these bytes. The FIRST trailer byte, however, is NOT noise for
# 0xD5 — it disambiguates which of the two auto-lock timers the frame targets
# (0xD5 covers both; there is no separate 0xAD SET_AUTO_LOCK_TIME frame for
# this — an earlier 13-byte 0xAD sample was something else entirely, see
# operations.md): `0x0e` = "Re-bloqueo de seguridad" delay (confirmed 10s),
# `0x01` = "Bloqueo automático al cerrar" delay (confirmed 5s). Unconfirmed
# whether the lock validates either trailer byte for SET specifically.
_VERIFY_FAIL_TIME_TRAILER = bytes.fromhex("0c4a")
_AUTO_LOCKUP_RELOCK_TRAILER = bytes.fromhex("0efe")
_AUTO_LOCKUP_ON_CLOSE_TRAILER = bytes.fromhex("01fe")


def build_set_verify_fail_time(seconds: int) -> LockOperationWrite:
    """SET_VERIFY_FAIL_TIME (0xAF): lockout duration after 10 failed keypad tries.

    Frame: ``af <seconds:4 LE> <trailer:2>``. Captured live setting "Bloqueo de
    verificación" to 2 minutes: ``af780000000c4a`` (0x78 = 120s). The app's own
    picker only offers discrete values (no bloqueo, 1-5 min, 30 min) but nothing
    in the captured frame suggests the lock only accepts those — pass any
    seconds value.
    """

    if not 0 <= seconds <= 0xFFFFFFFF:
        raise ValueError("seconds must fit in 4 bytes (0..4294967295)")
    body = seconds.to_bytes(4, "little") + _VERIFY_FAIL_TIME_TRAILER
    return LockOperationWrite(
        operation=f"set:0xaf:{seconds}s",
        payload=build_control_frame(0xAF, body),
        write_prefix=0x01,
    )


def build_set_auto_lockup_delay_time(seconds: int) -> LockOperationWrite:
    """SET_AUTO_LOCKUP_DELAY_TIME (0xD5): delay before the "Re-bloqueo de
    seguridad" auto re-lock fires after a remote/automation/third-party unlock.

    Frame: ``d5 <seconds:2 LE> 0e <trailer:1>``. Captured live setting it to
    10s: ``d50a000efe``. See :func:`build_set_auto_lock_on_close_delay_time`
    for the OTHER auto-lock timer — same opcode, different disambiguating byte.
    """

    if not 0 <= seconds <= 0xFFFF:
        raise ValueError("seconds must fit in 2 bytes (0..65535)")
    body = seconds.to_bytes(2, "little") + _AUTO_LOCKUP_RELOCK_TRAILER
    return LockOperationWrite(
        operation=f"set:0xd5:relock:{seconds}s",
        payload=build_control_frame(0xD5, body),
        write_prefix=0x01,
    )


def build_set_auto_lock_on_close_delay_time(seconds: int) -> LockOperationWrite:
    """SET the "Bloqueo automático al cerrar" timer — how long after the door
    is detected shut before the lock auto-locks.

    Same opcode as :func:`build_set_auto_lockup_delay_time` (0xD5) — the two
    auto-lock timers share it, disambiguated by the first trailer byte.
    Frame: ``d5 <seconds:2 LE> 01 <trailer:1>``. Captured live setting it to
    5s: ``d50500 01fe``. (There is no separate 0xAD opcode for this despite an
    earlier 13-byte 0xAD sample suggesting one — see operations.md.)
    """

    if not 0 <= seconds <= 0xFFFF:
        raise ValueError("seconds must fit in 2 bytes (0..65535)")
    body = seconds.to_bytes(2, "little") + _AUTO_LOCKUP_ON_CLOSE_TRAILER
    return LockOperationWrite(
        operation=f"set:0xd5:on_close:{seconds}s",
        payload=build_control_frame(0xD5, body),
        write_prefix=0x01,
    )


# SET_DOORLOCK_ALARM_VOLUME (0x83, 2026-08-28 sweep). Frame `83 02 <val> 07`.
# Only two levels exist in the app's UI for this setting (distinct from the
# 4-level alert_volume enum decoded in lock_state.decode_alert_volume): Normal
# and Silencio. Both bytes confirmed live via change-and-reread.
ALARM_VOLUME_SILENCIO = 0x00
ALARM_VOLUME_NORMAL = 0x10


def build_set_alarm_volume(*, silent: bool) -> LockOperationWrite:
    """SET the alarm/siren volume ("Volumen de alarma"): Normal or Silencio.

    Frame: ``83 02 <val> 07``. ``val=0x00``=Silencio, ``val=0x10``=Normal —
    both confirmed live (docs/devices/u200/operations.md).
    """

    val = ALARM_VOLUME_SILENCIO if silent else ALARM_VOLUME_NORMAL
    body = bytes([0x02, val, 0x07])
    return LockOperationWrite(
        operation=f"set:0x83:{'silencio' if silent else 'normal'}",
        payload=build_control_frame(0x83, body),
        write_prefix=0x01,
    )


# SET_ALERT_VOLUME (0x02 kind=0x02, 2026-08-30 sweep). This is the 4-level
# "Volumen de alerta" enum (distinct from both voice volume 0x02/kind=0x04 and
# alarm volume 0x83) — same read-side enum as lock_state.decode_alert_volume
# (01=Alto, 02=Medio, 03=Bajo, 04=Silencio). Frame: `02 02 <val> 04 <trailer>`
# where trailer = val + 0x0c — confirmed additive via 2 isolated captures
# (Bajo: 020203040f, Medio: 020202040e — 0x0f-0x03 == 0x0e-0x02 == 0x0c).
ALERT_VOLUME_ALTO = 0x01
ALERT_VOLUME_MEDIO = 0x02
ALERT_VOLUME_BAJO = 0x03
ALERT_VOLUME_SILENCIO = 0x04
_ALERT_VOLUME_TRAILER_OFFSET = 0x0C
_ALERT_VOLUME_NAMES = {
    ALERT_VOLUME_ALTO: "alto",
    ALERT_VOLUME_MEDIO: "medio",
    ALERT_VOLUME_BAJO: "bajo",
    ALERT_VOLUME_SILENCIO: "silencio",
}


def build_set_alert_volume(level: int) -> LockOperationWrite:
    """SET the "Volumen de alerta" level (Alto/Medio/Bajo/Silencio).

    Frame: ``02 02 <level> 04 <level + 0x0c>``. Only ``level`` in
    ``{1, 2, 3, 4}`` is valid — matches the read-side enum in
    :func:`aqara_ble.lock_state.decode_alert_volume`.
    """

    if level not in _ALERT_VOLUME_NAMES:
        raise ValueError("level must be one of 1 (Alto), 2 (Medio), 3 (Bajo), 4 (Silencio)")
    trailer = (level + _ALERT_VOLUME_TRAILER_OFFSET) & 0xFF
    body = bytes([0x02, level, 0x04, trailer])
    return LockOperationWrite(
        operation=f"set:0x02:alert_volume:{_ALERT_VOLUME_NAMES[level]}",
        payload=build_control_frame(0x02, body),
        write_prefix=0x01,
    )


# SET_ALERT_DELAY (0x18, 2026-08-30 sweep). "Retraso de alerta" — how long the
# door can stay open before the alarm sounds. Frame:
# `18 05 0a 03 <seconds:1> 88 <trailer = seconds XOR 0xdf>`, confirmed via 3
# isolated captures (60s: 18050a033c88e3, 10s: 18050a030a88d5,
# 5s: 18050a030588da — trailer XOR seconds == 0xdf in all three). The app's UI
# only offers a fixed preset list (3/5/10/15/30/60/180s) but the wire format
# is a plain single byte, so any 0-255s value is accepted here.
_ALERT_DELAY_PREFIX = bytes.fromhex("050a03")
_ALERT_DELAY_TRAILER_PREFIX = 0x88
_ALERT_DELAY_TRAILER_XOR = 0xDF


def build_set_alert_delay(seconds: int) -> LockOperationWrite:
    """SET the "Retraso de alerta" (open-door alarm delay), in seconds.

    Frame: ``18 05 0a 03 <seconds> 88 <seconds XOR 0xdf>``.
    """

    if not 0 <= seconds <= 0xFF:
        raise ValueError("seconds must fit in 1 byte (0..255)")
    trailer = seconds ^ _ALERT_DELAY_TRAILER_XOR
    body = _ALERT_DELAY_PREFIX + bytes([seconds, _ALERT_DELAY_TRAILER_PREFIX, trailer])
    return LockOperationWrite(
        operation=f"set:0x18:alert_delay:{seconds}s",
        payload=build_control_frame(0x18, body),
        write_prefix=0x01,
    )


# LANGUAGE. CORRECTED 2026-08-30 (previous byte-position note was wrong): the
# frame is `03 <code:1> 83 <trailer=code XOR 0x05>` — the LANGUAGE CODE is
# byte1, not byte2 as the 2026-08-29 note assumed. Byte2 (0x83) is a CONSTANT
# marker, not "English's code" — that earlier conclusion was a misreading of
# which byte varies (it only had one sample at the time). Re-derived live
# 2026-08-30 with TWO independent isolated captures, each confirmed by an
# explicit lock-side ACK (`03 00 00 06 00`) that was absent for an invalid
# code tried for Español (see below):
#   English: code=0x02 -> `03028307` (trailer 0x02^0x05=0x07) — matches the
#   original 2026-08-29 capture too, now correctly reinterpreted.
#   Deutsch: code=0x09 -> `0309830c` (trailer 0x09^0x05=0x0c), ACK'd, and a
#   fresh cold relaunch confirmed the lock's real state changed to Deutsch.
# Español's real code is UNKNOWN — code=0x0a was tried (guessed from the
# XOR-0x05 pattern continuing sequentially) and got NO ack + no state change
# (a fresh relaunch still showed Deutsch), so 0x0a is confirmed WRONG. Worse:
# the official app's own "Selección de idioma > Otros idiomas > Español
# (Descargado) > Confirmar" flow is BUGGED on this firmware/app version — it
# reproducibly closes the picker sheet as a no-op the moment "Español" is
# tapped (5/5 attempts, both via touch and after ruling out the keypad gate),
# while the sibling flow for Français behaves the same way (also never shows
# a checkmark) — so this isn't Español-specific, the whole "Otros idiomas"
# sub-sheet's row-tap doesn't register a selection on this app build. Only
# ENGLISH and DEUTSCH are exposed as builders. Do NOT guess Español's code
# further on a real lock — re-attempt via a full BLE session using our own
# client (bypassing the buggy app UI) if this is picked back up, or retry the
# app flow on an app update.
LANGUAGE_ENGLISH_CODE = 0x02
LANGUAGE_DEUTSCH_CODE = 0x09
_LANGUAGE_CONST_BYTE = 0x83
_LANGUAGE_TRAILER_XOR = 0x05


def build_set_language_english() -> LockOperationWrite:
    """SET LANGUAGE to English — code 0x02, confirmed live with an ACK.

    Frame: ``03 02 83 07``.
    """

    trailer = LANGUAGE_ENGLISH_CODE ^ _LANGUAGE_TRAILER_XOR
    body = bytes([LANGUAGE_ENGLISH_CODE, _LANGUAGE_CONST_BYTE, trailer])
    return LockOperationWrite(
        operation="set:0x03:english",
        payload=build_control_frame(0x03, body),
        write_prefix=0x01,
    )


def build_set_language_deutsch() -> LockOperationWrite:
    """SET LANGUAGE to Deutsch — code 0x09, confirmed live with an ACK and a
    fresh cold-relaunch re-read.

    Frame: ``03 09 83 0c``.
    """

    trailer = LANGUAGE_DEUTSCH_CODE ^ _LANGUAGE_TRAILER_XOR
    body = bytes([LANGUAGE_DEUTSCH_CODE, _LANGUAGE_CONST_BYTE, trailer])
    return LockOperationWrite(
        operation="set:0x03:deutsch",
        payload=build_control_frame(0x03, body),
        write_prefix=0x01,
    )


# SET_AUXILIARY_LOCKING (0xC4, 2026-08-29 sweep). ONE opcode for BOTH auto-lock
# sub-toggles, disambiguated by a "kind" byte: 0x02 = "Bloqueo automático al
# cerrar", 0x04 = "Re-bloqueo de seguridad". Each was captured in its OWN
# isolated connection (nothing else changed) — only the ENABLE frame for each
# is confirmed; no OFF-state frame was captured, so no disable builder is
# exposed yet, and `val`'s meaning past "differs by toggle" is unconfirmed.
_AUX_LOCKING_TRAILER = 0x98


def build_set_auxiliary_locking_on_close_enabled() -> LockOperationWrite:
    """Enable "Bloqueo automático al cerrar" (auto-lock when the door shuts).

    Frame: ``c4 02 0006 98``. Captured live 2026-08-29 in an isolated capture
    (the "Re-bloqueo de seguridad" toggle and both timers were left untouched).
    """

    body = bytes([0x02]) + (0x0006).to_bytes(2, "big") + bytes([_AUX_LOCKING_TRAILER])
    return LockOperationWrite(
        operation="set:0xc4:on_close_enabled",
        payload=build_control_frame(0xC4, body),
        write_prefix=0x01,
    )


def build_set_auxiliary_locking_relock_enabled() -> LockOperationWrite:
    """Enable "Re-bloqueo de seguridad" (auto re-lock after a remote/automation
    unlock that isn't followed by the door opening).

    Frame: ``c4 04 0000 98``. Captured live 2026-08-29 in an isolated capture
    (the "Bloqueo automático al cerrar" toggle and both timers were left
    untouched).
    """

    body = bytes([0x04]) + (0x0000).to_bytes(2, "big") + bytes([_AUX_LOCKING_TRAILER])
    return LockOperationWrite(
        operation="set:0xc4:relock_enabled",
        payload=build_control_frame(0xC4, body),
        write_prefix=0x01,
    )


def build_add_visitor_password(pin: str, group_id: int = 1) -> LockOperationWrite:
    """Enrol a visitor PIN over BLE (USER family, write-prefix ``0x02``).

    Frame (plaintext, no CRC — the USER family is not the CRC'd LOG family):
    ``13 <group_id> 03 02 <total_len> <pwd_len> <pwd BCD>`` where
    ``total_len = 1 + len(pin)//2`` and ``pwd_len`` is the digit count. E.g. PIN
    ``"730492"`` group ``1`` → ``130103020406730492`` on write-prefix ``0x02``.

    Reversed from the plugin's ``addVistorPwdUserByBle`` and confirmed live
    (the lock's reply ``0215<user-id>`` carries a status byte ``0x00`` = success;
    ``read_burst`` correlates by opcode so the reply may not pair with this write,
    but any non-empty reply means it landed — verify enrolment out of band).

    ``pin`` must be an even number of decimal digits (BCD-packed two per byte).
    """
    if not pin.isdigit() or len(pin) % 2 != 0:
        raise ValueError("pin must be an even number of decimal digits")
    if not 0 <= group_id <= 0xFF:
        raise ValueError("group_id must be a single byte (0-255)")
    total_len = 1 + len(pin) // 2
    pwd_len = len(pin)
    frame = bytes([0x13, group_id, 0x03, 0x02, total_len, pwd_len]) + bytes.fromhex(pin)
    return LockOperationWrite(
        operation=f"add_visitor_password:group{group_id}",
        payload=frame,
        write_prefix=0x02,
    )


def build_start_enrol(user_group_id: int, kind: str = "finger") -> LockOperationWrite:
    """Start a fingerprint/NFC enrolment over BLE (USER family, ``ADD_USER`` 0x01).

    Frame (plaintext, no CRC): write-prefix ``0x02`` (``SendMainCmd.USER``) then
    ``01 <userGroupId> <sourceType>`` — ``ADD_USER`` (``0x01``) followed by the
    target user-group id and the 1-byte ``SourceType`` (finger ``0x81`` / NFC
    ``0x83``; admin variants ``0x41`` / ``0x43``). E.g. group ``5`` finger →
    payload ``010581``.

    Reversed from the plugin's ``sendAddFingerprintCmd`` / ``sendAddNFCCmd`` (both
    the same ``ADD_USER`` frame, differing only in the source byte). After this the
    lock drives an interactive report loop on the notify channel — decode it with
    :func:`aqara_ble.enrol.decode_enrol_report`. Needs the front-panel sensor awake
    (physical), and the person presents the finger/card.

    ``kind`` is one of :data:`aqara_ble.enrol.SOURCE_TYPES`.
    """
    from .enrol import SOURCE_TYPES  # noqa: PLC0415

    if kind not in SOURCE_TYPES:
        raise ValueError(f"kind must be one of {sorted(SOURCE_TYPES)}")
    if not 0 <= user_group_id <= 0xFF:
        raise ValueError("user_group_id must be a single byte (0-255)")
    frame = bytes([0x01, user_group_id, SOURCE_TYPES[kind]])
    return LockOperationWrite(
        operation=f"start_enrol:{kind}:group{user_group_id}",
        payload=frame,
        write_prefix=0x02,
    )


def build_abort_enrol(user_group_id: int) -> LockOperationWrite:
    """Cancel an in-progress enrolment (USER family, ``QUITE_ADD_USER`` 0x02).

    Frame: write-prefix ``0x02`` then ``02 <userGroupId>``. Reversed from the
    plugin's ``sendOutAddUserCmd`` (``stopRecordFingerprint`` / page-exit).
    """
    if not 0 <= user_group_id <= 0xFF:
        raise ValueError("user_group_id must be a single byte (0-255)")
    return LockOperationWrite(
        operation=f"abort_enrol:group{user_group_id}",
        payload=bytes([0x02, user_group_id]),
        write_prefix=0x02,
    )


def build_delete_user(user_id: int) -> LockOperationWrite:
    """Delete a user (and all their credentials) over BLE (USER family, ``DEL_USER``).

    Frame (plaintext, no CRC): write-prefix ``0x02`` (``SendMainCmd.USER``) then
    ``03 <user_id LE-4B>`` — i.e. ``DEL_USER`` (``0x03``) followed by the lock's
    32-bit user id as **four little-endian bytes**. ``user_id`` is the full lock id
    (same value the cloud ``/dev/lock/query`` reports and the access log carries).
    E.g. id ``2147614723`` (``0x80020003``) → payload ``0303000280``.

    Reversed from the plugin's on-device single-user delete (``UserSubCmd.DEL_USER``
    with ``data = fixBitString(record.userId, 2)`` over the raw 4-byte LE hex, a
    no-op) — not the cloud ``deleteCertificateByChannel`` path. Format confirmed
    live: a ``password`` access-log row ``user_id_raw=03000280`` decodes LE to
    ``0x80020003``, matching that credential's cloud id exactly. Removes the whole
    user entry; for a visitor password (its own user) that deletes exactly that PIN.

    Needs the keypad (front panel) AWAKE: confirmed live 2026-09-07 — a delete sent
    with the keypad asleep had no effect, while the same frame with it awake deleted
    the target on the first try (table went 7→6, others intact). The credential DB
    is fronted by the sleeping keypad panel, so both the table read and add/delete
    need it awake — wake it first (see ``read_front_connection`` + a keypad press).
    The reply is not opcode-correlated by ``read_burst`` (like the add), so a ``None``
    reply is normal; confirm by re-reading the table.
    """
    if not 0 <= user_id <= 0xFFFFFFFF:
        raise ValueError("user_id must fit in four bytes (0-4294967295)")
    frame = bytes([0x03]) + user_id.to_bytes(4, "little")
    return LockOperationWrite(
        operation=f"delete_user:{user_id}",
        payload=frame,
        write_prefix=0x02,
    )


def build_control_query_write(sub_cmd: int, data: bytes = b"") -> LockOperationWrite:
    """Build a generic **read-only-intended** control query write (feature 021).

    Wraps ``build_control_frame(sub_cmd, data)`` with the captured control write
    prefix (0x01). Use it to probe catalogued status opcodes (e.g. ``0x07``
    ``LOCK_STATUS``, ``0xE5`` ``GET_DOOR_LOCK_STATUS``) whose response might carry
    the bolt position — the keepalive/operate/state_snapshot ACKs do not. The
    exact payload of these opcodes is **unconfirmed**; the honest first probe
    sends only the opcode byte. The caller is responsible for sending only
    read-only opcodes — this helper does not enforce that (the CLI does).
    """

    return LockOperationWrite(
        operation=f"query:0x{sub_cmd:02x}",
        payload=build_control_frame(sub_cmd, data),
        write_prefix=0x01,
    )


class SessionOperationTransport(Protocol):
    def send_plaintext_operation(self, payload: bytes) -> None:
        """Send plaintext operation bytes through an authenticated session."""


def build_lock_operation_write(
    operation: LockOperation | str | LockOperationWrite,
) -> LockOperationWrite:
    # Passthrough (feature 021): a pre-built write (e.g. a status-query probe from
    # build_control_query_write) is sent as-is, so the session's actuator path is
    # unchanged and can carry generic control frames too.
    if isinstance(operation, LockOperationWrite):
        return operation
    normalized = normalize_lock_operation(operation)
    # Every control frame in a real capture is written to ff61 with prefix 0x01
    # (short frames) — including the actuation commands (their ff61 write was
    # `01` + ciphertext). Legacy values are not dispatched.
    prefix_by_operation = {
        LockOperation.KEEPALIVE: 0x01,
        LockOperation.LOCK: 0x01,
        LockOperation.UNLOCK: 0x01,
        LockOperation.STATE_SNAPSHOT: 0x01,
    }
    try:
        prefix = prefix_by_operation[normalized]
    except KeyError as exc:
        raise ValueError(
            f"{normalized.name} is legacy/non-functional and is not dispatched; "
            f"use UNLOCK/LOCK (the real captured commands)."
        ) from exc
    return LockOperationWrite(
        operation=normalized,
        payload=bytes.fromhex(normalized.value),
        write_prefix=prefix,
    )


def send_lock_operation(
    transport: SessionOperationTransport,
    operation: LockOperation | str,
) -> LockOperationWrite:
    write = build_lock_operation_write(operation)
    transport.send_plaintext_operation(write.payload)
    return write
