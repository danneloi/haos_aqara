"""Lock state snapshot decoded from the control-channel response (feature 019).

`run_authenticated_lock_operation` already returns the **decrypted** control
response. This module turns that response into a typed `LockState`. It is
deliberately **honest**: `raw_hex` is always exposed, and a decoded field is set
**only** when captured evidence supports it — otherwise it stays `None`. We never
invent a lock state.

Confirmed real samples (2026-08-17, this project's own lock, own account):

    keepalive `2f012f`  ->  response `2f00 2c06`
    unlock    (open)    ->  response `7400 7706`

Working hypothesis (NOT yet confirmed — needs labelled captures in known physical
states): the response echoes the sub-command byte (`0x2f` keepalive, `0x74`
operate) followed by a direction/status byte and a 2-byte tail. The direction
byte of the operate response looked like `0x00` after an unlock — plausibly the
resulting bolt position — but a single sample is not proof. `decode_lock_state`
therefore leaves `locked`/`battery_percent` as `None` until a sample set pins
them down (see docs/devices/u200/validation.md capture procedure).
"""

from __future__ import annotations

from dataclasses import dataclass

#: Where a LockState came from.
SOURCE_KEEPALIVE = "keepalive"
SOURCE_OPERATION = "operation"
SOURCE_QUERY = "query"
SOURCE_EVENT = "event"  # spontaneous ff62 report (needs an open session)
SOURCE_BATTERY = "battery"  # GET_BATTERY_INFO (0xde) read response

#: GET_BATTERY_INFO (0xde) reply. CONFIRMED live 2026-08-25 against this project's
#: own lock: the read `de 00 158b3609` returns `de 00 07 00 01 01 <pct> 00 00 <crc16>`
#: — e.g. `de0007000101300000c70a`, byte 6 = 0x30 = 48% (Matter reported 49%, ±1).
GET_BATTERY_INFO_REPLY = 0xDE


#: LOCK_STATUS (0x07) reply. CONFIRMED live 2026-08-25 against this project's own
#: lock, correlated with ff62 (0x1d locked / 0xdd unlocked): the read `07 00 158b3609`
#: returns `07 00 <status> 00 00 00 00 00 00 <crc16>` where **bit 0x02 of `status`
#: (byte 2) is the bolt-retracted flag** — set = unlocked, clear = locked. Samples:
#: 0x06 & 0x0b = unlocked, 0x04 = locked (ff62-confirmed).
LOCK_STATUS_REPLY = 0x07
STATUS_UNLOCKED_BIT = 0x02


def decode_lock_status(raw: bytes | None) -> bool | None:
    """Decode a LOCK_STATUS (0x07) response into the bolt position.

    Returns ``True`` (locked), ``False`` (unlocked), or ``None`` when the frame is
    not a recognised LOCK_STATUS reply. Bit ``0x02`` of the status byte is the
    bolt-retracted flag: set → unlocked, clear → locked.
    """
    if not raw or len(raw) < 3:
        return None
    if raw[0] != LOCK_STATUS_REPLY or raw[1] != 0x00:
        return None
    return (raw[2] & STATUS_UNLOCKED_BIT) == 0


def decode_battery_info(raw: bytes | None) -> int | None:
    """Extract the battery percentage from a GET_BATTERY_INFO (0xde) response.

    The confirmed reply is ``de 00 07 00 01 01 <pct> 00 00 <crc16>`` where byte 6
    is the charge percentage. Returns the percentage (0..100) or ``None`` when the
    frame is not a recognised battery reply or the value is out of range.
    """
    if not raw or len(raw) < 7:
        return None
    if raw[0] != GET_BATTERY_INFO_REPLY or raw[1] != 0x00:
        return None
    pct = raw[6]
    return pct if 0 <= pct <= 100 else None


# ── Feature settings decoded from the app (feature 032) ──────────────────────
# Correlated live 2026-08-25 by driving the phone app while reading each opcode:
# door type "EU" ↔ e0000101, pull-spring ON+2s ↔ e400010200, assist-turn OFF ↔ e9000084.

GET_DOOR_LOCK_TYPE_REPLY = 0xE0
GET_PULL_SPRING_REPLY = 0xE4
GET_ASSIST_TURN_REPLY = 0xE9
_DOOR_TYPES = {0x01: "eu", 0x02: "uk", 0x03: "us"}


def decode_door_type(raw: bytes | None) -> str | None:
    """Decode GET_DOOR_LOCK_TYPE (0xe0) → 'eu' | 'uk' | 'us' (or None).

    Confirmed live: `e0 00 01 01` = EU (byte 2 = 0x01). UK/US map from the app's
    option order; an unrecognised value returns ``f"type-{n}"`` rather than None.
    """
    if not raw or len(raw) < 3 or raw[0] != GET_DOOR_LOCK_TYPE_REPLY or raw[1] != 0x00:
        return None
    return _DOOR_TYPES.get(raw[2], f"type-{raw[2]}")


def decode_assist_turn(raw: bytes | None) -> bool | None:
    """Decode GET_ASSIST_TURN (0xe9) → enabled flag (byte 2). Confirmed OFF = 0x00."""
    if not raw or len(raw) < 3 or raw[0] != GET_ASSIST_TURN_REPLY or raw[1] != 0x00:
        return None
    return raw[2] != 0x00


def decode_pull_spring(raw: bytes | None) -> tuple[bool, int] | None:
    """Decode GET_PULL_SPRING (0xe4) → (enabled, retraction_seconds).

    Confirmed live: `e4 00 01 02 00` = ON, 2 s (byte 2 = enabled, byte 3 = seconds).
    """
    if not raw or len(raw) < 4 or raw[0] != GET_PULL_SPRING_REPLY or raw[1] != 0x00:
        return None
    return (raw[2] != 0x00, raw[3])


# ── configuration settings reads (2026-08-27, confirmed live) ────────────────
# These read over BLE from our OWN authenticated session — there is no privilege
# tier (see docs/devices/u200/settings-protocol.md). Frames + replies captured on
# fw 3.0.0_0085 and cross-checked byte-for-byte against the official app:
#   volume   0xc3  `c3 04 43 01` -> `c3 00 02 04 …`
#   language 0x68  `68 01 68`    -> `68 00 02 01 00 00 …`
#   alarm    0x84  `84 02 04 07` -> `84 00 02 00 10 …`
#   setting  0x1a  `1a 01 1a`    -> `1a 00 00 01 <alert> 0a 01 01 02 00 00 02 00 …`
GET_LOCK_VOLUME_REPLY = 0xC3
GET_LANGUAGE_REPLY = 0x68
GET_ALARM_VOLUME_REPLY = 0x84
GET_LOCK_SETTING_REPLY = 0x1A

#: Alert volume lives in the lock-setting bulk blob (0x1a), byte 4. Fully pinned
#: 2026-08-27 by change-and-reread: 01=Alto, 03=Bajo, 04=Silencio → 02=Medio.
ALERT_VOLUME_LEVELS = {0x01: "high", 0x02: "medium", 0x03: "low", 0x04: "silent"}
#: Lock language, byte 3 of the 0x68 reply. Only 'es' (0x01) is confirmed so far.
LANGUAGES = {0x01: "es"}


def decode_alert_volume(raw: bytes | None) -> str | None:
    """Decode alert volume from the lock-setting blob (0x1a, byte 4) → level name.

    CONFIRMED live 2026-08-27 (change-and-reread): 01='high', 02='medium',
    03='low', 04='silent'. An unknown code returns ``f"level-{n}"`` (never None
    for a valid reply), so the caller always sees real data.
    """
    if not raw or len(raw) < 5 or raw[0] != GET_LOCK_SETTING_REPLY or raw[1] != 0x00:
        return None
    return ALERT_VOLUME_LEVELS.get(raw[4], f"level-{raw[4]}")


def decode_lock_volume(raw: bytes | None) -> int | None:
    """Decode the system/voice volume (0xc3) → level byte (raw[2]).

    Live sample 2026-08-27: `c3 00 02 04 …` (byte 2 = 0x02). The exact scale is not
    yet pinned by a change-and-reread, so this returns the raw level integer.
    """
    if not raw or len(raw) < 3 or raw[0] != GET_LOCK_VOLUME_REPLY or raw[1] != 0x00:
        return None
    return raw[2]


def decode_alarm_volume(raw: bytes | None) -> str | None:
    """Decode the alarm (siren) volume (0x84) → raw value hex.

    Live sample 2026-08-27: `84 00 02 00 10 …`. Scale/field layout not yet pinned by
    a change-and-reread, so this honestly returns the value bytes (reply minus the
    opcode, status and 2-byte CRC) as hex rather than a guessed level.
    """
    if not raw or len(raw) < 5 or raw[0] != GET_ALARM_VOLUME_REPLY or raw[1] != 0x00:
        return None
    return raw[2:-2].hex()


def decode_language(raw: bytes | None) -> str | None:
    """Decode the lock language (0x68, byte 3) → language code.

    Live sample 2026-08-27: `68 00 02 01 00 00 …` = Español (byte 3 = 0x01). Only
    'es'=0x01 is confirmed; other indices fall through to ``f"lang-{n}"``.
    """
    if not raw or len(raw) < 4 or raw[0] != GET_LANGUAGE_REPLY or raw[1] != 0x00:
        return None
    return LANGUAGES.get(raw[3], f"lang-{raw[3]}")


@dataclass(frozen=True)
class LockSettings:
    """Configuration settings read over BLE in one persistent session.

    ``alert_volume`` is fully confirmed ('high'/'medium'/'low'/'silent'). The others
    carry real captured data with the exact enum scales still being pinned:
    ``system_volume`` is the raw 0xc3 level byte, ``language`` decodes byte 3 of
    0x68, ``alarm_volume`` is the 0x84 value hex. Each field is ``None`` when that
    opcode did not answer. ``raw`` keeps every reply for debugging/refinement.
    """

    alert_volume: str | None = None
    system_volume: int | None = None
    language: str | None = None
    alarm_volume: str | None = None
    raw: dict[str, str | None] | None = None


# ── ff62 spontaneous event stream (feature 034) ──────────────────────────────
# Captured live 2026-08-26 by holding the connection while operating the lock.
# Frame shape: <opcode:1> <arg:1> [payload] <unix_ts:4 LE> <crc:2>.
#   0xdd unlock, 0x1d lock (arg = source; 0xff = manual, payload byte = lock
#   counter), 0x15 status/heartbeat. Battery is pushed separately as a 0xde frame
#   `de 07 00 01 01 <pct> 00 00 <crc>` (no timestamp).
LOCK_SOURCES = {0xFF: "manual"}


@dataclass(frozen=True)
class LockEvent:
    """One spontaneous ff62 report decoded into a typed event."""

    raw_hex: str
    kind: str  # "locked" | "unlocked" | "battery" | "status" | "unknown"
    locked: bool | None = None
    battery_percent: int | None = None
    source: str | None = None  # for lock events: "manual" / "source-0xNN"
    timestamp: int | None = None  # Unix seconds, when the frame carries one


def decode_event(raw: bytes | None) -> LockEvent | None:
    """Decode a spontaneous ff62 frame into a :class:`LockEvent` (or None).

    Confirmed live: `dd…` unlock, `1d ff <ctr>00dec0…` manual lock, `de…<pct>…`
    battery push, `15…` status. The 4 bytes before the 2-byte CRC are a Unix
    timestamp for the state/status frames.
    """
    if not raw or len(raw) < 6:
        return None
    op = raw[0]
    ts = int.from_bytes(raw[-6:-2], "little") if len(raw) >= 8 else None
    if op == REPORT_UNLOCKED:
        return LockEvent(raw.hex(), "unlocked", locked=False, timestamp=ts)
    if op == REPORT_LOCKED:
        source = LOCK_SOURCES.get(raw[1], f"source-0x{raw[1]:02x}")
        return LockEvent(raw.hex(), "locked", locked=True, source=source, timestamp=ts)
    if op == GET_BATTERY_INFO_REPLY and len(raw) >= 5:
        pct = raw[-5]  # `… <pct> 00 00 <crc:2>` — same offset pushed or read
        if 0 <= pct <= 100:
            return LockEvent(raw.hex(), "battery", battery_percent=pct)
    if op == REPORT_STATUS:
        return LockEvent(raw.hex(), "status", timestamp=ts)
    return LockEvent(raw.hex(), "unknown")

#: ff62 spontaneous-report opcodes (first byte). CONFIRMED live 2026-08-24
#: against this project's own lock: the lock pushes 0x1d when it becomes locked
#: and 0xdd when unlocked; 0x15 is a periodic status heartbeat (no position here).
REPORT_LOCKED = 0x1D
REPORT_UNLOCKED = 0xDD
REPORT_STATUS = 0x15


def decode_state_report(raw: bytes | None) -> bool | None:
    """Decode a spontaneous ff62 report frame into the bolt position.

    Returns ``True`` (locked, first byte ``0x1d``), ``False`` (unlocked,
    ``0xdd``), or ``None`` when the frame is not a position report (e.g. the
    ``0x15`` heartbeat). Confirmed live — see the opcode constants above.
    """
    if not raw:
        return None
    first = raw[0]
    if first == REPORT_LOCKED:
        return True
    if first == REPORT_UNLOCKED:
        return False
    return None


@dataclass(frozen=True)
class LockState:
    """A point-in-time view of the lock, decoded from a control response.

    ``raw_hex`` is the decrypted response bytes (or ``None`` if the lock did not
    answer). Decoded fields are ``None`` unless confirmed by evidence — a
    consumer must treat ``None`` as "unknown", never as a default state.
    """

    raw_hex: str | None
    source: str
    responded: bool
    locked: bool | None = None
    battery_percent: int | None = None

    @property
    def sub_command(self) -> int | None:
        """The echoed sub-command byte of the response, if any (e.g. 0x2f/0x74)."""

        if not self.raw_hex or len(self.raw_hex) < 2:
            return None
        return int(self.raw_hex[:2], 16)


def decode_front_connection(raw: bytes | None) -> bool | None:
    """Decode a GET_FRONT_CONNECTION (0xdd) reply → is the keypad present?

    Frame ``dd 00 <presence:1> 04 <crc>`` — byte[2] is the front-panel (keypad)
    connection state: ``0x01`` = present, ``0x00`` = absent. Confirmed live
    2026-09-07 by correlation with a fingerbot press (0x00→0x01 on wake). Returns
    ``True``/``False``, or ``None`` if the reply is missing/too short/not a 0xdd.
    """
    if not raw or len(raw) < 3 or raw[0] != 0xDD:
        return None
    return raw[2] == 0x01


def decode_lock_state(raw: bytes | None, source: str) -> LockState:
    """Build a `LockState` from a decrypted control response.

    Only evidence-backed fields are populated; everything unconfirmed stays
    ``None``. Never raises on unexpected bytes and never invents a state.
    """

    if not raw:
        return LockState(raw_hex=None, source=source, responded=False)
    # Present the raw bytes; decoded fields remain None until confirmed by a
    # labelled capture set (see module docstring / validation.md).
    return LockState(raw_hex=raw.hex(), source=source, responded=True)


__all__ = [
    "GET_BATTERY_INFO_REPLY",
    "LOCK_STATUS_REPLY",
    "REPORT_LOCKED",
    "REPORT_STATUS",
    "REPORT_UNLOCKED",
    "SOURCE_BATTERY",
    "SOURCE_EVENT",
    "SOURCE_KEEPALIVE",
    "SOURCE_OPERATION",
    "SOURCE_QUERY",
    "STATUS_UNLOCKED_BIT",
    "LockEvent",
    "LockState",
    "decode_assist_turn",
    "decode_battery_info",
    "decode_door_type",
    "decode_event",
    "decode_front_connection",
    "decode_lock_state",
    "decode_lock_status",
    "decode_pull_spring",
    "decode_state_report",
]
