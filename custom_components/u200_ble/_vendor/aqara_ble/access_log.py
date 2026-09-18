"""Read + decode the U200 stored access log over BLE (SYNC_LOG 0x13).

Reverse-engineered from the RN plugin (`getLogList` / `parseLogData` /
`parseLockLog`); see ``docs/devices/u200/access-log-read-spec.md`` and
``docs/devices/u200/access-log-protocol.md``. The lock (the always-on back
panel) stores its access history and returns it on request — the keypad/
front panel does NOT need to be awake for this.

Request frame (write-prefix ``0x03``): ``13 <fromLE:2> <toLE:2> <trailer:2>``
— a numeric record-index range, paged by the real app in fixed 30-record
steps (0-29, 30-59, 60-89, ...). The 2-byte trailer's exact formula is not
derived, but it IS required and IS a deterministic function of ``(from, to)``
only (confirmed live: byte-identical across independent BLE sessions against
the same lock) — see ``_KNOWN_PAGE_TRAILERS`` below, copied verbatim from two
real ``adb bugreport`` captures of the official app's own session (the same
literal bytes `probe_sync_log.py` uses).

CONFIRMED 2026-09-08: omitting the trailer (this module's behaviour before
this date) does not make the lock reject the request — it silently answers
with page 0 (records 0-29) regardless of the requested ``end``, no matter how
high ``end`` was. That is why ``read_access_log(0, 49)`` was only ever
returning the newest 30 records, never the newest 49/50 — the extra 19 were
silently dropped, along with anything beyond record 29 in age. Any event that
scrolled past position 29 (a page's worth of *any* logged event — not just
credential-open, also plain lock/unlock/anti-lock/exception rows) between it
happening and the next read would look "missing" purely because of this, with
no protocol-level explanation needed. Fixed here by always requesting whole,
exactly-30-record, trailer-complete pages and paging as many as the caller's
range needs.

Reply: a 9-byte container header (18 hex chars) to drop, then self-describing
entries ``[prefix:2][len L:1][payload:L]``. Each payload is one log record
decoded by :func:`decode_lock_log_record`:

    record = [attr:1][userId:4][timestamp:4 LE][tail…]
    attr high nibble = method (for a credential open, low nibble == 0)
    timestamp = little-endian u32 seconds

Method (high nibble of attr, for `lo == 0` credential opens) and the low-nibble
event class are proven from the plugin control flow; the exact attr of a real
open-by-credential row is pending one live confirmation.
"""
from __future__ import annotations

from dataclasses import dataclass

#: attr high-nibble → unlock method (credential-open rows, low nibble 0).
METHOD_BY_HI = {
    0x0: "ble",           # userId 00000000 = app, 02000000 = homekit, else zigbee
    0x1: "password",
    0x2: "fingerprint",   # userId[4:8]=='0680' fingerprint, else face
    0x3: "key",
    0x5: "NFC",
    0x6: "temp_password",
    0x9: "homekit",
    0xA: "key",
    0xC: "homenet",
    0xD: "matter",
}

#: low nibble → event class (non-open events are status/exception, not accesses).
EVENT_CLASS = {
    0x0: "credential_open",
    0x1: "lock_event",
    0x2: "open_anti_lock",
    0x3: "close_anti_lock",
    0x4: "knob_or_finger_in",
    0x5: "lockout_or_finger_up",
    0xF: "lock_exception",
}

#: Hex chars to drop before the first entry. CONFIRMED live 2026-09-07: the
#: library-visible 0x13 reply already starts at the first entry (each entry is
#: ``[prefix:2][len L:1][payload:L]``, e.g. ``0b0009<9-byte record>``), so there
#: is NO extra container header to strip here — 0. (The plugin's ``slice(18)`` is
#: against its own raw transport buffer, which the library has already unwrapped.)
_REPLY_HEADER_HEXCHARS = 0

#: Number of records per SYNC_LOG page — the app's own fixed page size, and
#: (see module docstring) the size the lock silently clamps ANY request to
#: when the request is missing a valid trailer.
PAGE_SIZE = 30

#: Confirmed literal 2-byte trailers for standard 30-record pages, copied
#: verbatim from two real `adb bugreport` captures of the official app's own
#: BLE session (see docs/devices/u200/access-log-protocol.md and
#: `probe_sync_log.py`'s CANDIDATE_REAL_FRAMES / CANDIDATE_JUMP_FRAMES, same
#: source bytes). Keyed by (from, to) record index (inclusive).
_KNOWN_PAGE_TRAILERS: dict[tuple[int, int], bytes] = {
    (0, 29): bytes.fromhex("a07f"),
    (30, 59): bytes.fromhex("c27f"),
    (60, 89): bytes.fromhex("6c7f"),
    (90, 119): bytes.fromhex("967a"),
    (120, 149): bytes.fromhex("b87a"),
    (150, 179): bytes.fromhex("7a75"),
    (180, 209): bytes.fromhex("d475"),
    (210, 239): bytes.fromhex("3e70"),
    (240, 269): bytes.fromhex("1071"),
    (270, 299): bytes.fromhex("b278"),
    (300, 329): bytes.fromhex("1c78"),
    (330, 359): bytes.fromhex("e67d"),
    (360, 389): bytes.fromhex("c87d"),
    (390, 419): bytes.fromhex("0a72"),
    (420, 449): bytes.fromhex("a472"),
    (450, 479): bytes.fromhex("6e77"),
    (480, 509): bytes.fromhex("8077"),
    (510, 539): bytes.fromhex("2274"),
    (540, 569): bytes.fromhex("cc71"),
    (570, 599): bytes.fromhex("f672"),
    (600, 629): bytes.fromhex("9874"),
}


def known_pages() -> list[tuple[int, int]]:
    """Return every (from, to) page for which a confirmed trailer is known, sorted."""
    return sorted(_KNOWN_PAGE_TRAILERS)


def iter_pages(start: int, end: int) -> list[tuple[int, int]]:
    """Split a [start, end] record-index range into whole 30-record pages.

    Always returns full ``PAGE_SIZE``-wide, page-aligned (start, end) pairs —
    e.g. ``iter_pages(0, 49)`` → ``[(0, 29), (30, 59)]`` — because a
    non-page-aligned request is exactly what got silently clamped away (see
    module docstring). Pages beyond the confirmed table (past record 629) are
    still returned so a caller CAN try them, but :func:`build_access_log_frame`
    will fall back to a trailer-less (unconfirmed, possibly clamped) frame for
    those.
    """
    if start < 0 or end < start:
        raise ValueError("need 0 <= start <= end")
    pages = []
    p = (start // PAGE_SIZE) * PAGE_SIZE
    while p <= end:
        pages.append((p, p + PAGE_SIZE - 1))
        p += PAGE_SIZE
    return pages


def build_access_log_frame(start: int, end: int) -> str:
    """Return the ``read_burst`` spec for one SYNC_LOG page.

    Uses the confirmed literal trailer when ``(start, end)`` is a known page
    (see ``_KNOWN_PAGE_TRAILERS``); a page that is not exactly on a known
    30-record boundary silently falls back to the old trailer-less 5-byte
    frame — UNCONFIRMED, and (per the module docstring) likely to just be
    answered with page 0 again. Prefer :func:`iter_pages` to always request
    whole, known pages.
    """
    if not (0 <= start <= 0xFFFF and 0 <= end <= 0xFFFF):
        raise ValueError("start/end must be 16-bit indices")
    body = start.to_bytes(2, "little") + end.to_bytes(2, "little")
    trailer = _KNOWN_PAGE_TRAILERS.get((start, end))
    if trailer is not None:
        body += trailer
    return f"03:13{body.hex()}"


@dataclass(frozen=True)
class AccessLogEntry:
    timestamp: int          # unix seconds (0 if unparseable)
    method: str | None      # unlock method for credential opens, else None
    event_class: str        # "credential_open" / "lock_event" / "lock_exception" / …
    user_id: str            # raw 4-byte user/credential id (hex)
    credential_id: int      # user_id decoded little-endian (see decode_credential_id)
    raw_attr: int           # the attr byte
    raw_hex: str            # the whole record


def decode_credential_id(user_id_hex: str) -> int:
    """Decode a raw 4-byte ``user_id`` hex string into its little-endian id.

    CONFIRMED 2026-09-09 (two independent credentials, cross-checked against a
    fresh live BLE capture of the access log): for a ``credential_open`` row,
    this is the SAME numeric id the cloud roster (``GET /dev/lock/query``)
    calls ``typeValue`` and :func:`aqara_ble.lock_ops.build_delete_user` takes
    as its ``user_id`` argument -- it identifies the specific acting
    credential, not just its unlock method. Returns 0 for an empty/short
    ``user_id_hex`` (e.g. a non-open row where the field is meaningless).
    """
    if len(user_id_hex) < 8:
        return 0
    return int.from_bytes(bytes.fromhex(user_id_hex[:8]), "little")


def decode_lock_log_record(record_hex: str) -> AccessLogEntry:
    """Decode ONE log record (starting at the attr byte) — used for stored + push."""
    rec = record_hex
    attr = int(rec[0:2], 16)
    hi, lo = attr >> 4, attr & 0x0F
    user_id = rec[2:10] if len(rec) >= 10 else ""
    ts = 0
    if len(rec) >= 18:
        ts = int(rec[16:18] + rec[14:16] + rec[12:14] + rec[10:12], 16)
    method: str | None = None
    if lo == 0x0:  # a credential-open row: the high nibble names the method
        method = METHOD_BY_HI.get(hi)
        if hi == 0x2 and user_id[4:8] != "0680":
            method = "face"
        elif hi == 0x0 and user_id == "02000000":
            method = "homekit"
    return AccessLogEntry(
        timestamp=ts,
        method=method,
        event_class=EVENT_CLASS.get(lo, f"class-0x{lo:x}"),
        user_id=user_id,
        credential_id=decode_credential_id(user_id),
        raw_attr=attr,
        raw_hex=rec,
    )


def decode_access_log(reply_hex: str, *, header_hexchars: int = _REPLY_HEADER_HEXCHARS) -> list[AccessLogEntry]:
    """Decode a SYNC_LOG (0x13) reply page into access-log entries.

    Drops the ``header_hexchars`` container header, then walks the self-describing
    entries (``[prefix:2][len L:1][payload:L]``) and decodes each record.
    """
    blob = reply_hex[header_hexchars:] if len(reply_hex) > header_hexchars else ""
    out: list[AccessLogEntry] = []
    p = 0
    n = len(blob)
    while p + 6 <= n:
        length = int(blob[p + 4 : p + 6], 16)
        end = p + 6 + length * 2
        if end > n:
            break
        record = blob[p + 6 : end]
        if record:
            out.append(decode_lock_log_record(record))
        p = end
    return out


# -- SYNC_LOG-page compatibility layer --------------------------------------
#
# `haos_aqara` (the Home Assistant integration) was originally written
# against an earlier, page-oriented SYNC_LOG decoder (`decode_sync_log_page`,
# `SyncLogRecord`) that lived in a since-abandoned, vendored copy of this
# library. That decoder was never wrong, just less general than the
# `AccessLogEntry`/`decode_access_log`/`read_access_log` machinery above
# (which additionally handles paging/trailers correctly -- see the module
# docstring). Rather than maintain two competing decoders, this section
# restores the OLD names/shapes `haos_aqara` imports as thin adapters over
# the one real decoder, so `haos_aqara`'s `client.py`/`sensor.py` need no
# changes. New code should prefer `AccessLogEntry`/`read_access_log` directly.


@dataclass(frozen=True)
class SyncLogRecord:
    """One decoded SYNC_LOG (0x13) access-log entry (legacy/compat shape).

    Equivalent to :class:`AccessLogEntry` -- ``event_type`` is
    ``AccessLogEntry.raw_attr`` and ``extra_hex`` is ``AccessLogEntry.user_id``
    -- kept only so callers written against the old page decoder keep working.
    See :func:`sync_log_record_from_entry`.
    """

    raw_hex: str
    event_type: int
    extra_hex: str
    timestamp: int


def sync_log_record_from_entry(entry: AccessLogEntry) -> SyncLogRecord:
    """Adapt an :class:`AccessLogEntry` into the legacy :class:`SyncLogRecord` shape."""
    return SyncLogRecord(
        raw_hex="0b0009" + entry.raw_hex,
        event_type=entry.raw_attr,
        extra_hex=entry.user_id,
        timestamp=entry.timestamp,
    )


#: `event_type` (== `AccessLogEntry.raw_attr`) -> label. CONFIRMED live
#: 2026-09-02 (own lock) by cross-referencing 30+ decoded records against the
#: official app's own "Protokoll" (history) screen -- every timestamp matched
#: the app's displayed local time to the exact second (decoded here as UTC).
#: `0x20`/`0xa1` were additionally confirmed by a labelled physical test
#: (close, then fingerprint open, at a known real-world time). `0xff`
#: confirmed for one of its two seen `extra` values; `0xd0` seen only once (a
#: Matter-based unlock). A type not in this table has no confirmed label yet --
#: `decode_sync_log_event_label` returns `None` rather than guessing one.
SYNC_LOG_EVENT_LABELS: dict[int, str] = {
    0x20: "unlock_fingerprint",
    0xA1: "lock",
    0xD1: "lock",
    0xA4: "unlockable_from_inside_or_key",
    0xD0: "unlock_matter",
    0xFF: "keypad_removed_alert",
}


def decode_sync_log_event_label(event_type: int) -> str | None:
    """Best-known label for a SYNC_LOG record's `event_type` byte, or `None`.

    See `SYNC_LOG_EVENT_LABELS` for what's confirmed and how.
    """
    return SYNC_LOG_EVENT_LABELS.get(event_type)


def decode_sync_log_credential_slot(record: SyncLogRecord) -> int | None:
    """The fingerprint/credential slot number for a `type=0x20` (unlock) record.

    CONFIRMED live 2026-09-02 (own lock): for `event_type == 0x20`, `extra` is
    `<slot:1> 00 01 80` -- the leading byte is the enrolled credential's slot
    number. This is a SPECIAL CASE of the more general
    :func:`decode_credential_id` (the slot is just its low byte) -- valid only
    because this household's credential ids happen to share the
    `0x8001__xx` pattern. Prefer `AccessLogEntry.credential_id` for anything
    new; this stays only for `haos_aqara`'s existing, deliberately
    name-free "slot number, not a name" sensor. Returns `None` for any other
    `event_type`, or if `extra` doesn't match the confirmed `.. 00 01 80`
    shape (keeps this honest rather than guessing a slot number out of an
    unrelated byte layout).
    """
    if record.event_type != 0x20:
        return None
    raw = bytes.fromhex(record.extra_hex)
    if len(raw) == 4 and raw[1:] == b"\x00\x01\x80":
        return raw[0]
    return None
