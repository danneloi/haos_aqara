"""Language voice-pack OTA streaming over the AUX channel (ff91/ff92).

Wire evidence (2026-09-02, `captures/ota/btsnoop_end.log`, both directions)
established the real mechanism:

- The transfer is NOT a standalone plaintext blast. It runs INSIDE a fully
  authenticated aqara session (ECDH done, CCCD enabled on ff62/ff64/ff92/ff08,
  control channel kept alive). A bare unauthenticated ff91 write is ignored.
- The phone streams the voice `.bin` (wrapped with per-block markers + an
  activation tail + two `0x90` commit frames) to ff91 as WRITE_WITHOUT_RESPONSE.
- The lock **block-acks on ff92** — ~1637 notifications for a full transfer —
  i.e. it is flow-controlled, not fire-and-forget.
- The control channel must keep receiving keepalives or the lock goes quiet
  ~30 s in.

This module drives that stream given a :class:`~aqara_ble.session.PostAuthContext`
(handed in after auth by ``run_authenticated_lock_operation(post_auth=…)``). It
is deliberately a thin, observable driver: it streams the captured/con­structed
frames, interleaves control keepalives, and surfaces every ff92 ack so a caller
can see whether the lock engaged (and, crucially, whether the `0x90` commit was
accepted or rejected).
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import time
from dataclasses import dataclass, field

from .ota_language import (
    OTA_DATA_PREFIX,
    OTA_SUBCMD_ID,
    OTA_SUBCMD_MANIFEST,
    build_ota_control_frame,
    build_ota_data_plan,
    build_ota_manifest_json,
    crc16_xmodem,
    ota_decrypt,
)
from .session import PostAuthContext

# The pre-stream OTA "arming" reads the app issues on the control channel right
# before it starts pushing ff91, recovered by decrypting the capture's control
# channel (keystream reuse; 2026-09-02). Plaintext is the `<op> <family> <op>`
# read shape. The hypothesis under test: issuing these transitions the lock's OTA
# state machine into "ready to receive", without which it ignores the ff91 stream.
ARMING_READS: tuple[tuple[str, bytes], ...] = (
    ("SYNC_OTA_URL", bytes([0x1A, 0x01, 0x1A])),
    ("READ_LOCK_LANGUAGE", bytes([0x68, 0x01, 0x68])),
    ("VOICE_OTA_INFO_GET", bytes([0xA6, 0x03, 0xA6])),
)


#: OTA info-frame language display names by file-name language code (the exact
#: strings the app sends in the subcmd-0x01 info frame; FR verified vs capture).
_OTA_LANG_NAMES = {"FR": "Français", "ES": "Español", "EN": "English", "DE": "Deutsch",
                   "IT": "Italiano", "PT": "Português", "ZH": "中文"}


def _lang_from_filename(filename: str) -> str:
    """Map ``U200_<CODE>_audio_burn.bin`` → the app's language display name."""
    parts = filename.upper().split("_")
    for p in parts:
        if p in _OTA_LANG_NAMES:
            return _OTA_LANG_NAMES[p]
    return "English"


@dataclass
class VoicePackResult:
    """Outcome of a from-scratch language voice-pack OTA push."""

    frames_sent: int
    duration_s: float
    #: (seconds-since-start, decoded-json-dict | raw-bytes) for each ff92 ack.
    acks: list[tuple[float, object]] = field(default_factory=list)
    completed: bool = False
    final_status: dict | None = None
    stalled_at: int | None = None


async def run_voice_pack_ota(
    ctx: PostAuthContext,
    blob: bytes,
    filename: str,
    *,
    arm: bool = True,
    # SAFE defaults (2026-09-04): streaming too fast corrupts blocks → the lock's
    # final MD5/CRC check fails → `xfer_statu:abort` at progress 100 (NOT a
    # presence gate — see docs/devices/u200/keypad-and-presence.md and
    # ota-0x90-investigation.md: "delay 10ms → abort; 25ms → success"). The old
    # 0.006 s / window 3 defaults abort reproducibly over the ESPHome proxy; the
    # historically-successful run used 0.033 s / window 1. Callers can go faster
    # explicitly on a transport that flow-controls (bumble/Mac WoR gating).
    data_delay: float = 0.025,
    keepalive_every_s: float = 8.0,
    ack_timeout_s: float = 30.0,
    ack_wait_s: float = 4.0,
    window: int = 1,
    stall_s: float = 12.0,
    max_resends: int = 30,
    manifest_wait_s: float = 90.0,
    manifest_resend_s: float = 4.0,
    post_manifest_settle_s: float = 4.0,
    resume_from: int = 0,
    skip_manifest: bool = False,
    language_name: str | None = None,
    progress: object | None = None,
) -> VoicePackResult:
    """Drive the full language voice-pack OTA from scratch, inside ``ctx``'s
    authenticated session — the exact protocol captured live 2026-09-02:

      1. ``0x90 || CCM(\\x04{"ID":255}\\x00)``               (start)
      2. ``0x90 || CCM(\\x03{"MCU_role":"receiver","file_info":…}\\x00)`` (manifest)
      3. stream the ``.bin`` as XMODEM-framed ``0x11`` data writes to ff91
      4. lock reports ``{"ID":0,"xfer_statu":"success","progress":100}`` on ff92
      5. ``0x90 || CCM(\\x04{"ID":255}\\x00)``               (close)

    All control short-packs are AES-CCM under the session key+nonce (the same
    codec as the control channel); ff92 acks are decrypted the same way.
    """

    def decode_ack(raw: bytes) -> dict | None:
        if not raw:
            return None
        body = raw[1:] if raw[0] == 0x90 else raw
        try:
            pt = ota_decrypt(ctx.session_key_hex, ctx.nonce_hex, body)
            start = pt.index(b"{")
            end = pt.rindex(b"}") + 1
            obj = json.loads(pt[start:end])
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None

    acks: list[tuple[float, object]] = []
    state = {"done": False, "status": None, "manifest_acked": False, "stalled_at": None,
             "nak": 0, "resends": 0, "blockack": 0}
    t0 = time.monotonic()

    async def drain() -> None:
        while True:
            channel, data = await ctx.aux_reports.get()
            if channel != "ff92":
                continue
            raw = bytes(data)
            obj = decode_ack(raw)
            acks.append((time.monotonic() - t0, obj if obj is not None else raw))
            # ff92 status codes are 2-byte plaintext (confirmed vs the app capture,
            # btsnoop_start_50pct.log 2026-09-03): 0x1106 = per-block ACK (709 for a
            # 708-block transfer — exactly one per block), 0x1115 = NAK/retransmit,
            # 0x1143 = start/idle marker (only 2 in the whole app transfer). Advance
            # only on a real 0x1106; retransmit on 0x1115; ignore 0x1143.
            if raw[:2] == b"\x11\x06":
                state["blockack"] = state.get("blockack", 0) + 1
            elif raw[:2] == b"\x11\x15":
                state["nak"] = state.get("nak", 0) + 1
            if isinstance(obj, dict):
                state["manifest_acked"] = True
                if obj.get("xfer_statu") in ("success", "abort"):
                    state["done"] = True
                    state["status"] = obj

    def ctrl(subcmd: int, js: bytes) -> bytes:
        return build_ota_control_frame(ctx.session_key_hex, ctx.nonce_hex, subcmd, js)

    drainer = asyncio.ensure_future(drain())
    try:
        if arm:
            for _name, pt in ARMING_READS:
                await ctx.send_control(pt)
                await ctx.read_control(timeout=3.0)

        # Handshake: send start + manifest, and RE-SEND both every
        # ``manifest_resend_s`` until the lock acks. The lock only answers while
        # it is "present" (a keypad touch), and that presence window is short and
        # hard to time by hand — re-sending lets a single keypad pulse anywhere in
        # ``manifest_wait_s`` land a manifest while the lock is awake. Once acked,
        # the OTA keeps the lock engaged on its own (no more presence needed), so
        # the bulk stream runs without any further keypad pulses.
        # On a resume after a mid-stream link drop we do NOT re-send the manifest
        # (that would reset the lock's receiver to block 0); we go straight to
        # streaming from ``resume_from``, relying on the lock having kept its OTA
        # receive state across the reconnect.
        manifest = build_ota_manifest_json(filename, blob)
        deadline = time.monotonic() + manifest_wait_s
        resend_at = 0.0
        while not skip_manifest and time.monotonic() < deadline and not state["manifest_acked"]:
            if time.monotonic() >= resend_at:
                await ctx.write_aux(ctrl(OTA_SUBCMD_ID, b'{"ID":255}'))
                await asyncio.sleep(0.2)
                await ctx.write_aux(ctrl(OTA_SUBCMD_MANIFEST, manifest))
                resend_at = time.monotonic() + manifest_resend_s
            await ctx.send_keepalive()
            await asyncio.sleep(0.4)

        # The keypad touch that woke the lock for the manifest ack leaves a brief
        # window where the lock NAKs incoming blocks (it's handling the keypad
        # event). Let it settle before streaming so those early NAKs don't trip
        # the lock's ~7-NAK abort.
        if not skip_manifest and state["manifest_acked"] and post_manifest_settle_s > 0:
            settle_end = time.monotonic() + post_manifest_settle_s
            while time.monotonic() < settle_end:
                await ctx.send_keepalive()
                await asyncio.sleep(0.5)

        # DATA PHASE — ack-driven flow control. The lock aborts if blocks arrive
        # faster than it acks them on ff92, so: send the init frame, wait for its
        # ack, then stream one block at a time keeping at most ``window`` blocks
        # ahead of the lock's ack count.
        init, groups = build_ota_data_plan(blob, filename)
        # OTA INFO frame (subcmd 0x01) — the app sends this right after the manifest
        # and BEFORE the file-info/data. It declares the file's MD5 (as a 32-char hex
        # ASCII string) and the language display name, as a little TLV:
        #   0x01 0x21 <md5-hex:32> 0x00 0x02 <len(lang)+1> <lang-utf8> 0x00
        # WITHOUT it the lock caps the transfer at exactly 16 blocks and NAKs the 17th
        # (decoded from the app's own SUCCESSFUL transfer, ccm_fr.log 2026-09-02;
        # MD5(FR bin) matched the captured token byte-exact). This is THE unlock past
        # the long-standing 16-block wall.
        if not skip_manifest:
            _md5 = hashlib.md5(blob).hexdigest().encode()  # md5 is protocol-defined, not security
            _lang = (language_name or _lang_from_filename(filename)).encode("utf-8")
            # Full plaintext exactly as the app encrypts it (ccm_fr.log 2026-09-02):
            #   0x01 0x21 <md5-hex:32> 0x00 0x02 <len(lang)+1> <lang-utf8> 0x00
            # It goes on the CONTROL channel ff61 (btsnoop: handle 0x0031), NOT the
            # 0x90 OTA channel — sending it as a 0x90 subcmd made the lock read it as
            # a version query and reject it (statu 0xFFFFFFFF).
            _info_pt = (
                b"\x01\x21" + _md5 + b"\x00\x02" + bytes([len(_lang) + 1]) + _lang + b"\x00"
            )
            # The app's ff61 wire frame for this command is a 3-byte header
            # ``3f a5 ff`` (a5 = VOICE_OTA_INFO_SET opcode, in cleartext) followed by
            # the CCM(payload) — NOT our usual single 0x01 write-prefix. With the 0x01
            # prefix the lock read it as a GET (replied 0xa6…) and never SET, so it
            # kept the default 16-block window. Replicate the exact header.
            from .control_codec import encrypt_control_payload  # noqa: PLC0415
            from .gatt_uuids import CONTROL_WRITE_UUID  # noqa: PLC0415
            _enc = encrypt_control_payload(
                ctx.session_key_hex, ctx.nonce_hex, plaintext=_info_pt
            )
            await ctx.client.write_gatt_char(
                CONTROL_WRITE_UUID, b"\x3f\xa5\xff" + _enc, response=False
            )
            # Drain the lock's ff62 reply (it acks the SET) so it doesn't sit in the
            # control-response queue; the value itself is not needed.
            with contextlib.suppress(Exception):
                await ctx.read_control(timeout=2.0)
            await asyncio.sleep(0.25)
        if not skip_manifest:
            await ctx.write_aux(init)
            base = len(acks)
            idl = time.monotonic() + ack_wait_s
            while time.monotonic() < idl and len(acks) <= base and not state["done"]:
                await asyncio.sleep(0.03)

        total = sum(len(g) for g in groups) + 1
        sent = 1  # the init frame
        last_ack_t = time.monotonic()
        # ABSOLUTE ack-count gating. The lock ACKs every block with one 0x1106 on
        # ff92 (confirmed: 709 acks for 708 blocks). ``base_ack`` is the 0x1106 count
        # after the init/file-info frame settles, so block ``gi`` is confirmed once
        # ``state["blockack"] >= base_ack + gi + 1``. This is immune to ack pipelining
        # (the lock often acks block N-1 while we send block N): a RELATIVE "did the
        # count go up since I started this block" test wrongly declared a block
        # unacked whenever its ack had already arrived early, and resent it forever
        # (reproducibly stuck at block ~16). Absolute counting fixes that.
        base_ack = state["blockack"]
        next_ka = time.monotonic() + keepalive_every_s
        last_ack_n = state["blockack"]
        # WINDOWED CONTINUOUS STREAMING — the app streams gaplessly (~4.5 blk/s, 708
        # blocks) so the lock's OTA receiver stays fed and flushes its buffer to flash
        # in the background WITHOUT the sender pausing. Strict per-block stop-and-wait
        # pauses right where the lock goes quiet to flush (~block 16) and deadlocks.
        # Here we keep up to ``window`` blocks in flight ahead of the confirmed 0x1106
        # count, pace each write, retransmit a NAK'd block, and stall only if the lock
        # stops acking for ``stall_s``.
        ngroups = len(groups)
        gi = resume_from
        while gi < ngroups and not state["done"]:
            confirmed = state["blockack"] - base_ack  # blocks the lock has 0x1106'd
            if state["blockack"] > last_ack_n:
                last_ack_n = state["blockack"]
                last_ack_t = time.monotonic()
            # Flow control: hold if we're already ``window`` blocks ahead of the acks.
            if (gi - confirmed) >= window:
                if time.monotonic() - last_ack_t > stall_s:
                    state["stalled_at"] = gi + 1
                    break
                # A NAK while holding → retransmit the oldest unacked block.
                if state["nak"] > state.get("nak_seen", 0):
                    state["nak_seen"] = state["nak"]
                    state["resends"] = state.get("resends", 0) + 1
                    if state["resends"] <= max_resends and confirmed < ngroups:
                        for w in groups[confirmed]:
                            await ctx.write_aux(w)
                            if data_delay > 0:
                                await asyncio.sleep(data_delay)
                await asyncio.sleep(0.005)
                continue
            for w in groups[gi]:
                await ctx.write_aux(w)
                sent += 1
                if data_delay > 0:
                    await asyncio.sleep(data_delay)
            gi += 1
            now = time.monotonic()
            if now >= next_ka:
                with contextlib.suppress(Exception):
                    await ctx.send_keepalive()
                next_ka = now + keepalive_every_s
            if progress is not None and (gi % 50 == 0 or gi == ngroups):
                progress(sent, total, state["blockack"])  # type: ignore[operator]

        # END-OF-TRANSFER / ACTIVATION (btsnoop_end.log): after the last data block
        # the app sends a 2-byte 0x1104 end-of-data marker, then a zero-filled
        # file-info frame (0x11 01 00 ff + 128x0x00 + CRC16) as the "activation", then
        # the 0x90 commit frame (subcmd 0x04 {"ID":255}) — each sent twice — and only
        # THEN does the lock reply xfer_statu:"success". Without this the lock has all
        # 1984 blocks but reports abort at progress 100.
        await asyncio.sleep(0.3)
        with contextlib.suppress(Exception):
            await ctx.write_aux(bytes([OTA_DATA_PREFIX, 0x04]))  # 0x1104 end-of-data
            await asyncio.sleep(0.15)
            _activation = (
                bytes([OTA_DATA_PREFIX, 0x01, 0x00, 0xFF]) + b"\x00" * 128
                + crc16_xmodem(b"\x00" * 128).to_bytes(2, "big")
            )
            for _ in range(2):
                await ctx.write_aux(_activation)
                await asyncio.sleep(0.15)
            for _ in range(2):
                await ctx.write_aux(ctrl(OTA_SUBCMD_ID, b'{"ID":255}'))
                await asyncio.sleep(0.15)

        deadline = time.monotonic() + ack_timeout_s
        while time.monotonic() < deadline and not state["done"]:
            await ctx.send_keepalive()
            await asyncio.sleep(0.5)
    finally:
        drainer.cancel()

    return VoicePackResult(
        frames_sent=sent,
        duration_s=time.monotonic() - t0,
        acks=acks,
        completed=bool(state["done"]),
        final_status=state["status"],
        stalled_at=state["stalled_at"],
    )
