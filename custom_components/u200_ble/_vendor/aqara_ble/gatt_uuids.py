"""GATT identity constants for the U200 — device-specific leaf data.

This module is a **leaf**: it imports nothing else from ``aqara_ble``. It
holds the service/characteristic UUIDs, the GATT-caching preamble UUID16 tuple,
the pre-auth CCCD-enable order, and the U200 service-UUID tuples — the concrete
identity values the architecture doc classifies as device-specific.

It exists to break the previous layering inversion where the low-level radio
layer (:mod:`aqara_ble.transport`) imported these constants *upward* from
:mod:`aqara_ble.session` (the authenticated-protocol/orchestration layer).
Both ``session`` and ``transport`` now import them *downward* from here, so
importing the transport no longer drags in ``session → auth → kdf → cryptography``.

These are pure relocations: the values are byte-identical to their previous
definitions in ``session.py``/``transport.py`` and MUST stay so
(Constitution Principle II — protocol fidelity).
"""

from __future__ import annotations

# ── Service / characteristic UUIDs ───────────────────────────────────────────
AUTH_SERVICE_UUID = "0000fcb9-0000-1000-8000-00805f9b34fb"
AUTH_WRITE_UUID = "0000ff07-0000-1000-8000-00805f9b34fb"
AUTH_NOTIFY_UUID = "0000ff08-0000-1000-8000-00805f9b34fb"
CONTROL_SERVICE_UUID = "0000ff60-2333-5b1e-9d7c-c687fd2f04f2"
CONTROL_WRITE_UUID = "0000ff61-2333-5b1e-9d7c-c687fd2f04f2"
CONTROL_NOTIFY_UUID = "0000ff62-2333-5b1e-9d7c-c687fd2f04f2"
# Notificaciones secundarias (svc ff60): la app las habilita antes del auth.
CONTROL_NOTIFY2_UUID = "0000ff64-2333-5b1e-9d7c-c687fd2f04f2"
AUX_SERVICE_UUID = "0000ff90-2333-5b1e-9d7c-c687fd2f04f2"
# OTA voice-pack write channel: ATT value handle 0x003c (60),
# WRITE_WITHOUT_RESPONSE (opcode 0x52, fire-and-forget). Plaintext — no AES-CCM.
# Confirmed by live GATT discovery 2026-09-02 (tools/dump_gatt.py). This is the
# characteristic the language-OTA transfer streams its ~6800 chunks over.
AUX_WRITE_UUID = "0000ff91-2333-5b1e-9d7c-c687fd2f04f2"
AUX_NOTIFY_UUID = "0000ff92-2333-5b1e-9d7c-c687fd2f04f2"

# ── U200 service-UUID tuples (identification + macOS discovery restriction) ───
#: Services the U200 exposes (auth fcb9, control ff60, auxiliary ff90). Used both
#: to identify a candidate from its advertisement and to restrict discovery on
#: stacks (CoreBluetooth) that refuse to enumerate descriptors of foreign services.
U200_SERVICE_UUIDS: tuple[str, ...] = (
    AUTH_SERVICE_UUID,
    CONTROL_SERVICE_UUID,
    AUX_SERVICE_UUID,
)
#: 16-bit short forms of the same services, for advertisements that carry them short.
U200_SERVICE_UUID16: tuple[str, ...] = tuple(u[4:8] for u in U200_SERVICE_UUIDS)

# ── GATT "Robust Caching" preamble (Bluetooth 5.1+, Vol 3 Part G) ─────────────
# Read By Type of Appearance (0x2A01) and Database Hash (0x2B2A): the two reads
# the app/Android always performs right after the MTU exchange and before writing
# the public key (0610). Resolved by UUID, not by raw handle (handles are not
# stable). bleak does not expose this primitive; Bumble does, via
# Client.read_characteristics_by_uuid. Adapters that lack it skip the step.
GATT_CACHING_PREAMBLE_UUID16 = (0x2A01, 0x2B2A)  # Appearance, Database Hash

# ── Pre-auth CCCD-enable order ───────────────────────────────────────────────
# Orden EXACTO en el que la app habilita CCCD antes de mandar la clave pública
# (confirmado por captura real).
PRE_AUTH_NOTIFY_ORDER = (
    CONTROL_NOTIFY_UUID,  # ff62
    CONTROL_NOTIFY2_UUID,  # ff64
    AUX_NOTIFY_UUID,  # ff92
    AUTH_NOTIFY_UUID,  # ff08
)
