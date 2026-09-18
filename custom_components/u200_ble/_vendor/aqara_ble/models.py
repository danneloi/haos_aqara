"""Aqara device-model identification from the BLE advertisement (feature 016).

The U200 puts a 13-byte payload under manufacturer id ``0x0B27`` in its
advertisement. Its layout follows the Xiaomi/MiBeacon convention closely enough
that the **product id** (a.k.a. Xiaomi device id) is a little-endian ``uint16``
at offset 2:

    28 08 | 03 9c | 51 | 15 f2 80 2a 10 9d 22 80
    ^frameControl ^prodID(LE=0x9C03) ^counter ^remainder (unverified)

``product_id = 0x9C03`` identifies the **U200 model** (not a per-unit value).
Evidence: the live advertisement captured 2026-08-17, and the original
investigation running the real ``xiaomi-ble`` parser, which read
``device_id=0x9c03`` from the same beacon. The U200's beacon is otherwise **not**
a valid MiBeacon (``version=0``, product not in the Xiaomi catalogue), so only
frameControl/product_id/counter are treated as known; the remainder is exposed
raw and its semantics are not asserted.
"""

from __future__ import annotations

#: Known product ids (uint16, from the advertisement) -> human model name.
#: Extend as other Aqara BLE devices are identified. An id not here yields
#: ``model=None`` — the scanner never invents a model.
MODEL_BY_PRODUCT_ID: dict[int, str] = {
    0x9C03: "U200",
}


def decode_manufacturer_payload(payload: bytes | None) -> tuple[int | None, str | None]:
    """Decode an Aqara (``0x0B27``) manufacturer payload.

    Returns ``(product_id, model)``. ``product_id`` is the little-endian
    ``uint16`` at offset 2 when the payload has at least 4 bytes, else ``None``.
    ``model`` is looked up in :data:`MODEL_BY_PRODUCT_ID`, or ``None`` for an
    unknown/undecodable product.
    """

    if not payload or len(payload) < 4:
        return None, None
    product_id = int.from_bytes(payload[2:4], "little")
    return product_id, MODEL_BY_PRODUCT_ID.get(product_id)


__all__ = ["MODEL_BY_PRODUCT_ID", "decode_manufacturer_payload"]
