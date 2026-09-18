"""GATT client abstraction for transport-independent Aqara U200 protocol.

This module defines the typed interface that the session layer depends on,
allowing the library to work with any BLE transport (Bleak, Bumble, or a
custom implementation) without tight coupling to a specific implementation.

The interface is defined using `typing.Protocol` (structural typing) to enable:
- `BleakClient` to satisfy the interface without explicit subclassing
- `BumbleGattAdapter` to continue working unchanged
- Test mocks to work naturally without any boilerplate
- Home Assistant Bluetooth Manager integration in the future
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    pass


class GattClient(Protocol):
    """Minimal typed interface for GATT operations required by the session layer.

    This protocol defines the structural interface that `run_authenticated_lock_operation`
    depends on. Any object implementing these methods can be used as a client,
    regardless of the underlying BLE transport (Bleak, Bumble, native OS, etc.).

    The interface is intentionally minimal: only the methods actually used by the
    session are included. Optional low-level capabilities (MTU negotiation,
    connection parameter updates, etc.) are discovered dynamically via `getattr()`,
    not enforced by this protocol.

    Implementations:
    - `BleakClient` (from the bleak library) satisfies this protocol structurally
    - `BumbleGattAdapter` (aqara_ble.bumble_transport) wraps Bumble's Peer
    - Test mocks can implement this interface without external dependencies
    """

    async def write_gatt_char(
        self,
        char_specifier: str,
        data: bytes,
        response: bool = False,
    ) -> None:
        """Write data to a GATT characteristic.

        Args:
            char_specifier: UUID string (128-bit or 16-bit short form) identifying
                the characteristic to write to. Both "0000ff07-0000-1000-8000-00805f9b34fb"
                and "ff07" formats are supported by implementations.
            data: Bytes to write. The size must fit within the connection's MTU.
            response: If True, wait for a GATT Write Response. If False, send a
                Write Command without waiting (faster, but no confirmation of
                success from the device).

        Raises:
            Implementations may raise exceptions on I/O errors, disconnection,
            or invalid characteristic UUID.
        """
        ...

    async def start_notify(
        self,
        char_specifier: str,
        callback: Callable[[Any, bytearray], None],
    ) -> None:
        """Enable notifications on a GATT characteristic.

        When the characteristic's value changes on the server, the callback will
        be invoked with the updated value.

        Args:
            char_specifier: UUID string identifying the characteristic.
            callback: A callable that receives (sender_object, data: bytearray)
                when a notification arrives. The sender_object is implementation-
                specific and is typically ignored by session code.

        Raises:
            Implementations may raise exceptions if the characteristic does not
            support notifications, or on I/O errors.
        """
        ...

    async def stop_notify(
        self,
        char_specifier: str,
    ) -> None:
        """Disable notifications on a GATT characteristic.

        Args:
            char_specifier: UUID string identifying the characteristic.

        Raises:
            Implementations may raise exceptions on I/O errors. Best-effort
            implementations tolerate failures (e.g., if the characteristic was
            never subscribed to).
        """
        ...
