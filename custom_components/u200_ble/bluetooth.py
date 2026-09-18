"""Home Assistant Bluetooth routing for U200 BLE (address-based, generic)."""

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from bleak.backends.device import BLEDevice
from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant, callback


@dataclass(slots=True, frozen=True)
class U200BleBluetoothState:
    """Non-sensitive Bluetooth reachability state."""

    reachable: bool = False
    last_seen: datetime | None = None
    rssi: int | None = None


class U200BleBluetoothManager:
    """Resolve and observe one U200 through Home Assistant Bluetooth.

    Never owns a Bleak scanner: Home Assistant selects the nearest connectable
    local adapter or remote Bluetooth Proxy for the configured address.
    """

    def __init__(self, hass: HomeAssistant, address: str) -> None:
        """Initialize Bluetooth routing."""
        self._hass = hass
        self.address = address
        self._state = U200BleBluetoothState(
            reachable=self.async_get_ble_device() is not None
        )

    @property
    def state(self) -> U200BleBluetoothState:
        """Return the latest reachability snapshot."""
        return self._state

    def async_get_ble_device(self) -> BLEDevice | None:
        """Resolve the current connectable path chosen by Home Assistant."""
        return bluetooth.async_ble_device_from_address(
            self._hass, self.address, connectable=True
        )

    def async_start(
        self, on_state_change: Callable[[U200BleBluetoothState], None]
    ) -> Callable[[], None]:
        """Subscribe to Home Assistant Bluetooth state for this address."""

        @callback
        def _async_discovered(
            service_info: bluetooth.BluetoothServiceInfoBleak,
            change: bluetooth.BluetoothChange,
        ) -> None:
            del change
            self._state = U200BleBluetoothState(
                reachable=True,
                last_seen=datetime.now(UTC),
                rssi=getattr(service_info, "rssi", None),
            )
            on_state_change(self._state)

        @callback
        def _async_unavailable(
            service_info: bluetooth.BluetoothServiceInfoBleak,
        ) -> None:
            del service_info
            self._state = replace(self._state, reachable=False)
            on_state_change(self._state)

        cancel_discovery = bluetooth.async_register_callback(
            self._hass,
            _async_discovered,
            {"address": self.address, "connectable": True},
            bluetooth.BluetoothScanningMode.ACTIVE,
        )
        cancel_unavailable = bluetooth.async_track_unavailable(
            self._hass,
            _async_unavailable,
            self.address,
            connectable=True,
        )

        @callback
        def _cancel() -> None:
            cancel_discovery()
            cancel_unavailable()

        return _cancel
