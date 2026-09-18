"""Button platform for U200 BLE — on-demand access-log refresh."""

from homeassistant.components.button import ButtonEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import U200BleConfigEntry
from .const import DOMAIN
from .coordinator import U200BleCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: U200BleConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the U200 BLE refresh button."""
    del hass
    coordinator = entry.runtime_data.coordinator
    async_add_entities([U200BleRefresh(entry, coordinator)])


class U200BleRefresh(CoordinatorEntity[U200BleCoordinator], ButtonEntity):
    """Read the access log over BLE, once, on demand.

    The integration polls in the background on the configured interval; press
    this to pull a fresh value right away instead of waiting. Also
    opportunistically refreshes the "Credential table" sensor in the same
    BLE connection if the front-panel keypad happens to be awake -- touch
    the keypad/fingerprint sensor right before pressing this button to
    reliably catch it awake (see coordinator.py's ``async_refresh_log``).
    """

    _attr_has_entity_name = True
    _attr_translation_key = "refresh"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(
        self, entry: U200BleConfigEntry, coordinator: U200BleCoordinator
    ) -> None:
        """Initialize the refresh button."""
        super().__init__(coordinator)
        address = entry.runtime_data.address
        self._attr_unique_id = f"{address}_refresh"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, address)},
            manufacturer="Aqara",
            model="U200",
            name=entry.title,
        )

    async def async_press(self) -> None:
        """Trigger a one-shot BLE access-log read (runs in the background)."""
        self.coordinator.config_entry.async_create_background_task(
            self.coordinator.hass,
            self.coordinator.async_refresh_log(),
            f"{DOMAIN}_refresh_button",
        )
