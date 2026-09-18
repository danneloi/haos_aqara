"""Sensor platform for U200 BLE — a single access-log entity."""

from datetime import UTC, datetime
from typing import Any

from ._vendor.aqara_ble.access_log import EVENT_CLASS, METHOD_BY_HI
from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import U200BleConfigEntry
from .const import CONF_CREDENTIAL_NAMES, DOMAIN
from .coordinator import U200BleCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: U200BleConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the single U200 BLE access-log sensor."""
    del hass
    coordinator = entry.runtime_data.coordinator
    async_add_entities(
        [
            U200BleLastUnlock(entry, coordinator),
            U200BleLastUnlockPerson(entry, coordinator),
            U200BleLastUnlockTime(entry, coordinator),
            # U200BleUserTable deliberately NOT created (2026-09-10, on
            # request): rarely useful in practice -- it only ever updates
            # when the front-panel keypad happens to be awake (see the
            # class's own docstring below), so it sat on "Unbekannt" most
            # of the time. The class is kept, unused, in case it's wanted
            # again later -- just uncomment the line below.
            # U200BleUserTable(entry, coordinator),
        ]
    )


class U200BleLastUnlock(CoordinatorEntity[U200BleCoordinator], SensorEntity):
    """The most recent access-log entry ("Letzter Entsperrer"), read over BLE.

    Confirmed live (see docs/devices/u200/access-log-protocol.md in the
    aqara-ble project): request/reply shape, bulk-reply reassembly and the
    12-byte record decode are all real, not guessed.

    The state is WHAT unlocked/locked it (fingerprint / mechanical key or
    inside handle / Matter / a lock event) — never WHO. The BLE protocol only
    exposes a numeric credential *slot* for a fingerprint event; it has no
    concept of a person's name. The slot number (if any) is exposed as the
    ``credential_slot`` attribute so the user can map it to a household
    member themselves (e.g. from the Aqara app's own user-management screen)
    — this integration never stores or guesses that mapping.
    """

    _attr_has_entity_name = True
    _attr_translation_key = "last_unlock"
    _attr_device_class = SensorDeviceClass.ENUM
    #: A credential-open entry's label is its METHOD (password/fingerprint/
    #: matter/ble/NFC/key/...); any other entry (a plain lock event, tamper,
    #: ...) falls back to its EVENT_CLASS instead -- see client.py's
    #: LastUnlockEvent / async_read_last_unlock_event. Union of both value
    #: sets covers every label this sensor can ever actually report -- PLUS
    #: "face" (2026-09-07, confirmed live): aqara_ble.access_log's
    #: decode_lock_log_record() special-cases attr-hi 0x2 into "face" when
    #: userId[4:8] != "0680" (0680 == fingerprint instead), a string that
    #: deliberately does NOT appear in METHOD_BY_HI's own values() -- so it
    #: must be added here by hand or native_value() below silently nulls out
    #: every face-unlock entry (looked like the BLE read itself was failing;
    #: it wasn't -- only this enum-options list was incomplete).
    _attr_options = sorted(
        set(METHOD_BY_HI.values()) | set(EVENT_CLASS.values()) | {"face"}
    )

    def __init__(
        self, entry: U200BleConfigEntry, coordinator: U200BleCoordinator
    ) -> None:
        """Initialize the last-access-log-event sensor."""
        super().__init__(coordinator)
        address = entry.runtime_data.address
        self._attr_unique_id = f"{address}_last_unlock"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, address)},
            manufacturer="Aqara",
            model="U200",
            name=entry.title,
        )

    @property
    def native_value(self) -> str | None:
        """Return the confirmed event label, or None if unread/unrecognized."""
        value = self.coordinator.data.last_unlock_label
        return value if value in self._attr_options else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose the credential slot (NUMBER ONLY, never a name) and timestamp."""
        data = self.coordinator.data
        attrs: dict[str, Any] = {"credential_slot": data.last_unlock_credential_slot}
        if data.last_unlock_timestamp is not None:
            attrs["occurred_at"] = datetime.fromtimestamp(
                data.last_unlock_timestamp, tz=UTC
            ).isoformat()
        return attrs


class U200BleLastUnlockPerson(CoordinatorEntity[U200BleCoordinator], SensorEntity):
    """Who unlocked/locked it last -- resolved from the user-entered mapping.

    Companion to ``U200BleLastUnlock`` (which reports the raw METHOD, e.g.
    "face" or "password" -- never a name, since the BLE protocol itself has
    no concept of a person). THIS entity is the opt-in convenience layer on
    top: it looks up the same read's ``credential_slot`` in the config
    entry's options (see CONF_CREDENTIAL_NAMES in const.py, set via
    Settings -> Devices & Services -> U200 BLE -> Configure) and shows the
    name the user assigned to that slot, if any.

    Free-text state (not an enum) on purpose: names are whatever the user
    types, unbounded. An unmapped/new slot shows a placeholder that still
    carries the raw slot number, both so it's obviously "not yet named" and
    so the user can copy that number straight into the options form.
    """

    _attr_has_entity_name = True
    _attr_translation_key = "last_unlock_person"

    def __init__(
        self, entry: U200BleConfigEntry, coordinator: U200BleCoordinator
    ) -> None:
        """Initialize the last-access-log-person sensor."""
        super().__init__(coordinator)
        self._entry = entry
        address = entry.runtime_data.address
        self._attr_unique_id = f"{address}_last_unlock_person"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, address)},
            manufacturer="Aqara",
            model="U200",
            name=entry.title,
        )

    #: German label shown for a status event that has no attributable
    #: person at all (see ``is_credential_open`` on ``LastUnlockEvent``) --
    #: keyed by the raw ``event_class`` (``last_unlock_label`` for a
    #: non-open row). Only ``lock_event`` is mapped -- confirmed 1:1 against
    #: the Aqara app's own "Erfolgreich verriegelt" label (2026-09-08). The
    #: other classes (open_anti_lock, close_anti_lock, knob_or_finger_in,
    #: lockout_or_finger_up, lock_exception) fall back to their raw class
    #: name below rather than a guessed German label, since those aren't
    #: confirmed against the app yet.
    _NON_CREDENTIAL_LABELS: dict[str, str] = {
        "lock_event": "Verriegelt",
        # See client.py's _parse_last_unlock_event: a "matter"-labelled
        # entry is now treated as non-credential (is_credential_open=False)
        # because it's a confirmed-spurious, fixed-placeholder-id pair, not
        # a real person-attributed unlock.
        "matter": "Automatisch (kein zugeordneter Nutzer)",
    }

    @property
    def native_value(self) -> str | None:
        """Return the resolved name, a status label, or a raw fallback.

        Only a real credential-open (someone unlocking) gets a *person*
        name -- ``last_unlock_is_credential_open`` is False for a status
        event (a plain lock/relock, anti-lock, tamper, ...) that never
        involved a credential at all, so there is no person to attribute it
        to. Rather than hiding that as an opaque "Unbekannt" (we DO know
        what happened, just not "by whom"), this shows a readable label for
        the event itself -- "Verriegelt" for a plain lock event, confirmed
        2026-09-08 against the Aqara app's own log; other, less-confirmed
        status classes fall back to their raw class name so nothing is
        silently swallowed.

        For a real credential-open, two sources, in priority order:
        1. The manual mapping in this entry's options (Configure -> name
           mapping) -- lets the user correct/override a specific slot by
           hand, e.g. if the automatic match below is ever wrong.
        2. The AUTOMATIC mapping fetched from the Aqara cloud every poll
           cycle (coordinator.py's async_refresh_credential_names) --
           covers fingerprint/face slots without any manual setup at all.
        Falls back to a placeholder carrying the raw slot number when
        neither source has it yet -- also how a brand-new, not-yet-enrolled
        or not-yet-cloud-synced credential shows up.
        """
        data = self.coordinator.data
        if not data.last_unlock_is_credential_open:
            label = data.last_unlock_label
            if not label:
                return None
            return self._NON_CREDENTIAL_LABELS.get(label, label)
        slot = data.last_unlock_credential_slot
        if slot is None:
            return None
        manual: dict[str, str] = self._entry.options.get(CONF_CREDENTIAL_NAMES, {})
        if name := manual.get(str(slot)):
            return name
        automatic = data.credential_names or {}
        if name := automatic.get(str(slot)):
            return name
        return f"Unzugeordnet (Slot {slot})"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose the underlying method/event label and raw slot for context."""
        data = self.coordinator.data
        attrs: dict[str, Any] = {
            "method_or_event": data.last_unlock_label,
            "credential_slot": data.last_unlock_credential_slot,
        }
        if data.last_unlock_timestamp is not None:
            attrs["occurred_at"] = datetime.fromtimestamp(
                data.last_unlock_timestamp, tz=UTC
            ).isoformat()
        return attrs


class U200BleLastUnlockTime(CoordinatorEntity[U200BleCoordinator], SensorEntity):
    """WHEN the most recent access-log event occurred, as its own entity.

    2026-09-10: added on request -- both ``U200BleLastUnlock`` and
    ``U200BleLastUnlockPerson`` already exposed this same moment as an
    ``occurred_at`` attribute, but Home Assistant's default device page
    only lists an entity's STATE, not its attributes, so the timestamp was
    effectively invisible without opening each entity individually. This
    sensor surfaces the exact same value (the lock's own record timestamp,
    not when Home Assistant happened to poll) as a first-class, always-
    visible row.

    ``device_class: timestamp`` means Home Assistant renders this as a
    proper date+time (localized to the viewer, with relative "vor 3
    Minuten"-style display) rather than a raw string -- no manual
    formatting needed here.
    """

    _attr_has_entity_name = True
    _attr_translation_key = "last_unlock_time"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(
        self, entry: U200BleConfigEntry, coordinator: U200BleCoordinator
    ) -> None:
        """Initialize the last-access-log-time sensor."""
        super().__init__(coordinator)
        address = entry.runtime_data.address
        self._attr_unique_id = f"{address}_last_unlock_time"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, address)},
            manufacturer="Aqara",
            model="U200",
            name=entry.title,
        )

    @property
    def native_value(self) -> datetime | None:
        """Return the lock-reported event time, or None before the first read."""
        ts = self.coordinator.data.last_unlock_timestamp
        if ts is None:
            return None
        return datetime.fromtimestamp(ts, tz=UTC)


class U200BleUserTable(CoordinatorEntity[U200BleCoordinator], SensorEntity):
    """The user/credential table read over BLE (SYNC_USER_ID_VALID_PERIOD / 0x1f).

    This is what was originally asked for early in this project: seeing the
    lock's own registered credentials (slot, type, when created) straight
    from Home Assistant -- the same information the Aqara app's own
    "Benutzerverwaltung" (user management) screen shows -- without going
    through the Aqara cloud at all. Confirmed live 2026-09-08 (direct
    Mac-side BLE test, Aqara-1.16.0/log.txt): 9 real credentials read this
    way (2 password, 7 fingerprint), matching the cloud's own count/types.

    Only ever updates opportunistically: this read needs the front-panel
    keypad AWAKE (unlike the access log, which the always-on back panel
    serves regardless of keypad state), and there is no confirmed way to
    wake it remotely -- see client.py's ``async_read_snapshot``. In
    practice this means it updates whenever someone happens to have just
    touched the keypad or fingerprint sensor right around a poll; to force
    a fresh read on demand, touch the panel and then immediately press the
    "Refresh over Bluetooth" button. The ``updated_at`` attribute says how
    stale the current value is.

    No name is ever shown here -- only the bare numeric slot (the lock's
    internal ``user_id``) and credential type, the same privacy stance as
    every other sensor in this integration; see ``U200BleLastUnlockPerson``
    for how a slot becomes a person's name (via the user's own name mapping
    or the Aqara cloud -- never derived here).
    """

    _attr_has_entity_name = True
    _attr_translation_key = "user_table"
    _attr_native_unit_of_measurement = "credentials"

    def __init__(
        self, entry: U200BleConfigEntry, coordinator: U200BleCoordinator
    ) -> None:
        """Initialize the user/credential-table sensor."""
        super().__init__(coordinator)
        address = entry.runtime_data.address
        self._attr_unique_id = f"{address}_user_table"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, address)},
            manufacturer="Aqara",
            model="U200",
            name=entry.title,
        )

    @property
    def native_value(self) -> int | None:
        """Return the credential count, or None before the first successful read."""
        table = self.coordinator.data.user_table
        return len(table) if table is not None else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose each credential's slot/type/creation time -- never a name."""
        data = self.coordinator.data
        attrs: dict[str, Any] = {}
        if data.user_table is not None:
            attrs["credentials"] = [
                {
                    "slot": cred.user_id,
                    "type": cred.type_name,
                    "created_at": datetime.fromtimestamp(
                        cred.create_time, tz=UTC
                    ).isoformat(),
                }
                for cred in data.user_table
            ]
        if data.user_table_updated_at is not None:
            attrs["updated_at"] = data.user_table_updated_at.isoformat()
        return attrs
