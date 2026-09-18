"""U200 BLE integration -- access-log data only.

Deliberately minimal, on purpose: this exists solely to expose the Aqara
U200's access-log (SYNC_LOG) entries over BLE. Lock/unlock, battery and
settings are handled by this user's existing Matter integration for the same
device -- Matter carries none of the access-log data (BLE-only). Named
"U200 BLE" (not "Aqara U200") so it is never confused with a full-featured
Aqara U200 integration installed alongside it.
"""

import logging
from dataclasses import dataclass

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .bluetooth import U200BleBluetoothManager
from .client import (
    U200BleClient,
    U200BleClientAdapter,
    async_fetch_ltmk,
    build_cloud_auth,
    generate_device_identity,
)
from .const import (
    CONF_CLIENT_ID,
    CONF_DEVICE_ID,
    CONF_GUARD_CODE,
    CONF_LTMK,
    CONF_PHONE_ID,
    CONF_REGION,
    DEFAULT_REGION,
    DOMAIN,
)
from .coordinator import U200BleCoordinator

PLATFORMS: tuple[Platform, ...] = (
    Platform.SENSOR,
    Platform.BUTTON,
)

# This integration is configured through the UI (config entries) only; it
# takes no YAML configuration under its domain.
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


@dataclass(slots=True)
class U200BleRuntimeData:
    """Typed runtime resources for one configured U200."""

    address: str
    device_id: str
    region: str
    bluetooth: U200BleBluetoothManager
    client: U200BleClient
    coordinator: U200BleCoordinator


type U200BleConfigEntry = ConfigEntry[U200BleRuntimeData]

_LOGGER = logging.getLogger(__name__)

#: Deployment sanity check, always-visible (WARNING, not gated behind debug
#: logging): bump the date whenever a change needs unambiguous proof it's
#: actually the running code -- 2026-09-05 we spent a whole round-trip
#: unable to tell whether a coordinator.py/client.py edit had actually
#: reached the running Home Assistant instance versus an old cached
#: version, because the only symptom either way is total silence.
_DEPLOY_MARKER = "2026-09-08i (access-log SYNC_LOG paging fix: send whole trailer-complete 30-record pages instead of a trailer-less 0..49 request that the lock was silently clamping to just the newest 30 records)"

# fetch_ltmk service: a guard code is only valid ~30s, far too short for a
# config-flow round-trip or an HA restart -- so instead this is a callable
# service (Developer Tools -> Actions) the user fires immediately after
# reading a fresh guard code off the Aqara app. See async_setup_entry below
# for why the LTMK is normally fetched automatically without one (code 854
# only hits the fetch_ltmk cloud call itself, not ordinary logins).
SERVICE_FETCH_LTMK = "fetch_ltmk"
ATTR_GUARD_CODE = "guard_code"
ATTR_CONFIG_ENTRY_ID = "config_entry_id"

SERVICE_FETCH_LTMK_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_GUARD_CODE): cv.string,
        vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string,
    }
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up integration-global resources (none needed)."""
    del hass, config
    return True


async def async_setup_entry(hass: HomeAssistant, entry: U200BleConfigEntry) -> bool:
    """Set up a U200 BLE config entry."""
    _LOGGER.warning("u200_ble: startup marker rev=%s", _DEPLOY_MARKER)
    address = entry.data[CONF_ADDRESS]
    bluetooth_manager = U200BleBluetoothManager(hass, address)

    # One-time migration for entries created before CONF_CLIENT_ID/
    # CONF_PHONE_ID existed: mint and persist a stable identity now instead
    # of letting build_cloud_auth() fall back to a fresh random one on every
    # setup (see CONF_CLIENT_ID in const.py -- that pattern is what appears
    # to have triggered Aqara's guard-code challenge, cloud error 855, after
    # today's several restarts).
    if CONF_CLIENT_ID not in entry.data or CONF_PHONE_ID not in entry.data:
        hass.config_entries.async_update_entry(
            entry, data={**entry.data, **generate_device_identity()}
        )

    try:
        auth = build_cloud_auth(entry.data)
    except KeyError as err:
        raise ConfigEntryAuthFailed(
            "Aqara cloud credentials are incomplete; reauthentication is required"
        ) from err

    device_id = entry.data[CONF_DEVICE_ID]
    region = entry.data.get(CONF_REGION, DEFAULT_REGION)

    # One-time LTMK fetch (see CONF_LTMK in const.py): once cached, every BLE
    # session derives OFFLINE instead of doing a ~2-3s cloud login round-trip
    # inside the (short-lived, proxy-dependent) BLE connection window. Never
    # fatal: on failure this setup just falls back to the cloud-login path,
    # same as before this existed, and the next setup tries again.
    ltmk_hex = entry.data.get(CONF_LTMK)
    if not ltmk_hex:
        try:
            ltmk_bytes = await async_fetch_ltmk(hass, auth, device_id)
        except Exception as err:  # noqa: BLE001 - best-effort, see above
            _LOGGER.warning(
                "u200_ble: could not fetch LTMK for offline BLE session "
                "(falling back to per-read cloud login this time): %s", err
            )
        else:
            ltmk_hex = ltmk_bytes.hex()
            hass.config_entries.async_update_entry(
                entry, data={**entry.data, CONF_LTMK: ltmk_hex}
            )
    ltmk = bytes.fromhex(ltmk_hex) if ltmk_hex else None

    client: U200BleClient = U200BleClientAdapter(
        hass, bluetooth_manager, auth, device_id, region, ltmk=ltmk
    )
    coordinator = U200BleCoordinator(hass, entry, bluetooth_manager, client)

    entry.runtime_data = U200BleRuntimeData(
        address=address,
        device_id=device_id,
        region=region,
        bluetooth=bluetooth_manager,
        client=client,
        coordinator=coordinator,
    )

    entry.async_on_unload(
        bluetooth_manager.async_start(coordinator.async_handle_bluetooth_state)
    )
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Background BLE poll — starts on every setup (fresh install AND every HA
    # restart), so the sensor populates on its own within a few minutes
    # instead of staying 'unknown' until someone presses Refresh.
    entry.async_on_unload(coordinator.async_stop_polling)
    coordinator.async_start_polling()

    entry.async_on_unload(entry.add_update_listener(_async_reload_on_options))

    _async_register_fetch_ltmk_service(hass)

    return True


def _async_register_fetch_ltmk_service(hass: HomeAssistant) -> None:
    """Register the (domain-wide, idempotent) ``fetch_ltmk`` service.

    Safe to call from every config entry's setup: ``has_service`` makes this
    a no-op after the first entry registers it, and the handler itself
    always resolves the *current* target entry at call time (never a stale
    entry captured at registration), so a reload/second-entry setup never
    leaves a handler pointing at a torn-down entry.
    """
    if hass.services.has_service(DOMAIN, SERVICE_FETCH_LTMK):
        return

    async def _async_handle_fetch_ltmk(call: ServiceCall) -> None:
        """Fetch and apply an LTMK using a freshly-issued guard code.

        Must complete within the guard code's ~30s validity window, so this
        does exactly one thing: build a throwaway auth with the supplied
        code, fetch the LTMK, persist it to the config entry, and push it
        into the already-running client via ``set_ltmk`` -- no reload.
        """
        guard_code: str = call.data[ATTR_GUARD_CODE]
        config_entry_id: str | None = call.data.get(ATTR_CONFIG_ENTRY_ID)

        target_entry = _resolve_fetch_ltmk_target_entry(hass, config_entry_id)

        fresh_auth = build_cloud_auth(
            {**target_entry.data, CONF_GUARD_CODE: guard_code}
        )
        try:
            ltmk_bytes = await async_fetch_ltmk(
                hass, fresh_auth, target_entry.data[CONF_DEVICE_ID]
            )
        except Exception as err:  # noqa: BLE001 - surfaced to the user below
            raise HomeAssistantError(
                f"u200_ble: LTMK-Abruf fehlgeschlagen: {err}"
            ) from err

        ltmk_hex = ltmk_bytes.hex()
        hass.config_entries.async_update_entry(
            target_entry, data={**target_entry.data, CONF_LTMK: ltmk_hex}
        )
        target_entry.runtime_data.client.set_ltmk(ltmk_bytes)
        _LOGGER.warning(
            "u200_ble: fetch_ltmk service succeeded -- BLE session for %s is "
            "now offline (no more per-read cloud login)",
            target_entry.data.get(CONF_DEVICE_ID),
        )

    hass.services.async_register(
        DOMAIN,
        SERVICE_FETCH_LTMK,
        _async_handle_fetch_ltmk,
        schema=SERVICE_FETCH_LTMK_SCHEMA,
    )


def _resolve_fetch_ltmk_target_entry(
    hass: HomeAssistant, config_entry_id: str | None
) -> U200BleConfigEntry:
    """Pick which config entry the ``fetch_ltmk`` service call targets.

    Most installs have exactly one U200 BLE lock configured, so
    ``config_entry_id`` is optional in that case; with more than one
    configured lock it must be given explicitly (Developer Tools shows the
    entry id in the integration's page URL).
    """
    if config_entry_id is not None:
        entry = hass.config_entries.async_get_entry(config_entry_id)
        if entry is None or entry.domain != DOMAIN:
            raise HomeAssistantError(
                f"u200_ble: config_entry_id '{config_entry_id}' ist keine "
                "bekannte U200-BLE-Instanz"
            )
        return entry  # type: ignore[return-value]

    entries = hass.config_entries.async_entries(DOMAIN)
    if len(entries) == 1:
        return entries[0]  # type: ignore[return-value]
    raise HomeAssistantError(
        "u200_ble: mehr als ein U200-BLE-Schloss konfiguriert -- bitte "
        "config_entry_id im Service-Aufruf angeben"
    )


async def _async_reload_on_options(
    hass: HomeAssistant, entry: U200BleConfigEntry
) -> None:
    """Reload the entry when options (the poll interval) change."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: U200BleConfigEntry) -> bool:
    """Unload platforms; entry unload callbacks release Bluetooth subscriptions."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
