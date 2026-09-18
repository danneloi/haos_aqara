"""Config flow for U200 BLE — manual setup only (no Bluetooth discovery)."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, override

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_ADDRESS, CONF_PASSWORD
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.selector import (
    EntitySelector,
    EntitySelectorConfig,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from ._vendor.aqara_ble import CloudAuthManager
from .client import (
    async_resolve_device_id,
    async_validate_cloud_auth,
    auth_token_snapshot,
    generate_device_identity,
    is_invalid_auth_error,
)
from .const import (
    CONF_ACCOUNT,
    CONF_CREDENTIAL_NAMES,
    CONF_DEVICE_ID,
    CONF_DISTRICT,
    CONF_GUARD_CODE,
    CONF_POLL_MINUTES,
    CONF_REGION,
    CONF_TRIGGER_LOCK_ENTITY,
    DEFAULT_DISTRICT,
    DEFAULT_POLL_MINUTES,
    DEFAULT_REGION,
    DOMAIN,
    MAX_POLL_MINUTES,
    MIN_POLL_MINUTES,
    SUPPORTED_REGIONS,
)

#: Transient options-flow field name for the free-text "slot: name" textarea
#: -- NOT the storage key (that's CONF_CREDENTIAL_NAMES, holding the already
#: -parsed dict). Kept local to this module; nothing else needs it.
_CREDENTIAL_NAMES_TEXT_FIELD = "credential_names_text"

_NON_EMPTY_TEXT = vol.All(str, vol.Strip, vol.Length(min=1))
_PASSWORD_SELECTOR = TextSelector(
    TextSelectorConfig(
        type=TextSelectorType.PASSWORD,
        autocomplete="current-password",
    )
)
_NON_EMPTY_PASSWORD = vol.All(_PASSWORD_SELECTOR, vol.Length(min=1))

_LOGGER = logging.getLogger(__name__)


def _auth_schema() -> dict[vol.Marker, Any]:
    """Return the Aqara account fields (account + masked password + guard code).

    Only account + password are required: aqara-ble bakes the app-global
    appid/appkey and generates the per-install phone_id/client_id.
    ``guard_code`` is optional and empty by default — most accounts never
    need it; it exists for when the Aqara cloud has asked for a one-time
    verification code (e.g. after a login from a new device or location).
    """
    return {
        vol.Required(CONF_ACCOUNT): _NON_EMPTY_TEXT,
        vol.Required(CONF_PASSWORD): _NON_EMPTY_PASSWORD,
        vol.Optional(CONF_GUARD_CODE, default=""): str,
    }


def _entry_data(user_input: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize non-password text; skip non-string fields."""
    return {
        key: value if key == CONF_PASSWORD else value.strip()
        for key, value in user_input.items()
        if isinstance(value, str)
    }


async def _async_auth_error(
    hass: HomeAssistant, data: Mapping[str, Any]
) -> tuple[str | None, CloudAuthManager | None]:
    """Validate Aqara credentials; return (sanitized flow error key, auth).

    On success, ``auth`` is the ``CloudAuthManager`` that was just built and
    logged in with -- it already holds a fresh, guard-code-validated token
    (see ``async_validate_cloud_auth`` in client.py). A caller that gets one
    back should hand that token off to the entry's real, long-lived auth
    object (``U200BleClientAdapter.apply_auth_token``) instead of letting it
    be discarded -- otherwise the very next read has to log in again from
    scratch with an empty guard code, which Aqara can reject all over again
    if it is currently demanding a guard code on every fresh login.
    Confirmed live 2026-09-13.
    """
    try:
        auth = await async_validate_cloud_auth(hass, data)
    except Exception as err:  # noqa: BLE001 - map all library/network failures
        _LOGGER.exception(
            "Aqara cloud auth validation failed (%s)", type(err).__name__
        )
        error = "invalid_auth" if is_invalid_auth_error(err) else "cannot_connect"
        return error, None
    return None, auth


async def _async_resolve_device_id(
    hass: HomeAssistant, data: Mapping[str, Any], mac: str
) -> tuple[str | None, str | None]:
    """Resolve the lock's device id from the account; return (device_id, error)."""
    try:
        return await async_resolve_device_id(hass, data, mac=mac), None
    except Exception as err:  # noqa: BLE001 - no lock found / ambiguous / transient
        _LOGGER.exception(
            "Aqara device-id resolution failed (%s)", type(err).__name__
        )
        return None, "no_device"


def _parse_credential_names(text: str) -> dict[str, str]:
    """Parse the options-flow textarea into {str(slot): name}.

    One mapping per line, ``<slot>: <name>`` -- slot as the plain decimal
    integer shown in the sensor's ``credential_slot`` attribute (e.g.
    ``83886464``), or hex with a ``0x`` prefix. Blank lines and lines
    starting with ``#`` are ignored (comments). Raises ``ValueError`` with a
    human-readable message on the first malformed line -- the options flow
    turns that into a form error instead of silently dropping data.
    """
    mapping: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"Missing ':' in line: {line!r}")
        slot_part, _, name_part = line.partition(":")
        slot_part = slot_part.strip()
        name = name_part.strip()
        if not name:
            raise ValueError(f"No name given for slot {slot_part!r}")
        try:
            slot = int(slot_part, 0) if slot_part.lower().startswith("0x") else int(slot_part)
        except ValueError as err:
            raise ValueError(f"Not a valid slot number: {slot_part!r}") from err
        mapping[str(slot)] = name
    return mapping


def _format_credential_names(mapping: Mapping[str, str]) -> str:
    """Inverse of ``_parse_credential_names``, for prefilling the textarea."""
    return "\n".join(f"{slot}: {name}" for slot, name in mapping.items())


class U200BleConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle U200 BLE configuration (manual only — no Bluetooth discovery)."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> U200BleOptionsFlow:
        """Return the options flow (poll interval)."""
        return U200BleOptionsFlow()

    @override
    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle manual setup."""
        if user_input is not None:
            data = _entry_data(user_input)
            address = data[CONF_ADDRESS]
            await self.async_set_unique_id(address)
            self._abort_if_unique_id_configured()
            device_id = data.get(CONF_DEVICE_ID) or None
            # Mint this entry's cloud-login identity ONCE, before validating,
            # so the validation call and every future read reuse the same
            # client_id/phone_id instead of a fresh one each time (see
            # CONF_CLIENT_ID in const.py for why that matters).
            data.update(generate_device_identity())
            error, _validated_auth = await _async_auth_error(self.hass, data)
            if not error and not device_id:
                device_id, error = await _async_resolve_device_id(
                    self.hass, data, address
                )
            if error:
                return self.async_show_form(
                    step_id="user",
                    data_schema=self._user_schema(),
                    errors={"base": error},
                )
            data[CONF_DEVICE_ID] = device_id
            # The guard code (if any) was a one-time, ~30s-lived value that
            # was already consumed by the _async_auth_error() validation
            # call above. It must NOT be persisted: build_cloud_auth() reads
            # CONF_GUARD_CODE fresh from entry.data on every future login,
            # and resending an already-used/expired one-time code makes the
            # cloud reject that (and every subsequent) ordinary login with
            # code 855 -- turning a single guard-code entry into a permanent
            # "must reauth every time" loop entirely of our own making.
            data[CONF_GUARD_CODE] = ""
            return self.async_create_entry(
                title=f"U200 BLE {address}",
                data=data,
                options={},
            )

        return self.async_show_form(
            step_id="user",
            data_schema=self._user_schema(),
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Start credential reauthentication."""
        del entry_data
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Validate and replace cloud credentials without exposing stored secrets."""
        entry = self._get_reauth_entry()
        schema = vol.Schema(_auth_schema())
        errors: dict[str, str] = {}

        if user_input is not None:
            updates = _entry_data(user_input)
            candidate = {**entry.data, **updates}
            error, validated_auth = await _async_auth_error(self.hass, candidate)
            if error:
                errors["base"] = error
            else:
                # Same reasoning as in async_step_user: the guard code just
                # entered was already consumed by the validation call above
                # (candidate). Persisting it would make the cloud reject
                # every future ordinary login with code 855, forcing reauth
                # again and again.
                updates[CONF_GUARD_CODE] = ""
                # async_update_and_abort (NOT ...reload_and_abort): this
                # entry already has a generic entry.add_update_listener
                # (_async_reload_on_options in __init__.py) that reloads on
                # ANY entry.data/options change, including this one. Using
                # the reload-and-abort variant here as well double-reloads
                # the entry on every reauth (confirmed live 2026-09-13: two
                # "startup marker" log lines seconds apart) and is exactly
                # the combination Home Assistant deprecated in 2026.6,
                # breaking in 2026.12 ("has an update listener and should
                # use it for scheduling a reload").
                #
                # Also unstick the ALREADY-RUNNING coordinator directly,
                # right now -- do not rely on the entry reload alone. If
                # this reauth ends up persisting data identical to what is
                # already stored (e.g. same account/password, guard code
                # cleared to "" both times), async_update_and_abort's
                # underlying async_update_entry() sees no actual change and
                # never fires the update listener, so no reload happens at
                # all -- leaving the coordinator's _auth_error_pending
                # flag stuck forever.
                if hasattr(entry, "runtime_data"):
                    entry.runtime_data.coordinator.clear_pending_auth_error()
                    # Hand the just-validated token to the RUNNING
                    # coordinator's own auth object instead of letting it
                    # be discarded with `validated_auth` -- without this,
                    # the very next read builds its own signer from
                    # scratch (empty guard code) and can be rejected all
                    # over again by Aqara -- confirmed live 2026-09-13
                    # only 14s after a successful reauth.
                    snapshot = auth_token_snapshot(validated_auth)
                    if snapshot is not None:
                        entry.runtime_data.client.apply_auth_token(*snapshot)
                        await entry.runtime_data.coordinator.async_persist_current_auth_token()
                return self.async_update_and_abort(
                    entry,
                    data_updates=updates,
                )

        suggested = {
            CONF_ACCOUNT: entry.data.get(CONF_ACCOUNT, ""),
        }
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=self.add_suggested_values_to_schema(schema, suggested),
            errors=errors,
        )

    @staticmethod
    def _user_schema() -> vol.Schema:
        """Return manual setup fields (address + account + password + ...)."""
        return vol.Schema(
            {
                vol.Required(CONF_ADDRESS): _NON_EMPTY_TEXT,
                vol.Required(CONF_REGION, default=DEFAULT_REGION): vol.In(
                    SUPPORTED_REGIONS
                ),
                vol.Required(CONF_DISTRICT, default=DEFAULT_DISTRICT): _NON_EMPTY_TEXT,
                **_auth_schema(),
                vol.Optional(CONF_DEVICE_ID, default=""): str,
            }
        )


class U200BleOptionsFlow(OptionsFlow):
    """Options: poll interval + the credential-slot -> name mapping.

    The name mapping is the ONLY place in this integration real names ever
    exist -- entered here, stored in this config entry's options (HA's own
    storage, not this git repo), and never written back into source. See
    CONF_CREDENTIAL_NAMES in const.py.
    """

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Set the poll interval and the credential-slot -> name mapping."""
        errors: dict[str, str] = {}
        credential_names_text = None

        if user_input is not None:
            credential_names_text = user_input.get(_CREDENTIAL_NAMES_TEXT_FIELD, "")
            try:
                credential_names = _parse_credential_names(credential_names_text)
            except ValueError as err:
                _LOGGER.warning("u200_ble: invalid credential_names input: %s", err)
                errors["base"] = "invalid_credential_names"
            else:
                return self.async_create_entry(
                    data={
                        CONF_POLL_MINUTES: user_input[CONF_POLL_MINUTES],
                        CONF_CREDENTIAL_NAMES: credential_names,
                        CONF_TRIGGER_LOCK_ENTITY: user_input.get(
                            CONF_TRIGGER_LOCK_ENTITY, ""
                        ),
                    }
                )

        poll_minutes = self.config_entry.options.get(
            CONF_POLL_MINUTES, DEFAULT_POLL_MINUTES
        )
        if credential_names_text is None:
            credential_names_text = _format_credential_names(
                self.config_entry.options.get(CONF_CREDENTIAL_NAMES, {})
            )

        trigger_lock_entity = self.config_entry.options.get(
            CONF_TRIGGER_LOCK_ENTITY, ""
        )
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_POLL_MINUTES, default=poll_minutes
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=MIN_POLL_MINUTES,
                            max=MAX_POLL_MINUTES,
                            step=1,
                            unit_of_measurement="min",
                            mode=NumberSelectorMode.BOX,
                        )
                    ),
                    vol.Optional(
                        _CREDENTIAL_NAMES_TEXT_FIELD, default=credential_names_text
                    ): TextSelector(
                        TextSelectorConfig(
                            type=TextSelectorType.TEXT, multiline=True
                        )
                    ),
                    #: Optional: a lock.* entity for this SAME physical lock
                    #: from a DIFFERENT integration (this user's Matter
                    #: integration) -- see CONF_TRIGGER_LOCK_ENTITY in
                    #: const.py. Left unset, nothing changes from before.
                    vol.Optional(
                        CONF_TRIGGER_LOCK_ENTITY, default=trigger_lock_entity
                    ): EntitySelector(EntitySelectorConfig(domain="lock")),
                }
            ),
            errors=errors,
        )
