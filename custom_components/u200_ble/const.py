"""Constants for U200 BLE -- a minimal integration exposing only the Aqara
U200's access-log (SYNC_LOG) data over BLE.

Deliberately separate from a full lock integration: lock/unlock, battery and
settings are already handled by Matter for this user, and Matter does not
carry the access log (who/what unlocked, over BLE only) -- see the project's
Zwischen Log for the 2026-09-03 finding. Named "U200 BLE" (not "Aqara U200")
so it is never confused with a full-featured Aqara U200 integration running
alongside it.
"""

from typing import Final

DOMAIN: Final = "u200_ble"

CONF_ACCOUNT: Final = "account"
CONF_ADDRESS: Final = "address"
CONF_DEVICE_ID: Final = "device_id"
CONF_REGION: Final = "region"
#: Aqara's cloud checks a login's declared "district" (its own internal
#: country/location code) against the one it last recorded for the account,
#: and rejects the login (cloud error code 858) on a mismatch -- see the
#: haos_aqara project's README for the full story. Set this to your own
#: Aqara account's country; "DE" is only a starting value for the form.
CONF_DISTRICT: Final = "district"
DEFAULT_DISTRICT: Final = "DE"
#: Optional second-factor code the Aqara cloud sometimes demands at login.
#: Empty ("") means "not needed", which is what most accounts use.
CONF_GUARD_CODE: Final = "guard_code"

#: Per-install cloud-login identity (aqara_ble's CloudAuthManager client_id/
#: phone_id). Generated ONCE (at config-flow setup, or migrated in on first
#: setup of an older entry) and persisted here -- never regenerated on every
#: HA restart. Confirmed live (2026-09-05): leaving these unset makes
#: CloudAuthManager mint a fresh random uuid4 identity on every
#: async_setup_entry() call, which looks to Aqara's cloud like a brand-new
#: app install logging in every time HA restarts/reloads this entry; enough
#: of those in a short window appears to be what triggers the cloud's
#: guard-code (temporary-key) challenge, cloud error code 855, on a
#: previously fine account.
CONF_CLIENT_ID: Final = "client_id"
CONF_PHONE_ID: Final = "phone_id"

#: Cached LTMK (long-term master key, 32 bytes, hex-encoded) for this lock.
#: Fetched ONCE from the Aqara cloud (aqara_ble.CloudAuthManager.fetch_ltmk,
#: added in aqara-ble 1.11.1) and persisted here, then passed to every BLE
#: session so it derives OFFLINE (no per-read cloud login round-trip).
#: Added 2026-09-07: correlated ESPHome-proxy + HA debug logs showed the
#: per-read cloud login (login -> cloud_get_public_key -> get_session_material)
#: alone took ~2-3s of HTTPS round-trips *inside* the BLE connection window,
#: right before the connection closed again -- leaving too little time left
#: for the actual BLE protocol exchange. The LTMK path skips that entirely.
CONF_LTMK: Final = "ltmk"

DEFAULT_REGION: Final = "EU"
SUPPORTED_REGIONS: Final = ("EU", "US", "CN")

#: How often to connect over BLE and read the log, in minutes.
CONF_POLL_MINUTES: Final = "poll_minutes"
DEFAULT_POLL_MINUTES: Final = 30
MIN_POLL_MINUTES: Final = 5
MAX_POLL_MINUTES: Final = 1440

#: Optional entity_id of a *different* integration's ``lock.*`` entity for
#: this SAME physical lock (this user's case: the Matter integration, which
#: already reports lock/unlock essentially instantly -- see const.py's
#: module docstring). When set, the coordinator additionally listens for
#: that entity transitioning to "unlocked" and triggers an immediate
#: access-log read (see coordinator.py's _async_on_trigger_lock_state_change)
#: instead of only ever picking the new entry up on the next regular
#: CONF_POLL_MINUTES cycle, which could be many minutes (or, while the
#: retry backoff is active after a run of failures, much longer) later.
#: 2026-09-10: added on request. Empty/unset ("") means "off", which is
#: also how an existing config entry behaves after upgrading (no listener
#: registered, identical to before this option existed).
CONF_TRIGGER_LOCK_ENTITY: Final = "trigger_lock_entity"

#: Grace period between a trigger entity reporting "unlocked" and this
#: integration actually connecting to read the access log. Not zero: the
#: lock itself needs a moment to finish writing the SYNC_LOG record and
#: resume BLE-advertising after the unlock operation; connecting instantly
#: risked losing the race the same way the very first read after a fresh
#: unlock sometimes did during manual testing.
TRIGGER_REFRESH_DELAY_SECONDS: Final = 5.0

#: Maps a raw credential slot (decimal str(int), as shown in the
#: "credential_slot" attribute -- e.g. "83886464") to a human-readable name
#: ("Mom", "Roommate", ...). Lives ONLY in this config entry's *options*
#: (HA's own .storage/core.config_entries on the HA host, entered via the
#: options flow UI) -- deliberately never hardcoded here in source, since
#: this is a public integration and real household names should never
#: end up in anything that could get pushed or shared from it.
#: Empty/unset slots fall back to showing the raw slot number instead of a
#: name, which is also how a NEW, not-yet-mapped person/credential surfaces.
CONF_CREDENTIAL_NAMES: Final = "credential_names"

#: How many times a single read tries to connect+read before giving up.
#: Kept at 1: bleak_retry_connector's own establish_connection() already
#: retries its own connection attempts internally, and a contended/shared
#: onboard Bluetooth adapter can only handle one connection attempt at a
#: time -- stacking our own outer retries on top of that was observed live
#: (2026-09-04) to starve OTHER BLE devices sharing the same adapter.
#: coordinator.py's poll loop handles retrying a failed cycle on its own
#: (with exponential backoff), so this no longer needs to loop internally.
BLE_READ_ATTEMPTS: Final = 1
BLE_READ_GAP_SECONDS: Final = 8.0
