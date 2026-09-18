"""Runtime coordinator for U200 BLE — access-log only."""

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from collections.abc import Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.helpers.event import async_track_state_change_event
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from ._vendor.aqara_ble import CloudServiceError, UserCredential

from .bluetooth import U200BleBluetoothManager, U200BleBluetoothState
from .client import LastUnlockEvent, U200BleClient
from .const import (
    CONF_ACCOUNT,
    CONF_POLL_MINUTES,
    CONF_TRIGGER_LOCK_ENTITY,
    DEFAULT_POLL_MINUTES,
    DOMAIN,
    TRIGGER_REFRESH_DELAY_SECONDS,
)
from .exceptions import U200BleAuthenticationError

_LOGGER = logging.getLogger(__name__)

#: While reads keep failing (no value yet, or the lock/adapter is
#: unreachable/contended), retry on a short interval instead of waiting the
#: full configured poll period -- but back off exponentially, doubling this
#: interval on every further failure up to _MAX_RETRY_SECONDS. A shared
#: onboard Bluetooth adapter can only handle one connection attempt at a
#: time; hammering it every _INITIAL_RETRY_SECONDS while the lock is simply
#: unreachable was observed live (2026-09-04) to starve OTHER BLE devices on
#: the same adapter (a Tuya device lost its own connection while this kept
#: retrying) -- backing off once retries aren't working reduces that
#: collateral damage while still recovering quickly once conditions improve.
_INITIAL_RETRY_SECONDS = 60.0
_MAX_RETRY_SECONDS = 1800.0
_INITIAL_DELAY_SECONDS = 10.0

#: Minimum time between credential-name cloud fetch ATTEMPTS, success or
#: failure alike. Confirmed live 2026-09-08: doing this every poll cycle
#: (every few minutes) meant a fresh Aqara-account cloud LOGIN every few
#: minutes -- which sometimes gets challenged with ``code=855``
#: ("Cle temporaire incorrecte, entrez s'il vous plait" -- a short-lived
#: guard-code step-up-auth prompt, the same one the fetch_ltmk service
#: handles interactively) since Aqara's cloud appears to demand it
#: sporadically for frequent logins from the same account/client, not as a
#: fixed rule (a login moments later, with no guard code given, succeeded
#: fine). We can't satisfy that prompt unattended (it needs a live ~30s
#: code from the app), so the only real lever we have is to log in far
#: less often: which slot maps to which name essentially never changes,
#: so refreshing once every few hours is still more than fast enough to
#: pick up a newly enrolled fingerprint/face, while cutting our login
#: frequency (and therefore how often we can hit that prompt) drastically
#: versus once every few minutes.
_CREDENTIAL_FETCH_INTERVAL = 6 * 3600.0  # 6 hours

#: Conservative cap on how old a persisted cloud-auth token may be
#: before we stop trusting it and let a fresh login happen instead.
#: A real Aqara token is expected to last roughly a week. Kept well
#: under that on purpose -- guessing wrong on the low side just costs
#: one extra ordinary login; guessing wrong on the high side risks
#: presenting an already-dead token (harmless: the vendored session.py
#: retries once with a forced fresh login on the resulting code 108).
_AUTH_TOKEN_MAX_AGE_SECONDS = 5 * 24 * 3600.0  # 5 days


@dataclass(slots=True, frozen=True)
class U200BleRuntimeSnapshot:
    """Safe runtime state pushed to Home Assistant entities."""

    reachable: bool
    last_seen: datetime | None
    rssi: int | None
    last_error_type: str | None
    #: Most recent access-log entry, read over BLE (SYNC_LOG / 0x13; None
    #: until first read). ``last_unlock_credential_slot`` is a bare NUMBER —
    #: never a name; see ``client.LastUnlockEvent``.
    last_unlock_label: str | None = None
    last_unlock_credential_slot: int | None = None
    last_unlock_timestamp: int | None = None
    #: Whether the entry above is an actual credential-open (a person
    #: unlocking) rather than a status event (lock/relock, anti-lock,
    #: tamper, ...) with no attributable person -- see
    #: client.LastUnlockEvent.is_credential_open.
    last_unlock_is_credential_open: bool = False
    #: {slot: person name}, fetched from the Aqara CLOUD (no BLE) -- see
    #: client.U200BleClientAdapter.async_fetch_credential_names. Names are
    #: real and sensitive: this dict is HA runtime state only, never
    #: written to source. Empty until the first successful cloud fetch, or
    #: if that account has no fingerprint/face credentials enrolled.
    credential_names: dict[str, str] | None = None
    #: Most recent user/credential table read over BLE (SYNC_USER_ID_VALID_
    #: PERIOD / 0x1f) -- an opportunistic bonus read piggybacked on the
    #: regular access-log poll connection, only ever successful when the
    #: front-panel keypad happened to be awake at that moment (see
    #: client.py's async_read_snapshot). None until the first such read
    #: succeeds; can go a long time without updating since the panel is
    #: asleep most of the time -- ``user_table_updated_at`` says how stale
    #: the current value is. Never contains a name, only bare numeric
    #: slots/types, same as ``last_unlock_credential_slot``.
    user_table: tuple[UserCredential, ...] | None = None
    user_table_updated_at: datetime | None = None


class U200BleCoordinator(DataUpdateCoordinator[U200BleRuntimeSnapshot]):
    """Coordinate Bluetooth reachability and on-demand access-log reads."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        bluetooth_manager: U200BleBluetoothManager,
        client: U200BleClient,
    ) -> None:
        """Initialize the push coordinator."""
        super().__init__(
            hass,
            logger=_LOGGER,
            name=DOMAIN,
            config_entry=entry,
            always_update=False,
        )
        self.bluetooth_manager = bluetooth_manager
        self.client = client
        self._entry = entry
        self._read_lock = asyncio.Lock()
        self._last_error_type: str | None = None
        self._last_unlock: LastUnlockEvent | None = None
        self._user_table: tuple[UserCredential, ...] | None = None
        self._user_table_updated_at: datetime | None = None
        self._poll_task: asyncio.Task[None] | None = None
        self._poll_stop = asyncio.Event()
        self._retry_seconds = _INITIAL_RETRY_SECONDS
        self._credential_names: dict[str, str] = {}
        #: time.monotonic() of the last credential-name cloud fetch ATTEMPT
        #: (success or failure), or None before the first one -- see
        #: _CREDENTIAL_FETCH_INTERVAL / async_refresh_credential_names.
        #: 2026-09-11: this used to live ONLY in memory, timed with
        #: time.monotonic() -- which resets to 0 on every HA restart, so
        #: the "once per _CREDENTIAL_FETCH_INTERVAL" throttle below was
        #: silently worthless across restarts: every single restart
        #: immediately attempted a fresh cloud login for the credential-
        #: name fetch, moments after startup -- confirmed live from the
        #: 2026-09-10/11 lockout log (a credential-name fetch attempt,
        #: and its 855 guard-code rejection, landed within ~30s of each of
        #: several restarts that night). Fixed by persisting the last
        #: ATTEMPT time in a dedicated Store (not the config entry itself,
        #: to avoid triggering _async_reload_on_options's entry-update
        #: listener) and using wall-clock time.time() instead of
        #: time.monotonic() so it actually survives a restart -- see
        #: async_refresh_credential_names below for the load/save.
        self._credential_fetch_last_attempt_at: float | None = None
        self._credential_fetch_state_loaded = False
        self._credential_fetch_store: Store[dict[str, float]] = Store(
            hass, 1, f"{DOMAIN}_{entry.entry_id}_credential_fetch"
        )
        #: Persisted (token, user_id, account, saved_at) snapshot of this
        #: entry's Aqara cloud-auth token -- lets a freshly built
        #: CloudAuthManager (one is constructed from scratch on every HA
        #: restart/entry reload, see build_cloud_auth in client.py) reuse a
        #: still-valid token instead of always performing a brand-new login.
        #: Loaded lazily (once) in async_refresh_log, since __init__ cannot
        #: await -- mirrors the _credential_fetch_store pattern above. This
        #: closes a reauth-then-immediate-relogin bug where a freshly
        #: validated token was discarded instead of reused.
        self._auth_token_store: Store[dict[str, Any]] = Store(
            hass, 1, f"{DOMAIN}_{entry.entry_id}_auth_token"
        )
        self._auth_token_state_loaded = False
        self._last_persisted_token: str | None = None
        #: Unsubscribe callback for the optional CONF_TRIGGER_LOCK_ENTITY
        #: state-change listener -- see async_start_polling/async_stop_polling
        #: and _async_on_trigger_lock_state_change below. None when no
        #: trigger entity is configured (the default, unchanged behaviour).
        self._trigger_unsub: Callable[[], None] | None = None
        #: Set once a read hits a genuine Aqara auth/guard-code rejection
        #: (CloudServiceError code 810/855 -> U200BleAuthenticationError)
        #: and reauth has been requested. See async_refresh_log's early
        #: guard and _async_poll_loop below for why this exists: 2026-09-10
        #: night, the poll loop kept retrying with the same now-stale
        #: guard_code every 60s-1800s AND the manual refresh button was
        #: pressed repeatedly on top of that, each attempt separately
        #: counting against Aqara's own "5 failed logins" rate limit --
        #: together they escalated a single, normal guard-code challenge
        #: (855) into a full account lockout (818, "wait ~5 min"), which
        #: then kept getting re-triggered by further retries during the
        #: cooldown. Cleared automatically once a read succeeds again
        #: (normally right after the user completes reauth, which reloads
        #: the whole config entry and recreates this coordinator anyway --
        #: but cleared here too in case a read ever succeeds without a
        #: reload, e.g. a stale flag from a since-resolved transient case).
        self._auth_error_pending: bool = False
        self.data = self._build_snapshot(bluetooth_manager.state)

    @callback
    def clear_pending_auth_error(self) -> None:
        """Unstick the poll loop right after a successful reauth.

        Called from config_flow.py's async_step_reauth_confirm the moment
        validation succeeds -- NOT left to the entry reload alone. Reason
        (found live 2026-09-13): Home Assistant's own
        ``async_update_entry()`` only fires the registered update listener
        (and therefore only reloads the entry / recreates this coordinator)
        when the persisted data actually differs from what is already
        stored. Since a reauth submission with an unchanged
        account/password, and a guard code that gets cleared to "" every
        time, can end up identical to what is already
        persisted, no reload happens at all -- leaving THIS coordinator's
        stale ``_auth_error_pending=True`` stuck forever, silently skipping
        every future read even though the credentials are fine again.
        """
        if self._auth_error_pending:
            _LOGGER.debug(
                "u200_ble: clearing _auth_error_pending after a successful "
                "reauth validation -- resuming normal reads"
            )
            self._auth_error_pending = False

    @callback
    def async_start_polling(self) -> None:
        """Start the background BLE poll loop (runs on every setup/restart).

        Also wires up the optional CONF_TRIGGER_LOCK_ENTITY listener, if the
        user configured one (Configure -> "Auslösendes Schloss" / trigger
        lock entity): an options change reloads the whole config entry (see
        __init__.py's _async_reload_on_options), which recreates this
        coordinator and calls this method again -- so simply re-reading the
        option here on every (re)start is enough, no separate change
        handling needed.
        """
        if self._poll_task is not None:
            return
        self._poll_stop.clear()
        self._poll_task = self.config_entry.async_create_background_task(
            self.hass, self._async_poll_loop(), f"{DOMAIN}_poll"
        )
        trigger_entity_id = self._entry.options.get(CONF_TRIGGER_LOCK_ENTITY, "")
        if trigger_entity_id:
            self._trigger_unsub = async_track_state_change_event(
                self.hass,
                [trigger_entity_id],
                self._async_on_trigger_lock_state_change,
            )

    async def async_stop_polling(self) -> None:
        """Stop the background poll (on unload)."""
        self._poll_stop.set()
        task, self._poll_task = self._poll_task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if self._trigger_unsub is not None:
            self._trigger_unsub()
            self._trigger_unsub = None

    @callback
    def _async_on_trigger_lock_state_change(self, event: Event) -> None:
        """React to the configured trigger lock.* entity unlocking.

        2026-09-10: added on request -- without this, a fresh access-log
        entry is only ever picked up on the next regular CONF_POLL_MINUTES
        cycle (up to 30 min by default, longer still while the retry
        backoff is active), even though another integration (this user's
        Matter one) already reports the SAME physical lock unlocking
        within a second or two. Only reacts to a genuine transition INTO
        "unlocked" (never locking, never "unavailable"/"unknown", and never
        a mere attribute-only update with the state string unchanged) to
        avoid firing a BLE read on every minor update of the watched
        entity. Schedules the actual read after TRIGGER_REFRESH_DELAY_SECONDS
        rather than instantly -- the lock needs a moment to finish writing
        its own SYNC_LOG record and resume advertising.

        Known gap, not solved by this: a FAILED unlock attempt (wrong code,
        unrecognized fingerprint) never transitions the watched lock.*
        entity to "unlocked" at all, so it still waits for the next regular
        poll -- there is no separate "keypad woke up" entity to listen to
        instead.
        """
        # Plain dict access (not the typed EventStateChangedData some newer
        # HA versions offer for this event): stays correct across HA
        # versions rather than pinning to one's exact typing surface, same
        # spirit as this integration's other defensive-against-version-
        # drift code (see client.py's build_cloud_auth/inspect.signature).
        new_state = event.data.get("new_state")
        old_state = event.data.get("old_state")
        if new_state is None or new_state.state != "unlocked":
            return
        if old_state is not None and old_state.state == new_state.state:
            return
        self.config_entry.async_create_background_task(
            self.hass,
            self._async_delayed_trigger_refresh(),
            f"{DOMAIN}_trigger_refresh",
        )

    async def _async_delayed_trigger_refresh(self) -> None:
        """Wait TRIGGER_REFRESH_DELAY_SECONDS, then read the access log once."""
        await asyncio.sleep(TRIGGER_REFRESH_DELAY_SECONDS)
        await self.async_refresh_log()

    async def _async_poll_loop(self) -> None:
        """Read the access log over BLE on a configurable cadence.

        Reads once shortly after startup, then every ``poll_minutes`` once a
        read has succeeded. While reads keep failing, retries with
        exponential backoff (see ``_retry_seconds``) instead of hammering a
        possibly contended/unreachable adapter on a fixed short interval.
        """
        try:
            await asyncio.wait_for(
                self._poll_stop.wait(), timeout=_INITIAL_DELAY_SECONDS
            )
            return  # stopped during the initial delay
        except TimeoutError:
            pass
        while not self._poll_stop.is_set():
            got_value = await self.async_refresh_log()
            if self._auth_error_pending:
                # Do NOT schedule another retry on any timer -- see
                # _auth_error_pending's docstring. Just wait to be stopped
                # (entry unload/reload, which happens automatically once
                # reauth succeeds and recreates this coordinator fresh).
                await self._poll_stop.wait()
                return
            await self.async_refresh_credential_names()
            if got_value:
                self._retry_seconds = _INITIAL_RETRY_SECONDS
                interval = self._poll_seconds
            else:
                interval = self._retry_seconds
                self._retry_seconds = min(
                    self._retry_seconds * 2, _MAX_RETRY_SECONDS
                )
            try:
                await asyncio.wait_for(self._poll_stop.wait(), timeout=interval)
                return
            except TimeoutError:
                continue

    @property
    def _poll_seconds(self) -> float:
        """Configured poll interval, in seconds."""
        minutes = self._entry.options.get(CONF_POLL_MINUTES, DEFAULT_POLL_MINUTES)
        try:
            minutes = float(minutes)
        except (TypeError, ValueError):
            minutes = float(DEFAULT_POLL_MINUTES)
        return minutes * 60.0

    async def _async_load_auth_token_once(self) -> None:
        """Lazily restore a persisted cloud-auth token, at most once.

        A no-op if the adapter's own auth object already has a token
        cached -- e.g. because config_flow.py just handed one off after a
        successful reauth (``U200BleClientAdapter.apply_auth_token``): a
        token obtained seconds ago is always preferred over one restored
        from disk.
        """
        if self._auth_token_state_loaded:
            return
        self._auth_token_state_loaded = True
        if self.client.auth_token_snapshot() is not None:
            return
        try:
            stored = await self._auth_token_store.async_load()
        except Exception:  # noqa: BLE001 - best-effort, see class docstring
            stored = None
        if not stored:
            return
        if stored.get("account") != self._entry.data.get(CONF_ACCOUNT):
            return
        age = time.time() - stored.get("saved_at", 0)
        if age < 0 or age > _AUTH_TOKEN_MAX_AGE_SECONDS:
            return
        token = stored.get("token")
        if not token:
            return
        self.client.apply_auth_token(token, stored.get("user_id", ""))
        self._last_persisted_token = token
        _LOGGER.debug(
            "u200_ble: restored a cached Aqara cloud token from disk "
            "(saved %.0f h ago) -- skipping a fresh login for now",
            age / 3600,
        )

    async def async_persist_current_auth_token(self) -> None:
        """Best-effort: save the auth object's current token, if changed.

        Call this once a cloud login is known to have just succeeded (a
        completed read, a completed reauth handoff) -- persisting it lets
        the NEXT HA restart/entry reload reuse it instead of forcing a
        brand-new login, which needs a guard code far more often than the
        token itself actually expires (confirmed live 2026-09-13: a fresh
        login was rejected with code 854 only 14s after a previous one had
        just succeeded).
        """
        snapshot = self.client.auth_token_snapshot()
        if snapshot is None:
            return
        token, user_id = snapshot
        if token == self._last_persisted_token:
            return
        self._last_persisted_token = token
        try:
            await self._auth_token_store.async_save(
                {
                    "token": token,
                    "user_id": user_id,
                    "account": self._entry.data.get(CONF_ACCOUNT),
                    "saved_at": time.time(),
                }
            )
        except Exception:  # noqa: BLE001 - best-effort, see class docstring
            pass

    async def async_refresh_log(self) -> bool:
        """Read the access log once over BLE (guarded), updating the snapshot.

        Also opportunistically refreshes the user/credential table in the
        SAME BLE connection when the front-panel keypad happens to be awake
        (see client.py's ``async_read_snapshot``) -- most of the time it
        isn't, and that part is then simply skipped at effectively no extra
        cost. Skipped entirely only when the lock is unreachable. Used by
        both the poll loop (to drive its backoff -- see
        ``_async_poll_loop``) and the manual Refresh button. Returns
        whether the access-log read specifically was obtained (used for
        backoff pacing) -- independent of whether the bonus table read
        also succeeded this time.

        Refuses to even attempt a read while ``_auth_error_pending`` is
        set (see that flag's own docstring in __init__) -- protects
        against BOTH the poll loop's own retries AND repeated manual
        button presses hammering Aqara's login endpoint with credentials
        already known to be rejected.
        """
        # Restore a still-valid cached token (if any) before the very
        # first read this coordinator lifetime attempts one -- see
        # _async_load_auth_token_once's own docstring for the reasoning.
        await self._async_load_auth_token_once()
        if self._auth_error_pending:
            _LOGGER.debug(
                "access-log read skipped: a previous read already hit an "
                "Aqara auth/guard-code rejection -- waiting for reauth to "
                "complete instead of retrying with the same credentials."
            )
            return False
        if self.bluetooth_manager.async_get_ble_device() is None:
            # Live check, not the cached ``state.reachable`` flag: that flag
            # only flips on discrete HA Bluetooth advertisement/"unavailable"
            # callbacks (see bluetooth.py) and can lag behind reality -- e.g.
            # stay stuck False after the lock briefly stops advertising while
            # holding a connection elsewhere, even once it's advertising
            # again. This early-exit used to be completely silent, which
            # made every skipped button press indistinguishable from one
            # that actually attempted a BLE connection and failed -- observed
            # live 2026-09-05: several manual refreshes produced zero log
            # output at all, cached-reachable or not.
            _LOGGER.debug(
                "access-log read skipped: lock not currently resolvable via "
                "any connectable Bluetooth adapter/proxy (cached "
                "reachable=%s)",
                self.bluetooth_manager.state.reachable,
            )
            return False
        try:
            async with self._read_lock:
                value, table = await self.client.async_read_snapshot()
        except asyncio.CancelledError:
            raise
        except U200BleAuthenticationError as err:
            # Log the underlying Aqara error (code + message) -- safe to log
            # in full, same reasoning as the generic-failure branch in
            # client.py's _async_one_read: a CloudServiceError's code/message
            # is Aqara's own short status text (e.g. "code=854 message=need
            # dynamic token login"), never account/password/token material.
            # Found missing during earlier live testing:
            # is_invalid_auth_error() correctly recognizing a code here (810/
            # 853/854/855) means client.py raises this generic
            # U200BleAuthenticationError instead of falling into its own
            # logged branch -- and this handler used to just set flags
            # silently, so the actual reason a read failed and reauth was
            # requested was never written anywhere, even at DEBUG level.
            _LOGGER.warning(
                "u200_ble: Aqara auth rejected during a read -- reauth "
                "requested (%s)",
                err.__cause__ or err,
            )
            self._last_error_type = type(err).__name__
            self._auth_error_pending = True
            self._entry.async_start_reauth(self.hass)
            return False
        except Exception as err:  # noqa: BLE001 - transient BLE/cloud errors
            _LOGGER.debug("access-log read failed (%s)", type(err).__name__)
            return False
        # Reached past the try/except above without raising: the read (and
        # any login it needed) succeeded this time.
        self._auth_error_pending = False
        await self.async_persist_current_auth_token()
        changed = False
        if table is not None:
            # Bonus read, piggybacked on this same connection -- only ever
            # non-None when the front-panel keypad happened to be awake
            # (see client.py's async_read_snapshot). Worth pushing even if
            # the credential list content is unchanged from last time: the
            # refreshed "as of" timestamp is new information on its own (it
            # confirms the table is still current as of just now).
            self._user_table = table
            self._user_table_updated_at = datetime.now(UTC)
            changed = True
        if value is None:
            if changed:
                self.async_set_updated_data(
                    self._build_snapshot(self.bluetooth_manager.state)
                )
            return False
        if value != self._last_unlock:
            self._last_unlock = value
            self._last_error_type = None
            changed = True
        if changed:
            self.async_set_updated_data(
                self._build_snapshot(self.bluetooth_manager.state)
            )
        return True

    async def async_refresh_credential_names(self) -> None:
        """Refresh {slot: name} from the Aqara cloud (no BLE, no keypad).

        Best-effort and non-fatal, same as the LTMK bootstrap in
        __init__.py: on failure this just keeps the previous cache (or
        stays empty on the very first attempt) rather than breaking the
        access-log poll cycle it runs alongside.

        Unlike the BLE read (which uses the offline LTMK session), this
        call needs a full Aqara-account cloud LOGIN every time it doesn't
        already have a cached token. Confirmed live 2026-09-08: doing this
        every poll cycle occasionally collides with a sporadic Aqara
        ``code=855`` guard-code challenge on login (see
        ``_CREDENTIAL_FETCH_INTERVAL``) -- so this now only actually
        attempts a fetch once per ``_CREDENTIAL_FETCH_INTERVAL``, on
        success OR failure, rather than on every poll -- and, since
        2026-09-11, that throttle is persisted (see __init__'s
        ``_credential_fetch_store``) so it actually survives an HA
        restart instead of resetting every time.
        """
        if not self._credential_fetch_state_loaded:
            self._credential_fetch_state_loaded = True
            try:
                stored = await self._credential_fetch_store.async_load()
            except Exception:  # noqa: BLE001 - best-effort, see class docstring
                stored = None
            if stored is not None:
                self._credential_fetch_last_attempt_at = stored.get("last_attempt_at")
        now = time.time()
        last = self._credential_fetch_last_attempt_at
        if last is not None and now - last < _CREDENTIAL_FETCH_INTERVAL:
            return
        self._credential_fetch_last_attempt_at = now
        try:
            await self._credential_fetch_store.async_save({"last_attempt_at": now})
        except Exception:  # noqa: BLE001 - best-effort: worst case, the
            # in-memory value above still gates THIS run; only a future
            # restart would lose the persisted timestamp.
            pass
        try:
            names = await self.client.async_fetch_credential_names()
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001 - best-effort, see above
            if isinstance(err, CloudServiceError):
                _LOGGER.debug(
                    "credential-name cloud fetch failed: CloudServiceError "
                    "code=%s message=%s endpoint=%s; keeping previous mapping "
                    "(%d entries); retrying in %d h",
                    err.code, err.message, err.endpoint,
                    len(self._credential_names),
                    _CREDENTIAL_FETCH_INTERVAL // 3600,
                )
            else:
                _LOGGER.debug(
                    "credential-name cloud fetch failed (%s: %s); keeping "
                    "previous mapping (%d entries); retrying in %d h",
                    type(err).__name__, err,
                    len(self._credential_names),
                    _CREDENTIAL_FETCH_INTERVAL // 3600,
                )
            return
        if names != self._credential_names:
            self._credential_names = names
            self.async_set_updated_data(
                self._build_snapshot(self.bluetooth_manager.state)
            )

    @callback
    def async_handle_bluetooth_state(self, state: U200BleBluetoothState) -> None:
        """Push a Home Assistant Bluetooth state change to entities."""
        self.async_set_updated_data(self._build_snapshot(state))

    def _build_snapshot(
        self, bluetooth_state: U200BleBluetoothState
    ) -> U200BleRuntimeSnapshot:
        """Build a sanitized immutable snapshot."""
        return U200BleRuntimeSnapshot(
            reachable=bluetooth_state.reachable,
            last_seen=bluetooth_state.last_seen,
            rssi=bluetooth_state.rssi,
            last_error_type=self._last_error_type,
            last_unlock_label=self._last_unlock.label if self._last_unlock else None,
            last_unlock_credential_slot=(
                self._last_unlock.credential_slot if self._last_unlock else None
            ),
            last_unlock_timestamp=(
                self._last_unlock.timestamp if self._last_unlock else None
            ),
            last_unlock_is_credential_open=(
                self._last_unlock.is_credential_open if self._last_unlock else False
            ),
            credential_names=dict(self._credential_names),
            user_table=self._user_table,
            user_table_updated_at=self._user_table_updated_at,
        )
