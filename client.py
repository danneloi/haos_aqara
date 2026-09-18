"""Protocol-independent client boundary and real Aqara U200 adapter.

Deliberately minimal: this integration reads the access log (SYNC_LOG /
0x13) over BLE, plus -- opportunistically, in the SAME connection -- the
user/credential table (SYNC_USER_ID_VALID_PERIOD / 0x1f) whenever the
front-panel keypad happens to be awake (see ``async_read_snapshot``). No
lock/unlock, no battery, no settings -- those are already covered by this
user's Matter integration for the same device; Matter has no access-log or
credential-table data, both BLE-only (see const.py).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Any, Protocol

from ._vendor.aqara_ble import (
    CloudAuthManager,
    CloudServiceError,
    FlowPhase,
    U200ClientError,
    UserCredential,
)
from ._vendor.aqara_ble.app_constants import generate_client_id, generate_phone_id
from ._vendor.aqara_ble import (
    U200Client as ProtocolU200Client,
)

if TYPE_CHECKING:
    # 2026-09-10: kept type-checking-only, NOT a runtime import. The
    # installed aqara_ble on the real HA host does not export
    # LockCredential from its package root (confirmed live: "cannot import
    # name 'LockCredential' from 'aqara_ble'") -- with `from __future__
    # import annotations` above, every annotation in this file is a string
    # at runtime and never evaluated, so this name only needs to resolve
    # for a type checker (mypy), never for Home Assistant actually loading
    # this module.
    from ._vendor.aqara_ble import LockCredential
from bleak_retry_connector import (
    BleakClientWithServiceCache,
    establish_connection,
)
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import HomeAssistant

from .bluetooth import U200BleBluetoothManager
from .const import (
    BLE_READ_ATTEMPTS,
    BLE_READ_GAP_SECONDS,
    CONF_ACCOUNT,
    CONF_CLIENT_ID,
    CONF_DISTRICT,
    CONF_GUARD_CODE,
    CONF_LTMK,
    CONF_PHONE_ID,
    CONF_REGION,
    DEFAULT_DISTRICT,
    DEFAULT_REGION,
)
from .exceptions import U200BleAuthenticationError

_LOGGER = logging.getLogger(__name__)
_CONNECTION_NAME = "U200 BLE"
_DISCONNECT_TIMEOUT = 10

AUTH_CONFIG_KEYS = (
    CONF_ACCOUNT,
    CONF_PASSWORD,
)


@dataclass(frozen=True)
class LastUnlockEvent:
    """The most recent access-log (SYNC_LOG / 0x13) entry, read over BLE.

    ``label`` is the entry's unlock METHOD (e.g. ``"password"``,
    ``"fingerprint"``, ``"matter"``, ``"ble"``, ``"NFC"``, ``"key"``) for a
    credential-open row, per ``aqara_ble.access_log.METHOD_BY_HI`` -- or, for
    a non-open row (a plain lock event, tamper, etc.), the entry's raw
    ``event_class`` (e.g. ``"lock_event"``, ``"lock_exception"``) as a
    fallback label.

    ``credential_slot`` is the entry's raw ``user_id`` (a 4-byte
    lock-internal credential/user id), decoded as a little-endian uint32 --
    the BLE protocol itself has no concept of a person's name, only this
    numeric id, which is exactly the same id the Aqara cloud calls
    ``typeValue`` (see ``_resolve_credential_slot`` and
    ``async_fetch_credential_names`` below; confirmed 2026-09-09 via a
    live protocol trace). Which household member it belongs to is known only inside the
    Aqara app/cloud's own user records, never derivable here. This
    integration never guesses or stores a name for it.

    ``timestamp`` is Unix seconds (UTC), as read from the lock.
    """

    event_type: int
    label: str | None
    credential_slot: int | None
    timestamp: int
    #: True only for an actual credential-open row (someone unlocking with
    #: a fingerprint/password/NFC/key/app/etc.) -- False for a status event
    #: with no attributable person (a plain lock/relock, anti-lock, tamper,
    #: ...). ``credential_slot`` is only ever meaningful when this is True;
    #: the person sensor (sensor.py) uses this to avoid showing a
    #: misleading "Unzugeordnet (Slot 0)" for e.g. a routine "door was
    #: locked" event that never involved a credential at all.
    is_credential_open: bool = False


class U200BleClient(Protocol):
    """Contract consumed by the Home Assistant runtime.

    Real protocol/session/KDF details stay behind an adapter implementing this
    contract. Entities must never depend directly on aqara-ble internals.
    """

    async def async_read_snapshot(
        self,
    ) -> tuple[LastUnlockEvent | None, tuple[UserCredential, ...] | None]:
        """Read the access log, over BLE, plus the user/credential table if
        the front panel happens to be awake right now -- in ONE connection.

        Numeric credential slot only in ``LastUnlockEvent`` — never a name
        (see its docstring). The table element is ``None`` when the front
        panel wasn't awake at read time (nothing attempted) or the whole
        read failed; an empty tuple is a genuine "0 credentials" result.
        """
        ...

    async def async_fetch_credential_names(self) -> dict[str, str]:
        """Fetch {slot: person name} from the Aqara cloud (no BLE); {} on failure.

        This is the ONLY place a real name ever enters this integration --
        always from the user's own Aqara cloud account, never hardcoded.
        """
        ...


def generate_device_identity() -> dict[str, str]:
    """Mint a fresh per-install cloud-login identity (client_id + phone_id).

    Call this ONCE per config entry (at config-flow creation, or as a
    one-time migration for an entry that predates CONF_CLIENT_ID/
    CONF_PHONE_ID) and persist the result in entry.data. Never call it on
    every setup -- see CONF_CLIENT_ID's docstring in const.py for why that
    made Aqara's cloud start demanding a guard code (error 855) on every HA
    restart.
    """
    return {CONF_CLIENT_ID: generate_client_id(), CONF_PHONE_ID: generate_phone_id()}


def build_cloud_auth(config: Mapping[str, Any]) -> CloudAuthManager:
    """Build library-owned cloud auth from Home Assistant config-entry data.

    Only account + password are strictly required. ``client_id``/``phone_id``
    should already be in ``config`` (persisted by the config flow / the
    migration in __init__.py) so this reuses the SAME cloud-login identity
    across restarts -- CloudAuthManager mints a fresh random one otherwise,
    which repeated HA restarts turn into what looks like many different app
    installs logging into the same account in a short window. district must
    match the account's own country (see CONF_DISTRICT) or the cloud rejects
    the login outright (code 858) regardless of correct credentials.

    guard_code is normally empty (ordinary reads/logins haven't needed one
    since CONF_CLIENT_ID/CONF_PHONE_ID stopped the per-restart identity churn
    that used to trigger code 855). NOTE (2026-09-07): fetching the LTMK
    itself (``CloudAuthManager.fetch_ltmk``, ``/dev/bluetooth/query``) seems
    to ALWAYS demand a fresh one regardless (code 854, "dynamic token login
    required") -- see the ``fetch_ltmk`` service in __init__.py, which builds
    its own auth with a freshly-supplied guard_code for just that one call.

    2026-09-10 UPDATE: the ``aqara_ble``
    actually installed on the real HA host turned out to be an older build
    whose ``CloudAuthManager.__init__`` doesn't accept every keyword this
    function used to pass unconditionally -- confirmed live via a
    ``TypeError: CloudAuthManager.__init__() got an unexpected keyword
    argument 'guard_code'``. Rather than guess which keywords a given
    installed version does or doesn't have, this now inspects the actual,
    installed constructor's signature at call time and only passes a
    keyword if it's really there -- account/password are the only two
    assumed unconditionally, since nothing in this integration works at
    all without them. A keyword that gets silently dropped this way simply
    falls back to whatever that older ``CloudAuthManager`` build already
    did on its own (e.g. an older, guard-code-less/identity-churn-prone
    login path) -- not perfect, but running with a reduced feature set beats
    the whole integration refusing to set up at all.
    """
    kwargs: dict[str, Any] = {
        "account": config[CONF_ACCOUNT],
        "password": config[CONF_PASSWORD],
    }
    optional_kwargs = {
        "client_id": config.get(CONF_CLIENT_ID) or None,
        "phone_id": config.get(CONF_PHONE_ID) or None,
        "region": config.get(CONF_REGION, DEFAULT_REGION),
        "district": config.get(CONF_DISTRICT, DEFAULT_DISTRICT),
        "guard_code": config.get(CONF_GUARD_CODE, ""),
    }
    accepted = set(inspect.signature(CloudAuthManager.__init__).parameters)
    for name, value in optional_kwargs.items():
        if name in accepted:
            kwargs[name] = value
        else:
            _LOGGER.debug(
                "CloudAuthManager on this aqara_ble install has no '%s' "
                "constructor parameter -- skipping it (older library "
                "build than this integration was written against)",
                name,
            )
    return CloudAuthManager(**kwargs)


def is_invalid_auth_error(err: BaseException) -> bool:
    """Return whether an exception chain is an Aqara invalid-auth rejection.

    Code 810: wrong password / unregistered account (confirmed, see
    aqara_ble.auth). Code 855: the cloud is demanding a guard code (a
    short-lived, ~30s one-time code) that was missing, wrong, or expired --
    observed live 2026-09-05, message "temporary key incorrect, please
    re-enter". Code 854: the cloud rejects the ordinary account login
    itself with "dynamic token login required" (854, seen live 2026-09-13
    at /user/guard-code/login -- NOT the /dev/bluetooth/query LTMK
    endpoint) -- i.e. even a ordinary, non-LTMK login can apparently be
    guard-code-gated by Aqara (e.g. after recent suspicious activity on the
    account), contradicting this integration's earlier assumption that only
    the LTMK fetch ever needs one. Code 853: "dynamic token format
    incorrect" (seen live 2026-09-13 during a reauth submission) -- the
    guard code the user typed doesn't match Aqara's expected format at
    all (e.g. mistyped, wrong number of digits). All four are not
    retryable with the same credentials: each needs a human back in the
    loop (a corrected password, or a freshly issued/correctly-formatted
    guard code), so all four should surface Home Assistant's reauth flow
    -- or, for 853 specifically, at least a clear "credentials rejected"
    form error instead of a misleading "cannot connect" one during the
    reauth/setup flow itself -- instead of silently retrying forever with
    input that will never become valid, which would otherwise show up as
    silent infinite retry / a confusing form error instead.
    """
    current: BaseException | None = err
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, CloudServiceError) and (
            current.is_code(810)
            or current.is_code(853)
            or current.is_code(854)
            or current.is_code(855)
        ):
            return True
        current = current.__cause__ or current.__context__
    return False


def auth_token_snapshot(auth: CloudAuthManager) -> tuple[str, str] | None:
    """Read back the (token, user_id) a ``CloudAuthManager`` already holds.

    ``CloudAuthManager`` has no public getter for its cached token (only
    ``get_token()``, which logs in if none is cached yet) -- this reaches
    into its private cache so a token obtained by ONE instance (e.g. the
    throwaway one ``async_validate_cloud_auth`` builds just to check a
    submitted guard code) can be handed to a DIFFERENT, long-lived instance
    instead of being thrown away. Returns ``None`` if no token is cached yet
    (nothing to hand off).
    """
    token = getattr(auth, "_token", None)
    if not token:
        return None
    return token, getattr(auth, "_user_id", "") or ""


def apply_auth_token_snapshot(
    auth: CloudAuthManager, snapshot: tuple[str, str]
) -> None:
    """Install a (token, user_id) pair obtained elsewhere into ``auth``.

    Skips the fresh login ``get_token()`` would otherwise perform on its
    next call -- see ``auth_token_snapshot`` above for why this matters.
    """
    auth._token, auth._user_id = snapshot  # noqa: SLF001 - see docstring


async def async_validate_cloud_auth(
    hass: HomeAssistant, config: Mapping[str, Any]
) -> CloudAuthManager:
    """Validate credentials without blocking Home Assistant's event loop.

    Returns the ``CloudAuthManager`` this just built and logged in with --
    it already holds a fresh, guard-code-validated token (see
    ``CloudAuthManager.get_token``). Callers that validate credentials
    during a reauth/setup flow should hand that token off to the entry's
    actual long-lived auth object (``apply_auth_token_snapshot`` above)
    instead of discarding it: a second, brand-new login attempt right
    after this one succeeds gets no benefit from the guard code that was
    just accepted (the field is cleared to "" before being persisted, see
    Teil 19) and can be rejected all over again if Aqara is currently
    demanding a guard code on every fresh login -- confirmed live
    2026-09-13.
    """
    auth = build_cloud_auth(config)
    await hass.async_add_executor_job(auth.build_signer)
    return auth


async def async_fetch_ltmk(
    hass: HomeAssistant, auth: CloudAuthManager, device_id: str
) -> bytes:
    """Fetch this lock's LTMK from the Aqara cloud (blocking HTTP, off-loop).

    One-time call (see CONF_LTMK in const.py): the caller persists the
    result and never needs to call this again for the same device, since a
    device's LTMK does not change. Raises whatever ``CloudAuthManager.
    fetch_ltmk`` raises (``CloudServiceError``, ``ValueError``) -- the caller
    treats this as best-effort and falls back to the per-read cloud login.
    """
    return await hass.async_add_executor_job(auth.fetch_ltmk, device_id)


async def async_fetch_lock_credentials(
    hass: HomeAssistant, auth: CloudAuthManager, device_id: str
) -> tuple[LockCredential, ...]:
    """Fetch the lock's cloud credential table (blocking HTTP, off-loop).

    ``GET /dev/lock/query`` -- no BLE, no keypad touch, run on every poll
    cycle (see coordinator.py); cheap and names change rarely, but this way
    a newly enrolled person's name shows up without restarting HA. Raises
    whatever ``CloudAuthManager.fetch_lock_credentials`` raises -- the
    caller treats this as best-effort, same as the LTMK fetch above.
    """
    return await hass.async_add_executor_job(auth.fetch_lock_credentials, device_id)


def _resolve_credential_slot(entry: Any) -> int | None:
    """Decode an access-log entry's ``user_id`` into its credential id.

    2026-09-10 UPDATE: this used to special-case fingerprint/face credential-opens to
    just the FIRST byte of ``user_id`` (a lock-internal "slot"), matched
    against the cloud's ``userCode`` field -- and fell back to a WRONG,
    non-byte-swapped parse (plain ``int(user_id, 16)``) for every other
    method, a value that was never matched against anything at all. A
    Frida-based capture of the Aqara app's own network traffic (2026-09-09)
    confirmed, on two independent credentials of different methods, that
    the correct decode is UNIVERSAL across every method: the whole 4-byte
    ``user_id``, read as a little-endian uint32. That value is exactly the
    same credential id the cloud roster calls ``typeValue`` -- see
    ``async_fetch_credential_names`` below, which now matches on that same
    field for every credential type, not just fingerprint/face.

    Reimplemented inline here (matches ``aqara_ble.access_log``'s
    ``decode_credential_id`` byte-for-byte) rather than importing it from
    the library: this integration cannot currently rely on a newer
    ``aqara_ble`` build being installed/importable wherever it actually
    runs, and importing a function that turns out to be missing there is
    exactly what broke a sibling integration on 2026-09-09. Keeping the
    decode local and dependency-free avoids repeating that failure.
    """
    user_id = getattr(entry, "user_id", None)
    if not user_id or len(user_id) < 8:
        return None
    try:
        return int.from_bytes(bytes.fromhex(user_id[0:8]), "little")
    except ValueError:
        return None


def _parse_last_unlock_event(entries: list) -> LastUnlockEvent | None:
    """Pick the newest access-log entry out of one read page and decode it.

    NOTE (2026-09-08): entries[0] used to be trusted blindly as "the newest"
    (aqara-ble's docs say SYNC_LOG index page 0..49 = the newest records). A
    live comparison against the Aqara app's own access-log screen showed
    this sensor stuck on a stale entry (a plain lock event) while the app
    already listed a newer credential-open event that should have long
    since been in range. Whatever the root cause (buffer ordering, a
    stale/misattributed BLE reply, ...), we no longer trust positional
    order at all -- pick the entry with the highest timestamp explicitly.
    An unparseable timestamp (0) sorts last automatically, so it's never
    picked over a real one.
    """
    if not entries:
        return None
    newest = max(entries, key=lambda e: e.timestamp)
    if _LOGGER.isEnabledFor(logging.DEBUG):
        _LOGGER.debug(
            "access-log page: %d entries, newest picked ts=%s attr=0x%02x "
            "user_id=%s (entries[0] was ts=%s attr=0x%02x user_id=%s)",
            len(entries), newest.timestamp, newest.raw_attr, newest.user_id,
            entries[0].timestamp, entries[0].raw_attr, entries[0].user_id,
        )
    for i, e in enumerate(entries):
        _LOGGER.debug(
            "  access-log[%02d] attr=0x%02x class=%s method=%s user_id=%s ts=%s",
            i, e.raw_attr, e.event_class, e.method, e.user_id, e.timestamp,
        )
    label = newest.method or newest.event_class
    if label == "face":
        # CONFIRMED 2026-09-18 via a live debug capture (same method as the
        # 2026-09-17 "matter" fix above): aqara_ble.access_log's
        # decode_lock_log_record() special-cases attr-hi 0x2 (which its own
        # METHOD_BY_HI table calls "fingerprint") into "face" whenever
        # user_id[4:8] != "0680". On this lock/firmware that check never
        # once matches: every confirmed real fingerprint credential-open
        # observed so far decodes to a user_id whose [4:8] slice is "0180",
        # not "0680" -- so the vendored heuristic always falls through to
        # "face", even for a plain fingerprint touch. This lock model has no
        # face-recognition hardware at all, and no "face" label has ever
        # corresponded to an actual face scan in testing, so -- exactly like
        # the "matter" case above -- we correct a heuristic that has been
        # live-disproven rather than propagate it. If a face-capable variant
        # of this lock is ever confirmed to hit this path for real, this
        # override needs to become conditional instead of unconditional.
        label = "fingerprint"
    slot = _resolve_credential_slot(newest)
    is_open = newest.event_class == "credential_open"
    if newest.method == "matter":
        # CONFIRMED 2026-09-17 via a live debug capture: every single
        # "matter" (attr
        # high-nibble 0xD) entry seen on this lock so far carries the
        # EXACT SAME fixed user_id (hex "00000007" -> decoded id 7) --
        # nothing like a real Aqara typeValue (every genuine personal
        # credential on this account decodes to a value around 2.1476
        # BILLION, ~9 orders of magnitude larger) -- and is always paired,
        # seconds apart, with a plain attr=0xD1 *lock_event* carrying that
        # SAME id. Cross-checked against this user's separate Matter lock
        # entity's own state history: no mechanical lock/unlock transition
        # exists at all around either occurrence's timestamp, even though
        # every confirmed real fingerprint/face open in the same log page
        # DOES line up with a Matter state change within a few seconds.
        # aqara_ble.access_log's own module docstring already flags every
        # METHOD_BY_HI entry beyond 0x0 ("ble") and 0x2 ("fingerprint"/
        # "face") as an unconfirmed guess -- "matter" (0xD) is one of them,
        # and this is now confirmed live to be wrong: it is NOT a real,
        # person-attributable unlock. Treating it as a non-open status
        # event (like a plain lock_event) instead of a credential open
        # avoids misleadingly showing an "Unzugeordnet (Slot 7)" that
        # implies some UNIDENTIFIED person did this -- nobody did; it is
        # a spurious/internal log pair, not an access.
        is_open = False
    return LastUnlockEvent(
        event_type=newest.raw_attr,
        label=label,
        credential_slot=slot,
        timestamp=newest.timestamp,
        is_credential_open=is_open,
    )


async def async_resolve_device_id(
    hass: HomeAssistant, config: Mapping[str, Any], *, mac: str | None = None
) -> str:
    """Resolve the lock's device id from the account (off the event loop).

    Lets the config flow avoid asking the user for a device id: it lists the
    account's devices and, when there is more than one, matches ``mac``. For
    a lock registered in Aqara's cloud as a Matter device (bridged via a
    hub), this "mac" field can come back as a non-BLE identifier and
    auto-resolution can fail even with one lock on the account — enter the
    Aqara device ID manually in that case (see README).
    """
    auth = build_cloud_auth(config)
    return await hass.async_add_executor_job(partial(auth.resolve_device_id, mac=mac))


class U200BleClientAdapter:
    """Adapt HA-managed Bluetooth connections to ``aqara-ble``, log-only."""

    def __init__(
        self,
        hass: HomeAssistant,
        bluetooth_manager: U200BleBluetoothManager,
        auth: CloudAuthManager,
        device_id: str,
        region: str,
        ltmk: bytes | None = None,
    ) -> None:
        """Initialize a stateless adapter for one config entry.

        ``ltmk`` (see CONF_LTMK in const.py), when known, is threaded into
        every BLE session so it derives OFFLINE -- no per-read cloud login.
        ``None`` falls back to the (slower, network-dependent) cloud-login
        path aqara-ble has always used. ``hass`` is only needed to run the
        cloud credential-name fetch (``async_fetch_credential_names``) off
        the event loop -- the BLE read path never touches it.
        """
        self._hass = hass
        self._bluetooth_manager = bluetooth_manager
        self._auth = auth
        self._device_id = device_id
        self._region = region
        self._ltmk = ltmk

    def set_ltmk(self, ltmk: bytes | None) -> None:
        """Apply a freshly-fetched LTMK to this already-running client.

        Used by the ``fetch_ltmk`` service (see __init__.py): once a guard
        code is used to pull the LTMK from the cloud, the result is applied
        here immediately so the very next BLE read already goes offline --
        no config-entry reload / HA restart needed. ``None`` reverts to the
        per-read cloud-login path.
        """
        self._ltmk = ltmk

    def auth_token_snapshot(self) -> tuple[str, str] | None:
        """See module-level ``auth_token_snapshot`` -- reads this adapter's
        own long-lived auth object (``None`` if it has no token cached
        yet)."""
        return auth_token_snapshot(self._auth)

    def apply_auth_token(self, token: str, user_id: str) -> None:
        """See module-level ``apply_auth_token_snapshot`` -- installs a
        token obtained elsewhere (e.g. a just-completed reauth validation,
        or one restored from disk) into this adapter's own long-lived auth
        object, so the next read reuses it instead of logging in again from
        scratch."""
        apply_auth_token_snapshot(self._auth, (token, user_id))

    async def async_read_snapshot(
        self,
    ) -> tuple[LastUnlockEvent | None, tuple[UserCredential, ...] | None]:
        """Read the access log (SYNC_LOG / 0x13), plus the user/credential
        table (SYNC_USER_ID_VALID_PERIOD / 0x1f) if the front panel happens
        to be awake -- both in the SAME BLE connection.

        Wraps ``aqara_ble``'s ``read_access_log(0, 49)`` (offline-capable
        since aqara-ble 1.13.0 -- the always-on back panel serves it, no
        keypad wake needed) and picks the newest entry out of the returned
        entries **by comparing timestamps explicitly** (see
        ``_parse_last_unlock_event`` above) rather than assuming
        ``entries[0]`` is already the newest -- a live comparison against
        the Aqara app's own log showed that assumption can go stale.

        CONFIRMED 2026-09-08: ``read_access_log`` now always requests whole,
        trailer-complete 30-record pages (a request missing the lock's
        required per-page trailer was silently answered with just the
        newest 30 records, no matter what range was asked for -- see
        ``aqara_ble.access_log``'s module docstring) -- so ``(0, 49)`` here
        actually covers the newest 60 records (two full pages) merged, not
        just the newest 30 as before.

        The user table is a bonus, best-effort extra read piggybacked on
        the SAME connection (no extra BLE connect/disconnect cycle -- see
        ``BLE_READ_ATTEMPTS``'s docstring on shared-adapter contention):
        ``read_front_connection()`` (GET_FRONT_CONNECTION / 0xdd) is a fast
        (~50ms), always-on-back-panel check, so it costs nothing extra when
        it -- as it usually does -- reports the front-panel keypad asleep.
        Only when it reports awake do we follow through with the slower
        table read; attempting the table read while the panel is asleep
        just times out after ~10s with nothing (confirmed live 2026-09-08,
        see Aqara-1.16.0/log.txt in this project). The panel is realistically
        only awake for a few seconds after someone has just physically
        touched the keypad/fingerprint sensor -- there's no confirmed BLE or
        cloud command that wakes it remotely on demand (docs/protocols/
        cloud-protocol.md §4.11's cloud wake-relay is unconfirmed/INFERRED
        and, per its own note, wakes the lock's BLE radio generally, not
        specifically this keypad panel) -- so this is a "catch it awake if
        we're lucky" read: touching the panel right before pressing the
        Refresh button (button.py) is the reliable way to actually get a
        fresh table. A failure in this bonus part never discards an
        already-successful access-log result from the same connection.
        """

        async def _reader(client: ProtocolU200Client):
            entries = await client.read_access_log(0, 49)
            event = _parse_last_unlock_event(entries)
            table: tuple[UserCredential, ...] | None = None
            try:
                awake = await client.read_front_connection()
                if awake:
                    table = tuple(await client.read_user_table())
                    _LOGGER.debug(
                        "user table: front panel awake, read %d credential(s)",
                        len(table),
                    )
            except asyncio.CancelledError:
                raise
            except Exception as err:  # noqa: BLE001 - best-effort bonus read
                _LOGGER.debug(
                    "user-table opportunistic read failed (%s); keeping the "
                    "access-log result from this same connection",
                    type(err).__name__,
                )
            return event, table

        result = await self._async_read_retry(
            _reader,
            is_useful=lambda value: value is not None and value[0] is not None,
        )
        if result is None:
            return None, None
        return result

    async def async_fetch_credential_names(self) -> dict[str, str]:
        """Fetch {credential_id: person name} from the Aqara cloud -- no BLE.

        Wraps ``CloudAuthManager.fetch_lock_credentials`` (``GET
        /dev/lock/query``, see aqara_ble.kdf.LockCredential): the SAME cloud
        table the Aqara app's own "Benutzerverwaltung" (user management)
        screen shows -- the BLE SYNC_LOG protocol itself never carries a
        name, only a numeric credential id.

        2026-09-10 UPDATE: this
        used to key on the cloud's ``userCode`` field and only cover
        fingerprint/face rows (``type`` 1 or 6) -- every other credential
        type had no confirmed BLE-side match and was skipped entirely. A
        2026-09-09 network capture confirmed that ``typeValue`` (not
        ``userCode``) is the field matching ``_resolve_credential_slot``'s
        decode, and that this holds for EVERY credential type, not just
        fingerprint/face -- so this now keys on ``type_value`` and no
        longer filters by type.
        """
        rows = await async_fetch_lock_credentials(self._hass, self._auth, self._device_id)
        names: dict[str, str] = {}
        for row in rows:
            if not row.type_value.isdigit():
                continue
            names[str(int(row.type_value))] = row.group_name
        return names

    async def _async_read_retry(
        self,
        reader: Callable[[ProtocolU200Client], Awaitable[Any]],
        *,
        is_useful: Callable[[Any], bool] = lambda value: value is not None,
    ) -> Any:
        """Run one read, retrying while the result isn't useful.

        HA's Bluetooth proxy occasionally drops the lock's notify response, so a
        read times out and returns None even though the next attempt succeeds.
        Retry up to ``BLE_READ_ATTEMPTS`` times, spacing attempts by the reconnect
        gap. Auth failures propagate immediately (no point retrying bad creds).
        """
        value = None
        for attempt in range(BLE_READ_ATTEMPTS):
            value = await self._async_one_read(reader)
            if is_useful(value):
                return value
            if attempt < BLE_READ_ATTEMPTS - 1:
                await asyncio.sleep(BLE_READ_GAP_SECONDS)
        return value

    async def _async_one_read(
        self, reader: Callable[[ProtocolU200Client], Awaitable[Any]]
    ) -> Any:
        """Open one BLE session, run ``reader(protocol_client)``, release.

        Best-effort: returns None on connect/read failure; auth failures propagate
        so the coordinator can trigger reauth.
        """
        ble_device = self._bluetooth_manager.async_get_ble_device()
        if ble_device is None:
            # Same live check the coordinator's own gate uses (see
            # coordinator.py's async_refresh_log) -- log here too since this
            # adapter can also be reached with a stale/absent cached
            # reachable flag, and this return used to be silent.
            _LOGGER.debug(
                "U200 BLE read skipped: lock not currently resolvable via "
                "any connectable Bluetooth adapter/proxy"
            )
            return None
        bleak_client: BleakClientWithServiceCache | None = None
        try:
            bleak_client = await establish_connection(
                BleakClientWithServiceCache,
                ble_device,
                _CONNECTION_NAME,
                ble_device_callback=lambda: (
                    self._bluetooth_manager.async_get_ble_device() or ble_device
                ),
            )
            protocol_client = ProtocolU200Client.from_gatt(
                auth=self._auth,
                gatt_client=bleak_client,
                device_id=self._device_id,
                region=self._region,
                ltmk=self._ltmk,
            )
            return await reader(protocol_client)
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001
            if is_invalid_auth_error(err) or (
                isinstance(err, U200ClientError) and err.phase is FlowPhase.LOGIN
            ):
                raise U200BleAuthenticationError(
                    "Aqara rejected the configured credentials"
                ) from err
            # Safe to log in full: at this point it can only come from
            # establish_connection() (bleak/BlueZ-level connect failure) or
            # from_gatt()'s own setup, never from inside an authenticated
            # protocol exchange — no session material or BLE payload bytes
            # are in scope yet.
            _LOGGER.debug("U200 BLE read failed (%s): %s", type(err).__name__, err)
            return None
        finally:
            if bleak_client is not None:
                try:
                    async with asyncio.timeout(_DISCONNECT_TIMEOUT):
                        await bleak_client.disconnect()
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
