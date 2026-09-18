"""
Automatic token management for cloud authentication.

Handles login, token refresh on 108 errors, and transparent credential loading.
"""

from __future__ import annotations

import logging
from typing import Any

from .app_constants import APP_ID, APP_KEY, generate_client_id, generate_phone_id
from .cloud_crypto import Signer, make_local_signer
from .errors import FlowPhase, NoDeviceFoundError, U200ClientError
from .kdf import (
    REGION_BASE_URLS,
    CloudServiceError,
    LockCredential,
    cloud_device_mac,
    cloud_list_devices,
    fetch_lock_credentials,
    fetch_ltmk,
    login,
)


def _mac_forms(mac: str) -> set[str]:
    """Return comparable forms of a MAC (bare hex + byte-reversed) for matching."""
    hexed = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    reversed_bytes = "".join(
        hexed[i : i + 2] for i in range(len(hexed) - 2, -2, -2) if hexed[i : i + 2]
    )
    return {hexed, reversed_bytes}

logger = logging.getLogger(__name__)


class CloudAuthManager:
    """Manages Aqara cloud authentication with automatic token refresh.

    Features:
    - Load credentials from environment or .env files
    - Automatic login with account/password (no manual token required)
    - Transparent token refresh on expiration (code 108)
    - Thread-safe caching of valid tokens
    """

    def __init__(
        self,
        *,
        account: str,
        password: str,
        appid: str | None = None,
        appkey: str | None = None,
        client_id: str | None = None,
        phone_id: str | None = None,
        region: str = "EU",
        district: str = "ES",
        guard_code: str = "",
    ) -> None:
        """Initialize auth manager with account credentials.

        Only ``account`` and ``password`` are required. The app-global ``appid``/
        ``appkey`` default to the baked constants and ``client_id``/``phone_id``
        are generated per install (see ``app_constants``), so a consumer never has
        to supply values a user cannot obtain. Any of them may still be passed
        explicitly (e.g. from a captured app session) to override the defaults.

        Args:
            account: Aqara account (email or phone)
            password: Aqara account password
            appid: Aqara app ID (defaults to the app-global constant)
            appkey: Aqara app key (defaults to the app-global constant)
            client_id: FCM client ID (generated if omitted)
            phone_id: Device phone ID (generated if omitted)
            region: Aqara region (EU, CN, etc.)
            district: Aqara district (ES, CN, etc.)
            guard_code: short-lived (~30s) dynamic/temporary code the cloud
                sometimes demands (codes 855/854 -- observed live 2026-09,
                the ``/dev/bluetooth/query`` LTMK fetch in particular seems to
                always require one, even when ordinary logins do not). Empty
                for logins that don't need one. Restored 2026-09-07 after
                being dropped from this constructor in the 1.11 offline-
                session refactor; ``kdf.login()`` itself always supported it.
        """
        self.account = account
        self.password = password
        self.appid = appid or APP_ID
        self.appkey = appkey or APP_KEY
        self.client_id = client_id or generate_client_id()
        self.phone_id = phone_id or generate_phone_id()
        self.region = region
        self.district = district
        self.guard_code = guard_code

        self._token: str | None = None
        self._user_id: str | None = None

    def _login(self) -> tuple[str, str]:
        """Perform login and return (token, user_id).

        A ``code 810`` (wrong password / unregistered account) is translated into
        a clear, **non-retryable** error so the caller never loops on it — it is
        not a token expiry. No credential is logged.
        """
        logger.debug("cloud login: starting")
        try:
            result = login(
                self.account,
                self.password,
                appid=self.appid,
                appkey=self.appkey,
                client_id=self.client_id,
                phone_id=self.phone_id,
                region=self.region,
                district=self.district,
                guard_code=self.guard_code,
            )
        except CloudServiceError as exc:
            if exc.is_code(810):
                raise RuntimeError(
                    "Aqara login rejected the credentials (code 810): wrong "
                    "password, or the account is not registered in this region. "
                    "This is not a token expiry and is not retried."
                ) from exc
            raise
        token = result.get("token")
        user_id = result.get("userId") or result.get("uid")
        if not token:
            raise RuntimeError(f"Login failed: no token in result {sorted(result)}")
        logger.debug("cloud login: succeeded")
        return token, user_id or ""

    def build_signer(self, *, force_refresh: bool = False) -> Signer:
        """Build a cloud request signer bound to a valid token (logging in if
        needed). Used by the operation flow to sign cloud calls and to rebuild
        the signer after a token refresh."""
        token = self.get_token(force_refresh=force_refresh)
        return make_local_signer(
            appid=self.appid,
            appkey=self.appkey,
            token=token,
            user_id=self._user_id or "",
            client_id=self.client_id,
            phone_id=self.phone_id,
            area=self.region,
        )

    def get_token(self, *, force_refresh: bool = False) -> str:
        """Get valid token, logging in if needed.

        Args:
            force_refresh: Force new login even if cached token exists

        Returns:
            Valid JWT token for cloud API calls
        """
        if self._token and not force_refresh:
            return self._token

        token, user_id = self._login()
        self._token = token
        self._user_id = user_id
        return token

    def handle_expired_token(self) -> str:
        """Handle a ``code=108`` (token expired) by forcing a fresh login.

        Returns:
            New valid token
        """
        logger.debug("cloud token: refreshing (expired)")
        return self.get_token(force_refresh=True)

    def list_devices(self) -> list[dict[str, Any]]:
        """List the devices registered on this Aqara account (logs in if needed).

        Each dict carries ``deviceId`` (the ``matt.<...>`` DID the BLE flow needs),
        ``model``, ``name``, etc. Blocking HTTP — call via a worker thread on an
        event loop.
        """
        signer = self.build_signer()
        base = REGION_BASE_URLS.get(self.region, REGION_BASE_URLS["EU"])
        return cloud_list_devices(None, base, signer=signer)

    def fetch_ltmk(self, device_id: str) -> bytes:
        """Fetch the lock's LTMK (long-term master key) from the cloud.

        The LTMK lets the BLE control channel derive session keys OFFLINE (no
        per-operation cloud round-trip). This is a one-time cloud read of the
        owner's own device credential; cache the result and pass it to
        ``U200Client`` (``ltmk=``) to run cloud-free. Blocking HTTP — call via a
        worker thread on an event loop.
        """
        signer = self.build_signer()
        base = REGION_BASE_URLS.get(self.region, REGION_BASE_URLS["EU"])
        return fetch_ltmk(device_id, None, base, signer=signer)

    def fetch_lock_credentials(self, device_id: str) -> tuple[LockCredential, ...]:
        """Fetch the lock's cloud-side credential table (users, passwords,
        fingerprints, NFC) -- ``GET /dev/lock/query``, no BLE, no keypad.

        Each row's ``group_name`` is a real person's display name as set in
        the Aqara app -- treat it as sensitive (see ``LockCredential`` in
        kdf.py). Blocking HTTP -- call via a worker thread on an event loop.
        """
        signer = self.build_signer()
        base = REGION_BASE_URLS.get(self.region, REGION_BASE_URLS["EU"])
        return fetch_lock_credentials(device_id, None, base, signer=signer)

    def resolve_device_id(self, *, mac: str | None = None) -> str:
        """Resolve the lock's device id from the account — no manual id needed.

        A single registered device is returned directly; with several, the given
        BLE ``mac`` is matched against each device's cloud MAC. This is what lets a
        consumer configure with only an account + password. Blocking HTTP.
        """
        devices = self.list_devices()
        ids = [str(d["deviceId"]) for d in devices if d.get("deviceId")]
        if not ids:
            raise NoDeviceFoundError("no devices registered on this Aqara account")
        if len(ids) == 1:
            return ids[0]
        if mac:
            signer = self.build_signer()
            base = REGION_BASE_URLS.get(self.region, REGION_BASE_URLS["EU"])
            target = _mac_forms(mac)
            for did in ids:
                try:
                    device_mac = cloud_device_mac(did, None, base, signer=signer)
                except Exception:
                    continue
                if device_mac and target & _mac_forms(device_mac):
                    return did
        raise U200ClientError(
            FlowPhase.LOGIN,
            f"{len(ids)} devices on this account; a MAC is needed to pick the lock",
        )

    # NOTE: environment-based construction lives OUTSIDE the library, in
    # examples/auth_from_env.py (Feature 014). The library never reads the
    # environment: the consumer (e.g. Home Assistant) injects credentials.
