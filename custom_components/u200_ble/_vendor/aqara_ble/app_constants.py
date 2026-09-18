"""Aqara Home app-global client constants.

``APP_ID`` / ``APP_KEY`` are the Aqara Home app's API client credentials — the
**same for every install** (trivially extractable from the app; ``APP_KEY`` is the
fixed AES-128-GCM body key that the server also holds, so it cannot be per-user).
They are baked here so a consumer authenticates with only an **account +
password** — never asking the user for values they cannot obtain.

``phone_id`` / ``client_id`` are per-install identifiers the app generates on first
run. The cloud accepts arbitrary values (they are plain headers, not part of the
request signature — confirmed live), so we generate them instead of asking.
"""

from __future__ import annotations

import uuid

#: Aqara Home app id (app-global, not a user secret).
APP_ID = "444c476ef7135e53330f46e7"
#: Aqara Home app key (app-global AES-128-GCM body key; not a user secret).
APP_KEY = "uOJy0qmKwXj6aHUB2KQEIJuXHMDVTAJi"


def generate_phone_id() -> str:
    """Return a fresh per-install phone id (32 hex chars, like the app)."""
    return uuid.uuid4().hex


def generate_client_id() -> str:
    """Return a fresh per-install FCM-style client id (64 hex chars)."""
    return uuid.uuid4().hex + uuid.uuid4().hex
