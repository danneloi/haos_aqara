"""Cloud voice-pack listing + CDN download for the U200 language OTA.

The library already STREAMS a voice pack to the lock
(:func:`aqara_ble.ota.run_voice_pack_ota` /
:meth:`aqara_ble.client.U200Client.push_voice_pack_ota`). This module gets the
pack in the FIRST place — the same cloud + public-CDN path the official app uses,
phone-free:

  1. ``GET /app/dev/voice/list?did=<did>`` (signed) → one row per language, each
     carrying a public CDN ``url`` and a ``fileInfo`` ``[{fileName, md5}]``.
  2. ``GET <url>/<fileName>`` from the CDN (no auth) → the ``.bin`` bytes,
     verified against the row's md5.

Together with ``push_voice_pack_ota`` this makes an end-to-end, one-call
language change (see :meth:`U200Client.change_language`), with no captured
frames and no phone.
"""
from __future__ import annotations

import hashlib
import json
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

#: Signed cloud endpoint that lists the account's downloadable voice packs.
VOICE_LIST_PATH = "/app/dev/voice/list"

#: A cloud request signer: ``signer(path_rel, query_or_body) -> headers mapping``
#: (the same shape :meth:`aqara_ble.auth.CloudAuthManager.build_signer` returns).
Signer = Callable[[str, str], "dict[str, str]"]


@dataclass(frozen=True)
class VoicePackInfo:
    """One downloadable language voice pack, as the cloud describes it."""

    lang: str  #: cloud language code (e.g. "13" for Français), as a string
    name: str  #: display name if the row carries one (may be "")
    file_name: str  #: e.g. "U200_ES_audio_burn.bin"
    md5: str  #: lowercase hex md5 of the .bin, for verification
    url: str  #: asset base URL; the download is ``url + "/" + file_name``

    @property
    def download_url(self) -> str:
        return self.url.rstrip("/") + "/" + self.file_name


def _signed_get(base_url: str, path: str, query: str, signer: Signer, timeout: float) -> dict[str, Any]:
    # For GETs the Aqara sign preimage puts the raw query string in the body
    # position; the same string also rides on the URL.
    headers = {
        str(k): str(v)
        for k, v in dict(signer(path, query)).items()
        if str(k).lower() not in ("host", "content-length")
    }
    headers.setdefault("Accept", "application/json")
    headers["Accept-Encoding"] = "identity"
    url = base_url + path + (f"?{query}" if query else "")
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def parse_voice_list(payload: dict[str, Any]) -> list[VoicePackInfo]:
    """Parse a ``/app/dev/voice/list`` response body into :class:`VoicePackInfo`
    rows. Pure (no I/O) so it is unit-testable against a captured fixture.

    Tolerates the two shapes seen live: ``result`` as a bare list, or wrapped in
    ``{list|voiceList|langList|data|items: [...]}``; and ``fileInfo`` as either a
    real list or a JSON-encoded string of one.
    """
    if payload.get("code") not in (0, None):
        raise RuntimeError(f"voice/list code={payload.get('code')}: {payload.get('message')}")
    result = payload.get("result")
    rows: Any = result if isinstance(result, list) else None
    if rows is None and isinstance(result, dict):
        for key in ("list", "voiceList", "langList", "data", "items"):
            if isinstance(result.get(key), list):
                rows = result[key]
                break
    out: list[VoicePackInfo] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        file_info = row.get("fileInfo")
        if isinstance(file_info, str):
            try:
                file_info = json.loads(file_info)
            except ValueError:
                continue
        # ``fileInfo`` is usually a list of {fileName, md5}; occasionally a dict
        # wrapping that list under "fileInfo"/"files".
        files = file_info
        if isinstance(file_info, dict):
            files = file_info.get("fileInfo") or file_info.get("files")
        if not isinstance(files, list) or not files or not isinstance(files[0], dict):
            continue
        f0 = files[0]
        out.append(
            VoicePackInfo(
                lang=str(row.get("lang") or row.get("language") or row.get("langCode")
                         or row.get("code") or ""),
                name=str(row.get("name") or ""),
                file_name=str(f0.get("fileName") or ""),
                md5=str(f0.get("md5") or "").lower(),
                url=str(row.get("url") or (file_info.get("url") if isinstance(file_info, dict) else "")),
            )
        )
    return out


def cloud_get_voice_list(
    device_id: str, base_url: str, signer: Signer, *, timeout: float = 15.0
) -> list[VoicePackInfo]:
    """Fetch and parse the account's downloadable voice packs for ``device_id``.

    ``base_url`` is a region base (``aqara_ble.kdf.REGION_BASE_URLS``); ``signer``
    is ``CloudAuthManager.build_signer()``. Only the bare ``did=`` query returns
    ``code=0`` (verified live 2026-09-02) — do not add ``model=``.
    """
    payload = _signed_get(base_url, VOICE_LIST_PATH, f"did={device_id}", signer, timeout)
    return parse_voice_list(payload)


def download_voice_pack(info: VoicePackInfo, *, verify: bool = True, timeout: float = 120.0) -> bytes:
    """Download a voice pack's ``.bin`` from the public CDN and (by default) verify
    it against ``info.md5``. Raises on an md5 mismatch."""
    with urllib.request.urlopen(info.download_url, timeout=timeout) as resp:
        blob = resp.read()
    if verify and info.md5 and hashlib.md5(blob).hexdigest() != info.md5:
        raise RuntimeError(
            f"downloaded {info.file_name} md5 {hashlib.md5(blob).hexdigest()} != expected {info.md5}"
        )
    return blob


def select_voice_pack(rows: list[VoicePackInfo], language: str) -> VoicePackInfo:
    """Pick the row for ``language`` — matched against the cloud ``lang`` code, the
    display ``name``, or the file name's ``_<CODE>_`` segment (case-insensitive),
    so callers can say "ES", "Español", or "13". Raises if none/ambiguous."""
    want = language.strip().lower()
    hits = [
        r for r in rows
        if want in (r.lang.lower(), r.name.lower())
        or f"_{want}_" in r.file_name.lower()
    ]
    if not hits:
        avail = ", ".join(sorted({r.file_name for r in rows}))
        raise LookupError(f"no voice pack for {language!r}; available: {avail}")
    if len({r.file_name for r in hits}) > 1:
        raise LookupError(f"ambiguous language {language!r}: {[r.file_name for r in hits]}")
    return hits[0]
