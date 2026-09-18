"""BLE scanning and identification of the Aqara U200 (feature 015).

`identify_candidate` (in `transport.py`) classifies one advertisement; this
module adds the two things the facade needs on top of a transport:

- `scan(transport, timeout, mac=…)` — ask the radio to scan and get back the
  `ScanCandidate`s sorted best-first (score, then RSSI).
- `select_preferred(candidates, mac=…)` — pick the lock, or refuse: a device
  that only shares Aqara's manufacturer id is never chosen automatically (a
  real false positive was seen on 2026-08-17), and a tie between equally good
  candidates without a MAC raises `AmbiguousDeviceError` with the list.

The old print-only scanner is gone; `examples/lock_cli.py scan` prints these
results instead. The U200 advertises only after its keypad has been touched.
"""

from __future__ import annotations

from .errors import AmbiguousDeviceError, NoDeviceFoundError
from .transport import (
    AQARA_COMPANY_ID,
    DEFAULT_SCAN_TIMEOUT,
    EXPECTED_NAME,
    ScanCandidate,
    Transport,
    identify_candidate,
    normalize_mac,
)

__all__ = [
    "AQARA_COMPANY_ID",
    "EXPECTED_NAME",
    "identify_candidate",
    "scan",
    "select_preferred",
]

_KEYPAD_HINT = (
    "la U200 solo anuncia tras activar físicamente su teclado; tócalo y vuelve a escanear."
)


async def scan(
    transport: Transport,
    timeout: float = DEFAULT_SCAN_TIMEOUT,
    *,
    mac: str | None = None,
) -> list[ScanCandidate]:
    """Scan with ``transport`` and return U200 candidates, best first."""

    candidates = await transport.scan(timeout, mac=mac)
    return sorted(candidates, key=ScanCandidate.sort_key, reverse=True)


def select_preferred(candidates: list[ScanCandidate], *, mac: str | None = None) -> ScanCandidate:
    """Choose the lock among ``candidates`` (see module docstring for the rules)."""

    pool = list(candidates)
    if mac is not None:
        wanted = normalize_mac(mac)
        pool = [c for c in pool if normalize_mac(c.address) == wanted]
        if not pool:
            raise NoDeviceFoundError(
                f"ningún candidato con MAC {wanted}; {_KEYPAD_HINT}", seen=candidates
            )
    if not pool:
        raise NoDeviceFoundError(f"ningún candidato U200 en el escaneo; {_KEYPAD_HINT}")
    preferred = [c for c in pool if c.is_preferred]
    if not preferred:
        raise NoDeviceFoundError(
            "solo se vieron dispositivos que comparten el fabricante 0x0B27 (sin nombre "
            f"'{EXPECTED_NAME}' ni servicios U200); no se conecta a ciegas — indica `mac=` "
            f"si de verdad es tu cerradura. {_KEYPAD_HINT}",
            seen=candidates,
        )
    preferred.sort(key=ScanCandidate.sort_key, reverse=True)
    best = preferred[0]
    ties = [c for c in preferred if c.score == best.score and c.address != best.address]
    if ties and mac is None:
        raise AmbiguousDeviceError([best, *ties])
    return best
