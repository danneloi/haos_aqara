"""Facade errors and flow phases (feature 015).

Kept in their own module so `scanner.py` (which raises the scan errors) and
`client.py` (which raises the rest) do not import each other circularly. The
public names are re-exported from `aqara_ble`.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .transport import ScanCandidate


class FlowPhase(str, Enum):
    """Where in the flow something happened (used to bound and label errors)."""

    LOGIN = "login"
    SCAN = "scan"
    CONNECT = "connect"
    DISCOVER = "discover"
    OPERATION = "operation"
    DISCONNECT = "disconnect"


class U200ClientError(RuntimeError):
    """A phase of the facade flow failed. The original error is ``__cause__``."""

    def __init__(self, phase: FlowPhase, message: str) -> None:
        super().__init__(f"[{phase.value}] {message}")
        self.phase = phase


class NoDeviceFoundError(U200ClientError):
    """The scan found no acceptable U200 candidate."""

    def __init__(self, message: str, *, seen: list[ScanCandidate] | None = None) -> None:
        super().__init__(FlowPhase.SCAN, message)
        self.seen: list[ScanCandidate] = list(seen or [])


class AmbiguousDeviceError(U200ClientError):
    """Several equally good candidates and no MAC to pick one."""

    def __init__(self, candidates: list[ScanCandidate]) -> None:
        super().__init__(
            FlowPhase.SCAN,
            f"{len(candidates)} candidatos igual de buenos; indica `mac=` para elegir: "
            + ", ".join(f"{c.address} ({','.join(sorted(c.reasons))})" for c in candidates),
        )
        self.candidates = candidates


__all__ = ["AmbiguousDeviceError", "FlowPhase", "NoDeviceFoundError", "U200ClientError"]
