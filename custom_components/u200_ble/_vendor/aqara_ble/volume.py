"""Observed voice-volume control helpers.

This module intentionally separates two concerns:

1. Building the control request structure we already observed on the wire.
2. Sending those bytes through a caller-provided authenticated transport.

The session-specific KDF and control authentication are still unresolved, so
the transport must be supplied by a higher layer that already knows how to
write to the lock.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .protocol import ControlRequest


class VoiceVolumePreset(str, Enum):
    MEDIUM = "medium"
    HIGH = "high"


def normalize_voice_volume_preset(preset: VoiceVolumePreset | str) -> VoiceVolumePreset:
    if isinstance(preset, VoiceVolumePreset):
        return preset

    normalized = preset.strip().lower()
    if normalized in {"medium", "medio"}:
        return VoiceVolumePreset.MEDIUM
    if normalized in {"high", "alto"}:
        return VoiceVolumePreset.HIGH
    raise ValueError(f"preset no soportado: {preset}")


@dataclass(frozen=True)
class VoiceVolumeWrite:
    preset: VoiceVolumePreset
    request: ControlRequest

    @property
    def bytes(self) -> bytes:
        return self.request.as_bytes()


_VOICE_VOLUME_REQUESTS: dict[VoiceVolumePreset, ControlRequest] = {
    VoiceVolumePreset.MEDIUM: ControlRequest(
        kind=0x01,
        command=0xD3,
        body=bytes.fromhex("02d13e15"),
        trailer=bytes.fromhex("d5fddfe4"),
    ),
    VoiceVolumePreset.HIGH: ControlRequest(
        kind=0x01,
        command=0xD3,
        body=bytes.fromhex("02d23e16"),
        trailer=bytes.fromhex("5faddd09"),
    ),
}


class ControlWriteTransport(Protocol):
    def write(self, payload: bytes) -> None:
        """Send raw authenticated control bytes to the lock."""


def build_voice_volume_write(preset: VoiceVolumePreset | str) -> VoiceVolumeWrite:
    normalized = normalize_voice_volume_preset(preset)
    try:
        request = _VOICE_VOLUME_REQUESTS[normalized]
    except KeyError as exc:
        raise ValueError(f"preset no soportado: {preset}") from exc
    return VoiceVolumeWrite(preset=normalized, request=request)


def write_voice_volume(
    transport: ControlWriteTransport,
    preset: VoiceVolumePreset | str,
) -> VoiceVolumeWrite:
    """Write the observed voice-volume control request via an authenticated transport."""

    write = build_voice_volume_write(preset)
    transport.write(write.bytes)
    return write


def set_voice_volume(
    transport: ControlWriteTransport,
    level: VoiceVolumePreset | str,
) -> VoiceVolumeWrite:
    """User-facing alias for changing the lock voice/alert volume."""

    return write_voice_volume(transport, level)
