"""Integration-owned exceptions for U200 BLE."""


class U200BleError(Exception):
    """Base exception for the integration runtime boundary."""


class U200BleBluetoothUnavailableError(U200BleError):
    """Raised when no connectable Home Assistant Bluetooth path can reach the lock."""


class U200BleAuthenticationError(U200BleError):
    """Raised when Aqara rejects the configured cloud credentials."""
