# Vendored copy of aqara_ble, bundled so this integration needs no external
# pip package. This integration's protocol library is maintained in a
# separate, private repository, so a manifest.json requirements URL/PyPI
# publish is not available; vendoring avoids that entirely and survives
# any HA container rebuild without a manual pip install step.
"""Autonomous BLE control for the Aqara U200 smart lock.

Pure-Python reimplementation of the cloud KDF, the BLE authentication
handshake (frames ``0610``/``0710``) and the AES-CCM control channel. See
``docs/`` for the reverse-engineered protocol.

This package is assembled incrementally, one Spec Kit feature at a time. The
recommended entry point is the **feature 015 facade**: ``U200Client`` +
a ``Transport`` (``BleakTransport`` for the host radio, ``BumbleTransport`` for
an external ESP32-S3 HCI controller) + ``CloudAuthManager`` (account login with
automatic token refresh). The lower-level pieces (KDF, framing, session flow,
operations catalogue) remain public for advanced consumers.
"""

from __future__ import annotations


from .access_log import (
    SYNC_LOG_EVENT_LABELS,
    AccessLogEntry,
    SyncLogRecord,
    build_access_log_frame,
    decode_access_log,
    decode_credential_id,
    decode_lock_log_record,
    decode_sync_log_credential_slot,
    decode_sync_log_event_label,
    sync_log_record_from_entry,
)
from .auth import CloudAuthManager
from .bumble_transport import BumbleGattAdapter
from .client import OperationResult, U200Client
from .cloud_crypto import (
    aes128gcm_decrypt_body,
    aes128gcm_encrypt_body,
    compute_nonce,
    compute_sign,
    encrypt_login_password,
    hkdf_expand,
    hkdf_extract,
    hkdf_sha256,
    make_local_signer,
)
from .control_codec import decrypt_control_payload, encrypt_control_payload
from .enrol import SOURCE_TYPES, EnrolReport, decode_enrol_report
from .errors import AmbiguousDeviceError, FlowPhase, NoDeviceFoundError, U200ClientError
from .framing import (
    assemble_auth_fragments,
    build_auth_message,
    crc16_aqara,
    fragment_auth_message,
    parse_auth_message,
)
from .gatt import GattClient
from .gatt_uuids import (
    AUTH_NOTIFY_UUID,
    AUTH_SERVICE_UUID,
    AUTH_WRITE_UUID,
    AUX_NOTIFY_UUID,
    AUX_SERVICE_UUID,
    CONTROL_NOTIFY2_UUID,
    CONTROL_NOTIFY_UUID,
    CONTROL_SERVICE_UUID,
    CONTROL_WRITE_UUID,
    GATT_CACHING_PREAMBLE_UUID16,
    PRE_AUTH_NOTIFY_ORDER,
    U200_SERVICE_UUIDS,
)
from .kdf import (
    CloudServiceError,
    LockCredential,
    OfflinePasswordBatch,
    OfflinePasswordLogEntry,
    build_cloud_auth_headers,
    cloud_device_mac,
    cloud_get_public_key,
    cloud_list_devices,
    cloud_verify,
    fetch_lock_credentials,
    fetch_ltmk,
    fetch_offline_password_log,
    fetch_offline_passwords,
    get_session_material,
    login,
    prepare_runtime_cloud_auth_headers,
)
from .lock_ops import (
    LockOperation,
    LockOperationWrite,
    build_abort_enrol,
    build_add_visitor_password,
    build_control_frame,
    build_control_query_write,
    build_delete_user,
    build_lock_operation_write,
    build_operate_frame,
    build_set_alarm_volume,
    build_set_alert_delay,
    build_set_alert_volume,
    build_set_auto_lock_on_close_delay_time,
    build_set_auto_lockup_delay_time,
    build_set_auxiliary_locking_on_close_enabled,
    build_set_auxiliary_locking_relock_enabled,
    build_set_language_deutsch,
    build_set_language_english,
    build_set_verify_fail_time,
    build_start_enrol,
    normalize_lock_operation,
    send_lock_operation,
)
from .lock_state import (
    LockEvent,
    LockSettings,
    LockState,
    decode_alarm_volume,
    decode_alert_volume,
    decode_event,
    decode_front_connection,
    decode_language,
    decode_lock_state,
    decode_lock_volume,
)
from .models import MODEL_BY_PRODUCT_ID, decode_manufacturer_payload
from .offline_login import derive_session_material, generate_ephemeral
from .operations_catalog import (
    OPERATIONS_CATALOG,
    CommandFamily,
    OperationEntry,
    OperationStatus,
    find_operation,
    operations_in_family,
)
from .ota_language import (
    build_ota_control_frame,
    build_ota_file_info,
    build_ota_init_frame,
    build_ota_manifest_json,
    crc16_mijia,
    crc16_xmodem,
    frame_data_block,
    iter_data_frames,
    iter_ota_data_writes,
    ota_decrypt,
    ota_encrypt,
)
from .protocol import (
    ControlRequest,
    control_command_name,
    parse_control_request,
    valid_crc,
)
from .scanner import identify_candidate, scan, select_preferred
from .session import (
    OperationInProgressError,
    SessionMaterial,
    run_authenticated_lock_operation,
)
from .transport import (
    AQARA_COMPANY_ID,
    EXPECTED_NAME,
    BleakTransport,
    BumbleTransport,
    ScanCandidate,
    Transport,
)
from .user_table import (
    CREDENTIAL_TYPES,
    USER_TABLE_FRAME,
    UserCredential,
    decode_user_table,
)
from .voice_ota import (
    VoicePackInfo,
    cloud_get_voice_list,
    download_voice_pack,
    parse_voice_list,
    select_voice_pack,
)
from .volume import (
    VoiceVolumePreset,
    VoiceVolumeWrite,
    build_voice_volume_write,
    normalize_voice_volume_preset,
    set_voice_volume,
    write_voice_volume,
)

# Vendored copy: not pip-installed under this name, so
# importlib.metadata.version("aqara-ble") would report whatever unrelated
# aqara-ble install (if any) happens to sit in the same environment, not
# this bundled source tree. Hardcode instead -- bump this string by hand
# whenever the vendored copy is refreshed from ~/Desktop/Aqara.
__version__ = "1.17.0+vendored"

__all__ = [
    "AQARA_COMPANY_ID",
    "AUTH_NOTIFY_UUID",
    "AUTH_SERVICE_UUID",
    "AUTH_WRITE_UUID",
    "AUX_NOTIFY_UUID",
    "AUX_SERVICE_UUID",
    "CONTROL_NOTIFY2_UUID",
    "CONTROL_NOTIFY_UUID",
    "CONTROL_SERVICE_UUID",
    "CONTROL_WRITE_UUID",
    "CREDENTIAL_TYPES",
    "EXPECTED_NAME",
    "GATT_CACHING_PREAMBLE_UUID16",
    "MODEL_BY_PRODUCT_ID",
    "OPERATIONS_CATALOG",
    "PRE_AUTH_NOTIFY_ORDER",
    "SOURCE_TYPES",
    "SYNC_LOG_EVENT_LABELS",
    "U200_SERVICE_UUIDS",
    "USER_TABLE_FRAME",
    "AccessLogEntry",
    "AmbiguousDeviceError",
    "BleakTransport",
    "BumbleGattAdapter",
    "BumbleTransport",
    "CloudAuthManager",
    "CloudServiceError",
    "CommandFamily",
    "ControlRequest",
    "EnrolReport",
    "FlowPhase",
    "GattClient",
    "LockCredential",
    "LockEvent",
    "LockOperation",
    "LockOperationWrite",
    "LockSettings",
    "LockState",
    "NoDeviceFoundError",
    "OfflinePasswordBatch",
    "OfflinePasswordLogEntry",
    "OperationEntry",
    "OperationInProgressError",
    "OperationResult",
    "OperationStatus",
    "ScanCandidate",
    "SessionMaterial",
    "SyncLogRecord",
    "Transport",
    "U200Client",
    "U200ClientError",
    "UserCredential",
    "VoicePackInfo",
    "VoiceVolumePreset",
    "VoiceVolumeWrite",
    "__version__",
    "aes128gcm_decrypt_body",
    "aes128gcm_encrypt_body",
    "assemble_auth_fragments",
    "build_abort_enrol",
    "build_access_log_frame",
    "build_add_visitor_password",
    "build_auth_message",
    "build_cloud_auth_headers",
    "build_control_frame",
    "build_control_query_write",
    "build_delete_user",
    "build_lock_operation_write",
    "build_operate_frame",
    "build_ota_control_frame",
    "build_ota_file_info",
    "build_ota_init_frame",
    "build_ota_manifest_json",
    "build_set_alarm_volume",
    "build_set_alert_delay",
    "build_set_alert_volume",
    "build_set_auto_lock_on_close_delay_time",
    "build_set_auto_lockup_delay_time",
    "build_set_auxiliary_locking_on_close_enabled",
    "build_set_auxiliary_locking_relock_enabled",
    "build_set_language_deutsch",
    "build_set_language_english",
    "build_set_verify_fail_time",
    "build_start_enrol",
    "build_voice_volume_write",
    "cloud_device_mac",
    "cloud_get_public_key",
    "cloud_get_voice_list",
    "cloud_list_devices",
    "cloud_verify",
    "compute_nonce",
    "compute_sign",
    "control_command_name",
    "crc16_aqara",
    "crc16_mijia",
    "crc16_xmodem",
    "decode_access_log",
    "decode_alarm_volume",
    "decode_alert_volume",
    "decode_credential_id",
    "decode_enrol_report",
    "decode_event",
    "decode_front_connection",
    "decode_language",
    "decode_lock_log_record",
    "decode_lock_state",
    "decode_lock_volume",
    "decode_manufacturer_payload",
    "decode_sync_log_credential_slot",
    "decode_sync_log_event_label",
    "decode_user_table",
    "decrypt_control_payload",
    "derive_session_material",
    "download_voice_pack",
    "encrypt_control_payload",
    "encrypt_login_password",
    "fetch_lock_credentials",
    "fetch_ltmk",
    "fetch_offline_password_log",
    "fetch_offline_passwords",
    "find_operation",
    "fragment_auth_message",
    "frame_data_block",
    "generate_ephemeral",
    "get_session_material",
    "hkdf_expand",
    "hkdf_extract",
    "hkdf_sha256",
    "identify_candidate",
    "iter_data_frames",
    "iter_ota_data_writes",
    "login",
    "make_local_signer",
    "normalize_lock_operation",
    "normalize_voice_volume_preset",
    "operations_in_family",
    "ota_decrypt",
    "ota_encrypt",
    "parse_auth_message",
    "parse_control_request",
    "parse_voice_list",
    "prepare_runtime_cloud_auth_headers",
    "run_authenticated_lock_operation",
    "scan",
    "select_preferred",
    "select_voice_pack",
    "send_lock_operation",
    "set_voice_volume",
    "sync_log_record_from_entry",
    "valid_crc",
    "write_voice_volume",
]
