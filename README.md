# U200 BLE — Aqara Access Log for Home Assistant

A Home Assistant custom integration that reads the **access log** (unlock/lock history, including *who* used which credential) of an Aqara U200 smart lock directly over Bluetooth Low Energy (BLE).

This integration is **read-only / log-focused**. It does not lock or unlock the door itself — pair it with whatever you already use for actual lock control (for example, Matter, if your U200 supports it). What this integration adds is the missing piece Matter and most other integrations don't expose: a per-event history of *which* fingerprint, code, key card, or app credential opened the lock, including a resolvable human-readable name (via a name mapping you fill in yourself, entirely local — see below).

## What this gives you

- `sensor.<lock>_last_access_log_time` — timestamp of the most recent access-log entry.
- `sensor.<lock>_last_access_log_person` — the credential slot involved, mapped to a friendly name if you've configured one, otherwise shown as an unassigned slot number.
- `sensor.<lock>_last_access_log_event` — the method used (fingerprint, code, key card, app/Bluetooth, etc.).
- A `button` entity to force a refresh over Bluetooth on demand.
- A `fetch_ltmk` service to enable an offline BLE session (skips the cloud login round-trip on every read).

Credential-to-name mapping lives only in this integration's own config-entry options (stored locally in Home Assistant's own config storage) — never hardcoded in source, and never sent anywhere.

> **Privacy note:** Any person names that appear in this repository's code comments or docs (for example "Mom", "Roommate") are fictional placeholder examples only, invented to illustrate the credential-name-mapping feature. They are not real names of any real person, and no real household names, account names, or personal identifiers of the author are included anywhere in this repository.

## Requirements

- Home Assistant 2024.x or newer.
- **A working Bluetooth connection from Home Assistant to the lock.** This integration talks to the U200 directly over BLE, so Home Assistant needs *some* way to reach it:
  - A **Bluetooth proxy** (for example an ESPHome Bluetooth proxy running on an ESP32) placed within BLE range of the lock — the recommended setup if your Home Assistant host itself isn't close enough to the lock, or
  - A Bluetooth adapter directly on/near the Home Assistant host, with the built-in `bluetooth_adapters` integration active and BLE range to the lock.

  Without one of these, Home Assistant simply has no BLE path to the lock and this integration cannot function. If you already use Bluetooth proxies for other BLE devices in Home Assistant, no extra proxy is needed — the existing Bluetooth integration/proxies are shared automatically.

  Ready-to-flash ESPHome Bluetooth proxy configs for three common boards are included in this repository under [`esphome/`](esphome/): a classic **ESP32**, an **ESP32-C3 Super Mini**, and an **ESP32-S3**. Fill in your own Wi-Fi credentials, API encryption key, and OTA password (each file has placeholders and comments explaining where), then flash with the [ESPHome](https://esphome.io/) CLI or add-on. See [`esphome/README.md`](esphome/README.md) for board-specific notes.
- An Aqara account (email/phone + password) with the lock already added in the Aqara app, since credential names and some lock metadata are fetched from the Aqara cloud during setup.
- Your Aqara account's district/region, as used by the Aqara app (needed for cloud login).
- A **guard code** from the Aqara app for the very first login (Account → Security → "guard code" or similar, depending on app version/language). This is a short-lived (~30 second) confirmation code; request it in the app right before completing setup here.

## Installation

### Option A: HACS (recommended)

[![Open this repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=danneloi&repository=haos_aqara&category=integration)

Click the badge above (this also works from the Home Assistant companion app), then click **Download**, and restart Home Assistant. This isn't a default HACS repository, so the badge adds it as a custom repository automatically. To do the same by hand instead: **HACS → Integrations → ⋮ (top right) → Custom repositories** → add `https://github.com/danneloi/haos_aqara` as category **Integration** → find **U200 BLE** → **Download** → restart Home Assistant.

### Option B: Manual

1. Download this repository (or just the `custom_components/u200_ble` folder).
2. Copy the `u200_ble` folder into your Home Assistant `config/custom_components/` directory, so you end up with `config/custom_components/u200_ble/...`.
3. Restart Home Assistant.

## Setup

[![Open your Home Assistant instance and start setting up this integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=u200_ble)

1. Click the badge above, or go to **Settings → Devices & Services → Add Integration** and search for **U200 BLE**.
2. Enter your Aqara account email/phone, password, district/region, and the lock's Bluetooth address (or select it if discovered automatically).
3. When prompted for a guard code, open the Aqara app, request one, and enter it here right away — it expires quickly.
4. Once set up, open the integration's **Configure/Options** to map credential slots (shown as raw numbers at first) to friendly names as they show up in the access log.

## Known limitations

- Credential-open events reported with method `matter` are a confirmed artifact of how this lock's access log encodes certain internal/system events — they always carry a fixed placeholder identifier rather than a real credential, and are treated by this integration as non-attributable (they will not show up as a real person unlocking). This is intentional and was confirmed via direct protocol inspection.
- Fixed (2026-09-18): every real fingerprint credential-open used to be mislabeled `face` (this integration's underlying protocol library special-cases that method based on a byte pattern that never matched on the tested lock/firmware). It's now corrected back to `fingerprint`. If a name mapping still looks wrong for `fingerprint`/`face`/any other method after updating, please open an issue with the raw `sensor.*_last_access_log_event` attributes attached (redact your own account/device details first).
- This integration depends on a vendored copy of a separate, private protocol library for the low-level BLE/cloud protocol handling. It's bundled here so no external PyPI package is required, but it means protocol updates need to be re-vendored manually into new releases of this integration.

## Contributing / issues

Please redact any personal information (names, exact addresses, account identifiers, MAC addresses) from logs before posting them in an issue.

## License

MIT — see [LICENSE](LICENSE).
