# ESPHome Bluetooth Proxy configs

Three ready-to-flash [ESPHome](https://esphome.io/) configs that turn a cheap ESP32 board into a Bluetooth proxy for Home Assistant. Any one of these gives Home Assistant (and therefore this integration) a BLE path to the Aqara U200 lock, as long as the board is placed within normal BLE range of the lock.

You only need **one** of these boards, whichever you have on hand:

| File | Board | Framework | Notes |
|---|---|---|---|
| `bt-proxy-esp32.yaml` | Classic ESP32 (DevKitC, WROOM-32, NodeMCU-32S, ...) | esp-idf | Good general-purpose choice, decent range |
| `bt-proxy-esp32-c3-supermini.yaml` | ESP32-C3 "Super Mini" | esp-idf (required) | Tiny/cheap, USB-C, somewhat shorter range |
| `bt-proxy-esp32-s3.yaml` | ESP32-S3 dev boards | esp-idf | More RAM/CPU headroom if you're also running other ESPHome components on the same board |

## Before flashing any of them

Each file has three placeholders you must fill in yourself — do **not** flash them as-is:

1. **Wi-Fi credentials** — either replace `!secret wifi_ssid` / `!secret wifi_password` with your own `secrets.yaml` entries (recommended, see the [ESPHome secrets guide](https://esphome.io/guides/faq.html#tips-for-secrets-yaml)), or inline your SSID/password directly.
2. **API encryption key** — generate your own (running `esphome wizard` once will generate one for you, or generate 32 random bytes yourself and base64-encode them). Never reuse the placeholder in these files.
3. **OTA password** and the **fallback-hotspot password** — pick your own values.

## Flashing

With the [ESPHome CLI](https://esphome.io/guides/installing_esphome.html) installed:

```bash
esphome run bt-proxy-esp32.yaml
```

(swap in whichever file matches your board). The first flash needs a USB cable; after that, ESPHome can update the device over-the-air.

If you use the ESPHome Home Assistant add-on instead, just copy the relevant file's content into a new device there.

## After flashing

The device should show up automatically in Home Assistant under **Settings → Devices & Services** as a discovered ESPHome device with Bluetooth proxy capability. No further configuration is needed on the Home Assistant side — any Bluetooth-based integration (including this one) will automatically be able to use it once it's online and within range of the target device.
