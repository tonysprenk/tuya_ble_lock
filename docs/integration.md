# Tuya BLE Lock - Integration Documentation

## Overview

Tuya BLE Lock is a Home Assistant custom integration for **local Bluetooth control** of Tuya-based smart door locks. After a one-time cloud-assisted setup, all daily operations (lock, unlock, credential management) happen entirely over BLE with **zero cloud dependency**.

Key features:
- Lock/unlock via Home Assistant UI or automations
- Battery monitoring
- Credential management (PINs, fingerprints, NFC cards)
- Temporary passwords with time limits
- Lock settings (volume, auto-lock, privacy lock)
- State persistence across HA restarts

## Prerequisites

1. A **Bluetooth adapter** on your Home Assistant host (built-in or USB)
2. Home Assistant 2024.1 or later
3. One of the following, depending on your chosen setup method:

| Setup method | What you need | App required? | Cloud required? |
|-------------|---------------|---------------|-----------------|
| **Cloud-Assisted** | Tuya Smart / Smart Life app with the lock paired to your account | Yes (can remove after) | One-time only |
| **Standalone** | A Tuya Smart / Smart Life app account (lock does NOT need to be paired) | Account only | One-time only |
| **Manual** | The auth key (hex) for your lock, obtained by other means | No | No |

## Installation

### HACS (Recommended)

1. Open HACS in Home Assistant
2. Go to **Integrations** > three-dot menu > **Custom repositories**
3. Add `https://github.com/tkhadimullin/tuya_ble_lock` as an **Integration**
4. Search for "Tuya BLE Lock" and install
5. Restart Home Assistant

### Manual

1. Download this repository
2. Copy the `custom_components/tuya_ble_lock` folder to your HA `config/custom_components/` directory
3. Restart Home Assistant

## Setup

After installation, add the integration via **Settings > Devices & Services > Add Integration > Tuya BLE Lock**.

### Setup Methods

The integration offers three setup paths:

#### Cloud-Assisted (Recommended)

**Requires:** Lock paired to your Tuya Smart / Smart Life app account.

1. HA auto-discovers your lock via Bluetooth, or you enter the MAC address manually
2. Enter your app email, password, country code, and cloud region
3. The integration fetches the encryption keys and device credentials from the cloud
4. If the lock is already paired to the app, setup completes instantly — no BLE pairing needed
5. If the lock is not yet paired (new or factory-reset), the integration performs BLE pairing automatically using the fetched auth key

This is the fastest path when you already have the lock in the Tuya app. The cloud is contacted once during setup and never again.

#### Standalone

**Requires:** A Tuya Smart / Smart Life app account. The lock does **not** need to be paired to it.

1. Select your lock model from the dropdown
2. Enter your Tuya app account credentials
3. The integration fetches only the auth key from the cloud, then pairs the lock directly over BLE

This is the best option for a brand new or factory-reset lock that you want to set up without ever adding it to the Tuya app. You still need a Tuya account because the auth key is stored on Tuya's servers.

#### Manual Auth Key

**Requires:** The auth key (hex string) for your lock. No app or cloud account needed.

1. Paste the auth key directly
2. The integration pairs the lock over BLE using this key

Fully app-free and cloud-free. Use this if you've extracted the auth key by other means (e.g., from another integration, from a Tuya IoT Platform developer account, or shared by someone who set up the lock previously).

### Why Cloud Credentials Are Needed

The **Cloud-Assisted** and **Standalone** setup methods require your Tuya Smart / Smart Life app credentials. Here's why:

Tuya BLE locks use a unique encryption key (called an "auth key") that is assigned to each device during manufacturing. This key is stored on Tuya's cloud servers and is required to establish a secure BLE session with the lock. There is no way to extract it from the lock itself.

During setup, the integration logs into the Tuya cloud API on your behalf to retrieve this key. After this one-time step:

- **Your email and password are not stored** — they are used only during the setup flow and discarded immediately
- **The lock is not associated or re-associated** with the account — the integration simply reads the device's auth key
- **No cloud connection is ever made again** — all subsequent operations happen entirely over local Bluetooth

If you prefer to avoid cloud credentials entirely, use the **Manual Auth Key** method and provide the auth key directly.

### Coexistence with the Tuya App

Setting up this integration does **not** remove your lock from the Tuya Smart / Smart Life app. You can continue using the app to control the lock alongside Home Assistant.

However, BLE locks only support **one active connection at a time**. This means:

- If the **Tuya app** is connected to the lock (e.g., you have the lock's page open), Home Assistant will not be able to connect until the app disconnects
- If **Home Assistant** is holding a BLE connection (within 60 seconds of the last operation), the Tuya app will not be able to connect until HA's idle timeout expires

In practice this is rarely an issue — the integration automatically disconnects after 60 seconds of inactivity, and the app only connects briefly when you interact with it. PINs, fingerprints, and cards always work regardless of which controller is connected, since they are processed locally by the lock.

## Entities

Each lock creates the following entities:

| Entity | Type | Description |
|--------|------|-------------|
| Lock | `lock` | Main lock/unlock control. Tracks locked/unlocked state via motor feedback and passage mode sync. |
| Battery | `sensor` | Battery percentage (0-100%). Updated periodically via BLE. |
| Battery state | `sensor` | Qualitative battery level: high, medium, low, exhausted. |
| Privacy lock | `switch` | Electronic double-lock (DP 79). |
| Passage mode | `switch` | Keep lock unlocked until manually locked. Only on supported models (e.g., H8 Pro). |
| Volume | `select` | Keypad sound level. Options vary by model (mute/normal or mute/low/normal/high). |
| Auto-lock delay | `number` | Seconds before auto-lock engages. Only on models with passage mode. |
| Refresh status | `button` | Force a BLE status refresh. |
| UUID | `sensor` | Device UUID (diagnostic). |
| Login key | `sensor` | BLE login key (diagnostic). |
| Virtual ID | `sensor` | Device virtual ID (diagnostic). |
| Auth key | `sensor` | Device auth key (diagnostic). |

Volume, auto-lock delay, and refresh are **configuration entities** — they appear on the device page but not on the default dashboard.

Diagnostic sensors (UUID, login key, virtual ID, auth key) are hidden by default and only visible when "Show disabled entities" is enabled.

## Lock Behaviour

### Auto-Lock

Tuya BLE locks automatically re-lock after unlocking. Some models re-lock within a few seconds, while others have a configurable **Auto-lock delay** (in seconds) that you can adjust via the corresponding entity.

The integration tracks lock state through motor feedback (DP 47) and passage mode sync (DP 33). When the motor stops after an unlock, the state returns to "locked". This is reflected in Home Assistant automatically — no polling required.

### Passage Mode

Passage mode keeps the lock **permanently unlocked** until you manually turn it off. This is useful for:

- Keeping a door unlocked during business hours or a party
- Allowing free entry/exit without credentials
- Temporarily disabling the lock for maintenance or moving furniture

When passage mode is **on**:
- The lock does not auto-lock after being opened
- The bolt stays retracted
- Anyone can open the door without a PIN, fingerprint, or card
- The lock entity in HA shows "unlocked"

When passage mode is **off**:
- Normal auto-lock behaviour resumes
- The lock re-engages after the configured delay
- The lock entity in HA shows "locked"

Passage mode is controlled via the **Passage mode** switch entity. It is only available on models that support DP 33 (auto_lock), such as the H8 Pro. The Smart Lock 3 (SYD8811) does not support passage mode.

### Privacy Lock (Double Lock)

The privacy lock (also called double lock) adds an extra electronic lock engagement. When enabled:

- The lock cannot be opened with regular credentials (PINs, fingerprints, cards)
- Only admin credentials may be able to bypass it (model-dependent)
- Useful as a "do not disturb" / night lock mode

Controlled via the **Privacy lock** switch entity (DP 79).

## Services

All services are available under the `tuya_ble_lock` domain in **Developer Tools > Services**.

For detailed examples, automation recipes, and step-by-step enrollment walkthroughs, see the [Credential Management Guide](credential-management.md).

### add_pin

Enroll a PIN code on one or more locks.

| Field | Required | Description |
|-------|----------|-------------|
| `device_id` | Yes | Lock device(s) to add the PIN to |
| `pin_code` | Yes | PIN digits (6-10 digits) |
| `person` | No | HA person to associate with |
| `admin` | No | Whether this is an admin credential (default: false) |

### add_fingerprint

Start fingerprint enrollment. The user must place their finger on the sensor multiple times (typically 4-6 touches) when prompted by the lock.

| Field | Required | Description |
|-------|----------|-------------|
| `device_id` | Yes | Lock device |
| `person` | No | HA person to associate with |
| `admin` | No | Admin credential (default: false) |

### add_card

Start NFC/RFID card enrollment. Tap the card on the lock's sensor when prompted.

| Field | Required | Description |
|-------|----------|-------------|
| `device_id` | Yes | Lock device |
| `person` | No | HA person to associate with |
| `admin` | No | Admin credential (default: false) |

### delete_credential

Delete credentials from a lock. Specify either a person + type, or a specific credential ID.

| Field | Required | Description |
|-------|----------|-------------|
| `device_id` | Yes | Lock device |
| `person` | No | Delete credentials belonging to this person |
| `cred_type` | No | Only delete this type: `pin`, `fingerprint`, or `card` |
| `credential_id` | No | Delete a specific credential by UUID (from `list_credentials`) |

### list_credentials

Returns all credentials stored for a lock, grouped by member and type.

| Field | Required | Description |
|-------|----------|-------------|
| `device_id` | Yes | Lock device |

### create_temp_password

Create a time-limited temporary password on the lock.

| Field | Required | Description |
|-------|----------|-------------|
| `device_id` | Yes | Lock device |
| `name` | Yes | Password name/label |
| `pin_code` | Yes | PIN digits |
| `effective_time` | Yes | Start time (datetime) |
| `expiry_time` | Yes | End time (datetime) |

## Device Profiles

The integration uses JSON device profiles to handle differences between lock models. Profiles are stored in `custom_components/tuya_ble_lock/device_profiles/`.

Each profile defines:
- Which entities to create and their DP mappings
- How to parse DP reports (`state_map`)
- Which services are available and their DP assignments
- Protocol version (V3 or V4)

The correct profile is auto-selected based on the `product_id` reported by the lock. If no matching profile exists, a default profile is used.

### Currently Supported Devices

| Device | Product ID | Profile |
|--------|-----------|---------|
| Smart Lock 3 (SYD8811) | `qqmu5mit` | `qqmu5mit.json` |
| H8 Pro | `wwbdbt3h` | `wwbdbt3h.json` |
| Generic Tuya BLE Lock | — | `_default.json` |

See the [Adding New Devices](../README.md#adding-new-devices) section in the README for how to create profiles for other locks.

## Troubleshooting

### Lock not discovered

- Ensure the lock is **powered on** and within Bluetooth range (~5m)
- Wake the lock by touching the keypad or fingerprint sensor
- Check that your HA host has a working Bluetooth adapter (`bluetoothctl show`)

### Pairing fails

- The lock must be in **pairing mode** (usually: factory reset, or remove from Tuya app)
- If already bound to another controller, you may need to factory reset the lock first
- Ensure your Tuya cloud credentials are correct and the cloud region matches your app

### Lock shows "Unavailable"

- BLE locks sleep aggressively to save battery. The integration reconnects on demand.
- Press the refresh button or trigger a lock/unlock to wake the connection
- Check HA logs for BLE connection errors

### Operations are slow

- First operation after idle may take 5-15 seconds (BLE reconnect + handshake)
- Subsequent operations within 60 seconds are fast (~1 second) due to idle-disconnect caching
- If the Tuya app is open on the lock's page, it may be holding the BLE connection — close the app and try again (see [Coexistence with the Tuya App](#coexistence-with-the-tuya-app))

### Battery shows "Unknown"

- Battery is polled every 12 hours via BLE
- Press "Refresh status" to trigger an immediate battery read
- Some models only report battery state (high/medium/low) rather than exact percentage
