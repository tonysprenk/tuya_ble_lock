# Tuya BLE Smart Lock — Project Notes

## Project Goal

Build a Home Assistant HACS integration for **local BLE control** of Tuya-based smart door locks with **zero cloud dependency** for ongoing operation.

---

## Decompiled Apps

### 1. Gainsborough Forte (investigation on hold)

- **Package:** `com.gainsborough.lock`
- **Version:** 1.4.0 (code 12), SDK target 36, min SDK 21
- **Architecture:** White-labeled TTLock platform
- **Cloud API:** `https://euservlet.ttlock.com` (40+ endpoints)
- **Decompiled to:** `decompiled/` (apktool + jadx, 4 DEX files, ~10K Java files)

#### TTLock BLE Protocol (from decompiled)

- **GATT Service:** `00001910-0000-1000-8000-00805f9b34fb`
- **Write Char:** `0000fff2-0000-1000-8000-00805f9b34fb`
- **Notify Char:** `0000fff4-0000-1000-8000-00805f9b34fb`
- **Encryption:** AES-128-CBC, default factory key `"blackdyupic"`
- **Packet prefix:** `0xAA`, terminated with `\r\n`, fragmented at 20-byte BLE chunks
- **140+ BLE commands** covering: unlock/lock, passcode CRUD, fingerprint/face/palm vein enrollment, IC card, key fob, door sensor, passage mode, DFU, audit logs
- **Lock versions:** V1, V2, V2S, V2S_PLUS, V3, CAR, MOBI, V3_CAR

### 2. Tuya Smart (investigation ongoing)

- **Package:** `com.tuya.smart` (v7.2.8)
- **Architecture:** Tuya/ThingClips IoT platform, React Native hybrid, heavily obfuscated
- **Decompiled to:** `decompiled-tuya/` (apktool + jadx, 13 DEX files, ~63K Java files)
- **Obfuscation:** Class/method names replaced with patterns like `dpqpbdp`, `bqqpdpd`, etc.

---

## Tuya BLE Protocol — Full Specification (Reverse-Engineered)

### GATT UUIDs

| Role | UUID |
|---|---|
| Service | `0000fd50-0000-1000-8000-00805f9b34fb` |
| Write Characteristic | `00000001-0000-1001-8001-00805f9b07d0` |
| Notify Characteristic | `00000002-0000-1001-8001-00805f9b07d0` |

### Advertisement (Manufacturer ID `0x07D0`)

```
[0-1]  Manufacturer ID (LE): 0xD0, 0x07
[2]    Flags: bit7=isBind, bit6=isShare, bit5=isRoam
[3]    Protocol version: 3
[4]    Sub-version: 0 or 3
[5-6]  Capability flags (2 bytes)
[7]    Reserved
[8-23] Encrypted UUID data (AES-CBC, key=IV=MD5(productIdRaw))
```

Other manufacturer IDs: `0x5902` (BLE-only legacy), `0x5904` (single BLE short), `0x6902` (BLE-only extended), and `0x59xx`/`0x69xx` bound variants.

### Packet Framing

**Inner frame:**
```
[SN: 4B BE] [ACK_SN: 4B BE] [CODE: 2B BE] [DATA_LEN: 2B BE] [DATA: N bytes] [CRC16: 2B]
```

**Encryption wrapper:**
```
[security_flag: 1B] [IV: 16B] [AES-CBC ciphertext: N bytes (zero-padded to 16B)]
```

**BLE fragmentation:**
- First fragment: `[seq_varint=0] [total_len_varint] [type_nibble=0x20] [data...]`
- Subsequent:     `[seq_varint=N] [data...]`
- Default MTU: 20 bytes

### Cryptography

| Component | Algorithm | Details |
|---|---|---|
| Key exchange | ECDH secp256r1 | 65-byte uncompressed public keys |
| Communication key | MD5(ECDH shared secret) | 16 bytes, used as AES key |
| Packet encryption | AES-128-CBC / NoPadding | Random 16-byte IV per packet, zero-padded plaintext |
| CRC | CRC-16/MODBUS | Polynomial 0xA001, init 0xFFFF |
| Advertisement decryption | AES-128-CBC | key=IV=MD5(productIdRaw) |

### Security Flag Values

| Flag | Key derivation | Use case |
|---|---|---|
| 0 | None (plaintext) | ECDH exchange only |
| 4 | `MD5(loginKey.UTF8)` | Post-pair data ops (P3 protocol) |
| 5 | `MD5(MD5(loginKey.UTF8) + srand)` | Post-pair session (P3) |
| 6 | `communicationKey` (MD5 of ECDH) | CommRod protocol (our target) |
| 14 | `MD5((loginKeyComplete + secretKey).UTF8)` | New security |
| 15 | `MD5((loginKeyComplete + secretKey).UTF8 + srand)` | New security session |

### Command Codes (Pairing-Relevant)

| Code | Hex | Name | Direction |
|---|---|---|---|
| 0 | 0x00 | DEVICE_INFO | App → Device |
| 1 | 0x01 | PAIR | App → Device |
| 2 | 0x02 | SEND_DPS | App → Device |
| 3 | 0x03 | QUERY_STATUS | App → Device |
| 5 | 0x05 | UNBIND | App → Device |
| 6 | 0x06 | DEVICE_RESET | App → Device |
| 32 | 0x20 | ECDH_KEY | Bidirectional |
| 35 | 0x23 | DATA_TRANSFER / SCHEMA_CHECK | Bidirectional |
| 32798 | 0x7FFE | TRANSPARENT (machine key) | App → Device |
| 32769 | 0x8001 | RECV_DP | Device → App |
| 32785 | 0x8011 | TIME_REQUEST | Device → App |

### Pairing Flow (CommRod Protocol)

```
App                                          Device
 │                                              │
 │  1. ECDH (0x20) — plaintext                  │
 │  [0x03][app_pubkey_65B] ─────────────────────>│
 │<──────────────── [0x03][dev_pubkey_65B]       │
 │  communicationKey = MD5(ECDH_shared_secret)   │
 │                                              │
 │  2. Machine Key (0x7FFE, sub 0x07) — encrypted│
 │  [00 00 00 07][machineKey_bytes] ────────────>│
 │<──────────────── [sub=7][0x00=OK] or [!=0=ERR]│
 │                                              │
 │  3. Device Info (0x00) — encrypted            │
 │  [MTU_2B] ──────────────────────────────────>│
 │<──────────────── [device_info_blob]           │
 │                                              │
 │  4. Pair (0x01) — encrypted                   │
 │  [UUID_16B][00*6][00*22][flag] ─────────────>│
 │<──────────────── [0x00=new, 0x02=bound]       │
 │                                              │
 │  5. Schema Check (0x23) — encrypted           │
 │  [sha256_of_schema] ────────────────────────>│
 │<──────────────── [result]                     │
```

---

## Key Finding: Cloud vs Local Pairing

### Cloud Dependency Analysis

The standard Tuya pairing flow calls cloud APIs:
1. `thing.m.device.register` — register device, get `devId`
2. `m.thing.device.auth.key.get` — get `encryptedAuthKey` from cloud
3. `m.thing.device.keys.get.create` — get `localKey`, `secKey`, `verifyKey`

### Critical Insight: BLE-Only Devices

**BLE-only devices (no WiFi) cannot phone home.** Therefore:
- All validation of the machine key MUST happen locally on the device
- No hardcoded factory keys were found anywhere in the 63K-file codebase
- All encryption uses dynamically-derived keys (ECDH → MD5)
- The `encryptedAuthKey` from cloud is sent as-is to the device (app doesn't decrypt it)

**Hypothesis:** The device may accept any machine key sent over the ECDH-encrypted channel, since it has no way to validate it against the cloud. The PoC tests this.

### What Was NOT Found

- No hardcoded AES factory keys in any of the 63K decompiled Java files
- No device-specific factory secret provisioning code
- No certificate pinning or signature verification for machine keys
- All `SecretKeySpec` instantiations accept runtime parameters, never constants

---

## PoC: Local BLE Pairing Script

**Location:** `tuya_ble_poc/`

| File | Purpose |
|---|---|
| `__init__.py` | Package init |
| `__main__.py` | CLI entry point |
| `crypto_utils.py` | ECDH (secp256r1), AES-128-CBC, CRC-16/MODBUS, MD5 |
| `protocol.py` | Packet framing, encryption, BLE fragmentation, command builder |
| `pair_device.py` | Full pairing flow with multi-strategy machine key testing |

### Dependencies

```
pip install bleak cryptography
```

### Usage

```bash
# Scan for Tuya BLE devices
python -m tuya_ble_poc --scan

# Pair (tries multiple machine key strategies automatically)
python -m tuya_ble_poc --mac AA:BB:CC:DD:EE:FF

# Pair with known machine key
python -m tuya_ble_poc --mac AA:BB:CC:DD:EE:FF --machine-key "your_key"
```

### Machine Key Strategies Tested (in order)

1. User-provided (via `--machine-key`)
2. Empty string
3. Random 32-char hex
4. MD5(MAC address)
5. All zeros (32 chars)
6. MD5(UUID or address)

### Test Status

- All crypto primitives self-tested and passing (ECDH, AES-CBC, CRC-16, framing, fragmentation)
- **Awaiting real hardware test** with CSR Bluetooth USB dongle + Tuya BLE lock

### Hardware Notes

- **Dongle:** CSR8510-based USB Bluetooth adapter
- Supported by BlueZ on Linux
- Some cheap clones cap BLE MTU at 23 (effective 20 bytes) — PoC handles this
- May need `sudo` for BLE scanning
- If multiple adapters: `export BLUETOOTH_ADAPTER=hci1`

---

## Existing Community Work

### ha_tuya_ble (PlusPlus-ua)

- **Repo:** https://github.com/PlusPlus-ua/ha_tuya_ble
- Requires Tuya Cloud credentials (local_key, uuid, device_id)
- Uses cloud to fetch credentials, then operates locally
- Supports sensors, switches, covers — but **no lock entity support**
- Good reference for Tuya BLE DP (data point) protocol after pairing

---

## Planned Home Assistant Integration

### Template Base

Using `nikolajflojgaard/homeassistant-hacs-template` — provides:
- Config flow (UI-based, VERSION=2) with reauth + options
- DataUpdateCoordinator pattern
- Persistent storage with schema migration
- Services + WebSocket API
- Diagnostics with secret redaction
- Rename script for domain customization

### Target Entity Platforms

| Platform | Entities |
|---|---|
| `lock` | Lock/unlock, deadlock |
| `binary_sensor` | Door sensor (open/closed), tamper alert, battery low |
| `sensor` | Battery %, RSSI, firmware version, last unlock method/time |
| `switch` | Passage mode, auto-lock, privacy lock, audio, remote unlock |
| `number` | Auto-lock delay, backlight duration, sensitivity, volume |

### Services

- `add_passcode` / `delete_passcode` / `clear_all_passcodes`
- `add_fingerprint` / `delete_fingerprint` / `clear_all_fingerprints`
- `get_audit_log`
- `factory_reset`
- `calibrate_time`

### Architecture Decision

- **Pairing:** Full local BLE pairing (no cloud). If PoC proves machine key can be locally generated, integration handles entire flow. Otherwise, fall back to cloud-assisted pairing (2 API calls during setup, then pure local BLE).
- **Communication:** Pure BLE only, no cloud dependency for ongoing operations
- **Protocol:** Tuya BLE CommRod (ECDH + AES-128-CBC, security flag 6)

---

## Next Steps

1. **Test PoC with real hardware** — CSR dongle + Tuya BLE lock in pairing mode
2. **Analyze machine key response** — determine if local generation works
3. **If local works:** proceed with full HA integration build
4. **If local fails:** implement cloud-assisted pairing (embed 2 Tuya API calls in config flow)
5. **Build HA integration** using template + protocol library
6. **Add lock entity** with DP-based commands for lock/unlock
7. **Add supporting entities** (sensors, switches, binary sensors)
8. **Add services** (passcode management, fingerprint, audit logs)
