#!/usr/bin/env python3
"""Dump ALL BLE advertisement data for known Tuya devices.

Scans for specific MAC addresses and prints every piece of advertisement
data: service_data, manufacturer_data, service_uuids, local_name, tx_power, etc.

Also attempts to extract product_id from FD50 service_data and decrypt
the UUID from manufacturer_data using the product_id as the AES key.

Usage:
    python3 scan_adv.py [--duration SECONDS]

Does NOT connect to the device — passive scan only.
"""

import asyncio
import hashlib
import sys

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Add your device MACs here to filter scan results
TARGET_MACS = set()


def decrypt_uuid_with_product_id(product_id_raw: bytes, encrypted_uuid: bytes) -> str | None:
    """Decrypt UUID from manufacturer_data using product_id as AES key.

    key = IV = MD5(product_id_raw)
    Ciphertext = manufacturer_data bytes 6..21 (16 bytes)
    """
    try:
        key = hashlib.md5(product_id_raw).digest()
        dec = Cipher(algorithms.AES(key), modes.CBC(key)).decryptor()
        plaintext = dec.update(encrypted_uuid) + dec.finalize()
        # Strip null padding
        return plaintext.rstrip(b"\x00").decode("ascii", errors="replace")
    except Exception as e:
        return f"<decrypt failed: {e}>"


def decrypt_uuid_with_service_data(service_data: bytes, encrypted_uuid: bytes) -> str | None:
    """Decrypt UUID using full service_data as key source (existing method).

    key = IV = MD5(service_data)
    """
    try:
        key = hashlib.md5(service_data).digest()
        dec = Cipher(algorithms.AES(key), modes.CBC(key)).decryptor()
        plaintext = dec.update(encrypted_uuid) + dec.finalize()
        return plaintext.rstrip(b"\x00").decode("ascii", errors="replace")
    except Exception as e:
        return f"<decrypt failed: {e}>"


def parse_manufacturer_data(mfr_id: int, data: bytes) -> dict:
    """Parse Tuya manufacturer data fields."""
    result = {"raw_hex": data.hex(), "length": len(data)}

    if mfr_id == 0x07D0 and len(data) >= 7:
        # Standard Tuya v3 format
        result["flags_byte"] = f"0x{data[0]:02x}"
        result["is_bound"] = bool(data[0] & 0x80)
        result["is_share"] = bool(data[0] & 0x40)
        result["is_roam"] = bool(data[0] & 0x20)
        result["protocol_version"] = data[1]
        result["sub_version"] = data[2]
        result["capability_1"] = f"0x{data[3]:02x}"
        result["capability_2"] = f"0x{data[4]:02x}"
        result["reserved"] = f"0x{data[5]:02x}"
        if len(data) >= 22:
            result["encrypted_uuid_hex"] = data[6:22].hex()
            result["encrypted_uuid_len"] = len(data[6:22])
        if len(data) > 22:
            result["trailing_bytes_hex"] = data[22:].hex()

    elif mfr_id in (0x5902, 0x5904, 0x6902) and len(data) >= 4:
        # BLE-only legacy/short/extended formats
        result["flags_byte"] = f"0x{data[0]:02x}"
        result["protocol_version"] = data[1]
        if len(data) >= 20:
            result["encrypted_uuid_hex"] = data[4:20].hex()

    return result


def parse_service_data(uuid_str: str, data: bytes) -> dict:
    """Parse service data for known Tuya service UUIDs."""
    result = {"raw_hex": data.hex(), "length": len(data)}

    if "fd50" in uuid_str.lower():
        # FD50 Tuya BLE service data
        if len(data) >= 1:
            result["first_byte"] = f"0x{data[0]:02x}"
            if data[0] == 0x00 and len(data) > 1:
                # Byte 0 = 0x00 means remaining bytes are product_id (raw)
                product_id_raw = data[1:]
                result["product_id_raw_hex"] = product_id_raw.hex()
                try:
                    result["product_id_ascii"] = product_id_raw.decode("ascii", errors="replace")
                except Exception:
                    pass
            else:
                # Other formats — dump everything
                result["payload_hex"] = data[1:].hex() if len(data) > 1 else ""
                try:
                    result["payload_ascii"] = data.decode("ascii", errors="replace")
                except Exception:
                    pass

    elif "a201" in uuid_str.lower():
        result["note"] = "A201 Tuya BLE alternative service data"
        if len(data) >= 1:
            result["first_byte"] = f"0x{data[0]:02x}"
            try:
                result["payload_ascii"] = data.decode("ascii", errors="replace")
            except Exception:
                pass

    return result


async def scan(duration: float = 15.0) -> None:
    target_set = {m.upper() for m in TARGET_MACS}
    found: dict[str, tuple[BLEDevice, AdvertisementData]] = {}

    def callback(device: BLEDevice, adv: AdvertisementData) -> None:
        if device.address.upper() in target_set:
            # Keep the latest advertisement
            found[device.address.upper()] = (device, adv)

    print(f"Scanning for {len(TARGET_MACS)} target device(s) for {duration}s...")
    print(f"Targets: {', '.join(sorted(TARGET_MACS))}")
    print()

    scanner = BleakScanner(detection_callback=callback, scanning_mode="active")
    await scanner.start()
    await asyncio.sleep(duration)
    await scanner.stop()

    if not found:
        print("No target devices found during scan.")
        print("Make sure the devices are powered on and within range.")
        return

    for mac, (device, adv) in sorted(found.items()):
        print("=" * 70)
        print(f"DEVICE: {mac}")
        print(f"  Name:        {device.name or '<none>'}")
        print(f"  RSSI:        {adv.rssi} dBm")
        print(f"  TX Power:    {adv.tx_power}")
        print()

        # --- Service UUIDs ---
        print("  Service UUIDs:")
        if adv.service_uuids:
            for suuid in adv.service_uuids:
                print(f"    - {suuid}")
        else:
            print("    (none)")
        print()

        # --- Service Data ---
        print("  Service Data:")
        fd50_data = None
        if adv.service_data:
            for suuid, sd in adv.service_data.items():
                raw = bytes(sd)
                parsed = parse_service_data(suuid, raw)
                print(f"    UUID: {suuid}")
                print(f"      Raw ({len(raw)}B): {raw.hex()}")
                for k, v in parsed.items():
                    if k not in ("raw_hex", "length"):
                        print(f"      {k}: {v}")
                if "fd50" in suuid.lower():
                    fd50_data = raw
                print()
        else:
            print("    (none)")
            print()

        # --- Manufacturer Data ---
        print("  Manufacturer Data:")
        encrypted_uuid = None
        if adv.manufacturer_data:
            for mfr_id, md in adv.manufacturer_data.items():
                raw = bytes(md)
                parsed = parse_manufacturer_data(mfr_id, raw)
                print(f"    Manufacturer ID: 0x{mfr_id:04X} ({mfr_id})")
                print(f"      Raw ({len(raw)}B): {raw.hex()}")
                for k, v in parsed.items():
                    if k not in ("raw_hex", "length"):
                        print(f"      {k}: {v}")
                if mfr_id == 0x07D0 and len(raw) >= 22:
                    encrypted_uuid = raw[6:22]
                print()
        else:
            print("    (none)")
            print()

        # --- UUID Decryption Attempts ---
        if encrypted_uuid:
            print("  UUID Decryption Attempts:")

            # Method 1: Using FD50 service_data[1:] as product_id (ha_tuya_ble method)
            if fd50_data and len(fd50_data) > 1 and fd50_data[0] == 0x00:
                product_id_raw = fd50_data[1:]
                uuid_val = decrypt_uuid_with_product_id(product_id_raw, encrypted_uuid)
                print(f"    Method 1 (product_id={product_id_raw!r}): {uuid_val}")
            else:
                print(f"    Method 1 (product_id from FD50[1:]): N/A — FD50 first byte != 0x00 or no FD50 data")

            # Method 2: Using full FD50 service_data (our existing method)
            if fd50_data:
                uuid_val = decrypt_uuid_with_service_data(fd50_data, encrypted_uuid)
                print(f"    Method 2 (MD5 of full FD50 service_data): {uuid_val}")

            print()

        # --- Platform Data (if any) ---
        if hasattr(adv, 'platform_data') and adv.platform_data:
            print("  Platform Data:")
            print(f"    {adv.platform_data}")
            print()

        print()


def main():
    duration = 15.0
    if "--duration" in sys.argv:
        idx = sys.argv.index("--duration")
        if idx + 1 < len(sys.argv):
            duration = float(sys.argv[idx + 1])

    asyncio.run(scan(duration))


if __name__ == "__main__":
    main()
