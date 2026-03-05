#!/usr/bin/env python3
"""Tuya BLE Lock Control — local-only, no cloud needed after initial pairing.

Usage:
    python3 lock_control.py pair --auth-key HEX      # First-time pairing (auth key from cloud)
    python3 lock_control.py unlock                    # Unlock the lock
    python3 lock_control.py lock                      # Lock the lock
    python3 lock_control.py status                    # Read lock status / DPs
    python3 lock_control.py auto-lock on|off          # Enable/disable auto-lock
    python3 lock_control.py volume mute|normal        # Set beep volume (WARNING: mute disables motor!)
    python3 lock_control.py double-lock on|off        # Electronic double lock
    python3 lock_control.py add-pin MEMBER_ID DIGITS  # Add PIN code (e.g., add-pin 1 123456)
    python3 lock_control.py add-fingerprint MEMBER_ID # Enroll fingerprint
    python3 lock_control.py add-card MEMBER_ID        # Enroll NFC/RFID card
    python3 lock_control.py delete-method MEMBER_ID TYPE HW_ID  # Delete credential
    python3 lock_control.py listen [--duration MIN]     # Listen for unsolicited DP reports (default: 10 min)
    python3 lock_control.py dp DP_ID TYPE VALUE       # Raw DP write
    python3 lock_control.py [--mac XX:XX:XX:XX:XX:XX] [--admin] unlock

Session key derivation:
    login_key = stored 6-byte key from initial pairing
    session_key = MD5(login_key + srand)
    where srand = 6-byte random from device info response each session

Protocol: Tuya BLE v4.2, FD50 service, AES-128-CBC encryption
"""

import asyncio
import hashlib
import secrets
import struct
import sys
import logging
import time
import argparse

from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("bleak").setLevel(logging.WARNING)
log = logging.getLogger("lock")

# Device config — fill in your own values
DEFAULT_MAC = "AA:BB:CC:DD:EE:FF"
FD50_WRITE = "00000001-0000-1001-8001-00805f9b07d0"
FD50_NOTIFY = "00000002-0000-1001-8001-00805f9b07d0"

# Credentials — derive from your Tuya cloud localKey and device_id:
#   LOGIN_KEY = localKey[:6].encode()
#   VIRTUAL_ID = device_id.encode() + b"\x00" * (22 - len(device_id))
LOGIN_KEY = b""       # e.g. b"AbCdEf"
VIRTUAL_ID = b"" + b"\x00" * 22  # e.g. b"your_device_id" + padding to 22 bytes

# Tuya BLE commands
CMD_DEVICE_INFO = 0x0000
CMD_PAIR = 0x0001
CMD_DP_WRITE_V4 = 0x0027
CMD_DEVICE_STATUS = 0x0003
CMD_TIME_V1 = 0x8011
CMD_TIME_V2 = 0x8012
CMD_DP_REPORT_V4 = 0x8006

# DP type names
DP_TYPES = {0: "RAW", 1: "BOOL", 2: "VALUE", 3: "STRING", 4: "ENUM", 5: "BITMAP"}

# Verified DPs for this device (jtmspro_2b_2, productId: qqmu5mit)
# Source: Tuya cloud schema (device_schema.json)
KNOWN_DPS = {
    1: "unlock_method_create",      # RAW rw: enroll fingerprint/password/card/face
    2: "unlock_method_delete",      # RAW rw: delete credential
    3: "unlock_method_modify",      # RAW rw: modify credential schedule
    8: "residual_electricity",      # VALUE ro: battery % (0-100)
    9: "battery_state",             # ENUM ro: high/medium/low/exhausted
    12: "unlock_fingerprint",       # VALUE ro: fingerprint unlock record
    13: "unlock_password",          # VALUE ro: password unlock record
    14: "unlock_dynamic",           # VALUE ro: dynamic password unlock record
    15: "unlock_card",              # VALUE ro: card unlock record
    18: "open_inside",              # BOOL ro: interior unlock event
    19: "unlock_ble",               # VALUE ro: BLE unlock record
    20: "lock_record",              # RAW ro: locking action records
    21: "alarm_lock",               # ENUM ro: alarm events
    24: "doorbell",                 # BOOL ro: doorbell ring event
    31: "beep_volume",              # ENUM rw: mute(0), normal(1) — WARNING: mute disables motor!
    33: "automatic_lock",           # BOOL rw: auto-lock enable/disable
    44: "rtc_lock",                 # BOOL rw
    46: "manual_lock",              # BOOL rw: manual lock command
    47: "lock_motor_state",         # BOOL ro: false=locked, true=unlocked
    51: "temporary_password_creat", # RAW rw: create temp password
    52: "temporary_password_delete",# RAW rw: delete temp password
    53: "temporary_password_modify",# RAW rw: modify temp password schedule
    54: "synch_method",             # RAW rw: cloud<->device credential sync (NOT a query interface)
    55: "unlock_temporary",         # VALUE ro: temp password unlock record
    61: "remote_no_dp_key",         # RAW rw: remote unlock command
    62: "unlock_phone_remote",      # VALUE ro: app remote unlock record
    63: "unlock_voice_remote",      # VALUE ro: voice remote unlock record
    69: "record",                   # RAW rw
    70: "check_code_set",           # RAW rw
    71: "ble_unlock_check",         # RAW rw: BLE unlock command
    79: "electronic_double_lock",   # BOOL rw: electronic security lock
    # Non-standard / manufacturer-custom (observed in BLE reports)
    520: "battery_custom",          # VALUE: battery % (0-100)
}

# Volume level names — this device only supports mute(0) and normal(1)
VOLUME_LEVELS = {"mute": 0, "normal": 1}


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b & 0xFF
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def varint_encode(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value > 0:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)


def varint_decode(data: bytes, pos: int) -> tuple:
    result = 0
    offset = 0
    while offset < 5 and pos + offset < len(data):
        b = data[pos + offset]
        result |= (b & 0x7F) << (offset * 7)
        offset += 1
        if (b & 0x80) == 0:
            break
    return result, pos + offset


def encrypt_frame(sn, ack_sn, cmd, data, key, sec_flag):
    """Build encrypted MTP fragments."""
    header = struct.pack(">IIHH", sn, ack_sn, cmd, len(data))
    frame = header + data
    frame += struct.pack(">H", crc16(frame))
    padded = bytearray(frame)
    while len(padded) % 16 != 0:
        padded += b"\x00"
    iv = secrets.token_bytes(16)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    payload = bytes([sec_flag]) + iv + enc.update(bytes(padded)) + enc.finalize()
    # Fragment
    frags = []
    offset = 0
    idx = 0
    while offset < len(payload):
        hdr = varint_encode(idx)
        if idx == 0:
            hdr += varint_encode(len(payload))
            hdr += bytes([0x40])  # version 4
        chunk = payload[offset:offset + 20 - len(hdr)]
        frags.append(hdr + chunk)
        offset += len(chunk)
        idx += 1
    return frags


def decrypt_frame(payload, keys):
    """Decrypt MTP-reassembled payload."""
    if len(payload) < 17:
        return None
    sec = payload[0]
    if sec == 0:
        # Unencrypted
        try:
            f = TuyaBleFrame.from_bytes(payload[1:])
            return {"sec": 0, "sn": f.sn, "ack_sn": f.ack_sn, "cmd": f.code, "data": f.data}
        except Exception:
            return None
    iv = payload[1:17]
    enc = payload[17:]
    if len(enc) == 0 or len(enc) % 16 != 0:
        log.warning("Skipping frame: ciphertext len=%d not multiple of 16", len(enc))
        return None
    key = keys.get(sec)
    if not key:
        return None
    try:
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        raw = dec.update(enc) + dec.finalize()
    except Exception as exc:
        log.warning("Decrypt failed for sec=%d: %s", sec, exc)
        return None
    sn, ack_sn, cmd, dlen = struct.unpack(">IIHH", raw[:12])
    return {"sec": sec, "sn": sn, "ack_sn": ack_sn, "cmd": cmd, "data": raw[12:12+dlen]}


def reassemble(fragments):
    """Reassemble MTP fragments, split into messages."""
    messages = []
    current = []
    for f in fragments:
        idx, _ = varint_decode(f, 0)
        if idx == 0 and current:
            messages.append(current)
            current = []
        current.append(f)
    if current:
        messages.append(current)

    results = []
    for msg_frags in messages:
        buf = bytearray()
        exp_len = 0
        for f in msg_frags:
            pos = 0
            pkt, pos = varint_decode(f, pos)
            if pkt == 0:
                exp_len, pos = varint_decode(f, pos)
                pos += 1
            buf.extend(f[pos:])
        results.append(bytes(buf[:exp_len]) if exp_len else bytes(buf))
    return results


def parse_dp_report(data):
    """Parse V4 DP report: [sn(4)][flags(1)][0x80][dp_id(2)][type(1)][len(2)][val]."""
    if len(data) < 6:
        return []
    klv = data[6:]
    dps = []
    pos = 0
    while pos + 5 <= len(klv):
        dp_id = struct.unpack(">H", klv[pos:pos+2])[0]
        dp_type = klv[pos+2]
        dp_len = struct.unpack(">H", klv[pos+3:pos+5])[0]
        if pos + 5 + dp_len > len(klv):
            break
        val = klv[pos+5:pos+5+dp_len]
        dps.append({"id": dp_id, "type": dp_type, "len": dp_len, "raw": val})
        pos += 5 + dp_len
    return dps


def format_dp(dp):
    """Format a DP for display."""
    dp_id = dp["id"]
    dp_type = dp["type"]
    raw = dp["raw"]
    name = KNOWN_DPS.get(dp_id, "unknown")
    tname = DP_TYPES.get(dp_type, f"?{dp_type}")

    if dp_type == 1:  # BOOL
        val = "TRUE" if raw[0] else "FALSE"
    elif dp_type == 2:  # VALUE
        val = str(int.from_bytes(raw, "big"))
    elif dp_type == 4:  # ENUM
        val = str(int.from_bytes(raw, "big"))
    else:
        val = raw.hex()
    return f"DP {dp_id:>4d} ({name:>16s}) [{tname:>6s}] = {val}"


class LockSession:
    def __init__(self, client, login_key, auth_key=None):
        self.client = client
        self.login_key = login_key
        self.sn = 1
        self.keys = {4: hashlib.md5(login_key).digest()}
        self.session_key = None
        self.notifs = []
        # Auth key for first activation (sec_flag=1)
        if auth_key:
            self.keys[1] = auth_key  # SecretKey1 = raw authKey bytes

    def on_notify(self, sender, data):
        self.notifs.append(bytes(data))

    def derive_session(self, srand, auth_key=None):
        self.session_key = hashlib.md5(self.login_key + srand).digest()
        self.keys[5] = self.session_key
        # SecretKey2 = MD5(hex(authKey) + srand) — for first activation pair
        if auth_key:
            self.keys[2] = hashlib.md5(auth_key.hex().encode("ascii") + srand).digest()

    async def send(self, cmd, data, sec_flag, ack_sn=0):
        key = self.keys[sec_flag]
        frags = encrypt_frame(self.sn, ack_sn, cmd, data, key, sec_flag)
        for f in frags:
            await self.client.write_gatt_char(FD50_WRITE, f, response=False)
            await asyncio.sleep(0.05)
        self.sn += 1

    async def send_recv(self, cmd, data, sec_flag, wait=8.0):
        self.notifs.clear()
        await self.send(cmd, data, sec_flag)
        for _ in range(int(wait * 4)):
            await asyncio.sleep(0.25)
            if self.notifs:
                await asyncio.sleep(0.8)
                break
            if not self.client.is_connected:
                return []
        raw = list(self.notifs)
        self.notifs.clear()
        if not raw:
            return []
        payloads = reassemble(raw)
        frames = []
        for p in payloads:
            f = decrypt_frame(p, self.keys)
            if f:
                frames.append(f)
        return frames

    async def handle_time_requests(self, frames):
        for f in frames:
            cmd = f["cmd"]
            try:
                if cmd == CMD_TIME_V1:
                    ts = str(int(time.time() * 1000)).encode()
                    tz = struct.pack(">h", -int(time.timezone / 36))
                    await self.send(cmd, ts + tz, 5, ack_sn=f["sn"])
                elif cmd == CMD_TIME_V2:
                    t = time.localtime()
                    tz = -int(time.timezone / 36)
                    td = struct.pack(">BBBBBBBh", t.tm_year % 100, t.tm_mon, t.tm_mday,
                                     t.tm_hour, t.tm_min, t.tm_sec, t.tm_wday, tz)
                    await self.send(cmd, td, 5, ack_sn=f["sn"])
            except Exception as exc:
                log.warning("Time response failed (BLE disconnected?): %s", exc)

    async def collect(self, timeout=3.0):
        self.notifs.clear()
        frames = []
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(0.5)
            if self.notifs:
                await asyncio.sleep(0.8)
                raw = list(self.notifs)
                self.notifs.clear()
                for p in reassemble(raw):
                    f = decrypt_frame(p, self.keys)
                    if f:
                        frames.append(f)
                await self.handle_time_requests(frames)
        return frames


def decrypt_uuid(service_data, encrypted_id):
    key = hashlib.md5(service_data).digest()
    dec = Cipher(algorithms.AES(key), modes.CBC(key)).decryptor()
    return (dec.update(encrypted_id) + dec.finalize()).decode("ascii")


async def connect_and_setup(mac, auth_key_hex=None):
    """Scan, connect, authenticate, return session.

    Args:
        mac: BLE MAC address
        auth_key_hex: If provided, do first-activation using this auth key (hex string).
                      If None, reconnect using stored LOGIN_KEY.
    """
    log.info("Scanning for %s...", mac)
    scanner = BleakScanner(scanning_mode="active")
    await scanner.start()
    await asyncio.sleep(5.0)
    await scanner.stop()

    device = None
    svc_data = enc_id = None
    for d, adv in scanner.discovered_devices_and_advertisement_data.values():
        if d.address.upper() == mac.upper():
            device = d
            for suuid, sd in (adv.service_data or {}).items():
                if "fd50" in suuid:
                    svc_data = sd
            for mid, md in (adv.manufacturer_data or {}).items():
                if mid == 0x07D0 and len(md) >= 20:
                    enc_id = md[4:20]
            break

    if not device:
        log.error("Device not found!")
        return None, None

    uuid = decrypt_uuid(svc_data, enc_id)
    log.info("UUID: %s", uuid)

    client = None
    for attempt in range(5):
        try:
            client = BleakClient(device, timeout=30.0)
            await client.connect()
            # Verify service discovery completed
            _ = client.services
            break
        except Exception as e:
            log.warning("Connection attempt %d failed: %s", attempt + 1, e)
            if client and client.is_connected:
                await client.disconnect()
            client = None
            await asyncio.sleep(3.0)
    else:
        return None, None

    auth_key_bytes = bytes.fromhex(auth_key_hex) if auth_key_hex else None
    session = LockSession(client, LOGIN_KEY, auth_key=auth_key_bytes)
    await client.start_notify(FD50_NOTIFY, session.on_notify)
    await asyncio.sleep(0.3)

    if auth_key_hex:
        # --- First activation: unencrypted device info, then encrypted pair ---
        log.info("First activation using auth key: %s", auth_key_hex)

        # Device info is UNENCRYPTED (sec_flag=0) for unbound devices.
        # Build and send manually since encrypt_frame always uses AES-CBC.
        session.notifs.clear()
        inner = struct.pack(">IIHH", session.sn, 0, CMD_DEVICE_INFO, 2) + struct.pack(">H", 20)
        inner += struct.pack(">H", crc16(inner))
        payload = bytes([0x00]) + inner  # sec_flag=0, no IV
        hdr = varint_encode(0) + varint_encode(len(payload)) + bytes([0x40])
        await client.write_gatt_char(FD50_WRITE, hdr + payload, response=False)
        session.sn += 1
        log.info("CMD_DEVICE_INFO sent (unencrypted), waiting...")
        await asyncio.sleep(4.0)

        raw = list(session.notifs)
        session.notifs.clear()
        if not raw:
            log.error("No device info response!")
            return None, None

        # Parse unencrypted response: reassemble, then read raw inner frame
        p = reassemble(raw)[0]
        inner = p[1:]  # skip sec_flag=0 byte
        sn_r, ack_sn_r, cmd_r, dlen = struct.unpack(">IIHH", inner[:12])
        data = inner[12:12 + dlen]
        log.info("Device info: cmd=0x%04X len=%d data=%s", cmd_r, dlen, data.hex())

        srand = data[6:12]
        bound = data[5]
        log.info("Bound=%s, srand=%s", "YES" if bound else "NO", srand.hex())
        session.derive_session(srand, auth_key=auth_key_bytes)

        # Generate new login key and pair
        new_login_key = secrets.token_bytes(6)
        new_virtual_id = secrets.token_bytes(22)
        pair_data = uuid.encode()[:16] + new_login_key + new_virtual_id
        pair_data = (pair_data + b"\x00" * 44)[:44]

        # Try pairing with different security flags
        pair_success = False
        for try_flag in [2, 1, 0]:
            log.info("Trying pair with sec_flag=%d, loginKey=%s", try_flag, new_login_key.hex())
            if try_flag == 0:
                # Unencrypted pair — build manually
                session.notifs.clear()
                p_inner = struct.pack(">IIHH", session.sn, 0, CMD_PAIR, len(pair_data))
                p_inner += pair_data
                p_inner += struct.pack(">H", crc16(p_inner))
                p_payload = bytes([0x00]) + p_inner
                # Fragment the payload
                frags_to_send = []
                f_offset = 0
                f_idx = 0
                while f_offset < len(p_payload):
                    fhdr = varint_encode(f_idx)
                    if f_idx == 0:
                        fhdr += varint_encode(len(p_payload))
                        fhdr += bytes([0x40])
                    chunk = p_payload[f_offset:f_offset + 20 - len(fhdr)]
                    frags_to_send.append(fhdr + chunk)
                    f_offset += len(chunk)
                    f_idx += 1
                for f in frags_to_send:
                    await client.write_gatt_char(FD50_WRITE, f, response=False)
                    await asyncio.sleep(0.05)
                session.sn += 1
                await asyncio.sleep(5.0)
                raw_resp = list(session.notifs)
                session.notifs.clear()
                if raw_resp:
                    log.info("Got %d notifications for sec_flag=0 pair", len(raw_resp))
                    p_msgs = reassemble(raw_resp)
                    log.info("Reassembled %d messages", len(p_msgs))
                    # The device may respond encrypted even to unencrypted request.
                    # Try decrypting with the NEW session key (derived from new loginKey + srand)
                    new_session_key = hashlib.md5(new_login_key + srand).digest()
                    new_key4 = hashlib.md5(new_login_key).digest()
                    trial_keys = {0: b'\x00' * 16, 4: new_key4, 5: new_session_key,
                                  1: auth_key_bytes, 2: session.keys.get(2, b'\x00' * 16)}
                    for mi, p0 in enumerate(p_msgs):
                        sec_byte = p0[0]
                        log.info("  msg[%d]: sec_flag=%d len=%d hex=%s",
                                 mi, sec_byte, len(p0), p0.hex()[:80])
                        if sec_byte == 0:
                            # Unencrypted response
                            p_inner_r = p0[1:]
                            if len(p_inner_r) >= 12:
                                _, _, cmd_r, dlen_r = struct.unpack(">IIHH", p_inner_r[:12])
                                d = p_inner_r[12:12 + dlen_r]
                                log.info("    cmd=0x%04X data=%s", cmd_r, d.hex() if d else "")
                                if cmd_r == CMD_PAIR and d and d[0] == 0:
                                    pair_success = True
                        else:
                            # Encrypted — try all keys
                            f = decrypt_frame(p0, trial_keys)
                            if f:
                                log.info("    Decrypted: cmd=0x%04X data=%s",
                                         f["cmd"], f["data"].hex() if f["data"] else "")
                                if f["cmd"] == CMD_PAIR and f["data"] and f["data"][0] == 0:
                                    pair_success = True
                            else:
                                log.info("    Could not decrypt (tried all keys)")
                    if pair_success:
                        break
                else:
                    log.info("  No response for sec_flag=0")
            else:
                if try_flag not in session.keys:
                    log.info("  Skipping sec_flag=%d (no key)", try_flag)
                    continue
                session.notifs.clear()
                frames = await session.send_recv(CMD_PAIR, pair_data, sec_flag=try_flag, wait=8.0)
                if frames:
                    status = frames[0]["data"][0] if frames[0]["data"] else -1
                    log.info("  Pair status: %d (%s)", status,
                             {0: "OK", 2: "ALREADY_BOUND"}.get(status, "ERROR"))
                    if status == 0:
                        pair_success = True
                        await session.handle_time_requests(frames[1:] if len(frames) > 1 else [])
                        break
                    await session.handle_time_requests(frames[1:] if len(frames) > 1 else [])
                else:
                    # Check raw notifications (maybe decrypt failed)
                    raw_resp = list(session.notifs)
                    session.notifs.clear()
                    if raw_resp:
                        log.info("  Got %d raw notifs but decrypt failed", len(raw_resp))
                        for rn in raw_resp:
                            log.info("    raw: %s", rn.hex())
                    else:
                        log.info("  No response for sec_flag=%d", try_flag)

        if pair_success:
            log.info("=== PAIR SUCCESS! NEW CREDENTIALS ===")
            log.info("LOGIN_KEY = bytes.fromhex(\"%s\")", new_login_key.hex())
            log.info("VIRTUAL_ID = bytes.fromhex(\"%s\")", new_virtual_id.hex())
            session.login_key = new_login_key
            session.keys[4] = hashlib.md5(new_login_key).digest()
            session.derive_session(srand)
        else:
            log.error("Pairing failed with all security flags!")
            return None, None
    else:
        # --- Reconnect using stored LOGIN_KEY ---
        frames = await session.send_recv(CMD_DEVICE_INFO, struct.pack(">H", 20), sec_flag=4)
        if not frames:
            log.error("No device info response!")
            return None, None

        data = frames[0]["data"]
        srand = data[6:12]
        bound = data[5]
        session.derive_session(srand)
        log.info("Bound=%s, session key derived", "YES" if bound else "NO")
        await session.handle_time_requests(frames[1:] if len(frames) > 1 else [])

        pair_data = uuid.encode()[:16] + LOGIN_KEY + VIRTUAL_ID[:22]
        pair_data = (pair_data + b"\x00" * 44)[:44]
        frames = await session.send_recv(CMD_PAIR, pair_data, sec_flag=5)
        if frames:
            status = frames[0]["data"][0] if frames[0]["data"] else -1
            log.info("Pair status: %d (%s)", status,
                     {0: "OK", 2: "ALREADY_BOUND"}.get(status, "ERROR"))
            await session.handle_time_requests(frames[1:] if len(frames) > 1 else [])

    # Collect any unsolicited messages
    extra = await session.collect(timeout=2.0)
    await session.handle_time_requests(extra)

    return client, session


def build_v4_dp(dp_id, dp_type, value):
    """Build V4 DP write payload: [version(1)][reserved(4)][dp_id(1)][type(1)][len(2)][value]."""
    header = b'\x00\x00\x00\x00\x00'
    return header + struct.pack(">BBH", dp_id & 0xFF, dp_type, len(value)) + value


async def send_dp_and_report(session, dp_data, label):
    """Send a V4 DP write and log results."""
    frames = await session.send_recv(CMD_DP_WRITE_V4, dp_data, sec_flag=5)
    if frames:
        resp = frames[0]
        ok = resp["data"] == b'\x00\x00\x00\x00\x00\x00'
        log.info("%s: %s", label, "SUCCESS" if ok else f"response={resp['data'].hex()}")
        await session.handle_time_requests(frames[1:])
    else:
        log.error("No response to %s command!", label)

    reports = await session.collect(timeout=3.0)
    for f in reports:
        if f["cmd"] == CMD_DP_REPORT_V4:
            for dp in parse_dp_report(f["data"]):
                log.info("  %s", format_dp(dp))


async def do_unlock(session):
    """Send unlock command (DP 1 = BOOL TRUE)."""
    await send_dp_and_report(session, build_v4_dp(1, 1, b'\x01'), "Unlock")


async def do_lock(session):
    """Send lock command (DP 1 = BOOL FALSE)."""
    await send_dp_and_report(session, build_v4_dp(1, 1, b'\x00'), "Lock")


# -- DP 71 (ble_unlock_check) unlock/lock -------
# Payload format (19 bytes):
#   [00 01]       version/header (2B)
#   [ff ff]       member_id (2B, 0xFFFF = admin/all)
#   [8B ASCII]    check code (e.g., "01700413")
#   [01]          action: 01=unlock, 00=lock (1B)
#   [4B BE]       Unix timestamp in seconds (4B big-endian)
#   [00 00]       padding (2B)

DEFAULT_CHECK_CODE = b"00000000"  # device does NOT validate — any 8 bytes work


def build_dp71_payload(action_unlock=True, check_code=None, member_id=0xFFFF):
    """Build DP 71 (ble_unlock_check) RAW payload."""
    code = check_code or DEFAULT_CHECK_CODE
    if isinstance(code, str):
        code = code.encode()
    # Pad or truncate to 8 bytes
    code = (code + b'\x00' * 8)[:8]
    ts = int(time.time())
    payload = struct.pack(">HH", 1, member_id)  # version=1, member_id
    payload += code                               # 8-byte check code
    payload += bytes([0x01 if action_unlock else 0x00])  # action
    payload += struct.pack(">I", ts)              # timestamp
    payload += b'\x00\x00'                        # padding
    return payload


async def do_unlock_dp71(session, check_code=None):
    """Unlock using DP 71 (ble_unlock_check). Works even when beep_volume is muted."""
    payload = build_dp71_payload(action_unlock=True, check_code=check_code)
    log.info("DP 71 unlock payload: %s", payload.hex())
    await send_dp_and_report(session, build_v4_dp(71, 0, payload), "Unlock (DP 71)")


async def do_lock_dp71(session, check_code=None):
    """Lock using DP 71 (ble_unlock_check)."""
    payload = build_dp71_payload(action_unlock=False, check_code=check_code)
    log.info("DP 71 lock payload: %s", payload.hex())
    await send_dp_and_report(session, build_v4_dp(71, 0, payload), "Lock (DP 71)")


async def do_auto_lock(session, on):
    """Enable/disable auto-lock (DP 33 = BOOL)."""
    await send_dp_and_report(session, build_v4_dp(33, 1, b'\x01' if on else b'\x00'),
                             f"Auto-lock {'ON' if on else 'OFF'}")


async def do_volume(session, level):
    """Set beep volume (DP 31 = ENUM). WARNING: mute(0) disables motor on this firmware!"""
    val = struct.pack(">B", VOLUME_LEVELS[level])
    await send_dp_and_report(session, build_v4_dp(31, 4, val),
                             f"Volume {level}")


async def do_double_lock(session, on):
    """Enable/disable electronic double lock (DP 79 = BOOL)."""
    await send_dp_and_report(session, build_v4_dp(79, 1, b'\x01' if on else b'\x00'),
                             f"Double lock {'ON' if on else 'OFF'}")


async def do_raw_dp(session, dp_id, dp_type, value_hex):
    """Write an arbitrary DP."""
    val = bytes.fromhex(value_hex)
    await send_dp_and_report(session, build_v4_dp(dp_id, dp_type, val),
                             f"DP {dp_id} (type={dp_type})")


CRED_TYPE_NAMES = {0x01: "password", 0x02: "card", 0x03: "fingerprint", 0x04: "face"}



# -- Credential enrollment --------------------------------------------------

# Credential type codes
CRED_TYPES = {"password": 0x01, "card": 0x02, "fingerprint": 0x03, "face": 0x04}

# Enrollment stage codes
STAGE_START = 0x00
STAGE_PROGRESS = 0xFC
STAGE_FAILED = 0xFD
STAGE_CANCEL = 0xFE
STAGE_DONE = 0xFF

STAGE_NAMES = {
    0x00: "STARTED", 0xFC: "IN_PROGRESS", 0xFD: "FAILED",
    0xFE: "CANCELLED", 0xFF: "COMPLETE",
}


def build_validity_permanent():
    """Build 17-byte validity block for permanent access.

    Permanent access: 2000-01-01 to 2030-12-31, no recurrence.
    """
    return (
        struct.pack(">I", 0x386CD300)   # start: 2000-01-01 00:00:00 UTC
        + struct.pack(">I", 0x72BC9B7F) # end:   2030-12-31 23:59:59 UTC
        + b'\x00'                        # pattern: no recurrence
        + b'\x00\x00\x00\x00'           # recurring bits: none
        + b'\x00\x00'                    # period start: 00:00
        + b'\x17\x3b'                    # period end: 23:59
    )


def build_enroll_payload(cred_type, member_id, admin=False, password_digits=None):
    """Build DP 1 (unlock_method_create) RAW payload.

    Format: type, stage, admin, member, hw_id, validity, times, pwd_len, pwd_data.

    Args:
        cred_type: 0x01=password, 0x02=card, 0x03=fingerprint, 0x04=face
        member_id: 1-100 (0xFF = bound account admin)
        admin: True for admin credential
        password_digits: list of ints 0-9 for password type, None otherwise
    """
    pwd = bytes(password_digits) if password_digits else b''
    payload = bytes([
        cred_type,
        STAGE_START,
        0x01 if admin else 0x00,
        member_id & 0xFF,
        0xFF,  # hardware ID: auto-assign
    ])
    payload += build_validity_permanent()
    payload += bytes([
        0x00,       # times: permanent
        len(pwd),   # password length
    ])
    payload += pwd
    return payload


def parse_enroll_response(raw):
    """Parse DP 1 enrollment response from device.

    Format: [type:1][stage:1][admin:1][member:1][hw_id:1][count:1][result:1]
    Stages: 0x00=START, 0xFC=PROGRESS, 0xFF=DONE
    """
    if len(raw) < 7:
        return {"raw": raw.hex()}
    return {
        "type": CRED_TYPES.get(raw[0]) or f"0x{raw[0]:02x}",
        "stage": STAGE_NAMES.get(raw[1], f"0x{raw[1]:02x}"),
        "admin": bool(raw[2]),
        "member_id": raw[3],
        "hw_id": raw[4],
        "count": raw[5],
        "result": "OK" if raw[6] == 0x00 else f"err=0x{raw[6]:02x}",
    }


async def send_sync_marker(session):
    """Send DP 54 (synch_method) sync marker before credential operations.

    Sends 0x030102 before biometric enrollment to prepare the lock.
    """
    dp_data = build_v4_dp(54, 0, b'\x03\x01\x02')  # DP 54, type RAW
    log.debug("Sending DP 54 sync marker (030102)")
    frames = await session.send_recv(CMD_DP_WRITE_V4, dp_data, sec_flag=5, wait=3.0)
    for f in frames:
        if f["cmd"] == CMD_DP_REPORT_V4:
            for dp in parse_dp_report(f["data"]):
                log.debug("  Sync response: %s", format_dp(dp))


async def do_add_pin(session, member_id, digits, admin=False):
    """Add a PIN code to the lock (single exchange)."""
    pin_bytes = [int(d) for d in digits]
    for d in pin_bytes:
        if d < 0 or d > 9:
            log.error("PIN digits must be 0-9")
            return
    payload = build_enroll_payload(0x01, member_id, admin=admin, password_digits=pin_bytes)
    log.info("Adding PIN for member %d: %s (%d digits)", member_id, digits, len(pin_bytes))
    dp_data = build_v4_dp(1, 0, payload)  # dp_type=0 (RAW)
    frames = await session.send_recv(CMD_DP_WRITE_V4, dp_data, sec_flag=5, wait=10.0)

    for f in frames:
        if f["cmd"] == CMD_DP_REPORT_V4:
            for dp in parse_dp_report(f["data"]):
                if dp["id"] == 1 and dp["type"] == 0:
                    resp = parse_enroll_response(dp["raw"])
                    log.info("  Enrollment response: %s", resp)
                else:
                    log.info("  %s", format_dp(dp))
        else:
            await session.handle_time_requests([f])

    reports = await session.collect(timeout=3.0)
    for f in reports:
        if f["cmd"] == CMD_DP_REPORT_V4:
            for dp in parse_dp_report(f["data"]):
                if dp["id"] == 1 and dp["type"] == 0:
                    resp = parse_enroll_response(dp["raw"])
                    log.info("  Enrollment response: %s", resp)
                else:
                    log.info("  %s", format_dp(dp))


async def do_add_fingerprint(session, member_id, admin=False):
    """Start fingerprint enrollment (multi-step, device-driven touch count)."""
    await send_sync_marker(session)
    payload = build_enroll_payload(0x03, member_id, admin=admin)
    log.info("Starting fingerprint enrollment for member %d", member_id)
    log.info("Place your finger on the sensor when prompted (typically 4 touches)...")
    dp_data = build_v4_dp(1, 0, payload)  # dp_type=0 (RAW)
    frames = await session.send_recv(CMD_DP_WRITE_V4, dp_data, sec_flag=5, wait=10.0)

    for f in frames:
        if f["cmd"] == CMD_DP_REPORT_V4:
            for dp in parse_dp_report(f["data"]):
                if dp["id"] == 1 and dp["type"] == 0:
                    resp = parse_enroll_response(dp["raw"])
                    log.info("  Enrollment: %s", resp)
                else:
                    log.info("  %s", format_dp(dp))
        else:
            await session.handle_time_requests([f])

    # Wait for touches (up to 60s total — user must place finger each time)
    log.info("Waiting for finger touches (up to 60s)...")
    deadline = asyncio.get_event_loop().time() + 60.0
    done = False
    while not done and asyncio.get_event_loop().time() < deadline:
        reports = await session.collect(timeout=5.0)
        for f in reports:
            if f["cmd"] == CMD_DP_REPORT_V4:
                for dp in parse_dp_report(f["data"]):
                    if dp["id"] == 1 and dp["type"] == 0:
                        resp = parse_enroll_response(dp["raw"])
                        log.info("  Enrollment: %s", resp)
                        if resp["stage"] in ("COMPLETE", "FAILED", "CANCELLED"):
                            done = True
                    else:
                        log.info("  %s", format_dp(dp))
            else:
                await session.handle_time_requests([f])

    if not done:
        log.warning("Enrollment timed out (no completion response in 60s)")


async def do_add_card(session, member_id, admin=False):
    """Start card enrollment (single capture: tap card once)."""
    await send_sync_marker(session)
    payload = build_enroll_payload(0x02, member_id, admin=admin)
    log.info("Starting card enrollment for member %d", member_id)
    log.info("Tap your card on the sensor...")
    dp_data = build_v4_dp(1, 0, payload)  # dp_type=0 (RAW)
    frames = await session.send_recv(CMD_DP_WRITE_V4, dp_data, sec_flag=5, wait=15.0)

    for f in frames:
        if f["cmd"] == CMD_DP_REPORT_V4:
            for dp in parse_dp_report(f["data"]):
                if dp["id"] == 1 and dp["type"] == 0:
                    resp = parse_enroll_response(dp["raw"])
                    log.info("  Enrollment: %s", resp)
                else:
                    log.info("  %s", format_dp(dp))
        else:
            await session.handle_time_requests([f])

    # Wait for card tap (up to 30s)
    log.info("Waiting for card tap (up to 30s)...")
    deadline = asyncio.get_event_loop().time() + 30.0
    done = False
    while not done and asyncio.get_event_loop().time() < deadline:
        reports = await session.collect(timeout=5.0)
        for f in reports:
            if f["cmd"] == CMD_DP_REPORT_V4:
                for dp in parse_dp_report(f["data"]):
                    if dp["id"] == 1 and dp["type"] == 0:
                        resp = parse_enroll_response(dp["raw"])
                        log.info("  Enrollment: %s", resp)
                        if resp["stage"] in ("COMPLETE", "FAILED", "CANCELLED"):
                            done = True
                    else:
                        log.info("  %s", format_dp(dp))
            else:
                await session.handle_time_requests([f])

    if not done:
        log.warning("Enrollment timed out")


async def do_delete_method(session, member_id, cred_type, hw_id):
    """Delete a credential from the lock (DP 2 = RAW)."""
    payload = bytes([
        cred_type,
        0x00,       # stage
        0x00,       # admin flag
        member_id & 0xFF,
        hw_id & 0xFF,
        0x01,       # deletion method: single
    ])
    type_name = {v: k for k, v in CRED_TYPES}.get(cred_type, f"type={cred_type}")
    log.info("Deleting %s for member %d, hw_id %d", type_name, member_id, hw_id)
    dp_data = build_v4_dp(2, 0, payload)  # DP 2, type RAW
    frames = await session.send_recv(CMD_DP_WRITE_V4, dp_data, sec_flag=5, wait=10.0)

    for f in frames:
        if f["cmd"] == CMD_DP_REPORT_V4:
            for dp in parse_dp_report(f["data"]):
                log.info("  %s", format_dp(dp))
        else:
            await session.handle_time_requests([f])

    reports = await session.collect(timeout=3.0)
    for f in reports:
        if f["cmd"] == CMD_DP_REPORT_V4:
            for dp in parse_dp_report(f["data"]):
                log.info("  %s", format_dp(dp))


def parse_sync_bitmap(raw):
    """Parse credential partition bitmap: [partition_id(1)][bitmap(1)] pairs.

    Each partition holds 8 credential slots.
    Credential index = (partition_id - 1) * 8 + bit_position.
    """
    if len(raw) < 2 or raw == b'\x00\x00':
        return []
    creds = []
    pos = 0
    while pos + 1 < len(raw):
        part_id = raw[pos]
        bitmap = raw[pos + 1]
        pos += 2
        if part_id == 0 and bitmap == 0:
            continue
        for bit in range(8):
            if bitmap & (1 << bit):
                creds.append((part_id - 1) * 8 + bit)
    return creds


async def do_sync(session, cred_type_name=None):
    """Query lock's credential database via DP 54 synch_method.

    Writes an 'ins' byte (credential type) to DP 54 and listens
    for the bitmap response on ALL DPs.
    """
    types_to_query = (
        [(cred_type_name, CRED_TYPES[cred_type_name])]
        if cred_type_name
        else [("fingerprint", 0x03), ("password", 0x01), ("card", 0x02)]
    )

    for name, utype in types_to_query:
        log.info("--- Sync %s (ins=0x%02x) ---", name, utype)

        # Write single ins byte to DP 54
        dp_data = build_v4_dp(54, 0, bytes([utype]))
        frames = await session.send_recv(CMD_DP_WRITE_V4, dp_data, sec_flag=5, wait=10.0)

        for f in frames:
            cmd = f["cmd"]
            data = f["data"]
            if cmd == CMD_DP_REPORT_V4:
                for dp in parse_dp_report(data):
                    log.info("  %s", format_dp(dp))
                    if dp["type"] == 0 and dp["id"] != 520:  # RAW, not battery
                        creds = parse_sync_bitmap(dp["raw"])
                        if creds:
                            log.info("    -> Credential slots: %s", creds)
            elif cmd in (CMD_TIME_V1, CMD_TIME_V2):
                await session.handle_time_requests([f])
            else:
                log.info("  Frame cmd=0x%04X len=%d data=%s",
                         cmd, len(data), data.hex()[:120])

        # Collect additional reports with extended timeout
        reports = await session.collect(timeout=8.0)
        for f in reports:
            cmd = f["cmd"]
            data = f["data"]
            if cmd == CMD_DP_REPORT_V4:
                for dp in parse_dp_report(data):
                    log.info("  %s", format_dp(dp))
                    if dp["type"] == 0 and dp["id"] != 520:
                        creds = parse_sync_bitmap(dp["raw"])
                        if creds:
                            log.info("    -> Credential slots: %s", creds)
            elif cmd not in (CMD_TIME_V1, CMD_TIME_V2):
                log.info("  Frame cmd=0x%04X len=%d data=%s",
                         cmd, len(data), data.hex()[:120])


async def do_listen(session, duration_minutes=10):
    """Stay connected and log ALL unsolicited DP reports from the lock.

    This helps discover what the lock broadcasts and how often (battery, state, etc.).
    Press Ctrl+C to stop early.
    """
    duration_secs = duration_minutes * 60
    start = time.time()
    report_count = 0
    dp_seen = {}  # dp_id -> list of (timestamp, value)

    log.info("=== LISTENING for %d minutes (Ctrl+C to stop) ===", duration_minutes)
    log.info("Connected at %s", time.strftime("%H:%M:%S"))

    try:
        while time.time() - start < duration_secs:
            elapsed = time.time() - start
            # Check for notifications every 0.5s
            await asyncio.sleep(0.5)

            if not session.client.is_connected:
                log.warning("[%5.0fs] BLE disconnected!", elapsed)
                break

            if not session.notifs:
                continue

            # Process accumulated notifications
            await asyncio.sleep(0.3)  # let any remaining fragments arrive
            raw = list(session.notifs)
            session.notifs.clear()

            payloads = reassemble(raw)
            for p in payloads:
                f = decrypt_frame(p, session.keys)
                if not f:
                    log.info("[%5.0fs] Undecryptable frame: %d bytes, hex=%s",
                             elapsed, len(p), p.hex()[:60])
                    continue

                cmd = f["cmd"]
                data = f["data"]
                ts_str = time.strftime("%H:%M:%S")

                if cmd in (CMD_TIME_V1, CMD_TIME_V2):
                    log.info("[%5.0fs] %s Time request (cmd=0x%04X) — responding",
                             elapsed, ts_str, cmd)
                    await session.handle_time_requests([f])
                elif cmd == CMD_DP_REPORT_V4:
                    dps = parse_dp_report(data)
                    for dp in dps:
                        report_count += 1
                        dp_id = dp["id"]
                        val_str = format_dp(dp)
                        log.info("[%5.0fs] %s DP REPORT #%d: %s",
                                 elapsed, ts_str, report_count, val_str)
                        if dp_id not in dp_seen:
                            dp_seen[dp_id] = []
                        dp_seen[dp_id].append((elapsed, dp["raw"].hex()))
                else:
                    log.info("[%5.0fs] %s Frame cmd=0x%04X len=%d data=%s",
                             elapsed, ts_str, cmd, len(data), data.hex()[:80])

            # Periodic status line every 60s
            if int(elapsed) % 60 == 0 and int(elapsed) > 0 and elapsed - int(elapsed) < 0.6:
                log.info("[%5.0fs] Still listening... %d reports so far, DPs seen: %s",
                         elapsed, report_count, list(dp_seen.keys()) if dp_seen else "none")

    except KeyboardInterrupt:
        log.info("Interrupted by user")

    elapsed = time.time() - start
    log.info("=== LISTEN COMPLETE: %.0fs, %d DP reports ===", elapsed, report_count)
    if dp_seen:
        log.info("Summary of DPs received:")
        for dp_id, entries in sorted(dp_seen.items()):
            name = KNOWN_DPS.get(dp_id, "unknown")
            log.info("  DP %d (%s): %d reports", dp_id, name, len(entries))
            for t, val in entries:
                log.info("    @ %.0fs: %s", t, val)
    else:
        log.info("No DP reports received during the listening period.")


async def do_listen_test(session):
    """Listen while sending unlock/lock commands to observe state change DPs.

    Timeline: connect → wait 10s → unlock71 → wait 20s → lock71 → wait 20s → summary
    """
    start = time.time()
    report_count = 0
    dp_seen = {}

    async def drain_and_log(label, wait_secs):
        nonlocal report_count
        deadline = time.time() + wait_secs
        while time.time() < deadline:
            await asyncio.sleep(0.5)
            if not session.client.is_connected:
                log.warning("[%s] BLE disconnected!", label)
                return
            if not session.notifs:
                continue
            await asyncio.sleep(0.3)
            raw = list(session.notifs)
            session.notifs.clear()
            for p in reassemble(raw):
                f = decrypt_frame(p, session.keys)
                if not f:
                    log.info("[%s] Undecryptable: %d bytes", label, len(p))
                    continue
                elapsed = time.time() - start
                cmd = f["cmd"]
                data = f["data"]
                if cmd in (CMD_TIME_V1, CMD_TIME_V2):
                    log.info("[%5.0fs] %s Time request — responding", elapsed, label)
                    await session.handle_time_requests([f])
                elif cmd == CMD_DP_REPORT_V4:
                    for dp in parse_dp_report(data):
                        report_count += 1
                        dp_id = dp["id"]
                        log.info("[%5.0fs] %s DP REPORT #%d: %s",
                                 elapsed, label, report_count, format_dp(dp))
                        if dp_id not in dp_seen:
                            dp_seen[dp_id] = []
                        dp_seen[dp_id].append((elapsed, dp["raw"].hex()))
                elif cmd == CMD_DP_WRITE_V4:
                    ok = data == b'\x00\x00\x00\x00\x00\x00'
                    log.info("[%5.0fs] %s CMD response: %s", elapsed, label,
                             "SUCCESS" if ok else data.hex())
                else:
                    log.info("[%5.0fs] %s Frame cmd=0x%04X data=%s",
                             elapsed, label, cmd, data.hex()[:80])

    log.info("=== LISTEN-TEST: unlock/lock with state observation ===")

    # Phase 1: initial listen
    log.info("Phase 1: Listening for 10s (baseline)...")
    await drain_and_log("BASELINE", 10)

    # Phase 2: unlock
    log.info("Phase 2: Sending UNLOCK (DP 71)...")
    session.notifs.clear()
    payload = build_dp71_payload(action_unlock=True)
    dp_data = build_v4_dp(71, 0, payload)
    await session.send(CMD_DP_WRITE_V4, dp_data, sec_flag=5)
    log.info("Phase 2: Listening for 60s after unlock...")
    await drain_and_log("AFTER_UNLOCK", 60)

    # Phase 3: lock
    log.info("Phase 3: Sending LOCK (DP 71)...")
    session.notifs.clear()
    payload = build_dp71_payload(action_unlock=False)
    dp_data = build_v4_dp(71, 0, payload)
    await session.send(CMD_DP_WRITE_V4, dp_data, sec_flag=5)
    log.info("Phase 3: Listening for 60s after lock...")
    await drain_and_log("AFTER_LOCK", 60)

    elapsed = time.time() - start
    log.info("=== LISTEN-TEST COMPLETE: %.0fs, %d DP reports ===", elapsed, report_count)
    if dp_seen:
        log.info("Summary of DPs received:")
        for dp_id, entries in sorted(dp_seen.items()):
            name = KNOWN_DPS.get(dp_id, "unknown")
            log.info("  DP %d (%s): %d reports", dp_id, name, len(entries))
            for t, val in entries:
                log.info("    @ %.0fs: %s", t, val)
    else:
        log.info("No DP reports received.")


async def do_status(session):
    """Query device status and report all DPs."""
    frames = await session.send_recv(CMD_DEVICE_STATUS, b"", sec_flag=5)
    if frames:
        log.info("Device status: %d", frames[0]["data"][0] if frames[0]["data"] else -1)

    # Collect all DP reports
    all_dps = []
    reports = await session.collect(timeout=5.0)
    for f in reports:
        if f["cmd"] == CMD_DP_REPORT_V4:
            for dp in parse_dp_report(f["data"]):
                all_dps.append(dp)
                log.info("  %s", format_dp(dp))
        elif f["cmd"] in (CMD_TIME_V1, CMD_TIME_V2):
            pass  # handled by collect
        else:
            log.info("  Other cmd=0x%04X: %s", f["cmd"], f["data"].hex())

    if not all_dps:
        log.info("  No DP reports received")


async def main():
    parser = argparse.ArgumentParser(description="Tuya BLE Lock Control")
    parser.add_argument("action",
                        choices=["pair", "unlock", "lock", "unlock71", "lock71",
                                 "status", "listen", "listen-test", "sync",
                                 "auto-lock", "volume", "double-lock",
                                 "add-pin", "add-fingerprint", "add-card", "delete-method", "dp"],
                        help="Action to perform")
    parser.add_argument("value", nargs="?", default=None,
                        help="Value for the action (on/off, seconds, volume level, member_id, etc.)")
    parser.add_argument("extra", nargs="*",
                        help="Extra args: PIN digits for add-pin, TYPE HW_ID for delete-method, etc.")
    parser.add_argument("--mac", default=DEFAULT_MAC, help="Device MAC address")
    parser.add_argument("--auth-key", type=str, help="Auth key hex for first activation pairing")
    parser.add_argument("--admin", action="store_true", help="Set admin flag for credential enrollment")
    parser.add_argument("--duration", type=int, default=2, help="Listen duration in minutes (default: 2)")
    args = parser.parse_args()

    # Validate args for commands that need a value
    on_off_cmds = {"auto-lock", "double-lock"}
    if args.action in on_off_cmds:
        if args.value not in ("on", "off"):
            parser.error(f"{args.action} requires 'on' or 'off'")
    elif args.action == "volume":
        if args.value not in VOLUME_LEVELS:
            parser.error(f"volume requires one of: {', '.join(VOLUME_LEVELS)}")
    elif args.action == "add-pin":
        if args.value is None or not args.extra:
            parser.error("add-pin requires: MEMBER_ID PIN_DIGITS (e.g., add-pin 1 123456)")
        if not args.extra[0].isdigit():
            parser.error("PIN must be numeric digits")
    elif args.action in ("add-fingerprint", "add-card"):
        if args.value is None or not args.value.isdigit():
            parser.error(f"{args.action} requires: MEMBER_ID (e.g., {args.action} 1)")
    elif args.action == "delete-method":
        if args.value is None or len(args.extra) < 2:
            parser.error("delete-method requires: MEMBER_ID TYPE HW_ID "
                         "(TYPE: password/card/fingerprint/face, e.g., delete-method 1 password 0)")
    elif args.action == "sync":
        if args.value and args.value not in CRED_TYPES:
            parser.error(f"sync type must be one of: {', '.join(CRED_TYPES)} (or omit for all)")
    elif args.action == "dp":
        if args.value is None or len(args.extra) < 2:
            parser.error("dp requires: DP_ID TYPE VALUE_HEX (e.g., dp 33 1 01)")

    # Determine auth key: use --auth-key for 'pair' command
    auth_key_hex = args.auth_key if args.action == "pair" else None
    if args.action == "pair" and not auth_key_hex:
        parser.error("pair requires --auth-key AUTH_KEY_HEX")

    async def run_action(session):
        if args.action == "pair":
            log.info("Pairing complete — update LOGIN_KEY and VIRTUAL_ID in this script")
            return
        elif args.action == "unlock":
            await do_unlock(session)
        elif args.action == "lock":
            await do_lock(session)
        elif args.action == "unlock71":
            code = args.value.encode() if args.value else None
            await do_unlock_dp71(session, check_code=code)
        elif args.action == "lock71":
            code = args.value.encode() if args.value else None
            await do_lock_dp71(session, check_code=code)
        elif args.action == "status":
            await do_status(session)
        elif args.action == "listen":
            await do_listen(session, duration_minutes=args.duration)
        elif args.action == "listen-test":
            await do_listen_test(session)
        elif args.action == "auto-lock":
            await do_auto_lock(session, args.value == "on")
        elif args.action == "volume":
            await do_volume(session, args.value)
        elif args.action == "double-lock":
            await do_double_lock(session, args.value == "on")
        elif args.action == "add-pin":
            await do_add_pin(session, int(args.value), args.extra[0], admin=args.admin)
        elif args.action == "add-fingerprint":
            await do_add_fingerprint(session, int(args.value), admin=args.admin)
        elif args.action == "add-card":
            await do_add_card(session, int(args.value), admin=args.admin)
        elif args.action == "delete-method":
            ctype = CRED_TYPES.get(args.extra[0])
            if ctype is None:
                log.error("Unknown type '%s'. Use: %s", args.extra[0], ", ".join(CRED_TYPES))
                return
            await do_delete_method(session, int(args.value), ctype, int(args.extra[1]))
        elif args.action == "sync":
            await do_sync(session, args.value)  # value = credential type name or None for all
        elif args.action == "dp":
            await do_raw_dp(session, int(args.value), int(args.extra[0]), args.extra[1])

    from bleak.exc import BleakError
    for attempt in range(3):
        client, session = await connect_and_setup(args.mac, auth_key_hex=auth_key_hex)
        if not client or not session:
            return
        try:
            await run_action(session)
            break
        except BleakError as e:
            log.warning("BLE error (attempt %d/3): %s", attempt + 1, e)
            try:
                if client.is_connected:
                    await client.disconnect()
            except Exception:
                pass
            if attempt < 2:
                log.info("Reconnecting...")
                await asyncio.sleep(2.0)
            else:
                log.error("Failed after 3 attempts")
        finally:
            try:
                if client and client.is_connected:
                    await client.stop_notify(FD50_NOTIFY)
                    await client.disconnect()
            except Exception:
                pass


if __name__ == "__main__":
    asyncio.run(main())
