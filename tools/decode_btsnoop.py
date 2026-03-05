#!/usr/bin/env python3
"""Decode Tuya BLE protocol frames from btsnoop_hci.log captures.

Supports both standard (Android/Linux btmon) and Apple PacketLogger btsnoop formats.

Usage:
    # Decode with known login key (hex of the raw login key bytes):
    python3 decode_btsnoop.py capture.btsnoop --login-key AABBCCDDEEFF

    # Decode with cloud localKey (ASCII, first 6 chars become login key):
    python3 decode_btsnoop.py capture.btsnoop --local-key 'YourLocalKey1234'

    # Just extract raw ATT data (no decryption):
    python3 decode_btsnoop.py capture.btsnoop --raw-only

How to capture:
    iOS (Apple PacketLogger — requires paid Apple Developer account):
    1. Download the Bluetooth logging profile from developer.apple.com
    2. Install the profile on your iOS device (Settings → General → VPN & Device Management)
    3. Install PacketLogger from Xcode Additional Tools
    4. Capture, then File → Export as btsnoop
    5. python3 decode_btsnoop.py capture.btsnoop --login-key HEX

    Android:
    1. Settings → Developer Options → Enable "Bluetooth HCI snoop log"
    2. adb pull /sdcard/btsnoop_hci.log
    3. python3 decode_btsnoop.py btsnoop_hci.log --login-key HEX

    Linux (btmon):
    sudo btmon -w capture.btsnoop &
    python3 decode_btsnoop.py capture.btsnoop --login-key HEX
"""

import argparse
import hashlib
import struct
import sys
from datetime import datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# --- Tuya BLE constants ---

TUYA_WRITE_HANDLE = 0x001D  # Default; overridden by auto-detection
TUYA_NOTIFY_HANDLE = 0x001F  # Default; overridden by auto-detection

CMD_NAMES = {
    0x0000: "DEVICE_INFO",
    0x0001: "PAIR",
    0x0002: "SEND_DPS",
    0x0003: "QUERY_STATUS",
    0x0005: "UNBIND",
    0x0006: "DEVICE_RESET",
    0x0020: "ECDH_KEY",
    0x0023: "DATA_TRANSFER",
    0x0027: "DP_WRITE_V4",
    0x7FFE: "TRANSPARENT",
    0x8001: "RECV_DP",
    0x8006: "DP_REPORT_V4",
    0x8011: "TIME_REQUEST_V1",
    0x8012: "TIME_REQUEST_V2",
}

SEC_NAMES = {
    0: "NONE",
    1: "AUTH_KEY",
    2: "AUTH_SESSION",
    4: "LOGIN_KEY",
    5: "SESSION_KEY",
    6: "COMM_KEY",
    14: "NEW_SEC",
    15: "NEW_SEC_SESSION",
}

DP_TYPE_NAMES = {0: "RAW", 1: "BOOL", 2: "VALUE", 3: "STRING", 4: "ENUM", 5: "BITMAP"}

KNOWN_DPS = {
    1: "unlock_method_create",
    2: "unlock_method_delete",
    3: "unlock_method_modify",
    8: "residual_electricity",
    9: "battery_state",
    12: "unlock_fingerprint",
    13: "unlock_password",
    14: "unlock_dynamic",
    15: "unlock_card",
    18: "open_inside",
    19: "unlock_ble",
    20: "lock_record",
    21: "alarm_lock",
    24: "doorbell",
    31: "beep_volume",
    33: "automatic_lock",
    44: "rtc_lock",
    46: "manual_lock",
    47: "lock_motor_state",
    51: "temporary_password_creat",
    52: "temporary_password_delete",
    53: "temporary_password_modify",
    54: "synch_method",
    55: "unlock_temporary",
    61: "remote_no_dp_key",
    62: "unlock_phone_remote",
    63: "unlock_voice_remote",
    69: "record",
    70: "check_code_set",
    71: "ble_unlock_check",
    79: "electronic_double_lock",
    520: "battery_custom",
}


# --- CRC-16/MODBUS ---

def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


# --- Tuya BLE frame parsing ---

def decrypt_aes_cbc(key: bytes, iv: bytes, data: bytes) -> bytes | None:
    """Decrypt AES-128-CBC with no padding."""
    if len(data) == 0 or len(data) % 16 != 0:
        return None
    try:
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return dec.update(data) + dec.finalize()
    except Exception:
        return None


def parse_inner_frame(raw: bytes) -> dict | None:
    """Parse a decrypted inner frame: [SN:4][ACK_SN:4][CMD:2][DLEN:2][DATA:N][CRC:2]"""
    if len(raw) < 12:
        return None
    sn, ack_sn, cmd, dlen = struct.unpack(">IIHH", raw[:12])
    if 12 + dlen > len(raw):
        dlen = min(dlen, len(raw) - 12)
    data = raw[12:12 + dlen]
    return {
        "sn": sn,
        "ack_sn": ack_sn,
        "cmd": cmd,
        "data": data,
        "dlen": dlen,
    }


def try_decrypt_and_verify(payload: bytes, keys: dict[int, bytes]) -> dict | None:
    """Decrypt a Tuya BLE frame and verify CRC.

    Format: [sec_flag:1][IV:16][ciphertext:N]
    Returns parsed frame dict or None.
    """
    if len(payload) < 1:
        return None

    sec_flag = payload[0]

    if sec_flag == 0:
        frame = parse_inner_frame(payload[1:])
        if frame:
            frame["sec_flag"] = 0
        return frame

    if len(payload) < 17:
        return None

    iv = payload[1:17]
    enc = payload[17:]
    if len(enc) == 0 or len(enc) % 16 != 0:
        return None

    key = keys.get(sec_flag)
    if not key:
        return None

    raw = decrypt_aes_cbc(key, iv, enc)
    if raw is None or len(raw) < 12:
        return None

    frame = parse_inner_frame(raw)
    if not frame:
        return None

    # Verify CRC to confirm correct decryption
    dlen = frame["dlen"]
    if 12 + dlen + 2 <= len(raw):
        crc_stored = struct.unpack(">H", raw[12 + dlen:12 + dlen + 2])[0]
        crc_calc = crc16_modbus(raw[:12 + dlen])
        if crc_stored != crc_calc:
            return None  # Wrong key or corrupted data

    frame["sec_flag"] = sec_flag
    return frame


def parse_dp_report_v4(data: bytes) -> list[dict]:
    """Parse V4 DP report: [sn:4][flags:1][marker:1] then [dp_id:2][type:1][len:2][val:N]..."""
    if len(data) < 6:
        return []
    klv = data[6:]
    dps = []
    pos = 0
    while pos + 5 <= len(klv):
        dp_id = struct.unpack(">H", klv[pos:pos + 2])[0]
        dp_type = klv[pos + 2]
        dp_len = struct.unpack(">H", klv[pos + 3:pos + 5])[0]
        if pos + 5 + dp_len > len(klv):
            break
        val = klv[pos + 5:pos + 5 + dp_len]
        dps.append({"id": dp_id, "type": dp_type, "len": dp_len, "raw": val})
        pos += 5 + dp_len
    return dps


def parse_klv_v3(data: bytes) -> list[dict]:
    """Parse V3 KLV: [dp_id:1][type:1][len:1][val:N]... (1-byte length field)."""
    dps = []
    pos = 0
    while pos + 3 <= len(data):
        dp_id = data[pos]
        dp_type = data[pos + 1]
        dp_len = data[pos + 2]
        if pos + 3 + dp_len > len(data):
            break
        val = data[pos + 3:pos + 3 + dp_len]
        dps.append({"id": dp_id, "type": dp_type, "len": dp_len, "raw": val})
        pos += 3 + dp_len
    return dps


def parse_klv_v4(data: bytes) -> list[dict]:
    """Parse V4 KLV: [dp_id:1][type:1][len:2BE][val:N]... (2-byte length field)."""
    dps = []
    pos = 0
    while pos + 4 <= len(data):
        dp_id = data[pos]
        dp_type = data[pos + 1]
        dp_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        if pos + 4 + dp_len > len(data):
            break
        val = data[pos + 4:pos + 4 + dp_len]
        dps.append({"id": dp_id, "type": dp_type, "len": dp_len, "raw": val})
        pos += 4 + dp_len
    return dps


def parse_dp_write_v4(data: bytes) -> list[dict]:
    """Parse V4 DP write: [header:5B] then KLV."""
    if len(data) < 5:
        return []
    return parse_klv_v4(data[5:])


def format_dp(dp: dict) -> str:
    """Format a DP for display."""
    dp_id = dp["id"]
    dp_type = dp["type"]
    dp_name = KNOWN_DPS.get(dp_id, f"unknown_{dp_id}")
    type_name = DP_TYPE_NAMES.get(dp_type, f"type_{dp_type}")
    raw = dp["raw"]

    val_str = raw.hex()
    if dp_type == 1 and len(raw) == 1:  # BOOL
        val_str = "TRUE" if raw[0] else "FALSE"
    elif dp_type == 2 and len(raw) == 4:  # VALUE
        val_str = str(int.from_bytes(raw, "big"))
    elif dp_type == 2 and len(raw) == 1:  # VALUE (1 byte)
        val_str = str(raw[0])
    elif dp_type == 4 and len(raw) == 1:  # ENUM
        val_str = str(raw[0])

    extra = ""
    if dp_id == 71 and dp_type == 0 and len(raw) == 19:
        ver = struct.unpack(">H", raw[0:2])[0]
        member = struct.unpack(">H", raw[2:4])[0]
        code = raw[4:12].decode("ascii", errors="replace")
        action = "UNLOCK" if raw[12] == 1 else "LOCK" if raw[12] == 0 else f"?{raw[12]}"
        ts = struct.unpack(">I", raw[13:17])[0]
        ts_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts > 1000000000 else str(ts)
        extra = f'  [{action} member=0x{member:04x} code="{code}" time={ts_str}]'

    return f"DP {dp_id:>3d} ({dp_name:>22s}) [{type_name:>6s}] = {val_str}{extra}"


# --- BLE fragment reassembly ---

def reassemble_fragments(fragments: list[bytes]) -> list[bytes]:
    """Reassemble Tuya BLE fragmented messages.

    First fragment: [seq_varint=0][total_len_varint][type_byte][data...]
    Subsequent:     [seq_varint=N][data...]
    """
    if not fragments:
        return []

    messages = []
    current_data = bytearray()
    expected_total = 0

    for frag in fragments:
        if len(frag) < 2:
            continue

        pos = 0
        seq = 0
        shift = 0
        while pos < len(frag):
            b = frag[pos]
            seq |= (b & 0x7F) << shift
            pos += 1
            shift += 7
            if not (b & 0x80):
                break

        if seq == 0:
            if current_data and expected_total > 0:
                messages.append(bytes(current_data[:expected_total]))
            current_data = bytearray()

            total_len = 0
            shift = 0
            while pos < len(frag):
                b = frag[pos]
                total_len |= (b & 0x7F) << shift
                pos += 1
                shift += 7
                if not (b & 0x80):
                    break
            expected_total = total_len

            if pos < len(frag):
                pos += 1  # skip type byte

            current_data.extend(frag[pos:])
        else:
            current_data.extend(frag[pos:])

    if current_data and expected_total > 0:
        messages.append(bytes(current_data[:expected_total]))

    return messages


# --- btsnoop parser (standard + Apple PacketLogger) ---

BTSNOOP_MAGIC = b"btsnoop\x00"
BTSNOOP_EPOCH = datetime(2000, 1, 1)


def parse_btsnoop(filepath: str):
    """Parse btsnoop file and yield HCI packets."""
    with open(filepath, "rb") as f:
        magic = f.read(8)
        if magic != BTSNOOP_MAGIC:
            raise ValueError(f"Not a btsnoop file (magic={magic!r})")
        version, data_type = struct.unpack(">II", f.read(8))

        pkt_idx = 0
        while True:
            hdr = f.read(24)
            if len(hdr) < 24:
                break
            orig_len, incl_len, flags, drops, ts = struct.unpack(">IIIIq", hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break

            us = ts - 0x00dcddb30f2f8000
            dt = BTSNOOP_EPOCH + timedelta(microseconds=us)

            direction = "recv" if (flags & 1) else "sent"
            is_cmd = bool(flags & 2)

            yield {
                "idx": pkt_idx,
                "time": dt,
                "direction": direction,
                "is_cmd": is_cmd,
                "data": data,
            }
            pkt_idx += 1


def _detect_btsnoop_format(packets: list[dict]) -> str:
    """Detect whether btsnoop uses standard (with HCI type byte) or Apple format.

    Standard: first byte is HCI packet type (0x01=CMD, 0x02=ACL, 0x04=EVT)
    Apple PacketLogger: no HCI type byte, data starts directly with packet content.
    """
    for pkt in packets[:50]:
        data = pkt["data"]
        if len(data) < 2:
            continue
        # Standard format: ACL data starts with 0x02, events with 0x04
        if data[0] == 0x04 and pkt["is_cmd"] and pkt["direction"] == "recv":
            return "standard"
        if data[0] == 0x02 and not pkt["is_cmd"]:
            return "standard"
        # Apple format: events start directly with event code (0x3E for LE Meta)
        if data[0] == 0x3E and pkt["is_cmd"] and pkt["direction"] == "recv":
            return "apple"
    return "apple"  # default to Apple since it's more common with PacketLogger


def extract_att_apple(packets: list[dict], target_mac_le: bytes) -> list[dict]:
    """Extract ATT data from Apple PacketLogger btsnoop (no HCI type byte).

    Apple format: btsnoop flags determine packet type:
      - flags bit1=0, bit0=0: sent data (ACL)
      - flags bit1=0, bit0=1: recv data (ACL)
      - flags bit1=1, bit0=0: sent cmd (HCI CMD)
      - flags bit1=1, bit0=1: recv evt (HCI EVT)
    """
    conn_handles = set()
    att_events = []

    # Phase 1: find LE connection events
    for pkt in packets:
        data = pkt["data"]
        is_evt = pkt["is_cmd"] and pkt["direction"] == "recv"
        if not is_evt or len(data) < 14:
            continue
        evt_code = data[0]
        if evt_code != 0x3E:  # LE Meta Event
            continue
        sub_evt = data[2]
        if sub_evt == 0x0A and len(data) >= 14:  # LE Enhanced Connection Complete
            status = data[3]
            handle = struct.unpack("<H", data[4:6])[0]
            addr = data[8:14]
            if status == 0 and addr == target_mac_le:
                conn_handles.add(handle)
        elif sub_evt == 0x01 and len(data) >= 13:  # LE Connection Complete
            status = data[3]
            handle = struct.unpack("<H", data[4:6])[0]
            addr = data[8:14]
            if status == 0 and addr == target_mac_le:
                conn_handles.add(handle)

    # Phase 2: auto-detect write/notify ATT handles from traffic
    write_handle = None
    notify_handle = None
    for pkt in packets:
        data = pkt["data"]
        if pkt["is_cmd"] or len(data) < 9:
            continue
        hf = struct.unpack("<H", data[0:2])[0]
        h = hf & 0x0FFF
        if conn_handles and h not in conn_handles:
            continue
        acl_len = struct.unpack("<H", data[2:4])[0]
        l2cap_data = data[4:4 + acl_len]
        if len(l2cap_data) < 4:
            continue
        l2cap_len, cid = struct.unpack("<HH", l2cap_data[:4])
        if cid != 0x0004:
            continue
        att_data = l2cap_data[4:4 + l2cap_len]
        if len(att_data) < 3:
            continue
        att_opcode = att_data[0]
        att_handle = struct.unpack("<H", att_data[1:3])[0]
        if att_opcode in (0x12, 0x52) and write_handle is None:
            write_handle = att_handle
        elif att_opcode in (0x1B, 0x1D) and notify_handle is None:
            notify_handle = att_handle
        if write_handle and notify_handle:
            break

    if not write_handle and not notify_handle:
        return att_events
    write_handle = write_handle or TUYA_WRITE_HANDLE
    notify_handle = notify_handle or TUYA_NOTIFY_HANDLE

    # Phase 3: extract ACL/ATT data
    for pkt in packets:
        data = pkt["data"]
        is_data = not pkt["is_cmd"]
        if not is_data or len(data) < 9:
            continue

        handle_flags = struct.unpack("<H", data[0:2])[0]
        handle = handle_flags & 0x0FFF

        # Filter to known connection handles (if found), else accept all
        if conn_handles and handle not in conn_handles:
            continue

        acl_len = struct.unpack("<H", data[2:4])[0]
        l2cap_data = data[4:4 + acl_len]
        if len(l2cap_data) < 4:
            continue
        l2cap_len, cid = struct.unpack("<HH", l2cap_data[:4])
        if cid != 0x0004:  # ATT CID
            continue

        att_data = l2cap_data[4:4 + l2cap_len]
        if len(att_data) < 3:
            continue

        att_opcode = att_data[0]
        att_handle = struct.unpack("<H", att_data[1:3])[0]
        att_value = att_data[3:]

        if att_opcode in (0x12, 0x52) and att_handle == write_handle:
            att_events.append({
                "time": pkt["time"],
                "direction": "APP->LOCK",
                "handle": att_handle,
                "data": att_value,
            })
        elif att_opcode in (0x1B, 0x1D) and att_handle == notify_handle:
            att_events.append({
                "time": pkt["time"],
                "direction": "LOCK->APP",
                "handle": att_handle,
                "data": att_value,
            })

    return att_events


def extract_att_standard(packets: list[dict], target_mac_le: bytes) -> list[dict]:
    """Extract ATT data from standard btsnoop (with HCI type byte prefix)."""
    conn_handles = set()
    att_events = []

    for pkt in packets:
        data = pkt["data"]
        if len(data) < 1:
            continue

        pkt_type = data[0]

        # HCI Event (0x04)
        if pkt_type == 0x04 and len(data) >= 4:
            evt_code = data[1]
            if evt_code == 0x3E and len(data) >= 16:  # LE Meta
                sub_evt = data[3]
                if sub_evt == 0x01 and len(data) >= 16:  # Connection Complete
                    status = data[4]
                    conn_handle = struct.unpack("<H", data[5:7])[0]
                    peer_addr = data[9:15]
                    if status == 0 and peer_addr == target_mac_le:
                        conn_handles.add(conn_handle)
                elif sub_evt == 0x0A and len(data) >= 33:  # Enhanced Connection Complete
                    status = data[4]
                    conn_handle = struct.unpack("<H", data[5:7])[0]
                    peer_addr = data[9:15]
                    if status == 0 and peer_addr == target_mac_le:
                        conn_handles.add(conn_handle)

    # Phase 2: auto-detect write/notify ATT handles
    write_handle = None
    notify_handle = None
    for pkt in packets:
        data = pkt["data"]
        if len(data) < 9 or data[0] != 0x02:
            continue
        hf = struct.unpack("<H", data[1:3])[0]
        ch = hf & 0x0FFF
        if conn_handles and ch not in conn_handles:
            continue
        acl_len = struct.unpack("<H", data[3:5])[0]
        l2cap_data = data[5:5 + acl_len]
        if len(l2cap_data) < 4:
            continue
        l2cap_len, cid = struct.unpack("<HH", l2cap_data[:4])
        if cid != 0x0004:
            continue
        att_data = l2cap_data[4:4 + l2cap_len]
        if len(att_data) < 3:
            continue
        att_opcode = att_data[0]
        att_handle = struct.unpack("<H", att_data[1:3])[0]
        if att_opcode in (0x12, 0x52) and write_handle is None:
            write_handle = att_handle
        elif att_opcode in (0x1B, 0x1D) and notify_handle is None:
            notify_handle = att_handle
        if write_handle and notify_handle:
            break

    if not write_handle and not notify_handle:
        return att_events
    write_handle = write_handle or TUYA_WRITE_HANDLE
    notify_handle = notify_handle or TUYA_NOTIFY_HANDLE

    # Phase 3: extract ACL/ATT data
    for pkt in packets:
        data = pkt["data"]
        if len(data) < 1:
            continue

        pkt_type = data[0]

        # HCI ACL Data (0x02)
        if pkt_type == 0x02 and len(data) >= 9:
            handle_flags = struct.unpack("<H", data[1:3])[0]
            conn_handle = handle_flags & 0x0FFF
            if conn_handles and conn_handle not in conn_handles:
                continue

            acl_len = struct.unpack("<H", data[3:5])[0]
            l2cap_data = data[5:5 + acl_len]
            if len(l2cap_data) < 4:
                continue
            l2cap_len, cid = struct.unpack("<HH", l2cap_data[:4])
            if cid != 0x0004:
                continue

            att_data = l2cap_data[4:4 + l2cap_len]
            if len(att_data) < 3:
                continue

            att_opcode = att_data[0]
            att_handle = struct.unpack("<H", att_data[1:3])[0]
            att_value = att_data[3:]

            if att_opcode in (0x12, 0x52) and att_handle == write_handle:
                att_events.append({
                    "time": pkt["time"],
                    "direction": "APP->LOCK",
                    "handle": att_handle,
                    "data": att_value,
                })
            elif att_opcode in (0x1B, 0x1D) and att_handle == notify_handle:
                att_events.append({
                    "time": pkt["time"],
                    "direction": "LOCK->APP",
                    "handle": att_handle,
                    "data": att_value,
                })

    return att_events


def extract_att_data(packets: list[dict], target_mac: str = "") -> list[dict]:
    """Extract ATT data from btsnoop packets, auto-detecting format."""
    target_mac_bytes = bytes(int(b, 16) for b in target_mac.split(":"))
    target_mac_le = target_mac_bytes[::-1]  # BLE uses little-endian MAC

    fmt = _detect_btsnoop_format(packets)
    if fmt == "apple":
        return extract_att_apple(packets, target_mac_le)
    else:
        return extract_att_standard(packets, target_mac_le)


# --- Main decode logic ---

def build_keys(login_key_hex: str = "", local_key: str = "") -> tuple[dict[int, bytes], bytes]:
    """Build decryption keys. Returns (keys_dict, raw_login_key_bytes).

    Key derivation:
      - sec_flag 4 (LOGIN_KEY): key = MD5(login_key_bytes)
      - sec_flag 5 (SESSION_KEY): key = MD5(login_key_bytes + srand)
        where srand comes from DEVICE_INFO response (auto-derived during decode)
    """
    keys: dict[int, bytes] = {}
    login_key_bytes = b""

    if login_key_hex:
        login_key_bytes = bytes.fromhex(login_key_hex)
        keys[4] = hashlib.md5(login_key_bytes).digest()
    elif local_key:
        # localKey[:6].encode() = login_key
        login_key_bytes = local_key[:6].encode("utf-8")
        keys[4] = hashlib.md5(login_key_bytes).digest()

    return keys, login_key_bytes


def format_frame(frame: dict, direction: str) -> list[str]:
    """Format a decoded frame for display. Returns list of output lines."""
    cmd = frame["cmd"]
    cmd_name = CMD_NAMES.get(cmd, f"0x{cmd:04X}")
    data = frame.get("data", b"")

    lines = [f"  {cmd_name} sn={frame['sn']}"]

    if cmd == 0x0000:  # DEVICE_INFO
        if direction == "W" and len(data) >= 2:
            mtu = struct.unpack(">H", data[:2])[0]
            lines.append(f"    MTU={mtu}")
        elif direction == "N" and len(data) >= 12:
            bound = data[5]
            srand = data[6:12].hex()
            lines.append(f"    bound={bound} srand={srand}")
    elif cmd == 0x0001:  # PAIR
        if direction == "W" and len(data) >= 44:
            uuid_s = data[:16].decode("ascii", errors="replace")
            lines.append(f'    uuid="{uuid_s}"')
        elif direction == "N" and data:
            status = {0: "NEW_PAIR", 2: "ALREADY_BOUND"}.get(data[0], f"status={data[0]}")
            lines.append(f"    {status}")
    elif cmd == 0x0003:  # QUERY_STATUS
        if data:
            lines.append(f"    data={data.hex()}")
    elif cmd == 0x8006:  # DP_REPORT_V4
        dps = parse_dp_report_v4(data)
        for dp in dps:
            lines.append(f"    {format_dp(dp)}")
        if not dps:
            lines.append(f"    raw={data.hex()}")
    elif cmd == 0x8001:  # RECV_DP (V3 KLV: [dp_id:1][type:1][len:1][val:N])
        dps = parse_klv_v3(data)
        for dp in dps:
            lines.append(f"    {format_dp(dp)}")
        if not dps:
            lines.append(f"    raw={data.hex()}")
    elif cmd == 0x0027:  # DP_WRITE_V4
        if direction == "W":
            dps = parse_dp_write_v4(data)
            for dp in dps:
                lines.append(f"    {format_dp(dp)}")
            if not dps:
                lines.append(f"    raw={data.hex()}")
        else:
            lines.append(f"    ack={data.hex()}")
    elif cmd in (0x8011, 0x8012):  # TIME_REQUEST
        if data:
            lines.append(f'    time="{data.decode("ascii", errors="replace")}"')
        else:
            lines.append(f"    (time sync request)")
    elif cmd == 0x0020:  # ECDH
        if data:
            lines.append(f"    sub_cmd={data[0]} key_len={len(data) - 1}")
    else:
        if data:
            lines.append(f"    data[{len(data)}]={data[:60].hex()}{'...' if len(data) > 60 else ''}")

    return lines


def main():
    parser = argparse.ArgumentParser(description="Decode Tuya BLE traffic from btsnoop captures")
    parser.add_argument("file", help="btsnoop file path")
    parser.add_argument("--mac", required=True, help="Target device MAC (e.g., AA:BB:CC:DD:EE:FF)")
    parser.add_argument("--login-key", default="", help="Login key hex (e.g., AABBCCDDEEFF)")
    parser.add_argument("--local-key", default="", help="Cloud localKey (ASCII)")
    parser.add_argument("--raw-only", action="store_true", help="Show raw ATT data only")
    args = parser.parse_args()

    print(f"Parsing {args.file}...")
    packets = list(parse_btsnoop(args.file))
    print(f"Total HCI packets: {len(packets)}")

    fmt = _detect_btsnoop_format(packets)
    print(f"Detected format: {fmt}")

    print(f"\nExtracting ATT data for MAC {args.mac}...")
    att_events = extract_att_data(packets, args.mac)
    print(f"Found {len(att_events)} ATT event(s)")

    if not att_events:
        print("\nNo ATT events found. Check --mac or verify capture has BLE traffic.")
        return

    if args.raw_only:
        for evt in att_events:
            ts = evt["time"].strftime("%H:%M:%S.%f")[:-3]
            print(f"[{ts}] {evt['direction']:>12s}  handle=0x{evt['handle']:04X} "
                  f"len={len(evt['data'])} data={evt['data'].hex()}")
        return

    keys, login_key_bytes = build_keys(args.login_key, args.local_key)
    print(f"Keys available: sec_flags={list(keys.keys())}")

    # Reassemble fragments
    write_frags: list[bytes] = []
    notify_frags: list[bytes] = []
    messages: list[tuple[str, bytes, datetime | None]] = []

    for evt in att_events:
        direction = "W" if evt["direction"] == "APP->LOCK" else "N"
        data = evt["data"]
        frag_list = write_frags if direction == "W" else notify_frags

        is_first = len(data) >= 2 and (data[0] & 0x7F) == 0 and not (data[0] & 0x80)
        if is_first and frag_list:
            for msg in reassemble_fragments(frag_list):
                messages.append((direction, msg, evt["time"]))
            frag_list.clear()
        frag_list.append(data)
        if direction == "W":
            write_frags = frag_list
        else:
            notify_frags = frag_list

    for d, fl in [("W", write_frags), ("N", notify_frags)]:
        if fl:
            for msg in reassemble_fragments(fl):
                messages.append((d, msg, None))

    print(f"Reassembled: {len(messages)} messages")

    # Decode
    print(f"\n{'=' * 80}")
    print("TUYA BLE PROTOCOL DECODE")
    print(f"{'=' * 80}\n")

    for direction, msg, ts in messages:
        arrow = "APP->LOCK" if direction == "W" else "LOCK->APP"
        ts_str = ts.strftime("%H:%M:%S.%f")[:-3] if ts else "END"
        sec_flag = msg[0] if msg else -1
        sec_name = SEC_NAMES.get(sec_flag, f"sec={sec_flag}")

        frame = try_decrypt_and_verify(msg, keys)

        if frame:
            lines = format_frame(frame, direction)
            print(f"[{ts_str}] {arrow:>12s} {lines[0]}")
            for line in lines[1:]:
                print(f"{'':>26s}{line}")

            # Auto-derive session key from DEVICE_INFO response
            if frame["cmd"] == 0x0000 and direction == "N":
                data = frame.get("data", b"")
                if len(data) >= 12 and login_key_bytes:
                    srand = data[6:12]
                    # CORRECT: MD5(raw_login_key + srand)
                    session_key = hashlib.md5(login_key_bytes + srand).digest()
                    keys[5] = session_key
                    print(f"{'':>26s}    ** session_key={session_key.hex()}")
        else:
            extra = ""
            if sec_flag == 5 and 5 not in keys:
                extra = " (need DEVICE_INFO for srand)"
            print(f"[{ts_str}] {arrow:>12s}  ENCRYPTED {sec_name}{extra} len={len(msg)}")

    print()


if __name__ == "__main__":
    main()
