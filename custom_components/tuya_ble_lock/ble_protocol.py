"""Tuya BLE CommRod protocol — framing, encryption & fragmentation.

Adapted from protocol.py and lock_control.py in the PoC.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass

from .ble_crypto import aes_cbc_decrypt, aes_cbc_encrypt, crc16_modbus_bytes

_LOGGER = logging.getLogger(__name__)

# Frame constants
FRAG_TYPE_DATA = 4  # version nibble value for V4 (0x40)


def encode_varint(value: int) -> bytes:
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


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a varint at offset. Returns (value, new_offset)."""
    value = 0
    shift = 0
    pos = offset
    while pos < len(data):
        b = data[pos]
        value |= (b & 0x7F) << shift
        pos += 1
        shift += 7
        if not (b & 0x80):
            break
    return value, pos


@dataclass
class TuyaBleFrame:
    sn: int = 0
    ack_sn: int = 0
    code: int = 0
    data: bytes = b""

    def to_bytes(self) -> bytes:
        header = struct.pack(">IIHH", self.sn, self.ack_sn, self.code, len(self.data))
        frame = header + self.data
        return frame + crc16_modbus_bytes(frame)

    @classmethod
    def from_bytes(cls, raw: bytes) -> "TuyaBleFrame":
        if len(raw) < 14:
            raise ValueError(f"Frame too short: {len(raw)} bytes")
        sn, ack_sn, code, data_len = struct.unpack(">IIHH", raw[:12])
        data = raw[12 : 12 + data_len]
        crc_received = raw[12 + data_len : 12 + data_len + 2]
        crc_expected = crc16_modbus_bytes(raw[: 12 + data_len])
        if crc_received != crc_expected:
            raise ValueError(
                f"CRC mismatch: got {crc_received.hex()}, expected {crc_expected.hex()}"
            )
        return cls(sn=sn, ack_sn=ack_sn, code=code, data=data)


def encrypt_frame(key: bytes, security_flag: int, plaintext: bytes) -> bytes:
    if security_flag == 0:
        return bytes([security_flag]) + plaintext
    iv, ct = aes_cbc_encrypt(key, plaintext)
    return bytes([security_flag]) + iv + ct


def decrypt_frame(key: bytes, encrypted: bytes) -> bytes:
    sec_flag = encrypted[0]
    if sec_flag == 0:
        return encrypted[1:]
    iv = encrypted[1:17]
    ct = encrypted[17:]
    return aes_cbc_decrypt(key, iv, ct)


def fragment(encrypted_payload: bytes, mtu: int = 20, protocol_version: int = 4) -> list[bytes]:
    total_len = len(encrypted_payload)
    fragments: list[bytes] = []
    offset = 0
    frag_idx = 0
    ver_byte = protocol_version << 4  # 0x30 for V3, 0x40 for V4

    while offset < total_len:
        header = encode_varint(frag_idx)
        if frag_idx == 0:
            header += encode_varint(total_len)
            header += bytes([ver_byte])
        payload_size = mtu - len(header)
        chunk = encrypted_payload[offset : offset + payload_size]
        fragments.append(header + chunk)
        offset += len(chunk)
        frag_idx += 1
    return fragments


def reassemble(raw_notifications: list[bytes]) -> list[bytes]:
    """Reassemble raw BLE notifications into complete message payloads.

    Handles interleaved fragment streams — some devices (e.g. H8 Pro on service
    1910) send fragments from multiple messages concurrently on the same
    characteristic.  Each stream starts with a seq=0 fragment containing the
    total payload length.  Continuation fragments (seq > 0) are routed to the
    correct stream by matching expected sequence numbers and remaining capacity.
    """
    if not raw_notifications:
        return []

    # Each stream: [expected_next_seq, total_len, buf]
    streams: list[list] = []  # [[expected_seq, total_len, bytearray], ...]

    for notif in raw_notifications:
        if not notif:
            continue
        seq, pos = decode_varint(notif, 0)
        if seq == 0:
            # Start of a new message stream
            total_len, pos = decode_varint(notif, pos)
            pos += 1  # skip version/type byte
            buf = bytearray(notif[pos:])
            streams.append([1, total_len, buf])
        else:
            # Continuation fragment — find the right stream
            _, data_pos = decode_varint(notif, 0)
            frag_data = notif[data_pos:]
            assigned = False
            for stream in streams:
                exp_seq, total_len, buf = stream
                if exp_seq == seq:
                    remaining = total_len - len(buf)
                    if remaining >= len(frag_data):
                        buf.extend(frag_data)
                        stream[0] = seq + 1  # advance expected_seq
                        assigned = True
                        break
            if not assigned:
                # Fallback: assign to first stream expecting this seq (ignore capacity)
                for stream in streams:
                    if stream[0] == seq:
                        stream[2].extend(frag_data)
                        stream[0] = seq + 1
                        assigned = True
                        break
            if not assigned:
                _LOGGER.debug(
                    "Orphan fragment seq=%d len=%d — no matching stream",
                    seq, len(frag_data),
                )

    results = []
    for _, total_len, buf in streams:
        results.append(bytes(buf[:total_len]) if total_len else bytes(buf))
    return results


class SequenceCounter:
    def __init__(self):
        self._value = 0

    def next(self) -> int:
        self._value += 1
        return self._value


def build_command(
    code: int,
    data: bytes,
    security_flag: int,
    key: bytes | None,
    seq: SequenceCounter,
    mtu: int = 20,
) -> list[bytes]:
    frame = TuyaBleFrame(sn=seq.next(), ack_sn=0, code=code, data=data)
    raw = frame.to_bytes()
    if security_flag == 0 or key is None:
        encrypted = encrypt_frame(b"", 0, raw)
    else:
        encrypted = encrypt_frame(key, security_flag, raw)
    return fragment(encrypted, mtu)


def parse_frames(keys: dict[int, bytes], raw_notifications: list[bytes]) -> list[dict]:
    """Reassemble raw BLE notifications, decrypt, and return parsed frames.

    Args:
        keys: Dict mapping security flag -> AES key.
        raw_notifications: Raw BLE notification payloads.

    Returns:
        List of dicts with keys: cmd, sn, ack_sn, data, sec_flag.
    """
    payloads = reassemble(raw_notifications)
    _LOGGER.debug(
        "parse_frames: %d notifications → %d payloads, sizes=%s",
        len(raw_notifications), len(payloads),
        [len(p) for p in payloads],
    )
    frames = []
    for payload in payloads:
        sec_flag = payload[0]
        if sec_flag == 0:
            raw = payload[1:]
        else:
            key = keys.get(sec_flag)
            if not key:
                _LOGGER.warning(
                    "Skipping frame with sec_flag=%d (no key). Available keys: %s. Payload[0:32]=%s",
                    sec_flag, list(keys.keys()), payload[:32].hex(),
                )
                continue
            try:
                raw = decrypt_frame(key, payload)
            except Exception as exc:
                _LOGGER.debug("Decrypt failed (sec_flag=%d): %s", sec_flag, exc)
                continue
        try:
            f = TuyaBleFrame.from_bytes(raw)
            frames.append({
                "cmd": f.code,
                "sn": f.sn,
                "ack_sn": f.ack_sn,
                "data": f.data,
                "sec_flag": sec_flag,
            })
        except Exception as exc:
            _LOGGER.debug("Frame parse failed (sec_flag=%d): %s", sec_flag, exc)
            continue
    return frames


def parse_dp_report(data: bytes) -> list[dict]:
    """Parse V4 DP report: [sn(4)][flags(1)][0x80][dp_id(2)][type(1)][len(2)][val]."""
    if len(data) < 6:
        return []
    klv = data[6:]
    dps = []
    pos = 0
    while pos + 5 <= len(klv):
        dp_id = struct.unpack(">H", klv[pos : pos + 2])[0]
        dp_type = klv[pos + 2]
        dp_len = struct.unpack(">H", klv[pos + 3 : pos + 5])[0]
        if pos + 5 + dp_len > len(klv):
            break
        val = klv[pos + 5 : pos + 5 + dp_len]
        dps.append({"id": dp_id, "type": dp_type, "len": dp_len, "raw": val})
        pos += 5 + dp_len
    return dps


def parse_dp_report_v3(data: bytes) -> list[dict]:
    """Parse V3 DP report (RECV_DP 0x8001): [dp_id(1)][type(1)][len(1)][val]..."""
    dps = []
    pos = 0
    while pos + 3 <= len(data):
        dp_id = data[pos]
        dp_type = data[pos + 1]
        dp_len = data[pos + 2]
        if pos + 3 + dp_len > len(data):
            break
        val = data[pos + 3 : pos + 3 + dp_len]
        dps.append({"id": dp_id, "type": dp_type, "len": dp_len, "raw": val})
        pos += 3 + dp_len
    return dps


def build_v4_dp(dp_id: int, dp_type: int, value: bytes) -> bytes:
    """Build V4 DP write payload: [version(1)][reserved(4)][dp_id(1)][type(1)][len(2)][value]."""
    header = b"\x00\x00\x00\x00\x00"
    return header + struct.pack(">BBH", dp_id & 0xFF, dp_type, len(value)) + value


def build_v3_dp(dp_id: int, dp_type: int, value: bytes) -> bytes:
    """Build V3 KLV payload: [dp_id(1)][type(1)][len(1)][value]."""
    return struct.pack(">BBB", dp_id & 0xFF, dp_type, len(value)) + value
