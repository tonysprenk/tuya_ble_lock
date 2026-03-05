"""Cryptographic utilities for Tuya BLE protocol."""

from __future__ import annotations

import hashlib
import os
import struct

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


def generate_ecdh_keypair() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Generate a secp256r1 ECDH keypair.

    Returns (private_key_object, uncompressed_public_key_65_bytes).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    pub_bytes = private_key.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    )  # 65 bytes: 0x04 || X(32) || Y(32)
    return private_key, pub_bytes


def derive_ecdh_shared_secret(
    private_key: ec.EllipticCurvePrivateKey,
    peer_pub_bytes: bytes,
) -> bytes:
    """Compute the raw ECDH shared secret (32 bytes)."""
    peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), peer_pub_bytes
    )
    return private_key.exchange(ec.ECDH(), peer_pub)


def derive_communication_key(shared_secret: bytes) -> bytes:
    """communication_key = MD5(ecdh_shared_secret) → 16 bytes."""
    return hashlib.md5(shared_secret).digest()


def _pad_zero(data: bytes) -> bytes:
    """Pad *data* with zero bytes to the next 16-byte boundary."""
    remainder = len(data) % 16
    if remainder:
        data += b"\x00" * (16 - remainder)
    return data


def aes_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt with AES-128-CBC / zero-padding.

    Returns (iv_16, ciphertext).
    """
    if iv is None:
        iv = os.urandom(16)
    padded = _pad_zero(plaintext)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv, ct


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-128-CBC / NoPadding."""
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(ciphertext) + dec.finalize()


def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-128-ECB / zero-padding."""
    padded = _pad_zero(plaintext)
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(padded) + enc.finalize()


def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-128-ECB / NoPadding (used for advertisement parsing)."""
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return dec.update(ciphertext) + dec.finalize()


def crc16_modbus(data: bytes) -> int:
    """Compute CRC-16/MODBUS over *data*. Returns an int."""
    crc = 0xFFFF
    for b in data:
        crc ^= b & 0xFF
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def crc16_modbus_bytes(data: bytes) -> bytes:
    """CRC-16/MODBUS as 2 big-endian bytes (matches Tuya protocol)."""
    return struct.pack(">H", crc16_modbus(data))


def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def _init_crc8_table() -> list[int]:
    """Generate CRC8 lookup table with polynomial 0x07 (CRC-8/SMBUS)."""
    table = [0] * 256
    for i in range(256):
        crc = i
        for _ in range(8):
            shifted = (crc << 1) & 0x1FE
            if crc & 0x80:
                shifted ^= 0x07
            crc = shifted
        table[i] = crc & 0xFF
    return table

_CRC8_TABLE = _init_crc8_table()


def made_session_key(input_data: bytes) -> bytes:
    """Derive a 16-byte session key from srand + loginKey bytes.

    This replicates the native ``madeSessionKey()`` from libBleLib.so.
    Input is typically ``srand(6B) + loginKey(6B) = 12 bytes``.
    Output is always 16 bytes.
    """
    length = len(input_data)
    output = bytearray(16)

    if length < 16:
        for i in range(16):
            if i < length:
                val = output[i] ^ input_data[i]
            else:
                wrap_idx = i - length
                val = (input_data[wrap_idx] + input_data[wrap_idx + 1]) & 0xFF
                val ^= output[i]
            output[i] = _CRC8_TABLE[val]
    else:
        for i in range(16):
            val = output[i] ^ input_data[i]
            output[i] = _CRC8_TABLE[val]

    return bytes(output)
