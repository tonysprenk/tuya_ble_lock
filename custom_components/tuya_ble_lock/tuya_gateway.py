"""Tuya gateway status helpers for BLE locks."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import uuid
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_LOGGER = logging.getLogger(__name__)


def extract_dps_from_gateway_message(
    message: dict[str, Any],
    device_id: str,
    status_code_map: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    """Extract Tuya DP reports from a gateway/MQ status message.

    The coordinator already knows how to process BLE-style DP reports, so the
    gateway path converts Tuya cloud status items into the same shape:
    ``{"id": dp_id, "raw": raw_bytes}``.
    """
    data = message.get("data", {})
    if not isinstance(data, dict) or data.get("devId") != device_id:
        return []

    status_items = data.get("status", [])
    if not isinstance(status_items, list):
        return []

    code_map = status_code_map or {}
    reports: list[dict[str, Any]] = []
    seen: set[int] = set()
    for item in status_items:
        if not isinstance(item, dict):
            continue
        for key, value in item.items():
            dp_id = _dp_id_for_status_key(key, code_map)
            if dp_id is None or dp_id in seen:
                continue
            raw = _raw_bytes_from_status_value(value)
            if raw is None:
                continue
            reports.append({"id": dp_id, "raw": raw})
            seen.add(dp_id)

        code = item.get("code")
        if isinstance(code, str) and code in code_map and code_map[code] not in seen:
            raw = _raw_bytes_from_status_value(item.get("value"))
            if raw is not None:
                dp_id = code_map[code]
                reports.append({"id": dp_id, "raw": raw})
                seen.add(dp_id)

    return reports


def _dp_id_for_status_key(key: str, status_code_map: dict[str, int]) -> int | None:
    if key.isdigit():
        return int(key)
    mapped = status_code_map.get(key)
    return int(mapped) if mapped is not None else None


def _raw_bytes_from_status_value(value: Any) -> bytes | None:
    if isinstance(value, bool):
        return b"\x01" if value else b"\x00"
    if isinstance(value, int):
        return int(value).to_bytes(4, "big", signed=False)
    if isinstance(value, str):
        if not value:
            return b""
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            return value.encode()
    return None


def decode_gateway_payload(payload: bytes | str, password: str) -> dict[str, Any] | None:
    """Decode a Tuya gateway MQTT payload.

    Tuya's open-hub MQTT wrapper may contain a base64 encoded AES-ECB payload
    in ``data``. Plain JSON payloads are returned unchanged.
    """
    if isinstance(payload, bytes):
        payload = payload.decode()
    payload = payload.strip()
    if not payload:
        return None
    message = json.loads(payload)
    if not isinstance(message, dict):
        return None

    data = message.get("data")
    if isinstance(data, dict):
        return message
    if not isinstance(data, str):
        return message

    key = password[8:24].encode()
    if len(key) != 16:
        raise ValueError("Tuya MQTT password is too short for AES payload decryption")

    encrypted = base64.b64decode(data)
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    decrypted = _remove_pkcs7_padding(decrypted)
    decoded = json.loads(decrypted.decode())
    if isinstance(decoded, dict):
        return decoded
    return None


def _remove_pkcs7_padding(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if 1 <= pad_len <= 16 and data.endswith(bytes([pad_len]) * pad_len):
        return data[:-pad_len]
    return data.rstrip(b"\x00")


class TuyaGatewayStatusListener:
    """Tuya open-hub MQTT listener that forwards status DPs to the coordinator."""

    def __init__(
        self,
        hass,
        entry,
        profile: dict[str, Any],
        device_id: str,
        on_dps,
        *,
        credentials: dict[str, Any] | None = None,
    ) -> None:
        self.hass = hass
        self.entry = entry
        self.profile = profile
        self.device_id = device_id
        self._on_dps = on_dps
        self._credentials = credentials or {}
        self._mqtt_client = None
        self._mqtt_password = ""
        self._started = False
        self._closed = False

    @property
    def started(self) -> bool:
        return self._started

    async def async_start(self) -> bool:
        """Start the gateway MQTT listener.

        Returns False when cloud credentials are missing or the Tuya API does
        not provide usable MQTT parameters. Startup failures are non-fatal.
        """
        if self._started:
            return True
        if not self._credentials:
            _LOGGER.debug("Tuya gateway listener not started for %s: missing credentials", self.device_id)
            return False

        from homeassistant.helpers.aiohttp_client import async_get_clientsession

        from .const import (
            CONF_TUYA_COUNTRY,
            CONF_TUYA_EMAIL,
            CONF_TUYA_PASSWORD,
            CONF_TUYA_REGION,
        )
        from .tuya_cloud import TuyaMobileAPIAsync

        session = async_get_clientsession(self.hass)
        stable_device_id = hashlib.sha256(
            f"tuya_ble_lock_mqtt|{self.device_id}".encode()
        ).hexdigest()
        client = TuyaMobileAPIAsync(
            session,
            region=self._credentials[CONF_TUYA_REGION],
            device_id=stable_device_id,
        )
        login_resp = await client.async_login(
            self._credentials[CONF_TUYA_COUNTRY],
            self._credentials[CONF_TUYA_EMAIL],
            self._credentials[CONF_TUYA_PASSWORD],
        )
        if not login_resp.get("success"):
            error = login_resp.get("errorMsg", login_resp.get("msg", "Login failed"))
            _LOGGER.warning("Tuya gateway listener login failed for %s: %s", self.device_id, error)
            return False

        mqtt_resp = await client.async_get_mqtt_config(_new_link_id())
        if not mqtt_resp.get("success"):
            error = mqtt_resp.get("errorMsg", mqtt_resp.get("msg", "MQTT config failed"))
            _LOGGER.warning("Tuya gateway MQTT config failed for %s: %s", self.device_id, error)
            return False

        config = mqtt_resp.get("result", {})
        if not isinstance(config, dict):
            _LOGGER.warning("Tuya gateway MQTT config for %s had unexpected result: %s", self.device_id, config)
            return False

        return await self.hass.async_add_executor_job(self._start_mqtt_client, config)

    async def async_stop(self) -> None:
        self._closed = True
        client = self._mqtt_client
        self._mqtt_client = None
        self._started = False
        if client is None:
            return
        await self.hass.async_add_executor_job(self._stop_mqtt_client, client)

    def _start_mqtt_client(self, config: dict[str, Any]) -> bool:
        try:
            import paho.mqtt.client as mqtt
        except ImportError as exc:
            _LOGGER.warning("Tuya gateway listener requires paho-mqtt: %s", exc)
            return False

        url = str(config.get("url") or "")
        username = str(config.get("username") or "")
        password = str(config.get("password") or "")
        client_id = str(config.get("client_id") or "")
        source_topic = str(config.get("source_topic") or "")
        if not all((url, username, password, client_id, source_topic)):
            _LOGGER.warning("Tuya gateway MQTT config missing required fields for %s", self.device_id)
            return False

        host, port, use_tls = _parse_mqtt_url(url)
        mqtt_client = _create_mqtt_client(mqtt, client_id)
        mqtt_client.username_pw_set(username, password)
        if use_tls:
            mqtt_client.tls_set()
        mqtt_client.on_connect = self._on_mqtt_connect
        mqtt_client.on_disconnect = self._on_mqtt_disconnect
        mqtt_client.on_message = self._on_mqtt_message
        mqtt_client._tuya_source_topic = source_topic

        self._mqtt_password = password
        mqtt_client.connect(host, port, keepalive=60)
        mqtt_client.loop_start()
        self._mqtt_client = mqtt_client
        self._started = True
        _LOGGER.info("Tuya gateway listener started for %s", self.device_id)
        return True

    def _stop_mqtt_client(self, client) -> None:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:
            _LOGGER.debug("Error while stopping Tuya gateway MQTT listener", exc_info=True)

    def _on_mqtt_connect(self, client, _userdata, _flags, rc, *_args) -> None:
        if rc != 0:
            _LOGGER.warning("Tuya gateway MQTT connect failed for %s: rc=%s", self.device_id, rc)
            return
        source_topic = getattr(client, "_tuya_source_topic", "")
        if source_topic:
            client.subscribe(source_topic)
            _LOGGER.debug("Tuya gateway MQTT subscribed to %s for %s", source_topic, self.device_id)

    def _on_mqtt_disconnect(self, _client, _userdata, rc, *_args) -> None:
        if rc and not self._closed:
            _LOGGER.warning("Tuya gateway MQTT disconnected for %s: rc=%s", self.device_id, rc)

    def _on_mqtt_message(self, _client, _userdata, msg) -> None:
        try:
            decoded = decode_gateway_payload(msg.payload, self._mqtt_password)
        except Exception:
            _LOGGER.debug("Failed to decode Tuya gateway MQTT payload for %s", self.device_id, exc_info=True)
            return
        if decoded:
            self._handle_decoded_message(decoded)

    def _handle_decoded_message(self, message: dict[str, Any]) -> None:
        dps = extract_dps_from_gateway_message(
            message,
            self.device_id,
            self._gateway_status_code_map(),
        )
        if not dps:
            return
        self.hass.loop.call_soon_threadsafe(self._on_dps, dps)

    def _gateway_status_code_map(self) -> dict[str, int]:
        lock_cfg = self.profile.get("entities", {}).get("lock", {})
        code_map = lock_cfg.get("gateway_status_code_map", {})
        if not isinstance(code_map, dict):
            return {}
        result: dict[str, int] = {}
        for code, dp_id in code_map.items():
            try:
                result[str(code)] = int(dp_id)
            except (TypeError, ValueError):
                continue
        return result


def _new_link_id() -> str:
    return uuid.uuid4().hex[:8]


def _parse_mqtt_url(url: str) -> tuple[str, int, bool]:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme:
        host = parsed.hostname or ""
        use_tls = parsed.scheme in {"ssl", "mqtts", "tls"}
        default_port = 8883 if use_tls else 1883
        return host, parsed.port or default_port, use_tls

    if ":" in url:
        host, port_text = url.rsplit(":", 1)
        try:
            return host, int(port_text), False
        except ValueError:
            return url, 1883, False
    return url, 1883, False


def _create_mqtt_client(mqtt, client_id: str):
    callback_api_version = getattr(mqtt, "CallbackAPIVersion", None)
    if callback_api_version is not None:
        try:
            return mqtt.Client(
                callback_api_version.VERSION1,
                client_id=client_id,
                clean_session=True,
            )
        except TypeError:
            pass
    return mqtt.Client(client_id=client_id, clean_session=True)
