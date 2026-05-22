"""Tuya gateway status helpers for BLE locks."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_LOGGER = logging.getLogger(__name__)

_DP71_MANUAL_LOCK_CODES = {"manual_lock"}


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
    reports_by_id: dict[int, tuple[int, bytes]] = {}
    report_order: list[int] = []
    for item in status_items:
        if not isinstance(item, dict):
            continue
        for key, value in item.items():
            dp_id = _dp_id_for_status_key(key, code_map)
            if dp_id is None:
                continue
            raw = _raw_bytes_from_status_value(value, dp_id=dp_id, status_code=key)
            if raw is None:
                continue
            _record_status_report(reports_by_id, report_order, dp_id, raw, key)

        code = item.get("code")
        if isinstance(code, str) and code in code_map:
            dp_id = code_map[code]
            raw = _raw_bytes_from_status_value(item.get("value"), dp_id=dp_id, status_code=code)
            if raw is not None:
                _record_status_report(reports_by_id, report_order, dp_id, raw, code)

    return [{"id": dp_id, "raw": reports_by_id[dp_id][1]} for dp_id in report_order]


def _record_status_report(
    reports_by_id: dict[int, tuple[int, bytes]],
    report_order: list[int],
    dp_id: int,
    raw: bytes,
    status_code: str,
) -> None:
    priority = _status_report_priority(dp_id, raw, status_code)
    existing = reports_by_id.get(dp_id)
    if existing is not None and existing[0] >= priority:
        return
    if existing is None:
        report_order.append(dp_id)
    reports_by_id[dp_id] = (priority, raw)


def _status_report_priority(dp_id: int, raw: bytes, status_code: str) -> int:
    if dp_id == 71 and status_code in _DP71_MANUAL_LOCK_CODES:
        return 10
    if dp_id == 71 and len(raw) >= 13:
        return 100
    return 50


def _dp_id_for_status_key(key: str, status_code_map: dict[str, int]) -> int | None:
    if key.isdigit():
        return int(key)
    mapped = status_code_map.get(key)
    return int(mapped) if mapped is not None else None


def _raw_bytes_from_status_value(
    value: Any,
    *,
    dp_id: int | None = None,
    status_code: str | None = None,
) -> bytes | None:
    if dp_id == 71 and status_code in _DP71_MANUAL_LOCK_CODES:
        locked = _manual_lock_status_value(value)
        if locked is not None:
            return _synthetic_dp71_lock_state_payload(locked)
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


def _manual_lock_status_value(value: Any) -> bool | None:
    if value is True:
        return True
    if isinstance(value, int) and value == 1:
        return True
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "lock", "locked", "manual_lock"}:
            return True
    return None


def _synthetic_dp71_lock_state_payload(locked: bool) -> bytes:
    # Keep the check-code bytes zeroed so a status-only event cannot replace the command check code.
    action = b"\x00" if locked else b"\x01"
    timestamp = int(time.time()).to_bytes(4, "big")
    return b"\x00\x01\xff\xff" + bytes(8) + action + timestamp + b"\x00\x00"


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
            CONF_TUYA_ACCESS_ID,
            CONF_TUYA_ACCESS_SECRET,
            CONF_TUYA_REGION,
        )
        from .tuya_cloud import TuyaOpenAPIAsync

        access_id = self._credentials.get(CONF_TUYA_ACCESS_ID)
        access_secret = self._credentials.get(CONF_TUYA_ACCESS_SECRET)
        if not access_id or not access_secret:
            _LOGGER.warning(
                "Tuya gateway listener for %s requires Tuya IoT OpenAPI Access ID and Access Secret",
                self.device_id,
            )
            return False

        session = async_get_clientsession(self.hass)
        client = TuyaOpenAPIAsync(
            session,
            region=self._credentials[CONF_TUYA_REGION],
            access_id=access_id,
            access_secret=access_secret,
        )
        mqtt_resp = await client.async_get_open_hub_config(_new_link_id())
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
        source_topics = _source_topics_from_config(config)
        if not all((url, username, password, client_id, source_topics)):
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
        mqtt_client.on_subscribe = self._on_mqtt_subscribe
        mqtt_client._tuya_subscribe_topics = source_topics
        mqtt_client._tuya_source_topic = source_topics[0]

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
        source_topics = tuple(getattr(client, "_tuya_subscribe_topics", ()) or ())
        if not source_topics:
            source_topic = getattr(client, "_tuya_source_topic", "")
            source_topics = (source_topic,) if source_topic else ()
        _LOGGER.debug(
            "Tuya gateway MQTT connected for %s; requesting %d subscriptions",
            self.device_id,
            len(source_topics),
        )
        for source_topic in source_topics:
            result = client.subscribe(source_topic)
            _LOGGER.debug(
                "Tuya gateway MQTT subscribe requested for %s: topic=%s result=%s",
                self.device_id,
                _topic_for_log(source_topic),
                result,
            )

    def _on_mqtt_disconnect(self, _client, _userdata, rc, *_args) -> None:
        if rc and not self._closed:
            _LOGGER.warning("Tuya gateway MQTT disconnected for %s: rc=%s", self.device_id, rc)

    def _on_mqtt_subscribe(self, _client, _userdata, mid, granted_qos, *_args) -> None:
        qos_values = _mqtt_granted_qos_values(granted_qos)
        if 128 in qos_values:
            _LOGGER.warning(
                "Tuya gateway MQTT subscription rejected for %s: mid=%s granted_qos=%s",
                self.device_id,
                mid,
                qos_values,
            )
            return
        _LOGGER.debug(
            "Tuya gateway MQTT subscription acknowledged for %s: mid=%s granted_qos=%s",
            self.device_id,
            mid,
            qos_values,
        )

    def _on_mqtt_message(self, _client, _userdata, msg) -> None:
        payload = msg.payload or b""
        _LOGGER.debug(
            "Tuya gateway MQTT message received for %s: topic=%s bytes=%d",
            self.device_id,
            _topic_for_log(str(getattr(msg, "topic", ""))),
            len(payload),
        )
        try:
            decoded = decode_gateway_payload(payload, self._mqtt_password)
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
            _LOGGER.debug(
                "Tuya gateway message for %s produced no mapped DPs; status=%s",
                self.device_id,
                _status_summary_for_log(message),
            )
            return
        _LOGGER.debug(
            "Tuya gateway message for %s mapped DP ids=%s",
            self.device_id,
            [dp["id"] for dp in dps],
        )
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


def _status_summary_for_log(message: dict[str, Any]) -> list[dict[str, Any]]:
    data = message.get("data", {})
    if not isinstance(data, dict):
        return []
    status_items = data.get("status", [])
    if not isinstance(status_items, list):
        return []
    summary: list[dict[str, Any]] = []
    for item in status_items:
        if not isinstance(item, dict):
            continue
        summary.append(
            {
                "code": item.get("code"),
                "keys": sorted(str(key) for key in item if key != "value"),
            }
        )
    return summary


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


def _source_topic_from_config(config: dict[str, Any]) -> str:
    source_topic = config.get("source_topic")
    if isinstance(source_topic, dict):
        topic = source_topic.get("device")
        if isinstance(topic, str):
            return topic
        for value in source_topic.values():
            if isinstance(value, str):
                return value
        return ""
    return str(source_topic or "")


def _source_topics_from_config(config: dict[str, Any]) -> tuple[str, ...]:
    topics: list[str] = []
    source_topic = config.get("source_topic")
    if isinstance(source_topic, dict):
        device_topic = source_topic.get("device")
        if isinstance(device_topic, str):
            topics.append(device_topic)
        topics.extend(
            value
            for value in source_topic.values()
            if isinstance(value, str) and value != device_topic
        )
    elif source_topic:
        topics.append(str(source_topic))

    expanded: list[str] = []
    for topic in topics:
        expanded.append(topic)
    return tuple(dict.fromkeys(expanded))


def _topic_for_log(topic: str) -> str:
    parts = topic.split("/")
    if len(parts) >= 4 and parts[0] == "cloud" and parts[1] == "token":
        parts[3] = _redact_topic_token(parts[3])
    return "/".join(parts)


def _redact_topic_token(value: str) -> str:
    if len(value) <= 10:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def _mqtt_granted_qos_values(granted_qos) -> list[int]:
    if granted_qos is None:
        return []
    if isinstance(granted_qos, int):
        return [granted_qos]
    result: list[int] = []
    for value in granted_qos:
        try:
            result.append(int(value))
        except (TypeError, ValueError):
            continue
    return result


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
