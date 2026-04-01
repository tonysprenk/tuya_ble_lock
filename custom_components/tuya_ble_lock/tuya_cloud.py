"""Async Tuya mobile API client for BLE auth key retrieval.

Adapted from tuya_mobile_api.py — rewritten from requests to aiohttp.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid as uuid_mod
import base64
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

# Constants (same values as in original mobile API)
DEFAULT_CERT_SIGN = (
    "93:21:9F:C2:73:E2:20:0F:4A:DE:E5:F7:19:1D:C6:56:"
    "BA:2A:2D:7B:2F:F5:D2:4C:D5:5C:4B:61:55:00:1E:40"
)
DEFAULT_BMP_KEY = "f3hd7pet4p83kemjdf5wqsa5tavrv579"
DEFAULT_CLIENT_ID = "3cxxt3au9x33ytvq3h9j"
DEFAULT_APP_SECRET = "5gdtanjtf38vyxkqh87cjwfcqjhvjjqa"

MOBILE_REGIONS = {
    "us": "https://a1.tuyaus.com",
    "eu": "https://a1.tuyaeu.com",
    "cn": "https://a1.tuyacn.com",
    "in": "https://a1.tuyain.com",
    "nz": "https://a1.tuyaus.com",
}

SIGN_PARAMS = [
    "a", "v", "lat", "lon", "et", "lang", "deviceId",
    "imei", "imsi", "appVersion", "ttid", "isH5",
    "h5Token", "os", "clientId", "postData", "time",
    "n4h5", "sid", "sp", "requestId",
]


def _post_data_hash(post_data: str) -> str:
    """MD5 hash with Tuya's byte-rearrangement quirk."""
    h = hashlib.md5(post_data.encode()).hexdigest()
    return h[8:16] + h[0:8] + h[24:32] + h[16:24]


def _sign(params: dict[str, str], hmac_key: str) -> str:
    sorted_keys = sorted(params.keys())
    parts = []
    for key in sorted_keys:
        if key not in SIGN_PARAMS:
            continue
        val = str(params[key])
        if not val:
            continue
        if key == "postData":
            val = _post_data_hash(val)
        parts.append(f"{key}={val}")
    feed = "||".join(parts)
    return hmac.new(hmac_key.encode(), feed.encode(), hashlib.sha256).hexdigest()


class TuyaMobileAPIAsync:
    """Async Tuya mobile API client (a1.tuyaus.com/api.json)."""

    def __init__(self, session, region: str = "us", device_id: str | None = None):
        self._session = session
        self._region = region
        self.base_url = MOBILE_REGIONS.get(region, MOBILE_REGIONS["us"])
        self.device_id = device_id or os.urandom(32).hex()

        self.sid = ""
        self.ecode = ""
        self.uid = ""
        self._hmac_key = f"{DEFAULT_CERT_SIGN}_{DEFAULT_BMP_KEY}_{DEFAULT_APP_SECRET}"

    async def _call(
        self, action: str, version: str = "1.0",
        post_data: dict | None = None, country_code: str = "",
    ) -> dict[str, Any]:
        """Make a signed API call to /api.json."""
        request_id = str(uuid_mod.uuid4())
        t = str(int(time.time()))

        params: dict[str, str] = {
            "a": action,
            "v": version,
            "clientId": DEFAULT_CLIENT_ID,
            "deviceId": self.device_id,
            "os": "Android",
            "lang": "en",
            "ttid": "tuyaSmart",
            "appVersion": "7.2.8",
            "sdkVersion": "3.29.5",
            "time": t,
            "requestId": request_id,
        }
        if self.sid:
            params["sid"] = self.sid
        if country_code:
            params["countryCode"] = country_code
        if post_data is not None:
            params["postData"] = json.dumps(post_data, separators=(",", ":"))
        params["sign"] = _sign(params, self._hmac_key)

        url = self.base_url + "/api.json"
        headers = {"User-Agent": "TuyaSmart/7.2.8 (Android)"}
        _LOGGER.debug("Tuya API call: action=%s postData=%s", action, params.get("postData"))
        async with self._session.get(url, params=params, headers=headers) as resp:
            resp.raise_for_status()
            result = await resp.json()
            _LOGGER.debug("Tuya API response: %s", result)
            return result

    async def async_login(self, country_code: str, email: str, password: str) -> dict:
        passwd_md5 = hashlib.md5(password.encode()).hexdigest()
        payload = {
            "countryCode": country_code,
            "email": email,
            "passwd": passwd_md5,
            "options": '{"group": 1}',
            "token": "",
            "ifencrypt": 0,
        }
        result = await self._call(
            "thing.m.user.email.password.login",
            version="3.0",
            post_data=payload,
            country_code=country_code,
        )
        if result.get("success"):
            user_data = result.get("result", {})
            self.sid = user_data.get("sid", "")
            self.ecode = user_data.get("ecode", "")
            self.uid = user_data.get("uid", "")
        return result

    async def async_get_ble_auth_key(self, device_uuid: str, device_mac: str = "") -> dict:
        payload = {"uuid": device_uuid}
        if device_mac:
            payload["mac"] = device_mac
        return await self._call(
            "m.thing.device.auth.key.get",
            version="3.0",
            post_data=payload,
        )

    async def async_get_home_list(self) -> dict:
        return await self._call(
            "tuya.m.location.list",
            version="2.1",
            post_data={},
        )

    async def async_list_devices(self, gid: int | str) -> dict:
        request_id = str(uuid_mod.uuid4())
        t = str(int(time.time()))
        params: dict[str, str] = {
            "a": "tuya.m.my.group.device.list",
            "v": "2.0",
            "clientId": DEFAULT_CLIENT_ID,
            "deviceId": self.device_id,
            "os": "Android",
            "lang": "en",
            "ttid": "tuyaSmart",
            "appVersion": "7.2.8",
            "sdkVersion": "3.29.5",
            "time": t,
            "requestId": request_id,
            "gid": str(gid),
            "postData": json.dumps({}, separators=(",", ":")),
        }
        if self.sid:
            params["sid"] = self.sid
        params["sign"] = _sign(params, self._hmac_key)
        url = self.base_url + "/api.json"
        headers = {"User-Agent": "TuyaSmart/7.2.8 (Android)"}
        async with self._session.get(url, params=params, headers=headers) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def async_get_device_dps(self, gid: int | str, device_id: str) -> dict:
        request_id = str(uuid_mod.uuid4())
        t = str(int(time.time()))
        params: dict[str, str] = {
            "a": "tuya.m.device.dp.get",
            "v": "2.0",
            "clientId": DEFAULT_CLIENT_ID,
            "deviceId": self.device_id,
            "os": "Android",
            "lang": "en",
            "ttid": "tuyaSmart",
            "appVersion": "7.2.8",
            "sdkVersion": "3.29.5",
            "time": t,
            "requestId": request_id,
            "gid": str(gid),
            "postData": json.dumps({"devId": device_id}, separators=(",", ":")),
        }
        if self.sid:
            params["sid"] = self.sid
        params["sign"] = _sign(params, self._hmac_key)
        url = self.base_url + "/api.json"
        headers = {"User-Agent": "TuyaSmart/7.2.8 (Android)"}
        async with self._session.get(url, params=params, headers=headers) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def async_find_device_by_mac(self, device_mac: str) -> dict | None:
        """Look up device info by MAC address via cloud API.

        Iterates homes and their devices, matching by MAC (case-insensitive,
        colon-stripped). Returns dict with uuid, devId, localKey, name or None.
        """
        mac_clean = device_mac.replace(":", "").upper()
        homes_resp = await self.async_get_home_list()
        homes_result = homes_resp.get("result", {})
        if isinstance(homes_result, dict):
            homes_result = homes_result.get("result", [])
        for home in homes_result:
            gid = home.get("groupId") or home.get("gid")
            if not gid:
                continue
            devs_resp = await self.async_list_devices(gid)
            devs_result = devs_resp.get("result", {})
            if isinstance(devs_result, dict):
                devs_result = devs_result.get("result", [])
            for dev in devs_result:
                dev_mac = (dev.get("mac") or "").replace(":", "").upper()
                if dev_mac == mac_clean:
                    return {
                        "uuid": dev.get("uuid", ""),
                        "devId": dev.get("devId", ""),
                        "localKey": dev.get("localKey", ""),
                        "name": dev.get("name", ""),
                        "productId": dev.get("productId", ""),
                        "gid": gid,
                    }
        return None

    async def async_find_device_by_dev_id(self, device_id: str) -> dict | None:
        """Look up device info by devId so follow-up calls know the gid/home."""
        homes_resp = await self.async_get_home_list()
        homes_result = homes_resp.get("result", {})
        if isinstance(homes_result, dict):
            homes_result = homes_result.get("result", [])
        for home in homes_result:
            gid = home.get("groupId") or home.get("gid")
            if not gid:
                continue
            devs_resp = await self.async_list_devices(gid)
            devs_result = devs_resp.get("result", {})
            if isinstance(devs_result, dict):
                devs_result = devs_result.get("result", [])
            for dev in devs_result:
                if dev.get("devId") == device_id:
                    return {
                        "uuid": dev.get("uuid", ""),
                        "devId": dev.get("devId", ""),
                        "localKey": dev.get("localKey", ""),
                        "name": dev.get("name", ""),
                        "productId": dev.get("productId", ""),
                        "gid": gid,
                        "raw": dev,
                    }
        return None


def _redact_cloud_value(value: Any) -> Any:
    """Redact obvious secrets before writing mobile API payloads to HA logs."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, inner in value.items():
            lowered = key.lower()
            if lowered in {"localkey", "authkey", "token", "passwd", "password", "sid"}:
                redacted[key] = "<redacted>"
            else:
                redacted[key] = _redact_cloud_value(inner)
        return redacted
    if isinstance(value, list):
        return [_redact_cloud_value(item) for item in value]
    return value


async def async_fetch_auth_key_only(
    hass: HomeAssistant, device_uuid: str, email: str, password: str,
    country_code: str, region: str,
) -> str:
    """Lightweight helper: login + get auth key only (no device lookup).

    Returns auth_key hex string. Used by standalone pairing when UUID is already known.
    """
    session = async_get_clientsession(hass)
    client = TuyaMobileAPIAsync(session, region=region)
    login_resp = await client.async_login(country_code, email, password)
    if not login_resp.get("success"):
        error = login_resp.get("errorMsg", login_resp.get("msg", "Login failed"))
        raise Exception(f"Tuya login failed: {error}")

    resp = await client.async_get_ble_auth_key(device_uuid)
    if not resp.get("success"):
        error = resp.get("errorMsg", resp.get("msg", "Auth key fetch failed"))
        raise Exception(f"Auth key fetch failed: {error}")
    result = resp.get("result", {})
    auth_key = (
        result.get("authKey")
        or result.get("auth_key")
        or result.get("encryptedAuthKey")
        or ""
    )
    if not auth_key:
        raise Exception("Auth key not found in API response")
    return auth_key


async def async_fetch_auth_key(
    hass: HomeAssistant, device_uuid: str, email: str, password: str,
    country_code: str, region: str, device_mac: str = "",
) -> dict:
    """One-shot helper: login + get auth key + device info.

    Returns dict with keys: auth_key, uuid, local_key, device_id, name.
    If device_uuid is empty, looks up device by MAC via cloud API.
    """
    session = async_get_clientsession(hass)
    client = TuyaMobileAPIAsync(session, region=region)
    login_resp = await client.async_login(country_code, email, password)
    if not login_resp.get("success"):
        error = login_resp.get("errorMsg", login_resp.get("msg", "Login failed"))
        raise Exception(f"Tuya login failed: {error}")

    cloud_info: dict = {}
    resolved_uuid = device_uuid

    # Look up device info by MAC (needed for UUID, localKey, devId)
    if device_mac:
        cloud_info = await client.async_find_device_by_mac(device_mac) or {}
        if cloud_info:
            _LOGGER.info(
                "Cloud device info: uuid=%s devId=%s name=%s",
                cloud_info.get("uuid"), cloud_info.get("devId"), cloud_info.get("name"),
            )
            if not resolved_uuid:
                resolved_uuid = cloud_info.get("uuid", "")

    if not resolved_uuid:
        raise Exception("Auth key fetch failed: no device UUID (BLE or cloud)")

    resp = await client.async_get_ble_auth_key(resolved_uuid, device_mac=device_mac)
    if not resp.get("success"):
        error = resp.get("errorMsg", resp.get("msg", "Auth key fetch failed"))
        raise Exception(f"Auth key fetch failed: {error}")
    result = resp.get("result", {})
    auth_key = (
        result.get("authKey")
        or result.get("auth_key")
        or result.get("encryptedAuthKey")
        or ""
    )
    if not auth_key:
        _LOGGER.warning("Auth key not found in API response. Result: %s", result)

    return {
        "auth_key": auth_key,
        "uuid": resolved_uuid,
        "local_key": cloud_info.get("localKey", ""),
        "device_id": cloud_info.get("devId", ""),
        "name": cloud_info.get("name", ""),
        "product_id": cloud_info.get("productId", ""),
    }


async def async_fetch_check_code_dps(
    hass: HomeAssistant,
    email: str,
    password: str,
    country_code: str,
    region: str,
    device_id: str,
    source_dps: tuple[int, ...] = (73, 71),
) -> dict[int, bytes]:
    """Fetch current RAW DP payloads for the lock's check-code DPs from Tuya cloud."""
    stable_device_id = hashlib.sha256(
        f"tuya_ble_lock|{email}|{device_id}|{region}".encode()
    ).hexdigest()
    session = async_get_clientsession(hass)
    client = TuyaMobileAPIAsync(session, region=region, device_id=stable_device_id)
    login_resp = await client.async_login(country_code, email, password)
    if not login_resp.get("success"):
        error = login_resp.get("errorMsg", login_resp.get("msg", "Login failed"))
        raise Exception(f"Tuya login failed: {error}")

    device_info = await client.async_find_device_by_dev_id(device_id)
    if not device_info or not device_info.get("gid"):
        raise Exception(f"Could not resolve gid for device {device_id}")

    dp_resp = await client.async_get_device_dps(device_info["gid"], device_id)
    result = dp_resp.get("result", {})
    if isinstance(result, dict) and "result" in result:
        result = result["result"]
    if not isinstance(result, dict):
        raise Exception(f"Unexpected DP response: {dp_resp}")

    raw_dps: dict[int, bytes] = {}
    for dp_id in source_dps:
        dp = result.get(str(dp_id))
        if not isinstance(dp, dict):
            continue
        value = dp.get("value")
        if not value or not isinstance(value, str):
            continue
        try:
            raw_dps[int(dp_id)] = base64.b64decode(value)
        except Exception:
            _LOGGER.debug("Failed to decode base64 cloud DP %s value %r", dp_id, value, exc_info=True)
    return raw_dps


async def async_fetch_cloud_lock_debug(
    hass: HomeAssistant,
    email: str,
    password: str,
    country_code: str,
    region: str,
    device_id: str,
) -> dict[str, Any]:
    """Fetch full mobile-api device object and raw DP payload map for debugging."""
    stable_device_id = hashlib.sha256(
        f"tuya_ble_lock|{email}|{device_id}|{region}".encode()
    ).hexdigest()
    session = async_get_clientsession(hass)
    client = TuyaMobileAPIAsync(session, region=region, device_id=stable_device_id)
    login_resp = await client.async_login(country_code, email, password)
    if not login_resp.get("success"):
        error = login_resp.get("errorMsg", login_resp.get("msg", "Login failed"))
        raise Exception(f"Tuya login failed: {error}")

    device_info = await client.async_find_device_by_dev_id(device_id)
    if not device_info or not device_info.get("gid"):
        raise Exception(f"Could not resolve gid for device {device_id}")

    dp_resp = await client.async_get_device_dps(device_info["gid"], device_id)
    result = dp_resp.get("result", {})
    if isinstance(result, dict) and "result" in result:
        result = result["result"]
    if not isinstance(result, dict):
        result = {}

    decoded_dps: dict[str, str] = {}
    for key, dp in result.items():
        if not isinstance(dp, dict):
            continue
        value = dp.get("value")
        if not isinstance(value, str):
            continue
        try:
            decoded_dps[str(key)] = base64.b64decode(value).hex()
        except Exception:
            continue

    return {
        "device_info": _redact_cloud_value(device_info.get("raw", device_info)),
        "device_info_keys": sorted(device_info.get("raw", device_info).keys()),
        "dp_response": _redact_cloud_value(dp_resp),
        "decoded_dp_hex": decoded_dps,
    }
