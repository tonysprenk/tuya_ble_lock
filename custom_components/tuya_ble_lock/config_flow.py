"""Config flow for Tuya BLE Smart Lock."""

from __future__ import annotations

import asyncio
import binascii
import hashlib
import logging

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.components import bluetooth

from .const import (
    DOMAIN,
    CONF_DEVICE_MAC,
    CONF_DEVICE_UUID,
    CONF_LOGIN_KEY,
    CONF_VIRTUAL_ID,
    CONF_AUTH_KEY,
    CONF_PRODUCT_ID,
    CONF_TUYA_EMAIL,
    CONF_TUYA_PASSWORD,
    CONF_TUYA_COUNTRY,
    CONF_TUYA_REGION,
)
from .device_profiles import async_get_profile_choices
from .tuya_cloud import async_fetch_auth_key, async_fetch_auth_key_only

_LOGGER = logging.getLogger(__name__)


def _decrypt_uuid(service_data: bytes, encrypted_id: bytes) -> str:
    """Decrypt device UUID from BLE advertisement.

    Key = IV = MD5(FD50 service data). Ciphertext = manufacturer_data[4:20].
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = hashlib.md5(service_data).digest()
    dec = Cipher(algorithms.AES(key), modes.CBC(key)).decryptor()
    return (dec.update(encrypted_id) + dec.finalize()).decode("ascii").rstrip("\x00")


STEP_USER_DATA_SCHEMA = vol.Schema({
    vol.Required(CONF_DEVICE_MAC): str,
})

STEP_CLOUD_SCHEMA = vol.Schema({
    vol.Required(CONF_EMAIL): str,
    vol.Required(CONF_PASSWORD): str,
    vol.Required("country_code", description={"suggested_value": "1"}): str,
    vol.Required("region", default="us"): vol.In(["us", "eu", "cn", "in"]),
})

STEP_MANUAL_AUTH_SCHEMA = vol.Schema({
    vol.Required(CONF_AUTH_KEY): str,
})

STEP_EXISTING_CREDS_SCHEMA = vol.Schema({
    vol.Required(CONF_LOGIN_KEY): str,
    vol.Required(CONF_VIRTUAL_ID): str,
})


class TuyaBLELockConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self):
        self._discovered_device = None
        self._uuid = None
        self._mac = None
        self._name = None
        self._auth_key = None
        self._email = None
        self._password = None
        self._country = None
        self._region = None
        self._login_key = None
        self._virtual_id = None
        self._cloud_local_key = None
        self._cloud_device_id = None
        self._product_id = None
        self._setup_method = None

    async def async_step_bluetooth(self, discovery_info):
        self._mac = discovery_info.address
        self._name = discovery_info.name or ""
        # Try to decrypt UUID from FD50 service data (standard Tuya BLE)
        svc_data = None
        for suuid, sd in (discovery_info.service_data or {}).items():
            if "fd50" in suuid.lower():
                svc_data = sd
                break
        man = discovery_info.manufacturer_data.get(0x07D0)
        if svc_data and man and len(man) >= 20:
            try:
                self._uuid = _decrypt_uuid(bytes(svc_data), bytes(man[4:20]))
                _LOGGER.debug("Bluetooth discovery UUID: %s", self._uuid)
            except Exception:
                _LOGGER.debug("UUID decryption failed in bluetooth step", exc_info=True)
                self._uuid = None
        # A201 devices: UUID will be resolved via cloud API during auth key fetch
        if not self._uuid:
            has_a201 = any("a201" in suuid.lower() for suuid in (discovery_info.service_data or {}))
            if has_a201:
                _LOGGER.info("A201 Tuya BLE device detected (MAC=%s), UUID will be resolved via cloud", self._mac)
        if self._uuid:
            await self.async_set_unique_id(self._uuid)
            self._abort_if_unique_id_configured()
        return await self.async_step_choose_method()

    def _try_extract_uuid_from_advertisement(self) -> None:
        """Try to decrypt UUID from cached BLE advertisement data."""
        if self._uuid or not self._mac:
            return
        try:
            service_info = bluetooth.async_last_service_info(self.hass, self._mac)
            if not service_info:
                _LOGGER.debug("No cached service info for %s", self._mac)
                return
            svc_data = None
            for suuid, sd in (service_info.service_data or {}).items():
                if "fd50" in suuid.lower():
                    svc_data = sd
                    break
            man = service_info.manufacturer_data.get(0x07D0)
            if svc_data and man and len(man) >= 20:
                self._uuid = _decrypt_uuid(bytes(svc_data), bytes(man[4:20]))
                _LOGGER.debug("Extracted UUID from advertisement: %s", self._uuid)
            else:
                # Check for A201 service data (alternative Tuya BLE format)
                has_a201 = any("a201" in suuid.lower() for suuid in (service_info.service_data or {}))
                if has_a201:
                    _LOGGER.info("A201 device detected — UUID will be resolved via cloud API")
                else:
                    _LOGGER.debug(
                        "Incomplete advertisement data: svc_data=%s, man=%s",
                        svc_data is not None, man.hex() if man else None,
                    )
        except Exception:
            _LOGGER.debug("Could not extract UUID from advertisement", exc_info=True)

    async def async_step_user(self, user_input=None):
        if user_input:
            self._mac = user_input[CONF_DEVICE_MAC]
            dev = bluetooth.async_ble_device_from_address(self.hass, self._mac)
            if not dev:
                return self.async_show_form(
                    step_id="user",
                    data_schema=STEP_USER_DATA_SCHEMA,
                    errors={"base": "device_not_found"},
                )
            self._discovered_device = dev
            self._try_extract_uuid_from_advertisement()
            return await self.async_step_choose_method()
        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
        )

    async def async_step_choose_method(self, user_input=None):
        """Let user choose between cloud-assisted, standalone, or manual setup."""
        if user_input:
            method = user_input.get("setup_method", "cloud")
            self._setup_method = method
            if method == "cloud":
                return await self.async_step_cloud_login()
            elif method == "standalone":
                return await self.async_step_standalone()
            else:
                return await self.async_step_manual_auth()
        return self.async_show_form(
            step_id="choose_method",
            data_schema=vol.Schema({
                vol.Required("setup_method", default="cloud"): vol.In({
                    "cloud": "Tuya Cloud credentials (recommended)",
                    "standalone": "Standalone pairing (no cloud device lookup)",
                    "manual": "Manual (paste auth key)",
                }),
            }),
            description_placeholders={"name": self._name or self._mac},
        )

    async def async_step_cloud_login(self, user_input=None):
        if user_input:
            self._email = user_input[CONF_EMAIL]
            self._password = user_input[CONF_PASSWORD]
            self._country = user_input["country_code"]
            self._region = user_input["region"]
            _LOGGER.debug(
                "Fetching auth key: uuid=%r, mac=%r, region=%s",
                self._uuid, self._mac, self._region,
            )
            try:
                cloud_result = await async_fetch_auth_key(
                    self.hass,
                    self._uuid or "",
                    self._email,
                    self._password,
                    self._country,
                    self._region,
                    device_mac=self._mac or "",
                )
                self._auth_key = cloud_result["auth_key"]
                self._cloud_local_key = cloud_result.get("local_key", "")
                self._cloud_device_id = cloud_result.get("device_id", "")
                if not self._name and cloud_result.get("name"):
                    self._name = cloud_result["name"]
                if cloud_result.get("product_id"):
                    self._product_id = cloud_result["product_id"]
                # If UUID was resolved from cloud (A201 devices), store it
                if cloud_result.get("uuid") and not self._uuid:
                    self._uuid = cloud_result["uuid"]
                    _LOGGER.info("UUID resolved via cloud: %s", self._uuid)
                    await self.async_set_unique_id(self._uuid)
                    self._abort_if_unique_id_configured()
            except Exception:
                _LOGGER.exception("Auth key fetch failed")
                return self.async_show_form(
                    step_id="cloud_login",
                    data_schema=STEP_CLOUD_SCHEMA,
                    errors={"base": "auth_key_failed"},
                )

            # If we have cloud device info, derive credentials directly
            # (device is already bound to the Tuya account)
            if self._cloud_local_key and self._cloud_device_id:
                _LOGGER.info(
                    "Device already bound — deriving credentials from cloud "
                    "(localKey=%s..., devId=%s)",
                    self._cloud_local_key[:4], self._cloud_device_id,
                )
                login_key = self._cloud_local_key[:6].encode()
                virtual_id = self._cloud_device_id.encode()
                virtual_id = (virtual_id + b"\x00" * 22)[:22]
                self._login_key = login_key.hex()
                self._virtual_id = virtual_id.hex()
                return await self.async_step_confirm()

            # Device not yet bound — need BLE pairing
            return await self.async_step_pair()
        return self.async_show_form(
            step_id="cloud_login",
            data_schema=STEP_CLOUD_SCHEMA,
        )

    async def async_step_standalone(self, user_input=None):
        """Standalone pairing: pick lock model, login to Tuya for auth key only."""
        errors = {}
        if user_input:
            self._product_id = user_input.get(CONF_PRODUCT_ID)
            self._email = user_input[CONF_EMAIL]
            self._password = user_input[CONF_PASSWORD]
            self._country = user_input["country_code"]
            self._region = user_input.get("region", "us")

            if not self._uuid:
                self._try_extract_uuid_from_advertisement()
            if not self._uuid:
                # Try resolving via cloud MAC lookup as last resort
                try:
                    cloud_result = await async_fetch_auth_key(
                        self.hass, "", self._email, self._password,
                        self._country, self._region, device_mac=self._mac or "",
                    )
                    self._auth_key = cloud_result["auth_key"]
                    if cloud_result.get("uuid"):
                        self._uuid = cloud_result["uuid"]
                        await self.async_set_unique_id(self._uuid)
                        self._abort_if_unique_id_configured()
                    return await self.async_step_pair()
                except Exception:
                    _LOGGER.exception("UUID resolution + auth key fetch failed")
                    errors["base"] = "no_uuid"
            else:
                try:
                    auth_key = await async_fetch_auth_key_only(
                        self.hass, self._uuid, self._email, self._password,
                        self._country, self._region,
                    )
                    self._auth_key = auth_key
                    return await self.async_step_pair()
                except Exception:
                    _LOGGER.exception("Auth key fetch failed")
                    errors["base"] = "auth_key_failed"

        # Build schema dynamically with available profiles
        profile_choices = await async_get_profile_choices(self.hass)
        if not profile_choices:
            profile_choices = {"_default": "Default (generic lock)"}

        schema = vol.Schema({
            vol.Required(CONF_PRODUCT_ID): vol.In(profile_choices),
            vol.Required(CONF_EMAIL): str,
            vol.Required(CONF_PASSWORD): str,
            vol.Required("country_code", description={"suggested_value": "1"}): str,
            vol.Required("region", default="us"): vol.In(["us", "eu", "cn", "in"]),
        })
        return self.async_show_form(
            step_id="standalone",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "name": self._name or self._mac,
                "uuid": self._uuid or "(will resolve via cloud)",
            },
        )

    async def async_step_manual_auth(self, user_input=None):
        """Handle manual auth key entry (paste known key)."""
        if user_input:
            self._auth_key = user_input[CONF_AUTH_KEY]
            # With manual auth key, always attempt BLE pairing
            return await self.async_step_pair()
        return self.async_show_form(
            step_id="manual_auth",
            data_schema=STEP_MANUAL_AUTH_SCHEMA,
        )

    async def async_step_pair(self, user_input=None):
        from .ble_session import TuyaBLELockSession, DeviceAlreadyBoundError

        ble_device = bluetooth.async_ble_device_from_address(
            self.hass, self._mac, connectable=True
        )
        if not ble_device:
            return self.async_show_form(
                step_id="pair",
                errors={"base": "device_not_found"},
            )

        session = TuyaBLELockSession(
            self.hass,
            ble_device,
            b"",  # no login_key yet
            b"",  # no virtual_id yet
            self._uuid or "",
            auth_key=binascii.unhexlify(self._auth_key) if self._auth_key else None,
        )

        try:
            login_key, virtual_id = await asyncio.wait_for(
                session.async_pair_first_activation(self._auth_key),
                timeout=120.0,
            )
            self._login_key = login_key.hex()
            self._virtual_id = virtual_id.hex()
        except DeviceAlreadyBoundError:
            # Cloud path: we already handled this above, but just in case
            if self._cloud_local_key and self._cloud_device_id:
                login_key = self._cloud_local_key[:6].encode()
                virtual_id = self._cloud_device_id.encode()
                virtual_id = (virtual_id + b"\x00" * 22)[:22]
                self._login_key = login_key.hex()
                self._virtual_id = virtual_id.hex()
                return await self.async_step_confirm()
            # Manual path: ask user for existing credentials
            _LOGGER.warning("Device already bound but no cloud credentials — requesting manual input")
            return await self.async_step_existing_credentials()
        except Exception:
            _LOGGER.exception("Pairing failed")
            return self.async_show_form(
                step_id="pair",
                errors={"base": "pairing_failed"},
            )
        return await self.async_step_confirm()

    async def async_step_existing_credentials(self, user_input=None):
        """Handle already-bound device by accepting existing login_key/virtual_id."""
        if user_input:
            self._login_key = user_input[CONF_LOGIN_KEY]
            self._virtual_id = user_input[CONF_VIRTUAL_ID]
            return await self.async_step_confirm()
        return self.async_show_form(
            step_id="existing_credentials",
            data_schema=STEP_EXISTING_CREDS_SCHEMA,
        )

    async def async_step_confirm(self, user_input=None):
        if user_input is not None:
            data = {
                CONF_DEVICE_MAC: self._mac,
                CONF_DEVICE_UUID: self._uuid or "",
                CONF_LOGIN_KEY: self._login_key,
                CONF_VIRTUAL_ID: self._virtual_id,
                CONF_AUTH_KEY: self._auth_key,
                CONF_PRODUCT_ID: self._product_id or "",
            }
            options = {
                CONF_TUYA_EMAIL: self._email,
                CONF_TUYA_PASSWORD: self._password,
                CONF_TUYA_COUNTRY: self._country,
                CONF_TUYA_REGION: self._region,
            }
            return self.async_create_entry(
                title=self._name or self._mac, data=data, options=options
            )
        return self.async_show_form(
            step_id="confirm",
            description_placeholders={"name": self._name, "mac": self._mac},
        )

    async def async_step_reauth(self, user_input=None):
        return await self.async_step_cloud_login()
