"""Tuya BLE Smart Lock integration entry points."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.components import bluetooth
from homeassistant.const import Platform
from homeassistant.exceptions import ConfigEntryNotReady

from .const import DOMAIN
from .credential_store import CredentialStore
from .coordinator import TuyaBLELockCoordinator
from .device_profiles import async_load_profile
from .models import TuyaBLELockData

_LOGGER = logging.getLogger(__name__)


def _platforms_for_profile(profile: dict) -> list[Platform]:
    """Determine which HA platforms to load based on profile entities."""
    entities = profile.get("entities", {})
    platforms = [Platform.LOCK, Platform.SENSOR, Platform.BUTTON]

    if "volume_select" in entities:
        platforms.append(Platform.SELECT)
    if "double_lock_switch" in entities or "auto_lock_switch" in entities:
        platforms.append(Platform.SWITCH)
    if "auto_lock_time_number" in entities:
        platforms.append(Platform.NUMBER)

    return platforms


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    from .services import async_register_services

    await async_register_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    if DOMAIN not in hass.data:
        hass.data[DOMAIN] = {}
    if "credential_store" not in hass.data[DOMAIN]:
        store = CredentialStore(hass)
        await store.async_load()
        hass.data[DOMAIN]["credential_store"] = store
    credential_store = hass.data[DOMAIN]["credential_store"]

    mac = entry.data["device_mac"]
    ble_device = bluetooth.async_ble_device_from_address(hass, mac, connectable=True)
    if not ble_device:
        raise ConfigEntryNotReady(f"BLE device {mac} not available")

    login_key = bytes.fromhex(entry.data["login_key"])
    virtual_id = bytes.fromhex(entry.data["virtual_id"])
    device_uuid = entry.data.get("device_uuid", "")
    product_id = entry.data.get("product_id")

    profile = await async_load_profile(hass, product_id)

    from .ble_session import TuyaBLELockSession

    protocol_version = profile.get("protocol_version", 4)
    session = TuyaBLELockSession(
        hass, ble_device, login_key, virtual_id, device_uuid,
        protocol_version=protocol_version,
    )

    coordinator = TuyaBLELockCoordinator(hass, entry, ble_device, session, profile)

    # One-shot status fetch in background — single attempt, no retries.
    entry.async_create_background_task(
        hass, coordinator.async_one_shot_status(), "tuya_ble_lock_status"
    )

    platforms = _platforms_for_profile(profile)
    entry.runtime_data = TuyaBLELockData(
        coordinator=coordinator,
        credential_store=credential_store,
        profile=profile,
        platforms=platforms,
    )

    await hass.config_entries.async_forward_entry_setups(entry, platforms)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data: TuyaBLELockData = entry.runtime_data
    await data.coordinator._session.async_disconnect()
    return await hass.config_entries.async_unload_platforms(entry, data.platforms)
