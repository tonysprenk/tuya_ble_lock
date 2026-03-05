"""Base entity class for Tuya BLE lock devices."""

from __future__ import annotations

from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN


class TuyaBLELockEntity(CoordinatorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry):
        super().__init__(coordinator)
        self._entry = entry
        self._mac = entry.data["device_mac"]

    @property
    def device_info(self) -> DeviceInfo:
        model = "BLE Smart Lock"
        rd = getattr(self._entry, "runtime_data", None)
        if rd and hasattr(rd, "profile") and rd.profile:
            model = rd.profile.get("model", model)
        return DeviceInfo(
            identifiers={(DOMAIN, self._mac)},
            name=self._entry.title,
            manufacturer="Tuya",
            model=model,
            connections={(CONNECTION_BLUETOOTH, self._mac)},
        )

    @property
    def available(self) -> bool:
        # Default CoordinatorEntity marks unavailable only when the last
        # coordinator update failed (UpdateFailed).  Between successful polls
        # entities stay available and show their last known values — even if
        # the BLE link is currently down (locks sleep between ads).
        return super().available
