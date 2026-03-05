"""Sensor platform for Tuya BLE lock."""

from __future__ import annotations

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass, SensorStateClass
from homeassistant.const import PERCENTAGE
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.restore_state import RestoreEntity

from .entity import TuyaBLELockEntity
from .models import TuyaBLELockData

# (config_entry data key, sensor name suffix, unique_id suffix)
_DIAG_KEYS = [
    ("device_uuid", "UUID", "uuid"),
    ("login_key", "Login key", "login_key"),
    ("virtual_id", "Virtual ID", "virtual_id"),
    ("auth_key", "Auth key", "auth_key"),
]


async def async_setup_entry(hass, entry, async_add_entities):
    data: TuyaBLELockData = entry.runtime_data
    profile = data.profile or {}
    entities_cfg = profile.get("entities", {})

    entities = []
    if "battery_sensor" in entities_cfg:
        entities.append(TuyaBLEBatterySensor(data.coordinator, entry))
    for conf_key, name, uid_suffix in _DIAG_KEYS:
        entities.append(TuyaBLEDiagnosticSensor(data.coordinator, entry, conf_key, name, uid_suffix))
    async_add_entities(entities)


BATTERY_STATE_TO_PERCENT = {
    "high": 100,
    "medium": 50,
    "low": 25,
    "exhausted": 5,
}


class TuyaBLEBatterySensor(TuyaBLELockEntity, SensorEntity, RestoreEntity):
    _attr_name = "Battery"
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT

    @property
    def unique_id(self):
        return f"{self._mac}_battery"

    @property
    def native_value(self) -> int | None:
        pct = self.coordinator.state.get("battery_percent")
        if pct is not None:
            return pct
        # Fall back to battery_state enum → approximate percentage
        state = self.coordinator.state.get("battery_state")
        if state:
            return BATTERY_STATE_TO_PERCENT.get(state)
        return None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        if self.coordinator.state.get("battery_percent") is None:
            last = await self.async_get_last_state()
            if last and last.state not in (None, "unknown", "unavailable"):
                try:
                    self.coordinator.state["battery_percent"] = int(float(last.state))
                except (ValueError, TypeError):
                    pass


class TuyaBLEDiagnosticSensor(TuyaBLELockEntity, SensorEntity):
    """Exposes config entry secrets as diagnostic sensors for CLI/API access."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, entry, conf_key: str, name: str, uid_suffix: str):
        self._attr_name = name
        self._uid_suffix = uid_suffix
        super().__init__(coordinator, entry)
        self._conf_key = conf_key

    @property
    def unique_id(self):
        return f"{self._mac}_{self._uid_suffix}"

    @property
    def available(self) -> bool:
        # Diagnostic sensors read from config_entry data, not BLE — always available.
        return True

    @property
    def native_value(self) -> str | None:
        return self._entry.data.get(self._conf_key)
