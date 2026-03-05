"""Number platform for Tuya BLE lock."""

from __future__ import annotations

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.const import EntityCategory, UnitOfTime
from homeassistant.helpers.restore_state import RestoreEntity

from .entity import TuyaBLELockEntity
from .models import TuyaBLELockData


async def async_setup_entry(hass, entry, async_add_entities):
    data: TuyaBLELockData = entry.runtime_data
    profile = data.profile or {}
    entities_cfg = profile.get("entities", {})

    entities = []
    if "auto_lock_time_number" in entities_cfg:
        cfg = entities_cfg["auto_lock_time_number"]
        entities.append(TuyaBLEAutoLockTimeNumber(data.coordinator, entry, cfg))

    if entities:
        async_add_entities(entities)


class TuyaBLEAutoLockTimeNumber(TuyaBLELockEntity, NumberEntity, RestoreEntity):
    _attr_name = "Auto-lock delay"
    _attr_icon = "mdi:timer-lock-outline"
    _attr_mode = NumberMode.BOX
    _attr_entity_category = EntityCategory.CONFIG
    _attr_native_unit_of_measurement = UnitOfTime.SECONDS

    def __init__(self, coordinator, entry, cfg: dict) -> None:
        super().__init__(coordinator, entry)
        self._attr_native_min_value = cfg.get("min", 1)
        self._attr_native_max_value = cfg.get("max", 600)
        self._attr_native_step = 1

    @property
    def unique_id(self):
        return f"{self._mac}_auto_lock_time"

    @property
    def native_value(self) -> float | None:
        val = self.coordinator.state.get("auto_lock_time")
        return float(val) if val is not None else None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        if self.coordinator.state.get("auto_lock_time") is None:
            last = await self.async_get_last_state()
            if last and last.state not in (None, "unknown", "unavailable"):
                try:
                    self.coordinator.state["auto_lock_time"] = int(float(last.state))
                except (ValueError, TypeError):
                    pass

    async def async_set_native_value(self, value: float) -> None:
        await self.coordinator.async_set_auto_lock_time(int(value))
