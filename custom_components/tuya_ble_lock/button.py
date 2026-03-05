"""Button platform for Tuya BLE lock."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.const import EntityCategory

from .entity import TuyaBLELockEntity
from .models import TuyaBLELockData


async def async_setup_entry(hass, entry, async_add_entities):
    data: TuyaBLELockData = entry.runtime_data
    async_add_entities([
        TuyaBLERefreshButton(data.coordinator, entry),
    ])


class TuyaBLERefreshButton(TuyaBLELockEntity, ButtonEntity):
    _attr_name = "Refresh status"
    _attr_icon = "mdi:refresh"
    _attr_entity_category = EntityCategory.CONFIG

    @property
    def unique_id(self):
        return f"{self._mac}_refresh"

    async def async_press(self) -> None:
        await self.coordinator.async_request_refresh()
