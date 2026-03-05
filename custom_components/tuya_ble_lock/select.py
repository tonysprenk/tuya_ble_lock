"""Select platform for Tuya BLE lock."""

from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.const import EntityCategory
from homeassistant.helpers.restore_state import RestoreEntity

from .entity import TuyaBLELockEntity
from .models import TuyaBLELockData


async def async_setup_entry(hass, entry, async_add_entities):
    data: TuyaBLELockData = entry.runtime_data
    profile = data.profile or {}
    vol_cfg = profile.get("entities", {}).get("volume_select")

    entities = []
    if vol_cfg:
        options = [o.capitalize() for o in vol_cfg.get("options", ["mute", "normal"])]
        entities.append(TuyaBLEVolumeSelect(data.coordinator, entry, options))

    if entities:
        async_add_entities(entities)


class TuyaBLEVolumeSelect(TuyaBLELockEntity, SelectEntity, RestoreEntity):
    _attr_name = "Keypad sound"
    _attr_icon = "mdi:volume-high"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator, entry, options: list[str]):
        super().__init__(coordinator, entry)
        self._attr_options = options
        # Build bidirectional mappings: "Mute" <-> 0, "Normal" <-> 1, etc.
        self._label_to_val = {label: idx for idx, label in enumerate(options)}
        self._val_to_label = {idx: label for idx, label in enumerate(options)}

    @property
    def unique_id(self):
        return f"{self._mac}_volume"

    @property
    def current_option(self) -> str | None:
        vol = self.coordinator.state.get("volume")
        if vol is None:
            return None
        return self._val_to_label.get(vol, f"unknown_{vol}")

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        if self.coordinator.state.get("volume") is None:
            last = await self.async_get_last_state()
            if last and last.state in self._label_to_val:
                self.coordinator.state["volume"] = self._label_to_val[last.state]

    async def async_select_option(self, option: str) -> None:
        value = self._label_to_val.get(option)
        if value is not None:
            await self.coordinator.async_set_volume(value)
