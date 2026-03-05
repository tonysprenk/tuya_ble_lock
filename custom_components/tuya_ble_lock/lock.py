"""Lock platform for Tuya BLE lock.

Tracks actual locked/unlocked state via DP reports (motor_state transitions)
and passage mode sync (auto_lock DP).  State is persisted across restarts
via RestoreEntity.
"""

from __future__ import annotations

from homeassistant.components.lock import LockEntity
from homeassistant.helpers.restore_state import RestoreEntity

from .entity import TuyaBLELockEntity
from .models import TuyaBLELockData


async def async_setup_entry(hass, entry, async_add_entities):
    data: TuyaBLELockData = entry.runtime_data
    async_add_entities([TuyaBLELock(data.coordinator, entry)])


class TuyaBLELock(TuyaBLELockEntity, LockEntity, RestoreEntity):
    _attr_name = None
    _attr_unique_id_suffix = "lock"

    def __init__(self, coordinator, entry) -> None:
        super().__init__(coordinator, entry)
        self._unlocking = False
        self._is_locked = True

    @property
    def unique_id(self) -> str:
        return f"{self._mac}_lock"

    @property
    def icon(self) -> str:
        return "mdi:lock" if self.is_locked else "mdi:lock-open"

    @property
    def is_locked(self) -> bool:
        return self._is_locked

    @property
    def is_locking(self) -> bool:
        return False

    @property
    def is_unlocking(self) -> bool:
        return self._unlocking

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last = await self.async_get_last_state()
        if last and last.state in ("locked", "unlocked"):
            self._is_locked = last.state == "locked"

    async def async_lock(self, **kwargs) -> None:
        await self.coordinator.async_lock()
        self._is_locked = True
        self.async_write_ha_state()

    async def async_unlock(self, **kwargs) -> None:
        self._unlocking = True
        self.async_write_ha_state()
        await self.coordinator.async_unlock()
        self._unlocking = False
        self._is_locked = False
        self.async_write_ha_state()

    def _handle_coordinator_update(self) -> None:
        """React to DP pushes for lock state.

        Motor state:
        - True = motor actively running (lock/unlock in progress)
        - False = motor stopped → lock is now locked
        Only re-lock when currently unlocked to avoid spurious updates.

        Passage mode sync:
        - auto_lock=False (passage ON) = lock is unlocked
        - auto_lock=True (passage OFF) = lock is locked
        """
        motor = self.coordinator.state.get("motor_state")
        if motor is False and not self._is_locked:
            self._is_locked = True

        auto_lock = self.coordinator.state.get("auto_lock")
        if auto_lock is not None:
            if auto_lock is False and self._is_locked:
                self._is_locked = False
            elif auto_lock is True and not self._is_locked:
                self._is_locked = True

        super()._handle_coordinator_update()
