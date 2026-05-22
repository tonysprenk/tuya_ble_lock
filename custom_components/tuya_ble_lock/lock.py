"""Lock platform for Tuya BLE lock.

Tracks actual locked/unlocked state via DP reports (motor_state transitions)
and passage mode sync (auto_lock DP).  State is persisted across restarts
via RestoreEntity.
"""

from __future__ import annotations

import asyncio
import logging

from homeassistant.components.lock import LockEntity
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.restore_state import RestoreEntity

from .entity import TuyaBLELockEntity
from .models import TuyaBLELockData

_LOGGER = logging.getLogger(__name__)

LOCK_COMMAND_TIMEOUT_SECONDS = 45


async def async_setup_entry(hass, entry, async_add_entities):
    data: TuyaBLELockData = entry.runtime_data
    async_add_entities([TuyaBLELock(data.coordinator, entry)])


class TuyaBLELock(TuyaBLELockEntity, LockEntity, RestoreEntity):
    _attr_name = None
    _attr_unique_id_suffix = "lock"

    def __init__(self, coordinator, entry) -> None:
        super().__init__(coordinator, entry)
        self._locking = False
        self._unlocking = False
        self._command_task: asyncio.Task | None = None
        self._is_locked = True
        runtime_data = getattr(entry, "runtime_data", None)
        profile = getattr(runtime_data, "profile", {}) if runtime_data else {}
        self._lock_cfg = profile.get("entities", {}).get("lock", {})

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
        return self._locking

    @property
    def is_unlocking(self) -> bool:
        return self._unlocking

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last = await self.async_get_last_state()
        if last and last.state in ("locked", "unlocked"):
            self._is_locked = last.state == "locked"

    def _command_in_progress(self) -> bool:
        return self._command_task is not None and not self._command_task.done()

    def _start_command_task(self, coro, name: str) -> asyncio.Task:
        hass = getattr(self, "hass", None)
        if hass is not None:
            return hass.async_create_task(coro, name=name)
        return asyncio.create_task(coro, name=name)

    async def _async_run_command(self, action_name: str, command, target_locked: bool) -> None:
        try:
            await asyncio.wait_for(
                command(),
                timeout=LOCK_COMMAND_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            _LOGGER.warning(
                "Timed out %s %s after %ds",
                action_name,
                self._mac,
                LOCK_COMMAND_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            _LOGGER.warning("Failed to %s %s: %s", action_name, self._mac, exc)
        else:
            self._is_locked = target_locked
        finally:
            if action_name == "lock":
                self._locking = False
            else:
                self._unlocking = False
            self.async_write_ha_state()
            if self._command_task is asyncio.current_task():
                self._command_task = None

    async def async_lock(self, **kwargs) -> None:
        if self._command_in_progress():
            raise HomeAssistantError("A Tuya BLE lock command is already in progress")
        self._locking = True
        self.async_write_ha_state()
        self._command_task = self._start_command_task(
            self._async_run_command("lock", self.coordinator.async_lock, True),
            f"tuya_ble_lock_lock_{self._mac}",
        )

    async def async_unlock(self, **kwargs) -> None:
        if self._command_in_progress():
            raise HomeAssistantError("A Tuya BLE lock command is already in progress")
        self._unlocking = True
        self.async_write_ha_state()
        self._command_task = self._start_command_task(
            self._async_run_command("unlock", self.coordinator.async_unlock, False),
            f"tuya_ble_lock_unlock_{self._mac}",
        )

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
        if self._lock_cfg.get("motor_state_reflects_lock_state", True):
            motor = self.coordinator.state.get("motor_state")
            if self._lock_cfg.get("motor_state_true_is_unlocked"):
                if motor is True and self._is_locked:
                    self._is_locked = False
            if motor is False and not self._is_locked:
                self._is_locked = True

        if self._lock_cfg.get("auto_lock_reflects_lock_state", True):
            auto_lock = self.coordinator.state.get("auto_lock")
            if auto_lock is not None:
                if auto_lock is False and self._is_locked:
                    self._is_locked = False
                elif auto_lock is True and not self._is_locked:
                    self._is_locked = True

        lock_state = self.coordinator.state.get("lock_state")
        if lock_state is not None:
            self._is_locked = bool(lock_state)

        super()._handle_coordinator_update()
