"""Lock platform for Tuya BLE lock.

Tracks actual locked/unlocked state via DP reports (motor_state transitions)
and passage mode sync (auto_lock DP).  State is persisted across restarts
via RestoreEntity.
"""

from __future__ import annotations

import asyncio
import logging

from homeassistant.components.lock import LockEntity
from homeassistant.helpers.restore_state import RestoreEntity

from .entity import TuyaBLELockEntity
from .models import TuyaBLELockData

_LOGGER = logging.getLogger(__name__)

LOCK_COMMAND_TIMEOUT_SECONDS = 20
LOCK_COMMAND_SAFETY_RELOCK_SECONDS = 120
LOCK_COMMAND_SAFETY_RELOCK_POLL_SECONDS = 2
LOCK_EXTERNAL_STATE_CONFIRMATIONS = 1


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
        self._queued_target_locked: bool | None = None
        self._safety_relock_task: asyncio.Task | None = None
        self._external_state_candidate: tuple[bool, str | None] | None = None
        self._external_state_candidate_count = 0
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

    def _set_pending_state(self, target_locked: bool) -> None:
        self._locking = target_locked
        self._unlocking = not target_locked
        self.async_write_ha_state()

    def _start_lock_command_task(self, target_locked: bool) -> None:
        action_name = "lock" if target_locked else "unlock"
        command = self.coordinator.async_lock if target_locked else self.coordinator.async_unlock
        self._command_task = self._start_command_task(
            self._async_run_command(action_name, command, target_locked),
            f"tuya_ble_lock_{action_name}_{self._mac}",
        )

    def _queue_or_start_command(self, target_locked: bool) -> None:
        if not target_locked:
            self._cancel_safety_relock_monitor()
        self._set_pending_state(target_locked)
        if self._command_in_progress():
            self._queued_target_locked = target_locked
            _LOGGER.info(
                "Queued %s command for %s while another command is in progress",
                "lock" if target_locked else "unlock",
                self._mac,
            )
            return
        self._queued_target_locked = None
        self._start_lock_command_task(target_locked)

    def _cancel_safety_relock_monitor(self) -> None:
        task = self._safety_relock_task
        if task is not None and not task.done():
            task.cancel()
        self._safety_relock_task = None

    def _start_safety_relock_monitor(self) -> None:
        task = self._safety_relock_task
        if task is not None and not task.done():
            return
        self._safety_relock_task = self._start_command_task(
            self._async_safety_relock_monitor(),
            f"tuya_ble_lock_safety_relock_{self._mac}",
        )

    def _motor_state_can_report_unlocked(self) -> bool:
        if not self._lock_cfg.get("motor_state_unlock_requires_command", False):
            return True
        return self._pending_target_matches(False)

    async def _async_safety_relock_monitor(self) -> None:
        deadline = asyncio.get_running_loop().time() + LOCK_COMMAND_SAFETY_RELOCK_SECONDS
        try:
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(LOCK_COMMAND_SAFETY_RELOCK_POLL_SECONDS)
                if self._command_in_progress() or self._locking:
                    continue
                if self._is_locked:
                    continue
                _LOGGER.warning(
                    "Re-locking %s because it reopened within %ds of a lock command",
                    self._mac,
                    LOCK_COMMAND_SAFETY_RELOCK_SECONDS,
                )
                self._queue_or_start_command(True)
                return
        except asyncio.CancelledError:
            raise
        finally:
            if self._safety_relock_task is asyncio.current_task():
                self._safety_relock_task = None

    def _coordinator_locked_state(self) -> tuple[bool | None, str | None]:
        """Return the most authoritative lock state currently reported by DPs."""
        motor = self.coordinator.state.get("motor_state")
        motor_true_is_unlocked = self._lock_cfg.get("motor_state_true_is_unlocked")
        locked: bool | None = None
        source: str | None = None

        if self._lock_cfg.get("auto_lock_reflects_lock_state", True):
            auto_lock = self.coordinator.state.get("auto_lock")
            if auto_lock is not None:
                locked = bool(auto_lock)
                source = "auto_lock"

        lock_state_is_shadowed = (
            motor_true_is_unlocked
            and motor is not None
            and (not bool(motor) or self._motor_state_can_report_unlocked())
        )
        lock_state = self.coordinator.state.get("lock_state")
        if (
            lock_state is not None
            and self._lock_cfg.get("lock_state_reflects_lock_state", True)
            and not lock_state_is_shadowed
        ):
            locked = bool(lock_state)
            source = "lock_state"

        if self._lock_cfg.get("motor_state_reflects_lock_state", True):
            if motor_true_is_unlocked and motor is not None:
                if bool(motor):
                    if self._motor_state_can_report_unlocked():
                        locked = False
                        source = "motor_state"
                    else:
                        _LOGGER.debug(
                            "Ignoring unsolicited unlocked motor_state for %s",
                            self._mac,
                        )
                else:
                    locked = True
                    source = "motor_state"
            elif motor is False and not self._is_locked:
                locked = True
                source = "motor_state"

        return locked, source

    def _apply_command_success_state(self, action_name: str, target_locked: bool) -> None:
        locked, source = self._coordinator_locked_state()
        target_name = "locked" if target_locked else "unlocked"

        if locked is None:
            self._is_locked = target_locked
            self._clear_external_state_candidate()
            _LOGGER.info(
                "%s command for %s completed; no confirmed state source is available, assuming %s",
                action_name.capitalize(),
                self._mac,
                target_name,
            )
            if target_locked:
                self._start_safety_relock_monitor()
            return

        reported_name = "locked" if locked else "unlocked"
        self._is_locked = locked
        self._clear_external_state_candidate()
        if locked == target_locked:
            _LOGGER.info(
                "%s command for %s confirmed by %s as %s",
                action_name.capitalize(),
                self._mac,
                source,
                target_name,
            )
            if target_locked:
                self._start_safety_relock_monitor()
            return

        _LOGGER.warning(
            "%s command for %s completed but %s still reports %s; keeping confirmed state",
            action_name.capitalize(),
            self._mac,
            source,
            reported_name,
        )

    def _clear_external_state_candidate(self) -> None:
        self._external_state_candidate = None
        self._external_state_candidate_count = 0

    def _external_state_confirmations_required(self) -> int:
        configured = self._lock_cfg.get(
            "external_state_confirmations",
            LOCK_EXTERNAL_STATE_CONFIRMATIONS,
        )
        try:
            return max(1, int(configured))
        except (TypeError, ValueError):
            return LOCK_EXTERNAL_STATE_CONFIRMATIONS

    def _pending_target_matches(self, locked: bool) -> bool:
        return (self._locking and locked) or (self._unlocking and not locked)

    def _apply_external_locked_state(self, locked: bool, source: str | None) -> bool:
        """Apply unsolicited state reports only after enough matching evidence."""
        if locked == self._is_locked:
            self._clear_external_state_candidate()
            return False

        if self._pending_target_matches(locked):
            self._is_locked = locked
            self._clear_external_state_candidate()
            _LOGGER.info(
                "Accepted %s state for %s from %s while command is pending",
                "locked" if locked else "unlocked",
                self._mac,
                source,
            )
            if locked:
                self._start_safety_relock_monitor()
            else:
                self._cancel_safety_relock_monitor()
            return True

        confirmations_required = self._external_state_confirmations_required()
        candidate = (locked, source)
        if self._external_state_candidate == candidate:
            self._external_state_candidate_count += 1
        else:
            self._external_state_candidate = candidate
            self._external_state_candidate_count = 1

        if self._external_state_candidate_count < confirmations_required:
            _LOGGER.debug(
                "Holding external %s state for %s from %s until %d/%d confirmations",
                "locked" if locked else "unlocked",
                self._mac,
                source,
                self._external_state_candidate_count,
                confirmations_required,
            )
            return False

        self._is_locked = locked
        self._clear_external_state_candidate()
        _LOGGER.info(
            "Accepted external %s state for %s from %s after %d confirmations",
            "locked" if locked else "unlocked",
            self._mac,
            source,
            confirmations_required,
        )
        return True

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
            self._apply_command_success_state(action_name, target_locked)
        finally:
            if action_name == "lock":
                self._locking = False
            else:
                self._unlocking = False
            self.async_write_ha_state()
            if self._command_task is asyncio.current_task():
                self._command_task = None
                queued_target = self._queued_target_locked
                self._queued_target_locked = None
                if queued_target is not None and queued_target != self._is_locked:
                    self._queue_or_start_command(queued_target)

    async def async_lock(self, **kwargs) -> None:
        self._queue_or_start_command(True)

    async def async_unlock(self, **kwargs) -> None:
        self._queue_or_start_command(False)

    def _handle_coordinator_update(self) -> None:
        """React to DP pushes for lock state.

        Motor-state interpretation is profile-specific. The Raykube profile
        treats DP47 True as unlocked and uses it as the physical source of truth.
        Older profiles only use motor_state=False as a relock signal.

        Passage mode sync:
        - auto_lock=False (passage ON) = lock is unlocked
        - auto_lock=True (passage OFF) = lock is locked
        """
        locked, source = self._coordinator_locked_state()
        if locked is not None:
            self._apply_external_locked_state(locked, source)

        super()._handle_coordinator_update()
