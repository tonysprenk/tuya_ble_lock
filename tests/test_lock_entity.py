from __future__ import annotations

import asyncio
import importlib
import logging
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace


INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "tuya_ble_lock"


class FakeEntityBase:
    pass


class FakeCoordinatorEntity(FakeEntityBase):
    def __init__(self, coordinator):
        self.coordinator = coordinator
        self.write_count = 0

    @property
    def available(self):
        return True

    def async_write_ha_state(self):
        self.write_count += 1

    def _handle_coordinator_update(self):
        pass


class FakeLockEntity(FakeEntityBase):
    pass


class FakeHomeAssistantError(Exception):
    pass


class FakeHass:
    def async_create_task(self, coro, name=None):
        return asyncio.create_task(coro, name=name)


class FakeRestoreEntity(FakeEntityBase):
    async def async_get_last_state(self):
        return None


def install_homeassistant_stubs() -> None:
    custom_components = types.ModuleType("custom_components")
    tuya_ble_lock = types.ModuleType("custom_components.tuya_ble_lock")
    tuya_ble_lock.__path__ = [str(INTEGRATION_DIR)]

    ha = types.ModuleType("homeassistant")
    components = types.ModuleType("homeassistant.components")
    lock_mod = types.ModuleType("homeassistant.components.lock")
    lock_mod.LockEntity = FakeLockEntity

    helpers = types.ModuleType("homeassistant.helpers")
    restore_state = types.ModuleType("homeassistant.helpers.restore_state")
    restore_state.RestoreEntity = FakeRestoreEntity

    exceptions = types.ModuleType("homeassistant.exceptions")
    exceptions.HomeAssistantError = FakeHomeAssistantError

    device_registry = types.ModuleType("homeassistant.helpers.device_registry")
    device_registry.CONNECTION_BLUETOOTH = "bluetooth"

    entity_mod = types.ModuleType("homeassistant.helpers.entity")
    entity_mod.DeviceInfo = dict

    update_coordinator = types.ModuleType("homeassistant.helpers.update_coordinator")
    update_coordinator.CoordinatorEntity = FakeCoordinatorEntity

    sys.modules.update(
        {
            "custom_components": custom_components,
            "custom_components.tuya_ble_lock": tuya_ble_lock,
            "homeassistant": ha,
            "homeassistant.components": components,
            "homeassistant.components.lock": lock_mod,
            "homeassistant.exceptions": exceptions,
            "homeassistant.helpers": helpers,
            "homeassistant.helpers.restore_state": restore_state,
            "homeassistant.helpers.device_registry": device_registry,
            "homeassistant.helpers.entity": entity_mod,
            "homeassistant.helpers.update_coordinator": update_coordinator,
        }
    )


class ControlledCoordinator:
    def __init__(self):
        self.state = {}
        self.lock_started = asyncio.Event()
        self.unlock_started = asyncio.Event()
        self.finish_lock = asyncio.Event()
        self.finish_unlock = asyncio.Event()
        self.lock_error = None
        self.unlock_error = None
        self.lock_count = 0
        self.unlock_count = 0

    async def async_lock(self):
        self.lock_count += 1
        self.lock_started.set()
        await self.finish_lock.wait()
        if self.lock_error:
            raise self.lock_error

    async def async_unlock(self):
        self.unlock_count += 1
        self.unlock_started.set()
        await self.finish_unlock.wait()
        if self.unlock_error:
            raise self.unlock_error


class TuyaBLELockEntityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_homeassistant_stubs()
        sys.modules.pop("custom_components.tuya_ble_lock.lock", None)
        cls.lock_module = importlib.import_module("custom_components.tuya_ble_lock.lock")

    def make_entity(self):
        coordinator = ControlledCoordinator()
        entry = SimpleNamespace(
            data={"device_mac": "DC:23:51:D9:8B:86"},
            runtime_data=SimpleNamespace(profile={}),
        )
        entity = self.lock_module.TuyaBLELock(coordinator, entry)
        entity.hass = FakeHass()
        return entity, coordinator

    def test_unlock_returns_before_ble_command_finishes(self):
        async def scenario():
            entity, coordinator = self.make_entity()

            await asyncio.wait_for(entity.async_unlock(), timeout=0.05)

            self.assertTrue(entity.is_unlocking)
            self.assertTrue(entity.is_locked)
            self.assertIsNotNone(entity._command_task)
            task = entity._command_task

            await asyncio.wait_for(coordinator.unlock_started.wait(), timeout=0.05)
            coordinator.finish_unlock.set()
            await asyncio.wait_for(task, timeout=0.2)

            self.assertFalse(entity.is_unlocking)
            self.assertFalse(entity.is_locked)

        asyncio.run(scenario())

    def test_unlock_failure_clears_unlocking_state_without_changing_lock_state(self):
        async def scenario():
            entity, coordinator = self.make_entity()
            coordinator.unlock_error = RuntimeError("unlock command failed")

            await asyncio.wait_for(entity.async_unlock(), timeout=0.05)
            self.assertTrue(entity.is_unlocking)
            task = entity._command_task

            await asyncio.wait_for(coordinator.unlock_started.wait(), timeout=0.05)
            coordinator.finish_unlock.set()
            previous_disable_level = logging.root.manager.disable
            logging.disable(logging.CRITICAL)
            try:
                await asyncio.wait_for(task, timeout=0.2)
            finally:
                logging.disable(previous_disable_level)

            self.assertFalse(entity.is_unlocking)
            self.assertTrue(entity.is_locked)

        asyncio.run(scenario())

    def test_lock_failure_clears_locking_state_without_changing_lock_state(self):
        async def scenario():
            entity, coordinator = self.make_entity()
            entity._is_locked = False
            coordinator.lock_error = RuntimeError("lock command failed")

            await asyncio.wait_for(entity.async_lock(), timeout=0.05)
            self.assertTrue(entity.is_locking)
            task = entity._command_task

            await asyncio.wait_for(coordinator.lock_started.wait(), timeout=0.05)
            coordinator.finish_lock.set()
            previous_disable_level = logging.root.manager.disable
            logging.disable(logging.CRITICAL)
            try:
                await asyncio.wait_for(task, timeout=0.2)
            finally:
                logging.disable(previous_disable_level)

            self.assertFalse(entity.is_locking)
            self.assertFalse(entity.is_locked)

        asyncio.run(scenario())

    def test_failed_lock_does_not_start_safety_relock_monitor(self):
        async def scenario():
            module = self.lock_module
            old_window = module.LOCK_COMMAND_SAFETY_RELOCK_SECONDS
            old_poll = module.LOCK_COMMAND_SAFETY_RELOCK_POLL_SECONDS
            module.LOCK_COMMAND_SAFETY_RELOCK_SECONDS = 0.2
            module.LOCK_COMMAND_SAFETY_RELOCK_POLL_SECONDS = 0.01
            try:
                entity, coordinator = self.make_entity()
                entity._is_locked = False
                coordinator.lock_error = RuntimeError("lock command failed")

                await asyncio.wait_for(entity.async_lock(), timeout=0.05)
                task = entity._command_task
                await asyncio.wait_for(coordinator.lock_started.wait(), timeout=0.05)
                coordinator.finish_lock.set()
                previous_disable_level = logging.root.manager.disable
                logging.disable(logging.CRITICAL)
                try:
                    await asyncio.wait_for(task, timeout=0.2)
                finally:
                    logging.disable(previous_disable_level)

                await asyncio.sleep(0.05)

                self.assertFalse(entity.is_locked)
                self.assertEqual(coordinator.lock_count, 1)
                self.assertIsNone(entity._safety_relock_task)
            finally:
                module.LOCK_COMMAND_SAFETY_RELOCK_SECONDS = old_window
                module.LOCK_COMMAND_SAFETY_RELOCK_POLL_SECONDS = old_poll
                safety_task = getattr(entity, "_safety_relock_task", None)
                if safety_task is not None:
                    safety_task.cancel()

        asyncio.run(scenario())

    def test_lock_success_keeps_confirmed_state_when_target_not_observed(self):
        async def scenario():
            entity, coordinator = self.make_entity()
            entity._is_locked = False
            entity._lock_cfg["motor_state_true_is_unlocked"] = True
            coordinator.state["motor_state"] = True

            await asyncio.wait_for(entity.async_lock(), timeout=0.05)
            task = entity._command_task

            await asyncio.wait_for(coordinator.lock_started.wait(), timeout=0.05)
            coordinator.finish_lock.set()
            previous_disable_level = logging.root.manager.disable
            logging.disable(logging.CRITICAL)
            try:
                await asyncio.wait_for(task, timeout=0.2)
            finally:
                logging.disable(previous_disable_level)

            self.assertFalse(entity.is_locking)
            self.assertFalse(entity.is_locked)

        asyncio.run(scenario())

    def test_unlock_success_uses_confirmed_state_when_available(self):
        async def scenario():
            entity, coordinator = self.make_entity()
            entity._lock_cfg["motor_state_true_is_unlocked"] = True
            coordinator.state["motor_state"] = True

            await asyncio.wait_for(entity.async_unlock(), timeout=0.05)
            task = entity._command_task

            await asyncio.wait_for(coordinator.unlock_started.wait(), timeout=0.05)
            coordinator.finish_unlock.set()
            await asyncio.wait_for(task, timeout=0.2)

            self.assertFalse(entity.is_unlocking)
            self.assertFalse(entity.is_locked)

        asyncio.run(scenario())

    def test_queues_latest_command_when_command_is_in_progress(self):
        async def scenario():
            entity, coordinator = self.make_entity()

            await asyncio.wait_for(entity.async_unlock(), timeout=0.05)
            task = entity._command_task
            await asyncio.wait_for(coordinator.unlock_started.wait(), timeout=0.05)

            await asyncio.wait_for(entity.async_lock(), timeout=0.05)

            self.assertTrue(entity.is_locking)
            self.assertFalse(entity.is_unlocking)
            self.assertIs(entity._command_task, task)

            coordinator.finish_unlock.set()
            await asyncio.wait_for(coordinator.lock_started.wait(), timeout=0.2)
            queued_task = entity._command_task
            self.assertIsNotNone(queued_task)
            self.assertIsNot(queued_task, task)

            coordinator.finish_lock.set()
            await asyncio.wait_for(queued_task, timeout=0.2)

            self.assertFalse(entity.is_locking)
            self.assertFalse(entity.is_unlocking)
            self.assertTrue(entity.is_locked)

        asyncio.run(scenario())

    def test_collapses_multiple_queued_commands_to_latest_target(self):
        async def scenario():
            entity, coordinator = self.make_entity()

            await asyncio.wait_for(entity.async_unlock(), timeout=0.05)
            task = entity._command_task
            await asyncio.wait_for(coordinator.unlock_started.wait(), timeout=0.05)

            await asyncio.wait_for(entity.async_lock(), timeout=0.05)
            await asyncio.wait_for(entity.async_unlock(), timeout=0.05)

            self.assertTrue(entity.is_unlocking)
            self.assertFalse(entity.is_locking)

            coordinator.finish_unlock.set()
            await asyncio.wait_for(task, timeout=0.2)

            self.assertIsNone(entity._command_task)
            self.assertFalse(entity.is_locking)
            self.assertFalse(entity.is_unlocking)
            self.assertFalse(entity.is_locked)

        asyncio.run(scenario())

    def test_safety_relock_reissues_lock_if_lock_reopens_after_lock_command(self):
        async def scenario():
            module = self.lock_module
            old_window = module.LOCK_COMMAND_SAFETY_RELOCK_SECONDS
            old_poll = module.LOCK_COMMAND_SAFETY_RELOCK_POLL_SECONDS
            module.LOCK_COMMAND_SAFETY_RELOCK_SECONDS = 0.2
            module.LOCK_COMMAND_SAFETY_RELOCK_POLL_SECONDS = 0.01
            try:
                entity, coordinator = self.make_entity()
                entity._is_locked = False

                await asyncio.wait_for(entity.async_lock(), timeout=0.05)
                task = entity._command_task
                await asyncio.wait_for(coordinator.lock_started.wait(), timeout=0.05)
                coordinator.finish_lock.set()
                await asyncio.wait_for(task, timeout=0.2)

                self.assertTrue(entity.is_locked)
                self.assertEqual(coordinator.lock_count, 1)

                entity._is_locked = False
                entity.async_write_ha_state()

                for _ in range(20):
                    if coordinator.lock_count >= 2:
                        break
                    await asyncio.sleep(0.01)

                self.assertGreaterEqual(coordinator.lock_count, 2)
            finally:
                module.LOCK_COMMAND_SAFETY_RELOCK_SECONDS = old_window
                module.LOCK_COMMAND_SAFETY_RELOCK_POLL_SECONDS = old_poll
                safety_task = getattr(entity, "_safety_relock_task", None)
                if safety_task is not None:
                    safety_task.cancel()

        asyncio.run(scenario())

    def test_unlock_cancels_safety_relock_monitor(self):
        async def scenario():
            module = self.lock_module
            old_window = module.LOCK_COMMAND_SAFETY_RELOCK_SECONDS
            old_poll = module.LOCK_COMMAND_SAFETY_RELOCK_POLL_SECONDS
            module.LOCK_COMMAND_SAFETY_RELOCK_SECONDS = 0.2
            module.LOCK_COMMAND_SAFETY_RELOCK_POLL_SECONDS = 0.01
            try:
                entity, coordinator = self.make_entity()
                entity._is_locked = False

                await asyncio.wait_for(entity.async_lock(), timeout=0.05)
                task = entity._command_task
                await asyncio.wait_for(coordinator.lock_started.wait(), timeout=0.05)
                coordinator.finish_lock.set()
                await asyncio.wait_for(task, timeout=0.2)

                await asyncio.wait_for(entity.async_unlock(), timeout=0.05)
                unlock_task = entity._command_task
                coordinator.finish_unlock.set()
                await asyncio.wait_for(unlock_task, timeout=0.2)

                self.assertFalse(entity.is_locked)
                self.assertEqual(coordinator.lock_count, 1)
                await asyncio.sleep(0.05)
                self.assertEqual(coordinator.lock_count, 1)
            finally:
                module.LOCK_COMMAND_SAFETY_RELOCK_SECONDS = old_window
                module.LOCK_COMMAND_SAFETY_RELOCK_POLL_SECONDS = old_poll
                safety_task = getattr(entity, "_safety_relock_task", None)
                if safety_task is not None:
                    safety_task.cancel()

        asyncio.run(scenario())

    def test_command_timeout_is_short_enough_for_homekit(self):
        self.assertLessEqual(self.lock_module.LOCK_COMMAND_TIMEOUT_SECONDS, 20)

    def test_cloud_lock_state_updates_locked_state(self):
        entity, coordinator = self.make_entity()
        entity._is_locked = False

        coordinator.state["lock_state"] = True
        entity._handle_coordinator_update()
        self.assertTrue(entity.is_locked)

        coordinator.state["lock_state"] = False
        entity._handle_coordinator_update()
        self.assertFalse(entity.is_locked)

    def test_unsolicited_motor_unlocked_can_be_ignored(self):
        entity, coordinator = self.make_entity()
        entity._is_locked = True
        entity._lock_cfg["motor_state_true_is_unlocked"] = True
        entity._lock_cfg["motor_state_unlock_requires_command"] = True

        coordinator.state["motor_state"] = True
        entity._handle_coordinator_update()

        self.assertTrue(entity.is_locked)

    def test_pending_unlock_accepts_motor_unlocked_when_required(self):
        entity, coordinator = self.make_entity()
        entity._is_locked = True
        entity._unlocking = True
        entity._lock_cfg["motor_state_true_is_unlocked"] = True
        entity._lock_cfg["motor_state_unlock_requires_command"] = True
        entity._lock_cfg["external_state_confirmations"] = 2

        coordinator.state["motor_state"] = True
        entity._handle_coordinator_update()

        self.assertFalse(entity.is_locked)

    def test_external_state_can_require_multiple_confirmations(self):
        entity, coordinator = self.make_entity()
        entity._is_locked = False
        entity._lock_cfg["external_state_confirmations"] = 2

        coordinator.state["lock_state"] = True
        entity._handle_coordinator_update()
        self.assertFalse(entity.is_locked)

        entity._handle_coordinator_update()
        self.assertTrue(entity.is_locked)

    def test_pending_command_state_bypasses_external_confirmation_delay(self):
        async def scenario():
            entity, coordinator = self.make_entity()
            entity._is_locked = False
            entity._locking = True
            entity._lock_cfg["external_state_confirmations"] = 2

            coordinator.state["lock_state"] = True
            entity._handle_coordinator_update()

            self.assertTrue(entity.is_locked)
            safety_task = getattr(entity, "_safety_relock_task", None)
            if safety_task is not None:
                safety_task.cancel()

        asyncio.run(scenario())

    def test_motor_state_can_drive_physical_lock_state(self):
        entity, coordinator = self.make_entity()
        entity._is_locked = True
        entity._lock_cfg["motor_state_true_is_unlocked"] = True

        coordinator.state["motor_state"] = True
        entity._handle_coordinator_update()
        self.assertFalse(entity.is_locked)

        coordinator.state["motor_state"] = False
        entity._handle_coordinator_update()
        self.assertTrue(entity.is_locked)

    def test_motor_state_takes_priority_over_stale_lock_state(self):
        entity, coordinator = self.make_entity()
        entity._is_locked = True
        entity._lock_cfg["motor_state_true_is_unlocked"] = True

        coordinator.state["motor_state"] = True
        coordinator.state["lock_state"] = True
        entity._handle_coordinator_update()

        self.assertFalse(entity.is_locked)

    def test_auto_lock_setting_can_be_ignored_for_physical_lock_state(self):
        entity, coordinator = self.make_entity()
        entity._is_locked = True
        entity._lock_cfg["auto_lock_reflects_lock_state"] = False

        coordinator.state["auto_lock"] = False
        entity._handle_coordinator_update()

        self.assertTrue(entity.is_locked)


if __name__ == "__main__":
    unittest.main()
