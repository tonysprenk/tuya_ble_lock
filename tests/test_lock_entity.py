from __future__ import annotations

import asyncio
import importlib
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
            "homeassistant.helpers": helpers,
            "homeassistant.helpers.restore_state": restore_state,
            "homeassistant.helpers.device_registry": device_registry,
            "homeassistant.helpers.entity": entity_mod,
            "homeassistant.helpers.update_coordinator": update_coordinator,
        }
    )


class FailingCoordinator:
    def __init__(self):
        self.state = {}
        self.lock_observer = None
        self.unlock_observer = None

    async def async_lock(self):
        if self.lock_observer:
            self.lock_observer()
        raise RuntimeError("lock command failed")

    async def async_unlock(self):
        if self.unlock_observer:
            self.unlock_observer()
        raise RuntimeError("unlock command failed")


class TuyaBLELockEntityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_homeassistant_stubs()
        cls.lock_module = importlib.import_module("custom_components.tuya_ble_lock.lock")

    def make_entity(self):
        coordinator = FailingCoordinator()
        entry = SimpleNamespace(
            data={"device_mac": "DC:23:51:D9:8B:86"},
            runtime_data=SimpleNamespace(profile={}),
        )
        entity = self.lock_module.TuyaBLELock(coordinator, entry)
        return entity, coordinator

    def test_unlock_failure_clears_unlocking_state(self):
        entity, coordinator = self.make_entity()
        observed_unlocking = []
        coordinator.unlock_observer = lambda: observed_unlocking.append(entity.is_unlocking)

        with self.assertRaises(RuntimeError):
            asyncio.run(entity.async_unlock())

        self.assertEqual(observed_unlocking, [True])
        self.assertFalse(entity.is_unlocking)
        self.assertTrue(entity.is_locked)

    def test_lock_failure_clears_locking_state(self):
        entity, coordinator = self.make_entity()
        entity._is_locked = False
        observed_locking = []
        coordinator.lock_observer = lambda: observed_locking.append(entity.is_locking)

        with self.assertRaises(RuntimeError):
            asyncio.run(entity.async_lock())

        self.assertEqual(observed_locking, [True])
        self.assertFalse(entity.is_locking)
        self.assertFalse(entity.is_locked)


if __name__ == "__main__":
    unittest.main()
