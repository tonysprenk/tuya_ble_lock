from __future__ import annotations

import importlib
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace


INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "tuya_ble_lock"


class FakeCoordinatorEntity:
    def __init__(self, coordinator):
        self.coordinator = coordinator

    @property
    def available(self):
        return True


class FakeSensorEntity:
    pass


class FakeRestoreEntity:
    async def async_get_last_state(self):
        return None


class FakeSensorDeviceClass:
    BATTERY = "battery"


class FakeSensorStateClass:
    MEASUREMENT = "measurement"


class FakeEntityCategory:
    DIAGNOSTIC = "diagnostic"


def install_homeassistant_stubs() -> None:
    custom_components = types.ModuleType("custom_components")
    tuya_ble_lock = types.ModuleType("custom_components.tuya_ble_lock")
    tuya_ble_lock.__path__ = [str(INTEGRATION_DIR)]

    ha = types.ModuleType("homeassistant")
    components = types.ModuleType("homeassistant.components")
    sensor_mod = types.ModuleType("homeassistant.components.sensor")
    sensor_mod.SensorEntity = FakeSensorEntity
    sensor_mod.SensorDeviceClass = FakeSensorDeviceClass
    sensor_mod.SensorStateClass = FakeSensorStateClass

    const_mod = types.ModuleType("homeassistant.const")
    const_mod.PERCENTAGE = "%"

    helpers = types.ModuleType("homeassistant.helpers")
    restore_state = types.ModuleType("homeassistant.helpers.restore_state")
    restore_state.RestoreEntity = FakeRestoreEntity

    device_registry = types.ModuleType("homeassistant.helpers.device_registry")
    device_registry.CONNECTION_BLUETOOTH = "bluetooth"

    entity_mod = types.ModuleType("homeassistant.helpers.entity")
    entity_mod.DeviceInfo = dict
    entity_mod.EntityCategory = FakeEntityCategory

    update_coordinator = types.ModuleType("homeassistant.helpers.update_coordinator")
    update_coordinator.CoordinatorEntity = FakeCoordinatorEntity

    sys.modules.update(
        {
            "custom_components": custom_components,
            "custom_components.tuya_ble_lock": tuya_ble_lock,
            "homeassistant": ha,
            "homeassistant.components": components,
            "homeassistant.components.sensor": sensor_mod,
            "homeassistant.const": const_mod,
            "homeassistant.helpers": helpers,
            "homeassistant.helpers.restore_state": restore_state,
            "homeassistant.helpers.device_registry": device_registry,
            "homeassistant.helpers.entity": entity_mod,
            "homeassistant.helpers.update_coordinator": update_coordinator,
        }
    )


class TuyaBLEBatterySensorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_homeassistant_stubs()
        sys.modules.pop("custom_components.tuya_ble_lock.sensor", None)
        cls.sensor_module = importlib.import_module("custom_components.tuya_ble_lock.sensor")

    def make_sensor(self, state):
        coordinator = SimpleNamespace(state=state)
        entry = SimpleNamespace(
            title="TY",
            data={"device_mac": "DC:23:51:D9:8B:86"},
            runtime_data=SimpleNamespace(profile={}),
        )
        return self.sensor_module.TuyaBLEBatterySensor(coordinator, entry)

    def test_battery_state_overrides_restored_percent(self):
        sensor = self.make_sensor({"battery_percent": 50, "battery_state": "low"})

        self.assertEqual(sensor.native_value, 25)

    def test_battery_percent_is_used_when_no_enum_state_exists(self):
        sensor = self.make_sensor({"battery_percent": 50})

        self.assertEqual(sensor.native_value, 50)


if __name__ == "__main__":
    unittest.main()
