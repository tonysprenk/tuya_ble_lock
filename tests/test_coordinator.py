from __future__ import annotations

import asyncio
import importlib
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace


INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "tuya_ble_lock"


class FakeDataUpdateCoordinator:
    def __init__(self, hass, logger, *, name, update_interval):
        self.hass = hass
        self.logger = logger
        self.name = name
        self.update_interval = update_interval
        self.data = None

    def async_set_updated_data(self, data):
        self.data = data


class FakeUpdateFailed(Exception):
    pass


class FakeSession:
    def __init__(self):
        self.is_connected = True
        self.sent = []
        self.dp_callback = None

    def set_dp_report_callback(self, callback):
        self.dp_callback = callback

    async def async_send_dp_fire_and_forget(self, dp_id, dp_type, payload):
        self.sent.append((dp_id, dp_type, payload))

    async def async_disconnect(self):
        self.is_connected = False

    async def async_connect(self):
        self.is_connected = True
        return True


class FakeHass:
    def __init__(self):
        self.loop = asyncio.get_event_loop()

    def async_create_task(self, coro):
        return asyncio.create_task(coro)


def install_coordinator_stubs() -> None:
    custom_components = sys.modules.get("custom_components") or types.ModuleType("custom_components")
    tuya_ble_lock = sys.modules.get("custom_components.tuya_ble_lock") or types.ModuleType(
        "custom_components.tuya_ble_lock"
    )
    tuya_ble_lock.__path__ = [str(INTEGRATION_DIR)]

    homeassistant = sys.modules.get("homeassistant") or types.ModuleType("homeassistant")

    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = object
    core.callback = lambda func: func

    config_entries = types.ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = object

    helpers = sys.modules.get("homeassistant.helpers") or types.ModuleType("homeassistant.helpers")
    update_coordinator = types.ModuleType("homeassistant.helpers.update_coordinator")
    update_coordinator.DataUpdateCoordinator = FakeDataUpdateCoordinator
    update_coordinator.UpdateFailed = FakeUpdateFailed

    tuya_cloud = types.ModuleType("custom_components.tuya_ble_lock.tuya_cloud")

    async def async_fetch_cloud_lock_bundle(*args, **kwargs):
        raise AssertionError("test should not call the Tuya cloud")

    tuya_cloud.async_fetch_cloud_lock_bundle = async_fetch_cloud_lock_bundle

    sys.modules.update(
        {
            "custom_components": custom_components,
            "custom_components.tuya_ble_lock": tuya_ble_lock,
            "homeassistant": homeassistant,
            "homeassistant.core": core,
            "homeassistant.config_entries": config_entries,
            "homeassistant.helpers": helpers,
            "homeassistant.helpers.update_coordinator": update_coordinator,
            "custom_components.tuya_ble_lock.tuya_cloud": tuya_cloud,
        }
    )


class TuyaBLELockCoordinatorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_coordinator_stubs()
        sys.modules.pop("custom_components.tuya_ble_lock.coordinator", None)
        cls.coordinator_module = importlib.import_module("custom_components.tuya_ble_lock.coordinator")

    def make_coordinator(self):
        session = FakeSession()
        profile = {
            "entities": {
                "lock": {
                    "unlock_dp": 71,
                    "check_code": "49945663",
                }
            }
        }
        entry = SimpleNamespace(
            title="TY",
            data={"virtual_id": "74792d64657669636500"},
            options={},
        )
        coordinator = self.coordinator_module.TuyaBLELockCoordinator(
            FakeHass(),
            entry,
            ble_device=None,
            session=session,
            profile=profile,
        )
        coordinator._reset_idle_timer = lambda: None
        return coordinator, session

    def test_rejects_nonzero_lock_result_code(self):
        async def scenario():
            coordinator, _session = self.make_coordinator()

            async def fetch_status():
                coordinator.raw_dps[71] = b"\xff\xff\x00\x02"

            coordinator._fetch_status = fetch_status

            with self.assertRaises(FakeUpdateFailed):
                await coordinator._async_send_lock_action(action_unlock=True, allow_retry=False)

        asyncio.run(scenario())

    def test_clears_stale_lock_result_before_command(self):
        async def scenario():
            coordinator, session = self.make_coordinator()
            coordinator.raw_dps[71] = b"\xff\xff\x00\x02"

            async def fetch_status():
                return None

            coordinator._fetch_status = fetch_status

            await coordinator._async_send_lock_action(action_unlock=True, allow_retry=False)

            self.assertEqual(len(session.sent), 1)
            self.assertNotIn(71, coordinator.raw_dps)
            self.assertEqual(coordinator.data, coordinator.state)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
