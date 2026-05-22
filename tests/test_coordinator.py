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

    async def async_fetch_openapi_status_bundle(*args, **kwargs):
        raise AssertionError("test should not call the Tuya OpenAPI")

    tuya_cloud.async_fetch_cloud_lock_bundle = async_fetch_cloud_lock_bundle
    tuya_cloud.async_fetch_openapi_status_bundle = async_fetch_openapi_status_bundle

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

    def test_ignores_older_dp71_status_reports(self):
        async def scenario():
            coordinator, _session = self.make_coordinator()
            coordinator._profile["state_map"] = {"71": {"key": "lock_state", "parse": "dp71_lock_state"}}
            newer_locked = bytes.fromhex("0001ffff343939343536363300000000c80000")
            older_unlocked = bytes.fromhex("0001ffff343939343536363301000000640000")

            coordinator._process_dp_reports([{"id": 71, "raw": newer_locked}])
            coordinator._process_dp_reports([{"id": 71, "raw": older_unlocked}])

            self.assertTrue(coordinator.state["lock_state"])
            self.assertEqual(coordinator.raw_dps[71], newer_locked)

        asyncio.run(scenario())

    def test_background_poll_disconnects_when_it_opened_ble_connection(self):
        async def scenario():
            coordinator, session = self.make_coordinator()
            session.is_connected = False
            fetched = False

            async def refresh_status_from_cloud():
                return False

            async def fetch_status():
                nonlocal fetched
                fetched = True

            coordinator._async_refresh_status_from_cloud = refresh_status_from_cloud
            coordinator._fetch_status = fetch_status

            await coordinator._async_update_data()

            self.assertTrue(fetched)
            self.assertFalse(session.is_connected)

        asyncio.run(scenario())

    def test_unlock_refreshes_cloud_payload_before_command(self):
        async def scenario():
            coordinator, _session = self.make_coordinator()
            coordinator._profile["entities"]["lock"]["use_cloud_check_payload"] = True
            events = []

            async def refresh_check_code_from_cloud(*, force=False):
                events.append(f"refresh:{force}")

            async def pair_central_from_cloud():
                events.append("pair")

            async def send_lock_action(*, action_unlock, allow_retry):
                self.assertTrue(action_unlock)
                self.assertTrue(allow_retry)
                events.append("send")

            coordinator._async_refresh_check_code_from_cloud = refresh_check_code_from_cloud
            coordinator._async_pair_central_from_cloud = pair_central_from_cloud
            coordinator._async_send_lock_action = send_lock_action

            await coordinator.async_unlock()

            self.assertEqual(events, ["refresh:True", "pair", "send"])

        asyncio.run(scenario())

    def test_gateway_preferred_unlock_tries_gateway_before_ble(self):
        async def scenario():
            coordinator, _session = self.make_coordinator()
            coordinator._profile["entities"]["lock"]["preferred_control"] = "gateway"
            events = []

            async def gateway_lock_action(*, action_unlock):
                events.append(("gateway", action_unlock))
                return True

            async def refresh_check_code_from_cloud(*, force=False):
                events.append(("refresh", force))

            async def pair_central_from_cloud():
                events.append(("pair", None))

            async def send_lock_action(*, action_unlock, allow_retry):
                events.append(("ble", action_unlock, allow_retry))

            coordinator._async_send_gateway_lock_action = gateway_lock_action
            coordinator._async_refresh_check_code_from_cloud = refresh_check_code_from_cloud
            coordinator._async_pair_central_from_cloud = pair_central_from_cloud
            coordinator._async_send_lock_action = send_lock_action

            await coordinator.async_unlock()

            self.assertEqual(events, [("gateway", True)])

        asyncio.run(scenario())

    def test_gateway_preferred_unlock_falls_back_to_ble_when_gateway_fails(self):
        async def scenario():
            coordinator, _session = self.make_coordinator()
            coordinator._profile["entities"]["lock"]["preferred_control"] = "gateway"
            coordinator._profile["entities"]["lock"]["use_cloud_check_payload"] = True
            events = []

            async def gateway_lock_action(*, action_unlock):
                events.append(("gateway", action_unlock))
                return False

            async def refresh_check_code_from_cloud(*, force=False):
                events.append(("refresh", force))

            async def pair_central_from_cloud():
                events.append(("pair", None))

            async def send_lock_action(*, action_unlock, allow_retry):
                events.append(("ble", action_unlock, allow_retry))

            coordinator._async_send_gateway_lock_action = gateway_lock_action
            coordinator._async_refresh_check_code_from_cloud = refresh_check_code_from_cloud
            coordinator._async_pair_central_from_cloud = pair_central_from_cloud
            coordinator._async_send_lock_action = send_lock_action

            await coordinator.async_unlock()

            self.assertEqual(
                events,
                [
                    ("gateway", True),
                    ("refresh", True),
                    ("pair", None),
                    ("ble", True, True),
                ],
            )

        asyncio.run(scenario())

    def test_cloud_status_refresh_uses_credentials_from_entry_data(self):
        async def scenario():
            coordinator, _session = self.make_coordinator()
            module = self.coordinator_module
            coordinator._entry.options = {}
            coordinator._entry.data.update(
                {
                    module.CONF_TUYA_EMAIL: "user@example.com",
                    module.CONF_TUYA_PASSWORD: "secret",
                    module.CONF_TUYA_COUNTRY: "31",
                    module.CONF_TUYA_REGION: "eu",
                }
            )
            coordinator._profile["status_sync_dps"] = [47]
            coordinator._profile["state_map"] = {"47": {"key": "motor_state", "parse": "bool"}}

            async def fetch_cloud_lock_bundle(*args, **kwargs):
                self.assertEqual(kwargs["email"], "user@example.com")
                self.assertEqual(kwargs["password"], "secret")
                self.assertEqual(kwargs["country_code"], "31")
                self.assertEqual(kwargs["region"], "eu")
                self.assertEqual(kwargs["device_id"], "ty-device")
                self.assertEqual(kwargs["source_dps"], (47,))
                return {"raw_dps": {47: b"\x01"}}

            old_fetch = module.async_fetch_cloud_lock_bundle
            module.async_fetch_cloud_lock_bundle = fetch_cloud_lock_bundle
            try:
                refreshed = await coordinator._async_refresh_status_from_cloud()
            finally:
                module.async_fetch_cloud_lock_bundle = old_fetch

            self.assertTrue(refreshed)
            self.assertEqual(coordinator.state["motor_state"], True)

        asyncio.run(scenario())

    def test_cloud_status_refresh_does_not_overwrite_newer_dp71(self):
        async def scenario():
            coordinator, _session = self.make_coordinator()
            module = self.coordinator_module
            coordinator._entry.data.update(
                {
                    module.CONF_TUYA_EMAIL: "user@example.com",
                    module.CONF_TUYA_PASSWORD: "secret",
                    module.CONF_TUYA_COUNTRY: "31",
                    module.CONF_TUYA_REGION: "eu",
                }
            )
            coordinator._profile["status_sync_dps"] = [71]
            coordinator._profile["state_map"] = {"71": {"key": "lock_state", "parse": "dp71_lock_state"}}
            newer_locked = bytes.fromhex("0001ffff343939343536363300000000c80000")
            older_unlocked = bytes.fromhex("0001ffff343939343536363301000000640000")
            coordinator._process_dp_reports([{"id": 71, "raw": newer_locked}])

            async def fetch_cloud_lock_bundle(*args, **kwargs):
                return {"raw_dps": {71: older_unlocked}}

            old_fetch = module.async_fetch_cloud_lock_bundle
            module.async_fetch_cloud_lock_bundle = fetch_cloud_lock_bundle
            try:
                refreshed = await coordinator._async_refresh_status_from_cloud()
            finally:
                module.async_fetch_cloud_lock_bundle = old_fetch

            self.assertTrue(refreshed)
            self.assertTrue(coordinator.state["lock_state"])
            self.assertEqual(coordinator.raw_dps[71], newer_locked)

        asyncio.run(scenario())

    def test_openapi_status_refresh_uses_openapi_credentials_before_mobile_cloud(self):
        async def scenario():
            coordinator, _session = self.make_coordinator()
            module = self.coordinator_module
            coordinator._entry.data.update(
                {
                    module.CONF_TUYA_EMAIL: "user@example.com",
                    module.CONF_TUYA_PASSWORD: "secret",
                    module.CONF_TUYA_COUNTRY: "31",
                    module.CONF_TUYA_REGION: "eu",
                    module.CONF_TUYA_ACCESS_ID: "access-id",
                    module.CONF_TUYA_ACCESS_SECRET: "access-secret",
                }
            )
            coordinator._profile["status_sync_dps"] = [71]
            coordinator._profile["entities"]["lock"]["openapi_status_sync"] = True
            coordinator._profile["entities"]["lock"]["gateway_status_code_map"] = {"manual_lock": 71}
            coordinator._profile["state_map"] = {"71": {"key": "lock_state", "parse": "dp71_lock_state"}}

            async def fetch_openapi_status_bundle(*args, **kwargs):
                self.assertEqual(kwargs["region"], "eu")
                self.assertEqual(kwargs["access_id"], "access-id")
                self.assertEqual(kwargs["access_secret"], "access-secret")
                self.assertEqual(kwargs["device_id"], "ty-device")
                self.assertEqual(kwargs["status_code_map"], {"manual_lock": 71})
                self.assertEqual(kwargs["source_dps"], (71,))
                return {
                    "raw_dps": {71: bytes.fromhex("0001ffff343939343536363300000000c80000")},
                    "status_summary": [("manual_lock", "bool")],
                }

            old_openapi = module.async_fetch_openapi_status_bundle
            module.async_fetch_openapi_status_bundle = fetch_openapi_status_bundle
            try:
                refreshed = await coordinator._async_refresh_status_from_cloud()
            finally:
                module.async_fetch_openapi_status_bundle = old_openapi

            self.assertTrue(refreshed)
            self.assertTrue(coordinator.state["lock_state"])

        asyncio.run(scenario())

    def test_gateway_status_listener_starts_with_credentials_from_entry_data(self):
        async def scenario():
            coordinator, _session = self.make_coordinator()
            module = self.coordinator_module
            coordinator._entry.data.update(
                {
                    module.CONF_TUYA_EMAIL: "user@example.com",
                    module.CONF_TUYA_PASSWORD: "secret",
                    module.CONF_TUYA_COUNTRY: "31",
                    module.CONF_TUYA_REGION: "eu",
                }
            )
            coordinator._profile["entities"]["lock"]["gateway_status_listener"] = True
            events = []

            gateway_module = types.ModuleType("custom_components.tuya_ble_lock.tuya_gateway")

            class FakeListener:
                def __init__(self, hass, entry, profile, device_id, on_dps, *, credentials=None):
                    events.append(("init", device_id, credentials))
                    self.on_dps = on_dps

                async def async_start(self):
                    events.append(("start",))
                    return True

            gateway_module.TuyaGatewayStatusListener = FakeListener
            old_gateway = sys.modules.get("custom_components.tuya_ble_lock.tuya_gateway")
            sys.modules["custom_components.tuya_ble_lock.tuya_gateway"] = gateway_module
            try:
                started = await coordinator.async_start_gateway_status_listener()
            finally:
                if old_gateway is not None:
                    sys.modules["custom_components.tuya_ble_lock.tuya_gateway"] = old_gateway
                else:
                    sys.modules.pop("custom_components.tuya_ble_lock.tuya_gateway", None)

            self.assertTrue(started)
            self.assertEqual(
                events,
                [
                    (
                        "init",
                        "ty-device",
                        {
                            module.CONF_TUYA_EMAIL: "user@example.com",
                            module.CONF_TUYA_PASSWORD: "secret",
                            module.CONF_TUYA_COUNTRY: "31",
                            module.CONF_TUYA_REGION: "eu",
                        },
                    ),
                    ("start",),
                ],
            )

        asyncio.run(scenario())

    def test_gateway_status_listener_start_failure_schedules_retry(self):
        async def scenario():
            coordinator, _session = self.make_coordinator()
            module = self.coordinator_module
            coordinator._entry.data.update(
                {
                    module.CONF_TUYA_EMAIL: "user@example.com",
                    module.CONF_TUYA_PASSWORD: "secret",
                    module.CONF_TUYA_COUNTRY: "31",
                    module.CONF_TUYA_REGION: "eu",
                }
            )
            coordinator._profile["entities"]["lock"]["gateway_status_listener"] = True

            gateway_module = types.ModuleType("custom_components.tuya_ble_lock.tuya_gateway")

            class FakeListener:
                def __init__(self, *args, **kwargs):
                    pass

                async def async_start(self):
                    raise RuntimeError("temporary DNS failure")

            gateway_module.TuyaGatewayStatusListener = FakeListener
            old_gateway = sys.modules.get("custom_components.tuya_ble_lock.tuya_gateway")
            sys.modules["custom_components.tuya_ble_lock.tuya_gateway"] = gateway_module
            try:
                started = await coordinator.async_start_gateway_status_listener()
            finally:
                if old_gateway is not None:
                    sys.modules["custom_components.tuya_ble_lock.tuya_gateway"] = old_gateway
                else:
                    sys.modules.pop("custom_components.tuya_ble_lock.tuya_gateway", None)

            self.assertFalse(started)
            handle = coordinator._gateway_status_retry_handle
            self.assertIsNotNone(handle)

            await coordinator.async_stop_gateway_status_listener()
            self.assertTrue(handle.cancelled())

        asyncio.run(scenario())

    def test_ble_advertisement_listener_registers_for_device_address(self):
        async def scenario():
            coordinator, _session = self.make_coordinator()
            coordinator._profile["entities"]["lock"]["ble_advertisement_listener"] = True
            coordinator._ble_device = SimpleNamespace(address="AA:BB:CC:DD:EE:FF")
            registrations = []

            components = sys.modules.get("homeassistant.components") or types.ModuleType("homeassistant.components")
            bluetooth = types.ModuleType("homeassistant.components.bluetooth")

            class BluetoothScanningMode:
                ACTIVE = "active"

            def async_register_callback(hass, callback, matcher, mode):
                registrations.append((hass, callback, matcher, mode))
                return lambda: registrations.append(("unsubscribed",))

            bluetooth.BluetoothScanningMode = BluetoothScanningMode
            bluetooth.async_register_callback = async_register_callback
            components.bluetooth = bluetooth
            sys.modules["homeassistant.components"] = components
            sys.modules["homeassistant.components.bluetooth"] = bluetooth

            started = await coordinator.async_start_ble_advertisement_listener()

            self.assertTrue(started)
            self.assertEqual(registrations[0][2], {"address": "AA:BB:CC:DD:EE:FF"})
            self.assertEqual(registrations[0][3], "active")

            await coordinator.async_stop_ble_advertisement_listener()
            self.assertEqual(registrations[-1], ("unsubscribed",))

        asyncio.run(scenario())

    def test_gateway_status_listener_stop_is_idempotent(self):
        async def scenario():
            coordinator, _session = self.make_coordinator()
            events = []

            class FakeListener:
                async def async_stop(self):
                    events.append("stop")

            coordinator._gateway_status_listener = FakeListener()

            await coordinator.async_stop_gateway_status_listener()
            await coordinator.async_stop_gateway_status_listener()

            self.assertEqual(events, ["stop"])
            self.assertIsNone(coordinator._gateway_status_listener)

        asyncio.run(scenario())

    def test_safe_exception_message_redacts_signed_tuya_urls(self):
        message = self.coordinator_module._safe_exception_message(
            RuntimeError(
                "200, message='bad mime', url='https://a1.tuyaeu.com/api.json?"
                "sid=session-secret&postData=%7B%22uid%22:%22user-id%22%7D&sign=abc123'"
            )
        )

        self.assertNotIn("session-secret", message)
        self.assertNotIn("user-id", message)
        self.assertNotIn("abc123", message)
        self.assertIn("<redacted>", message)


if __name__ == "__main__":
    unittest.main()
