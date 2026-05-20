from __future__ import annotations

import asyncio
import importlib
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace


INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "tuya_ble_lock"


class FakeConfigFlow:
    def __init_subclass__(cls, **kwargs):
        return super().__init_subclass__()

    def _async_current_entries(self):
        return getattr(self, "_current_entries", [])

    def async_show_form(self, **kwargs):
        return {"type": "form", **kwargs}

    def async_create_entry(self, **kwargs):
        return {"type": "create_entry", **kwargs}

    def async_abort(self, **kwargs):
        return {"type": "abort", **kwargs}


class FakeConfigEntries:
    def __init__(self, entry):
        self.entry = entry
        self.reloads = []
        self.updated_data = None
        self.updated_options = None

    def async_get_entry(self, entry_id):
        if entry_id == self.entry.entry_id:
            return self.entry
        return None

    def async_update_entry(self, entry, *, data=None, options=None):
        if data is not None:
            entry.data = data
            self.updated_data = data
        if options is not None:
            entry.options = options
            self.updated_options = options

    async def async_reload(self, entry_id):
        self.reloads.append(entry_id)


class FakeHass:
    def __init__(self, entry):
        self.config_entries = FakeConfigEntries(entry)


def install_config_flow_stubs() -> None:
    custom_components = sys.modules.get("custom_components") or types.ModuleType("custom_components")
    tuya_ble_lock = sys.modules.get("custom_components.tuya_ble_lock") or types.ModuleType(
        "custom_components.tuya_ble_lock"
    )
    tuya_ble_lock.__path__ = [str(INTEGRATION_DIR)]

    voluptuous = types.ModuleType("voluptuous")
    voluptuous.Schema = lambda value: value
    voluptuous.Required = lambda key, *args, **kwargs: key
    voluptuous.In = lambda value: value

    homeassistant = sys.modules.get("homeassistant") or types.ModuleType("homeassistant")
    config_entries = types.ModuleType("homeassistant.config_entries")
    config_entries.ConfigFlow = FakeConfigFlow

    const = types.ModuleType("homeassistant.const")
    const.CONF_EMAIL = "email"
    const.CONF_PASSWORD = "password"

    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = object

    exceptions = types.ModuleType("homeassistant.exceptions")
    exceptions.HomeAssistantError = RuntimeError

    components = types.ModuleType("homeassistant.components")
    bluetooth = types.ModuleType("homeassistant.components.bluetooth")
    bluetooth.async_ble_device_from_address = lambda *args, **kwargs: None
    bluetooth.async_last_service_info = lambda *args, **kwargs: None

    tuya_cloud = types.ModuleType("custom_components.tuya_ble_lock.tuya_cloud")

    async def async_fetch_auth_key(*args, **kwargs):
        raise AssertionError("test should patch async_fetch_auth_key")

    async def async_fetch_auth_key_only(*args, **kwargs):
        raise AssertionError("test should not call async_fetch_auth_key_only")

    tuya_cloud.async_fetch_auth_key = async_fetch_auth_key
    tuya_cloud.async_fetch_auth_key_only = async_fetch_auth_key_only

    sys.modules.update(
        {
            "custom_components": custom_components,
            "custom_components.tuya_ble_lock": tuya_ble_lock,
            "voluptuous": voluptuous,
            "homeassistant": homeassistant,
            "homeassistant.config_entries": config_entries,
            "homeassistant.const": const,
            "homeassistant.core": core,
            "homeassistant.exceptions": exceptions,
            "homeassistant.components": components,
            "homeassistant.components.bluetooth": bluetooth,
            "custom_components.tuya_ble_lock.tuya_cloud": tuya_cloud,
        }
    )


class TuyaBLELockConfigFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_config_flow_stubs()
        sys.modules.pop("custom_components.tuya_ble_lock.config_flow", None)
        cls.config_flow_module = importlib.import_module("custom_components.tuya_ble_lock.config_flow")

    def make_flow(self, source="reauth"):
        module = self.config_flow_module
        entry = SimpleNamespace(
            entry_id="entry-1",
            title="TY",
            data={
                module.CONF_DEVICE_MAC: "DC:23:51:D9:8B:86",
                module.CONF_DEVICE_UUID: "old-uuid",
                module.CONF_LOGIN_KEY: "old-login",
                module.CONF_VIRTUAL_ID: "old-virtual",
                module.CONF_AUTH_KEY: "old-auth",
                module.CONF_PRODUCT_ID: "old-product",
            },
            options={
                module.CONF_TUYA_EMAIL: "old@example.com",
                module.CONF_TUYA_PASSWORD: "old-password",
                module.CONF_TUYA_COUNTRY: "1",
                module.CONF_TUYA_REGION: "us",
            },
        )
        flow = module.TuyaBLELockConfigFlow()
        flow.hass = FakeHass(entry)
        flow.context = {"entry_id": entry.entry_id, "source": source}
        flow._current_entries = [entry]
        return flow, entry

    def install_successful_cloud_response(self):
        async def fake_fetch_auth_key(*args, **kwargs):
            return {
                "auth_key": "new-auth",
                "local_key": "abcdef1234567890",
                "device_id": "new-device-id",
                "product_id": "hc7n0urm",
                "uuid": "new-uuid",
            }

        self.config_flow_module.async_fetch_auth_key = fake_fetch_auth_key

    def assert_credentials_updated(self, flow, entry):
        module = self.config_flow_module
        self.assertEqual(flow.hass.config_entries.reloads, [entry.entry_id])
        self.assertEqual(entry.options[module.CONF_TUYA_EMAIL], "new@example.com")
        self.assertEqual(entry.options[module.CONF_TUYA_PASSWORD], "new-password")
        self.assertEqual(entry.options[module.CONF_TUYA_COUNTRY], "31")
        self.assertEqual(entry.options[module.CONF_TUYA_REGION], "eu")
        self.assertEqual(entry.data[module.CONF_AUTH_KEY], "new-auth")
        self.assertEqual(entry.data[module.CONF_PRODUCT_ID], "hc7n0urm")
        self.assertEqual(entry.data[module.CONF_DEVICE_UUID], "new-uuid")
        self.assertEqual(entry.data[module.CONF_LOGIN_KEY], b"abcdef".hex())
        self.assertEqual(entry.data[module.CONF_VIRTUAL_ID], (b"new-device-id" + b"\x00" * 22)[:22].hex())

    def cloud_credentials_input(self):
        return {
            "email": "new@example.com",
            "password": "new-password",
            "country_code": "31",
            "region": "eu",
        }

    def test_bluetooth_discovery_aborts_when_mac_already_configured(self):
        async def scenario():
            flow, _entry = self.make_flow(source="bluetooth")
            discovery_info = SimpleNamespace(
                address="dc:23:51:d9:8b:86",
                name="TY",
                service_data={},
                manufacturer_data={},
            )

            result = await flow.async_step_bluetooth(discovery_info)

            self.assertEqual(result, {"type": "abort", "reason": "already_configured"})

        asyncio.run(scenario())

    def test_stale_bluetooth_flow_aborts_when_mac_already_configured(self):
        async def scenario():
            flow, _entry = self.make_flow(source="bluetooth")
            flow._mac = "DC:23:51:D9:8B:86"

            result = await flow.async_step_choose_method()

            self.assertEqual(result, {"type": "abort", "reason": "already_configured"})

        asyncio.run(scenario())

    def test_confirm_aborts_when_mac_already_configured(self):
        async def scenario():
            flow, _entry = self.make_flow(source="bluetooth")
            flow._mac = "DC:23:51:D9:8B:86"
            flow._name = "TY"

            result = await flow.async_step_confirm({})

            self.assertEqual(result, {"type": "abort", "reason": "already_configured"})

        asyncio.run(scenario())

    def test_reauth_updates_existing_entry_options_and_reloads(self):
        async def scenario():
            flow, entry = self.make_flow(source="reauth")
            self.install_successful_cloud_response()

            result = await flow.async_step_reauth(self.cloud_credentials_input())

            self.assertEqual(result, {"type": "abort", "reason": "reauth_successful"})
            self.assert_credentials_updated(flow, entry)

        asyncio.run(scenario())

    def test_reconfigure_shows_form_for_existing_entry(self):
        async def scenario():
            flow, _entry = self.make_flow(source="reconfigure")

            result = await flow.async_step_reconfigure()

            self.assertEqual(result["type"], "form")
            self.assertEqual(result["step_id"], "reconfigure")
            self.assertIn("data_schema", result)

        asyncio.run(scenario())

    def test_reconfigure_updates_existing_entry_options_and_reloads(self):
        async def scenario():
            flow, entry = self.make_flow(source="reconfigure")
            self.install_successful_cloud_response()

            result = await flow.async_step_reconfigure(self.cloud_credentials_input())

            self.assertEqual(result, {"type": "abort", "reason": "reconfigure_successful"})
            self.assert_credentials_updated(flow, entry)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
