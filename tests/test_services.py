from __future__ import annotations

import asyncio
import importlib
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace


INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "tuya_ble_lock"


class FakeServices:
    def __init__(self):
        self.registered = {}

    def async_register(self, domain, service, handler, schema=None, supports_response=None):
        self.registered[(domain, service)] = {
            "handler": handler,
            "schema": schema,
            "supports_response": supports_response,
        }


class FakeConfigEntries:
    def __init__(self, entry):
        self.entry = entry

    def async_entries(self, domain):
        return [self.entry]


class FakeHass:
    def __init__(self, entry):
        self.config_entries = FakeConfigEntries(entry)
        self.services = FakeServices()


def install_service_stubs(events) -> None:
    custom_components = sys.modules.get("custom_components") or types.ModuleType("custom_components")
    tuya_ble_lock = sys.modules.get("custom_components.tuya_ble_lock") or types.ModuleType(
        "custom_components.tuya_ble_lock"
    )
    tuya_ble_lock.__path__ = [str(INTEGRATION_DIR)]

    voluptuous = types.ModuleType("voluptuous")
    voluptuous.Schema = lambda value: value
    voluptuous.Required = lambda key, *args, **kwargs: key
    voluptuous.Optional = lambda key, *args, **kwargs: key
    voluptuous.Any = lambda *args, **kwargs: args
    voluptuous.All = lambda *args, **kwargs: args
    voluptuous.Coerce = lambda value: value
    voluptuous.Range = lambda *args, **kwargs: kwargs

    homeassistant = sys.modules.get("homeassistant") or types.ModuleType("homeassistant")
    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = object
    core.ServiceCall = object
    core.SupportsResponse = SimpleNamespace(OPTIONAL="optional")

    exceptions = types.ModuleType("homeassistant.exceptions")
    exceptions.HomeAssistantError = RuntimeError

    helpers = types.ModuleType("homeassistant.helpers")
    device_registry = types.ModuleType("homeassistant.helpers.device_registry")
    device_registry.async_get = lambda hass: SimpleNamespace(async_get=lambda device_id: None)

    credential_store = types.ModuleType("custom_components.tuya_ble_lock.credential_store")
    credential_store.CredentialStore = object

    ble_commands = types.ModuleType("custom_components.tuya_ble_lock.ble_commands")
    ble_commands.SYNC_MARKER = b""
    ble_commands.build_enroll_payload = lambda *args, **kwargs: b""
    ble_commands.build_delete_payload = lambda *args, **kwargs: b""
    ble_commands.build_temp_password_payload = lambda *args, **kwargs: b""
    ble_commands.parse_enroll_response = lambda *args, **kwargs: {}

    models = types.ModuleType("custom_components.tuya_ble_lock.models")
    models.TuyaBLELockData = object

    tuya_cloud = types.ModuleType("custom_components.tuya_ble_lock.tuya_cloud")

    async def async_fetch_openapi_status_bundle(*args, **kwargs):
        events.append(("openapi_status", kwargs))
        return {
            "raw_dps": {71: b"\x00\x01"},
            "status_summary": [("manual_lock", "bool")],
            "status_response": {"success": True, "result": []},
        }

    tuya_cloud.async_fetch_openapi_status_bundle = async_fetch_openapi_status_bundle

    sys.modules.update(
        {
            "custom_components": custom_components,
            "custom_components.tuya_ble_lock": tuya_ble_lock,
            "voluptuous": voluptuous,
            "homeassistant": homeassistant,
            "homeassistant.core": core,
            "homeassistant.exceptions": exceptions,
            "homeassistant.helpers": helpers,
            "homeassistant.helpers.device_registry": device_registry,
            "custom_components.tuya_ble_lock.credential_store": credential_store,
            "custom_components.tuya_ble_lock.ble_commands": ble_commands,
            "custom_components.tuya_ble_lock.models": models,
            "custom_components.tuya_ble_lock.tuya_cloud": tuya_cloud,
        }
    )


class TuyaBLELockServicesTest(unittest.TestCase):
    def test_probe_openapi_status_returns_raw_status_and_mapped_dps(self):
        async def scenario():
            events = []
            install_service_stubs(events)
            sys.modules.pop("custom_components.tuya_ble_lock.services", None)
            module = importlib.import_module("custom_components.tuya_ble_lock.services")

            coordinator = SimpleNamespace(
                profile={},
                _cloud_credentials=lambda: {
                    module.CONF_TUYA_REGION: "eu",
                    module.CONF_TUYA_ACCESS_ID: "access-id",
                    module.CONF_TUYA_ACCESS_SECRET: "access-secret",
                },
                _device_id_from_virtual_id=lambda: "device-1",
                _gateway_status_code_map=lambda: {"manual_lock": 71},
                _status_sync_dps=lambda: (33, 47, 71),
            )
            entry = SimpleNamespace(
                entry_id="entry-1",
                unique_id="unique-1",
                runtime_data=SimpleNamespace(coordinator=coordinator),
            )
            hass = FakeHass(entry)

            await module.async_register_services(hass)
            service = hass.services.registered[(module.DOMAIN, "probe_openapi_status")]
            response = await service["handler"](SimpleNamespace(data={"device_id": "entry-1"}))

            self.assertEqual(events[0][0], "openapi_status")
            self.assertEqual(events[0][1]["device_id"], "device-1")
            self.assertEqual(events[0][1]["status_code_map"], {"manual_lock": 71})
            self.assertEqual(events[0][1]["source_dps"], (33, 47, 71))
            self.assertEqual(response["status_summary"], [("manual_lock", "bool")])
            self.assertEqual(response["mapped_dps"], {71: "0001"})

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
