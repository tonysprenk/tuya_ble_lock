from __future__ import annotations

import importlib
import sys
import types
import unittest
from pathlib import Path


INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "tuya_ble_lock"


def install_tuya_cloud_stubs() -> None:
    custom_components = sys.modules.get("custom_components") or types.ModuleType("custom_components")
    tuya_ble_lock = sys.modules.get("custom_components.tuya_ble_lock") or types.ModuleType(
        "custom_components.tuya_ble_lock"
    )
    tuya_ble_lock.__path__ = [str(INTEGRATION_DIR)]

    homeassistant = sys.modules.get("homeassistant") or types.ModuleType("homeassistant")
    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = object
    helpers = sys.modules.get("homeassistant.helpers") or types.ModuleType("homeassistant.helpers")
    aiohttp_client = types.ModuleType("homeassistant.helpers.aiohttp_client")
    aiohttp_client.async_get_clientsession = lambda hass: None

    sys.modules.update(
        {
            "custom_components": custom_components,
            "custom_components.tuya_ble_lock": tuya_ble_lock,
            "homeassistant": homeassistant,
            "homeassistant.core": core,
            "homeassistant.helpers": helpers,
            "homeassistant.helpers.aiohttp_client": aiohttp_client,
        }
    )


class TuyaCloudTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_tuya_cloud_stubs()
        sys.modules.pop("custom_components.tuya_ble_lock.tuya_cloud", None)
        cls.tuya_cloud = importlib.import_module("custom_components.tuya_ble_lock.tuya_cloud")

    def test_redacts_sensitive_cloud_log_values(self):
        redacted = self.tuya_cloud._redact_cloud_value(
            {
                "email": "user@example.com",
                "passwd": "md5-password",
                "sid": "session-id",
                "uid": "user-id",
                "domain": {"mobileApiUrl": "https://a1.tuyaeu.com"},
            }
        )

        self.assertEqual(redacted["email"], "<redacted>")
        self.assertEqual(redacted["passwd"], "<redacted>")
        self.assertEqual(redacted["sid"], "<redacted>")
        self.assertEqual(redacted["uid"], "<redacted>")
        self.assertEqual(redacted["domain"]["mobileApiUrl"], "https://a1.tuyaeu.com")


if __name__ == "__main__":
    unittest.main()
