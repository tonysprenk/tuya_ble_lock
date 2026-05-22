from __future__ import annotations

import importlib
import sys
import types
import unittest
from pathlib import Path


INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "tuya_ble_lock"


def install_package_stub() -> None:
    custom_components = sys.modules.get("custom_components") or types.ModuleType("custom_components")
    tuya_ble_lock = sys.modules.get("custom_components.tuya_ble_lock") or types.ModuleType(
        "custom_components.tuya_ble_lock"
    )
    tuya_ble_lock.__path__ = [str(INTEGRATION_DIR)]
    sys.modules.update(
        {
            "custom_components": custom_components,
            "custom_components.tuya_ble_lock": tuya_ble_lock,
        }
    )


class DeviceProfilesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_package_stub()
        sys.modules.pop("custom_components.tuya_ble_lock.device_profiles", None)
        cls.profiles = importlib.import_module("custom_components.tuya_ble_lock.device_profiles")

    def test_dp71_action_payload_parses_locked_state(self):
        locked_payload = bytes.fromhex("0001ffff3332373833333039006a088e3b0000")
        unlocked_payload = bytes.fromhex("0001ffff3332373833333039016a088e3b0000")

        self.assertTrue(self.profiles.parse_dp_value(locked_payload, "dp71_lock_state"))
        self.assertFalse(self.profiles.parse_dp_value(unlocked_payload, "dp71_lock_state"))

    def test_short_dp71_payload_has_unknown_lock_state(self):
        self.assertIsNone(self.profiles.parse_dp_value(b"\x00\x01", "dp71_lock_state"))


if __name__ == "__main__":
    unittest.main()
