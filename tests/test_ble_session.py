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


class FakeSequenceCounter:
    def __init__(self):
        self.value = 0

    def next(self):
        self.value += 1
        return self.value


def install_ble_session_stubs() -> None:
    custom_components = sys.modules.get("custom_components") or types.ModuleType("custom_components")
    tuya_ble_lock = sys.modules.get("custom_components.tuya_ble_lock") or types.ModuleType(
        "custom_components.tuya_ble_lock"
    )
    tuya_ble_lock.__path__ = [str(INTEGRATION_DIR)]

    bleak = types.ModuleType("bleak")
    bleak.BleakClient = object

    bleak_exc = types.ModuleType("bleak.exc")
    bleak_exc.BleakError = RuntimeError

    bleak_retry_connector = types.ModuleType("bleak_retry_connector")

    async def establish_connection(*args, **kwargs):
        raise AssertionError("test should not attempt a real BLE connection")

    bleak_retry_connector.establish_connection = establish_connection

    homeassistant = sys.modules.get("homeassistant") or types.ModuleType("homeassistant")
    components = sys.modules.get("homeassistant.components") or types.ModuleType("homeassistant.components")
    bluetooth = types.ModuleType("homeassistant.components.bluetooth")
    bluetooth.async_ble_device_from_address = lambda *args, **kwargs: None

    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = object

    ble_protocol = types.ModuleType("custom_components.tuya_ble_lock.ble_protocol")
    ble_protocol.SequenceCounter = FakeSequenceCounter
    ble_protocol.parse_dp_report = lambda data: []
    ble_protocol.parse_dp_report_v3 = lambda data: []
    ble_protocol.parse_frames = lambda keys, raw: []
    ble_protocol.build_v3_dp = lambda dp_id, dp_type, value: b""
    ble_protocol.build_v4_dp = lambda dp_id, dp_type, value: b""
    ble_protocol.encrypt_frame = lambda key, sec_flag, raw: raw
    ble_protocol.fragment = lambda payload, mtu=20, protocol_version=4: [payload]
    ble_protocol.reassemble = lambda raw: []

    sys.modules.update(
        {
            "custom_components": custom_components,
            "custom_components.tuya_ble_lock": tuya_ble_lock,
            "bleak": bleak,
            "bleak.exc": bleak_exc,
            "bleak_retry_connector": bleak_retry_connector,
            "homeassistant": homeassistant,
            "homeassistant.components": components,
            "homeassistant.components.bluetooth": bluetooth,
            "homeassistant.core": core,
            "custom_components.tuya_ble_lock.ble_protocol": ble_protocol,
        }
    )


class TuyaBLELockSessionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_ble_session_stubs()
        sys.modules.pop("custom_components.tuya_ble_lock.ble_session", None)
        cls.session_module = importlib.import_module("custom_components.tuya_ble_lock.ble_session")

    def make_session(self):
        return self.session_module.TuyaBLELockSession(
            hass=object(),
            ble_device=SimpleNamespace(address="DC:23:51:D9:8B:86"),
            login_key=b"123456",
            virtual_id=b"",
            device_uuid="test-device",
        )

    def test_stale_connected_flag_does_not_short_circuit_reconnect(self):
        session = self.make_session()
        session.is_connected = True
        session._client = SimpleNamespace(is_connected=False)

        previous_disable_level = logging.root.manager.disable
        logging.disable(logging.CRITICAL)
        try:
            result = asyncio.run(session._async_connect_inner(max_attempts=0))
        finally:
            logging.disable(previous_disable_level)

        self.assertFalse(result)
        self.assertFalse(session.is_connected)


if __name__ == "__main__":
    unittest.main()
