from __future__ import annotations

import base64
import json
import importlib
import sys
import types
import unittest
from pathlib import Path


INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "tuya_ble_lock"


def install_gateway_stubs() -> None:
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


class TuyaGatewayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_gateway_stubs()
        sys.modules.pop("custom_components.tuya_ble_lock.tuya_gateway", None)
        cls.gateway = importlib.import_module("custom_components.tuya_ble_lock.tuya_gateway")

    def test_extracts_numeric_and_code_based_status_dps(self):
        dp71 = bytes.fromhex("0001ffff3332373833333039016a088e3b0000")
        message = {
            "protocol": 4,
            "data": {
                "devId": "device-1",
                "status": [
                    {
                        "code": "ble_unlock_check",
                        "value": base64.b64encode(dp71).decode(),
                        "71": base64.b64encode(dp71).decode(),
                    },
                    {"code": "automatic_lock", "value": True},
                    {"code": "lock_motor_state", "value": False},
                ],
            },
        }

        dps = self.gateway.extract_dps_from_gateway_message(
            message,
            "device-1",
            {
                "ble_unlock_check": 71,
                "automatic_lock": 33,
                "lock_motor_state": 47,
            },
        )

        self.assertEqual(
            dps,
            [
                {"id": 71, "raw": dp71},
                {"id": 33, "raw": b"\x01"},
                {"id": 47, "raw": b"\x00"},
            ],
        )

    def test_ignores_other_devices(self):
        dps = self.gateway.extract_dps_from_gateway_message(
            {"data": {"devId": "other", "status": [{"71": "AQI="}]}},
            "device-1",
            {"ble_unlock_check": 71},
        )

        self.assertEqual(dps, [])

    def test_encodes_integer_status_values_as_big_endian(self):
        dps = self.gateway.extract_dps_from_gateway_message(
            {"data": {"devId": "device-1", "status": [{"code": "auto_lock_time", "value": 30}]}},
            "device-1",
            {"auto_lock_time": 36},
        )

        self.assertEqual(dps, [{"id": 36, "raw": b"\x00\x00\x00\x1e"}])

    def test_manual_lock_status_synthesizes_locked_dp71_payload(self):
        dps = self.gateway.extract_dps_from_gateway_message(
            {"data": {"devId": "device-1", "status": [{"code": "manual_lock", "value": True}]}},
            "device-1",
            {"manual_lock": 71},
        )

        self.assertEqual(len(dps), 1)
        self.assertEqual(dps[0]["id"], 71)
        self.assertGreaterEqual(len(dps[0]["raw"]), 13)
        self.assertEqual(dps[0]["raw"][12], 0x00)

    def test_manual_lock_status_takes_priority_over_ble_unlock_check_payload(self):
        unlocked_dp71 = bytes.fromhex("0001ffff343939343536363301000000c80000")
        dps = self.gateway.extract_dps_from_gateway_message(
            {
                "data": {
                    "devId": "device-1",
                    "status": [
                        {"code": "manual_lock", "value": True},
                        {"code": "ble_unlock_check", "value": base64.b64encode(unlocked_dp71).decode()},
                    ],
                }
            },
            "device-1",
            {"manual_lock": 71, "ble_unlock_check": 71},
        )

        self.assertEqual(len(dps), 1)
        self.assertEqual(dps[0]["id"], 71)
        self.assertEqual(dps[0]["raw"][12], 0x00)

    def test_manual_lock_false_synthesizes_unlocked_dp71_payload(self):
        dps = self.gateway.extract_dps_from_gateway_message(
            {"data": {"devId": "device-1", "status": [{"code": "manual_lock", "value": False}]}},
            "device-1",
            {"manual_lock": 71},
        )

        self.assertEqual(len(dps), 1)
        self.assertEqual(dps[0]["id"], 71)
        self.assertEqual(dps[0]["raw"][12], 0x01)

    def test_decodes_aes_encrypted_gateway_payload(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        password = "abcdefgh1234567890ijklmnop"
        message = {"protocol": 4, "data": {"devId": "device-1", "status": [{"71": "AQI="}]}}
        plaintext = json.dumps(message, separators=(",", ":")).encode()
        pad_len = 16 - len(plaintext) % 16
        padded = plaintext + bytes([pad_len]) * pad_len
        encryptor = Cipher(
            algorithms.AES(password[8:24].encode()),
            modes.ECB(),
        ).encryptor()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        wrapper = {"data": base64.b64encode(encrypted).decode(), "protocol": 4}

        decoded = self.gateway.decode_gateway_payload(json.dumps(wrapper).encode(), password)

        self.assertEqual(decoded, message)

    def test_listener_dispatches_matching_status_dps_on_ha_loop(self):
        import asyncio

        async def scenario():
            received = []
            event = asyncio.Event()

            class FakeHass:
                def __init__(self):
                    self.loop = asyncio.get_running_loop()

            def on_dps(dps):
                received.append(dps)
                event.set()

            listener = self.gateway.TuyaGatewayStatusListener(
                FakeHass(),
                entry=None,
                profile={
                    "entities": {
                        "lock": {
                            "gateway_status_code_map": {"ble_unlock_check": 71},
                        }
                    }
                },
                device_id="device-1",
                on_dps=on_dps,
            )

            listener._handle_decoded_message(
                {"data": {"devId": "device-1", "status": [{"code": "ble_unlock_check", "value": "AQI="}]}}
            )

            await asyncio.wait_for(event.wait(), timeout=0.2)
            self.assertEqual(received, [[{"id": 71, "raw": b"\x01\x02"}]])

        asyncio.run(scenario())

    def test_source_topic_accepts_openapi_device_topic_object(self):
        topic = self.gateway._source_topic_from_config(
            {"source_topic": {"device": "cloud/token/in/device"}}
        )

        self.assertEqual(topic, "cloud/token/in/device")

    def test_source_topics_include_exact_topic_only(self):
        topics = self.gateway._source_topics_from_config(
            {"source_topic": "cloud/token/in/link-id"}
        )

        self.assertEqual(
            topics,
            (
                "cloud/token/in/link-id",
            ),
        )

    def test_source_topics_include_all_openapi_topic_object_values_without_wildcards(self):
        topics = self.gateway._source_topics_from_config(
            {
                "source_topic": {
                    "device": "cloud/token/in/device-link",
                    "other": "cloud/token/in/other-link",
                }
            }
        )

        self.assertEqual(
            topics,
            (
                "cloud/token/in/device-link",
                "cloud/token/in/other-link",
            ),
        )

    def test_mqtt_connect_subscribes_to_all_configured_topics(self):
        class FakeClient:
            def __init__(self):
                self._tuya_subscribe_topics = ("topic/a", "topic/b")
                self.subscribed = []

            def subscribe(self, topic):
                self.subscribed.append(topic)
                return (0, len(self.subscribed))

        client = FakeClient()
        listener = self.gateway.TuyaGatewayStatusListener(
            hass=None,
            entry=None,
            profile={},
            device_id="device-1",
            on_dps=lambda _dps: None,
        )

        listener._on_mqtt_connect(client, None, None, 0)

        self.assertEqual(client.subscribed, ["topic/a", "topic/b"])


if __name__ == "__main__":
    unittest.main()
