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

    def setUp(self):
        self.tuya_cloud._OPENAPI_TOKEN_CACHE.clear()

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

    def test_call_accepts_json_returned_as_text_plain(self):
        async def scenario():
            class FakeResponse:
                def __init__(self):
                    self.json_content_type = "not-called"

                async def __aenter__(self):
                    return self

                async def __aexit__(self, exc_type, exc, tb):
                    return None

                def raise_for_status(self):
                    return None

                async def json(self, *, content_type="application/json"):
                    self.json_content_type = content_type
                    return {"success": True}

            class FakeSession:
                def __init__(self):
                    self.response = FakeResponse()

                def get(self, *args, **kwargs):
                    return self.response

            session = FakeSession()
            client = self.tuya_cloud.TuyaMobileAPIAsync(session=session, region="eu")

            result = await client._call("device.openHubConfig", post_data={})

            self.assertTrue(result["success"])
            self.assertIsNone(session.response.json_content_type)

        import asyncio

        asyncio.run(scenario())

    def test_publish_device_dps_uses_mobile_dp_publish_action(self):
        async def scenario():
            client = self.tuya_cloud.TuyaMobileAPIAsync(session=None, region="eu")
            calls = []

            async def fake_call(action, version="1.0", post_data=None, country_code="", extra_params=None):
                calls.append((action, version, post_data, country_code, extra_params))
                return {"success": True, "result": True}

            client._call = fake_call

            result = await client.async_publish_device_dps(
                "device-1",
                {"71": "AAH/"},
                gid="home-1",
            )

            self.assertTrue(result["success"])
            self.assertEqual(
                calls,
                [
                    (
                        "tuya.m.device.dp.publish",
                        "1.0",
                        {
                            "devId": "device-1",
                            "gwId": "device-1",
                            "dps": {"71": "AAH/"},
                        },
                        "",
                        {"gid": "home-1"},
                    )
                ],
            )

        import asyncio

        asyncio.run(scenario())

    def test_get_mqtt_config_uses_open_hub_config_action(self):
        async def scenario():
            client = self.tuya_cloud.TuyaMobileAPIAsync(session=None, region="eu")
            client.uid = "user-1"
            calls = []

            async def fake_call(action, version="1.0", post_data=None, country_code="", extra_params=None):
                calls.append((action, version, post_data, country_code, extra_params))
                return {"success": True, "result": {"source_topic": "topic"}}

            client._call = fake_call

            result = await client.async_get_mqtt_config("abc12345")

            self.assertTrue(result["success"])
            self.assertEqual(
                calls,
                [
                    (
                        "device.openHubConfig",
                        "1.0",
                        {
                            "uid": "user-1",
                            "link_id": "abc12345",
                            "link_type": "mqtt",
                            "topics": "device",
                            "msg_encrypted_version": "1.0",
                        },
                        "",
                        None,
                    )
                ],
            )

        import asyncio

        asyncio.run(scenario())

    def test_openapi_get_mqtt_config_uses_access_config_endpoint(self):
        async def scenario():
            class FakeResponse:
                def __init__(self, payload):
                    self.payload = payload

                async def __aenter__(self):
                    return self

                async def __aexit__(self, exc_type, exc, tb):
                    return None

                def raise_for_status(self):
                    return None

                async def json(self, *, content_type=None):
                    return self.payload

            class FakeSession:
                def __init__(self):
                    self.calls = []
                    self.responses = [
                        {"success": True, "result": {"access_token": "token", "uid": "uid-1"}},
                        {"success": True, "result": {"source_topic": "topic"}},
                    ]

                def request(self, method, url, **kwargs):
                    self.calls.append((method, url, kwargs))
                    return FakeResponse(self.responses.pop(0))

            session = FakeSession()
            client = self.tuya_cloud.TuyaOpenAPIAsync(
                session,
                region="eu",
                access_id="access-id",
                access_secret="access-secret",
            )

            result = await client.async_get_open_hub_config("link-1")

            self.assertTrue(result["success"])
            self.assertEqual(session.calls[0][0], "GET")
            self.assertEqual(session.calls[0][1], "https://openapi.tuyaeu.com/v1.0/token")
            self.assertEqual(session.calls[0][2]["params"], {"grant_type": "1"})
            self.assertEqual(session.calls[1][0], "POST")
            self.assertEqual(
                session.calls[1][1],
                "https://openapi.tuyaeu.com/v1.0/iot-03/open-hub/access-config",
            )
            self.assertEqual(
                session.calls[1][2]["data"],
                '{"uid":"uid-1","link_id":"link-1","link_type":"mqtt","topics":"device","msg_encrypted_version":"1.0"}',
            )

        import asyncio

        asyncio.run(scenario())

    def test_openapi_get_device_status_uses_status_endpoint(self):
        async def scenario():
            class FakeResponse:
                def __init__(self, payload):
                    self.payload = payload

                async def __aenter__(self):
                    return self

                async def __aexit__(self, exc_type, exc, tb):
                    return None

                def raise_for_status(self):
                    return None

                async def json(self, *, content_type=None):
                    return self.payload

            class FakeSession:
                def __init__(self):
                    self.calls = []
                    self.responses = [
                        {"success": True, "result": {"access_token": "token", "uid": "uid-1"}},
                        {"success": True, "result": [{"code": "manual_lock", "value": True}]},
                    ]

                def request(self, method, url, **kwargs):
                    self.calls.append((method, url, kwargs))
                    return FakeResponse(self.responses.pop(0))

            session = FakeSession()
            client = self.tuya_cloud.TuyaOpenAPIAsync(
                session,
                region="eu",
                access_id="access-id",
                access_secret="access-secret",
            )

            result = await client.async_get_device_status("device-1")

            self.assertTrue(result["success"])
            self.assertEqual(session.calls[1][0], "GET")
            self.assertEqual(
                session.calls[1][1],
                "https://openapi.tuyaeu.com/v1.0/iot-03/devices/device-1/status",
            )

        import asyncio

        asyncio.run(scenario())

    def test_openapi_password_free_door_operate_uses_ticket_flow(self):
        async def scenario():
            class FakeResponse:
                def __init__(self, payload):
                    self.payload = payload

                async def __aenter__(self):
                    return self

                async def __aexit__(self, exc_type, exc, tb):
                    return None

                def raise_for_status(self):
                    return None

                async def json(self, *, content_type=None):
                    return self.payload

            class FakeSession:
                def __init__(self):
                    self.calls = []
                    self.responses = [
                        {"success": True, "result": {"access_token": "token", "uid": "uid-1"}},
                        {"success": True, "result": {"ticket_id": "ticket-1"}},
                        {"success": True, "result": True},
                    ]

                def request(self, method, url, **kwargs):
                    self.calls.append((method, url, kwargs))
                    return FakeResponse(self.responses.pop(0))

            session = FakeSession()
            client = self.tuya_cloud.TuyaOpenAPIAsync(
                session,
                region="eu",
                access_id="access-id",
                access_secret="access-secret",
            )

            result = await client.async_operate_door_password_free("device-1", open_door=True)

            self.assertTrue(result["success"])
            self.assertEqual(session.calls[1][0], "POST")
            self.assertEqual(
                session.calls[1][1],
                "https://openapi.tuyaeu.com/v1.0/smart-lock/devices/device-1/password-ticket",
            )
            self.assertEqual(session.calls[2][0], "POST")
            self.assertEqual(
                session.calls[2][1],
                "https://openapi.tuyaeu.com/v1.0/smart-lock/devices/device-1/password-free/door-operate",
            )
            self.assertEqual(session.calls[2][2]["data"], '{"ticket_id":"ticket-1","open":true}')

        import asyncio

        asyncio.run(scenario())

    def test_openapi_token_cache_reused_between_clients(self):
        async def scenario():
            class FakeResponse:
                def __init__(self, payload):
                    self.payload = payload

                async def __aenter__(self):
                    return self

                async def __aexit__(self, exc_type, exc, tb):
                    return None

                def raise_for_status(self):
                    return None

                async def json(self, *, content_type=None):
                    return self.payload

            class FakeSession:
                def __init__(self):
                    self.calls = []
                    self.responses = [
                        {
                            "success": True,
                            "result": {
                                "access_token": "cached-token",
                                "uid": "uid-1",
                                "expire_time": 7200,
                            },
                        },
                        {"success": True, "result": [{"code": "lock_motor_state", "value": True}]},
                        {"success": True, "result": [{"code": "lock_motor_state", "value": False}]},
                    ]

                def request(self, method, url, **kwargs):
                    self.calls.append((method, url, kwargs))
                    return FakeResponse(self.responses.pop(0))

            session = FakeSession()
            client_one = self.tuya_cloud.TuyaOpenAPIAsync(
                session,
                region="eu",
                access_id="access-id",
                access_secret="access-secret",
            )
            client_two = self.tuya_cloud.TuyaOpenAPIAsync(
                session,
                region="eu",
                access_id="access-id",
                access_secret="access-secret",
            )

            await client_one.async_get_device_status("device-1")
            await client_two.async_get_device_status("device-1")

            token_calls = [
                call for call in session.calls
                if call[1] == "https://openapi.tuyaeu.com/v1.0/token"
            ]
            status_calls = [
                call for call in session.calls
                if call[1] == "https://openapi.tuyaeu.com/v1.0/iot-03/devices/device-1/status"
            ]
            self.assertEqual(len(token_calls), 1)
            self.assertEqual(len(status_calls), 2)
            self.assertEqual(status_calls[1][2]["headers"]["access_token"], "cached-token")

        import asyncio

        asyncio.run(scenario())

    def test_fetch_openapi_status_bundle_maps_status_codes_to_dps(self):
        async def scenario():
            module = self.tuya_cloud
            events = []

            class FakeOpenAPI:
                def __init__(self, session, *, region, access_id, access_secret):
                    events.append(("init", region, access_id, access_secret))

                async def async_get_device_status(self, device_id):
                    events.append(("status", device_id))
                    return {
                        "success": True,
                        "result": [
                            {"code": "manual_lock", "value": True},
                            {"code": "automatic_lock", "value": False},
                        ],
                    }

            old_client = module.TuyaOpenAPIAsync
            module.TuyaOpenAPIAsync = FakeOpenAPI
            try:
                bundle = await module.async_fetch_openapi_status_bundle(
                    hass=None,
                    region="eu",
                    access_id="access-id",
                    access_secret="access-secret",
                    device_id="device-1",
                    status_code_map={"manual_lock": 71, "automatic_lock": 33},
                    source_dps=(33, 71),
                )
            finally:
                module.TuyaOpenAPIAsync = old_client

            self.assertEqual(
                events,
                [
                    ("init", "eu", "access-id", "access-secret"),
                    ("status", "device-1"),
                ],
            )
            self.assertEqual(bundle["raw_dps"][33], b"\x00")
            self.assertEqual(bundle["raw_dps"][71][12], 0x00)
            self.assertEqual(bundle["status_summary"], [("manual_lock", "bool"), ("automatic_lock", "bool")])

        import asyncio

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
