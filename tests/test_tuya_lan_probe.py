from __future__ import annotations

import importlib
import sys
import types
import unittest
from pathlib import Path


INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "tuya_ble_lock"


def install_lan_probe_stubs() -> None:
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


class FakeTinyTuya:
    class Device:
        instances = []

        def __init__(
            self,
            dev_id,
            address=None,
            local_key="",
            version=3.4,
            connection_timeout=5,
            connection_retry_limit=1,
            cid=None,
            parent=None,
            **_kwargs,
        ):
            self.dev_id = dev_id
            self.address = address
            self.local_key = local_key
            self.version = version
            self.connection_timeout = connection_timeout
            self.connection_retry_limit = connection_retry_limit
            self.cid = cid
            self.parent = parent
            self.calls = []
            self.persistent = None
            FakeTinyTuya.Device.instances.append(self)

        def set_socketRetryLimit(self, limit):
            self.calls.append(("set_socketRetryLimit", limit))

        def set_socketPersistent(self, persistent):
            self.persistent = persistent
            self.calls.append(("set_socketPersistent", persistent))

        def status(self):
            self.calls.append(("status",))
            return {"dps": {"47": True}, "device": self.dev_id, "cid": self.cid}

        def subdev_query(self):
            self.calls.append(("subdev_query",))
            return {"online": ["lock-1"]}

        def updatedps(self, dps):
            self.calls.append(("updatedps", tuple(dps)))
            return {"dps": {str(dp): True for dp in dps}, "cid": self.cid}


class TuyaLanProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_lan_probe_stubs()
        sys.modules.pop("custom_components.tuya_ble_lock.tuya_lan_probe", None)
        cls.module = importlib.import_module("custom_components.tuya_ble_lock.tuya_lan_probe")

    def setUp(self):
        FakeTinyTuya.Device.instances.clear()

    def test_selects_gateway_with_same_local_key_and_no_node_id(self):
        devices = [
            {"devId": "lock-1", "name": "A1 Ultra", "localKey": "shared", "nodeId": "lock-1"},
            {"devId": "other", "name": "Lamp", "localKey": "different", "ip": "192.168.1.30"},
            {"devId": "gw-1", "name": "Gateway", "localKey": "shared", "ip": "192.168.1.25"},
        ]

        gateway = self.module.select_gateway_candidate("lock-1", devices)

        self.assertEqual(gateway["devId"], "gw-1")

    def test_extract_lan_details_accepts_common_tuya_field_names(self):
        details = self.module.extract_lan_details(
            {
                "devId": "gw-1",
                "localKey": "key-1",
                "ip": "192.168.1.25",
                "nodeId": "node-1",
            }
        )

        self.assertEqual(details["device_id"], "gw-1")
        self.assertEqual(details["local_key"], "key-1")
        self.assertEqual(details["host"], "192.168.1.25")
        self.assertEqual(details["node_id"], "node-1")

    def test_tinytuya_probe_queries_gateway_and_subdevice_without_control(self):
        result = self.module.probe_tinytuya_gateway(
            FakeTinyTuya,
            gateway_id="gw-1",
            host="192.168.1.25",
            local_key="key-1",
            child_id="lock-1",
            child_cids=("lock-1",),
            status_dps=(47, 33),
            versions=(3.4,),
            timeout=2.0,
        )

        self.assertTrue(result["attempts"][0]["gateway_status"]["ok"])
        self.assertTrue(result["attempts"][0]["subdevice_status"]["ok"])
        gateway, child = FakeTinyTuya.Device.instances
        self.assertEqual(child.parent, gateway)
        self.assertEqual(child.cid, "lock-1")
        self.assertIn(("subdev_query",), gateway.calls)
        self.assertIn(("status",), child.calls)
        self.assertIn(("updatedps", (47, 33)), child.calls)
        self.assertNotIn(("set_multiple_values",), gateway.calls + child.calls)

    def test_adapter_network_discovery_keeps_only_enabled_private_lans(self):
        adapters = [
            {
                "name": "end0",
                "enabled": True,
                "ipv4": [{"address": "192.168.2.16", "network_prefix": 24}],
            },
            {
                "name": "hassio",
                "enabled": False,
                "ipv4": [{"address": "172.30.32.1", "network_prefix": 23}],
            },
            {
                "name": "wan",
                "enabled": True,
                "ipv4": [{"address": "86.89.194.195", "network_prefix": 24}],
            },
        ]

        networks = self.module.private_ipv4_networks_from_adapters(adapters)

        self.assertEqual(networks, ("192.168.2.0/24",))

    def test_lan_scan_checks_private_hosts_and_reports_open_tuya_ports(self):
        checked = []

        def fake_probe(host, port, timeout):
            checked.append((host, port, timeout))
            return host == "192.168.2.2" and port == 6668

        result = self.module.scan_tuya_lan_ports(
            ("192.168.2.0/30", "86.89.194.0/30"),
            ports=(6668, 6667),
            timeout=0.1,
            connect_checker=fake_probe,
            max_workers=1,
        )

        self.assertEqual(result["networks"], ["192.168.2.0/30"])
        self.assertEqual(result["hosts_scanned"], 2)
        self.assertEqual(result["candidates"], [{"host": "192.168.2.2", "open_ports": [6668]}])
        self.assertIn(("192.168.2.1", 6668, 0.1), checked)
        self.assertNotIn(("86.89.194.1", 6668, 0.1), checked)

    def test_child_cid_candidates_prefer_online_gateway_cid_then_uuid(self):
        candidates = self.module.child_cid_candidates(
            "bf68a8zsn0m8xzib",
            device_uuid="cdaf90aaa63d669e",
            subdevice_query={
                "reqType": "subdev_online_stat_report",
                "data": {"online": ["cdaf90aaa63d669e"], "nearby": ["other"]},
            },
        )

        self.assertEqual(candidates, ("cdaf90aaa63d669e", "other", "bf68a8zsn0m8xzib"))

    def test_extract_dps_from_lan_status_maps_requested_dps(self):
        dps = self.module.extract_dps_from_lan_status(
            {"dps": {"9": "low", "33": False, "47": True, "36": 10}},
            (47, 33),
        )

        self.assertEqual(dps, [{"id": 47, "raw": b"\x01"}, {"id": 33, "raw": b"\x00"}])

    def test_read_tinytuya_gateway_status_returns_subdevice_dps(self):
        result = self.module.read_tinytuya_gateway_status(
            FakeTinyTuya,
            gateway_id="gw-1",
            host="192.168.1.25",
            local_key="key-1",
            child_id="lock-1",
            child_cids=("lock-1",),
            status_dps=(47,),
            version=3.4,
            timeout=2.0,
        )

        self.assertEqual(result["dps"], [{"id": 47, "raw": b"\x01"}])


if __name__ == "__main__":
    unittest.main()
