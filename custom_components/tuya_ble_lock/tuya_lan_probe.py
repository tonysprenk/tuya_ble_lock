"""Read-only Tuya LAN gateway probing helpers."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import socket
from typing import Any, Callable

from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_TUYA_COUNTRY,
    CONF_TUYA_EMAIL,
    CONF_TUYA_PASSWORD,
    CONF_TUYA_REGION,
)
from .tuya_cloud import TuyaMobileAPIAsync

DEVICE_ID_KEYS = ("devId", "id", "device_id")
LOCAL_KEY_KEYS = ("localKey", "local_key", "localkey")
HOST_KEYS = ("ip", "localIp", "local_ip", "ipAddr", "ipaddr", "host", "address")
NODE_ID_KEYS = ("nodeId", "node_id", "cid", "meshId")
GATEWAY_MARKERS = ("gateway", "网关", "bluetooth", "ble", "lan ya")
LAN_PORTS = (6668, 6667, 6666)
LAN_PROTOCOL_VERSIONS = (3.4, 3.5, 3.3)
LAN_SCAN_TIMEOUT = 0.25
LAN_SCAN_WORKERS = 64
LAN_SCAN_MAX_HOSTS_PER_NETWORK = 254


def _first_string(device: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = device.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def extract_lan_details(device: dict[str, Any] | None) -> dict[str, str]:
    """Extract common LAN fields from Tuya mobile/cloud device metadata."""
    device = device or {}
    return {
        "device_id": _first_string(device, DEVICE_ID_KEYS),
        "local_key": _first_string(device, LOCAL_KEY_KEYS),
        "host": _first_string(device, HOST_KEYS),
        "node_id": _first_string(device, NODE_ID_KEYS),
    }


def _is_gateway_like(device: dict[str, Any]) -> bool:
    text = " ".join(
        str(device.get(key, ""))
        for key in ("name", "productName", "product_name", "model", "category", "productId")
    ).lower()
    return any(marker in text for marker in GATEWAY_MARKERS)


def select_gateway_candidate(
    lock_device_id: str,
    devices: list[dict[str, Any]],
    *,
    explicit_gateway_id: str | None = None,
) -> dict[str, Any] | None:
    """Choose the most likely parent gateway for a Tuya subdevice."""
    if explicit_gateway_id:
        for device in devices:
            if extract_lan_details(device)["device_id"] == explicit_gateway_id:
                return device
        return None

    lock_device = None
    for device in devices:
        if extract_lan_details(device)["device_id"] == lock_device_id:
            lock_device = device
            break
    lock_details = extract_lan_details(lock_device)

    scored: list[tuple[int, dict[str, Any]]] = []
    for device in devices:
        details = extract_lan_details(device)
        device_id = details["device_id"]
        if not device_id or device_id == lock_device_id:
            continue
        score = 0
        if lock_details["local_key"] and details["local_key"] == lock_details["local_key"]:
            score += 100
        if not details["node_id"]:
            score += 20
        if _is_gateway_like(device):
            score += 20
        if details["host"]:
            score += 10
        if score:
            scored.append((score, device))

    if not scored:
        return None
    scored.sort(key=lambda item: item[0], reverse=True)
    return scored[0][1]


def _redact_device_summary(device: dict[str, Any]) -> dict[str, Any]:
    details = extract_lan_details(device)
    return {
        "device_id": details["device_id"],
        "name": device.get("name") or device.get("productName") or device.get("product_name"),
        "category": device.get("category"),
        "product_id": device.get("productId") or device.get("product_id"),
        "host": details["host"],
        "node_id": details["node_id"],
        "local_key_present": bool(details["local_key"]),
        "online": device.get("online") if "online" in device else device.get("isOnline"),
        "gid": device.get("gid"),
    }


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(key): _jsonable(inner) for key, inner in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(inner) for inner in value]
    return repr(value)


def _call_result(func, *args) -> dict[str, Any]:
    try:
        return {"ok": True, "value": _jsonable(func(*args))}
    except Exception as exc:  # pragma: no cover - exact tinytuya exceptions vary by version
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _append_unique_text(values: list[str], value: Any) -> None:
    if value is None:
        return
    text = str(value).strip()
    if text and text not in values:
        values.append(text)


def _subdevice_query_cids(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    data = value.get("data")
    if not isinstance(data, dict):
        return []

    cids: list[str] = []
    for key in ("online", "nearby", "offline"):
        raw_values = data.get(key)
        if isinstance(raw_values, list):
            for raw_value in raw_values:
                _append_unique_text(cids, raw_value)
    return cids


def child_cid_candidates(
    lock_device_id: str,
    *,
    device_uuid: str = "",
    node_id: str = "",
    explicit_child_cid: str = "",
    subdevice_query: Any = None,
) -> tuple[str, ...]:
    """Return likely gateway child CIDs for a Tuya BLE subdevice."""
    candidates: list[str] = []
    _append_unique_text(candidates, explicit_child_cid)
    for cid in _subdevice_query_cids(subdevice_query):
        _append_unique_text(candidates, cid)
    _append_unique_text(candidates, device_uuid)
    _append_unique_text(candidates, node_id)
    _append_unique_text(candidates, lock_device_id)
    return tuple(candidates)


def probe_tcp_ports(host: str, ports: tuple[int, ...] = LAN_PORTS, timeout: float = 2.0) -> list[dict[str, Any]]:
    """Check whether common Tuya LAN TCP ports accept connections."""
    results = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                results.append({"port": port, "open": True})
        except OSError as exc:
            results.append({"port": port, "open": False, "error": f"{type(exc).__name__}: {exc}"})
    return results


def probe_tinytuya_gateway(
    tinytuya_module,
    *,
    gateway_id: str,
    host: str,
    local_key: str,
    child_id: str,
    child_cids: tuple[str, ...],
    status_dps: tuple[int, ...],
    versions: tuple[float, ...] = LAN_PROTOCOL_VERSIONS,
    timeout: float = 4.0,
) -> dict[str, Any]:
    """Run read-only tinytuya checks against a gateway and optional child."""
    attempts = []
    for version in versions:
        attempt: dict[str, Any] = {"version": version}
        gateway = None
        try:
            gateway = tinytuya_module.Device(
                gateway_id,
                host,
                local_key,
                version=version,
                connection_timeout=timeout,
                connection_retry_limit=1,
            )
            if hasattr(gateway, "set_socketRetryLimit"):
                gateway.set_socketRetryLimit(1)
            if hasattr(gateway, "set_socketPersistent"):
                gateway.set_socketPersistent(True)

            attempt["gateway_status"] = _call_result(gateway.status)
            attempt["subdevice_query"] = _call_result(gateway.subdev_query)

            queried_cids = child_cid_candidates(
                child_id,
                explicit_child_cid=child_cids[0] if child_cids else "",
                subdevice_query=(
                    attempt["subdevice_query"].get("value")
                    if attempt["subdevice_query"].get("ok")
                    else None
                ),
            )
            all_cids = tuple(dict.fromkeys((*queried_cids, *child_cids, child_id)))
            subdevices = []
            for cid in all_cids:
                child = tinytuya_module.Device(child_id, cid=cid, parent=gateway)
                child_result = {
                    "cid": cid,
                    "status": _call_result(child.status),
                }
                if status_dps:
                    child_result["updatedps"] = _call_result(child.updatedps, list(status_dps))
                subdevices.append(child_result)
            attempt["subdevices"] = subdevices
            if subdevices:
                attempt["subdevice_status"] = subdevices[0]["status"]
                if status_dps:
                    attempt["subdevice_updatedps"] = subdevices[0]["updatedps"]
        except Exception as exc:
            attempt["setup_error"] = f"{type(exc).__name__}: {exc}"
        finally:
            if gateway is not None and hasattr(gateway, "set_socketPersistent"):
                try:
                    gateway.set_socketPersistent(False)
                except Exception:
                    pass
        attempts.append(attempt)
    return {"attempts": attempts}


def _is_private_ipv4_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.version == 4
        and ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_unspecified
    )


def _network_from_ipv4(address: str, prefix: Any) -> str | None:
    if not address:
        return None
    try:
        if "/" in address and prefix in (None, ""):
            interface = ipaddress.ip_interface(address)
        else:
            interface = ipaddress.ip_interface(f"{address}/{prefix}")
    except (TypeError, ValueError):
        return None

    ip = interface.ip
    if not _is_private_ipv4_host(str(ip)):
        return None

    network = interface.network
    if network.prefixlen < 24:
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
    return str(network)


def private_ipv4_networks_from_adapters(adapters: list[dict[str, Any]]) -> tuple[str, ...]:
    """Extract bounded private IPv4 networks from HA network adapter metadata."""
    networks: list[str] = []
    seen: set[str] = set()
    for adapter in adapters:
        if adapter.get("enabled") is False:
            continue
        name = str(adapter.get("name", "")).lower()
        if name.startswith(("lo", "docker", "veth", "br-")) or name in {"hassio"}:
            continue
        for ipv4 in adapter.get("ipv4") or ():
            if not isinstance(ipv4, dict):
                continue
            prefix = ipv4.get("network_prefix", ipv4.get("prefix"))
            network = _network_from_ipv4(str(ipv4.get("address", "")), prefix)
            if network and network not in seen:
                seen.add(network)
                networks.append(network)
    return tuple(networks)


def _psutil_adapters() -> list[dict[str, Any]]:
    try:
        import psutil
    except ImportError:
        return []

    adapters = []
    for name, addrs in psutil.net_if_addrs().items():
        ipv4 = []
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            prefix = None
            if addr.netmask:
                try:
                    prefix = ipaddress.ip_network(f"0.0.0.0/{addr.netmask}").prefixlen
                except ValueError:
                    prefix = None
            ipv4.append({"address": addr.address, "network_prefix": prefix or 24})
        adapters.append({"name": name, "enabled": True, "ipv4": ipv4})
    return adapters


async def async_get_private_ipv4_networks(hass) -> tuple[str, ...]:
    """Return private LAN networks HA can use for local discovery."""
    try:
        from homeassistant.components import network

        adapters = await network.async_get_adapters(hass)
    except Exception:
        adapters = _psutil_adapters()
    return private_ipv4_networks_from_adapters(adapters)


def _tcp_port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _scan_hosts_for_network(network: ipaddress.IPv4Network, max_hosts: int) -> list[str]:
    hosts = []
    for host in network.hosts():
        hosts.append(str(host))
        if len(hosts) >= max_hosts:
            break
    return hosts


def scan_tuya_lan_ports(
    networks: tuple[str, ...],
    *,
    ports: tuple[int, ...] = LAN_PORTS,
    timeout: float = LAN_SCAN_TIMEOUT,
    connect_checker: Callable[[str, int, float], bool] = _tcp_port_open,
    max_workers: int = LAN_SCAN_WORKERS,
    max_hosts_per_network: int = LAN_SCAN_MAX_HOSTS_PER_NETWORK,
) -> dict[str, Any]:
    """Scan bounded private LAN ranges for hosts with common Tuya LAN ports open."""
    parsed_networks: list[ipaddress.IPv4Network] = []
    for network_text in networks:
        try:
            network = ipaddress.ip_network(network_text, strict=False)
        except ValueError:
            continue
        if network.version != 4 or not network.is_private:
            continue
        parsed_networks.append(network)

    hosts: list[str] = []
    for network in parsed_networks:
        hosts.extend(_scan_hosts_for_network(network, max_hosts_per_network))

    open_by_host: dict[str, list[int]] = {}
    max_workers = max(1, min(max_workers, max(len(hosts) * len(ports), 1)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(connect_checker, host, port, timeout): (host, port)
            for host in hosts
            for port in ports
        }
        for future in as_completed(futures):
            host, port = futures[future]
            try:
                is_open = future.result()
            except Exception:
                is_open = False
            if is_open:
                open_by_host.setdefault(host, []).append(port)

    candidates = [
        {"host": host, "open_ports": sorted(open_ports)}
        for host, open_ports in sorted(
            open_by_host.items(),
            key=lambda item: ipaddress.ip_address(item[0]),
        )
    ]
    return {
        "networks": [str(network) for network in parsed_networks],
        "ports": list(ports),
        "hosts_scanned": len(hosts),
        "candidates": candidates,
    }


async def _async_fetch_mobile_inventory(
    hass,
    credentials: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    session = async_get_clientsession(hass)
    client = TuyaMobileAPIAsync(session=session, region=credentials[CONF_TUYA_REGION])
    login = await client.async_login(
        credentials[CONF_TUYA_COUNTRY],
        credentials[CONF_TUYA_EMAIL],
        credentials[CONF_TUYA_PASSWORD],
    )
    if not login.get("success"):
        return login, []

    homes_resp = await client.async_get_home_list()
    homes = homes_resp.get("result", {})
    if isinstance(homes, dict):
        homes = homes.get("result", [])
    if not isinstance(homes, list):
        homes = []

    devices: list[dict[str, Any]] = []
    for home in homes:
        if not isinstance(home, dict):
            continue
        gid = home.get("groupId") or home.get("gid")
        if not gid:
            continue
        devs_resp = await client.async_list_devices(gid)
        devs_result = devs_resp.get("result", {})
        if isinstance(devs_result, dict):
            devs_result = devs_result.get("result", [])
        if not isinstance(devs_result, list):
            continue
        for item in devs_result:
            if isinstance(item, dict):
                device = dict(item)
                device["gid"] = gid
                devices.append(device)
    return login, devices


async def async_probe_gateway_lan(
    hass,
    *,
    credentials: dict[str, Any],
    lock_device_id: str,
    device_uuid: str = "",
    child_cid: str = "",
    gateway_device_id: str | None = None,
    host: str | None = None,
    status_dps: tuple[int, ...] = (),
    timeout: float = 4.0,
) -> dict[str, Any]:
    """Discover gateway metadata and run read-only LAN probes from Home Assistant."""
    login, devices = await _async_fetch_mobile_inventory(hass, credentials)
    result: dict[str, Any] = {
        "lock_device_id": lock_device_id,
        "login_success": bool(login.get("success")),
        "device_count": len(devices),
        "devices": [_redact_device_summary(device) for device in devices],
    }
    if not login.get("success"):
        result["login_response"] = _jsonable(login)
        return result

    lock_device = next(
        (device for device in devices if extract_lan_details(device)["device_id"] == lock_device_id),
        None,
    )
    gateway_device = select_gateway_candidate(
        lock_device_id,
        devices,
        explicit_gateway_id=gateway_device_id,
    )
    result["lock"] = _redact_device_summary(lock_device or {})
    result["gateway"] = _redact_device_summary(gateway_device or {})

    lock_details = extract_lan_details(lock_device)
    gateway_details = extract_lan_details(gateway_device)
    gateway_host = host or gateway_details["host"]
    local_key = gateway_details["local_key"] or lock_details["local_key"]
    gateway_id = gateway_details["device_id"] or gateway_device_id or ""
    child_cids = child_cid_candidates(
        lock_device_id,
        explicit_child_cid=child_cid,
        device_uuid=device_uuid,
        node_id=lock_details["node_id"],
    )

    metadata_host = gateway_host
    if not host and gateway_host and not _is_private_ipv4_host(gateway_host):
        result["cloud_host_skipped"] = gateway_host
        gateway_host = ""

    if not host and not gateway_host:
        networks = await async_get_private_ipv4_networks(hass)
        result["lan_networks"] = list(networks)
        discovery = await hass.async_add_executor_job(
            scan_tuya_lan_ports,
            networks,
        )
        result["lan_discovery"] = discovery
        if discovery["candidates"]:
            gateway_host = discovery["candidates"][0]["host"]

    result["probe_input"] = {
        "gateway_id": gateway_id,
        "host": gateway_host,
        "metadata_host": metadata_host,
        "child_id": lock_device_id,
        "child_cids": list(child_cids),
        "local_key_present": bool(local_key),
        "status_dps": list(status_dps),
    }
    if not gateway_id or not gateway_host or not local_key:
        result["probe_skipped"] = "missing gateway_id, host, or local_key"
        return result

    result["tcp_ports"] = await hass.async_add_executor_job(
        probe_tcp_ports,
        gateway_host,
        LAN_PORTS,
        min(timeout, 3.0),
    )

    def _run_tinytuya_probe() -> dict[str, Any]:
        try:
            import tinytuya
        except ImportError as exc:
            return {"available": False, "error": f"ImportError: {exc}"}
        probe = probe_tinytuya_gateway(
            tinytuya,
            gateway_id=gateway_id,
            host=gateway_host,
            local_key=local_key,
            child_id=lock_device_id,
            child_cids=child_cids,
            status_dps=status_dps,
            timeout=timeout,
        )
        probe["available"] = True
        return probe

    result["tinytuya"] = await hass.async_add_executor_job(_run_tinytuya_probe)
    return result
