"""DataUpdateCoordinator for Tuya BLE lock."""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_TUYA_COUNTRY,
    CONF_TUYA_EMAIL,
    CONF_TUYA_PASSWORD,
    CONF_TUYA_REGION,
)
from .device_profiles import parse_dp_value
from .tuya_cloud import async_fetch_check_code_dps

_LOGGER = logging.getLogger(__name__)

# Check code — SYD8811 does NOT validate, H8 Pro rejects all-zeros.
DEFAULT_CHECK_CODE = b"12345678"
DEFAULT_CHECK_CODE_SOURCE_DPS = (73, 71)

# Keep BLE connection alive for this long after last operation
IDLE_DISCONNECT_SECONDS = 60


class TuyaBLELockCoordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, ble_device, session, profile: dict):
        super().__init__(
            hass,
            _LOGGER,
            name=f"Tuya BLE Lock {entry.title}",
            update_interval=timedelta(hours=12),
        )
        self._entry = entry
        self._session = session
        self._ble_device = ble_device
        self._op_lock = asyncio.Lock()
        self._profile = profile
        self._idle_timer: asyncio.TimerHandle | None = None
        self._listener_task: asyncio.Task | None = None

        # Build state dict from profile's state_map
        self.state: dict[str, Any] = {}
        self.raw_dps: dict[int, bytes] = {}
        for dp_str, mapping in profile.get("state_map", {}).items():
            key = mapping.get("key", "")
            if key and key != "_ignore" and key not in self.state:
                self.state[key] = None

        # Register push callback so DP reports update state in real-time
        self._session.set_dp_report_callback(self._process_dp_reports)

    @property
    def profile(self) -> dict:
        return self._profile

    def _process_dp_reports(self, dps: list[dict]) -> None:
        """Update state from DP reports using profile's state_map."""
        _LOGGER.warning("Processing %d DPs: %s", len(dps),
                        [(dp["id"], dp["raw"].hex()) for dp in dps])
        state_map = self._profile.get("state_map", {})
        changed = False
        for dp in dps:
            self.raw_dps[dp["id"]] = bytes(dp["raw"])
            dp_id_str = str(dp["id"])
            mapping = state_map.get(dp_id_str)
            if not mapping:
                continue
            key = mapping.get("key", "")
            parse_type = mapping.get("parse", "raw_byte")
            if not key or key == "_ignore" or parse_type == "ignore":
                continue
            new_val = parse_dp_value(dp["raw"], parse_type)
            if self.state.get(key) != new_val:
                self.state[key] = new_val
                changed = True
        if changed:
            self.async_set_updated_data(self.state)

    def _reset_idle_timer(self) -> None:
        """Reset the idle disconnect timer. Call after every operation."""
        if self._idle_timer is not None:
            self._idle_timer.cancel()
        loop = self.hass.loop
        self._idle_timer = loop.call_later(
            IDLE_DISCONNECT_SECONDS, lambda: asyncio.ensure_future(self._idle_disconnect())
        )
        # Start background listener if not already running
        self._start_listener()

    def _start_listener(self) -> None:
        """Start background task that processes incoming BLE notifications."""
        if self._listener_task and not self._listener_task.done():
            return
        self._listener_task = self.hass.async_create_task(self._notification_listener())

    async def _notification_listener(self) -> None:
        """Periodically drain notification buffer while BLE is connected.

        This catches unsolicited DP pushes (auto-lock motor_state, physical
        lock/unlock events, etc.) that arrive between explicit operations.
        """
        _LOGGER.debug("Notification listener started")
        try:
            while self._session.is_connected:
                await asyncio.sleep(2.0)
                if not self._session.is_connected:
                    break
                # Only drain if no operation is in progress (don't steal their data)
                if self._op_lock.locked():
                    continue
                if self._session._notif_buf:
                    async with self._session._lock:
                        raw = list(self._session._notif_buf)
                        self._session._notif_buf.clear()
                    if raw:
                        from .ble_protocol import parse_frames
                        frames = parse_frames(self._session._keys, raw)
                        if frames:
                            _LOGGER.warning("Listener: %d frames from %d notifications",
                                            len(frames), len(raw))
                            self._session._dispatch_dp_reports(frames)
        except Exception as exc:
            _LOGGER.debug("Notification listener error: %s", exc)
        _LOGGER.debug("Notification listener stopped")

    async def _idle_disconnect(self) -> None:
        """Disconnect after idle timeout."""
        self._idle_timer = None
        if self._session.is_connected:
            _LOGGER.warning("Idle timeout (%ds), disconnecting BLE", IDLE_DISCONNECT_SECONDS)
            await self._session.async_disconnect()
        # Listener will exit on its own when is_connected becomes False

    async def _fetch_status(self) -> None:
        """Collect DP reports from the lock. Call while connected.

        CMD_DEVICE_STATUS returns 0 DPs on tested firmwares, so we rely on:
        - Battery trigger DP for devices that need it (SYD8811: DP 69 → DP 520)
        - Passive collect for auto-pushed DPs (H8 Pro pushes DP 8 after commands)
        - State restoration (RestoreEntity) for settings between restarts
        """
        battery_cfg = self._profile.get("entities", {}).get("battery_sensor")
        if battery_cfg:
            trigger_dp = battery_cfg.get("trigger_dp")
            trigger_hex = battery_cfg.get("trigger_payload")
            try:
                if trigger_dp and trigger_hex:
                    trigger_payload = bytes.fromhex(trigger_hex)
                    await self._session.async_send_dp_raw(trigger_dp, trigger_payload)
                # Collect any pushed DPs (triggered or auto-pushed after commands)
                extra = await self._session._collect(timeout=3.0)
                _LOGGER.warning("Status collect: %d frames", len(extra))
                self._session._dispatch_dp_reports(extra)
            except Exception as exc:
                _LOGGER.warning("Status fetch failed: %s", exc)

    async def async_one_shot_status(self) -> None:
        """Single-attempt status fetch at startup. No retries."""
        async with self._op_lock:
            try:
                if not await self._session.async_connect_single_attempt():
                    _LOGGER.debug("One-shot status: lock not responding, skipping")
                    return
                await self._fetch_status()
                self._reset_idle_timer()
            except Exception as exc:
                _LOGGER.debug("One-shot status failed: %s", exc)
                await self._session.async_disconnect()

    async def _async_update_data(self) -> dict[str, Any]:
        """Connect to the lock and refresh all status DPs."""
        async with self._op_lock:
            try:
                await self._async_ensure_connected()
                await self._fetch_status()
                self._reset_idle_timer()
            except UpdateFailed:
                _LOGGER.debug("Poll: BLE connect failed, returning stale state")
            except Exception as exc:
                _LOGGER.warning("Poll error: %s", exc)
        return self.state

    async def _async_ensure_connected(self) -> None:
        if not self._session.is_connected:
            if not await self._session.async_connect():
                raise UpdateFailed("BLE connection to lock failed")

    def _device_id_from_virtual_id(self) -> str:
        try:
            raw = bytes.fromhex(self._entry.data.get("virtual_id", ""))
        except ValueError:
            return ""
        try:
            return raw.rstrip(b"\x00").decode("ascii")
        except UnicodeDecodeError:
            return ""

    def _lock_cfg(self) -> dict:
        return self._profile.get("entities", {}).get("lock", {})

    @staticmethod
    def _normalize_check_code(value: bytes | str | None) -> bytes | None:
        if value is None:
            return None
        if isinstance(value, str):
            value = value.encode("ascii", errors="ignore")
        else:
            value = bytes(value)
        value = (value + b"\x00" * 8)[:8]
        if not value.strip(b"\x00"):
            return None
        return value

    @staticmethod
    def _extract_check_code_from_dp(raw: bytes) -> bytes | None:
        """Extract the 8-byte ASCII check code from a DP 71/73-style payload."""
        if len(raw) < 12:
            return None
        candidate = raw[4:12]
        if all(0x20 <= b <= 0x7E for b in candidate):
            return candidate
        return None

    def _configured_check_code(self) -> bytes | None:
        return self._normalize_check_code(self._lock_cfg().get("check_code"))

    def _runtime_check_code(self) -> bytes | None:
        source_dps = self._lock_cfg().get("check_code_dp", DEFAULT_CHECK_CODE_SOURCE_DPS)
        if isinstance(source_dps, int):
            source_dps = [source_dps]
        for dp_id in source_dps:
            try:
                raw = self.raw_dps.get(int(dp_id))
            except (TypeError, ValueError):
                continue
            if not raw:
                continue
            candidate = self._extract_check_code_from_dp(raw)
            if candidate:
                return candidate
        return None

    def _get_check_code(self) -> bytes:
        return (
            self._runtime_check_code()
            or self._configured_check_code()
            or DEFAULT_CHECK_CODE
        )

    async def _async_refresh_check_code_from_cloud(self) -> None:
        """Fetch the latest rotating check code from Tuya cloud when available."""
        options = self._entry.options
        email = options.get(CONF_TUYA_EMAIL)
        password = options.get(CONF_TUYA_PASSWORD)
        country = options.get(CONF_TUYA_COUNTRY)
        region = options.get(CONF_TUYA_REGION)
        if not all((email, password, country, region)):
            return

        device_id = self._device_id_from_virtual_id()
        if not device_id:
            return

        source_dps = self._lock_cfg().get("check_code_dp", DEFAULT_CHECK_CODE_SOURCE_DPS)
        if isinstance(source_dps, int):
            source_dps = (source_dps,)
        else:
            source_dps = tuple(int(dp_id) for dp_id in source_dps)

        try:
            cloud_dps = await async_fetch_check_code_dps(
                self.hass,
                email=email,
                password=password,
                country_code=country,
                region=region,
                device_id=device_id,
                source_dps=source_dps,
            )
        except Exception as exc:
            _LOGGER.debug("Cloud check-code refresh failed for %s: %s", self._entry.title, exc, exc_info=True)
            return

        if cloud_dps:
            _LOGGER.warning(
                "Refreshed cloud check-code DPs for %s: %s",
                self._entry.title,
                [(dp_id, raw.hex()) for dp_id, raw in cloud_dps.items()],
            )
            self.raw_dps.update(cloud_dps)

    def _get_payload_version(self) -> int:
        value = self._lock_cfg().get("payload_version", 1)
        try:
            return int(value) & 0xFFFF
        except (TypeError, ValueError):
            return 1

    def _get_member_id(self) -> int:
        value = self._lock_cfg().get("member_id", 0xFFFF)
        try:
            if isinstance(value, str):
                return int(value, 0) & 0xFFFF
            return int(value) & 0xFFFF
        except (TypeError, ValueError):
            return 0xFFFF

    def _build_unlock_payload(self, action_unlock: bool) -> bytes:
        """Build unlock/lock DP RAW payload.

        Format (19 bytes, standard Tuya BLE lock):
          [00 01]       version (2B)
          [ff ff]       member_id (2B, 0xFFFF = admin)
          [8B ASCII]    check code
          [01/00]       action: 01=unlock, 00=lock
          [4B BE]       Unix timestamp
          [00 00]       padding
        """
        code = self._get_check_code()
        ts = int(time.time())
        payload = struct.pack(">HH", self._get_payload_version(), self._get_member_id())
        payload += code
        payload += bytes([0x01 if action_unlock else 0x00])
        payload += struct.pack(">I", ts)
        payload += b"\x00\x00"
        return payload

    def _get_unlock_dp(self) -> int:
        """Get the unlock DP ID from profile."""
        return self._lock_cfg().get("unlock_dp", 71)

    async def async_lock(self) -> None:
        async with self._op_lock:
            await self._async_refresh_check_code_from_cloud()
            await self._async_ensure_connected()
            unlock_dp = self._get_unlock_dp()
            payload = self._build_unlock_payload(action_unlock=False)
            _LOGGER.warning("Sending lock command (DP %d RAW, %d bytes): %s", unlock_dp, len(payload), payload.hex())
            try:
                await self._session.async_send_dp_fire_and_forget(unlock_dp, 0, payload)
            except Exception as exc:
                _LOGGER.warning("Lock command failed, reconnecting: %s", exc)
                self._session.is_connected = False
                await self._async_ensure_connected()
                payload = self._build_unlock_payload(action_unlock=False)
                await self._session.async_send_dp_fire_and_forget(unlock_dp, 0, payload)
            await self._fetch_status()
            self.async_set_updated_data(self.state)
            self._reset_idle_timer()

    async def async_unlock(self) -> None:
        async with self._op_lock:
            await self._async_refresh_check_code_from_cloud()
            await self._async_ensure_connected()
            unlock_dp = self._get_unlock_dp()
            payload = self._build_unlock_payload(action_unlock=True)
            _LOGGER.warning("Sending unlock command (DP %d RAW, %d bytes): %s", unlock_dp, len(payload), payload.hex())
            try:
                await self._session.async_send_dp_fire_and_forget(unlock_dp, 0, payload)
            except Exception as exc:
                _LOGGER.warning("Unlock command failed, reconnecting: %s", exc)
                self._session.is_connected = False
                await self._async_ensure_connected()
                payload = self._build_unlock_payload(action_unlock=True)
                await self._session.async_send_dp_fire_and_forget(unlock_dp, 0, payload)
            await self._fetch_status()
            self.async_set_updated_data(self.state)
            self._reset_idle_timer()

    async def async_set_double_lock(self, enabled: bool) -> None:
        dl_cfg = self._profile.get("entities", {}).get("double_lock_switch")
        if not dl_cfg:
            _LOGGER.warning("Double lock not supported by this device profile")
            return
        dp = dl_cfg["dp"]
        async with self._op_lock:
            await self._async_ensure_connected()
            await self._session.async_send_dp_bool(dp, enabled)
            self.state["double_lock"] = enabled
            await self._fetch_status()
            self.async_set_updated_data(self.state)
            self._reset_idle_timer()

    async def async_set_volume(self, volume: int) -> None:
        vol_cfg = self._profile.get("entities", {}).get("volume_select")
        if not vol_cfg:
            _LOGGER.warning("Volume control not supported by this device profile")
            return
        dp = vol_cfg["dp"]
        async with self._op_lock:
            await self._async_ensure_connected()
            await self._session.async_send_dp(dp, 4, bytes([volume]))  # type=4 (ENUM)
            self.state["volume"] = volume
            await self._fetch_status()
            self.async_set_updated_data(self.state)
            self._reset_idle_timer()

    async def async_set_passage_mode(self, passage_on: bool) -> None:
        """Toggle passage mode. Inverted from DP 33 (auto_lock).

        passage_on=True  → auto_lock=False → lock stays open
        passage_on=False → auto_lock=True  → lock auto-locks normally
        """
        pm_cfg = self._profile.get("entities", {}).get("passage_mode_switch")
        if not pm_cfg:
            _LOGGER.warning("Passage mode not supported by this device profile")
            return
        dp = pm_cfg["dp"]
        auto_lock_val = not passage_on
        async with self._op_lock:
            await self._async_ensure_connected()
            await self._session.async_send_dp_bool(dp, auto_lock_val)
            self.state["auto_lock"] = auto_lock_val
            await self._fetch_status()
            self.async_set_updated_data(self.state)
            self._reset_idle_timer()

    async def async_set_auto_lock_time(self, seconds: int) -> None:
        alt_cfg = self._profile.get("entities", {}).get("auto_lock_time_number")
        if not alt_cfg:
            _LOGGER.warning("Auto-lock time not supported by this device profile")
            return
        dp = alt_cfg["dp"]
        async with self._op_lock:
            await self._async_ensure_connected()
            await self._session.async_send_dp(dp, 2, struct.pack(">I", seconds))  # type=2 (VALUE)
            self.state["auto_lock_time"] = seconds
            await self._fetch_status()
            self.async_set_updated_data(self.state)
            self._reset_idle_timer()
