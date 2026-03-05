"""Device profile loader for Tuya BLE locks.

Each profile is a JSON file named {product_id}.json in this package directory.
Falls back to _default.json for unknown product IDs.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

_LOGGER = logging.getLogger(__name__)
_PROFILES_DIR = Path(__file__).parent

BATTERY_STATE_MAP = {
    0: "high",
    1: "medium",
    2: "low",
    3: "exhausted",
}

# Cache populated by async_load_profile (runs in executor).
_PROFILE_CACHE: dict[str, dict] = {}


def _load_profile_sync(product_id: str | None) -> dict:
    """Load profile from disk (blocking). Must run in executor."""
    # Populate cache on first call
    if not _PROFILE_CACHE:
        for p in _PROFILES_DIR.glob("*.json"):
            _PROFILE_CACHE[p.stem] = json.loads(p.read_text())

    if product_id and product_id in _PROFILE_CACHE:
        _LOGGER.info("Loading device profile: %s", product_id)
        return _PROFILE_CACHE[product_id]

    _LOGGER.warning("No profile for product_id=%s, using default", product_id)
    return _PROFILE_CACHE.get("_default", {})


async def async_load_profile(hass, product_id: str | None) -> dict:
    """Load a device profile, running file I/O in the executor."""
    return await hass.async_add_executor_job(_load_profile_sync, product_id)


def _get_profile_choices_sync() -> dict[str, str]:
    """Return {product_id: display_name} for all profiles (blocking)."""
    if not _PROFILE_CACHE:
        for p in _PROFILES_DIR.glob("*.json"):
            _PROFILE_CACHE[p.stem] = json.loads(p.read_text())
    choices = {}
    for pid, profile in _PROFILE_CACHE.items():
        if pid.startswith("_"):
            continue
        name = profile.get("name", pid)
        choices[pid] = f"{name} ({pid})"
    return choices


async def async_get_profile_choices(hass) -> dict[str, str]:
    """Return available device profiles as {product_id: label} for UI dropdown."""
    return await hass.async_add_executor_job(_get_profile_choices_sync)


def parse_dp_value(raw: bytes, parse_type: str):
    """Parse a DP value according to the profile's parse type."""
    if parse_type == "int":
        return int.from_bytes(raw, "big")
    elif parse_type == "bool":
        return bool(raw[0]) if raw else None
    elif parse_type == "raw_byte":
        return raw[0] if raw else None
    elif parse_type == "battery_state_enum":
        return BATTERY_STATE_MAP.get(raw[0], f"unknown_{raw[0]}") if raw else None
    elif parse_type == "ignore":
        return None
    else:
        _LOGGER.warning("Unknown parse type: %s", parse_type)
        return raw.hex()
