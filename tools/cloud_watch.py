#!/usr/bin/env python3
"""Watch Tuya cloud DP changes in real-time.

Polls the cloud API and shows which DPs change between polls.
Use this to discover which DPs your lock reports when it unlocks/locks.

Usage:
    export TUYA_CLIENT_ID="..." TUYA_SECRET="..." TUYA_DEVICE_ID="..."
    python3 cloud_watch.py           # Poll every 3 seconds
    python3 cloud_watch.py --once    # Single snapshot
"""

import base64
import json
import os
import sys
import time
from datetime import datetime

from tuya_mobile_api import TuyaMobileAPI

DEV_ID = os.environ.get("TUYA_DEVICE_ID", "")
GID = int(os.environ.get("TUYA_GID", "0"))

# DPs we care about for lock operations
INTERESTING_DPS = {
    "8": "battery_%",
    "9": "battery_state",
    "31": "beep_volume",
    "33": "auto_lock",
    "46": "manual_lock",
    "47": "motor_state",
    "61": "remote_no_dp_key",
    "70": "check_code_set",
    "71": "ble_unlock_check",
    "79": "double_lock",
    "19": "unlock_ble",
    "62": "unlock_phone_remote",
    "20": "lock_record",
}


def get_dps(api):
    """Fetch all DP values with timestamps."""
    r = api.call_api("tuya.m.device.dp.get", version="2.0",
                     post_data={"devId": DEV_ID}, gid=GID)
    if not r.get("success") and "result" in r:
        inner = r["result"]
        if isinstance(inner, dict) and inner.get("success") is False:
            print(f"API error: {inner.get('errorMsg', inner)}")
            return None
    result = r.get("result", {})
    if isinstance(result, dict) and "result" in result:
        result = result["result"]
    return result


def format_value(dp_id, val):
    """Format a DP value for display, decoding base64 RAW values."""
    if isinstance(val, str) and val:
        try:
            decoded = base64.b64decode(val)
            return f"{val} → hex:{decoded.hex()}"
        except Exception:
            pass
    return str(val)


def snapshot(dps):
    """Create a snapshot of DP values and timestamps."""
    snap = {}
    for dp_id, dp_data in dps.items():
        snap[dp_id] = {
            "value": dp_data.get("value", ""),
            "time": dp_data.get("time", 0),
        }
    return snap


def diff_snapshots(old, new):
    """Find DPs that changed between two snapshots."""
    changes = []
    for dp_id in sorted(new.keys(), key=lambda x: int(x)):
        new_val = new[dp_id]
        old_val = old.get(dp_id, {})
        if new_val.get("time", 0) != old_val.get("time", 0):
            name = INTERESTING_DPS.get(dp_id, f"dp_{dp_id}")
            old_v = format_value(dp_id, old_val.get("value", ""))
            new_v = format_value(dp_id, new_val.get("value", ""))
            ts = datetime.fromtimestamp(new_val["time"] / 1000).strftime("%H:%M:%S.%f")[:-3]
            changes.append((dp_id, name, old_v, new_v, ts))
    return changes


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Watch Tuya cloud DP changes")
    parser.add_argument("--once", action="store_true", help="Single snapshot, no polling")
    parser.add_argument("--interval", type=float, default=2.0, help="Poll interval (seconds)")
    parser.add_argument("--all", action="store_true", help="Show all DPs, not just interesting ones")
    args = parser.parse_args()

    email = os.environ.get("TUYA_USERNAME", "")
    password = os.environ.get("TUYA_PASSWORD", "")
    region = os.environ.get("TUYA_REGION", "us")

    if not email or not password:
        print("Set TUYA_USERNAME and TUYA_PASSWORD")
        sys.exit(1)

    api = TuyaMobileAPI(region=region)
    result = api.login("64", email, password)
    if not result.get("success"):
        print(f"Login failed: {result}")
        sys.exit(1)
    print(f"Logged in as {email}")

    dps = get_dps(api)
    if not dps:
        print("Failed to get DPs")
        sys.exit(1)

    # Show initial snapshot
    print(f"\n{'='*70}")
    print("CURRENT DP VALUES")
    print(f"{'='*70}")
    for dp_id in sorted(dps.keys(), key=lambda x: int(x)):
        name = INTERESTING_DPS.get(dp_id, "")
        val = dps[dp_id].get("value", "")
        ts = dps[dp_id].get("time", 0)
        ts_str = datetime.fromtimestamp(ts / 1000).strftime("%H:%M:%S") if ts else "never"
        if not args.all and not name:
            continue
        formatted = format_value(dp_id, val)
        print(f"  DP {dp_id:>3s} {name:>20s} = {formatted:>50s}  [{ts_str}]")

    if args.once:
        return

    # Polling loop
    prev = snapshot(dps)
    print(f"\n{'='*70}")
    print(f"WATCHING FOR CHANGES (polling every {args.interval}s)...")
    print(f"Unlock/lock the device, then check what changes here.")
    print(f"{'='*70}\n")

    try:
        while True:
            time.sleep(args.interval)
            dps = get_dps(api)
            if not dps:
                continue
            curr = snapshot(dps)
            changes = diff_snapshots(prev, curr)
            if changes:
                now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                print(f"[{now}] === CHANGES DETECTED ===")
                for dp_id, name, old_v, new_v, ts in changes:
                    print(f"  DP {dp_id:>3s} ({name})")
                    print(f"    OLD: {old_v}")
                    print(f"    NEW: {new_v}")
                    print(f"    at:  {ts}")
                print()
            prev = curr
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
