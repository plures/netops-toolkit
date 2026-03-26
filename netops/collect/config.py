"""Collect device configurations.

Usage:
    python -m netops.collect.config --inventory inventory.yaml --group core
    python -m netops.collect.config --host 10.0.0.1 --vendor cisco_ios --user admin
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from netops.core import DeviceConnection, Inventory
from netops.core.connection import ConnectionParams, Transport

logger = logging.getLogger(__name__)


def collect_config(params: ConnectionParams) -> dict:
    """Collect running config from a device. Returns structured result."""
    result = {
        "host": params.host,
        "device_type": params.device_type,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "success": False,
        "config": None,
        "error": None,
    }

    try:
        with DeviceConnection(params) as conn:
            # Use vendor-appropriate show command
            if "nokia" in params.device_type:
                config = conn.send("admin display-config")
            else:
                config = conn.send("show running-config")

            result["success"] = True
            result["config"] = config
            result["lines"] = len(config.splitlines())
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"Failed to collect config from {params.host}: {e}")

    return result


def main() -> None:
    """CLI entry point for device configuration collection."""
    parser = argparse.ArgumentParser(description="Collect device configurations")
    parser.add_argument("--inventory", "-i", help="Inventory file (YAML/JSON)")
    parser.add_argument("--group", "-g", help="Inventory group to target")
    parser.add_argument("--host", help="Single host to connect to")
    parser.add_argument("--vendor", default="cisco_ios", help="Device type (default: cisco_ios)")
    parser.add_argument("--user", "-u", help="Username")
    parser.add_argument("--password", "-p", help="Password (or use env NETOPS_PASSWORD)")
    parser.add_argument("--transport", choices=["ssh", "telnet"], default="ssh")
    parser.add_argument("--output", "-o", help="Output directory for configs")
    parser.add_argument("--json", action="store_true", help="JSON output to stdout")
    args = parser.parse_args()

    import os
    password = args.password or os.environ.get("NETOPS_PASSWORD")

    results = []

    if args.inventory:
        inv = Inventory.from_file(args.inventory)
        devices = inv.filter(group=args.group) if args.group else list(inv.devices.values())

        for device in devices:
            params = ConnectionParams(
                host=device.host,
                username=device.username or args.user,
                password=device.password or password,
                device_type=device.vendor,
                transport=Transport(device.transport),
                port=device.port,
            )
            results.append(collect_config(params))
    elif args.host:
        params = ConnectionParams(
            host=args.host,
            username=args.user,
            password=password,
            device_type=args.vendor,
            transport=Transport(args.transport),
        )
        results.append(collect_config(params))
    else:
        parser.error("Provide --inventory or --host")

    # Output
    if args.json:
        json.dump(results, sys.stdout, indent=2)
    elif args.output:
        out = Path(args.output)
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        for r in results:
            if r["success"]:
                fname = f"{r['host']}_{ts}.cfg"
                (out / fname).write_text(r["config"])
                print(f"✅ {r['host']} → {out / fname} ({r['lines']} lines)")
            else:
                print(f"❌ {r['host']}: {r['error']}")
    else:
        for r in results:
            if r["success"]:
                print(f"✅ {r['host']}: {r['lines']} lines collected")
            else:
                print(f"❌ {r['host']}: {r['error']}")


if __name__ == "__main__":
    main()
