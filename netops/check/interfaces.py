"""Check interface status across devices.

Usage:
    python -m netops.check.interfaces --inventory inventory.yaml --down-only
    python -m netops.check.interfaces --host 10.0.0.1 --vendor cisco_ios
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from netops.core import DeviceConnection
from netops.core.connection import ConnectionParams
from netops.parsers.nokia_sros import parse_interfaces as parse_nokia_interfaces


def parse_cisco_interfaces(output: str) -> list[dict]:
    """Parse 'show ip interface brief' output."""
    interfaces = []
    for line in output.splitlines():
        # Interface  IP-Address  OK?  Method  Status  Protocol
        match = re.match(
            r"(\S+)\s+(\S+)\s+\S+\s+\S+\s+(administratively down|up|down)\s+(up|down)", line
        )
        if match:
            interfaces.append(
                {
                    "name": match.group(1),
                    "ip": match.group(2) if match.group(2) != "unassigned" else None,
                    "status": match.group(3),
                    "protocol": match.group(4),
                    "up": match.group(3) == "up" and match.group(4) == "up",
                }
            )
    return interfaces


def check_interfaces(params: ConnectionParams, down_only: bool = False) -> dict:
    """Check interface status on a device."""
    result = {
        "host": params.host,
        "success": False,
        "interfaces": [],
        "summary": {},
        "error": None,
    }

    try:
        with DeviceConnection(params) as conn:
            if "nokia" in params.device_type:
                output = conn.send("show port")
                all_interfaces = parse_nokia_interfaces(output)
                interfaces = (
                    [i for i in all_interfaces if not i["up"]] if down_only else all_interfaces
                )
                result["interfaces"] = interfaces
                result["summary"] = {
                    "total": len(all_interfaces),
                    "up": sum(1 for i in all_interfaces if i["up"]),
                    "down": sum(1 for i in all_interfaces if not i["up"]),
                }
                result["success"] = True
            else:
                output = conn.send("show ip interface brief")
                interfaces = parse_cisco_interfaces(output)

                if down_only:
                    interfaces = [i for i in interfaces if not i["up"]]

                result["interfaces"] = interfaces
                result["summary"] = {
                    "total": len(parse_cisco_interfaces(output)),
                    "up": sum(1 for i in parse_cisco_interfaces(output) if i["up"]),
                    "down": sum(1 for i in parse_cisco_interfaces(output) if not i["up"]),
                }
                result["success"] = True
    except Exception as e:
        result["error"] = str(e)

    return result


def main() -> None:
    """CLI entry point for the interface status checker."""
    parser = argparse.ArgumentParser(description="Check interface status")
    parser.add_argument("--host", required=True)
    parser.add_argument("--vendor", default="cisco_ios")
    parser.add_argument("--user", "-u")
    parser.add_argument("--password", "-p")
    parser.add_argument("--down-only", action="store_true", help="Show only down interfaces")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    import os

    params = ConnectionParams(
        host=args.host,
        username=args.user,
        password=args.password or os.environ.get("NETOPS_PASSWORD"),
        device_type=args.vendor,
    )

    result = check_interfaces(params, down_only=args.down_only)

    if args.json:
        json.dump(result, sys.stdout, indent=2)
    else:
        if result["success"]:
            s = result["summary"]
            print(f"📊 {result['host']}: {s['up']}/{s['total']} interfaces up, {s['down']} down")
            for iface in result["interfaces"]:
                status = "✅" if iface["up"] else "❌"
                ip = f" ({iface['ip']})" if iface.get("ip") else ""
                print(f"  {status} {iface['name']}{ip} — {iface['status']}/{iface['protocol']}")
        else:
            print(f"❌ {result['host']}: {result['error']}")


if __name__ == "__main__":
    main()
