"""
Juniper JunOS health checker.

Provides health checks for Juniper JunOS devices (MX, QFX, EX, SRX):

* Routing Engine (RE) CPU and memory utilisation
* FPC slot operational status
* Interface error counters
* BGP neighbour state and prefix counts
* OSPF adjacency verification
* Chassis alarms (major/minor)
* Chassis environment — power, cooling, temperature
* Routing table summary

Supports JunOS 18.x+.  Works with both XML RPC and CLI (text) modes via
Netmiko's ``juniper`` / ``juniper_junos`` device type.

Usage::

    python -m netops.check.juniper --host 10.0.0.1 --user netops \\
        --threshold cpu=80,mem=85 --json

    python -m netops.check.juniper --inventory inv.yaml --group juniper \\
        --threshold cpu=80,mem=85 --fail-on-alert
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

from netops.core import DeviceConnection
from netops.core.connection import ConnectionParams, Transport
from netops.core.inventory import Inventory
from netops.parsers.juniper import (
    parse_bgp_summary_junos,
    parse_chassis_alarms,
    parse_chassis_environment,
    parse_fpc_status,
    parse_interface_errors_junos,
    parse_ospf_neighbors_junos,
    parse_re_status,
    parse_route_summary,
)

logger = logging.getLogger(__name__)

# Default alert thresholds (percent)
DEFAULT_CPU_THRESHOLD = 80.0
DEFAULT_MEM_THRESHOLD = 85.0


# ---------------------------------------------------------------------------
# Individual check helpers
# ---------------------------------------------------------------------------


def check_junos_re(conn: DeviceConnection, cpu_threshold: float, mem_threshold: float) -> dict:
    """Return Routing Engine CPU and memory check result.

    Queries ``show chassis routing-engine`` and returns:

    * ``routing_engines`` – list of per-RE dicts from the parser
    * ``cpu_utilization`` – highest CPU % across all REs (``float``) or ``None``
    * ``mem_utilization`` – highest memory % across all REs (``float``) or ``None``
    * ``cpu_threshold``   – configured CPU alert threshold
    * ``mem_threshold``   – configured memory alert threshold
    * ``cpu_alert``       – ``True`` when any RE CPU ≥ *cpu_threshold*
    * ``mem_alert``       – ``True`` when any RE memory ≥ *mem_threshold*
    * ``alert``           – ``True`` when either cpu_alert or mem_alert is ``True``
    * ``error``           – error message on failure, else ``None``
    """
    try:
        output = conn.send("show chassis routing-engine")
        routing_engines = parse_re_status(output)

        cpu_vals = [re_["cpu_util"] for re_ in routing_engines if re_["cpu_util"] is not None]
        mem_vals = [re_["memory_util"] for re_ in routing_engines if re_["memory_util"] is not None]

        cpu_util = max(cpu_vals) if cpu_vals else None
        mem_util = max(mem_vals) if mem_vals else None

        cpu_alert = cpu_util is not None and cpu_util >= cpu_threshold
        mem_alert = mem_util is not None and mem_util >= mem_threshold

        return {
            "routing_engines": routing_engines,
            "cpu_utilization": cpu_util,
            "mem_utilization": mem_util,
            "cpu_threshold": cpu_threshold,
            "mem_threshold": mem_threshold,
            "cpu_alert": cpu_alert,
            "mem_alert": mem_alert,
            "alert": cpu_alert or mem_alert,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("RE check failed: %s", exc)
        return {
            "routing_engines": [],
            "cpu_utilization": None,
            "mem_utilization": None,
            "cpu_threshold": cpu_threshold,
            "mem_threshold": mem_threshold,
            "cpu_alert": False,
            "mem_alert": False,
            "alert": False,
            "error": str(exc),
        }


def check_junos_fpc(conn: DeviceConnection) -> dict:
    """Return FPC slot status check result.

    Queries ``show chassis fpc`` and returns:

    * ``fpcs``        – list of per-FPC dicts from the parser
    * ``total``       – total FPC slots parsed
    * ``online``      – count of FPCs in Online state
    * ``offline``     – count of FPCs in Offline state (excluding Empty/Spare)
    * ``alert``       – ``True`` when any non-empty FPC is not Online
    * ``error``       – error message on failure, else ``None``
    """
    try:
        output = conn.send("show chassis fpc")
        fpcs = parse_fpc_status(output)

        active_fpcs = [f for f in fpcs if f["state"].lower() not in ("empty", "spare")]
        online = sum(1 for f in active_fpcs if f["state"].lower() == "online")
        offline = sum(1 for f in active_fpcs if f["state"].lower() not in ("online",))

        return {
            "fpcs": fpcs,
            "total": len(fpcs),
            "online": online,
            "offline": offline,
            "alert": offline > 0,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("FPC check failed: %s", exc)
        return {
            "fpcs": [],
            "total": 0,
            "online": 0,
            "offline": 0,
            "alert": False,
            "error": str(exc),
        }


def check_junos_interfaces(conn: DeviceConnection) -> dict:
    """Return interface error-counter check result.

    Queries ``show interfaces extensive`` and returns:

    * ``interfaces``   – list of per-interface error dicts from the parser
    * ``total``        – total interfaces parsed
    * ``with_errors``  – count of interfaces with at least one non-zero error counter
    * ``alert``        – ``True`` when any interface has errors
    * ``error``        – error message on failure, else ``None``
    """
    try:
        output = conn.send("show interfaces extensive")
        interfaces = parse_interface_errors_junos(output)
        errored = [i for i in interfaces if i["has_errors"]]
        return {
            "interfaces": interfaces,
            "total": len(interfaces),
            "with_errors": len(errored),
            "alert": len(errored) > 0,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Interface check failed: %s", exc)
        return {
            "interfaces": [],
            "total": 0,
            "with_errors": 0,
            "alert": False,
            "error": str(exc),
        }


def check_junos_bgp(conn: DeviceConnection) -> dict:
    """Return BGP neighbour state check result.

    Queries ``show bgp summary`` and returns:

    * ``peers``             – list of peer dicts from the parser
    * ``total``             – total BGP peers parsed
    * ``established``       – count of peers in Established state
    * ``not_established``   – count of peers not in Established state
    * ``alert``             – ``True`` when any peer is not Established
    * ``error``             – error message on failure, else ``None``
    """
    try:
        output = conn.send("show bgp summary")
        peers = parse_bgp_summary_junos(output)
        established = sum(1 for p in peers if p.get("state") == "Established")
        not_established = len(peers) - established
        return {
            "peers": peers,
            "total": len(peers),
            "established": established,
            "not_established": not_established,
            "alert": not_established > 0,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("BGP check failed: %s", exc)
        return {
            "peers": [],
            "total": 0,
            "established": 0,
            "not_established": 0,
            "alert": False,
            "error": str(exc),
        }


def check_junos_ospf(conn: DeviceConnection) -> dict:
    """Return OSPF neighbour state check result.

    Queries ``show ospf neighbor`` and returns:

    * ``neighbors``     – list of neighbour dicts from the parser
    * ``total``         – total OSPF neighbours parsed
    * ``full``          – count of adjacencies in Full state
    * ``not_full``      – count of adjacencies not in Full state
    * ``alert``         – ``True`` when any adjacency is not Full
    * ``error``         – error message on failure, else ``None``
    """
    try:
        output = conn.send("show ospf neighbor")
        neighbors = parse_ospf_neighbors_junos(output)
        full = sum(1 for n in neighbors if n.get("is_full"))
        not_full = len(neighbors) - full
        return {
            "neighbors": neighbors,
            "total": len(neighbors),
            "full": full,
            "not_full": not_full,
            "alert": not_full > 0,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("OSPF check failed: %s", exc)
        return {
            "neighbors": [],
            "total": 0,
            "full": 0,
            "not_full": 0,
            "alert": False,
            "error": str(exc),
        }


def check_junos_alarms(conn: DeviceConnection) -> dict:
    """Return chassis alarm check result.

    Queries ``show chassis alarms`` and returns:

    * ``alarms``        – list of alarm dicts from the parser
    * ``major_count``   – number of Major alarms
    * ``minor_count``   – number of Minor alarms
    * ``alert``         – ``True`` when any Major alarm is present
    * ``error``         – error message on failure, else ``None``
    """
    try:
        output = conn.send("show chassis alarms")
        alarms = parse_chassis_alarms(output)
        major = sum(1 for a in alarms if a.get("is_major"))
        minor = len(alarms) - major
        return {
            "alarms": alarms,
            "major_count": major,
            "minor_count": minor,
            "alert": major > 0,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Alarm check failed: %s", exc)
        return {
            "alarms": [],
            "major_count": 0,
            "minor_count": 0,
            "alert": False,
            "error": str(exc),
        }


def check_junos_environment(conn: DeviceConnection) -> dict:
    """Return chassis environment check result.

    Queries ``show chassis environment`` and returns:

    * ``power_supplies`` – list of PSU status dicts
    * ``fans``           – list of fan status dicts
    * ``temperatures``   – list of temperature sensor dicts
    * ``overall_ok``     – ``True`` when every component reports OK
    * ``alert``          – ``True`` when ``overall_ok`` is ``False``
    * ``error``          – error message on failure, else ``None``
    """
    try:
        output = conn.send("show chassis environment")
        env = parse_chassis_environment(output)
        return {
            **env,
            "alert": not env["overall_ok"],
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Environment check failed: %s", exc)
        return {
            "power_supplies": [],
            "fans": [],
            "temperatures": [],
            "overall_ok": True,
            "alert": False,
            "error": str(exc),
        }


def check_junos_routes(conn: DeviceConnection) -> dict:
    """Return routing table summary check result (informational).

    Queries ``show route summary`` and returns:

    * ``tables``  – list of routing-table summary dicts
    * ``alert``   – always ``False`` (informational only)
    * ``error``   – error message on failure, else ``None``
    """
    try:
        output = conn.send("show route summary")
        tables = parse_route_summary(output)
        return {
            "tables": tables,
            "alert": False,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Route summary check failed: %s", exc)
        return {
            "tables": [],
            "alert": False,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Composite health check
# ---------------------------------------------------------------------------


def run_health_check(
    params: ConnectionParams,
    cpu_threshold: float = DEFAULT_CPU_THRESHOLD,
    mem_threshold: float = DEFAULT_MEM_THRESHOLD,
    check_bgp: bool = True,
    check_ospf: bool = True,
) -> dict:
    """Run all JunOS health checks against a single device.

    Runs:

    * **RE** – Routing Engine CPU and memory utilisation
    * **FPC** – slot operational status
    * **interfaces** – error counters
    * **BGP** – neighbour session states (when *check_bgp* is ``True``)
    * **OSPF** – adjacency states (when *check_ospf* is ``True``)
    * **alarms** – chassis alarm summary
    * **environment** – power supplies, fans and temperatures
    * **routes** – routing table summary (informational)

    Returns a result dict with keys:

    * ``host``          – device IP/hostname
    * ``timestamp``     – ISO-8601 UTC timestamp
    * ``success``       – ``True`` when connection succeeded
    * ``checks``        – dict of individual check results
    * ``overall_alert`` – ``True`` when any check triggered an alert
    * ``error``         – error message when connection failed
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result: dict = {
        "host": params.host,
        "timestamp": timestamp,
        "success": False,
        "checks": {},
        "overall_alert": False,
        "error": None,
    }

    try:
        with DeviceConnection(params) as conn:
            result["checks"]["re"] = check_junos_re(conn, cpu_threshold, mem_threshold)
            result["checks"]["fpc"] = check_junos_fpc(conn)
            result["checks"]["interfaces"] = check_junos_interfaces(conn)
            if check_bgp:
                result["checks"]["bgp"] = check_junos_bgp(conn)
            if check_ospf:
                result["checks"]["ospf"] = check_junos_ospf(conn)
            result["checks"]["alarms"] = check_junos_alarms(conn)
            result["checks"]["environment"] = check_junos_environment(conn)
            result["checks"]["routes"] = check_junos_routes(conn)
            result["success"] = True
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        return result

    result["overall_alert"] = any(
        result["checks"][k].get("alert", False) for k in result["checks"]
    )
    return result


def build_junos_health_report(results: list[dict]) -> dict:
    """Build an aggregated health report from a list of per-device results.

    Parameters
    ----------
    results:
        List of dicts returned by :func:`run_health_check`.

    Returns a summary dict with keys:

    * ``devices``                – total devices polled
    * ``devices_reachable``      – devices successfully reached
    * ``devices_with_alerts``    – count of devices with at least one alert
    * ``re_alerts``              – count of devices with RE CPU/memory alerts
    * ``fpc_alerts``             – count of devices with FPC alerts
    * ``interface_alerts``       – count of devices with interface error alerts
    * ``bgp_alerts``             – count of devices with BGP peer alerts
    * ``ospf_alerts``            – count of devices with OSPF adjacency alerts
    * ``alarm_alerts``           – count of devices with chassis alarm alerts
    * ``environment_alerts``     – count of devices with environment alerts
    * ``overall_alert``          – ``True`` when any device triggered an alert
    * ``results``                – original per-device result list
    """
    reachable = [r for r in results if r.get("success")]

    def _count_alert(key: str) -> int:
        return sum(1 for r in reachable if r.get("checks", {}).get(key, {}).get("alert"))

    devices_with_alerts = sum(1 for r in reachable if r.get("overall_alert"))

    return {
        "devices": len(results),
        "devices_reachable": len(reachable),
        "devices_with_alerts": devices_with_alerts,
        "re_alerts": _count_alert("re"),
        "fpc_alerts": _count_alert("fpc"),
        "interface_alerts": _count_alert("interfaces"),
        "bgp_alerts": _count_alert("bgp"),
        "ospf_alerts": _count_alert("ospf"),
        "alarm_alerts": _count_alert("alarms"),
        "environment_alerts": _count_alert("environment"),
        "overall_alert": devices_with_alerts > 0,
        "results": results,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_thresholds(raw: Optional[str]) -> dict[str, float]:
    """Parse ``cpu=80,mem=85`` style threshold string."""
    thresholds: dict[str, float] = {}
    if not raw:
        return thresholds
    for part in raw.split(","):
        part = part.strip()
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        try:
            thresholds[key.strip().lower()] = float(val.strip())
        except ValueError:
            pass
    return thresholds


def _print_result(result: dict) -> None:
    """Pretty-print a single device health result."""
    icon = "🚨" if result.get("overall_alert") else ("✅" if result.get("success") else "❌")
    print(f"{icon} {result['host']} [{result['timestamp']}]")

    if not result.get("success"):
        print(f"   ERROR: {result.get('error')}")
        return

    checks = result.get("checks", {})

    # Routing Engine
    re_check = checks.get("re", {})
    cpu = re_check.get("cpu_utilization")
    mem = re_check.get("mem_utilization")
    re_alert = " ⚠️  ALERT" if re_check.get("alert") else ""
    if cpu is not None:
        print(
            f"   RE CPU : {cpu:.1f}% (threshold {re_check.get('cpu_threshold')}%){re_alert}"
        )
    if mem is not None:
        print(
            f"   RE MEM : {mem:.1f}% (threshold {re_check.get('mem_threshold')}%){re_alert}"
        )

    # FPC
    fpc = checks.get("fpc", {})
    fpc_alert = " ⚠️  ALERT" if fpc.get("alert") else ""
    print(
        f"   FPC : {fpc.get('online', 0)} online,"
        f" {fpc.get('offline', 0)} offline{fpc_alert}"
    )

    # Interfaces
    iface = checks.get("interfaces", {})
    iface_alert = " ⚠️  ALERT" if iface.get("alert") else ""
    print(
        f"   IFACE ERRORS : {iface.get('with_errors', 0)}/{iface.get('total', 0)}"
        f" interfaces with errors{iface_alert}"
    )

    # BGP
    bgp = checks.get("bgp")
    if bgp is not None:
        bgp_alert = " ⚠️  ALERT" if bgp.get("alert") else ""
        print(
            f"   BGP : {bgp.get('established', 0)}/{bgp.get('total', 0)}"
            f" established{bgp_alert}"
        )

    # OSPF
    ospf = checks.get("ospf")
    if ospf is not None:
        ospf_alert = " ⚠️  ALERT" if ospf.get("alert") else ""
        print(
            f"   OSPF : {ospf.get('full', 0)}/{ospf.get('total', 0)}"
            f" full adjacencies{ospf_alert}"
        )

    # Alarms
    alarms = checks.get("alarms", {})
    alarm_alert = " ⚠️  ALERT" if alarms.get("alert") else ""
    print(
        f"   ALARMS : {alarms.get('major_count', 0)} major,"
        f" {alarms.get('minor_count', 0)} minor{alarm_alert}"
    )

    # Environment
    env = checks.get("environment", {})
    env_alert = " ⚠️  ALERT" if env.get("alert") else ""
    print(f"   ENVIRONMENT : {'OK' if env.get('overall_ok') else 'FAULT'}{env_alert}")

    # Routes (informational)
    routes = checks.get("routes", {})
    tables = routes.get("tables", [])
    if tables:
        for tbl in tables:
            print(
                f"   ROUTES [{tbl['table']}] : {tbl['active_routes']} active"
                f" / {tbl['total_routes']} total"
            )


def main() -> None:
    """CLI entry point for JunOS health checks."""
    parser = argparse.ArgumentParser(
        description="JunOS health checks — RE CPU/mem, FPC, interfaces, BGP, OSPF, alarms, environment"
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--inventory", "-i", metavar="FILE", help="YAML/JSON inventory file")
    target.add_argument("--host", metavar="IP", help="Single device IP/hostname")

    parser.add_argument("--group", "-g", metavar="GROUP", help="Filter inventory by group")
    parser.add_argument(
        "--vendor",
        default="juniper_junos",
        help="Device vendor string (default: juniper_junos)",
    )
    parser.add_argument("--user", "-u", metavar="USER", help="SSH username")
    parser.add_argument("--password", "-p", metavar="PASS", help="SSH password")
    parser.add_argument(
        "--threshold",
        metavar="KEY=VAL[,...]",
        help="Alert thresholds, e.g. cpu=80,mem=85",
    )
    parser.add_argument("--no-bgp", action="store_true", help="Skip BGP checks")
    parser.add_argument("--no-ospf", action="store_true", help="Skip OSPF checks")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--fail-on-alert", action="store_true", help="Exit 1 if any alert fires")
    args = parser.parse_args()

    thresholds = _parse_thresholds(args.threshold)
    cpu_thr = thresholds.get("cpu", DEFAULT_CPU_THRESHOLD)
    mem_thr = thresholds.get("mem", DEFAULT_MEM_THRESHOLD)
    password = args.password or os.environ.get("NETOPS_PASSWORD")

    device_params: list[ConnectionParams] = []

    if args.inventory:
        inv = Inventory.from_file(args.inventory)
        devices = inv.filter(group=args.group) if args.group else list(inv.devices.values())
        for dev in devices:
            device_params.append(
                ConnectionParams(
                    host=dev.host,
                    username=args.user or dev.username,
                    password=password or dev.password,
                    device_type=dev.vendor,
                    transport=Transport(dev.transport) if dev.transport else Transport.SSH,
                    port=dev.port,
                    enable_password=dev.enable_password,
                )
            )
    else:
        device_params.append(
            ConnectionParams(
                host=args.host,
                username=args.user,
                password=password,
                device_type=args.vendor,
            )
        )

    results = [
        run_health_check(
            p,
            cpu_threshold=cpu_thr,
            mem_threshold=mem_thr,
            check_bgp=not args.no_bgp,
            check_ospf=not args.no_ospf,
        )
        for p in device_params
    ]

    if args.json:
        json.dump(results if len(results) > 1 else results[0], sys.stdout, indent=2)
        print()
    else:
        for r in results:
            _print_result(r)

    if args.fail_on_alert and any(r.get("overall_alert") for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
