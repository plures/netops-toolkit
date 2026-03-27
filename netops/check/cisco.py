r"""Cisco IOS/IOS-XE health checker.

Extends the generic health check with Cisco-specific checks:

* CPU utilisation (``show processes cpu``)
* Memory utilisation (``show processes memory``)
* Interface error counters (CRC, input/output errors, drops)
* BGP neighbour state and prefix counts
* OSPF adjacency verification
* Environment — temperature, power supplies, fans
* Uptime and last reload reason

Supports IOS 15.x+ and IOS-XE 16.x+.

Usage::

    python -m netops.check.cisco --host 10.0.0.1 --user admin \\
        --threshold cpu=80,mem=85 --json

    python -m netops.check.cisco --inventory inv.yaml --group core \\
        --threshold cpu=80,mem=85 --fail-on-alert
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone

from netops.core import DeviceConnection
from netops.core.connection import ConnectionParams, Transport
from netops.core.inventory import Inventory
from netops.parsers.bgp import parse_bgp_summary_cisco
from netops.parsers.cisco import (
    parse_environment_cisco,
    parse_ospf_neighbors,
    parse_version_cisco,
)
from netops.parsers.health import (
    parse_cpu_cisco,
    parse_interface_errors_cisco,
    parse_logs_cisco,
    parse_memory_cisco,
)

logger = logging.getLogger(__name__)

# Default alert thresholds
DEFAULT_CPU_THRESHOLD = 80.0
DEFAULT_MEM_THRESHOLD = 85.0


# ---------------------------------------------------------------------------
# Individual check helpers
# ---------------------------------------------------------------------------


def check_cisco_cpu(conn: DeviceConnection, threshold: float) -> dict:
    """Return CPU utilisation check result for a Cisco IOS/IOS-XE device.

    Returns a dict with keys:

    * ``utilization``  – 1-minute average CPU % (``float``) or ``None`` on parse failure
    * ``threshold``    – configured alert threshold
    * ``alert``        – ``True`` when ``utilization >= threshold``
    * ``raw``          – full parsed data from the ``show processes cpu`` output
    """
    try:
        output = conn.send("show processes cpu")
        data = parse_cpu_cisco(output)
        utilization = data.get("one_minute", 0.0)
        return {
            "utilization": utilization,
            "threshold": threshold,
            "alert": utilization >= threshold,
            "raw": data,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("CPU check failed: %s", exc)
        return {"utilization": None, "threshold": threshold, "alert": False, "error": str(exc)}


def check_cisco_memory(conn: DeviceConnection, threshold: float) -> dict:
    """Return memory utilisation check result for a Cisco IOS/IOS-XE device.

    Returns a dict with keys:

    * ``utilization``  – memory used % (``float``) or ``None`` on parse failure
    * ``threshold``    – configured alert threshold
    * ``alert``        – ``True`` when ``utilization >= threshold``
    * ``raw``          – full parsed data from the ``show processes memory`` output
    """
    try:
        output = conn.send("show processes memory")
        data = parse_memory_cisco(output)
        utilization = data.get("utilization", 0.0)
        return {
            "utilization": utilization,
            "threshold": threshold,
            "alert": utilization >= threshold,
            "raw": data,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Memory check failed: %s", exc)
        return {"utilization": None, "threshold": threshold, "alert": False, "error": str(exc)}


def check_cisco_interfaces(conn: DeviceConnection) -> dict:
    """Return interface error-counter check result for a Cisco IOS/IOS-XE device.

    Returns a dict with keys:

    * ``interfaces``   – list of per-interface error dicts
    * ``total``        – total number of interfaces parsed
    * ``with_errors``  – count of interfaces that have at least one error counter > 0
    * ``alert``        – ``True`` when any interface has errors
    """
    try:
        output = conn.send("show interfaces")
        interfaces = parse_interface_errors_cisco(output)
        errored = [i for i in interfaces if i["has_errors"]]
        return {
            "interfaces": interfaces,
            "total": len(interfaces),
            "with_errors": len(errored),
            "alert": len(errored) > 0,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Interface check failed: %s", exc)
        return {"interfaces": [], "total": 0, "with_errors": 0, "alert": False, "error": str(exc)}


def check_cisco_logs(conn: DeviceConnection) -> dict:
    """Return log-scan check result (severity 0–3 events) for a Cisco IOS/IOS-XE device.

    Returns a dict with keys:

    * ``critical_count`` – count of severity 0–2 events
    * ``major_count``    – count of severity 3 events
    * ``events``         – list of parsed event dicts
    * ``alert``          – ``True`` when any critical or major events are present
    """
    try:
        output = conn.send("show logging")
        events = parse_logs_cisco(output)
        critical = sum(1 for e in events if e.get("severity", 9) <= 2)
        major = sum(1 for e in events if e.get("severity", 9) == 3)
        return {
            "critical_count": critical,
            "major_count": major,
            "events": events,
            "alert": (critical + major) > 0,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Log check failed: %s", exc)
        return {
            "critical_count": 0,
            "major_count": 0,
            "events": [],
            "alert": False,
            "error": str(exc),
        }


def check_cisco_bgp(conn: DeviceConnection, device_type: str = "cisco_ios") -> dict:
    """Return BGP neighbour state check result for a Cisco IOS/IOS-XE device.

    Returns a dict with keys:

    * ``peers``              – list of peer dicts from the BGP summary parser
    * ``total``              – total BGP peers parsed
    * ``established``        – count of peers in Established state
    * ``not_established``    – count of peers not in Established state
    * ``alert``              – ``True`` when any peer is not Established
    """
    try:
        if device_type == "cisco_xr":
            output = conn.send("show bgp summary")
        else:
            output = conn.send("show ip bgp summary")
        peers = parse_bgp_summary_cisco(output)
        established = sum(1 for p in peers if p.get("state") == "Established")
        not_established = len(peers) - established
        return {
            "peers": peers,
            "total": len(peers),
            "established": established,
            "not_established": not_established,
            "alert": not_established > 0,
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


def check_cisco_ospf(conn: DeviceConnection) -> dict:
    """Return OSPF adjacency check result for a Cisco IOS/IOS-XE device.

    Returns a dict with keys:

    * ``neighbors``      – list of neighbour dicts from the OSPF parser
    * ``total``          – total OSPF neighbours parsed
    * ``full``           – count of neighbours in FULL state
    * ``not_full``       – count of neighbours not in FULL state
    * ``alert``          – ``True`` when any neighbour is not in FULL state
    """
    try:
        output = conn.send("show ip ospf neighbor")
        neighbors = parse_ospf_neighbors(output)
        full = sum(1 for n in neighbors if n["is_full"])
        not_full = len(neighbors) - full
        return {
            "neighbors": neighbors,
            "total": len(neighbors),
            "full": full,
            "not_full": not_full,
            "alert": not_full > 0,
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


def check_cisco_environment(conn: DeviceConnection) -> dict:
    """Return environment check result for a Cisco IOS/IOS-XE device.

    Returns a dict with keys:

    * ``fans``           – list of fan status dicts
    * ``temperatures``   – list of temperature sensor dicts
    * ``power_supplies`` – list of power-supply status dicts
    * ``overall_ok``     – ``True`` when all reported components are OK
    * ``alert``          – ``True`` when ``overall_ok`` is ``False``
    """
    try:
        output = conn.send("show environment all")
        data = parse_environment_cisco(output)
        return {
            "fans": data["fans"],
            "temperatures": data["temperatures"],
            "power_supplies": data["power_supplies"],
            "overall_ok": data["overall_ok"],
            "alert": not data["overall_ok"],
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Environment check failed: %s", exc)
        return {
            "fans": [],
            "temperatures": [],
            "power_supplies": [],
            "overall_ok": True,
            "alert": False,
            "error": str(exc),
        }


def check_cisco_uptime(conn: DeviceConnection) -> dict:
    """Return uptime and reload reason check result for a Cisco IOS/IOS-XE device.

    Returns a dict with keys:

    * ``version``       – IOS/IOS-XE version string
    * ``platform``      – hardware platform identifier
    * ``uptime``        – uptime string as reported by the device
    * ``reload_reason`` – last reload or restart reason
    * ``image``         – system image file path
    * ``alert``         – always ``False`` (informational only)
    """
    try:
        output = conn.send("show version")
        data = parse_version_cisco(output)
        return {
            "version": data.get("version"),
            "platform": data.get("platform"),
            "uptime": data.get("uptime"),
            "reload_reason": data.get("reload_reason"),
            "image": data.get("image"),
            "alert": False,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Uptime check failed: %s", exc)
        return {
            "version": None,
            "platform": None,
            "uptime": None,
            "reload_reason": None,
            "image": None,
            "alert": False,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Composite health check
# ---------------------------------------------------------------------------


def run_cisco_health_check(
    params: ConnectionParams,
    cpu_threshold: float = DEFAULT_CPU_THRESHOLD,
    mem_threshold: float = DEFAULT_MEM_THRESHOLD,
    include_bgp: bool = True,
    include_ospf: bool = True,
    include_environment: bool = True,
) -> dict:
    """Run all Cisco IOS/IOS-XE health checks against a single device.

    Returns a result dict matching the standard health-check schema::

        {
            "host":          <str>,
            "timestamp":     <ISO-8601 UTC>,
            "success":       <bool>,
            "checks": {
                "cpu":               { "utilization": <float>, "alert": <bool>, ... },
                "memory":            { "utilization": <float>, "alert": <bool>, ... },
                "interface_errors":  { "with_errors": <int>,   "alert": <bool>, ... },
                "logs":              { "critical_count": <int>, "alert": <bool>, ... },
                "bgp":               { "not_established": <int>, "alert": <bool>, ... },
                "ospf":              { "not_full": <int>,      "alert": <bool>, ... },
                "environment":       { "overall_ok": <bool>,   "alert": <bool>, ... },
                "uptime":            { "uptime": <str>,        "alert": False, ... },
            },
            "overall_alert": <bool>,
            "error":         <str | None>,
        }

    Parameters
    ----------
    params:
        Device connection parameters.
    cpu_threshold:
        CPU alert threshold in percent (default: 80).
    mem_threshold:
        Memory alert threshold in percent (default: 85).
    include_bgp:
        When ``True`` (default), run the BGP peer check.
    include_ospf:
        When ``True`` (default), run the OSPF adjacency check.
    include_environment:
        When ``True`` (default), run the environment check.

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
            dt = params.device_type
            result["checks"]["cpu"] = check_cisco_cpu(conn, cpu_threshold)
            result["checks"]["memory"] = check_cisco_memory(conn, mem_threshold)
            result["checks"]["interface_errors"] = check_cisco_interfaces(conn)
            result["checks"]["logs"] = check_cisco_logs(conn)
            if include_bgp:
                result["checks"]["bgp"] = check_cisco_bgp(conn, dt)
            if include_ospf:
                result["checks"]["ospf"] = check_cisco_ospf(conn)
            if include_environment:
                result["checks"]["environment"] = check_cisco_environment(conn)
            result["checks"]["uptime"] = check_cisco_uptime(conn)
            result["success"] = True
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        return result

    result["overall_alert"] = any(result["checks"][k].get("alert", False) for k in result["checks"])
    return result


def build_cisco_health_report(results: list[dict]) -> dict:
    """Build an aggregated health report from a list of per-device results.

    Parameters
    ----------
    results:
        List of dicts returned by :func:`run_cisco_health_check`.

    Returns a summary dict with keys:

    * ``devices``                  – total devices polled
    * ``devices_reachable``        – devices successfully reached
    * ``devices_with_alerts``      – count of devices with at least one alert
    * ``cpu_alerts``               – devices with a CPU alert
    * ``memory_alerts``            – devices with a memory alert
    * ``interface_error_alerts``   – devices with interface error alerts
    * ``log_alerts``               – devices with log alerts
    * ``bgp_alerts``               – devices with BGP peer alerts
    * ``ospf_alerts``              – devices with OSPF adjacency alerts
    * ``environment_alerts``       – devices with environment alerts
    * ``overall_alert``            – ``True`` when any device triggered an alert
    * ``results``                  – original per-device result list

    """
    reachable = [r for r in results if r.get("success")]

    def _count_alert(key: str) -> int:
        """Count how many reachable devices have an alert for check *key*."""
        return sum(1 for r in reachable if r.get("checks", {}).get(key, {}).get("alert"))

    devices_with_alerts = sum(1 for r in reachable if r.get("overall_alert"))

    return {
        "devices": len(results),
        "devices_reachable": len(reachable),
        "devices_with_alerts": devices_with_alerts,
        "cpu_alerts": _count_alert("cpu"),
        "memory_alerts": _count_alert("memory"),
        "interface_error_alerts": _count_alert("interface_errors"),
        "log_alerts": _count_alert("logs"),
        "bgp_alerts": _count_alert("bgp"),
        "ospf_alerts": _count_alert("ospf"),
        "environment_alerts": _count_alert("environment"),
        "overall_alert": devices_with_alerts > 0,
        "results": results,
    }


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------


def _parse_thresholds(raw: str | None) -> dict[str, float]:
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
    """Pretty-print a single device Cisco health result."""
    icon = "🚨" if result.get("overall_alert") else ("✅" if result.get("success") else "❌")
    print(f"{icon} {result['host']} [{result['timestamp']}]")

    if not result.get("success"):
        print(f"   ERROR: {result.get('error')}")
        return

    checks = result.get("checks", {})

    cpu = checks.get("cpu", {})
    if cpu.get("utilization") is not None:
        tag = " ⚠️  ALERT" if cpu.get("alert") else ""
        print(f"   CPU : {cpu['utilization']:.1f}% (threshold {cpu['threshold']}%){tag}")

    mem = checks.get("memory", {})
    if mem.get("utilization") is not None:
        tag = " ⚠️  ALERT" if mem.get("alert") else ""
        print(f"   MEM : {mem['utilization']:.1f}% (threshold {mem['threshold']}%){tag}")

    iface = checks.get("interface_errors", {})
    tag = " ⚠️  ALERT" if iface.get("alert") else ""
    print(
        f"   IFACE ERRORS: {iface.get('with_errors', 0)}/{iface.get('total', 0)}"
        f" interfaces with errors{tag}"
    )

    logs = checks.get("logs", {})
    tag = " ⚠️  ALERT" if logs.get("alert") else ""
    print(
        f"   LOGS: {logs.get('critical_count', 0)} critical,"
        f" {logs.get('major_count', 0)} major{tag}"
    )

    bgp = checks.get("bgp", {})
    if "total" in bgp:
        tag = " ⚠️  ALERT" if bgp.get("alert") else ""
        print(
            f"   BGP: {bgp['established']}/{bgp['total']} established"
            f" ({bgp['not_established']} down){tag}"
        )

    ospf = checks.get("ospf", {})
    if "total" in ospf:
        tag = " ⚠️  ALERT" if ospf.get("alert") else ""
        print(f"   OSPF: {ospf['full']}/{ospf['total']} FULL ({ospf['not_full']} not FULL){tag}")

    env = checks.get("environment", {})
    if "overall_ok" in env:
        tag = " ⚠️  ALERT" if env.get("alert") else ""
        fans = len(env.get("fans", []))
        temps = len(env.get("temperatures", []))
        psu = len(env.get("power_supplies", []))
        print(
            f"   ENV: {'OK' if env['overall_ok'] else 'FAIL'}"
            f"  fans={fans}  temps={temps}  psu={psu}{tag}"
        )

    uptime = checks.get("uptime", {})
    if uptime.get("uptime"):
        ver = f"  IOS {uptime['version']}" if uptime.get("version") else ""
        print(f"   UPTIME: {uptime['uptime']}{ver}")
    if uptime.get("reload_reason"):
        print(f"   RELOAD: {uptime['reload_reason']}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for Cisco IOS/IOS-XE health checks."""
    parser = argparse.ArgumentParser(
        description="Cisco IOS/IOS-XE health checks (CPU, memory, interfaces, BGP, OSPF, env)"
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--inventory", "-i", metavar="FILE", help="YAML/JSON inventory file")
    target.add_argument("--host", metavar="IP", help="Single device IP/hostname")

    parser.add_argument("--group", "-g", metavar="GROUP", help="Filter inventory by group")
    parser.add_argument("--vendor", default="cisco_ios", help="Device vendor (single-host mode)")
    parser.add_argument("--user", "-u", metavar="USER", help="SSH username")
    parser.add_argument("--password", "-p", metavar="PASS", help="SSH password")
    parser.add_argument(
        "--threshold",
        metavar="KEY=VAL[,...]",
        help="Alert thresholds, e.g. cpu=80,mem=85",
    )
    parser.add_argument("--no-bgp", action="store_true", help="Skip BGP check")
    parser.add_argument("--no-ospf", action="store_true", help="Skip OSPF check")
    parser.add_argument("--no-env", action="store_true", help="Skip environment check")
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
        run_cisco_health_check(
            p,
            cpu_threshold=cpu_thr,
            mem_threshold=mem_thr,
            include_bgp=not args.no_bgp,
            include_ospf=not args.no_ospf,
            include_environment=not args.no_env,
        )
        for p in device_params
    ]

    report = build_cisco_health_report(results)

    if args.json:
        output = {"devices": results, "report": report}
        json.dump(output, sys.stdout, indent=2)
        print()
    else:
        for r in results:
            _print_result(r)

    if args.fail_on_alert and report.get("overall_alert"):
        sys.exit(1)


if __name__ == "__main__":
    main()
