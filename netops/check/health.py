"""
Composable health checks for network devices.

Runs CPU, memory, interface-error, and log checks across vendors and reports
results as structured JSON for monitoring integration.

Usage::

    python -m netops.check.health --inventory inv.yaml --group core \\
        --threshold cpu=80,mem=85

    python -m netops.check.health --host 10.0.0.1 --vendor cisco_ios \\
        --threshold cpu=80,mem=85 --json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

from netops.core.connection import ConnectionParams, Transport
from netops.core import DeviceConnection
from netops.core.inventory import Inventory
from netops.parsers.health import (
    parse_cpu_brocade,
    parse_cpu_cisco,
    parse_cpu_nokia,
    parse_cpu_paloalto,
    parse_interface_errors_brocade,
    parse_interface_errors_cisco,
    parse_interface_errors_nokia,
    parse_logs_brocade,
    parse_logs_cisco,
    parse_logs_nokia,
    parse_memory_brocade,
    parse_memory_cisco,
    parse_memory_nokia,
    parse_memory_paloalto,
)

logger = logging.getLogger(__name__)

# Default alert thresholds (percentages)
DEFAULT_CPU_THRESHOLD = 80.0
DEFAULT_MEM_THRESHOLD = 85.0


# ---------------------------------------------------------------------------
# Per-check helpers
# ---------------------------------------------------------------------------


def _is_nokia(device_type: str) -> bool:
    return "nokia" in device_type.lower()


def _is_brocade(device_type: str) -> bool:
    return "brocade" in device_type.lower()


def _is_paloalto(device_type: str) -> bool:
    return "paloalto" in device_type.lower() or "panos" in device_type.lower()


def check_cpu(conn: DeviceConnection, device_type: str, threshold: float) -> dict:
    """Return CPU utilisation check result."""
    try:
        if _is_nokia(device_type):
            output = conn.send("show system cpu")
            data = parse_cpu_nokia(output)
            utilization = data.get("avg", 0.0)
        elif _is_brocade(device_type):
            output = conn.send("show cpu")
            data = parse_cpu_brocade(output)
            utilization = data.get("one_minute", data.get("five_seconds", 0.0))
        elif _is_paloalto(device_type):
            output = conn.send("show system resources follow duration 1")
            data = parse_cpu_paloalto(output)
            utilization = data.get("utilization", 0.0)
        else:
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


def check_memory(conn: DeviceConnection, device_type: str, threshold: float) -> dict:
    """Return memory utilisation check result."""
    try:
        if _is_nokia(device_type):
            output = conn.send("show system memory-pools")
            data = parse_memory_nokia(output)
        elif _is_brocade(device_type):
            output = conn.send("show memory")
            data = parse_memory_brocade(output)
        elif _is_paloalto(device_type):
            output = conn.send("show system resources follow duration 1")
            data = parse_memory_paloalto(output)
        else:
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


def check_interface_errors(conn: DeviceConnection, device_type: str) -> dict:
    """Return interface error-counter check result."""
    try:
        if _is_nokia(device_type):
            output = conn.send("show port detail")
            interfaces = parse_interface_errors_nokia(output)
        elif _is_brocade(device_type):
            output = conn.send("show interfaces")
            interfaces = parse_interface_errors_brocade(output)
        else:
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
        logger.warning("Interface-errors check failed: %s", exc)
        return {"interfaces": [], "total": 0, "with_errors": 0, "alert": False, "error": str(exc)}


def check_logs(conn: DeviceConnection, device_type: str) -> dict:
    """Return log-scan check result (critical/major events)."""
    try:
        if _is_nokia(device_type):
            output = conn.send("show log 99")
            events = parse_logs_nokia(output)
            critical = sum(1 for e in events if e.get("severity") == "CRITICAL")
            major = sum(1 for e in events if e.get("severity") == "MAJOR")
        elif _is_brocade(device_type):
            output = conn.send("show logging")
            events = parse_logs_brocade(output)
            critical = sum(1 for e in events if e.get("severity") == "CRITICAL")
            major = sum(1 for e in events if e.get("severity") == "ERROR")
        else:
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


# ---------------------------------------------------------------------------
# Composite health check
# ---------------------------------------------------------------------------


def run_health_check(
    params: ConnectionParams,
    cpu_threshold: float = DEFAULT_CPU_THRESHOLD,
    mem_threshold: float = DEFAULT_MEM_THRESHOLD,
) -> dict:
    """Run all health checks against a single device.

    Returns a result dict with keys:

    * ``host``         – device IP/hostname
    * ``timestamp``    – ISO-8601 UTC timestamp
    * ``success``      – ``True`` when connection succeeded
    * ``checks``       – dict of individual check results
    * ``overall_alert``– ``True`` when any check triggered an alert
    * ``error``        – error message when connection failed
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
            result["checks"]["cpu"] = check_cpu(conn, dt, cpu_threshold)
            result["checks"]["memory"] = check_memory(conn, dt, mem_threshold)
            result["checks"]["interface_errors"] = check_interface_errors(conn, dt)
            result["checks"]["logs"] = check_logs(conn, dt)
            result["success"] = True
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        return result

    result["overall_alert"] = any(
        result["checks"][k].get("alert", False) for k in result["checks"]
    )
    return result


def build_health_report(results: list[dict]) -> dict:
    """Build an aggregated health report from a list of per-device results.

    Parameters
    ----------
    results:
        List of dicts returned by :func:`run_health_check`.

    Returns a summary dict with keys:

    * ``devices``                  – total devices polled
    * ``devices_reachable``        – devices successfully reached
    * ``devices_with_alerts``      – count of devices with at least one alert
    * ``cpu_alerts``               – count of devices with a CPU alert
    * ``memory_alerts``            – count of devices with a memory alert
    * ``interface_error_alerts``   – count of devices with interface error alerts
    * ``log_alerts``               – count of devices with log alerts
    * ``overall_alert``            – ``True`` when any device triggered an alert
    * ``results``                  – original per-device result list
    """
    reachable = [r for r in results if r.get("success")]

    cpu_alerts = sum(
        1 for r in reachable if r.get("checks", {}).get("cpu", {}).get("alert")
    )
    memory_alerts = sum(
        1 for r in reachable if r.get("checks", {}).get("memory", {}).get("alert")
    )
    interface_error_alerts = sum(
        1 for r in reachable if r.get("checks", {}).get("interface_errors", {}).get("alert")
    )
    log_alerts = sum(
        1 for r in reachable if r.get("checks", {}).get("logs", {}).get("alert")
    )
    devices_with_alerts = sum(1 for r in reachable if r.get("overall_alert"))

    return {
        "devices": len(results),
        "devices_reachable": len(reachable),
        "devices_with_alerts": devices_with_alerts,
        "cpu_alerts": cpu_alerts,
        "memory_alerts": memory_alerts,
        "interface_error_alerts": interface_error_alerts,
        "log_alerts": log_alerts,
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

    # CPU
    cpu = checks.get("cpu", {})
    if cpu.get("utilization") is not None:
        alert_tag = " ⚠️  ALERT" if cpu.get("alert") else ""
        print(
            f"   CPU : {cpu['utilization']:.1f}%"
            f" (threshold {cpu['threshold']}%){alert_tag}"
        )

    # Memory
    mem = checks.get("memory", {})
    if mem.get("utilization") is not None:
        alert_tag = " ⚠️  ALERT" if mem.get("alert") else ""
        print(
            f"   MEM : {mem['utilization']:.1f}%"
            f" (threshold {mem['threshold']}%){alert_tag}"
        )

    # Interface errors
    iface = checks.get("interface_errors", {})
    alert_tag = " ⚠️  ALERT" if iface.get("alert") else ""
    print(
        f"   IFACE ERRORS: {iface.get('with_errors', 0)}/{iface.get('total', 0)}"
        f" interfaces with errors{alert_tag}"
    )

    # Logs
    logs = checks.get("logs", {})
    alert_tag = " ⚠️  ALERT" if logs.get("alert") else ""
    print(
        f"   LOGS: {logs.get('critical_count', 0)} critical,"
        f" {logs.get('major_count', 0)} major{alert_tag}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run composable health checks (CPU, memory, interface errors, logs)"
    )

    # Target selection — either inventory-based or single host
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
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--fail-on-alert", action="store_true", help="Exit 1 if any alert fires")
    args = parser.parse_args()

    thresholds = _parse_thresholds(args.threshold)
    cpu_thr = thresholds.get("cpu", DEFAULT_CPU_THRESHOLD)
    mem_thr = thresholds.get("mem", DEFAULT_MEM_THRESHOLD)

    password = args.password or os.environ.get("NETOPS_PASSWORD")

    # Build list of ConnectionParams
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

    results = [run_health_check(p, cpu_threshold=cpu_thr, mem_threshold=mem_thr) for p in device_params]

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
