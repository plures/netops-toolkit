r"""Arista EOS health checker.

Provides health checks for Arista EOS devices (DCS-7xxx, DCS-720x, etc.):

* CPU and memory utilisation
* Interface error counters and transceiver DOM
* BGP/EVPN session state
* OSPF adjacency verification
* MLAG health and config-consistency
* Environment — temperature sensors, fans, power supplies

eAPI JSON is the primary transport.  Plain-text CLI output is used as a
fallback when eAPI is unavailable.

Usage::

    python -m netops.check.arista --host 10.0.0.1 --user netops \\
        --threshold cpu=80,mem=85 --json

    python -m netops.check.arista --inventory inv.yaml --group arista \\
        --threshold cpu=80,mem=85 --fail-on-alert
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import cast

from netops.core import DeviceConnection
from netops.core.connection import ConnectionParams, Transport
from netops.core.inventory import Inventory
from netops.parsers.arista import (
    parse_bgp_evpn_eos,
    parse_bgp_summary_eos,
    parse_bgp_summary_eos_text,
    parse_cpu_memory_eos,
    parse_environment_eos,
    parse_interfaces_eos,
    parse_mlag_config_sanity_eos,
    parse_mlag_eos,
    parse_mlag_eos_text,
    parse_ospf_neighbors_eos,
    parse_ospf_neighbors_eos_text,
    parse_transceivers_eos,
)

logger = logging.getLogger(__name__)

# Default alert thresholds (percent)
DEFAULT_CPU_THRESHOLD = 80.0
DEFAULT_MEM_THRESHOLD = 85.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _send_json(conn: DeviceConnection, command: str) -> dict:
    """Send *command* and return JSON-decoded output.

    Tries ``conn.send(command + " | json")`` first.  Falls back to a plain
    send and attempts JSON decoding.  Returns an empty dict only when JSON
    decoding fails; connection errors are re-raised so callers can handle them.
    """
    for cmd in (f"{command} | json", command):
        raw = conn.send(cmd)
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str) and raw.strip().startswith("{"):
            try:
                return cast(dict, json.loads(raw))
            except (ValueError, json.JSONDecodeError):
                pass
    return {}


# ---------------------------------------------------------------------------
# Individual check helpers
# ---------------------------------------------------------------------------


def check_eos_cpu_memory(
    conn: DeviceConnection, cpu_threshold: float, mem_threshold: float
) -> dict:
    """Return CPU and memory utilisation check result.

    Queries ``show version`` (JSON) and returns:

    * ``cpu_utilization``  – overall CPU % (float) or ``None``
    * ``memory_util``      – memory utilisation % (float) or ``None``
    * ``cpu_threshold``    – configured CPU alert threshold
    * ``mem_threshold``    – configured memory alert threshold
    * ``cpu_alert``        – ``True`` when CPU ≥ *cpu_threshold*
    * ``mem_alert``        – ``True`` when memory ≥ *mem_threshold*
    * ``alert``            – ``True`` when either cpu_alert or mem_alert
    * ``eos_version``      – EOS software version string or ``None``
    * ``model``            – hardware model or ``None``
    * ``serial_number``    – chassis serial number or ``None``
    * ``error``            – error message on failure, else ``None``
    """
    try:
        data = _send_json(conn, "show version")
        parsed = parse_cpu_memory_eos(data)

        cpu = parsed.get("cpu_utilization")
        mem = parsed.get("memory_util")

        cpu_alert = cpu is not None and cpu >= cpu_threshold
        mem_alert = mem is not None and mem >= mem_threshold

        return {
            **parsed,
            "cpu_threshold": cpu_threshold,
            "mem_threshold": mem_threshold,
            "cpu_alert": cpu_alert,
            "mem_alert": mem_alert,
            "alert": cpu_alert or mem_alert,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("CPU/memory check failed: %s", exc)
        return {
            "cpu_utilization": None,
            "memory_util": None,
            "memory_total_kb": None,
            "memory_used_kb": None,
            "uptime_seconds": None,
            "eos_version": None,
            "model": None,
            "serial_number": None,
            "cpu_threshold": cpu_threshold,
            "mem_threshold": mem_threshold,
            "cpu_alert": False,
            "mem_alert": False,
            "alert": False,
            "error": str(exc),
        }


def check_eos_interfaces(conn: DeviceConnection) -> dict:
    """Return interface error-counter check result.

    Queries ``show interfaces`` (JSON) and returns:

    * ``interfaces``   – list of per-interface dicts
    * ``total``        – total interfaces parsed
    * ``with_errors``  – count of interfaces with at least one error counter > 0
    * ``alert``        – ``True`` when any interface has errors
    * ``error``        – error message on failure, else ``None``
    """
    try:
        data = _send_json(conn, "show interfaces")
        interfaces = parse_interfaces_eos(data)
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


def check_eos_transceivers(conn: DeviceConnection) -> dict:
    """Return transceiver DOM check result.

    Queries ``show interfaces transceiver`` (JSON) and returns:

    * ``transceivers`` – list of transceiver DOM dicts
    * ``total``        – total transceivers parsed
    * ``with_alerts``  – count of transceivers with DOM alerts
    * ``alert``        – ``True`` when any transceiver has a DOM alert
    * ``error``        – error message on failure, else ``None``
    """
    try:
        data = _send_json(conn, "show interfaces transceiver")
        transceivers = parse_transceivers_eos(data)
        alerted = [t for t in transceivers if t.get("alert")]
        return {
            "transceivers": transceivers,
            "total": len(transceivers),
            "with_alerts": len(alerted),
            "alert": len(alerted) > 0,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Transceiver check failed: %s", exc)
        return {
            "transceivers": [],
            "total": 0,
            "with_alerts": 0,
            "alert": False,
            "error": str(exc),
        }


def check_eos_bgp(conn: DeviceConnection) -> dict:
    """Return BGP session state check result.

    Queries ``show bgp summary`` (JSON) and returns:

    * ``peers``             – list of BGP peer dicts
    * ``total``             – total peers parsed
    * ``established``       – count of peers in Established state
    * ``not_established``   – count of peers not Established
    * ``alert``             – ``True`` when any peer is not Established
    * ``error``             – error message on failure, else ``None``
    """
    try:
        data = _send_json(conn, "show bgp summary")
        peers = parse_bgp_summary_eos(data)
        if not peers:
            # Try CLI text fallback
            raw = conn.send("show bgp summary")
            if isinstance(raw, str):
                peers = parse_bgp_summary_eos_text(raw)

        established = sum(1 for p in peers if p.get("is_established"))
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


def check_eos_bgp_evpn(conn: DeviceConnection) -> dict:
    """Return BGP EVPN session state check result.

    Queries ``show bgp evpn summary`` (JSON).  Returns the same structure as
    :func:`check_eos_bgp`.
    """
    try:
        data = _send_json(conn, "show bgp evpn summary")
        peers = parse_bgp_evpn_eos(data)
        established = sum(1 for p in peers if p.get("is_established"))
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
        logger.warning("BGP EVPN check failed: %s", exc)
        return {
            "peers": [],
            "total": 0,
            "established": 0,
            "not_established": 0,
            "alert": False,
            "error": str(exc),
        }


def check_eos_ospf(conn: DeviceConnection) -> dict:
    """Return OSPF neighbour state check result.

    Queries ``show ip ospf neighbor`` (JSON) and returns:

    * ``neighbors``   – list of OSPF neighbour dicts
    * ``total``       – total neighbours parsed
    * ``full``        – count of adjacencies in Full state
    * ``not_full``    – count of adjacencies not in Full state
    * ``alert``       – ``True`` when any adjacency is not Full
    * ``error``       – error message on failure, else ``None``
    """
    try:
        data = _send_json(conn, "show ip ospf neighbor")
        neighbors = parse_ospf_neighbors_eos(data)
        if not neighbors:
            raw = conn.send("show ip ospf neighbor")
            if isinstance(raw, str):
                neighbors = parse_ospf_neighbors_eos_text(raw)

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


def check_eos_mlag(conn: DeviceConnection) -> dict:
    """Return MLAG health check result.

    Queries ``show mlag`` and ``show mlag config-sanity`` (JSON) and returns:

    * ``mlag``                – parsed mlag status dict
    * ``config_sanity``       – parsed mlag config-sanity dict
    * ``is_active``           – ``True`` when MLAG state is active
    * ``peer_link_ok``        – ``True`` when peer-link is up
    * ``peer_active``         – ``True`` when peer is active
    * ``config_consistent``   – ``True`` when config-sanity reports consistent
    * ``alert``               – ``True`` when MLAG is active but has issues
    * ``error``               – error message on failure, else ``None``
    """
    try:
        mlag_data = _send_json(conn, "show mlag")
        mlag = parse_mlag_eos(mlag_data)

        # Fallback to CLI text if JSON parse returned empty state
        if not mlag.get("state"):
            raw = conn.send("show mlag")
            if isinstance(raw, str):
                mlag = parse_mlag_eos_text(raw)

        sanity_data = _send_json(conn, "show mlag config-sanity")
        sanity = parse_mlag_config_sanity_eos(sanity_data)

        is_active = mlag.get("is_active", False)
        peer_link_ok = mlag.get("peer_link_ok", False)
        peer_active = mlag.get("is_peer_active", False)
        consistent = sanity.get("consistent", True)

        # Alert when MLAG is configured/active but has issues
        alert = is_active and (not peer_link_ok or not peer_active or not consistent)

        return {
            "mlag": mlag,
            "config_sanity": sanity,
            "is_active": is_active,
            "peer_link_ok": peer_link_ok,
            "peer_active": peer_active,
            "config_consistent": consistent,
            "alert": alert,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("MLAG check failed: %s", exc)
        return {
            "mlag": {},
            "config_sanity": {},
            "is_active": False,
            "peer_link_ok": False,
            "peer_active": False,
            "config_consistent": True,
            "alert": False,
            "error": str(exc),
        }


def check_eos_environment(conn: DeviceConnection) -> dict:
    """Return environment (temperature, fans, PSUs) check result.

    Queries ``show environment all`` (JSON) and returns:

    * ``power_supplies`` – list of PSU status dicts
    * ``fans``           – list of fan status dicts
    * ``temperatures``   – list of temperature sensor dicts
    * ``overall_ok``     – ``True`` when every component reports OK
    * ``alert``          – ``True`` when ``overall_ok`` is ``False``
    * ``error``          – error message on failure, else ``None``
    """
    try:
        data = _send_json(conn, "show environment all")
        env = parse_environment_eos(data)
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


# ---------------------------------------------------------------------------
# Composite health check
# ---------------------------------------------------------------------------


def run_health_check(
    params: ConnectionParams,
    cpu_threshold: float = DEFAULT_CPU_THRESHOLD,
    mem_threshold: float = DEFAULT_MEM_THRESHOLD,
    check_bgp: bool = True,
    check_evpn: bool = False,
    check_ospf: bool = True,
    check_mlag: bool = True,
    check_transceivers: bool = False,
) -> dict:
    """Run all EOS health checks against a single device.

    Runs:

    * **cpu_memory** – CPU and memory utilisation
    * **interfaces** – interface error counters
    * **transceivers** – DOM alerts (when *check_transceivers* is ``True``)
    * **bgp** – BGP session states (when *check_bgp* is ``True``)
    * **bgp_evpn** – EVPN BGP sessions (when *check_evpn* is ``True``)
    * **ospf** – OSPF adjacency states (when *check_ospf* is ``True``)
    * **mlag** – MLAG health and config-sanity (when *check_mlag* is ``True``)
    * **environment** – PSUs, fans and temperatures

    Returns
    -------
    dict
        Result dict with keys:

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
            result["checks"]["cpu_memory"] = check_eos_cpu_memory(
                conn, cpu_threshold, mem_threshold
            )
            result["checks"]["interfaces"] = check_eos_interfaces(conn)
            if check_transceivers:
                result["checks"]["transceivers"] = check_eos_transceivers(conn)
            if check_bgp:
                result["checks"]["bgp"] = check_eos_bgp(conn)
            if check_evpn:
                result["checks"]["bgp_evpn"] = check_eos_bgp_evpn(conn)
            if check_ospf:
                result["checks"]["ospf"] = check_eos_ospf(conn)
            if check_mlag:
                result["checks"]["mlag"] = check_eos_mlag(conn)
            result["checks"]["environment"] = check_eos_environment(conn)
            result["success"] = True
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        return result

    result["overall_alert"] = any(result["checks"][k].get("alert", False) for k in result["checks"])
    return result


def build_eos_health_report(results: list[dict]) -> dict:
    """Build an aggregated health report from a list of per-device results.

    Parameters
    ----------
    results:
        List of dicts returned by :func:`run_health_check`.

    Returns
    -------
    dict
        Summary dict with keys:

        * ``devices``                – total devices polled
        * ``devices_reachable``      – devices successfully reached
        * ``devices_with_alerts``    – count of devices with at least one alert
        * ``cpu_memory_alerts``      – count of devices with CPU/memory alerts
        * ``interface_alerts``       – count of devices with interface error alerts
        * ``bgp_alerts``             – count of devices with BGP peer alerts
        * ``ospf_alerts``            – count of devices with OSPF adjacency alerts
        * ``mlag_alerts``            – count of devices with MLAG health alerts
        * ``environment_alerts``     – count of devices with environment alerts
        * ``overall_alert``          – ``True`` when any device triggered an alert
        * ``results``                – original per-device result list

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
        "cpu_memory_alerts": _count_alert("cpu_memory"),
        "interface_alerts": _count_alert("interfaces"),
        "bgp_alerts": _count_alert("bgp"),
        "ospf_alerts": _count_alert("ospf"),
        "mlag_alerts": _count_alert("mlag"),
        "environment_alerts": _count_alert("environment"),
        "overall_alert": devices_with_alerts > 0,
        "results": results,
    }


# ---------------------------------------------------------------------------
# CLI
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
    """Pretty-print a single device health result."""
    icon = "🚨" if result.get("overall_alert") else ("✅" if result.get("success") else "❌")
    print(f"{icon} {result['host']} [{result['timestamp']}]")

    if not result.get("success"):
        print(f"   ERROR: {result.get('error')}")
        return

    checks = result.get("checks", {})

    # CPU / memory
    cm = checks.get("cpu_memory", {})
    cpu = cm.get("cpu_utilization")
    mem = cm.get("memory_util")
    cm_alert = " ⚠️  ALERT" if cm.get("alert") else ""
    if cpu is not None:
        print(f"   CPU  : {cpu:.1f}% (threshold {cm.get('cpu_threshold')}%){cm_alert}")
    if mem is not None:
        print(f"   MEM  : {mem:.1f}% (threshold {cm.get('mem_threshold')}%){cm_alert}")
    eos_ver = cm.get("eos_version") or cm.get("version")
    if eos_ver:
        model = cm.get("model") or ""
        print(f"   EOS  : {eos_ver}  {model}")

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
        print(f"   BGP  : {bgp.get('established', 0)}/{bgp.get('total', 0)} established{bgp_alert}")

    # EVPN BGP
    evpn = checks.get("bgp_evpn")
    if evpn is not None:
        evpn_alert = " ⚠️  ALERT" if evpn.get("alert") else ""
        print(
            f"   EVPN BGP : {evpn.get('established', 0)}/{evpn.get('total', 0)}"
            f" established{evpn_alert}"
        )

    # OSPF
    ospf = checks.get("ospf")
    if ospf is not None:
        ospf_alert = " ⚠️  ALERT" if ospf.get("alert") else ""
        print(
            f"   OSPF : {ospf.get('full', 0)}/{ospf.get('total', 0)} full adjacencies{ospf_alert}"
        )

    # MLAG
    mlag = checks.get("mlag")
    if mlag is not None:
        mlag_alert = " ⚠️  ALERT" if mlag.get("alert") else ""
        mlag_state = mlag.get("mlag", {}).get("state", "N/A")
        print(f"   MLAG : {mlag_state}{mlag_alert}")
        if not mlag.get("config_consistent"):
            print("   MLAG CONFIG SANITY : ⚠️  inconsistencies detected")

    # Environment
    env = checks.get("environment", {})
    env_alert = " ⚠️  ALERT" if env.get("alert") else ""
    psu_ok = sum(1 for p in env.get("power_supplies", []) if p.get("ok"))
    psu_total = len(env.get("power_supplies", []))
    fan_ok = sum(1 for f in env.get("fans", []) if f.get("ok"))
    fan_total = len(env.get("fans", []))
    temp_alert = sum(1 for t in env.get("temperatures", []) if not t.get("ok"))
    print(
        f"   ENV  : PSU {psu_ok}/{psu_total} OK,"
        f" Fans {fan_ok}/{fan_total} OK,"
        f" Temp alerts {temp_alert}{env_alert}"
    )


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for the Arista EOS health check CLI."""
    parser = argparse.ArgumentParser(
        description="Arista EOS health checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--host", metavar="IP", help="Single device IP or hostname")
    src.add_argument("--inventory", metavar="FILE", help="YAML inventory file")
    parser.add_argument("--user", default=os.environ.get("NETOPS_USER", "admin"))
    parser.add_argument("--password", default=os.environ.get("NETOPS_PASSWORD", ""))
    parser.add_argument("--group", metavar="GROUP", default=None)
    parser.add_argument(
        "--threshold",
        metavar="KEY=VAL[,KEY=VAL]",
        default=None,
        help="Alert thresholds, e.g. cpu=80,mem=85",
    )
    parser.add_argument("--no-bgp", action="store_true", help="Skip BGP checks")
    parser.add_argument("--evpn", action="store_true", help="Include EVPN BGP checks")
    parser.add_argument("--no-ospf", action="store_true", help="Skip OSPF checks")
    parser.add_argument("--no-mlag", action="store_true", help="Skip MLAG checks")
    parser.add_argument(
        "--transceivers", action="store_true", help="Include transceiver DOM checks"
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument(
        "--fail-on-alert",
        action="store_true",
        help="Exit with status 1 when any alert is raised",
    )
    parser.add_argument(
        "--transport",
        choices=["ssh", "telnet"],
        default="ssh",
        help="Connection transport (default: ssh)",
    )
    parser.add_argument("--port", type=int, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for Arista EOS health checks."""
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    thresholds = _parse_thresholds(args.threshold)
    cpu_threshold = thresholds.get("cpu", DEFAULT_CPU_THRESHOLD)
    mem_threshold = thresholds.get("mem", DEFAULT_MEM_THRESHOLD)

    transport = Transport.TELNET if args.transport == "telnet" else Transport.SSH

    if args.host:
        params = ConnectionParams(
            host=args.host,
            username=args.user,
            password=args.password,
            device_type="arista_eos",
            transport=transport,
            port=args.port,
        )
        results = [
            run_health_check(
                params,
                cpu_threshold=cpu_threshold,
                mem_threshold=mem_threshold,
                check_bgp=not args.no_bgp,
                check_evpn=args.evpn,
                check_ospf=not args.no_ospf,
                check_mlag=not args.no_mlag,
                check_transceivers=args.transceivers,
            )
        ]
    else:
        inv = Inventory.from_file(args.inventory)
        devices = inv.filter(group=args.group) if args.group else list(inv.devices.values())
        results = []
        for dev in devices:
            p = ConnectionParams(
                host=dev.host,
                username=args.user or dev.username,
                password=args.password or dev.password,
                device_type=dev.vendor or "arista_eos",
                transport=transport,
                port=dev.port or args.port,
            )
            results.append(
                run_health_check(
                    p,
                    cpu_threshold=cpu_threshold,
                    mem_threshold=mem_threshold,
                    check_bgp=not args.no_bgp,
                    check_evpn=args.evpn,
                    check_ospf=not args.no_ospf,
                    check_mlag=not args.no_mlag,
                    check_transceivers=args.transceivers,
                )
            )

    report = build_eos_health_report(results)

    if args.json_output:
        print(json.dumps(report, indent=2, default=str))
    else:
        for result in results:
            _print_result(result)
        print(
            f"\nSummary: {report['devices_reachable']}/{report['devices']} reachable,"
            f" {report['devices_with_alerts']} with alerts"
        )

    if args.fail_on_alert and report.get("overall_alert"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
