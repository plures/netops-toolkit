"""
BGP session monitor — peer status, prefix counts, flap detection.

Checks BGP sessions across one or many routers and reports:

* Peer up/down status
* Prefix count vs expected (alert on configurable deviation %)
* Flap detection — sessions established for fewer than *flap_min_uptime*
  seconds are flagged as potentially flapping
* Summary report aggregated across all polled routers

Supports Cisco IOS/IOS-XE/IOS-XR and Nokia SR-OS.

Usage::

    python -m netops.check.bgp --inventory inventory.yaml \\
        --expected-prefixes 10.0.0.2=100,10.0.0.3=200 \\
        --flap-min-uptime 300 --prefix-deviation 20

    python -m netops.check.bgp --host 10.0.0.1 --vendor cisco_ios --json
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
from netops.parsers.bgp import parse_bgp_summary_cisco, updown_to_seconds
from netops.parsers.nokia_sros import parse_bgp_summary as parse_bgp_summary_nokia

logger = logging.getLogger(__name__)

# Default thresholds
DEFAULT_FLAP_MIN_UPTIME = 300  # seconds — sessions up < 5 min are flagged
DEFAULT_PREFIX_DEVIATION_PCT = 20.0  # percent


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_nokia(device_type: str) -> bool:
    return "nokia" in device_type.lower()


def _normalize_peer(raw: dict) -> dict:
    """Return a copy of *raw* with the unified ``prefixes_received`` key.

    Nokia SR-OS parsers use ``received`` instead of ``prefixes_received``.
    This function maps ``received`` → ``prefixes_received`` so that the rest
    of the check logic works uniformly across vendors.
    """
    peer = dict(raw)
    if "prefixes_received" not in peer:
        peer["prefixes_received"] = peer.get("received")
    return peer


def _evaluate_peer(
    peer: dict,
    expected_prefixes: dict[str, int],
    flap_min_uptime: int,
    prefix_deviation_pct: float,
) -> dict:
    """Enrich a normalised peer dict with check results.

    Adds the following keys:

    * ``is_established``  – ``True`` when the session state is *Established*
    * ``uptime_seconds``  – parsed uptime in seconds, or ``None``
    * ``is_flapping``     – ``True`` when the session is Established but its
                            uptime is shorter than *flap_min_uptime* seconds
    * ``expected_prefixes`` – the expected prefix count (``int``) or ``None``
    * ``prefix_alert``    – ``True`` when received prefixes deviate from the
                            expected count by more than *prefix_deviation_pct*
    * ``alerts``          – human-readable list of alert messages for this peer
    """
    result = dict(peer)
    neighbor = peer["neighbor"]
    state = peer.get("state", "")
    up_down = peer.get("up_down", "")
    prefixes_received = peer.get("prefixes_received")

    is_established = state == "Established"
    uptime_seconds = updown_to_seconds(up_down) if is_established else None

    # Flap detection: established but suspiciously short uptime
    is_flapping = (
        is_established and uptime_seconds is not None and uptime_seconds < flap_min_uptime
    )

    # Prefix deviation check
    expected = expected_prefixes.get(neighbor)
    prefix_alert = False
    if is_established and expected is not None and prefixes_received is not None:
        if expected > 0:
            deviation = abs(prefixes_received - expected) / expected * 100
            prefix_alert = deviation > prefix_deviation_pct
        else:
            prefix_alert = prefixes_received != 0

    alerts: list[str] = []
    if not is_established:
        alerts.append(f"peer {neighbor} not established (state={state})")
    if is_flapping:
        alerts.append(
            f"peer {neighbor} may be flapping (uptime={up_down}, "
            f"threshold={flap_min_uptime}s)"
        )
    if prefix_alert:
        alerts.append(
            f"peer {neighbor} prefix count {prefixes_received} "
            f"deviates from expected {expected} "
            f"by >{prefix_deviation_pct:.0f}%"
        )

    result.update(
        {
            "is_established": is_established,
            "uptime_seconds": uptime_seconds,
            "is_flapping": is_flapping,
            "expected_prefixes": expected,
            "prefix_alert": prefix_alert,
            "alerts": alerts,
        }
    )
    return result


# ---------------------------------------------------------------------------
# Public check API
# ---------------------------------------------------------------------------


def check_bgp_peers(
    params: ConnectionParams,
    expected_prefixes: Optional[dict[str, int]] = None,
    flap_min_uptime: int = DEFAULT_FLAP_MIN_UPTIME,
    prefix_deviation_pct: float = DEFAULT_PREFIX_DEVIATION_PCT,
) -> dict:
    """Check BGP peer status on a single device.

    Parameters
    ----------
    params:
        Device connection parameters.
    expected_prefixes:
        Optional dict mapping *neighbor IP* → *expected prefix count*.
        An alert fires when the actual received-prefix count deviates from
        the expected value by more than *prefix_deviation_pct* percent.
    flap_min_uptime:
        Sessions established for fewer than this many seconds are flagged
        as potentially flapping (default: 300 s = 5 min).
    prefix_deviation_pct:
        Percentage threshold for prefix-count deviation alerts
        (default: 20%).

    Returns a result dict with keys:

    * ``host``          – device IP/hostname
    * ``timestamp``     – ISO-8601 UTC timestamp
    * ``success``       – ``True`` when the device was reached
    * ``peers``         – list of per-peer check dicts
    * ``summary``       – aggregate counts across all peers on this device
    * ``overall_alert`` – ``True`` when any alert fired
    * ``error``         – error message when connection failed
    """
    if expected_prefixes is None:
        expected_prefixes = {}

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result: dict = {
        "host": params.host,
        "timestamp": timestamp,
        "success": False,
        "peers": [],
        "summary": {},
        "overall_alert": False,
        "error": None,
    }

    try:
        with DeviceConnection(params) as conn:
            if _is_nokia(params.device_type):
                output = conn.send("show router bgp summary")
                raw_peers = parse_bgp_summary_nokia(output)
            else:
                if params.device_type == "cisco_xr":
                    output = conn.send("show bgp summary")
                else:
                    output = conn.send("show ip bgp summary")
                raw_peers = parse_bgp_summary_cisco(output)
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        return result

    peers = [
        _evaluate_peer(_normalize_peer(p), expected_prefixes, flap_min_uptime, prefix_deviation_pct)
        for p in raw_peers
    ]

    total = len(peers)
    established = sum(1 for p in peers if p["is_established"])
    not_established = total - established
    flapping = sum(1 for p in peers if p["is_flapping"])
    prefix_alerts = sum(1 for p in peers if p["prefix_alert"])

    result.update(
        {
            "success": True,
            "peers": peers,
            "summary": {
                "total": total,
                "established": established,
                "not_established": not_established,
                "flapping": flapping,
                "prefix_alerts": prefix_alerts,
            },
            "overall_alert": (not_established + flapping + prefix_alerts) > 0,
        }
    )
    return result


def build_bgp_report(results: list[dict]) -> dict:
    """Build an aggregated BGP report from a list of per-device results.

    Parameters
    ----------
    results:
        List of dicts returned by :func:`check_bgp_peers`.

    Returns a summary dict with keys:

    * ``routers``             – total routers polled
    * ``routers_reachable``   – routers successfully reached
    * ``total_peers``         – total BGP peers across all routers
    * ``established``         – peers in Established state
    * ``not_established``     – peers not in Established state
    * ``flapping``            – peers flagged as potentially flapping
    * ``prefix_alerts``       – peers with prefix-count deviations
    * ``overall_alert``       – ``True`` when any alert fired
    * ``peers``               – flat list of all peer dicts with ``router`` key
    """
    all_peers: list[dict] = []
    for r in results:
        if r.get("success"):
            for peer in r.get("peers", []):
                all_peers.append({**peer, "router": r["host"]})

    established = sum(1 for p in all_peers if p["is_established"])
    not_established = sum(1 for p in all_peers if not p["is_established"])
    flapping = sum(1 for p in all_peers if p["is_flapping"])
    prefix_alerts = sum(1 for p in all_peers if p["prefix_alert"])

    return {
        "routers": len(results),
        "routers_reachable": sum(1 for r in results if r.get("success")),
        "total_peers": len(all_peers),
        "established": established,
        "not_established": not_established,
        "flapping": flapping,
        "prefix_alerts": prefix_alerts,
        "overall_alert": (not_established + flapping + prefix_alerts) > 0,
        "peers": all_peers,
    }


# ---------------------------------------------------------------------------
# CLI output helpers
# ---------------------------------------------------------------------------


def _print_device_result(result: dict) -> None:
    """Pretty-print a single device BGP check result."""
    icon = "🚨" if result.get("overall_alert") else ("✅" if result.get("success") else "❌")
    print(f"{icon} {result['host']} [{result.get('timestamp', '')}]")

    if not result.get("success"):
        print(f"   ERROR: {result.get('error')}")
        return

    s = result["summary"]
    print(
        f"   Peers: {s['established']}/{s['total']} established"
        f"  |  flapping: {s['flapping']}"
        f"  |  prefix alerts: {s['prefix_alerts']}"
    )

    for peer in result.get("peers", []):
        if peer["is_established"] and not peer["is_flapping"] and not peer["prefix_alert"]:
            icon_p = "✅"
        else:
            icon_p = "⚠️ " if peer["is_established"] else "❌"

        pfx = (
            f"  pfx={peer['prefixes_received']}"
            if peer.get("prefixes_received") is not None
            else ""
        )
        exp = (
            f"/{peer['expected_prefixes']}"
            if peer.get("expected_prefixes") is not None
            else ""
        )
        uptime = f"  up={peer.get('up_down', 'N/A')}" if peer["is_established"] else ""
        state = peer.get("state", "?")
        neighbor = peer["neighbor"]
        print(f"   {icon_p} {neighbor} AS{peer['peer_as']} — {state}{pfx}{exp}{uptime}")

        for alert in peer.get("alerts", []):
            print(f"        ⚠  {alert}")


def _print_summary_report(report: dict) -> None:
    """Pretty-print the aggregated multi-router BGP report."""
    icon = "🚨" if report.get("overall_alert") else "✅"
    print(
        f"\n{icon} BGP Summary — {report['routers_reachable']}/{report['routers']} routers reachable"
        f"  |  {report['established']}/{report['total_peers']} peers established"
        f"  |  flapping: {report['flapping']}"
        f"  |  prefix alerts: {report['prefix_alerts']}"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_expected_prefixes(raw: Optional[str]) -> dict[str, int]:
    """Parse ``10.0.0.2=100,10.0.0.3=200`` into ``{'10.0.0.2': 100, ...}``."""
    result: dict[str, int] = {}
    if not raw:
        return result
    for part in raw.split(","):
        part = part.strip()
        if "=" not in part:
            continue
        ip, _, val = part.partition("=")
        try:
            result[ip.strip()] = int(val.strip())
        except ValueError:
            pass
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor BGP sessions: peer status, prefix counts, flap detection"
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--inventory", "-i", metavar="FILE", help="YAML/JSON inventory file")
    target.add_argument("--host", metavar="IP", help="Single device IP/hostname")

    parser.add_argument("--group", "-g", metavar="GROUP", help="Filter inventory by group")
    parser.add_argument("--vendor", default="cisco_ios", help="Device vendor (single-host mode)")
    parser.add_argument("--user", "-u", metavar="USER", help="SSH username")
    parser.add_argument("--password", "-p", metavar="PASS", help="SSH password")
    parser.add_argument(
        "--expected-prefixes",
        metavar="IP=N[,...]",
        help="Expected prefix counts, e.g. 10.0.0.2=100,10.0.0.3=200",
    )
    parser.add_argument(
        "--flap-min-uptime",
        type=int,
        default=DEFAULT_FLAP_MIN_UPTIME,
        metavar="SECS",
        help=f"Flap threshold: sessions up < N seconds are flagged (default: {DEFAULT_FLAP_MIN_UPTIME})",
    )
    parser.add_argument(
        "--prefix-deviation",
        type=float,
        default=DEFAULT_PREFIX_DEVIATION_PCT,
        metavar="PCT",
        help=f"Prefix deviation %% alert threshold (default: {DEFAULT_PREFIX_DEVIATION_PCT})",
    )
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--fail-on-alert", action="store_true", help="Exit 1 if any alert fires")
    args = parser.parse_args()

    expected_prefixes = _parse_expected_prefixes(args.expected_prefixes)
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
        check_bgp_peers(
            p,
            expected_prefixes=expected_prefixes,
            flap_min_uptime=args.flap_min_uptime,
            prefix_deviation_pct=args.prefix_deviation,
        )
        for p in device_params
    ]

    report = build_bgp_report(results)

    if args.json:
        output = {"devices": results, "report": report}
        json.dump(output, sys.stdout, indent=2)
        print()
    else:
        for r in results:
            _print_device_result(r)
        if len(results) > 1:
            _print_summary_report(report)

    if args.fail_on_alert and report.get("overall_alert"):
        sys.exit(1)


if __name__ == "__main__":
    main()
