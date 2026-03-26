r"""VLAN audit — compare declared vs actual VLAN configuration across switches.

Checks VLAN configuration on a switch fabric and reports:

* Missing VLANs   — declared VLANs not present on a switch
* Extra VLANs     — VLANs present on a switch but not in the declared database
* Name mismatches — VLANs present but with a different name than declared
* Trunk mismatches — declared VLANs not active on trunk interfaces
* Per-switch compliance status

Supports Cisco IOS/IOS-XE.

Usage::

    python -m netops.check.vlan --inventory inventory.yaml \\
        --expected-vlans 10,20,30-50,100 \\
        --check-trunks

    python -m netops.check.vlan --host 10.0.0.1 --vendor cisco_ios \\
        --vlan-db vlans.yaml --json

VLAN database file (``vlans.yaml``) format::

    vlans:
      10: MANAGEMENT
      20: SERVERS
      100: DMZ
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone

import yaml

from netops.core import DeviceConnection
from netops.core.connection import ConnectionParams, Transport
from netops.core.inventory import Inventory
from netops.parsers.vlan import expand_vlan_range, parse_interfaces_trunk, parse_vlan_brief

logger = logging.getLogger(__name__)

# Cisco system VLANs — always excluded from the extra-VLANs check
_SYSTEM_VLANS: frozenset[int] = frozenset({1002, 1003, 1004, 1005})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _find_missing_vlans(actual_ids: set[int], expected_ids: set[int]) -> list[int]:
    """Return sorted list of VLAN IDs in *expected* but absent from *actual*."""
    return sorted(expected_ids - actual_ids)


def _find_extra_vlans(
    actual_ids: set[int],
    expected_ids: set[int],
    ignore_ids: set[int] | None = None,
) -> list[int]:
    """Return sorted list of VLAN IDs in *actual* but absent from *expected*.

    System VLANs (1002-1005) and any IDs in *ignore_ids* are always excluded.
    """
    excluded = _SYSTEM_VLANS | (ignore_ids or set())
    return sorted(actual_ids - expected_ids - excluded)


def _check_name_mismatches(
    actual_vlans: list[dict],
    expected_names: dict[int, str],
) -> list[dict]:
    """Compare VLAN names against declared names.

    Returns list of ``{vlan_id, expected_name, actual_name}`` dicts for each
    VLAN whose actual name differs from the declared name.
    """
    mismatches: list[dict] = []
    actual_by_id = {v["vlan_id"]: v for v in actual_vlans}
    for vlan_id, expected_name in sorted(expected_names.items()):
        actual = actual_by_id.get(vlan_id)
        if actual and actual["name"] != expected_name:
            mismatches.append(
                {
                    "vlan_id": vlan_id,
                    "expected_name": expected_name,
                    "actual_name": actual["name"],
                }
            )
    return mismatches


def _check_trunk_vlans(trunks: list[dict], expected_ids: set[int]) -> list[dict]:
    """Check that every expected VLAN is active on each trunking interface.

    Only ports whose ``status`` is ``'trunking'`` are evaluated.

    Returns list of ``{port, missing_vlans}`` for trunks that are missing one
    or more expected VLANs from their active VLAN set.
    """
    mismatches: list[dict] = []
    for trunk in trunks:
        if trunk.get("status") != "trunking":
            continue
        missing = sorted(expected_ids - trunk["active_vlans"])
        if missing:
            mismatches.append({"port": trunk["port"], "missing_vlans": missing})
    return mismatches


# ---------------------------------------------------------------------------
# Public check API
# ---------------------------------------------------------------------------


def audit_vlans(
    params: ConnectionParams,
    expected_vlans: set[int],
    expected_names: dict[int, str] | None = None,
    check_trunks: bool = False,
    ignore_vlans: set[int] | None = None,
) -> dict:
    """Audit VLAN configuration on a single switch.

    Parameters
    ----------
    params:
        Device connection parameters.
    expected_vlans:
        Set of VLAN IDs that should be present on the switch.
    expected_names:
        Optional mapping of VLAN ID → declared VLAN name.  When provided,
        name mismatches are included in the result.
    check_trunks:
        When ``True``, also issue ``show interfaces trunk`` and flag any
        expected VLAN that is not active on a trunking interface.
    ignore_vlans:
        Additional VLAN IDs to exclude from the *extra VLANs* check
        (system VLANs 1002–1005 are always excluded regardless).

    Returns a result dict with keys:

    * ``host``             – device IP/hostname
    * ``timestamp``        – ISO-8601 UTC timestamp
    * ``success``          – ``True`` when the device was reached
    * ``actual_vlans``     – list of per-VLAN dicts from :func:`~netops.parsers.vlan.parse_vlan_brief`
    * ``trunks``           – list of trunk-port dicts (empty when *check_trunks* is ``False``)
    * ``missing_vlans``    – VLAN IDs in *expected_vlans* but absent from the switch
    * ``extra_vlans``      – VLAN IDs on switch but not in *expected_vlans*
    * ``name_mismatches``  – list of ``{vlan_id, expected_name, actual_name}``
    * ``trunk_mismatches`` – list of ``{port, missing_vlans}`` (empty when *check_trunks* is ``False``)
    * ``compliant``        – ``True`` when no discrepancies were found
    * ``alerts``           – human-readable list of alert messages
    * ``error``            – error message when the connection failed

    """
    if expected_names is None:
        expected_names = {}
    if ignore_vlans is None:
        ignore_vlans = set()

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result: dict = {
        "host": params.host,
        "timestamp": timestamp,
        "success": False,
        "actual_vlans": [],
        "trunks": [],
        "missing_vlans": [],
        "extra_vlans": [],
        "name_mismatches": [],
        "trunk_mismatches": [],
        "compliant": False,
        "alerts": [],
        "error": None,
    }

    try:
        with DeviceConnection(params) as conn:
            vlan_output = conn.send("show vlan brief")
            trunk_output = conn.send("show interfaces trunk") if check_trunks else ""
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        return result

    actual_vlans = parse_vlan_brief(vlan_output)
    trunks = parse_interfaces_trunk(trunk_output) if check_trunks else []

    actual_ids = {v["vlan_id"] for v in actual_vlans}
    missing_vlans = _find_missing_vlans(actual_ids, expected_vlans)
    extra_vlans = _find_extra_vlans(actual_ids, expected_vlans, ignore_vlans)
    name_mismatches = _check_name_mismatches(actual_vlans, expected_names)
    trunk_mismatches = _check_trunk_vlans(trunks, expected_vlans) if check_trunks else []

    alerts: list[str] = []
    if missing_vlans:
        alerts.append(f"missing VLANs: {', '.join(str(v) for v in missing_vlans)}")
    if extra_vlans:
        alerts.append(f"extra VLANs: {', '.join(str(v) for v in extra_vlans)}")
    for nm in name_mismatches:
        alerts.append(
            f"VLAN {nm['vlan_id']} name mismatch: "
            f"expected '{nm['expected_name']}', got '{nm['actual_name']}'"
        )
    for tm in trunk_mismatches:
        alerts.append(
            f"trunk {tm['port']} missing VLANs: "
            f"{', '.join(str(v) for v in tm['missing_vlans'])}"
        )

    result.update(
        {
            "success": True,
            "actual_vlans": actual_vlans,
            "trunks": trunks,
            "missing_vlans": missing_vlans,
            "extra_vlans": extra_vlans,
            "name_mismatches": name_mismatches,
            "trunk_mismatches": trunk_mismatches,
            "compliant": not alerts,
            "alerts": alerts,
        }
    )
    return result


def build_vlan_report(results: list[dict]) -> dict:
    """Build an aggregated VLAN audit report from per-switch results.

    Parameters
    ----------
    results:
        List of dicts returned by :func:`audit_vlans`.

    Returns a summary dict with keys:

    * ``switches``                – total switches polled
    * ``switches_reachable``      – switches successfully reached
    * ``switches_compliant``      – fully compliant switches
    * ``overall_alert``           – ``True`` when any switch is non-compliant
    * ``missing_vlan_switches``   – list of ``{host, missing_vlans}``
    * ``extra_vlan_switches``     – list of ``{host, extra_vlans}``
    * ``name_mismatch_switches``  – list of ``{host, name_mismatches}``
    * ``trunk_mismatch_switches`` – list of ``{host, trunk_mismatches}``

    """
    reachable = [r for r in results if r.get("success")]
    compliant = [r for r in reachable if r.get("compliant")]

    missing_vlan_switches = [
        {"host": r["host"], "missing_vlans": r["missing_vlans"]}
        for r in reachable
        if r["missing_vlans"]
    ]
    extra_vlan_switches = [
        {"host": r["host"], "extra_vlans": r["extra_vlans"]}
        for r in reachable
        if r["extra_vlans"]
    ]
    name_mismatch_switches = [
        {"host": r["host"], "name_mismatches": r["name_mismatches"]}
        for r in reachable
        if r["name_mismatches"]
    ]
    trunk_mismatch_switches = [
        {"host": r["host"], "trunk_mismatches": r["trunk_mismatches"]}
        for r in reachable
        if r["trunk_mismatches"]
    ]

    overall_alert = bool(
        missing_vlan_switches
        or extra_vlan_switches
        or name_mismatch_switches
        or trunk_mismatch_switches
    )

    return {
        "switches": len(results),
        "switches_reachable": len(reachable),
        "switches_compliant": len(compliant),
        "overall_alert": overall_alert,
        "missing_vlan_switches": missing_vlan_switches,
        "extra_vlan_switches": extra_vlan_switches,
        "name_mismatch_switches": name_mismatch_switches,
        "trunk_mismatch_switches": trunk_mismatch_switches,
    }


# ---------------------------------------------------------------------------
# CLI output helpers
# ---------------------------------------------------------------------------


def _print_device_result(result: dict) -> None:
    """Pretty-print a single switch VLAN audit result."""
    if not result.get("success"):
        print(f"❌ {result['host']} [{result.get('timestamp', '')}]")
        print(f"   ERROR: {result.get('error')}")
        return

    icon = "🚨" if result.get("alerts") else "✅"
    status = "COMPLIANT" if result.get("compliant") else "NON-COMPLIANT"
    actual_count = len(result.get("actual_vlans", []))
    print(f"{icon} {result['host']} [{result.get('timestamp', '')}] — {status}")
    print(f"   VLANs on switch: {actual_count}")

    if result["missing_vlans"]:
        print(f"   ⚠  Missing VLANs : {', '.join(str(v) for v in result['missing_vlans'])}")
    if result["extra_vlans"]:
        print(f"   ⚠  Extra VLANs   : {', '.join(str(v) for v in result['extra_vlans'])}")
    for nm in result.get("name_mismatches", []):
        print(
            f"   ⚠  VLAN {nm['vlan_id']} name: expected '{nm['expected_name']}', "
            f"got '{nm['actual_name']}'"
        )
    for tm in result.get("trunk_mismatches", []):
        print(
            f"   ⚠  Trunk {tm['port']} missing VLANs: "
            f"{', '.join(str(v) for v in tm['missing_vlans'])}"
        )


def _print_summary_report(report: dict) -> None:
    """Pretty-print the aggregated multi-switch VLAN audit report."""
    icon = "🚨" if report.get("overall_alert") else "✅"
    print(
        f"\n{icon} VLAN Audit Summary — "
        f"{report['switches_reachable']}/{report['switches']} switches reachable  |  "
        f"{report['switches_compliant']}/{report['switches_reachable']} compliant"
    )
    if report["missing_vlan_switches"]:
        hosts = ", ".join(s["host"] for s in report["missing_vlan_switches"])
        print(f"   Missing VLANs on : {hosts}")
    if report["extra_vlan_switches"]:
        hosts = ", ".join(s["host"] for s in report["extra_vlan_switches"])
        print(f"   Extra VLANs on   : {hosts}")
    if report["name_mismatch_switches"]:
        hosts = ", ".join(s["host"] for s in report["name_mismatch_switches"])
        print(f"   Name mismatches  : {hosts}")
    if report["trunk_mismatch_switches"]:
        hosts = ", ".join(s["host"] for s in report["trunk_mismatch_switches"])
        print(f"   Trunk mismatches : {hosts}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_vlan_db(path: str) -> tuple[set[int], dict[int, str]]:
    """Load a VLAN database YAML file.

    Expected format::

        vlans:
          10: MANAGEMENT
          20: SERVERS
          100: DMZ

    Returns ``(expected_vlans, expected_names)`` where *expected_vlans* is a
    ``set[int]`` and *expected_names* is a ``dict[int, str]``.
    """
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}

    raw = data.get("vlans") or {}
    expected_names: dict[int, str] = {}
    for k, v in raw.items():
        try:
            vlan_id = int(k)
        except (ValueError, TypeError):
            continue
        expected_names[vlan_id] = str(v) if v else ""

    return set(expected_names.keys()), expected_names


def main() -> None:
    """CLI entry point for the VLAN configuration auditor."""
    parser = argparse.ArgumentParser(
        description="Audit VLAN configurations: compare declared vs actual across switches"
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--inventory", "-i", metavar="FILE", help="YAML/JSON inventory file")
    target.add_argument("--host", metavar="IP", help="Single device IP/hostname")

    parser.add_argument("--group", "-g", metavar="GROUP", help="Filter inventory by group")
    parser.add_argument("--vendor", default="cisco_ios", help="Device vendor (single-host mode)")
    parser.add_argument("--user", "-u", metavar="USER", help="SSH username")
    parser.add_argument("--password", "-p", metavar="PASS", help="SSH password")

    vlan_source = parser.add_mutually_exclusive_group(required=True)
    vlan_source.add_argument(
        "--expected-vlans",
        metavar="RANGE",
        help="Expected VLAN IDs, e.g. 10,20,30-50,100",
    )
    vlan_source.add_argument(
        "--vlan-db",
        metavar="FILE",
        help="YAML file mapping VLAN IDs to names (vlans: {10: MANAGEMENT, ...})",
    )

    parser.add_argument(
        "--ignore-vlans",
        metavar="RANGE",
        help="VLAN IDs to exclude from the extra-VLANs check, e.g. 1,2",
    )
    parser.add_argument(
        "--check-trunks",
        action="store_true",
        help="Also check that expected VLANs are active on trunk interfaces",
    )
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--fail-on-alert", action="store_true", help="Exit 1 if any alert fires")
    args = parser.parse_args()

    password = args.password or os.environ.get("NETOPS_PASSWORD")

    if args.vlan_db:
        expected_vlans, expected_names = _parse_vlan_db(args.vlan_db)
    else:
        expected_vlans = expand_vlan_range(args.expected_vlans or "")
        expected_names = {}

    ignore_vlans = expand_vlan_range(args.ignore_vlans or "")

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
        audit_vlans(
            p,
            expected_vlans=expected_vlans,
            expected_names=expected_names,
            check_trunks=args.check_trunks,
            ignore_vlans=ignore_vlans,
        )
        for p in device_params
    ]

    report = build_vlan_report(results)

    if args.json:
        output = {"devices": results, "report": report}
        json.dump(output, sys.stdout, indent=2, default=list)
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
