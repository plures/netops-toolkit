"""
Security policy audit and health checks for Palo Alto Networks PAN-OS devices.

Policy audit::

    python -m netops.check.paloalto --host 10.0.0.1 --audit

Health checks::

    python -m netops.check.paloalto --inventory inv.yaml --group firewalls \\
        --health --json
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
from netops.parsers.paloalto import (
    parse_ha_state,
    parse_security_policy,
    parse_security_policy_stats,
    parse_session_info,
    parse_system_info,
)

logger = logging.getLogger(__name__)

# Default session-table utilization alert threshold (percent)
DEFAULT_SESSION_THRESHOLD = 80.0


# ---------------------------------------------------------------------------
# Security policy audit helpers
# ---------------------------------------------------------------------------


def check_unused_rules(
    policy: list[dict],
    stats: list[dict],
) -> list[dict]:
    """Identify security rules that have never been matched.

    Correlates ``policy`` (from :func:`~netops.parsers.paloalto.parse_security_policy`)
    with ``stats`` (from
    :func:`~netops.parsers.paloalto.parse_security_policy_stats`) and
    returns those rules whose hit count is zero.

    Each returned dict is the original rule dict augmented with a
    ``hit_count`` key (``int``).

    :param policy: parsed list of security rule dicts
    :param stats:  parsed list of per-rule hit-count dicts
    :returns:      list of unused rule dicts (hit count == 0)
    """
    hit_map: dict[str, int] = {s["name"]: s["hit_count"] for s in stats}
    unused: list[dict] = []
    for rule in policy:
        count = hit_map.get(rule["name"], 0)
        if count == 0:
            unused.append({**rule, "hit_count": 0})
    return unused


def check_shadowed_rules(policy: list[dict]) -> list[dict]:
    """Identify security rules that are shadowed by an earlier, broader rule.

    A rule R[i] is considered *shadowed* when there exists an earlier rule
    R[j] (j < i) such that:

    * R[j]'s source zones cover all of R[i]'s source zones  (or R[j] uses ``any``)
    * R[j]'s destination zones cover all of R[i]'s destination zones (or ``any``)
    * R[j]'s sources cover R[i]'s sources (or ``any``)
    * R[j]'s destinations cover R[i]'s destinations (or ``any``)
    * R[j]'s applications cover R[i]'s applications (or ``any``)

    The action of the shadowing rule is noted but not required to match —
    an ``allow`` above a ``deny`` shadows the ``deny`` just as much as two
    ``deny`` rules would.

    Each returned dict is the original rule dict augmented with:

    * ``shadowed_by`` – name of the first earlier rule that shadows this one

    :param policy: parsed list of security rule dicts (ordered as on device)
    :returns:      list of shadowed rule dicts
    """
    shadowed: list[dict] = []

    def _covers(broader: list[str], narrower: list[str]) -> bool:
        """Return True when *broader* is a superset of (or equal to) *narrower*."""
        if "any" in broader:
            return True
        return all(item in broader for item in narrower)

    for i, rule in enumerate(policy):
        for j in range(i):
            prev = policy[j]
            if (
                _covers(prev["from_zones"], rule["from_zones"])
                and _covers(prev["to_zones"], rule["to_zones"])
                and _covers(prev["sources"], rule["sources"])
                and _covers(prev["destinations"], rule["destinations"])
                and _covers(prev["applications"], rule["applications"])
            ):
                shadowed.append({**rule, "shadowed_by": prev["name"]})
                break  # Report only the first shadowing rule

    return shadowed


def run_policy_audit(conn: DeviceConnection) -> dict:
    """Run a full security policy audit against a connected device.

    Collects the security policy and per-rule hit counts, then runs:

    * **unused rules** – rules with zero hits
    * **shadowed rules** – rules obscured by a broader preceding rule

    Returns a dict with keys:

    * ``policy``         – full list of parsed security rules
    * ``stats``          – full list of hit-count records
    * ``unused_rules``   – list of rules with no hits
    * ``shadowed_rules`` – list of rules shadowed by an earlier rule
    * ``rule_count``     – total number of security rules
    * ``alert``          – ``True`` when unused or shadowed rules were found
    * ``error``          – error message on failure, else ``None``
    """
    result: dict = {
        "policy": [],
        "stats": [],
        "unused_rules": [],
        "shadowed_rules": [],
        "rule_count": 0,
        "alert": False,
        "error": None,
    }
    try:
        raw_policy = conn.send("show running security-policy")
        raw_stats = conn.send("show security policy statistics")

        result["policy"] = parse_security_policy(raw_policy)
        result["stats"] = parse_security_policy_stats(raw_stats)
        result["rule_count"] = len(result["policy"])
        result["unused_rules"] = check_unused_rules(result["policy"], result["stats"])
        result["shadowed_rules"] = check_shadowed_rules(result["policy"])
        result["alert"] = bool(result["unused_rules"] or result["shadowed_rules"])
    except Exception as exc:  # noqa: BLE001
        logger.warning("Policy audit failed: %s", exc)
        result["error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Health checks
# ---------------------------------------------------------------------------


def check_ha(conn: DeviceConnection) -> dict:
    """Return HA state check result.

    Returns a dict with keys:

    * ``enabled``     – ``True`` when HA is configured
    * ``mode``        – HA mode string (e.g. ``'Active-Passive'``)
    * ``local_state`` – local HA state (e.g. ``'active'``)
    * ``peer_state``  – peer HA state
    * ``peer_ip``     – peer management IP
    * ``alert``       – ``True`` when local state is not ``'active'`` or
                        ``'passive'`` in a known-good pair
    * ``error``       – error message on failure, else ``None``
    """
    try:
        output = conn.send("show high-availability state")
        ha = parse_ha_state(output)
        # Alert when HA is configured but the local unit is not in a stable state
        stable_states = {"active", "passive", "active-secondary"}
        local = (ha.get("local_state") or "").lower()
        alert = ha["enabled"] and local not in stable_states
        return {**ha, "alert": alert, "error": None}
    except Exception as exc:  # noqa: BLE001
        logger.warning("HA check failed: %s", exc)
        return {
            "enabled": False,
            "mode": None,
            "local_state": None,
            "peer_state": None,
            "peer_ip": None,
            "preemptive": False,
            "alert": False,
            "error": str(exc),
        }


def check_sessions(conn: DeviceConnection, threshold: float) -> dict:
    """Return session table utilization check result.

    Returns a dict with keys:

    * ``max_sessions``        – maximum supported sessions
    * ``active_sessions``     – current active sessions
    * ``session_utilization`` – utilization percentage (``float``)
    * ``threshold``           – alert threshold percentage
    * ``alert``               – ``True`` when utilization >= threshold
    * ``error``               – error message on failure, else ``None``
    """
    try:
        output = conn.send("show session info")
        info = parse_session_info(output)
        util = info.get("session_utilization") or 0.0
        return {
            **info,
            "threshold": threshold,
            "alert": util >= threshold,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Session check failed: %s", exc)
        return {
            "max_sessions": None,
            "active_sessions": None,
            "session_utilization": None,
            "threshold": threshold,
            "alert": False,
            "error": str(exc),
        }


def check_threat_status(conn: DeviceConnection) -> dict:
    """Return threat and URL filtering content status.

    Returns a dict with keys:

    * ``threat_version``  – installed threat content version
    * ``url_version``     – installed URL filtering database version
    * ``ha_mode``         – HA mode from ``show system info``
    * ``alert``           – always ``False`` (informational only)
    * ``error``           – error message on failure, else ``None``
    """
    try:
        output = conn.send("show system info")
        info = parse_system_info(output)
        return {
            "threat_version": info.get("threat_version"),
            "url_version": info.get("url_version"),
            "ha_mode": info.get("ha_mode"),
            "alert": False,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Threat status check failed: %s", exc)
        return {
            "threat_version": None,
            "url_version": None,
            "ha_mode": None,
            "alert": False,
            "error": str(exc),
        }


def run_health_check(
    params: ConnectionParams,
    session_threshold: float = DEFAULT_SESSION_THRESHOLD,
) -> dict:
    """Run all PAN-OS-specific health checks against a single device.

    Runs:

    * **HA state** – checks that the local unit is in a stable HA role
    * **Sessions** – checks session-table utilization against *session_threshold*
    * **Threat status** – reports content versions (informational)

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
            result["checks"]["ha"] = check_ha(conn)
            result["checks"]["sessions"] = check_sessions(conn, session_threshold)
            result["checks"]["threat_status"] = check_threat_status(conn)
            result["success"] = True
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        return result

    result["overall_alert"] = any(
        result["checks"][k].get("alert", False) for k in result["checks"]
    )
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_audit(result: dict) -> None:
    icon = "🚨" if result.get("alert") else "✅"
    print(f"{icon} Policy audit — {result['rule_count']} rules total")

    unused = result.get("unused_rules", [])
    if unused:
        print(f"   ⚠️  UNUSED RULES ({len(unused)}):")
        for r in unused:
            print(f"      • {r['name']}  (action: {r.get('action', '?')})")
    else:
        print("   ✅ No unused rules")

    shadowed = result.get("shadowed_rules", [])
    if shadowed:
        print(f"   ⚠️  SHADOWED RULES ({len(shadowed)}):")
        for r in shadowed:
            print(f"      • {r['name']}  shadowed by → {r.get('shadowed_by', '?')}")
    else:
        print("   ✅ No shadowed rules")

    if result.get("error"):
        print(f"   ERROR: {result['error']}")


def _print_health(result: dict) -> None:
    icon = "🚨" if result.get("overall_alert") else ("✅" if result.get("success") else "❌")
    print(f"{icon} {result['host']} [{result['timestamp']}]")

    if not result.get("success"):
        print(f"   ERROR: {result.get('error')}")
        return

    checks = result.get("checks", {})

    ha = checks.get("ha", {})
    if ha.get("enabled"):
        alert_tag = " ⚠️  ALERT" if ha.get("alert") else ""
        print(
            f"   HA : mode={ha.get('mode')}  local={ha.get('local_state')}"
            f"  peer={ha.get('peer_state')}{alert_tag}"
        )
    else:
        print("   HA : not configured")

    sess = checks.get("sessions", {})
    if sess.get("session_utilization") is not None:
        alert_tag = " ⚠️  ALERT" if sess.get("alert") else ""
        print(
            f"   SESSIONS : {sess['active_sessions']} active"
            f"  ({sess['session_utilization']:.1f}%"
            f" of {sess['max_sessions']}){alert_tag}"
        )

    threat = checks.get("threat_status", {})
    print(
        f"   CONTENT : threat={threat.get('threat_version')}  url={threat.get('url_version')}"
    )


def main() -> None:
    """CLI entry point for the Palo Alto PAN-OS security policy auditor."""
    parser = argparse.ArgumentParser(
        description="Palo Alto PAN-OS security policy audit and health checks"
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--inventory", "-i", metavar="FILE", help="YAML/JSON inventory file")
    target.add_argument("--host", metavar="IP", help="Single device IP/hostname")

    parser.add_argument("--group", "-g", metavar="GROUP", help="Filter inventory by group")
    parser.add_argument(
        "--vendor", default="paloalto_panos", help="Device vendor (single-host mode)"
    )
    parser.add_argument("--user", "-u", metavar="USER", help="SSH username")
    parser.add_argument("--password", "-p", metavar="PASS", help="SSH password")
    parser.add_argument(
        "--session-threshold",
        metavar="PCT",
        type=float,
        default=DEFAULT_SESSION_THRESHOLD,
        help=f"Session table alert threshold %% (default: {DEFAULT_SESSION_THRESHOLD})",
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--audit", action="store_true", help="Run security policy audit")
    mode.add_argument("--health", action="store_true", help="Run health checks (default)")

    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--fail-on-alert", action="store_true", help="Exit 1 if any alert fires")
    args = parser.parse_args()

    password = args.password or os.environ.get("NETOPS_PASSWORD")
    run_audit = args.audit

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

    results = []

    for p in device_params:
        if run_audit:
            try:
                with DeviceConnection(p) as conn:
                    res = run_policy_audit(conn)
                    res["host"] = p.host
            except Exception as exc:  # noqa: BLE001
                res = {"host": p.host, "error": str(exc), "alert": False}
        else:
            res = run_health_check(p, session_threshold=args.session_threshold)
        results.append(res)

    if args.json:
        json.dump(results if len(results) > 1 else results[0], sys.stdout, indent=2)
        print()
    else:
        for r in results:
            if run_audit:
                _print_audit(r)
            else:
                _print_health(r)

    if args.fail_on_alert and any(r.get("overall_alert") or r.get("alert") for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
