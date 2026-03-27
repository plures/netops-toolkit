r"""Unified multi-vendor health dashboard.

Aggregates health check results from all supported vendor checkers
(Cisco IOS/IOS-XE, Arista EOS, Juniper JunOS, Nokia SROS, Brocade,
Palo Alto PAN-OS) into a single normalised view and renders it as a
terminal table, JSON document, or self-contained HTML page.

Each vendor check result is normalised to a common row schema::

    {
        "device":    <str>,          # hostname / IP
        "vendor":    <str>,          # device_type string
        "site":      <str | None>,   # optional site tag
        "category":  <str>,          # "cpu", "memory", "interfaces", ...
        "status":    <str>,          # "ok", "warn", or "crit"
        "detail":    <str>,          # human-readable one-liner
        "timestamp": <str>,          # ISO-8601 UTC
    }

Usage::

    python -m netops.report.health_dashboard \\
        --inventory inv.yaml --group core \\
        --format table

    python -m netops.report.health_dashboard \\
        --inventory inv.yaml --vendor arista_eos \\
        --format html --output dashboard.html

Programmatic::

    from netops.report.health_dashboard import aggregate_dashboard, format_table

    results = [run_health_check(p) for p in device_params]
    dashboard = aggregate_dashboard(results, vendor_tag="cisco_ios")
    print(format_table(dashboard))
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Path to the bundled Jinja2 template
_DASHBOARD_TEMPLATE = Path(__file__).parent / "templates" / "health_dashboard.html.j2"

# ---------------------------------------------------------------------------
# Status helpers
# ---------------------------------------------------------------------------

_STATUS_RANK = {"ok": 0, "warn": 1, "crit": 2}


def _worst(a: str, b: str) -> str:
    """Return the more severe of two status strings."""
    return a if _STATUS_RANK.get(a, 0) >= _STATUS_RANK.get(b, 0) else b


def _pct_status(value: float | None, threshold: float | None) -> str:
    """Map a utilisation percentage to ok/warn/crit."""
    if value is None or threshold is None:
        return "ok"
    if value >= threshold:
        return "crit"
    if value >= threshold * 0.8:
        return "warn"
    return "ok"


# ---------------------------------------------------------------------------
# Per-check detail builders
# ---------------------------------------------------------------------------


def _detail_cpu(check: dict) -> tuple[str, str]:
    """Return (status, detail) for a CPU utilisation check result."""
    util = check.get("utilization")
    thr = check.get("threshold")
    status = _pct_status(util, thr)
    detail = f"{util:.1f}% (threshold {thr}%)" if util is not None else "N/A"
    return status, detail


def _detail_memory(check: dict) -> tuple[str, str]:
    """Return (status, detail) for a memory utilisation check result."""
    util = check.get("utilization")
    thr = check.get("threshold")
    status = _pct_status(util, thr)
    detail = f"{util:.1f}% (threshold {thr}%)" if util is not None else "N/A"
    return status, detail


def _detail_cpu_memory(check: dict) -> tuple[str, str]:
    """Arista combined cpu_memory check."""
    cpu = check.get("cpu_utilization")
    mem = check.get("memory_util")
    cpu_thr = check.get("cpu_threshold", 80.0)
    mem_thr = check.get("mem_threshold", 85.0)
    cpu_status = _pct_status(cpu, cpu_thr)
    mem_status = _pct_status(mem, mem_thr)
    status = _worst(cpu_status, mem_status)
    if check.get("alert"):
        status = "crit"
    parts = []
    if cpu is not None:
        parts.append(f"CPU {cpu:.1f}%")
    if mem is not None:
        parts.append(f"Mem {mem:.1f}%")
    detail = ", ".join(parts) if parts else "N/A"
    return status, detail


def _detail_routing_engine(check: dict) -> tuple[str, str]:
    """Juniper RE check (cpu + memory)."""
    cpu = check.get("cpu_utilization")
    mem = check.get("memory_utilization")
    cpu_thr = check.get("cpu_threshold", 80.0)
    mem_thr = check.get("mem_threshold", 85.0)
    cpu_status = _pct_status(cpu, cpu_thr)
    mem_status = _pct_status(mem, mem_thr)
    status = _worst(cpu_status, mem_status)
    if check.get("alert"):
        status = "crit"
    parts = []
    if cpu is not None:
        parts.append(f"CPU {cpu:.1f}%")
    if mem is not None:
        parts.append(f"Mem {mem:.1f}%")
    detail = ", ".join(parts) if parts else "N/A"
    return status, detail


def _detail_interfaces(check: dict) -> tuple[str, str]:
    """Return (status, detail) for an interface error check result."""
    w = check.get("with_errors", 0)
    t = check.get("total", 0)
    status = "crit" if check.get("alert") else "ok"
    detail = f"{w}/{t} interfaces with errors"
    return status, detail


def _detail_logs(check: dict) -> tuple[str, str]:
    """Return (status, detail) for a syslog severity check result."""
    crit = check.get("critical_count", 0)
    major = check.get("major_count", 0)
    status = "crit" if check.get("alert") else "ok"
    detail = f"{crit} critical, {major} major"
    return status, detail


def _detail_bgp(check: dict) -> tuple[str, str]:
    """Return (status, detail) for a BGP peer state check result."""
    ne = check.get("not_established", 0)
    total = check.get("total", 0)
    est = check.get("established", total - ne)
    status = "crit" if check.get("alert") else "ok"
    detail = f"{est}/{total} peers established"
    return status, detail


def _detail_ospf(check: dict) -> tuple[str, str]:
    """Return (status, detail) for an OSPF neighbor state check result."""
    nf = check.get("not_full", 0)
    total = check.get("total", 0)
    full = check.get("full", total - nf)
    status = "crit" if check.get("alert") else "ok"
    detail = f"{full}/{total} neighbors full"
    return status, detail


def _detail_environment(check: dict) -> tuple[str, str]:
    """Return (status, detail) for an environmental (power/fan/temp) check result."""
    status = "crit" if check.get("alert") else "ok"
    alerts = check.get("alerts", [])
    if alerts:
        detail = "; ".join(str(a) for a in alerts[:3])
    else:
        detail = "OK" if not check.get("alert") else "Alert"
    return status, detail


def _detail_fpc(check: dict) -> tuple[str, str]:
    """Return (status, detail) for a Juniper FPC online/offline check result."""
    offline = check.get("offline", 0)
    total = check.get("total", 0)
    status = "crit" if check.get("alert") else "ok"
    detail = f"{total - offline}/{total} FPCs online"
    return status, detail


def _detail_alarms(check: dict) -> tuple[str, str]:
    """Return (status, detail) for a chassis alarm check result."""
    major = check.get("major_count", 0)
    minor = check.get("minor_count", 0)
    status = "crit" if check.get("alert") else ("warn" if minor else "ok")
    detail = f"{major} major, {minor} minor alarms"
    return status, detail


def _detail_mlag(check: dict) -> tuple[str, str]:
    """Return (status, detail) for an Arista MLAG state check result."""
    status = "crit" if check.get("alert") else "ok"
    state = check.get("state", "unknown")
    detail = f"state={state}"
    return status, detail


def _detail_generic(check: dict) -> tuple[str, str]:
    """Return (status, detail) for a generic check result with no structured fields."""
    status = "crit" if check.get("alert") else "ok"
    detail = "Alert" if check.get("alert") else "OK"
    return status, detail


# Mapping from check key → (canonical category name, detail builder)
_CHECK_MAP: dict[str, tuple[str, Callable[[dict], tuple[str, str]]]] = {
    "cpu": ("cpu", _detail_cpu),
    "memory": ("memory", _detail_memory),
    "cpu_memory": ("cpu/memory", _detail_cpu_memory),
    "re": ("routing-engine", _detail_routing_engine),
    "interface_errors": ("interfaces", _detail_interfaces),
    "interfaces": ("interfaces", _detail_interfaces),
    "logs": ("logs", _detail_logs),
    "alarms": ("alarms", _detail_alarms),
    "bgp": ("bgp", _detail_bgp),
    "bgp_evpn": ("bgp-evpn", _detail_bgp),
    "ospf": ("ospf", _detail_ospf),
    "environment": ("environment", _detail_environment),
    "fpc": ("fpc", _detail_fpc),
    "mlag": ("mlag", _detail_mlag),
    "transceivers": ("transceivers", _detail_generic),
    "routes": ("routes", _detail_generic),
    "uptime": ("uptime", _detail_generic),
}


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------


def normalize_device_result(
    result: dict,
    vendor: str | None = None,
    site: str | None = None,
) -> list[dict]:
    """Convert a per-device health-check result to a list of normalised rows.

    Each row represents one check category and follows the common schema::

        {
            "device":    <str>,
            "vendor":    <str | None>,
            "site":      <str | None>,
            "category":  <str>,
            "status":    "ok" | "warn" | "crit",
            "detail":    <str>,
            "timestamp": <str>,
        }

    Parameters
    ----------
    result:
        A dict returned by any ``run_*_health_check()`` function.
    vendor:
        Vendor/platform tag to attach to each row (e.g. ``"cisco_ios"``).
        If *None* the raw key from *result* is used when available.
    site:
        Optional site/location label.

    Returns
    -------
    list
        List of row dicts. Unreachable devices produce a single
        ``status="crit"`` row with category ``"reachability"``.

    """
    device = result.get("host", "unknown")
    timestamp = result.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    vendor = vendor or result.get("vendor") or result.get("device_type")
    rows: list[dict] = []

    if not result.get("success"):
        rows.append(
            {
                "device": device,
                "vendor": vendor,
                "site": site,
                "category": "reachability",
                "status": "crit",
                "detail": result.get("error") or "Unreachable",
                "timestamp": timestamp,
            }
        )
        return rows

    checks: dict = result.get("checks", {})
    for check_key, check_data in checks.items():
        if not isinstance(check_data, dict):
            continue
        category, builder = _CHECK_MAP.get(check_key, (check_key, _detail_generic))
        status, detail = builder(check_data)
        rows.append(
            {
                "device": device,
                "vendor": vendor,
                "site": site,
                "category": category,
                "status": status,
                "detail": detail,
                "timestamp": timestamp,
            }
        )

    return rows


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def aggregate_dashboard(
    device_results: list[dict],
    vendor_tag: str | None = None,
    site_tag: str | None = None,
    filter_vendor: str | None = None,
    filter_site: str | None = None,
    filter_severity: str | None = None,
) -> dict:
    """Aggregate health check results into a unified dashboard dict.

    Parameters
    ----------
    device_results:
        List of per-device result dicts from any ``run_*_health_check()``.
    vendor_tag:
        Vendor label to attach to every row when the result dicts do not
        already carry one (e.g. when all devices share a vendor).
    site_tag:
        Site label to attach to every row.
    filter_vendor:
        When set, only include rows whose *vendor* contains this string
        (case-insensitive).
    filter_site:
        When set, only include rows matching this site label exactly.
    filter_severity:
        When set to ``"warn"`` or ``"crit"``, exclude ``"ok"`` rows.
        When set to ``"crit"``, also exclude ``"warn"`` rows.

    Returns
    -------
    dict
        Dashboard dict with keys:

        * ``generated_at``   – ISO-8601 UTC generation timestamp
        * ``filters``        – dict of active filter values
        * ``entries``        – list of normalised row dicts
        * ``summary``        – aggregated statistics
        * ``overall_status`` – worst status across all entries

    """
    all_entries: list[dict] = []
    for r in device_results:
        all_entries.extend(normalize_device_result(r, vendor=vendor_tag, site=site_tag))

    # Apply filters
    entries = all_entries
    if filter_vendor:
        fv = filter_vendor.lower()
        entries = [e for e in entries if e.get("vendor") and fv in e["vendor"].lower()]
    if filter_site:
        entries = [e for e in entries if e.get("site") == filter_site]
    if filter_severity == "crit":
        entries = [e for e in entries if e["status"] == "crit"]
    elif filter_severity == "warn":
        entries = [e for e in entries if e["status"] in ("warn", "crit")]

    # Compute summary statistics
    devices_seen: set[str] = set()
    devices_healthy: set[str] = set()
    devices_unhealthy: set[str] = set()
    devices_unreachable: set[str] = set()
    category_crit: dict[str, int] = {}
    checks_ok = checks_warn = checks_crit = 0

    for e in all_entries:  # stats always use unfiltered entries
        dev = e["device"]
        devices_seen.add(dev)
        if e["category"] == "reachability" and e["status"] == "crit":
            devices_unreachable.add(dev)
        if e["status"] == "ok":
            checks_ok += 1
        elif e["status"] == "warn":
            checks_warn += 1
            devices_unhealthy.add(dev)
        elif e["status"] == "crit":
            checks_crit += 1
            devices_unhealthy.add(dev)
            category_crit[e["category"]] = category_crit.get(e["category"], 0) + 1

    devices_healthy = devices_seen - devices_unhealthy
    total = len(devices_seen)
    pct_healthy = round(len(devices_healthy) / total * 100, 1) if total else 0.0

    top_issues = sorted(category_crit.items(), key=lambda x: x[1], reverse=True)
    top_issues_list = [{"category": cat, "count": cnt} for cat, cnt in top_issues[:5]]

    overall_status = "ok"
    if checks_warn:
        overall_status = "warn"
    if checks_crit:
        overall_status = "crit"

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "filters": {
            "vendor": filter_vendor,
            "site": filter_site,
            "severity": filter_severity,
        },
        "entries": entries,
        "summary": {
            "total_devices": total,
            "healthy_devices": len(devices_healthy),
            "pct_healthy": pct_healthy,
            "total_checks": checks_ok + checks_warn + checks_crit,
            "checks_ok": checks_ok,
            "checks_warn": checks_warn,
            "checks_crit": checks_crit,
            "unreachable_devices": len(devices_unreachable),
            "top_issues": top_issues_list,
        },
        "overall_status": overall_status,
    }


# ---------------------------------------------------------------------------
# Terminal table formatter
# ---------------------------------------------------------------------------

_COL_WIDTHS = {
    "device": 20,
    "vendor": 14,
    "site": 10,
    "category": 16,
    "status": 6,
    "detail": 40,
}

_STATUS_ICONS = {"ok": "✅", "warn": "⚠️ ", "crit": "🚨"}


def format_table(dashboard: dict, color: bool = True) -> str:
    """Render *dashboard* as a fixed-width terminal table string.

    Parameters
    ----------
    dashboard:
        Dict returned by :func:`aggregate_dashboard`.
    color:
        When *True* (default), status values are prefixed with emoji icons.

    Returns
    -------
    str
        Formatted string (no trailing newline).

    """
    entries = dashboard.get("entries", [])
    summary = dashboard.get("summary", {})
    lines: list[str] = []

    # Header
    lines.append("=" * 112)
    lines.append(f"  Network Health Dashboard — {dashboard.get('generated_at', '')}")
    lines.append(
        f"  Devices: {summary.get('total_devices', 0)}  "
        f"Healthy: {summary.get('healthy_devices', 0)} "
        f"({summary.get('pct_healthy', 0):.1f}%)  "
        f"Unreachable: {summary.get('unreachable_devices', 0)}  "
        f"Checks: OK={summary.get('checks_ok', 0)} "
        f"WARN={summary.get('checks_warn', 0)} "
        f"CRIT={summary.get('checks_crit', 0)}"
    )
    top = summary.get("top_issues", [])
    if top:
        top_str = ", ".join(f"{i['category']}({i['count']})" for i in top)
        lines.append(f"  Top issues: {top_str}")
    lines.append("=" * 112)

    if not entries:
        lines.append("  (no entries match the current filters)")
        return "\n".join(lines)

    # Column headers
    def _pad(s: str, w: int) -> str:
        """Left-justify *s* truncated or padded to exactly *w* characters."""
        return str(s)[:w].ljust(w)

    header = "  ".join(
        [
            _pad("DEVICE", _COL_WIDTHS["device"]),
            _pad("VENDOR", _COL_WIDTHS["vendor"]),
            _pad("SITE", _COL_WIDTHS["site"]),
            _pad("CATEGORY", _COL_WIDTHS["category"]),
            _pad("STATUS", _COL_WIDTHS["status"]),
            _pad("DETAIL", _COL_WIDTHS["detail"]),
        ]
    )
    lines.append(header)
    lines.append("-" * 112)

    for e in entries:
        status = e.get("status", "ok")
        icon = _STATUS_ICONS.get(status, status) if color else status.upper()
        row = "  ".join(
            [
                _pad(e.get("device", ""), _COL_WIDTHS["device"]),
                _pad(e.get("vendor") or "", _COL_WIDTHS["vendor"]),
                _pad(e.get("site") or "", _COL_WIDTHS["site"]),
                _pad(e.get("category", ""), _COL_WIDTHS["category"]),
                _pad(icon, _COL_WIDTHS["status"]),
                _pad(e.get("detail", ""), _COL_WIDTHS["detail"]),
            ]
        )
        lines.append(row)

    lines.append("=" * 112)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


def render_html(dashboard: dict, output_path: str | None = None) -> str:
    """Render *dashboard* as a self-contained HTML string.

    Parameters
    ----------
    dashboard:
        Dict returned by :func:`aggregate_dashboard`.
    output_path:
        When given, the HTML is also written to this path.

    Returns
    -------
    str
        Rendered HTML string.

    Raises
    ------
    ImportError
        When ``jinja2`` is not installed.

    """
    try:
        import jinja2  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "HTML rendering requires jinja2.  Install it with: pip install netops-toolkit[report]"
        ) from exc

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(_DASHBOARD_TEMPLATE.parent)),
        autoescape=jinja2.select_autoescape(["html"]),
        undefined=jinja2.Undefined,
    )
    env.filters["tojson"] = lambda v, indent=None: json.dumps(v, indent=indent, default=str)

    template = env.get_template(_DASHBOARD_TEMPLATE.name)
    html = template.render(**dashboard)

    if output_path:
        dest = Path(output_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(html, encoding="utf-8")
        logger.info("Health dashboard written to %s", dest)

    return html


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_thresholds(raw: str | None) -> dict[str, float]:
    """Parse a ``key=value[,...]`` threshold string into a dict of floats."""
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


def main() -> None:
    """CLI entry point: ``python -m netops.report.health_dashboard``."""
    from netops.check.health import run_health_check  # noqa: PLC0415
    from netops.core.connection import ConnectionParams, Transport  # noqa: PLC0415
    from netops.core.inventory import Inventory  # noqa: PLC0415

    parser = argparse.ArgumentParser(
        description=(
            "Unified multi-vendor health dashboard.  "
            "Aggregates health checks from all connected devices."
        )
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
    parser.add_argument(
        "--format",
        choices=["table", "json", "html"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("--output", "-o", metavar="FILE", help="Output file (html/json formats)")
    parser.add_argument("--site", metavar="SITE", help="Tag all results with a site label")
    parser.add_argument(
        "--filter-vendor",
        metavar="VENDOR",
        help="Show only entries matching this vendor",
    )
    parser.add_argument(
        "--filter-site",
        metavar="SITE",
        help="Show only entries matching this site",
    )
    parser.add_argument(
        "--filter-severity",
        choices=["warn", "crit"],
        metavar="SEVERITY",
        help="Show only entries at or above this severity (warn|crit)",
    )
    parser.add_argument("--fail-on-alert", action="store_true", help="Exit 1 if any alert fires")
    args = parser.parse_args()

    thresholds = _parse_thresholds(args.threshold)
    cpu_thr = thresholds.get("cpu", 80.0)
    mem_thr = thresholds.get("mem", 85.0)

    password = args.password or os.environ.get("NETOPS_PASSWORD")

    device_params: list[tuple[ConnectionParams, str | None]] = []  # (params, vendor_tag)

    if args.inventory:
        inv = Inventory.from_file(args.inventory)
        devices = inv.filter(group=args.group) if args.group else list(inv.devices.values())
        for dev in devices:
            params = ConnectionParams(
                host=dev.host,
                username=args.user or dev.username,
                password=password or dev.password,
                device_type=dev.vendor,
                transport=Transport(dev.transport) if dev.transport else Transport.SSH,
                port=dev.port,
                enable_password=dev.enable_password,
            )
            device_params.append((params, dev.vendor))
    else:
        params = ConnectionParams(
            host=args.host,
            username=args.user,
            password=password,
            device_type=args.vendor,
        )
        device_params.append((params, args.vendor))

    results = []
    for params, vt in device_params:
        r = run_health_check(params, cpu_threshold=cpu_thr, mem_threshold=mem_thr)
        r["vendor"] = vt
        results.append(r)

    dashboard = aggregate_dashboard(
        results,
        site_tag=args.site,
        filter_vendor=args.filter_vendor,
        filter_site=args.filter_site,
        filter_severity=args.filter_severity,
    )

    fmt = args.format
    if fmt == "json":
        output = json.dumps(dashboard, indent=2, default=str)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"Dashboard JSON written to {args.output}")
        else:
            print(output)
    elif fmt == "html":
        html = render_html(dashboard, output_path=args.output)
        if not args.output:
            print(html)
        else:
            print(f"Dashboard HTML written to {args.output}")
    else:
        print(format_table(dashboard))

    if args.fail_on_alert and dashboard["overall_status"] == "crit":
        sys.exit(1)


if __name__ == "__main__":
    main()
