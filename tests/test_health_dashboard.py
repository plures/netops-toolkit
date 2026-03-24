"""Tests for netops.report.health_dashboard."""

from __future__ import annotations

import re
from unittest.mock import patch

import pytest

from netops.report.health_dashboard import (
    aggregate_dashboard,
    format_table,
    normalize_device_result,
    render_html,
)

# ---------------------------------------------------------------------------
# Sample device results matching different vendor check schemas
# ---------------------------------------------------------------------------

# Generic / Cisco / Nokia / Brocade / PaloAlto style (check/health.py)
GENERIC_OK = {
    "host": "10.0.0.1",
    "timestamp": "2024-03-24T12:00:00Z",
    "success": True,
    "vendor": "cisco_ios",
    "checks": {
        "cpu": {"utilization": 40.0, "threshold": 80.0, "alert": False, "raw": {}},
        "memory": {"utilization": 55.0, "threshold": 85.0, "alert": False, "raw": {}},
        "interface_errors": {"total": 24, "with_errors": 0, "alert": False},
        "logs": {"critical_count": 0, "major_count": 0, "events": [], "alert": False},
    },
    "overall_alert": False,
    "error": None,
}

GENERIC_CPU_ALERT = {
    "host": "10.0.0.2",
    "timestamp": "2024-03-24T12:00:00Z",
    "success": True,
    "vendor": "cisco_ios",
    "checks": {
        "cpu": {"utilization": 92.0, "threshold": 80.0, "alert": True, "raw": {}},
        "memory": {"utilization": 60.0, "threshold": 85.0, "alert": False, "raw": {}},
        "interface_errors": {"total": 24, "with_errors": 2, "alert": True},
        "logs": {"critical_count": 1, "major_count": 0, "events": [], "alert": True},
    },
    "overall_alert": True,
    "error": None,
}

UNREACHABLE = {
    "host": "10.0.0.3",
    "timestamp": "2024-03-24T12:00:00Z",
    "success": False,
    "vendor": "cisco_ios",
    "checks": {},
    "overall_alert": False,
    "error": "Connection timed out",
}

# Arista EOS style
ARISTA_OK = {
    "host": "eos-sw1",
    "timestamp": "2024-03-24T12:00:00Z",
    "success": True,
    "vendor": "arista_eos",
    "checks": {
        "cpu_memory": {
            "cpu_utilization": 30.0,
            "memory_util": 45.0,
            "cpu_threshold": 80.0,
            "mem_threshold": 85.0,
            "cpu_alert": False,
            "mem_alert": False,
            "alert": False,
        },
        "interfaces": {"total": 48, "with_errors": 0, "alert": False},
        "bgp": {"total": 4, "established": 4, "not_established": 0, "alert": False},
        "ospf": {"total": 2, "full": 2, "not_full": 0, "alert": False},
        "environment": {"alert": False, "alerts": []},
    },
    "overall_alert": False,
    "error": None,
}

# Juniper JunOS style
JUNOS_WARN = {
    "host": "junos-r1",
    "timestamp": "2024-03-24T12:00:00Z",
    "success": True,
    "vendor": "juniper_junos",
    "checks": {
        "re": {
            "cpu_utilization": 68.0,
            "memory_utilization": 70.0,
            "cpu_threshold": 80.0,
            "mem_threshold": 85.0,
            "alert": False,
        },
        "fpc": {"total": 4, "offline": 0, "alert": False},
        "interfaces": {"total": 100, "with_errors": 0, "alert": False},
        "bgp": {"total": 6, "established": 6, "not_established": 0, "alert": False},
        "ospf": {"total": 3, "full": 3, "not_full": 0, "alert": False},
        "alarms": {"major_count": 0, "minor_count": 1, "alert": False},
        "environment": {"alert": False, "alerts": []},
        "routes": {"alert": False},
    },
    "overall_alert": False,
    "error": None,
}

CISCO_EXTENDED_OK = {
    "host": "cisco-r1",
    "timestamp": "2024-03-24T12:00:00Z",
    "success": True,
    "vendor": "cisco_ios",
    "checks": {
        "cpu": {"utilization": 30.0, "threshold": 80.0, "alert": False, "raw": {}},
        "memory": {"utilization": 55.0, "threshold": 85.0, "alert": False, "raw": {}},
        "interface_errors": {"total": 48, "with_errors": 0, "alert": False},
        "logs": {"critical_count": 0, "major_count": 0, "events": [], "alert": False},
        "bgp": {"total": 2, "established": 2, "not_established": 0, "alert": False},
        "ospf": {"total": 2, "full": 2, "not_full": 0, "alert": False},
        "environment": {"alert": False, "alerts": []},
        "uptime": {"alert": False},
    },
    "overall_alert": False,
    "error": None,
}


# ===========================================================================
# normalize_device_result
# ===========================================================================


class TestNormalizeDeviceResult:
    def test_unreachable_produces_single_crit_row(self):
        rows = normalize_device_result(UNREACHABLE)
        assert len(rows) == 1
        row = rows[0]
        assert row["status"] == "crit"
        assert row["category"] == "reachability"
        assert "timed out" in row["detail"]

    def test_generic_ok_row_count(self):
        rows = normalize_device_result(GENERIC_OK)
        assert len(rows) == 4  # cpu, memory, interface_errors, logs

    def test_generic_all_ok(self):
        rows = normalize_device_result(GENERIC_OK)
        for r in rows:
            assert r["status"] == "ok"

    def test_cpu_alert_maps_to_crit(self):
        rows = normalize_device_result(GENERIC_CPU_ALERT)
        cpu_row = next(r for r in rows if r["category"] == "cpu")
        assert cpu_row["status"] == "crit"

    def test_interface_errors_detail(self):
        rows = normalize_device_result(GENERIC_CPU_ALERT)
        iface_row = next(r for r in rows if r["category"] == "interfaces")
        assert "2/24" in iface_row["detail"]

    def test_logs_detail(self):
        rows = normalize_device_result(GENERIC_CPU_ALERT)
        log_row = next(r for r in rows if r["category"] == "logs")
        assert "1 critical" in log_row["detail"]
        assert "0 major" in log_row["detail"]

    def test_vendor_tag_attached(self):
        rows = normalize_device_result(GENERIC_OK, vendor="cisco_ios")
        for r in rows:
            assert r["vendor"] == "cisco_ios"

    def test_vendor_from_result(self):
        rows = normalize_device_result(GENERIC_OK)
        for r in rows:
            assert r["vendor"] == "cisco_ios"

    def test_site_tag_attached(self):
        rows = normalize_device_result(GENERIC_OK, site="dc1")
        for r in rows:
            assert r["site"] == "dc1"

    def test_device_field_populated(self):
        rows = normalize_device_result(GENERIC_OK)
        for r in rows:
            assert r["device"] == "10.0.0.1"

    def test_arista_cpu_memory_check(self):
        rows = normalize_device_result(ARISTA_OK)
        cats = [r["category"] for r in rows]
        assert "cpu/memory" in cats

    def test_arista_bgp_check(self):
        rows = normalize_device_result(ARISTA_OK)
        cats = [r["category"] for r in rows]
        assert "bgp" in cats

    def test_junos_routing_engine_check(self):
        rows = normalize_device_result(JUNOS_WARN)
        cats = [r["category"] for r in rows]
        assert "routing-engine" in cats

    def test_junos_alarms_check(self):
        rows = normalize_device_result(JUNOS_WARN)
        alarm_row = next(r for r in rows if r["category"] == "alarms")
        # minor_count=1 → warn even though overall alert=False
        assert alarm_row["status"] == "warn"

    def test_cisco_extended_checks(self):
        rows = normalize_device_result(CISCO_EXTENDED_OK)
        cats = [r["category"] for r in rows]
        assert "bgp" in cats
        assert "ospf" in cats
        assert "environment" in cats
        assert "uptime" in cats

    def test_warn_status_for_cpu_near_threshold(self):
        result = {
            "host": "r1",
            "timestamp": "2024-03-24T12:00:00Z",
            "success": True,
            "checks": {
                "cpu": {"utilization": 70.0, "threshold": 80.0, "alert": False},
            },
            "overall_alert": False,
            "error": None,
        }
        rows = normalize_device_result(result)
        cpu_row = next(r for r in rows if r["category"] == "cpu")
        assert cpu_row["status"] == "warn"

    def test_ok_status_for_cpu_well_below_threshold(self):
        result = {
            "host": "r1",
            "timestamp": "2024-03-24T12:00:00Z",
            "success": True,
            "checks": {
                "cpu": {"utilization": 20.0, "threshold": 80.0, "alert": False},
            },
            "overall_alert": False,
            "error": None,
        }
        rows = normalize_device_result(result)
        cpu_row = rows[0]
        assert cpu_row["status"] == "ok"


# ===========================================================================
# aggregate_dashboard
# ===========================================================================


class TestAggregateDashboard:
    def test_basic_structure(self):
        dash = aggregate_dashboard([GENERIC_OK])
        assert "generated_at" in dash
        assert "entries" in dash
        assert "summary" in dash
        assert "overall_status" in dash
        assert "filters" in dash

    def test_generated_at_format(self):
        dash = aggregate_dashboard([GENERIC_OK])
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", dash["generated_at"])

    def test_all_ok_overall_status(self):
        dash = aggregate_dashboard([GENERIC_OK])
        assert dash["overall_status"] == "ok"

    def test_crit_overall_status(self):
        dash = aggregate_dashboard([GENERIC_CPU_ALERT])
        assert dash["overall_status"] == "crit"

    def test_unreachable_counted(self):
        dash = aggregate_dashboard([GENERIC_OK, UNREACHABLE])
        assert dash["summary"]["unreachable_devices"] == 1

    def test_total_devices(self):
        dash = aggregate_dashboard([GENERIC_OK, GENERIC_CPU_ALERT, UNREACHABLE])
        assert dash["summary"]["total_devices"] == 3

    def test_healthy_devices(self):
        dash = aggregate_dashboard([GENERIC_OK, GENERIC_CPU_ALERT])
        # GENERIC_OK has no alerts → healthy; GENERIC_CPU_ALERT has crits → unhealthy
        assert dash["summary"]["healthy_devices"] == 1

    def test_pct_healthy_all_ok(self):
        dash = aggregate_dashboard([GENERIC_OK, CISCO_EXTENDED_OK])
        assert dash["summary"]["pct_healthy"] == 100.0

    def test_checks_crit_count(self):
        dash = aggregate_dashboard([GENERIC_CPU_ALERT])
        # cpu, interface_errors, logs all alert=True → 3 crit
        assert dash["summary"]["checks_crit"] == 3

    def test_checks_ok_count(self):
        dash = aggregate_dashboard([GENERIC_OK])
        assert dash["summary"]["checks_ok"] == 4  # cpu, memory, interface_errors, logs

    def test_top_issues_present_when_crits(self):
        dash = aggregate_dashboard([GENERIC_CPU_ALERT])
        assert len(dash["summary"]["top_issues"]) > 0

    def test_top_issues_empty_when_all_ok(self):
        dash = aggregate_dashboard([GENERIC_OK])
        assert dash["summary"]["top_issues"] == []

    def test_filter_vendor(self):
        # Mix arista and cisco results
        dash = aggregate_dashboard(
            [ARISTA_OK, GENERIC_OK],
            filter_vendor="arista",
        )
        for entry in dash["entries"]:
            assert "arista" in (entry.get("vendor") or "").lower()

    def test_filter_site(self):
        dash = aggregate_dashboard(
            [GENERIC_OK, GENERIC_CPU_ALERT],
            site_tag="dc1",
            filter_site="dc1",
        )
        for entry in dash["entries"]:
            assert entry["site"] == "dc1"

    def test_filter_severity_crit(self):
        dash = aggregate_dashboard([GENERIC_OK, GENERIC_CPU_ALERT], filter_severity="crit")
        for entry in dash["entries"]:
            assert entry["status"] == "crit"

    def test_filter_severity_warn_includes_crit(self):
        dash = aggregate_dashboard([GENERIC_OK, GENERIC_CPU_ALERT], filter_severity="warn")
        statuses = {e["status"] for e in dash["entries"]}
        assert "ok" not in statuses

    def test_filters_recorded_in_result(self):
        dash = aggregate_dashboard([GENERIC_OK], filter_vendor="cisco", filter_severity="crit")
        assert dash["filters"]["vendor"] == "cisco"
        assert dash["filters"]["severity"] == "crit"

    def test_empty_results(self):
        dash = aggregate_dashboard([])
        assert dash["summary"]["total_devices"] == 0
        assert dash["overall_status"] == "ok"

    def test_vendor_tag_overrides(self):
        result = {**GENERIC_OK, "vendor": None}
        dash = aggregate_dashboard([result], vendor_tag="test_vendor")
        for entry in dash["entries"]:
            assert entry["vendor"] == "test_vendor"

    def test_multi_vendor(self):
        dash = aggregate_dashboard([GENERIC_OK, ARISTA_OK, JUNOS_WARN])
        vendors = {e["vendor"] for e in dash["entries"]}
        assert "cisco_ios" in vendors
        assert "arista_eos" in vendors
        assert "juniper_junos" in vendors


# ===========================================================================
# format_table
# ===========================================================================


class TestFormatTable:
    def test_returns_string(self):
        dash = aggregate_dashboard([GENERIC_OK])
        table = format_table(dash)
        assert isinstance(table, str)

    def test_header_line_present(self):
        dash = aggregate_dashboard([GENERIC_OK])
        table = format_table(dash)
        assert "DEVICE" in table
        assert "CATEGORY" in table
        assert "STATUS" in table
        assert "DETAIL" in table

    def test_device_name_in_output(self):
        dash = aggregate_dashboard([GENERIC_OK])
        table = format_table(dash)
        assert "10.0.0.1" in table

    def test_summary_stats_in_header(self):
        dash = aggregate_dashboard([GENERIC_OK, GENERIC_CPU_ALERT])
        table = format_table(dash)
        assert "Devices:" in table

    def test_empty_entries_message(self):
        dash = aggregate_dashboard([GENERIC_OK], filter_severity="crit")
        table = format_table(dash)
        assert "no entries" in table.lower()

    def test_color_false_uses_text_status(self):
        dash = aggregate_dashboard([GENERIC_CPU_ALERT])
        table = format_table(dash, color=False)
        assert "CRIT" in table


# ===========================================================================
# render_html
# ===========================================================================


class TestRenderHTML:
    def test_returns_string(self):
        dash = aggregate_dashboard([GENERIC_OK])
        html = render_html(dash)
        assert isinstance(html, str)

    def test_html_structure(self):
        dash = aggregate_dashboard([GENERIC_OK])
        html = render_html(dash)
        assert "<!DOCTYPE html>" in html
        assert "Network Health Dashboard" in html

    def test_device_name_in_html(self):
        dash = aggregate_dashboard([GENERIC_OK])
        html = render_html(dash)
        assert "10.0.0.1" in html

    def test_crit_status_in_html(self):
        dash = aggregate_dashboard([GENERIC_CPU_ALERT])
        html = render_html(dash)
        assert "CRIT" in html

    def test_ok_status_in_html(self):
        dash = aggregate_dashboard([GENERIC_OK])
        html = render_html(dash)
        assert "OK" in html

    def test_generated_at_in_html(self):
        dash = aggregate_dashboard([GENERIC_OK])
        html = render_html(dash)
        assert dash["generated_at"] in html

    def test_writes_file(self, tmp_path):
        dash = aggregate_dashboard([GENERIC_OK])
        out = tmp_path / "dashboard.html"
        render_html(dash, output_path=str(out))
        assert out.exists()
        content = out.read_text()
        assert "<!DOCTYPE html>" in content

    def test_filter_bar_shown_when_filters_active(self):
        dash = aggregate_dashboard([GENERIC_OK], filter_vendor="cisco")
        html = render_html(dash)
        assert "Active filters" in html

    def test_filter_bar_absent_when_no_filters(self):
        dash = aggregate_dashboard([GENERIC_OK])
        html = render_html(dash)
        assert "Active filters" not in html

    def test_import_error_raised_without_jinja2(self):
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "jinja2":
                raise ImportError("no jinja2")
            return real_import(name, *args, **kwargs)

        dash = aggregate_dashboard([GENERIC_OK])
        with patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(ImportError, match="jinja2"):
                render_html(dash)

    def test_self_contained_no_external_stylesheets(self):
        dash = aggregate_dashboard([GENERIC_OK])
        html = render_html(dash)
        # No <link rel="stylesheet"> referencing external files
        assert '<link rel="stylesheet"' not in html
        assert "<style>" in html

    def test_multi_vendor_entries_in_html(self):
        dash = aggregate_dashboard([GENERIC_OK, ARISTA_OK])
        html = render_html(dash)
        assert "10.0.0.1" in html
        assert "eos-sw1" in html


# ===========================================================================
# Public re-exports from netops.report
# ===========================================================================


class TestPublicExports:
    def test_aggregate_dashboard_exported(self):
        from netops.report import aggregate_dashboard as ad

        assert callable(ad)

    def test_format_table_exported(self):
        from netops.report import format_table as ft

        assert callable(ft)

    def test_render_html_exported(self):
        from netops.report import render_html as rh

        assert callable(rh)
