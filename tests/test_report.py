"""Tests for the report generator, mailer, and scheduler modules."""

from __future__ import annotations

import re
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from netops.check.health import build_health_report
from netops.report.generator import (
    ReportGenerator,
    default_output_filename,
    generate_report,
)
from netops.report.mailer import ReportMailer, _html_to_plain
from netops.report.scheduler import ReportScheduler, ScheduledReport, _parse_time

# ---------------------------------------------------------------------------
# Fixtures / sample data
# ---------------------------------------------------------------------------

HEALTH_RESULT_OK = {
    "host": "10.0.0.1",
    "timestamp": "2024-03-24T12:00:00Z",
    "success": True,
    "checks": {
        "cpu": {"utilization": 45.0, "threshold": 80.0, "alert": False, "raw": {}},
        "memory": {"utilization": 60.0, "threshold": 85.0, "alert": False, "raw": {}},
        "interface_errors": {"interfaces": [], "total": 24, "with_errors": 0, "alert": False},
        "logs": {"critical_count": 0, "major_count": 0, "events": [], "alert": False},
    },
    "overall_alert": False,
    "error": None,
}

HEALTH_RESULT_ALERT = {
    "host": "10.0.0.2",
    "timestamp": "2024-03-24T12:00:00Z",
    "success": True,
    "checks": {
        "cpu": {"utilization": 92.0, "threshold": 80.0, "alert": True, "raw": {}},
        "memory": {"utilization": 70.0, "threshold": 85.0, "alert": False, "raw": {}},
        "interface_errors": {
            "interfaces": [{"name": "Gi0/1", "has_errors": True}],
            "total": 24,
            "with_errors": 1,
            "alert": True,
        },
        "logs": {"critical_count": 2, "major_count": 1, "events": [], "alert": True},
    },
    "overall_alert": True,
    "error": None,
}

HEALTH_RESULT_UNREACHABLE = {
    "host": "10.0.0.3",
    "timestamp": "2024-03-24T12:00:00Z",
    "success": False,
    "checks": {},
    "overall_alert": False,
    "error": "Connection timed out",
}

BGP_REPORT = {
    "routers": 2,
    "routers_reachable": 2,
    "total_peers": 4,
    "established": 3,
    "not_established": 1,
    "flapping": 0,
    "prefix_alerts": 0,
    "overall_alert": True,
    "peers": [
        {
            "router": "10.0.0.1",
            "neighbor": "10.0.0.10",
            "peer_as": 65001,
            "state": "Established",
            "up_down": "01:23:45",
            "prefixes_received": 100,
            "is_established": True,
            "uptime_seconds": 5025,
            "is_flapping": False,
            "expected_prefixes": 100,
            "prefix_alert": False,
            "alerts": [],
        },
        {
            "router": "10.0.0.1",
            "neighbor": "10.0.0.11",
            "peer_as": 65002,
            "state": "Active",
            "up_down": "never",
            "prefixes_received": None,
            "is_established": False,
            "uptime_seconds": None,
            "is_flapping": False,
            "expected_prefixes": None,
            "prefix_alert": False,
            "alerts": ["peer 10.0.0.11 not established (state=Active)"],
        },
    ],
}

VLAN_REPORT = {
    "switches": 2,
    "switches_reachable": 2,
    "switches_compliant": 1,
    "overall_alert": True,
    "missing_vlan_switches": [{"host": "sw1", "missing_vlans": [30, 40]}],
    "extra_vlan_switches": [],
    "name_mismatch_switches": [],
    "trunk_mismatch_switches": [],
    "results": [
        {
            "host": "sw1",
            "success": True,
            "compliant": False,
            "missing_vlans": [30, 40],
            "extra_vlans": [],
            "name_mismatches": [],
            "trunk_mismatches": [],
            "alerts": ["missing VLANs: 30, 40"],
            "actual_vlans": [],
            "trunks": [],
        },
        {
            "host": "sw2",
            "success": True,
            "compliant": True,
            "missing_vlans": [],
            "extra_vlans": [],
            "name_mismatches": [],
            "trunk_mismatches": [],
            "alerts": [],
            "actual_vlans": [],
            "trunks": [],
        },
    ],
}


def _make_sections() -> list[dict]:
    return [
        {
            "name": "Device Health",
            "type": "health",
            "data": build_health_report([HEALTH_RESULT_OK, HEALTH_RESULT_ALERT, HEALTH_RESULT_UNREACHABLE]),
        },
        {
            "name": "BGP Health",
            "type": "bgp",
            "data": BGP_REPORT,
        },
        {
            "name": "VLAN Audit",
            "type": "vlan",
            "data": VLAN_REPORT,
        },
    ]


# ===========================================================================
# build_health_report
# ===========================================================================


class TestBuildHealthReport:
    def test_total_devices(self):
        report = build_health_report([HEALTH_RESULT_OK, HEALTH_RESULT_ALERT, HEALTH_RESULT_UNREACHABLE])
        assert report["devices"] == 3

    def test_reachable_devices(self):
        report = build_health_report([HEALTH_RESULT_OK, HEALTH_RESULT_ALERT, HEALTH_RESULT_UNREACHABLE])
        assert report["devices_reachable"] == 2

    def test_devices_with_alerts(self):
        report = build_health_report([HEALTH_RESULT_OK, HEALTH_RESULT_ALERT, HEALTH_RESULT_UNREACHABLE])
        assert report["devices_with_alerts"] == 1

    def test_cpu_alerts(self):
        report = build_health_report([HEALTH_RESULT_OK, HEALTH_RESULT_ALERT])
        assert report["cpu_alerts"] == 1

    def test_memory_alerts(self):
        report = build_health_report([HEALTH_RESULT_OK, HEALTH_RESULT_ALERT])
        assert report["memory_alerts"] == 0

    def test_interface_error_alerts(self):
        report = build_health_report([HEALTH_RESULT_OK, HEALTH_RESULT_ALERT])
        assert report["interface_error_alerts"] == 1

    def test_log_alerts(self):
        report = build_health_report([HEALTH_RESULT_OK, HEALTH_RESULT_ALERT])
        assert report["log_alerts"] == 1

    def test_overall_alert_true(self):
        report = build_health_report([HEALTH_RESULT_OK, HEALTH_RESULT_ALERT])
        assert report["overall_alert"] is True

    def test_overall_alert_false(self):
        report = build_health_report([HEALTH_RESULT_OK])
        assert report["overall_alert"] is False

    def test_results_preserved(self):
        results = [HEALTH_RESULT_OK, HEALTH_RESULT_ALERT]
        report = build_health_report(results)
        assert report["results"] is results

    def test_empty_results(self):
        report = build_health_report([])
        assert report["devices"] == 0
        assert report["devices_reachable"] == 0
        assert report["overall_alert"] is False

    def test_all_unreachable(self):
        report = build_health_report([HEALTH_RESULT_UNREACHABLE])
        assert report["devices_reachable"] == 0
        assert report["cpu_alerts"] == 0
        assert report["overall_alert"] is False


# ===========================================================================
# ReportGenerator.build_report
# ===========================================================================


class TestReportGeneratorBuildReport:
    def test_keys_present(self):
        gen = ReportGenerator()
        rd = gen.build_report()
        assert "title" in rd
        assert "generated_at" in rd
        assert "sections" in rd
        assert "overall_alert" in rd
        assert "period" in rd

    def test_default_title(self):
        gen = ReportGenerator()
        rd = gen.build_report()
        assert rd["title"] == "Network Health Report"

    def test_custom_title(self):
        gen = ReportGenerator()
        rd = gen.build_report(title="Weekly Summary")
        assert rd["title"] == "Weekly Summary"

    def test_overall_alert_propagation(self):
        gen = ReportGenerator()
        sections = _make_sections()
        rd = gen.build_report(sections=sections)
        assert rd["overall_alert"] is True

    def test_overall_alert_false_when_no_alerts(self):
        gen = ReportGenerator()
        sections = [
            {"name": "BGP", "type": "bgp", "data": {**BGP_REPORT, "overall_alert": False}},
        ]
        rd = gen.build_report(sections=sections)
        assert rd["overall_alert"] is False

    def test_generated_at_format(self):
        gen = ReportGenerator()
        rd = gen.build_report()
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", rd["generated_at"])

    def test_period_preserved(self):
        gen = ReportGenerator()
        rd = gen.build_report(period="2024-03-23 to 2024-03-24")
        assert rd["period"] == "2024-03-23 to 2024-03-24"


# ===========================================================================
# ReportGenerator.generate_html
# ===========================================================================


class TestReportGeneratorGenerateHTML:
    def test_returns_string(self):
        gen = ReportGenerator()
        rd = gen.build_report(sections=_make_sections())
        html = gen.generate_html(rd)
        assert isinstance(html, str)

    def test_html_structure(self):
        gen = ReportGenerator()
        rd = gen.build_report(title="Test Report", sections=_make_sections())
        html = gen.generate_html(rd)
        assert "<!DOCTYPE html>" in html
        assert "Test Report" in html

    def test_overall_status_ok(self):
        gen = ReportGenerator()
        sections = [
            {"name": "BGP", "type": "bgp", "data": {**BGP_REPORT, "overall_alert": False}},
        ]
        rd = gen.build_report(sections=sections)
        html = gen.generate_html(rd)
        assert "OK" in html

    def test_overall_status_alert(self):
        gen = ReportGenerator()
        rd = gen.build_report(sections=_make_sections())
        html = gen.generate_html(rd)
        assert "Alert" in html

    def test_device_names_in_health_section(self):
        gen = ReportGenerator()
        rd = gen.build_report(sections=_make_sections())
        html = gen.generate_html(rd)
        assert "10.0.0.1" in html
        assert "10.0.0.2" in html

    def test_bgp_neighbor_in_html(self):
        gen = ReportGenerator()
        rd = gen.build_report(sections=_make_sections())
        html = gen.generate_html(rd)
        assert "10.0.0.10" in html

    def test_vlan_section_in_html(self):
        gen = ReportGenerator()
        rd = gen.build_report(sections=_make_sections())
        html = gen.generate_html(rd)
        assert "sw1" in html
        assert "sw2" in html

    def test_write_to_file(self, tmp_path):
        gen = ReportGenerator(output_dir=str(tmp_path))
        rd = gen.build_report(sections=_make_sections())
        out = tmp_path / "report.html"
        gen.generate_html(rd, output_path=str(out))
        assert out.exists()
        content = out.read_text()
        assert "<!DOCTYPE html>" in content

    def test_custom_template(self, tmp_path):
        tmpl = tmp_path / "custom.html.j2"
        tmpl.write_text("<html><body>{{ title }}</body></html>")
        gen = ReportGenerator(template_path=str(tmpl))
        rd = gen.build_report(title="Custom")
        html = gen.generate_html(rd)
        assert "<html>" in html
        assert "Custom" in html

    def test_missing_jinja2_raises_import_error(self, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "jinja2":
                raise ImportError("No module named 'jinja2'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        gen = ReportGenerator()
        rd = gen.build_report()
        with pytest.raises(ImportError, match="jinja2"):
            gen.generate_html(rd)

    def test_unknown_section_type(self):
        gen = ReportGenerator()
        sections = [
            {"name": "Custom", "type": "custom_check", "data": {"overall_alert": False, "value": 42}},
        ]
        rd = gen.build_report(sections=sections)
        html = gen.generate_html(rd)
        assert "Custom" in html


# ===========================================================================
# default_output_filename
# ===========================================================================


class TestDefaultOutputFilename:
    def test_html_extension(self):
        name = default_output_filename(fmt="html")
        assert name.endswith(".html")

    def test_pdf_extension(self):
        name = default_output_filename(fmt="pdf")
        assert name.endswith(".pdf")

    def test_prefix_included(self):
        name = default_output_filename(prefix="my-report", fmt="html")
        assert name.startswith("my-report-")

    def test_timestamp_pattern(self):
        name = default_output_filename()
        # e.g. netops-report-20240324-120000.html
        assert re.match(r"netops-report-\d{8}-\d{6}\.html", name)


# ===========================================================================
# generate_report (convenience wrapper)
# ===========================================================================


class TestGenerateReport:
    def test_returns_dict_with_html(self, tmp_path):
        result = generate_report(
            sections=_make_sections(),
            html_output=None,
        )
        assert "html" in result
        assert isinstance(result["html"], str)

    def test_html_file_written(self, tmp_path):
        out = tmp_path / "test.html"
        generate_report(sections=_make_sections(), html_output=str(out))
        assert out.exists()

    def test_auto_html_output(self, tmp_path):
        generate_report(
            sections=_make_sections(),
            output_dir=str(tmp_path),
            html_output="auto",
        )
        html_files = list(tmp_path.glob("*.html"))
        assert len(html_files) == 1

    def test_overall_alert_in_result(self):
        result = generate_report(sections=_make_sections(), html_output=None)
        assert "overall_alert" in result


# ===========================================================================
# ReportMailer
# ===========================================================================


class TestReportMailer:
    def test_send_plain_smtp(self):
        mailer = ReportMailer(host="smtp.example.com", use_tls=False, use_ssl=False)
        with patch("smtplib.SMTP") as mock_smtp_cls:
            mock_smtp = MagicMock()
            mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
            mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)
            mailer.send(
                recipients=["ops@example.com"],
                subject="Test",
                html_body="<h1>Test</h1>",
            )
            mock_smtp.sendmail.assert_called_once()

    def test_send_with_tls(self):
        mailer = ReportMailer(
            host="smtp.example.com", port=587, username="u", password="p", use_tls=True
        )
        with patch("smtplib.SMTP") as mock_smtp_cls:
            mock_smtp = MagicMock()
            mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
            mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)
            mailer.send(
                recipients=["ops@example.com"],
                subject="Test",
                html_body="<h1>Test</h1>",
            )
            mock_smtp.starttls.assert_called_once()
            mock_smtp.login.assert_called_once_with("u", "p")

    def test_send_with_ssl(self):
        mailer = ReportMailer(
            host="smtp.example.com", port=465, use_ssl=True, use_tls=False
        )
        with patch("smtplib.SMTP_SSL") as mock_smtp_cls:
            mock_smtp = MagicMock()
            mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
            mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)
            mailer.send(
                recipients=["ops@example.com"],
                subject="Test",
                html_body="<h1>Test</h1>",
            )
            mock_smtp.sendmail.assert_called_once()

    def test_send_with_pdf(self):
        mailer = ReportMailer(host="smtp.example.com", use_tls=False, use_ssl=False)
        with patch("smtplib.SMTP") as mock_smtp_cls:
            mock_smtp = MagicMock()
            mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
            mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)
            mailer.send(
                recipients=["ops@example.com"],
                subject="Test",
                html_body="<h1>Test</h1>",
                pdf_attachment=b"%PDF-1.4 fake",
                pdf_filename="report.pdf",
            )
            mock_smtp.sendmail.assert_called_once()
            args = mock_smtp.sendmail.call_args[0]
            assert "report.pdf" in args[2]

    def test_empty_recipients_raises(self):
        mailer = ReportMailer(host="smtp.example.com", use_tls=False)
        with pytest.raises(ValueError, match="recipients"):
            mailer.send(recipients=[], subject="Test", html_body="<h1>x</h1>")

    def test_from_addr_defaults_to_username(self):
        mailer = ReportMailer(host="smtp.example.com", username="netops@example.com")
        assert mailer.from_addr == "netops@example.com"

    def test_from_addr_explicit(self):
        mailer = ReportMailer(
            host="smtp.example.com",
            username="netops@example.com",
            from_addr="alerts@example.com",
        )
        assert mailer.from_addr == "alerts@example.com"

    def test_from_addr_fallback_no_username(self):
        mailer = ReportMailer(host="smtp.example.com")
        assert mailer.from_addr == "netops@localhost"


class TestHtmlToPlain:
    def test_strips_tags(self):
        result = _html_to_plain("<h1>Hello</h1><p>World</p>")
        assert "<" not in result
        assert "Hello" in result
        assert "World" in result

    def test_empty_string(self):
        assert _html_to_plain("") == ""


# ===========================================================================
# ScheduledReport.next_run
# ===========================================================================


class TestScheduledReportNextRun:
    def _make_job(self, frequency: str, time_of_day: str, day_of_week: str | None = None):
        return ScheduledReport(
            collect_fn=lambda: [],
            frequency=frequency,
            time_of_day=time_of_day,
            day_of_week=day_of_week,
            title="Test",
            output_dir=None,
            recipients=None,
            subject=None,
            pdf=False,
        )

    def test_daily_future_today(self):
        now = datetime(2024, 3, 24, 10, 0, 0, tzinfo=timezone.utc)
        job = self._make_job("daily", "14:00")
        nxt = job.next_run(now)
        assert nxt.date() == now.date()
        assert nxt.hour == 14
        assert nxt.minute == 0

    def test_daily_past_time_schedules_tomorrow(self):
        now = datetime(2024, 3, 24, 15, 0, 0, tzinfo=timezone.utc)
        job = self._make_job("daily", "14:00")
        nxt = job.next_run(now)
        assert nxt.date() == (now + timedelta(days=1)).date()

    def test_weekly_correct_day(self):
        # 2024-03-24 is a Sunday (weekday=6)
        now = datetime(2024, 3, 24, 10, 0, 0, tzinfo=timezone.utc)
        job = self._make_job("weekly", "08:00", "monday")
        nxt = job.next_run(now)
        # Next Monday from Sunday should be 2024-03-25
        assert nxt.weekday() == 0
        assert nxt >= now

    def test_weekly_same_day_past_time_next_week(self):
        # 2024-03-25 is a Monday (weekday=0)
        now = datetime(2024, 3, 25, 10, 0, 0, tzinfo=timezone.utc)
        job = self._make_job("weekly", "08:00", "monday")
        nxt = job.next_run(now)
        assert (nxt - now).days >= 6

    def test_next_run_always_in_future(self):
        now = datetime(2024, 3, 24, 12, 0, 0, tzinfo=timezone.utc)
        for freq, dow in [("daily", None), ("weekly", "wednesday")]:
            job = self._make_job(freq, "12:00", dow)
            nxt = job.next_run(now)
            assert nxt > now


# ===========================================================================
# _parse_time
# ===========================================================================


class TestParseTime:
    def test_midnight(self):
        assert _parse_time("00:00") == (0, 0)

    def test_noon(self):
        assert _parse_time("12:00") == (12, 0)

    def test_end_of_day(self):
        assert _parse_time("23:59") == (23, 59)

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError):
            _parse_time("1200")

    def test_invalid_hour_raises(self):
        with pytest.raises(ValueError):
            _parse_time("25:00")

    def test_invalid_minute_raises(self):
        with pytest.raises(ValueError):
            _parse_time("12:60")


# ===========================================================================
# ReportScheduler
# ===========================================================================


class TestReportScheduler:
    def test_schedule_daily_registers_job(self):
        scheduler = ReportScheduler()
        scheduler.schedule_daily(collect_fn=lambda: [], time_of_day="06:00")
        assert len(scheduler._jobs) == 1
        assert scheduler._jobs[0].frequency == "daily"

    def test_schedule_weekly_registers_job(self):
        scheduler = ReportScheduler()
        scheduler.schedule_weekly(
            collect_fn=lambda: [], day_of_week="tuesday", time_of_day="06:00"
        )
        assert len(scheduler._jobs) == 1
        assert scheduler._jobs[0].frequency == "weekly"
        assert scheduler._jobs[0].day_of_week == "tuesday"

    def test_invalid_day_of_week_raises(self):
        scheduler = ReportScheduler()
        with pytest.raises(ValueError, match="day_of_week"):
            scheduler.schedule_weekly(collect_fn=lambda: [], day_of_week="funday")

    def test_stop_signals_event(self):
        scheduler = ReportScheduler()
        scheduler._stop_event.set = MagicMock()
        scheduler.stop()
        scheduler._stop_event.set.assert_called_once()

    def test_start_nonblocking(self):
        scheduler = ReportScheduler()
        scheduler.schedule_daily(collect_fn=lambda: [], time_of_day="03:00")
        scheduler.start(blocking=False)
        assert scheduler._thread is not None
        assert scheduler._thread.is_alive()
        scheduler.stop()
        scheduler._thread.join(timeout=2)

    def test_run_job_calls_collect_fn(self, tmp_path):
        called = threading.Event()

        def collect():
            called.set()
            return []

        gen = ReportGenerator(output_dir=str(tmp_path))
        scheduler = ReportScheduler(generator=gen)
        job = ScheduledReport(
            collect_fn=collect,
            frequency="daily",
            time_of_day="00:00",
            day_of_week=None,
            title="Test",
            output_dir=str(tmp_path),
            recipients=None,
            subject="Test",
            pdf=False,
        )
        scheduler._run_job(job)
        assert called.is_set()

    def test_run_job_sends_email_when_configured(self, tmp_path):
        mock_mailer = MagicMock()
        gen = ReportGenerator(output_dir=str(tmp_path))
        scheduler = ReportScheduler(generator=gen, mailer=mock_mailer)
        job = ScheduledReport(
            collect_fn=lambda: [],
            frequency="daily",
            time_of_day="00:00",
            day_of_week=None,
            title="Test",
            output_dir=str(tmp_path),
            recipients=["ops@example.com"],
            subject="Test Report",
            pdf=False,
        )
        scheduler._run_job(job)
        mock_mailer.send.assert_called_once()
        call_kwargs = mock_mailer.send.call_args[1]
        assert call_kwargs["recipients"] == ["ops@example.com"]
        assert call_kwargs["subject"] == "Test Report"
