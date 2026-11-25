"""O04 author regressions; not independent acceptance or platform qualification."""

from __future__ import annotations

import hashlib
import json
import logging
import sys
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from netops.ansible import contracts as c
from netops.report.companion import project_outcome
from netops.report.generator import ReportGenerator
from tests.test_companion_compare import bound, input_source
from tests.test_companion_compare import pure_composition as pure_composition
from tests.test_workflow_contracts import policy as policy
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed


def test_html_j2_escapes_title_and_unknown_section_json():
    generator = ReportGenerator()
    data = generator.build_report(
        title='<img src=x onerror="alert(1)">',
        sections=[{"name": "<script>bad()</script>", "type": "custom",
                   "data": {"value": "</pre><script>bad()</script>"}}],
    )
    html = generator.generate_html(data)
    assert '<img src=x' not in html
    assert '<script>bad()' not in html
    assert "&lt;img" in html


def test_native_report_cli_is_real_and_preview_does_not_render(tmp_path, capsys):
    from netops.report import generator

    source = tmp_path / "sections.json"
    source.write_text('{"sections":[]}', encoding="utf-8")
    with patch.object(ReportGenerator, "generate_html", side_effect=AssertionError("render")):
        assert generator.main(["--input", str(source), "--preview"]) == 0
    assert "execution_performed" in capsys.readouterr().out


def test_native_report_source_failure_survives_successful_html(tmp_path, capsys):
    from netops.report import generator

    source = tmp_path / "sections.json"
    source.write_text(
        '{"sections":[{"name":"health","type":"custom",'
        '"data":{"results":[{"success":false}],"overall_alert":false}}]}',
        encoding="utf-8",
    )
    assert generator.main(["--input", str(source)]) == 5
    assert "<!DOCTYPE html>" in capsys.readouterr().out


@pytest.mark.parametrize("key", ["password", "private_key", "ansible_password"])
def test_native_report_refuses_credentials_without_rendering_or_leaking(key):
    generator = ReportGenerator()
    with pytest.raises(ValueError) as error:
        generator.build_report(sections=[
            {"name": "custom", "type": "custom", "data": {key: "O04_SECRET_SENTINEL"}},
        ])
    assert "O04_SECRET_SENTINEL" not in str(error.value)


def test_native_report_drops_raw_configuration_payloads():
    generator = ReportGenerator()
    report = generator.build_report(sections=[
        {"name": "health", "type": "custom",
         "data": {"raw": "O04_RAW_SENTINEL", "config": "O04_CONFIG_SENTINEL",
                  "total": 10**30}},
    ])
    html = generator.generate_html(report)
    assert "O04_RAW_SENTINEL" not in html
    assert "O04_CONFIG_SENTINEL" not in html
    assert str(10**30) in html


def test_auto_output_with_relative_native_directory_is_not_double_prefixed(tmp_path, monkeypatch):
    from netops.report.generator import generate_report

    monkeypatch.chdir(tmp_path)
    generate_report([], output_dir="reports")
    assert len(list((tmp_path / "reports").glob("*.html"))) == 1
    assert not (tmp_path / "reports/reports").exists()


def test_actual_pdf_probe_is_truthfully_blocked_when_dependency_import_is_denied():
    from netops.report.generator import probe_pdf

    with patch.dict(sys.modules, {"weasyprint": None}):
        result = probe_pdf()
    assert result["ready"] is False
    assert result["reason"] == "dependency-not-ready"


def mixed_source(request):
    selected = replace(request, operation="health.gather", scope=c.Scope(("r1", "r2")))
    return c.aggregate_outcome(selected, (
        c.TargetOutcome("r1", c.OutcomeStatus.SUCCEEDED, True, changed=True,
                        native_payload={"raw": "O04_RAW_SENTINEL"}),
        c.TargetOutcome("r2", c.OutcomeStatus.BLOCKED, False,
                        unapplied_effects=("gather",)),
    ))


def test_companion_projection_preserves_mixed_missing_and_native_private_payload_minimization(
    pure_composition,
):
    _, request = pure_composition
    source = mixed_source(request)
    projected = project_outcome(c.public_value(c.wire(source)), ("r1", "r2", "r3"))
    assert projected["source_status"] == "partial"
    assert projected["source_exit_code"] == 4
    assert projected["selected_count"] == 3
    assert projected["counts"]["succeeded"] == 1
    assert projected["counts"]["blocked"] == 2
    assert projected["missing_count"] == 1
    assert projected["coverage"][1]["attempted"] is False
    assert projected["changed"] is True
    assert "O04_RAW_SENTINEL" not in c.canonical_bytes(projected).decode()


def test_report_preview_has_no_renderer_files_clock_or_log_effect(pure_composition):
    service, request = pure_composition
    source = mixed_source(request)
    request = replace(request, operation="report.render", scope=c.Scope(("r1", "r2")))
    request, loaded = bound(request, input_source("outcomes", c.wire(source), fmt="json"))
    with patch.object(ReportGenerator, "generate_html", side_effect=AssertionError("renderer")), \
            patch("builtins.open", side_effect=AssertionError("read")), \
            patch("time.monotonic", side_effect=AssertionError("clock")), \
            patch("logging.Logger._log", side_effect=AssertionError("log")):
        plan = service.preview(request, loaded)
    assert plan.native_payload["report"]["source_status"] == "partial"
    assert plan.native_payload["report"]["coverage_complete"] is True
    assert plan.effects == ()


def test_actual_native_builder_preserves_companion_source_failure(pure_composition):
    _, request = pure_composition
    source = mixed_source(request)
    generator = ReportGenerator()
    report = generator.build_report(sections=[{
        "name": "Selected outcomes", "type": "companion",
        "data": json.loads(c.canonical_bytes(source)),
    }])
    assert report["overall_alert"] is True
    assert report["sections"][0]["data"]["source_status"] == "partial"
    html = generator.generate_html(report)
    assert '"source_status": "partial"' in html
    assert "O04_RAW_SENTINEL" not in html


def test_pdf_fetch_denial_is_load_bearing_even_if_library_swallows_callback_error(monkeypatch):
    """This unit driver is deliberately not a real PDF qualification."""
    class Driver:
        def __init__(self, *, string, url_fetcher):
            try:
                url_fetcher("https://forbidden.invalid/")
            except ValueError:
                pass

        def write_pdf(self):
            return b"%PDF-unit-fake\n%%EOF\n"

    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=Driver))
    generator = ReportGenerator()
    with pytest.raises(ValueError, match="report-resource-fetch-denied"):
        generator.generate_pdf(generator.build_report())


def test_pdf_never_accepts_html_disguised_as_pdf(monkeypatch):
    class Driver:
        def __init__(self, **kwargs):
            pass

        def write_pdf(self):
            return b"<html>not a PDF</html>"

    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=Driver))
    generator = ReportGenerator()
    with pytest.raises(ValueError, match="render-failed"):
        generator.generate_pdf(generator.build_report())


def test_report_io_metric_and_log_are_paired_safe_and_sink_cannot_erase_html(caplog):
    from netops.report import generator

    renderer = ReportGenerator()
    report = renderer.build_report()
    before = generator._COUNTS[("html", "succeeded")]
    with caplog.at_level(logging.INFO, logger="netops.report.generator"):
        expected = renderer.generate_html(report)
    records = [record for record in caplog.records if getattr(record, "boundary", None) == "html"]
    assert [record.outcome for record in records] == ["started", "succeeded"]
    assert all(record.metric == "netops.report.io.count" for record in records)
    assert all(record.metric_dimensions == {"boundary": "html", "outcome": record.outcome}
               for record in records)
    assert generator._COUNTS[("html", "succeeded")] == before + 1
    with patch.object(generator.logger, "info", side_effect=KeyboardInterrupt):
        assert renderer.generate_html(report) == expected


def test_unified_cli_returns_report_status_and_preview_skips_logging(monkeypatch):
    import netops.__main__ as cli

    monkeypatch.setattr(sys, "argv", ["netops", "report", "--preview", "--input", "chosen"])
    with patch("netops.report.generator.main", return_value=4) as report_main, \
            patch("netops.logging_setup.setup_logging", side_effect=AssertionError("logging")):
        assert cli.main() == 4
    report_main.assert_called_once_with(["--preview", "--input", "chosen"])


@pytest.mark.parametrize("source_details", [False, True])
def test_real_A02_admission_publication_retains_failed_source_and_cleanup(output_composed, source_details):
    """Actual broker/store/native HTML with inert filesystem; not OS qualification."""
    service, host, sources, effects, filesystem, select = output_composed
    request = select("report.render")
    error = c.SafeError(
        c.ErrorCategory.EXECUTION, c.ReasonCode.READING_UNAVAILABLE, c.Stage.EVALUATE,
        target_id="r1", next_action="Inspect the selected source.",
    )
    source = c.aggregate_outcome(
        replace(request, operation="health.gather", mode=c.Mode.OBSERVE),
        (c.TargetOutcome(
            "r1", c.OutcomeStatus.FAILED if source_details else c.OutcomeStatus.BLOCKED,
            source_details, errors=(error,) if source_details else (),
        ),),
        cleanup=c.CleanupOutcome("failed", ("protected-ref",), (error,))
        if source_details else c.CleanupOutcome(),
    )
    content = c.canonical_bytes(source)
    ref = c.InputRef("outcomes", "owned-outcomes", hashlib.sha256(content).hexdigest())
    request = replace(request, inputs=tuple(
        ref if item.kind == "outcomes" else item for item in request.inputs
    ))
    sources.value = replace(
        sources.value, request=request,
        sources=tuple(
            c.InputSource(ref, "json", content, "parser-1", "vendor-1")
            if item.source.kind == "outcomes" else item for item in sources.value.sources
        ),
    )
    grant = host.review(service, request)
    result = service.execute(request, grant)
    assert filesystem.content.startswith(b"<!DOCTYPE html>")
    assert len(result.artifacts) == len(filesystem.bindings) == 1
    assert result.status == (c.OutcomeStatus.FAILED if source_details else c.OutcomeStatus.BLOCKED)
    assert result.exit_code == (5 if source_details else 3)
    assert result.changed is True
    if source_details:
        assert result.errors[0].reason == c.ReasonCode.READING_UNAVAILABLE
        assert result.cleanup.status == "failed"
        assert result.cleanup.remaining_refs == ("protected-ref",)
    assert effects.calls == []
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(filesystem.bindings) == 1
