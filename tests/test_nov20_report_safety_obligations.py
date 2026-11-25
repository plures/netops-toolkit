"""Original report source, schema and no-fetch obligations, not PDF qualification."""

from __future__ import annotations

import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from netops.ansible import contracts as c
from netops.report.companion import _preserve_source, project_outcome
from netops.report.generator import ReportGenerator, _PdfResources
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import policy as policy


@pytest.mark.parametrize("status", [
    c.OutcomeStatus.FAILED, c.OutcomeStatus.BLOCKED, c.OutcomeStatus.UNSUPPORTED,
    c.OutcomeStatus.CANCELLED,
])
def test_saved_source_status_never_becomes_healthy_when_html_is_rendered(composed, status):
    service, host, request, sources, effects = composed
    source = c.aggregate_outcome(request, (c.TargetOutcome("r1", status, False),))
    projection = project_outcome(c.public_object(c.wire(source)), ("r1",))
    assert projection["source_status"] == status.value
    section = {"name": "saved", "type": "companion", "data": c.wire(source)}
    generator = ReportGenerator()
    report = generator.build_report(sections=[section])
    assert report["overall_alert"] is True
    rendered = generator.generate_html(report)
    assert status.value in rendered
    assert effects.calls == []


@pytest.mark.parametrize("source", ["success", "status", "source_status"])
def test_native_failure_indicators_are_not_erased_from_report_alerts(source):
    value = {"success": False} if source == "success" else {source: "failed"}
    result = ReportGenerator().build_report(sections=[
        {"name": "fixture", "type": "generic", "data": {"nested": [value]}},
    ])
    assert result["overall_alert"] is True


@pytest.mark.parametrize("resource", [
    '<img src="https://outside.invalid/a">',
    '<iframe src="file:///private">',
    '<object data="https://outside.invalid/a">',
    '<p srcset="https://outside.invalid/a">',
    '<p style="@import private">',
    '<style>@import "https://outside.invalid/a";</style>',
    '<a href="file:///private">private</a>',
    '<a href="https://name:secret@outside.invalid/a">private</a>',
])
def test_pdf_resource_safety_rejects_fetch_before_native_renderer(resource):
    # Pure preflight only; no mocked PDF signature or claimed native qualification.
    with pytest.raises(ValueError, match="report-resource-fetch-denied|output-rejected"):
        _PdfResources().feed(resource)


def test_pdf_safe_fragment_and_nonresource_text_are_not_external_fetch_authority():
    _PdfResources().feed('<style>body { color: black; }</style><p>Offline</p><a href="#id">local</a>')
    _PdfResources().feed('<a href="https://outside.invalid/docs">User-selected link, not fetch</a>')


@pytest.mark.parametrize("section", [
    {"name": "x", "type": "generic", "data": {}, "unexpected": True},
    {"name": 5, "type": "generic", "data": {}},
    {"name": "x", "type": "generic", "data": []},
])
def test_native_report_invalid_section_schema_is_not_success(section):
    with pytest.raises(ValueError, match="input-binding-invalid"):
        ReportGenerator().build_report(sections=[section])


def test_native_report_log_sink_failure_does_not_erase_real_render_result():
    generator = ReportGenerator()
    report = generator.build_report()
    with patch("netops.report.generator.logger.info", side_effect=RuntimeError("PRIVATE_LOG_FAILURE")):
        content = generator.generate_html(report)
    assert content.startswith("<!DOCTYPE html>")
    assert "PRIVATE_LOG_FAILURE" not in content


@pytest.mark.parametrize("field,value", [
    ("source_status", 5), ("findings", {}), ("errors", {}),
    ("cleanup", {"status": "failed", "remaining_refs": [4], "errors": []}),
])
def test_malformed_rendered_source_projection_is_not_silently_accepted(composed, field, value):
    service, host, request, sources, effects = composed
    source = c.aggregate_outcome(request, (c.TargetOutcome("r1", c.OutcomeStatus.FAILED, False),))
    projection = c.wire(project_outcome(c.public_object(c.wire(source))))
    projection[field] = value
    rendered = c.aggregate_outcome(
        request, (c.TargetOutcome("r1", c.OutcomeStatus.SUCCEEDED, True),), (c.StepOutcome(
            "render", c.OutcomeStatus.SUCCEEDED, True,
            native_payload=c.public_object({"sections": [{
                "name": "source", "type": "companion", "data": projection,
            }]}),
        ),),
    )
    with pytest.raises(c.ContractError):
        _preserve_source(rendered)


def test_missing_selected_source_target_is_explicitly_blocked_not_healthy(composed):
    service, host, request, sources, effects = composed
    request = replace(request, operation="report.render", mode=c.Mode.OUTPUT, scope=c.Scope(()))
    source = c.aggregate_outcome(request, ())
    projected = project_outcome(c.public_object(c.wire(source)), ("r1",))
    assert projected["source_status"] == "blocked"
    assert projected["missing_count"] == 1
    assert projected["coverage"][0]["missing"] is True


def test_duplicate_selected_saved_targets_fail_strict_contract(composed):
    service, host, request, sources, effects = composed
    target = c.TargetOutcome("r1", c.OutcomeStatus.SUCCEEDED, True)
    with pytest.raises(c.ContractError):
        source = c.aggregate_outcome(request, (target, target))
        project_outcome(c.public_object(c.wire(source)))


def test_native_report_nonregular_input_rejected_before_parse_or_output(tmp_path):
    from netops.report.generator import main

    source = tmp_path / "source.json"
    source.write_bytes(b'{"sections":[]}')
    output = tmp_path / "not-created.html"
    # Unit guard fault injection only; not real FIFO/device/platform qualification.
    with patch("netops.report.generator.os.fstat", return_value=SimpleNamespace(st_mode=stat.S_IFIFO)):
        result = main(["--input", str(source), "--output", str(output)])
    assert result != 0 and not output.exists()
    assert source.read_bytes() == b'{"sections":[]}'


def test_native_report_symlink_destination_guard_preserves_existing_bytes(tmp_path):
    destination = tmp_path / "output.html"
    destination.write_bytes(b"PRIOR_UNCHANGED_OUTPUT")
    original = Path.is_symlink

    def symlink(path):
        return path == destination or original(path)

    # Pure fault injection: no Windows symlink privilege is requested or claimed.
    with patch.object(Path, "is_symlink", symlink):
        with pytest.raises(ValueError, match="output-rejected"):
            ReportGenerator().generate_html(
                ReportGenerator().build_report(), output_path=str(destination),
            )
    assert destination.read_bytes() == b"PRIOR_UNCHANGED_OUTPUT"


def test_native_report_late_destination_guard_rejects_after_real_temp_write(tmp_path):
    destination = tmp_path / "output.html"
    sentinel = b"PRIOR_UNCHANGED_OUTPUT"
    destination.write_bytes(sentinel)
    generator = ReportGenerator()
    report = generator.build_report(title="Late destination safety")
    intended = generator.generate_html(report).encode("utf-8")
    original = Path.is_symlink
    acquired = []
    rejection = None
    receipt = None

    def delayed_destination(path):
        if path != destination:
            return original(path)
        temporary = list(tmp_path.glob(".netops-report-*"))
        if not temporary:
            return False
        # Observe real native fdopen/write/flush/fsync bytes, not a writer fake.
        assert len(temporary) == 1
        assert temporary[0].read_bytes() == intended
        acquired.append(temporary[0])
        return True

    # Only the destination observation is injected; no symlink privilege needed.
    with patch.object(Path, "is_symlink", delayed_destination):
        try:
            receipt = generator.generate_html(report, output_path=str(destination))
        except ValueError as error:
            rejection = error

    # These behavioral assertions, not query counts, bear the omission control.
    assert destination.read_bytes() == sentinel
    assert set(tmp_path.iterdir()) == {destination}
    assert acquired and all(not path.exists() for path in acquired)
    assert receipt is None
    assert rejection is not None and str(rejection) == "output-rejected"


def test_native_report_unchanged_destination_publishes_exact_html_without_temp(tmp_path):
    destination = tmp_path / "output.html"
    destination.write_bytes(b"PRIOR_UNCHANGED_OUTPUT")
    generator = ReportGenerator()
    report = generator.build_report(title="Unchanged destination")
    intended = generator.generate_html(report)

    receipt = generator.generate_html(report, output_path=str(destination))

    assert receipt == intended
    assert destination.read_bytes() == intended.encode("utf-8")
    assert set(tmp_path.iterdir()) == {destination}
