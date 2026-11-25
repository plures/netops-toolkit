"""AC-010 local source-only PDF/CLI proof; never native-library qualification."""

from __future__ import annotations

import sys
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from netops.ansible import contracts as c
from netops.ansible.execution import ExecutionHost, _Rejected
from netops.report import generator as g
from tests.test_nov20_independent_public_output import replace_input
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed
from tests.test_workflow_execution import policy as policy


def source_only_pdf_port(monkeypatch, result=b"%PDF-SOURCE-ONLY\n%%EOF", fetch=None):
    """Inert renderer boundary, explicitly not actual PDF/platform evidence."""
    calls = []

    class Renderer:
        def __init__(self, *, string, url_fetcher):
            calls.append(string)
            self.fetcher = url_fetcher

        def write_pdf(self):
            if fetch is not None:
                try:
                    self.fetcher(fetch)
                except ValueError:
                    pass  # Native renderer may swallow fetch refusal: still reject.
            if isinstance(result, BaseException):
                raise result
            return result

    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=Renderer))
    return calls


@pytest.mark.parametrize("resource", [
    '<img src="https://outside.invalid/x">',
    '<img src="file:///private">',
    '<style>p{background:url(https://outside.invalid/x)}</style>',
    '<style>@import "file:///private";</style>',
    '<a href="javascript:unsafe">x</a>',
])
def test_source_only_pdf_refuses_external_resources_before_renderer(monkeypatch, resource):
    calls = source_only_pdf_port(monkeypatch)
    generator = g.ReportGenerator()
    monkeypatch.setattr(generator, "generate_html", lambda report: resource)
    with pytest.raises(ValueError, match="report-resource-fetch-denied|output-rejected"):
        generator.generate_pdf(generator.build_report())
    assert calls == []


@pytest.mark.parametrize("url", ["https://outside.invalid/private", "file:///private"])
def test_source_only_pdf_rejects_caught_fetch_failure(monkeypatch, url):
    calls = source_only_pdf_port(monkeypatch, fetch=url)
    generator = g.ReportGenerator()
    with pytest.raises(ValueError, match="report-resource-fetch-denied"):
        generator.generate_pdf(generator.build_report())
    assert len(calls) == 1


@pytest.mark.parametrize("result", [None, "%PDF-SOURCE-ONLY\n%%EOF", b"not-pdf", b"%PDF-incomplete"])
def test_source_only_pdf_malformed_renderer_result_never_writes(monkeypatch, tmp_path, result):
    source_only_pdf_port(monkeypatch, result=result)
    destination = tmp_path / "not-created.pdf"
    generator = g.ReportGenerator()
    with pytest.raises(ValueError, match="render-failed"):
        generator.generate_pdf(generator.build_report(), str(destination))
    assert not destination.exists()


def test_source_only_pdf_renderer_failure_never_writes(monkeypatch, tmp_path):
    source_only_pdf_port(monkeypatch, result=RuntimeError("PRIVATE_RENDERER_FAILURE"))
    destination = tmp_path / "not-created.pdf"
    generator = g.ReportGenerator()
    with pytest.raises(RuntimeError):
        generator.generate_pdf(generator.build_report(), str(destination))
    assert not destination.exists()


def test_source_only_pdf_exact_dispatch_output_binding_and_error(monkeypatch, tmp_path):
    content = b"%PDF-SOURCE-ONLY\n%%EOF"
    calls = source_only_pdf_port(monkeypatch, result=content)
    generator = g.ReportGenerator(output_dir=str(tmp_path))
    report = generator.build_report()
    assert generator.generate_pdf(report, "source-port") == content
    assert (tmp_path / "source-port.pdf").read_bytes() == content
    assert len(calls) == 1
    write = Mock(side_effect=PermissionError("PRIVATE_OUTPUT_FAILURE"))
    monkeypatch.setattr(g, "_write_output", write)
    with pytest.raises(PermissionError):
        generator.generate_pdf(report, "denied")
    assert not (tmp_path / "denied.pdf").exists()
    assert write.call_args.args == (tmp_path / "denied.pdf", content)


@pytest.mark.parametrize("format", ["html", "pdf"])
@pytest.mark.parametrize("output", [False, True])
def test_native_cli_preview_has_exact_nonexecuting_wire(monkeypatch, tmp_path, capsys, format, output):
    source = tmp_path / "source.json"
    source.write_bytes(b'{"sections":[{"name":"saved","type":"generic","data":{"status":"failed"}}]}')
    destination = tmp_path / ("not-created." + format)
    bomb = Mock(side_effect=AssertionError("preview rendered"))
    monkeypatch.setattr(g.ReportGenerator, "generate_html", bomb)
    monkeypatch.setattr(g.ReportGenerator, "generate_pdf", bomb)
    argv = ["--input", str(source), "--preview", "--format", format]
    if output:
        argv += ["--output", str(destination)]
    assert g.main(argv) == 5
    expected = (
        '{"execution_performed": false, "format": "' + format
        + '", "output_requested": ' + ("true" if output else "false")
        + ', "sections": 1, "source_exit": 5}\n'
    )
    captured = capsys.readouterr()
    assert captured.out == expected and captured.err == ""
    assert not destination.exists()
    bomb.assert_not_called()


@pytest.mark.parametrize("data", [
    b'{"other":[]}', b'{"sections":{}}', b'{"sections":[4]}',
    b'{"sections":[],"sections":[]}', b'{"sections":[{"name":"x","type":"generic","data":[]}]}',
    b'not-json',
])
def test_native_cli_input_error_exact_exit_and_safe_error(tmp_path, capsys, data):
    source = tmp_path / "source.json"
    source.write_bytes(data)
    destination = tmp_path / "not-created.html"
    assert g.main(["--input", str(source), "--output", str(destination)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "input-binding-invalid or render-failed: validate saved sections and explicit output.\n"
    )
    assert not destination.exists() and source.read_bytes() == data


@pytest.mark.parametrize(("exception", "exit_code", "stderr"), [
    (ImportError("PRIVATE_ERROR"), 3,
     "dependency-not-ready: install the selected report/report-pdf extra in the consuming environment.\n"),
    (PermissionError("PRIVATE_ERROR"), 5,
     "render-failed: check the selected input/output and native PDF libraries.\n"),
    (ValueError("PRIVATE_ERROR"), 5,
     "input-binding-invalid or render-failed: validate saved sections and explicit output.\n"),
    (RuntimeError("PRIVATE_ERROR"), 5,
     "render-failed: inspect the trusted template and selected renderer.\n"),
])
def test_native_cli_render_errors_keep_exact_exit_and_minimal_error(
    monkeypatch, tmp_path, capsys, exception, exit_code, stderr,
):
    source = tmp_path / "source.json"
    source.write_bytes(b'{"sections":[]}')
    destination = tmp_path / "not-created.html"
    monkeypatch.setattr(g.ReportGenerator, "generate_html", Mock(side_effect=exception))
    assert g.main(["--input", str(source), "--output", str(destination)]) == exit_code
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == stderr
    assert "PRIVATE_ERROR" not in captured.err
    assert not destination.exists()


def test_native_cli_real_html_stdout_and_saved_output_match(tmp_path, capsys):
    source = tmp_path / "source.json"
    source.write_bytes(b'{"sections":[{"name":"<script>x</script>","type":"generic","data":{}}]}')
    assert g.main(["--input", str(source), "--title", "Literal report"]) == 0
    html = capsys.readouterr().out
    assert html.startswith("<!DOCTYPE html>")
    assert "<script>x</script>" not in html and "&lt;script&gt;x&lt;/script&gt;" in html
    destination = tmp_path / "actual.html"
    assert g.main(["--input", str(source), "--output", str(destination)]) == 0
    assert destination.read_bytes().startswith(b"<!DOCTYPE html>")
    assert capsys.readouterr().out == ""


def test_native_cli_pdf_requires_explicit_destination_before_dispatch(monkeypatch, tmp_path, capsys):
    source = tmp_path / "source.json"
    source.write_bytes(b'{"sections":[]}')
    bomb = Mock(side_effect=AssertionError("unselected PDF dispatched"))
    monkeypatch.setattr(g.ReportGenerator, "generate_pdf", bomb)
    assert g.main(["--input", str(source), "--format", "pdf"]) == 5
    assert capsys.readouterr().err == (
        "input-binding-invalid or render-failed: validate saved sections and explicit output.\n"
    )
    bomb.assert_not_called()


def test_source_only_public_pdf_uses_actual_consent_then_exact_renderer_port(
    output_composed, monkeypatch,
):
    service, host, sources, effects, filesystem, select = output_composed
    request = replace(select("report.render"), output_intent=c.OutputIntent(("pdf",), "owned"))
    sources.value = replace(sources.value, request=request)
    content = b"%PDF-SOURCE-ONLY\n%%EOF"
    calls = source_only_pdf_port(monkeypatch, result=content)
    grant = host.review(service, request)
    assert filesystem.bindings == [] and effects.calls == []
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.SUCCEEDED
    assert len(outcome.artifacts) == len(filesystem.bindings) == len(calls) == 1
    assert filesystem.content == content
    assert effects.calls == []
    assert service.execute(request, grant).status != c.OutcomeStatus.SUCCEEDED
    assert len(filesystem.bindings) == 1


@pytest.mark.parametrize("content", [b'{}', b'{"schema_version":"999"}', b'{"x":1,"x":2}'])
def test_public_report_malformed_saved_input_never_reviews_or_publishes(output_composed, content):
    service, host, sources, effects, filesystem, select = output_composed
    request = replace_input(sources, select("report.render"), "outcomes", content)
    assert service.execute(request).status != c.OutcomeStatus.SUCCEEDED
    with pytest.raises((c.ContractError, _Rejected)):
        host.review(service, request)
    assert filesystem.bindings == [] and effects.calls == []


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "nonobject"])
def test_actual_loaded_report_input_guard_rejects_missing_duplicate_malformed(
    output_composed, mutation,
):
    service, host, sources, effects, filesystem, select = output_composed
    from netops.ansible.workflows import bind_settings, hydrate_inputs
    from tests.test_workflow_execution import Clock

    request = select("report.render")
    loaded = bind_settings(
        request, hydrate_inputs(request, sources.value.sources, Clock()), sources.value.settings,
    )
    plan = service.preview(request, loaded)
    inputs = tuple(item for item in plan.native_payload["inputs"] if item["kind"] == "outcomes")
    if mutation == "missing":
        inputs = ()
    elif mutation == "duplicate":
        inputs = inputs + inputs
    else:
        inputs = (c.public_object({"kind": "outcomes", "value": []}),)
    changed = replace(plan, native_payload=c.public_object({"inputs": inputs}))
    with pytest.raises(_Rejected):
        ExecutionHost._input_value(changed, "outcomes")
    assert filesystem.bindings == [] and effects.calls == []


@pytest.mark.parametrize("kinds", [("yaml",), ("json",), ("html", "pdf"), ()])
def test_actual_public_report_wrong_format_never_obtains_consent(output_composed, kinds):
    service, host, sources, effects, filesystem, select = output_composed
    request = replace(select("report.render"), output_intent=c.OutputIntent(kinds, "owned"))
    sources.value = replace(sources.value, request=request)
    with pytest.raises((c.ContractError, _Rejected)):
        host.review(service, request)
    assert service.execute(request).status != c.OutcomeStatus.SUCCEEDED
    assert filesystem.bindings == [] and effects.calls == []


@pytest.mark.parametrize("preview", [True, False])
def test_native_cli_actual_saved_outcome_retains_partial_exit(tmp_path, capsys, preview):
    from tests.test_nov20_reviewed_nonempty_wire import EXPECTED_OUTCOME

    source = tmp_path / "source.json"
    source.write_bytes(EXPECTED_OUTCOME)
    output = tmp_path / "actual.html"
    argv = ["--input", str(source), "--output", str(output)]
    if preview:
        argv += ["--preview"]
    assert g.main(argv) == 4
    captured = capsys.readouterr()
    assert captured.err == ""
    if preview:
        assert captured.out == (
            '{"execution_performed": false, "format": "html", "output_requested": true, '
            '"sections": 1, "source_exit": 4}\n'
        )
        assert not output.exists()
    else:
        assert captured.out == ""
        assert b'"source_status": "partial"' in output.read_bytes()


def test_source_only_native_cli_pdf_dispatches_explicit_destination(monkeypatch, tmp_path, capsys):
    source = tmp_path / "source.json"
    source.write_bytes(b'{"sections":[]}')
    output = tmp_path / "source-port.pdf"
    content = b"%PDF-SOURCE-ONLY\n%%EOF"
    calls = source_only_pdf_port(monkeypatch, result=content)
    assert g.main(["--input", str(source), "--format", "pdf", "--output", str(output)]) == 0
    assert output.read_bytes() == content and len(calls) == 1
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("preview", [True, False])
def test_native_cli_unexpected_source_error_does_not_leak_or_render(
    monkeypatch, tmp_path, capsys, preview,
):
    output = tmp_path / "not-created.html"
    monkeypatch.setattr(g, "_read_input", Mock(side_effect=RuntimeError("PRIVATE_INPUT_ERROR")))
    argv = ["--input", str(tmp_path / "source.json"), "--output", str(output)]
    if preview:
        argv += ["--preview"]
    assert g.main(argv) == 5
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "render-failed: inspect the trusted template and selected renderer.\n"
    assert not output.exists()


def test_native_cli_missing_source_has_exact_os_error_exit(tmp_path, capsys):
    output = tmp_path / "not-created.html"
    assert g.main(["--input", str(tmp_path / "missing.json"), "--output", str(output)]) == 5
    assert capsys.readouterr().err == (
        "render-failed: check the selected input/output and native PDF libraries.\n"
    )
    assert not output.exists()


def test_actual_admitted_render_rejects_invalid_format_before_renderer(output_composed, monkeypatch):
    service, host, sources, effects, filesystem, select = output_composed
    request = select("report.render")
    grant = host.review(service, request)
    original_entry = host._entry
    entered = []

    def mutate_after_real_entry(permit, binding, plan, effect, kind):
        original_entry(permit, binding, plan, effect, kind)
        entered.append(kind)
        object.__setattr__(plan, "output_intent", c.OutputIntent(("yaml",), "owned"))

    bomb = Mock(side_effect=AssertionError("invalid format dispatched renderer"))
    monkeypatch.setattr(host, "_entry", mutate_after_real_entry)
    monkeypatch.setattr(g.ReportGenerator, "generate_html", bomb)
    monkeypatch.setattr(g.ReportGenerator, "generate_pdf", bomb)
    outcome = service.execute(request, grant)
    assert entered == ["render"]
    assert outcome.status != c.OutcomeStatus.SUCCEEDED and outcome.exit_code != 0
    assert outcome.artifacts == () and filesystem.bindings == [] and effects.calls == []
    bomb.assert_not_called()


def test_actual_input_value_nonsequence_guard_from_nonempty_plan(output_composed):
    from netops.ansible.workflows import bind_settings, hydrate_inputs
    from tests.test_workflow_execution import Clock

    service, host, sources, effects, filesystem, select = output_composed
    request = select("report.render")
    loaded = bind_settings(
        request, hydrate_inputs(request, sources.value.sources, Clock()), sources.value.settings,
    )
    plan = service.preview(request, loaded)
    malformed = replace(plan, native_payload=c.public_object({"inputs": 4}))
    with pytest.raises(c.ContractError):
        ExecutionHost._input_value(malformed, "outcomes")
    assert filesystem.bindings == [] and effects.calls == []
