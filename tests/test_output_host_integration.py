"""Owned host output controls, never policy or platform qualification."""

from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from tests.test_nov20_independent_public_output import replace_input
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed
from tests.test_workflow_execution import policy as policy


@pytest.mark.parametrize("qualification", [
    "controller_qualified", "route_qualified", "credential_channel_qualified",
])
def test_device_work_still_requires_each_qualified_host_fact(composed, qualification):
    service, host, request, sources, effects = composed
    sources.value = replace(sources.value, **{qualification: False})
    with pytest.raises(RuntimeError, match="dependency-not-ready"):
        host.review(service, request)
    assert effects.calls == []
    assert service.execute(request).status != c.OutcomeStatus.SUCCEEDED
    assert effects.calls == []


def test_empty_device_operation_is_not_empty_local_report_coverage(composed):
    service, host, request, sources, effects = composed
    with pytest.raises(c.ContractError, match="invalid-request"):
        replace(request, scope=c.Scope(()))
    assert effects.calls == []


@pytest.mark.parametrize("failure", ["render", "preflight"])
def test_failed_report_keeps_minimized_source_facts_without_publishing(
    output_composed, monkeypatch, failure,
):
    from netops.report.generator import ReportGenerator

    service, host, sources, effects, filesystem, select = output_composed
    request = select("report.render")
    error = c.SafeError(c.ErrorCategory.EXECUTION, c.ReasonCode.APPLY_FAILED, c.Stage.APPLY)
    source = c.aggregate_outcome(
        request,
        (c.TargetOutcome(
            "r1", c.OutcomeStatus.FAILED, True, remote_state="uncertain",
            native_payload=c.public_object({"raw": "NONREPORT_PRIVATE_SOURCE"}),
            errors=(error,),
        ),),
        cleanup=c.CleanupOutcome("failed", ("owned-source-cleanup",), (error,)),
    )
    request = replace_input(sources, request, "outcomes", c.canonical_bytes(source))
    grant = host.review(service, request)
    assert b"NONREPORT_PRIVATE" not in c.canonical_bytes(host._report_sources[request.operation_id])
    if failure == "preflight":
        filesystem.fail_validation = True
    else:
        def fail_render(*args, **kwargs):
            raise RuntimeError("NONREPORT_PRIVATE_RENDER")

        monkeypatch.setattr(ReportGenerator, "generate_html", fail_render)
    outcome = service.execute(request, grant)
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert outcome.cleanup.status == "failed"
    assert "owned-source-cleanup" in outcome.cleanup.remaining_refs
    assert any(item.reason == c.ReasonCode.APPLY_FAILED for item in outcome.errors)
    section = outcome.steps[0].native_payload["sections"][0]["data"]
    assert section["remote_uncertain"] is True
    assert section["source_status"] == "failed"
    assert b"NONREPORT_PRIVATE" not in c.canonical_bytes(outcome)
    assert not outcome.artifacts and filesystem.bindings == [] and effects.calls == []
    assert request.operation_id not in host._report_sources
    assert service.execute(request, grant).status != c.OutcomeStatus.SUCCEEDED
    assert filesystem.bindings == []


def test_nonempty_selected_report_still_requires_source_coverage(output_composed):
    service, host, sources, effects, filesystem, select = output_composed
    request = select("report.render")
    source = c.aggregate_outcome(
        replace(request, scope=c.Scope(())), (),
        (c.StepOutcome("offline", c.OutcomeStatus.SUCCEEDED, True),),
    )
    request = replace_input(sources, request, "outcomes", c.canonical_bytes(source))
    with pytest.raises(RuntimeError, match="input-binding-invalid"):
        host.review(service, request)
    assert filesystem.bindings == [] and effects.calls == []


def test_unauthorized_output_does_not_enter_native_renderer(output_composed, monkeypatch):
    from netops.report.generator import ReportGenerator

    service, host, sources, effects, filesystem, select = output_composed

    def reject_native_entry(*args, **kwargs):
        pytest.fail("Unauthorized output entered the renderer")

    monkeypatch.setattr(ReportGenerator, "generate_html", reject_native_entry)
    outcome = service.execute(select("report.render"))
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert not outcome.artifacts and filesystem.bindings == [] and effects.calls == []
