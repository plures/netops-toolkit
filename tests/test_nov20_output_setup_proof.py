"""Independent original O03/O04 admission guards; external effects stay inert."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.settings import AnsibleSettings
from tests.test_nov20_independent_public_output import replace_input
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed
from tests.test_workflow_execution import policy as policy


def local_only(sources):
    sources.value = replace(
        sources.value,
        controller_qualified=False,
        route_qualified=False,
        credential_channel_qualified=False,
        readiness=c.ReadinessProjection("ready", "not-requested", "not-requested"),
        settings=replace(sources.value.settings, ansible=AnsibleSettings(enabled=False)),
    )


def generated_request(sources):
    content = json.dumps({
        "results": [{
            "host": "r1", "device_type": "cisco_ios", "success": True,
            "timestamp": "2026-11-20T06:30:00Z",
            "checks": {"cpu": {"alert": True, "usage_percent": 99}},
        }],
    }).encode()
    ref = c.InputRef("findings", "owned-findings", hashlib.sha256(content).hexdigest())
    request = replace(
        sources.value.request, operation="compare.generate", mode=c.Mode.OUTPUT,
        inputs=(ref,), output_intent=c.OutputIntent(("yaml",), "owned"),
    )
    observation = c.Observation(
        "bound-observation", "r1", c.digest(request.context), request.context.route_digest,
        request.context.controller_id, ref, ref.digest, "2026-11-20T06:30:00Z", 0.0,
    )
    sources.value = replace(
        sources.value, request=request,
        sources=(c.InputSource(
            ref, "json", content, "parser-1", "vendor-1", observations=(observation,),
        ),),
    )
    return request


@pytest.mark.parametrize("operation", ["scan.discover", "health.gather", "config.collect"])
def test_empty_device_scope_is_not_local_offline_report_permission(composed, operation):
    service, host, request, sources, effects = composed
    local_only(sources)
    with pytest.raises(c.ContractError):
        replace(request, operation=operation, scope=c.Scope(()))
    assert effects.calls == []


@pytest.mark.parametrize("qualification", [
    "controller_qualified", "route_qualified", "credential_channel_qualified",
])
def test_nonlocal_device_work_still_requires_each_qualification(composed, qualification):
    service, host, request, sources, effects = composed
    sources.value = replace(sources.value, **{qualification: False})
    outcome = service.execute(request)
    assert outcome.status == c.OutcomeStatus.BLOCKED
    assert outcome.exit_code != 0
    assert effects.calls == [] and outcome.artifacts == ()


@pytest.mark.parametrize("mutation", ["request-mode", "controller", "root", "generation", "source"])
def test_report_grant_rejects_changed_exact_bound_inputs_without_publish(output_composed, mutation):
    service, host, sources, effects, filesystem, select = output_composed
    request = select("report.render")
    local_only(sources)
    grant = host.review(service, request)
    changed = request
    if mutation == "request-mode":
        with pytest.raises(c.ContractError):
            replace(request, mode=c.Mode.OBSERVE)
        assert filesystem.bindings == [] and effects.calls == []
        return
    elif mutation == "controller":
        changed = replace(request, context=replace(request.context, controller_id="other"))
        sources.value = replace(sources.value, request=changed)
    elif mutation == "root":
        sources.value = replace(sources.value, root_ref="other-owned-root")
    elif mutation == "generation":
        sources.value = replace(sources.value, generation=sources.value.generation + 1)
    else:
        original = sources.value.sources[-1]
        sources.value = replace(
            sources.value,
            sources=sources.value.sources[:-1] + (replace(original, content=b'{}'),),
        )
    outcome = service.execute(changed, grant)
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert outcome.exit_code != 0
    assert outcome.artifacts == ()
    assert filesystem.bindings == [] and effects.calls == []


def test_generated_yaml_is_exact_preview_bytes_bound_authorized_and_never_executed(output_composed):
    service, host, sources, effects, filesystem, select = output_composed
    request = generated_request(sources)
    local_only(sources)
    from netops.ansible.workflows import bind_settings, hydrate_inputs
    from tests.test_workflow_execution import Clock

    loaded = bind_settings(
        request, hydrate_inputs(request, sources.value.sources, Clock()), sources.value.settings,
    )
    preview = service.preview(request, loaded)
    expected = preview.native_payload["generated_yaml"].encode("utf-8")
    assert filesystem.bindings == [] and effects.calls == []
    assert service.execute(request).status != c.OutcomeStatus.SUCCEEDED
    assert filesystem.bindings == []
    grant = host.review(service, request)
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert filesystem.content == expected
    assert b"not dry_run" in expected and b"rescue:" in expected
    assert len(filesystem.bindings) == len(result.artifacts) == 1
    assert result.artifacts[0]["digest"] == hashlib.sha256(expected).hexdigest()
    assert effects.calls == []
    replay = service.execute(request, grant)
    assert replay.status != c.OutcomeStatus.SUCCEEDED
    assert len(filesystem.bindings) == 1 and effects.calls == []


def test_render_failure_retains_source_failure_cleanup_and_remote_uncertainty(
    output_composed, monkeypatch,
):
    service, host, sources, effects, filesystem, select = output_composed
    request = select("report.render")
    source_error = c.SafeError(c.ErrorCategory.EXECUTION, c.ReasonCode.APPLY_FAILED, c.Stage.APPLY)
    source = c.aggregate_outcome(
        request,
        (c.TargetOutcome(
            "r1", c.OutcomeStatus.FAILED, True, errors=(source_error,), remote_state="uncertain",
        ),),
        cleanup=c.CleanupOutcome("failed", ("owned-source-cleanup",), (source_error,)),
    )
    request = replace_input(sources, request, "outcomes", c.canonical_bytes(source))
    local_only(sources)
    grant = host.review(service, request)

    def fail_render(*args, **kwargs):
        raise RuntimeError("PRIVATE_RENDER_FAILURE_SENTINEL")

    monkeypatch.setattr("netops.report.generator.ReportGenerator.generate_html", fail_render)
    outcome = service.execute(request, grant)
    assert outcome.status != c.OutcomeStatus.SUCCEEDED and outcome.exit_code != 0
    assert outcome.artifacts == () and filesystem.bindings == [] and effects.calls == []
    assert any(error.reason == c.ReasonCode.APPLY_FAILED for error in outcome.errors)
    assert outcome.cleanup.status == "failed"
    assert "owned-source-cleanup" in outcome.cleanup.remaining_refs
    assert any(target.remote_state == "uncertain" for target in outcome.targets)
    assert "PRIVATE_RENDER_FAILURE_SENTINEL" not in c.canonical_bytes(outcome).decode()


def test_local_report_still_refuses_unready_native_renderer_without_publication(output_composed):
    service, host, sources, effects, filesystem, select = output_composed
    request = select("report.render")
    local_only(sources)
    sources.value = replace(
        sources.value, readiness=c.ReadinessProjection("blocked", "not-requested", "not-requested"),
    )
    outcome = service.execute(request)
    assert outcome.status == c.OutcomeStatus.BLOCKED
    assert outcome.artifacts == () and filesystem.bindings == [] and effects.calls == []


def test_report_cannot_publish_a_selected_target_missing_from_saved_coverage(output_composed):
    service, host, sources, effects, filesystem, select = output_composed
    request = replace(select("report.render"), scope=c.Scope(("r1", "r2")))
    sources.value = replace(sources.value, request=request)
    local_only(sources)
    outcome = service.execute(request)
    assert outcome.status != c.OutcomeStatus.SUCCEEDED and outcome.exit_code != 0
    assert outcome.artifacts == () and filesystem.bindings == [] and effects.calls == []
