"""Frozen O03/O04 effects through actual A02 host with controlled external ports."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

from netops.ansible import contracts as c
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed
from tests.test_workflow_execution import policy as policy


def replace_input(sources, request, kind, content):
    index = next(i for i, ref in enumerate(request.inputs) if ref.kind == kind)
    refs = list(request.inputs)
    refs[index] = replace(refs[index], digest=hashlib.sha256(content).hexdigest())
    data = list(sources.value.sources)
    data[index] = replace(data[index], source=refs[index], content=content)
    request = replace(request, inputs=tuple(refs))
    sources.value = replace(sources.value, request=request, sources=tuple(data))
    return request


def test_public_report_unauthorized_output_never_publishes(output_composed):
    service, host, sources, effects, filesystem, select = output_composed
    request = select("report.render")
    outcome = service.execute(request)
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert not outcome.artifacts
    assert filesystem.bindings == [] and effects.calls == []


def test_public_report_successful_render_preserves_failed_source_cleanup_uncertainty(output_composed):
    service, host, sources, effects, filesystem, select = output_composed
    request = select("report.render")
    error = c.SafeError(c.ErrorCategory.EXECUTION, c.ReasonCode.APPLY_FAILED, c.Stage.APPLY)
    source = c.aggregate_outcome(
        request,
        (c.TargetOutcome("r1", c.OutcomeStatus.FAILED, True,
                         errors=(error,), remote_state="uncertain"),),
        cleanup=c.CleanupOutcome("failed", ("owned-original-cleanup",), (error,)),
    )
    request = replace_input(sources, request, "outcomes", c.canonical_bytes(source))
    grant = host.review(service, request)
    outcome = service.execute(request, grant)
    assert len(outcome.artifacts) == len(filesystem.bindings) == 1, "Authorized render must really publish"
    assert filesystem.content.startswith(b"<!DOCTYPE html>")
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert outcome.exit_code != 0
    assert any(e.reason == c.ReasonCode.APPLY_FAILED for e in outcome.errors)
    assert outcome.cleanup.status == "failed"
    assert "owned-original-cleanup" in outcome.cleanup.remaining_refs
    assert b'"remote_uncertain": true' in filesystem.content or b'"remote_uncertain":true' in filesystem.content
    assert effects.calls == []
    assert service.execute(request, grant).status != c.OutcomeStatus.SUCCEEDED
    assert len(filesystem.bindings) == 1


def test_public_empty_offline_report_does_not_require_controller_targets(output_composed):
    service, host, sources, effects, filesystem, select = output_composed
    request = replace(select("report.render"), scope=c.Scope(()))
    source = c.aggregate_outcome(
        request, (), (c.StepOutcome("offline", c.OutcomeStatus.SUCCEEDED, True),),
    )
    request = replace_input(sources, request, "outcomes", c.canonical_bytes(source))
    grant = host.review(service, request)
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.SUCCEEDED
    assert len(outcome.artifacts) == len(filesystem.bindings) == 1
    assert effects.calls == []


def test_public_generate_exact_output_unexecuted_and_no_collect_apply(output_composed):
    service, host, sources, effects, filesystem, select = output_composed
    base = sources.value.request
    content = json.dumps({
        "results": [{
            "host": "r1", "device_type": "cisco_ios", "success": True,
            "timestamp": "2026-11-20T06:30:00Z",
            "checks": {"cpu": {"alert": True, "usage_percent": 99}},
        }],
    }).encode()
    ref = c.InputRef("findings", "owned-findings", hashlib.sha256(content).hexdigest())
    request = replace(
        base, operation="compare.generate", mode=c.Mode.OUTPUT, inputs=(ref,),
        output_intent=c.OutputIntent(("yaml",), "owned"),
    )
    sources.value = replace(sources.value, request=request, sources=(
        c.InputSource(ref, "json", content, "parser-1", "vendor-1", observations=(
            c.Observation(
                "bound-findings-observation", "r1", c.digest(request.context),
                request.context.route_digest, request.context.controller_id, ref, ref.digest,
                "2026-11-20T06:30:00Z", 0.0,
            ),
        )),
    ))
    grant = host.review(service, request)
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.SUCCEEDED
    assert len(outcome.artifacts) == len(filesystem.bindings) == 1
    assert b"not dry_run" in filesystem.content and b"rescue:" in filesystem.content
    assert effects.calls == []
    assert service.execute(request, grant).status != c.OutcomeStatus.SUCCEEDED
    assert len(filesystem.bindings) == 1


def test_public_local_report_does_not_invent_controller_qualification_dependency(output_composed):
    from netops.ansible.settings import AnsibleSettings

    service, host, sources, effects, filesystem, select = output_composed
    request = select("report.render")
    sources.value = replace(
        sources.value,
        controller_qualified=False, route_qualified=False, credential_channel_qualified=False,
        readiness=c.ReadinessProjection("ready", "not-requested", "not-requested"),
        settings=replace(sources.value.settings, ansible=AnsibleSettings(enabled=False)),
    )
    grant = host.review(service, request)
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.SUCCEEDED
    assert len(outcome.artifacts) == len(filesystem.bindings) == 1
    assert effects.calls == []
