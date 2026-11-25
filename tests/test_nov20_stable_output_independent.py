"""Frozen original output and uninstall guards through actual local admission."""

from __future__ import annotations

from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.dependencies._uninstall import ManagedUninstall
from netops.dependencies.runs import OwnedGenerationRuns
from tests.test_guided_setup_author import OWNER, public_case
from tests.test_i02_author_lifecycle import Cancel
from tests.test_nov20_output_setup_proof import generated_request, local_only
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed
from tests.test_workflow_execution import policy as policy


def test_generate_review_consumes_actual_canonical_save_intent_not_native_reroute(
    output_composed, monkeypatch,
):
    service, host, sources, effects, filesystem, select = output_composed
    request = generated_request(sources)
    local_only(sources)
    actual = service._policy.decide
    decisions = []

    def capture(event, facts):
        result = actual(event, facts)
        decisions.append((event, facts, result))
        return result

    monkeypatch.setattr(service._policy, "decide", capture)
    grant = host.review(service, request)
    admission = [
        item for item in decisions if "consent" in item[1].values
        and item[1].values["consent"]["present"] is True
    ]
    assert len(admission) == 1
    event, facts, decision = admission[0]
    assert facts.values["request"]["operation"] == "generate"
    assert facts.values["request"]["mode"] == "output"
    assert tuple((item.name, dict(item.params)) for item in decision.effects) == (
        ("request_effect", {"kind": "save"}),
    )
    assert decision.policy_digest == request.context.policy_identity.bundle_sha256
    assert decision.rule_ids == ("netops.companion.compare_operation_requested_save",)
    assert filesystem.bindings == [] and effects.calls == []
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.SUCCEEDED
    assert len(outcome.artifacts) == len(filesystem.bindings) == 1
    assert effects.calls == []


@pytest.mark.parametrize("guard", [
    "inputs-bound", "vendor-supported", "output-safe", "cancelled",
    "control-expired", "consent-expired", "plan-current", "policy-current",
    "preview", "check", "observe", "apply", "rollback",
])
def test_canonical_generate_cannot_emit_save_when_exact_guard_is_invalid(
    output_composed, monkeypatch, guard,
):
    service, host, sources, effects, filesystem, select = output_composed
    request = generated_request(sources)
    local_only(sources)
    actual = service._policy.decide
    captured = []

    def capture(event, facts):
        captured.append((event, facts))
        return actual(event, facts)

    monkeypatch.setattr(service._policy, "decide", capture)
    host.review(service, request)
    admission = [
        item for item in captured if "consent" in item[1].values
        and item[1].values["consent"]["present"] is True
    ]
    assert len(admission) == 1
    event, facts = admission[0]
    values = c.wire(facts.values)
    changes = {
        "inputs-bound": ("compare", "inputs_bound", False),
        "vendor-supported": ("compare", "vendor_supported", False),
        "output-safe": ("report", "output_safe", False),
        "cancelled": ("control", "cancelled", True),
        "control-expired": ("control", "remaining_ms", 0),
        "consent-expired": ("consent", "remaining_ms", 0),
        "plan-current": ("binding", "plan_current", False),
        "policy-current": ("binding", "policy_current", False),
    }
    if guard in changes:
        area, field, value = changes[guard]
        values[area][field] = value
    else:
        values["request"]["mode"] = guard
        event = replace(event, payload=c.public_object({**dict(event.payload), "mode": guard}))
    decision = actual(event, replace(facts, values=lc.object_value(values)))
    assert not any(
        item.name == "request_effect" and item.params["kind"] == "save"
        for item in decision.effects
    ), (guard, decision)
    assert filesystem.bindings == [] and effects.calls == []


@pytest.mark.parametrize("fault", [
    "remaining", "primary-error", "pin-postcheck", "pointer-postcheck", "clock-postcheck",
])
def test_uninstall_incomplete_or_failed_poststate_never_records_terminal_success(
    tmp_path, policy, monkeypatch, fault,
):
    # Effects are controlled external ports, not actual platform qualification.
    service, scope, context, port, state, effects, engine, private = public_case(tmp_path, policy)
    plan = service.plan(scope, context)
    service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    manifest = state.manifests[0]
    generation = lc.GenerationBinding(
        manifest.generation_id, 0, manifest.content_digest, c.digest(manifest),
    )
    state.runs = OwnedGenerationRuns(
        port, "managed-root", "managed-control", OWNER, policy[0],
        (generation,), generation.generation_id,
    )
    state.runs.initialize()
    uninstall = service.plan_uninstall(generation.generation_id, context)
    consent = private.review(uninstall, 10.0, 20.0)
    entered = []
    before = state.pointer()
    original_pointer, original_pins = state.pointer, state.runs.pins
    original_clock = service.clock.monotonic

    def pointer():
        if entered and fault == "pointer-postcheck":
            raise OSError("PRIVATE_POINTER_POSTCHECK")
        return original_pointer()

    def pins():
        if entered and fault == "pin-postcheck":
            raise OSError("PRIVATE_PIN_POSTCHECK")
        return original_pins()

    def clock():
        if entered and fault == "clock-postcheck":
            return float("nan")
        return original_clock()

    def remove(self, removed, remaining):
        entered.append("actual-owned-handler")
        removed.append("owned-removed")
        if fault == "remaining":
            remaining.append("owned-not-removed")
        if fault == "primary-error":
            raise OSError("PRIVATE_PRIMARY_REMOVAL")

    monkeypatch.setattr(state, "pointer", pointer)
    monkeypatch.setattr(state.runs, "pins", pins)
    monkeypatch.setattr(service.clock, "monotonic", clock)
    monkeypatch.setattr(ManagedUninstall, "_remove_selected", remove)
    event_count = len(engine.events)
    result = service.uninstall(uninstall, consent)
    assert entered == ["actual-owned-handler"]
    assert result.status != c.OutcomeStatus.SUCCEEDED
    assert not any(event.kind == lc.EventKind.STEP_COMPLETED for event in engine.events[event_count:])
    receipt = port.read("dependency-uninstall-result-" + uninstall.plan_id)
    assert receipt.payload["completed"] is False
    if fault == "remaining":
        assert result.pending_actions == ("owned-not-removed",)
    else:
        assert result.errors or result.cleanup_errors
    assert original_pointer() == before
    assert "PRIVATE_" not in repr(result)
    monkeypatch.setattr(service.clock, "monotonic", original_clock)
    replay = service.uninstall(uninstall, consent)
    assert replay.status != c.OutcomeStatus.SUCCEEDED
    assert entered == ["actual-owned-handler"]
