"""Original A02 strict owned-state, receipt, result and counter safety edges."""

from dataclasses import replace

import pytest

from netops.ansible import artifact_observations
from netops.ansible import contracts as c
from netops.ansible import lifecycle_execution as life
from netops.ansible.execution import EffectResult, ExecutionHost
from netops.ansible.native_effects import _publish_backup
from netops.ansible.policy.authorization import AuthorizationError
from tests.policy.test_a02_final_proof_nov19 import lifecycle_policy as lifecycle_policy
from tests.policy.test_lifecycle_execution import CONTENT, environment, reserve
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import policy as policy


@pytest.mark.parametrize(("function", "args"), [
    (life._object, ({}, ("required",))),
    (life._tuple, ([],)),
    (life._bytes, ((256,),)),
    (life._bytes, ((0,) * 65537,)),
    (life._pointer, ({
        "kind": "unknown", "revision": 0, "active_generation_id": "generation",
        "pointer_digest": "a" * 64,
    },)),
])
def test_closed_owned_schema_rejects_malformed_and_oversized_values(function, args):
    """LA02/03 and exact bounded hydration cannot coerce missing/wrong records."""
    with pytest.raises(c.ContractError):
        function(*args)


def test_owned_read_rejects_nonrecord_port_result(tmp_path, lifecycle_policy, monkeypatch):
    env = environment(tmp_path, lifecycle_policy)
    monkeypatch.setattr(env[2], "read", lambda resource: object())
    with pytest.raises(c.ContractError):
        env[3]._read("facts")


@pytest.mark.parametrize("change", [
    {"schema": "unknown"}, {"setup_enabled": 1}, {"cancelled": "false"},
])
def test_owned_facts_schema_and_boolean_flags_fail_closed(tmp_path, lifecycle_policy, change):
    env = environment(tmp_path, lifecycle_policy)
    record = env[2].read("facts")
    env[2].seed("facts", dict(record.payload, **change))
    with pytest.raises(c.ContractError):
        env[3]._facts()


@pytest.mark.parametrize(("observed", "change", "revision"), [
    (False, {"binding_digest": "b" * 64}, 0),
    (False, {}, 1),
    (False, {"result": {}}, 0),
    (True, {}, 0),
    (True, {"result.pointer": ("generation", 1)}, 1),
])
def test_receipt_hydration_rejects_corrupt_binding_phase_and_factual_shape(
    tmp_path, lifecycle_policy, observed, change, revision,
):
    """LA05/T23: a persisted alleged fact must match the exact pending occurrence."""
    env = environment(tmp_path, lifecycle_policy)
    permit, binding = reserve(env, lifecycle_policy)
    if observed:
        env[-1].enter(permit, binding)
    else:
        env[3].begin_receipt(binding)
    resource = env[3]._receipt_resource(binding)
    payload = dict(env[2].read(resource).payload)
    for key, value in change.items():
        if key.startswith("result."):
            result = dict(payload["result"])
            result[key.split(".", 1)[1]] = value
            payload["result"] = result
        else:
            payload[key] = value
    env[2].seed(resource, payload, revision=revision)
    with pytest.raises(c.ContractError):
        env[3].inspect_receipt(binding)


@pytest.mark.parametrize("pointer", [("wrong-generation", 1), ("generation", 2)])
def test_pointer_receipt_must_match_exact_generation_and_next_revision(
    tmp_path, lifecycle_policy, pointer,
):
    env = environment(tmp_path, lifecycle_policy, "restore-active-pointer")
    permit, binding = reserve(env, lifecycle_policy)
    env[-1].enter(permit, binding)
    resource = env[3]._receipt_resource(binding)
    payload = dict(env[2].read(resource).payload)
    payload["result"] = dict(payload["result"], pointer=pointer)
    env[2].seed(resource, payload, revision=1)
    with pytest.raises(c.ContractError):
        env[3].inspect_receipt(binding)


def test_completion_before_handler_fact_is_never_an_acknowledgement(tmp_path, lifecycle_policy):
    env = environment(tmp_path, lifecycle_policy)
    permit, _ = reserve(env, lifecycle_policy)
    writes = len(env[2].writes)
    with pytest.raises(AuthorizationError):
        env[-1].complete(permit)
    assert len(env[2].writes) == writes


@pytest.mark.parametrize("change", [
    {"schema": "unknown"}, {"content_digest": "b" * 64},
])
def test_inert_artifact_schema_and_measured_digest_must_match(
    tmp_path, lifecycle_policy, change,
):
    env = environment(tmp_path, lifecycle_policy)
    record = env[2].read("source")
    env[2].seed("source", dict(record.payload, **change))
    with pytest.raises(c.ContractError):
        env[3].artifact("source")


@pytest.mark.parametrize("damage", ["digest", "reservation", "revision"])
def test_owned_copy_rejects_wrong_digest_unreserved_destination_and_max(
    tmp_path, lifecycle_policy, damage,
):
    """LA03/MAX: no copy/CAS from malformed or exhausted owned state."""
    env = environment(tmp_path, lifecycle_policy)
    current = env[2].read("destination")
    if damage == "reservation":
        env[2].seed("destination", dict(current.payload, reserved=False))
    elif damage == "revision":
        env[2].seed("destination", current.payload, revision=9007199254740991)
    before = env[2].filename("destination").read_bytes()
    with pytest.raises((c.ContractError, AuthorizationError)):
        env[3].copy_artifact("source", "destination", "b" * 64 if damage == "digest" else CONTENT)
    assert env[2].filename("destination").read_bytes() == before
    assert not env[2].writes


@pytest.mark.parametrize("damage", ["manifest", "revision"])
def test_owned_tombstone_rejects_wrong_manifest_and_exhausted_revision(
    tmp_path, lifecycle_policy, damage,
):
    env = environment(tmp_path, lifecycle_policy, "dependency-uninstall")
    current = env[2].read("destination")
    if damage == "revision":
        env[2].seed("destination", current.payload, revision=9007199254740991)
    before = env[2].filename("destination").read_bytes()
    expected = "b" * 64 if damage == "manifest" else c.digest(current.payload["manifest"])
    with pytest.raises((c.ContractError, AuthorizationError)):
        env[3].remove_artifact("destination", expected)
    assert env[2].filename("destination").read_bytes() == before
    assert not env[2].writes


@pytest.mark.parametrize("damage", [
    "result-type", "step-type", "cleanup-type", "artifacts-container",
    "artifact-type", "unexpected-publication", "wrong-occurrence", "unselected",
])
def test_native_port_result_cannot_invent_shape_selection_or_publication(damage):
    """PX10/T23: validate actual typed result, exact occurrence and output authority."""
    effect = c.PlannedEffect("one", 0, "gather", "r1", "gather")
    result = EffectResult(c.StepOutcome("one", c.OutcomeStatus.SUCCEEDED, True))
    descriptor = c.ArtifactDescriptor(
        "owned", "a" * 64, 1, "text/plain", "public", "owned", "none", "root", "b" * 64,
    )
    if damage == "result-type":
        result = object()
    elif damage == "step-type":
        result = replace(result, step=object())
    elif damage == "cleanup-type":
        result = replace(result, cleanup=object())
    elif damage == "artifacts-container":
        result = replace(result, artifacts=[])
    elif damage == "artifact-type":
        result = replace(result, artifacts=(object(),))
    elif damage == "unexpected-publication":
        result = replace(result, artifacts=(descriptor,))
    elif damage == "wrong-occurrence":
        result = replace(result, step=replace(result.step, step_id="other"))
    else:
        result = replace(result, step=replace(result.step, selected=False))
    with pytest.raises(c.ContractError):
        ExecutionHost._validate_result(result, effect)


@pytest.mark.parametrize("damage", ["type", "controller", "route", "channel", "cancelled"])
def test_execution_source_port_requires_exact_inputs_and_real_booleans(composed, damage):
    """PX04/12: arbitrary objects/truthy values are not current host qualification."""
    service, host, request, sources, backend = composed
    if damage == "type":
        sources.reload = lambda operation_id: object()
    else:
        name = {
            "controller": "controller_qualified", "route": "route_qualified",
            "channel": "credential_channel_qualified", "cancelled": "cancelled",
        }[damage]
        sources.value = replace(sources.value, **{name: 1})
    with pytest.raises(c.ContractError):
        host._load(service, request)
    assert backend.calls == []


def test_private_backup_helper_rejects_unprotected_port_before_any_output():
    with pytest.raises(c.ContractError):
        _publish_backup(object(), None, None, None, b"inert")


def test_invalid_observation_scope_is_non_authoritative_and_cleared():
    with artifact_observations._lifecycle_observation_context(object()):
        assert artifact_observations._CONTEXT.get().operation_id == "none"
    assert artifact_observations._CONTEXT.get().operation_id == "none"


def test_secondary_error_observation_retains_closed_category_and_reason(caplog):
    observations = artifact_observations.ArtifactObservations()
    error = c.SafeError(c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE)
    with caplog.at_level("INFO", logger="netops.ansible.artifact_observations"):
        observations.record("cleanup.result", "failed", error=error)
    row = caplog.records[-1]
    assert row.error_category == "cleanup"
    assert row.reason == "cleanup-failed"
    assert row.next_action == error.next_action
