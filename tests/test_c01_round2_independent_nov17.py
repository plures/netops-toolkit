"""Independent original C01 settings, purity, private-data and completion probes."""

import hashlib
import json
import logging
import os
import pickle
import socket
import subprocess
import time
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

import pytest

from netops.ansible import contracts as c
from netops.ansible import workflows as w
from netops.ansible.policy.contracts import (
    PolicyBudgetError,
    PolicyEvaluationError,
    PolicyInputError,
)
from netops.ansible.settings import SettingsSnapshot, load_settings, resolve_settings
from netops.change.diff import diff_configs, format_json
from tests.test_c01_independent_nov17 import (
    ForbiddenPort,
    HydrationClock,
    hydrated,
    input_source,
    request,
)
from tests.test_c01_independent_nov17 import environment as environment

SETTINGS_CHANGES = (
    ("ansible.enabled", True), ("ansible.mode", "enforce"), ("ansible.enhanced", True),
    ("controller.id", "local-test-controller"), ("controller.wsl_distribution", "Ubuntu-24.04"),
    ("controller.start_timeout_seconds", 31), ("inventory.cache_ttl_seconds", 0),
    ("diagnostics.retention_days", 8), ("execution.target_limit", 101),
    ("execution.ssh_concurrency", 6), ("execution.ping_concurrency", 49),
    ("execution.snmp_concurrency", 9), ("execution.timeout_seconds", 301),
    ("authorization.ttl_seconds", 59), ("observation.max_age_seconds", 59),
    ("backup.retention_count", 11), ("backup.git", True),
    ("health.cpu_threshold", 90.0), ("health.memory_threshold", 90.0),
    ("logging.level", "DEBUG"), ("logging.max_bytes", 1024),
    *((key, r"C:\owned-c01-independent\selected") for key in (
        "NETOPS_STATE_ROOT", "NETOPS_INVENTORY", "NETOPS_VAULT",
        "NETOPS_INVENTORY_CACHE", "NETOPS_TUI_SETTINGS", "NETOPS_LOG_DIR", "NETOPS_LOG_SETTINGS",
    )),
)


@pytest.mark.parametrize(("key", "value"), SETTINGS_CHANGES)
def test_every_original_setting_is_bound_not_just_execution_tuning(environment, key, value):
    service, context, _ = environment
    req, original = hydrated(request(context))
    original_plan = service.preview(req, original)
    document = json.loads(c.canonical_bytes(SettingsSnapshot()))
    if "." in key:
        group, name = key.split(".")
        document[group][name] = value
    else:
        document[key] = value
    snapshot = load_settings(json.dumps(document).encode())
    loaded = w.bind_settings(req, original, snapshot)
    plan = service.preview(req, loaded)
    assert loaded.settings is snapshot and plan.settings is snapshot
    assert loaded.contents is original.contents and loaded.observations is original.observations
    assert loaded.request_digest == original.request_digest
    assert loaded.binding_digest != original.binding_digest
    assert plan.plan_digest != original_plan.plan_digest
    assert service.preview(req, original).plan_digest == original_plan.plan_digest
    assert plan.targets == original_plan.targets
    assert plan.effects == original_plan.effects
    assert plan.native_payload["execution_performed"] is False
    with pytest.raises(FrozenInstanceError):
        snapshot.execution.target_limit = 1
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(req, replace(original, settings=snapshot))


def test_settings_decode_resolve_bind_and_preview_have_no_implicit_host_owner(environment):
    service, context, _ = environment
    req, loaded = hydrated(request(context))
    baseline = service.preview(req, loaded)
    encoded = c.canonical_bytes(SettingsSnapshot())
    forbidden = AssertionError("C01 pure boundary tried a host effect")
    with patch("builtins.open", side_effect=forbidden), \
            patch.object(Path, "open", side_effect=forbidden), \
            patch.object(socket, "socket", side_effect=forbidden), \
            patch.object(subprocess, "Popen", side_effect=forbidden), \
            patch.object(os, "getenv", side_effect=forbidden), \
            patch.object(time, "time", side_effect=forbidden), \
            patch.object(time, "monotonic", side_effect=forbidden), \
            patch.object(logging, "basicConfig", side_effect=forbidden), \
            patch.object(logging, "FileHandler", side_effect=forbidden):
        snapshot = resolve_settings(load_settings(encoded), {
            "execution.ssh_concurrency": 7, "execution.timeout_seconds": 19,
        })
        bound = w.bind_settings(req, loaded, snapshot)
        plan = service.preview(req, bound)
        assert plan.settings is snapshot
        assert (plan.concurrency, plan.deadline_ms) == (7, 19000)
        assert service.catalog().qualification == "unqualified"
    assert plan.effects == baseline.effects
    assert plan.native_payload["execution_performed"] is False


def test_invalid_late_override_is_atomic_and_lower_limit_does_not_clip(environment):
    service, context, _ = environment
    original = SettingsSnapshot()
    before = c.canonical_bytes(original)
    with pytest.raises(c.ContractError):
        resolve_settings(original, {"execution.ssh_concurrency": 8, "authorization.ttl_seconds": 1})
    assert c.canonical_bytes(original) == before
    req, loaded = hydrated(request(context))
    snapshot = resolve_settings(original, {"execution.target_limit": 1})
    bound = w.bind_settings(req, loaded, snapshot)
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(req, bound)
    assert req.scope.target_ids == ("edge-b", "edge-a")
    assert service.preview(req, loaded).targets == req.scope.target_ids


@pytest.mark.parametrize("kind", ("text", "json", "yaml"))
@pytest.mark.parametrize("form", ("snmp", "tacacs", "radius", "structured"))
def test_supported_credentials_reject_before_any_public_content_hash(environment, monkeypatch,
                                                                    kind, form):
    _, context, _ = environment
    sentinel = "C01IndependentCredentialSentinel"
    lines = {
        "snmp": f"snmp-server user observer group v3 auth sha {sentinel} priv aes 128 {sentinel}",
        "tacacs": f"tacacs server auth-server\n key 7 {sentinel}\n!",
        "radius": f"radius-server host 192.0.2.1 key {sentinel}",
        "structured": f"snmp-server community {sentinel} RO",
    }
    if kind == "text":
        raw = lines[form].encode()
    elif form == "structured":
        raw = (json.dumps({"snmpv3": {"authKey": sentinel}}).encode() if kind == "json"
               else f"snmpv3:\n  authKey: {sentinel}\n".encode())
    else:
        raw = (json.dumps({"config": lines[form]}).encode() if kind == "json"
               else ("config: |\n  " + lines[form].replace("\n", "\n  ") + "\n").encode())
    ref = c.InputRef("before", "explicit-nonsecret-only-selection", "0" * 64)
    source = c.InputSource(ref, kind, raw, "independent-v1", "cisco-v1")
    req = replace(request(context), inputs=(ref,))
    real_sha = hashlib.sha256
    hashes = []

    def guarded_sha(data=b"", *args, **kwargs):
        hashes.append(data)
        assert sentinel.encode() not in data, "credential-bearing bytes hashed before rejection"
        return real_sha(data, *args, **kwargs)

    monkeypatch.setattr(w.hashlib, "sha256", guarded_sha)
    with pytest.raises(c.ContractError, match="input-binding-invalid") as caught:
        w.hydrate_inputs(req, (source,), HydrationClock())
    assert sentinel not in str(caught.value) + repr(caught.value.error) + repr(source)
    assert sentinel.encode() not in c.canonical_bytes(caught.value.error)
    assert raw not in hashes


@pytest.mark.parametrize("wire_field", ("unapplied_effects", "attempted"))
@pytest.mark.parametrize("container", ("targets", "steps"))
def test_response_decoder_refuses_a_successful_but_incomplete_selected_effect(environment,
                                                                           wire_field, container):
    _, context, _ = environment
    req = replace(request(context, "config.apply", targets=("edge-b",)), mode=c.Mode.APPLY)
    target = c.TargetOutcome("edge-b", c.OutcomeStatus.SUCCEEDED, True, changed=True,
                             remote_state="committed")
    step = c.StepOutcome("apply", c.OutcomeStatus.SUCCEEDED, True, changed=True)
    outcome = c.aggregate_outcome(req, (target,), (step,), executed_mode=c.Mode.APPLY)
    document = json.loads(c.canonical_bytes(outcome))
    document[container][0][wire_field] = ["apply"] if wire_field == "unapplied_effects" else False
    with pytest.raises(c.ContractError):
        c.OperationOutcome.from_json(json.dumps(document).encode())
    assert outcome.exit_code == 0 and outcome.changed


def test_completed_and_pending_apply_preserve_changed_cleanup_and_coverage(environment):
    _, context, _ = environment
    req = replace(request(context, "config.apply"), mode=c.Mode.APPLY)
    completed = c.TargetOutcome("edge-b", c.OutcomeStatus.SUCCEEDED, True,
                                changed=True, remote_state="committed")
    pending = c.TargetOutcome("edge-a", c.OutcomeStatus.BLOCKED, False,
                              unapplied_effects=("apply",))
    error = c.SafeError(c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE)
    cleanup = c.CleanupOutcome("failed", ("selected-owned-staging",), (error,))
    outcome = c.aggregate_outcome(req, (completed, pending), cleanup=cleanup)
    assert outcome.status == c.OutcomeStatus.PARTIAL and outcome.exit_code == 4
    assert outcome.changed and outcome.targets == (completed, pending)
    assert outcome.targets[1].unapplied_effects == ("apply",)
    assert outcome.cleanup is cleanup
    assert c.OperationOutcome.from_json(c.canonical_bytes(outcome)) == outcome


@pytest.mark.parametrize("factory", (c.TargetOutcome, c.StepOutcome))
@pytest.mark.parametrize(("attempted", "pending"), ((False, ()), (True, ("apply",))))
def test_direct_selected_success_cannot_invent_completed_effect(factory, attempted, pending):
    with pytest.raises(c.ContractError):
        factory("selected-work", c.OutcomeStatus.SUCCEEDED, attempted,
                unapplied_effects=pending)


@pytest.mark.parametrize("exception", (PolicyInputError, PolicyEvaluationError, PolicyBudgetError))
def test_internal_policy_failure_is_not_caller_invalid_and_never_leaks(environment, exception):
    _, context, engine = environment
    req, loaded = hydrated(request(context))
    sentinel = "C01PrivateEvaluatorDiagnostic"

    class BrokenPolicy:
        def decide(self, event, facts):
            raise exception(sentinel)

    forbidden = ForbiddenPort()
    service = w.WorkflowService(BrokenPolicy(), forbidden, forbidden, forbidden,
                                forbidden, forbidden, forbidden, forbidden)
    with pytest.raises(w.PolicyFailure) as caught:
        service.preview(req, loaded)
    failure = caught.value
    assert failure.exit_code == 5
    assert failure.error.category == c.ErrorCategory.POLICY
    assert failure.error.stage == c.Stage.EVALUATE
    assert failure.error.next_action
    assert sentinel not in str(failure) + repr(failure) + failure.diagnostic
    assert sentinel.encode() not in c.canonical_bytes(failure.error)
    assert failure.__suppress_context__
    malformed = replace(loaded, binding_digest="0" * 64)
    with pytest.raises(c.ContractError, match="input-binding-invalid") as caller:
        service.preview(req, malformed)
    assert caller.value.error.category == c.ErrorCategory.INVALID_INPUT
    healthy = w.WorkflowService(engine, forbidden, forbidden, forbidden,
                                forbidden, forbidden, forbidden, forbidden)
    assert healthy.preview(req, loaded).targets == req.scope.target_ids


def test_settings_preferences_are_not_execution_or_qualification_authority(environment):
    service, context, _ = environment
    req, loaded = hydrated(request(context, "config.apply"), input_source("intent", {}))
    snapshot = replace(SettingsSnapshot(),
                       ansible=replace(SettingsSnapshot().ansible, enabled=True,
                                       mode="enforce", enhanced=True),
                       backup=replace(SettingsSnapshot().backup, git=True))
    plan = service.preview(req, w.bind_settings(req, loaded, snapshot))
    assert plan.native_payload["execution_performed"] is False
    assert service.catalog().qualification == "unqualified"
    for authorization in (None, {"approved": True}, object()):
        outcome = service.execute(replace(req, mode=c.Mode.APPLY), authorization)
        assert outcome.exit_code == 3 and outcome.status == c.OutcomeStatus.BLOCKED
        assert all(not target.attempted for target in outcome.targets)
        assert outcome.executed_mode is None


def test_real_private_grant_value_cannot_serialize_or_activate_c01(environment):
    service, context, _ = environment

    class PrivateGrant(c.Authorization):
        @property
        def _host_owned(self):
            return True

    grant = PrivateGrant()
    assert repr(grant) == "<private>"
    with pytest.raises(TypeError, match="private-value"):
        pickle.dumps(grant)
    with pytest.raises(c.ContractError):
        c.canonical_bytes({"grant": grant})
    req = replace(request(context, "config.apply"), mode=c.Mode.APPLY)
    outcome = service.execute(req, grant)
    assert outcome.exit_code == 3 and not any(target.attempted for target in outcome.targets)


def test_selected_target_and_safe_error_have_exact_stable_wire_without_private_diagnostics():
    target = c.TargetOutcome("edge-a", c.OutcomeStatus.BLOCKED, False,
                             unapplied_effects=("apply",))
    assert c.canonical_bytes(target) == (
        b'{"attempted":false,"changed":false,"errors":[],"findings":[],"native_payload":{},'
        b'"remote_state":"unchanged","selected":true,"status":"blocked","target_id":"edge-a",'
        b'"unapplied_effects":["apply"]}'
    )
    error = c.SafeError(c.ErrorCategory.POLICY, c.ReasonCode.READING_UNAVAILABLE,
                        c.Stage.EVALUATE, target_id="edge-a", next_action="Reload local policy.")
    assert c.canonical_bytes(error) == (
        b'{"category":"policy","detail":"","next_action":"Reload local policy.",'
        b'"reason":"reading-unavailable","retryable":false,"stage":"evaluate",'
        b'"step_id":null,"target_id":"edge-a"}'
    )


def test_nonsecret_snmp_notification_configuration_keeps_native_diff_parity(environment):
    service, context, _ = environment
    before = "snmp-server enable traps snmp linkdown linkup\n"
    after = "snmp-server enable traps snmp authentication linkdown linkup\n"
    req, loaded = hydrated(request(context, "compare.compare"),
                           input_source("before", content=before.encode()),
                           input_source("after", content=after.encode()))
    plan = service.preview(req, loaded)
    assert c.wire(plan.native_payload["native_payload"]) == json.loads(
        format_json(diff_configs(before, after)),
    )
