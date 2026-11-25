"""Actual fixed action client/native guarded engine; only external ports are fake."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest

from netops.ansible import action_runtime as runtime
from netops.ansible import contracts as c
from netops.ansible._action_mutation import _MutationSpec
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    TrustedConsentAdapter,
    bind_plan,
)
from netops.ansible.policy.contracts import DecisionResult, EffectDescriptor
from netops.ansible.workflows import plan_digest
from netops.core.connection import ConnectionParams
from tests import test_nov19_independent_controller_execution as host

BEFORE = "hostname before\n"
AFTER = "hostname after\n"
SECRET = "successor-private-sentinel"


def rollback_host():
    """Issue fresh genuine authority for config.rollback, not the collect fixture."""
    template = host.actual_host(c.Mode.APPLY, "apply", enforce=True)
    request = replace(
        template[0], operation_id=str(uuid4()), operation="config.rollback", mode=c.Mode.ROLLBACK,
    )
    plan = replace(
        template[1], operation_id=request.operation_id, operation=request.operation,
        requested_mode=request.mode, request_digest=c.digest(request),
        effects=(replace(template[1].effects[0], kind="rollback"),),
    )
    plan = replace(plan, plan_digest=plan_digest(plan))
    binding = bind_plan(plan, "owned-root", 0)
    state, review, clock, cancel = host.HostState(binding), host.Review(), template[4], host.Cancel()
    consent = TrustedConsentAdapter(review)
    broker = AuthorizationBroker(state, consent)
    decision = DecisionResult(
        "allow", ("netops.companion.reviewed",), "reviewed",
        (EffectDescriptor("request_effect", c.public_object({"kind": "rollback"})),),
        plan.context.policy_identity.bundle_sha256,
    )
    grant = broker.issue(plan, consent.review(plan, binding, clock.now, 60.0), decision, clock.now)
    session = broker.consume(grant, binding, clock.now)
    effect = plan.effects[0]
    effect_binding = c.EffectBinding(
        binding, str(uuid4()), state.current.revision, effect.occurrence_id,
        effect.target_id, effect.step_id, (),
    )
    permit = broker.permit(session, effect_binding, clock.now)
    assert broker.enter(permit, effect_binding, clock.now)
    invocation = host._HostInvocation(permit, effect_binding, str(uuid4()), "rollback")
    return request, plan, state, broker, clock, cancel, invocation


def action_case(monkeypatch, kind="apply", fault=None):
    """Keep actual admission, client, push engine, pre/post checks and cleanup."""
    env = host.actual_host(c.Mode.APPLY, "apply", enforce=True) if kind == "apply" else rollback_host()
    control = host.bridge(env)
    control.ready(host.NONCE)
    binding = host.dispatch(env)
    spec = _MutationSpec(
        ("hostname after",) if kind == "apply" else (), BEFORE.encode(),
        hashlib.sha256((AFTER if kind == "apply" else BEFORE).encode()).hexdigest(),
        "owned-prestate-ref",
    )
    trace = []
    credential = {
        "target_id": "router", "task_id": binding.task_id,
        "host": "192.0.2.90", "port": 22, "vendor": "cisco_ios",
        "transport": "ssh", "fields": {"username": "operator", "password": SECRET},
        "known_hosts_ref": "approved-known-hosts", "key_ref": None,
    }

    class Connection:
        def __init__(self, value, jump):
            assert value == credential and jump is None
            self.params = ConnectionParams(host=value["host"], device_type=value["vendor"])
            self.reads = 0

        def connect(self):
            trace.append(("connect",))

        def send(self, command, expect_string=None):
            trace.append(("read", command))
            self.reads += 1
            if kind == "rollback":
                return BEFORE
            if self.reads == 1:
                return "drifted prestate\n" if fault == "prestate" else BEFORE
            return "unconfirmed poststate\n" if fault == "poststate" else AFTER

        def send_config(self, commands):
            trace.append(("write", tuple(commands)))
            if fault == "write":
                raise ConnectionError(SECRET)
            return ""

        def disconnect(self):
            trace.append(("close",))
            if fault == "cleanup":
                raise OSError(SECRET)

    # Model the process identity/fork boundary, not a real fork qualification.
    # Replacing this module's OS effect port does not mutate process-global os.name.
    process_identity = SimpleNamespace(name="posix", getpid=lambda: 7331001)
    monkeypatch.setattr(runtime, "os", process_identity)
    monkeypatch.setattr(runtime, "_StrictConnection", Connection)
    client = runtime._ActionClient({
        "protocol": 1, "socket": "/owned/private/broker", "auth": "9a" * 32,
        "intents": [{
            "handle": binding.occurrence_id, "binding": binding._wire(),
            "kind": kind, "mutation": spec._wire(),
        }],
    })
    process_identity.getpid = lambda: 7331002

    def exchange(message, selected, result):
        trace.append((message, selected.phase, selected.sequence))
        if message == "dispatch":
            if selected.phase == "mutation" and fault == "revoked":
                control.revoke(env[0].operation_id)
            control.request_dispatch(selected, env[5])
            if selected.phase == "credential":
                return {"kind": "credential", "credential": credential, "jump": None}
            return {"kind": "admitted"}
        if message == "check":
            control.check()
            return {"kind": "checked"}
        assert message == "complete"
        return {"kind": "completed"}

    monkeypatch.setattr(client, "_exchange", exchange)
    return env, control, client, binding, trace


@pytest.mark.parametrize("kind", ["apply", "rollback"])
def test_default_fixed_action_runs_guarded_native_mutation_only_after_real_host_permit(
    monkeypatch, kind, caplog,
):
    env, control, client, binding, trace = action_case(monkeypatch, kind)
    result = client.execute(binding.occurrence_id)
    assert result["status"] == "succeeded"
    assert result["remote_state"] == ("confirmed" if kind == "apply" else "rolled-back")
    assert result["mutation"]["confirmed"] is True
    assert result["mutation"]["poststate_verified"] is True
    assert result["mutation"]["cleanup_failed"] is False
    assert control._next[binding.occurrence_id] == 3
    mutation = trace.index(("dispatch", "mutation", 2))
    writes = [index for index, event in enumerate(trace) if event[0] == "write"]
    assert len(writes) == 1 and mutation < writes[0]
    assert trace[writes[0]][1] == (("hostname after",) if kind == "apply" else ("hostname before",))
    assert sum(event[0] == "close" for event in trace) == 1
    assert SECRET not in json.dumps(result) and SECRET not in caplog.text
    assert not env[3].is_revoked(env[0].operation_id)


@pytest.mark.parametrize("fault", ["prestate", "revoked"])
def test_default_fixed_action_denies_drift_or_revoked_host_permit_without_remote_write(
    monkeypatch, fault,
):
    _, _, client, binding, trace = action_case(monkeypatch, fault=fault)
    result = client.execute(binding.occurrence_id)
    assert result["status"] == "failed"
    assert not any(event[0] == "write" for event in trace)
    assert result["mutation"]["issued"] is False
    assert result["remote_state"] == "unchanged"
    assert sum(event[0] == "close" for event in trace) == 1


@pytest.mark.parametrize("fault", ["write", "poststate"])
def test_default_fixed_action_preserves_uncertain_issued_primary_and_never_implicit_rollback(
    monkeypatch, fault,
):
    _, _, client, binding, trace = action_case(monkeypatch, fault=fault)
    result = client.execute(binding.occurrence_id)
    assert result["status"] == "failed"
    assert result["remote_state"] == "uncertain"
    assert result["mutation"]["issued"] is True
    assert result["mutation"]["confirmed"] is False
    assert sum(event[0] == "write" for event in trace) == 1
    assert not result["mutation"]["rolled_back"]
    assert sum(event[0] == "close" for event in trace) == 1
    assert SECRET not in json.dumps(result)


def test_default_fixed_action_keeps_verified_primary_when_connection_cleanup_fails(monkeypatch):
    _, _, client, binding, trace = action_case(monkeypatch, fault="cleanup")
    result = client.execute(binding.occurrence_id)
    assert result["status"] == "succeeded"
    assert result["remote_state"] == "confirmed"
    assert result["mutation"]["poststate_verified"] is True
    assert result["mutation"]["cleanup_failed"] is True
    assert sum(event[0] == "write" for event in trace) == 1
    assert SECRET not in json.dumps(result)


def test_actual_actionbase_platform_import_is_an_explicit_dependency_gate():
    """No synthetic ActionBase, fcntl shim or skip may pretend this tuple is qualified."""
    from ansible.plugins.action import ActionBase

    from netops.ansible.action_plugins.netops_workflow import NetopsWorkflowAction

    assert issubclass(NetopsWorkflowAction, ActionBase)
