"""Independent T08/T13/T14/T30/T32 host-to-controller effect-port proofs."""

from __future__ import annotations

import json
import pickle
import threading
from contextlib import contextmanager
from dataclasses import replace
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.controller import (
    ControllerInstallation,
    ControllerLauncher,
    ProcessResult,
)
from netops.ansible.controller_control import (
    HostControllerCredentials,
    HostDispatchControl,
    _HostInvocation,
)
from netops.ansible.controller_protocol import DispatchBinding, ProtocolError, _decode_frame
from netops.ansible.credentials import (
    CredentialScope,
    CredentialTarget,
    ScopedCredentialResolver,
    UnlockSession,
)
from netops.ansible.policy.authorization import (
    AdmissionSnapshot,
    AuthorizationBroker,
    TrustedConsentAdapter,
    bind_plan,
)
from netops.ansible.policy.contracts import DecisionResult, EffectDescriptor
from netops.ansible.settings import AnsibleSettings, SettingsSnapshot
from netops.ansible.workflows import plan_digest
from netops.core.vault import CredentialVault
from tests.test_nov19_independent_credentials import (
    SENTINEL,
    Admission,
    Clock,
    Routes,
    policy_identity,
)

NONCE = "7c" * 32


class Cancel:
    def __init__(self):
        self.value = False

    def is_cancelled(self):
        return self.value


class HostState:
    def __init__(self, binding):
        self.current = AdmissionSnapshot(binding, 0, False, True)
        self.mutex = threading.RLock()

    @contextmanager
    def lock(self, operation_id):
        with self.mutex:
            yield

    def snapshot(self, operation_id):
        assert self.current.binding.operation_id == operation_id
        return self.current

    def compare_revision(self, operation_id, expected_revision, next_revision):
        assert self.current.binding.operation_id == operation_id
        if self.current.revision != expected_revision:
            return False
        self.current = replace(self.current, revision=next_revision)
        return True


class Review:
    def confirm(self, plan, binding, deadline):
        return plan.plan_digest == binding.plan_digest


class Events:
    def __init__(self):
        self.records = []
        self.throw = False

    def emit(self, event):
        self.records.append(event)
        if self.throw:
            raise RuntimeError("sink unavailable")


class RevokePort:
    def __init__(self):
        self.operations = []
        self.throw = False

    def revoke(self, operation):
        self.operations.append(operation)
        if self.throw:
            raise RuntimeError("revoke unavailable")


def actual_host(mode=c.Mode.OBSERVE, kind="collect", *, enabled=True, enforce=False, enter=True):
    identity = policy_identity()
    context = c.Context(
        "owned-controller", "a" * 64, "inventory", "b" * 64,
        identity, "c" * 64, "d" * 64,
    )
    operation = "config.apply" if kind == "apply" else "config.collect"
    request = c.OperationRequest(
        str(uuid4()), operation, mode, c.Scope(("router",), (), 100), context,
    )
    effect = c.PlannedEffect("effect-0", 0, kind, "router", "collect")
    settings = replace(SettingsSnapshot(), ansible=AnsibleSettings(
        enabled, "enforce" if enforce else "audit", False,
    ))
    plan = c.OperationPlan(
        request.operation_id, operation, mode, ("router",),
        (c.public_object({"target_id": "router"}),), context,
        c.digest(request), "e" * 64, identity.bundle_sha256, identity.reducer_version,
        (effect,), (), (), c.public_object({}), c.OutputIntent(), 1, 300000, (),
        "f" * 64, settings=settings,
    )
    plan = replace(plan, plan_digest=plan_digest(plan))
    binding = bind_plan(plan, "owned-root", 0)
    state, reviewer, clock, cancel = HostState(binding), Review(), Clock(), Cancel()
    consent = TrustedConsentAdapter(reviewer)
    broker = AuthorizationBroker(state, consent)
    receipt = consent.review(plan, binding, clock.now, 60.0)
    decision = DecisionResult(
        "allow", ("netops.companion.reviewed",), "reviewed",
        (EffectDescriptor("request_effect", c.public_object({"kind": kind})),),
        identity.bundle_sha256,
    )
    grant = broker.issue(plan, receipt, decision, clock.now)
    session = broker.consume(grant, binding, clock.now)
    effect_binding = c.EffectBinding(
        binding, str(uuid4()), state.current.revision, effect.occurrence_id,
        effect.target_id, effect.step_id, (),
    )
    permit = broker.permit(session, effect_binding, clock.now)
    if enter:
        assert broker.enter(permit, effect_binding, clock.now)
    invocation = _HostInvocation(permit, effect_binding, str(uuid4()), kind)
    return request, plan, state, broker, clock, cancel, invocation


def bridge(env):
    _, plan, _, broker, clock, cancel, invocation = env
    return HostDispatchControl(broker, (invocation,), plan, clock, cancel, clock.now)


def dispatch(env, phase="credential", sequence=0):
    request, plan, _, _, _, _, invocation = env
    return DispatchBinding(
        request.operation_id, plan.plan_digest, invocation.binding.plan.controller_digest,
        invocation.invocation_id, invocation.binding.occurrence_id,
        invocation.binding.target_id, invocation.binding.step_id, phase, sequence,
    )


def test_t08_worker_assertion_cannot_replace_entered_host_invocation():
    env = actual_host(enter=False)
    with pytest.raises(ProtocolError):
        bridge(env)


def test_t08_exact_host_dispatch_is_ordered_private_and_one_use():
    env = actual_host()
    control = bridge(env)
    control.ready(NONCE)
    first = control.request_dispatch(dispatch(env), env[5])
    assert first.binding == dispatch(env)
    assert repr(first) == "<private>"
    with pytest.raises(TypeError):
        pickle.dumps(first)
    second = control.request_dispatch(dispatch(env, "task", 1), env[5])
    assert second.binding.phase == "task"
    with pytest.raises(ProtocolError):
        control.request_dispatch(dispatch(env, "task", 1), env[5])
    assert env[3].is_revoked(env[0].operation_id)


@pytest.mark.parametrize("change", ["target", "task", "invocation", "plan", "controller", "skip"])
def test_t08_changed_dispatch_identity_revokes_not_worker_authorized(change):
    env = actual_host()
    control = bridge(env)
    control.ready(NONCE)
    changes = {
        "target": {"target_id": "other"}, "task": {"task_id": "apply"},
        "invocation": {"invocation_id": str(uuid4())}, "plan": {"plan_digest": "0" * 64},
        "controller": {"controller_digest": "0" * 64}, "skip": {"phase": "task", "sequence": 1},
    }
    with pytest.raises(ProtocolError):
        control.request_dispatch(replace(dispatch(env), **changes[change]), env[5])
    assert env[3].is_revoked(env[0].operation_id)


@pytest.mark.parametrize("stop", ["cancel", "kill", "expiry", "broker-revoke"])
def test_t14_host_cancel_kill_expiry_and_revoke_block_next_phase(stop):
    env = actual_host()
    control = bridge(env)
    control.ready(NONCE)
    control.request_dispatch(dispatch(env), env[5])
    if stop == "cancel":
        env[5].value = True
    elif stop == "kill":
        env[2].current = replace(env[2].current, dispatch_enabled=False)
    elif stop == "expiry":
        env[4].now += 60.0
    else:
        env[3].revoke(env[0].operation_id)
    with pytest.raises(ProtocolError):
        control.request_dispatch(dispatch(env, "task", 1), env[5])
    assert env[3].is_revoked(env[0].operation_id)


def test_t33_host_budget_rounds_down_and_readiness_does_not_restart_consent():
    env = actual_host()
    control = bridge(env)
    env[4].now += 12.0009
    budget = control.ready(NONCE)
    assert 47998 <= budget.authorization_remaining_ms <= 47999
    assert budget.operation_remaining_ms <= 287999
    with pytest.raises(ProtocolError):
        control.ready("ab" * 32)
    env[4].now += 47.9991
    with pytest.raises(ProtocolError):
        control.request_dispatch(dispatch(env), env[5])


@pytest.mark.parametrize("mode,enabled,enforce", [
    (c.Mode.OBSERVE, False, False),
    (c.Mode.APPLY, True, False),
])
def test_t08_disabled_or_audit_mutation_cannot_enter_bridge(mode, enabled, enforce):
    env = actual_host(
        mode, "apply" if mode == c.Mode.APPLY else "collect",
        enabled=enabled, enforce=enforce,
    )
    with pytest.raises(ProtocolError):
        bridge(env)


class Processes:
    """Fake ProcessPort: capture private handoff; launch no controller process."""

    def __init__(self, env):
        self.env = env
        self.launches = []
        self.private = []
        self.error = None
        self.installation = ControllerInstallation(
            c.ControllerContext(env[0].context), "linux", "/owned/controller/bin/python",
            "1" * 64, "2" * 64,
        )

    def verify(self, context, state):
        return self.installation

    def run(self, launch, private_input, cancel):
        self.launches.append(launch)
        self.private.append(private_input)
        launch.control.ready(NONCE)
        launch.control.request_dispatch(dispatch(self.env), cancel)
        launch.control.request_dispatch(dispatch(self.env, "task", 1), cancel)
        if self.error is not None:
            raise self.error
        return ProcessResult((c.TargetOutcome(
            "router", c.OutcomeStatus.SUCCEEDED, True,
            native_payload=c.public_object({"commands": 1}),
        ),), 0, c.CleanupOutcome("succeeded"))


@pytest.fixture
def launcher_case(monkeypatch, tmp_path):
    env = actual_host()
    request, plan, _, _, clock, cancel, _ = env
    control = bridge(env)
    target = CredentialTarget(
        "router", "collect", "nov19-router", "192.0.2.90", "cisco_ios",
        "ssh", 22, (), ("username", "password"), known_hosts_ref="owned-known-hosts",
    )
    scope = CredentialScope(
        request.operation_id, c.ControllerContext(request.context),
        control._invocations[0].binding.plan.controller_digest,
        request.context.route_digest, (target,), clock.now + 60.0,
    )
    monkeypatch.setenv("NETOPS_CRED_NOV19_ROUTER_USER", "operator")
    monkeypatch.setenv("NETOPS_CRED_NOV19_ROUTER_PASS", SENTINEL)
    resolver = ScopedCredentialResolver(
        CredentialVault(tmp_path / "unopened"), Routes(scope), clock,
    )
    value = resolver.resolve(scope, UnlockSession(scope, None, Admission()))
    credentials = HostControllerCredentials(value, scope, control)
    processes, revokes, events = Processes(env), RevokePort(), Events()
    launcher = ControllerLauncher(processes, revokes, object(), clock, events)
    return env, credentials, processes, revokes, events, launcher


def test_t13_actual_launcher_private_frame_never_argv_or_safe_outcome(launcher_case, caplog):
    env, credentials, processes, revokes, _, launcher = launcher_case
    caplog.set_level("INFO")
    outcome = launcher.run(c.ControllerRequest(env[0], env[1]), credentials, env[5])
    assert outcome.status == c.OutcomeStatus.SUCCEEDED
    assert len(processes.launches) == 1
    launch = processes.launches[0]
    assert launch.installation._argv(7) == (
        "/owned/controller/bin/python", "-I", "-m", "netops.ansible.worker", "--control-fd", "7",
    )
    assert SENTINEL not in repr(launch)
    assert SENTINEL not in repr(launch.installation._argv(7))
    assert SENTINEL not in c.canonical_bytes(outcome).decode()
    assert SENTINEL not in caplog.text
    assert SENTINEL in json.dumps(_decode_frame(processes.private[0])["credentials"])
    assert env[3].is_revoked(env[0].operation_id)
    assert revokes.operations == [env[0].operation_id]
    for boundary in ("controller.launch", "operation.step", "consent.invalidated", "cleanup.result"):
        records = [record for record in caplog.records if record.getMessage() == boundary]
        assert records, boundary
        assert all(record.metric.startswith("netops.") and record.metric_value == 1
                   for record in records)


def test_t32_throwing_sink_never_replaces_real_launcher_result(launcher_case):
    env, credentials, processes, _, events, launcher = launcher_case
    events.throw = True
    outcome = launcher.run(c.ControllerRequest(env[0], env[1]), credentials, env[5])
    assert outcome.status == c.OutcomeStatus.SUCCEEDED
    assert processes.launches
    assert launcher._observations.sink_failures > 0


def test_t14_process_fault_and_revoke_fault_remain_separate_safe_errors(launcher_case):
    env, credentials, processes, revokes, _, launcher = launcher_case
    processes.error = RuntimeError(SENTINEL)
    revokes.throw = True
    outcome = launcher.run(c.ControllerRequest(env[0], env[1]), credentials, env[5])
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert outcome.errors
    assert outcome.cleanup.status == "failed"
    assert outcome.cleanup.errors
    assert SENTINEL not in c.canonical_bytes(outcome).decode()


def test_t13_windows_launch_is_fixed_wsl_exec_not_native_or_shell():
    context = c.ControllerContext(actual_host()[0].context)
    installation = ControllerInstallation(
        context, "windows-wsl", "/owned/controller/bin/python",
        "1" * 64, "2" * 64, r"C:\Windows\System32\wsl.exe", "Qualified-NetOps",
    )
    assert installation._argv(9) == (
        r"C:\Windows\System32\wsl.exe", "--distribution", "Qualified-NetOps",
        "--exec", "/owned/controller/bin/python", "-I", "-m",
        "netops.ansible.worker", "--control-fd", "9",
    )
    with pytest.raises(c.ContractError):
        replace(installation, wsl_distribution="Qualified; bad-shell")
    with pytest.raises(c.ContractError):
        replace(installation, python=r"C:\Python\python.exe")
