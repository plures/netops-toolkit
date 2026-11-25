"""S02 author seams: real A01 host authority, fake native/control/process I/O."""

import pickle
import runpy
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import ModuleType, SimpleNamespace
from uuid import uuid4

import pytest

from netops.ansible import action_runtime
from netops.ansible import contracts as c
from netops.ansible.controller import (
    ControllerInstallation,
    ControllerLauncher,
    ProcessResult,
    _ControllerObservations,
)
from netops.ansible.controller_control import (
    HostControllerCredentials,
    HostDispatchControl,
    _HostInvocation,
    _Stop,
)
from netops.ansible.controller_credentials import _ControllerCredentialAdmission
from netops.ansible.controller_protocol import ControllerBudget, ProtocolError, _BudgetWindow
from netops.ansible.credentials import RouteBinding, ScopedCredentialResolver, UnlockSession
from netops.ansible.policy.authorization import (
    AdmissionSnapshot,
    AuthorizationBroker,
    TrustedConsentAdapter,
    bind_plan,
)
from netops.ansible.policy.contracts import DecisionResult, EffectDescriptor
from netops.ansible.worker import _parse_envelope
from netops.ansible.worker_broker import _HostChannel, _safe_action_result, _WorkerBroker

pytest_plugins = ("tests.test_controller_protocol",)
NONCE = "c" * 64
SECRET = "SYNTHETIC-S02-must-not-leak"


class Cancel:
    def __init__(self):
        self.event = threading.Event()

    def is_cancelled(self):
        return self.event.is_set()

    def wait(self, timeout):
        return self.event.wait(timeout)


class State:
    def __init__(self, binding):
        self.binding = binding
        self.revision = 0
        self.cancelled = False
        self.dispatch_enabled = True
        self.mutex = threading.RLock()

    def lock(self, operation_id):
        return self.mutex

    def snapshot(self, operation_id):
        return AdmissionSnapshot(self.binding, self.revision, self.cancelled, self.dispatch_enabled)

    def compare_revision(self, operation_id, previous, following):
        if self.revision != previous:
            return False
        self.revision = following
        return True


class Reviewer:
    def confirm(self, plan, binding, deadline):
        return True


@pytest.fixture
def host(plan, binding):
    clock = SimpleNamespace(value=10.0)
    clock.monotonic = lambda: clock.value
    plan_binding = bind_plan(plan, "synthetic-owned-root", 0)
    state = State(plan_binding)
    consent = TrustedConsentAdapter(Reviewer())
    broker = AuthorizationBroker(state, consent)
    decision = DecisionResult(
        "allow", ("netops.companion.test",), "allowed",
        (EffectDescriptor("request_effect", c.public_object({"kind": "collect"})),),
        plan.policy_digest,
    )
    receipt = consent.review(plan, plan_binding, 10.0, 10.0)
    session = broker.consume(broker.issue(plan, receipt, decision, 10.0), plan_binding, 10.0)
    effect_binding = c.EffectBinding(
        plan_binding, str(uuid4()), state.revision, "collect-0",
        binding.target_id, binding.task_id, (),
    )
    permit = broker.permit(session, effect_binding, clock.value)
    broker.enter(permit, effect_binding, clock.value)
    cancel = Cancel()
    control = HostDispatchControl(
        broker, (_HostInvocation(permit, effect_binding, binding.invocation_id, "collect"),),
        plan, clock, cancel, clock.value,
    )
    return control, broker, state, clock, cancel, permit, effect_binding


def test_real_host_subpermits_are_one_use_and_not_independent_authority(host, binding):
    control, broker, state, _, cancel, permit, effect = host
    budget = control.ready(NONCE)
    assert budget.authorization_remaining_ms == 10000
    first = control.request_dispatch(binding, cancel)
    assert first.binding == binding
    assert repr(first) == "<private>"
    with pytest.raises(TypeError):
        pickle.dumps(first)
    second = control.request_dispatch(replace(binding, phase="task", sequence=1), cancel)
    assert second.binding.phase == "task"
    assert state.revision == 1
    with pytest.raises(ProtocolError):
        control.request_dispatch(replace(binding, phase="task", sequence=1), cancel)
    assert broker.is_revoked(binding.operation_id)
    assert broker.reconcile(permit) == effect


@pytest.mark.parametrize("change", ["cancel", "expiry", "kill", "drift", "revoke", "backwards"])
def test_current_host_facts_rechecked_at_every_phase(host, binding, change):
    control, broker, state, clock, cancel, _, _ = host
    control.ready(NONCE)
    control.request_dispatch(binding, cancel)
    if change == "cancel":
        cancel.event.set()
    elif change == "expiry":
        clock.value = 20.0
    elif change == "kill":
        state.dispatch_enabled = False
    elif change == "drift":
        state.binding = replace(state.binding, generation=1)
    elif change == "revoke":
        broker.revoke(binding.operation_id)
    else:
        clock.value = 9.0
    with pytest.raises(ProtocolError):
        control.request_dispatch(replace(binding, phase="task", sequence=1), cancel)
    assert control._next[binding.occurrence_id] == 1
    assert broker.is_revoked(binding.operation_id)


def test_host_ready_replay_or_receipt_never_extends_original_deadline(host):
    control, broker, _, clock, _, _, _ = host
    clock.value = 18.001
    first = control.ready(NONCE)
    assert first.authorization_remaining_ms <= 1999
    with pytest.raises(ProtocolError):
        control.ready("d" * 64)
    clock.value = 20.0
    with pytest.raises(ProtocolError):
        control.check()
    assert broker.is_revoked(control._operation)


def test_accepted_cancel_stops_saturated_new_dispatch_and_preserves_issued_fact(
    host, binding, record_property,
):
    control, broker, state, _, cancel, permit, effect = host
    control.ready(NONCE)
    control.request_dispatch(binding, cancel)
    received = time.perf_counter()
    cancel.event.set()
    control.revoke(binding.operation_id)
    attempted = replace(binding, phase="task", sequence=1)

    def submit(_):
        with pytest.raises(ProtocolError):
            control.request_dispatch(attempted, cancel)
        return time.perf_counter()

    with ThreadPoolExecutor(max_workers=50) as pool:
        rejected = tuple(pool.map(submit, range(200)))
    assert control._next[binding.occurrence_id] == 1
    assert max(rejected) - received < 2.0
    record_property("fake_cancel_received_perf_seconds", received)
    record_property("fake_last_rejection_perf_seconds", max(rejected))
    record_property("fake_stop_bound_seconds", max(rejected) - received)
    assert broker.reconcile(permit) == effect
    # Already entered factual completion survives revoke, but cannot re-admit.
    broker.complete(permit, str(uuid4()), state.revision, 21.0)
    assert broker.is_revoked(binding.operation_id)


def test_duplicate_parallel_phase_has_at_most_one_dispatch(host, binding):
    control, _, _, _, cancel, _, _ = host
    control.ready(NONCE)

    def submit(_):
        try:
            return control.request_dispatch(binding, cancel)
        except ProtocolError:
            return None

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = tuple(pool.map(submit, range(40)))
    assert sum(value is not None for value in results) == 1


def test_forged_binding_is_not_pending_host_invocation(host, binding):
    control, broker, _, _, cancel, _, _ = host
    control.ready(NONCE)
    with pytest.raises(ProtocolError):
        control.request_dispatch(replace(binding, invocation_id=str(uuid4())), cancel)
    assert control._next[binding.occurrence_id] == 0
    assert broker.is_revoked(binding.operation_id)


def test_direct_json_credentials_cannot_launch_or_touch_state(operation_request, plan):
    calls = []

    class Process:
        def verify(self, *args):
            calls.append("verify")
            pytest.fail("forged authority reached verification")

    class Sink:
        def emit(self, event):
            assert SECRET not in repr(event)

    result = ControllerLauncher(Process(), None, None, None, Sink()).run(
        c.ControllerRequest(operation_request, plan), {"grant": True, "password": SECRET}, Cancel(),
    )
    assert result.status == c.OutcomeStatus.BLOCKED
    assert calls == []
    assert SECRET not in str(c.wire(result))


@pytest.mark.parametrize("delay", [2.001, 60.0])
def test_stalled_control_response_cannot_renew_or_dispatch(binding, delay):
    clock = SimpleNamespace(value=8000000.0)
    clock.monotonic = lambda: clock.value
    window = _BudgetWindow(clock, NONCE, binding.plan_digest)
    window.accept(ControllerBudget(NONCE, 100000, 100000), binding.plan_digest)

    class Frames:
        def send(self, value, timeout=2.0):
            pass

        def receive(self, timeout, cancel):
            clock.value += delay
            return {
                "kind": "permit", "binding": binding._wire(),
                "budget": ControllerBudget(NONCE, 100000, 100000)._wire(),
            }

    channel = _HostChannel(Frames(), window, Cancel())
    with pytest.raises(ProtocolError):
        channel.dispatch(binding)
    with pytest.raises(ProtocolError):
        window.check()


def test_worker_broker_replay_scope_auth_and_cancel_are_fail_closed(
    monkeypatch, envelope, binding,
):
    from netops.ansible import worker_broker as module

    clock = SimpleNamespace(value=100.0)
    clock.monotonic = lambda: clock.value
    window = _BudgetWindow(clock, NONCE, binding.plan_digest)
    window.accept(ControllerBudget(NONCE, 100000, 100000), binding.plan_digest)
    calls = []
    host = SimpleNamespace(dispatch=lambda value: calls.append(value))
    broker = _WorkerBroker(
        Path("/synthetic-owned"), envelope["credentials"], ((binding, "collect"),),
        host, window, 5,
    )
    incoming = {"auth": broker._auth, "kind": "dispatch", "binding": binding._wire(), "result": None}
    sent = []

    class Frames:
        def __init__(self, channel):
            pass

        def receive_one(self, timeout):
            return incoming

        def send(self, value):
            sent.append(value)

        def close(self):
            pass

    monkeypatch.setattr(module, "_SocketFrames", Frames)
    broker._slots.acquire()
    broker._handle(None)
    assert len(calls) == 1
    assert sent[0]["kind"] == "credential"
    broker._slots.acquire()
    broker._handle(None)
    assert len(calls) == 1
    assert sent[-1] == {"kind": "rejected"}
    assert broker._stop.is_set()
    # Authentication is not an output/state field; only the private resolver
    # response legitimately carries selected credential values.
    assert broker._auth not in repr(sent)


def test_check_mode_action_returns_before_client_taskvars_or_super(monkeypatch):
    module = ModuleType("ansible.plugins.action")

    class Base:
        def run(self, *args, **kwargs):
            pytest.fail("check mode called ActionBase I/O")

    module.ActionBase = Base
    monkeypatch.setitem(sys.modules, "ansible.plugins.action", module)
    action_type = runpy.run_path(str(
        Path(__file__).parents[1] / "netops/ansible/action_plugins/netops_workflow.py",
    ))["NetopsWorkflowAction"]
    action = action_type()
    action._task = SimpleNamespace(check_mode=True)
    monkeypatch.setattr(action_runtime, "_CLIENT", object())
    assert action.run(task_vars={"secret": SECRET}) == {
        "changed": False, "skipped": True, "netops": {"executed": False},
    }


def test_result_minimizer_rejects_deliberate_native_leak_and_effect_lie(binding):
    with pytest.raises(ProtocolError):
        _safe_action_result({
            "status": "succeeded", "attempted": True, "changed": False,
            "remote_state": "unchanged", "line_count": 1, "raw_exception": SECRET,
        }, binding.target_id)
    with pytest.raises(c.ContractError):
        _safe_action_result({
            "status": "succeeded", "attempted": False, "changed": False,
            "remote_state": "unchanged", "line_count": 1,
        }, binding.target_id)


def test_nonthrowing_telemetry_sinks_cannot_discard_facts(operation_request, caplog):
    class Broken:
        def emit(self, event):
            raise RuntimeError(SECRET)

    observations = _ControllerObservations(Broken())
    with caplog.at_level("INFO", logger="netops.ansible.controller"):
        observations.record("controller.launch", "failed", operation_request,
                            reason=c.ReasonCode.CONTROL_LOST)
    record = next(record for record in caplog.records if record.msg == "controller.launch")
    assert record.metric == "netops.controller.launch.count"
    assert record.metric_dimensions == {
        "outcome": "failed", "reason": "control-lost", "stage": "controller",
    }
    assert not any(name.endswith("_id") for name in record.metric_dimensions)
    assert SECRET not in caplog.text
    assert observations.sink_failures == 1
    assert observations._counts[("controller.launch", "failed", "control-lost")] == 1


def test_stop_first_cause_is_idempotent():
    stop = _Stop(Cancel())
    stop.stop(c.ReasonCode.CANCELLED)
    stop.stop(c.ReasonCode.CONTROL_LOST)
    assert stop.reason == c.ReasonCode.CANCELLED
    assert stop.is_cancelled() and stop.wait(10.0)


@pytest.fixture
def prepared(host, scope, vault):
    control, _, _, clock, _, _, _ = host
    target = replace(
        scope.targets[0], task_id=control._plan.operation, port=2222,
        key_ref=None, known_hosts_ref="/owned/known-hosts",
    )
    selected = replace(
        scope, targets=(target,), controller_digest=c.digest(control._plan.context.controller_id),
        expires_at=20.0,
    )
    admission = _ControllerCredentialAdmission(control, selected)
    route = RouteBinding(
        selected.controller_digest, selected.route_digest, selected.targets, "a" * 64,
        True, True, "reject", True,
    )
    routes = SimpleNamespace(validate=lambda context, scope: route)
    resolver = ScopedCredentialResolver(vault, routes, clock)
    value = resolver.resolve(
        selected, UnlockSession(selected, "SYNTHETIC-S01-only-master", admission),
    )
    return HostControllerCredentials(value, selected, control), resolver


class Sink:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def test_real_resolution_to_launcher_to_fake_worker_scope_roundtrip(host, prepared, binding):
    from netops.ansible.controller_protocol import _decode_frame

    control, broker, _, clock, cancel, _, _ = host
    private, resolver = prepared
    called = []

    class Process:
        def verify(self, context, state):
            return ControllerInstallation(context, "linux", "/owned/bin/python", "a" * 64, "a" * 64)

        def run(self, launch, private_input, stop):
            frame = _decode_frame(private_input)
            frame["budget"] = launch.control.ready(NONCE)._wire()
            parsed = _parse_envelope(frame, NONCE)
            assert parsed.credentials["targets"][0]["fields"]["password"].startswith("SYNTHETIC-S01")
            for identity, _ in parsed.intents:
                launch.control.request_dispatch(identity, stop)
                launch.control.request_dispatch(replace(identity, phase="task", sequence=1), stop)
            called.append("run")
            assert "SYNTHETIC-S01" not in repr(launch)
            assert "SYNTHETIC-S01" not in repr(launch.installation._argv(17))
            return ProcessResult((c.TargetOutcome(
                binding.target_id, c.OutcomeStatus.SUCCEEDED, True,
                native_payload=c.public_object({"line_count": 3}),
            ),), 0, c.CleanupOutcome("succeeded"))

    sink = Sink()
    launcher = ControllerLauncher(Process(), resolver, None, clock, sink)
    result = launcher.run(c.ControllerRequest(
        c.OperationRequest(
            control._plan.operation_id, control._plan.operation, control._plan.requested_mode,
            c.Scope(control._plan.targets), control._plan.context,
        ), control._plan,
    ), private, cancel)
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert called == ["run"] and len(sink.events) > 0
    assert "SYNTHETIC-S01" not in c.canonical_bytes(result).decode("utf-8")
    assert "SYNTHETIC-S01" not in repr(sink.events)
    assert broker.is_revoked(control._operation)
    assert launcher._active == {}


@pytest.mark.parametrize("cause", ["cancel", "expiry"])
def test_independent_watchdog_and_immediate_cancel_stop_stalled_fake_process(
    host, prepared, cause, record_property,
):
    control, broker, _, clock, cancel, _, _ = host
    private, resolver = prepared
    entered, stopped = threading.Event(), threading.Event()
    received_at = []
    stopped_at = []

    class Process:
        def verify(self, context, state):
            return ControllerInstallation(context, "linux", "/owned/bin/python", "a" * 64, "a" * 64)

        def run(self, launch, private_input, stop):
            entered.set()
            assert stop.wait(0.01) or not stop.is_cancelled()
            deadline = time.perf_counter() + 1.5
            while not stop.is_cancelled() and time.perf_counter() < deadline:
                stop.wait(0.01)
            assert stop.is_cancelled()
            stopped_at.append(time.perf_counter())
            stopped.set()
            return ProcessResult((), 1, c.CleanupOutcome("succeeded"))

    launcher = ControllerLauncher(Process(), resolver, None, clock, Sink())
    request = c.ControllerRequest(c.OperationRequest(
        control._operation, control._plan.operation, control._plan.requested_mode,
        c.Scope(control._plan.targets), control._plan.context,
    ), control._plan)
    outputs = []
    thread = threading.Thread(target=lambda: outputs.append(launcher.run(request, private, cancel)))
    thread.start()
    try:
        assert entered.wait(1.0)
        received_at.append(time.perf_counter())
        if cause == "cancel":
            # The same private stop is called by WorkflowService.cancel before
            # broker/resolver locks or cancellation receipt clock observation.
            launcher._cancel(control._operation)
        else:
            clock.value = 20.0
        assert stopped.wait(1.5)
        thread.join(timeout=1.0)
        assert not thread.is_alive()
    finally:
        cancel.event.set()
        launcher._cancel(control._operation)
        thread.join(timeout=1.0)
    assert broker.is_revoked(control._operation)
    assert outputs[0].errors[0].reason in (c.ReasonCode.CANCELLED, c.ReasonCode.DEADLINE_EXCEEDED)
    if cause == "cancel":
        assert outputs[0].status == c.OutcomeStatus.CANCELLED
        assert outputs[0].exit_code == 130
    assert stopped_at[0] - received_at[0] < 2.0
    record_property("fake_stalled_" + cause + "_received_perf_seconds", received_at[0])
    record_property("fake_stalled_" + cause + "_stopped_perf_seconds", stopped_at[0])
    record_property("fake_stalled_" + cause + "_stop_seconds", stopped_at[0] - received_at[0])


def test_fork_action_resolves_and_admits_before_native_and_minimizes_return(
    monkeypatch, binding, envelope,
):
    seen = []

    class Native:
        def supports(self, kind):
            return kind == "collect"

        def run(self, kind, credential, jump):
            assert [entry[0] for entry in seen] == ["dispatch", "dispatch"]
            assert credential["fields"]["password"] == SECRET
            return {
                "status": "succeeded", "attempted": True, "changed": False,
                "remote_state": "unchanged", "line_count": 4,
            }

    client = action_runtime._ActionClient({
        "protocol": 1, "socket": "/owned/broker", "auth": NONCE,
        "intents": [{"handle": binding.occurrence_id, "binding": binding._wire(), "kind": "collect"}],
    }, Native())
    # Explicit fake fork identity, never an actual platform or fork claim.
    monkeypatch.setattr(action_runtime, "os", SimpleNamespace(
        name="posix", getpid=lambda: client._owner_pid + 1,
    ))

    def exchange(kind, selected, result=None):
        seen.append((kind, selected.phase, result))
        if selected.phase == "credential" and kind == "dispatch":
            return {
                "kind": "credential", "credential": envelope["credentials"]["targets"][0],
                "jump": None,
            }
        return {"kind": "admitted" if kind == "dispatch" else "completed"}

    monkeypatch.setattr(client, "_request", exchange)
    result = client.execute(binding.occurrence_id)
    assert result["status"] == "succeeded" and result["line_count"] == 4
    assert SECRET not in str(result) and SECRET not in repr(seen)
    assert [entry[:2] for entry in seen] == [
        ("dispatch", "credential"), ("dispatch", "task"), ("complete", "task"),
    ]


def test_actual_native_read_adapter_uses_in_process_send_and_never_returns_config(
    monkeypatch, envelope,
):
    seen = []

    class Connection:
        def __init__(self, credential, jump):
            assert credential["fields"]["password"] == SECRET

        def __enter__(self):
            return self

        def __exit__(self, *args):
            seen.append("closed")

        def send(self, command):
            seen.append(command)
            return "first\n" + SECRET

    monkeypatch.setattr(action_runtime, "_StrictConnection", Connection)
    result = action_runtime._NativeActions().run(
        "collect", envelope["credentials"]["targets"][0], None,
    )
    assert seen == ["show running-config", "closed"]
    assert result["line_count"] == 2 and result["status"] == "succeeded"
    assert SECRET not in str(result)


def test_mutation_without_bound_protected_intent_is_rejected_before_private_resolution(
    monkeypatch, binding,
):
    selected = replace(binding, phase="credential")
    def forbidden(*args, **kwargs):
        pytest.fail("unbound mutation reached private credential/task dispatch")

    monkeypatch.setattr(action_runtime._ActionClient, "_request", forbidden)
    with pytest.raises(ProtocolError) as caught:
        action_runtime._ActionClient({
            "protocol": 1, "socket": "/owned/broker", "auth": NONCE,
            "intents": [{
                "handle": selected.occurrence_id, "binding": selected._wire(), "kind": "apply",
            }],
        })
    assert caught.value.reason == c.ReasonCode.INPUT_BINDING_INVALID


@pytest.mark.parametrize("cause", ["cancel", "startup", "authorization", "clock-back"])
def test_owned_group_watchdog_is_independent_of_stalled_broker_and_worker(
    monkeypatch, cause, record_property,
):
    from netops.ansible import controller_process as module

    calls = []
    signalled = threading.Event()

    def kill_group(pid, selected_signal):
        calls.append((pid, int(selected_signal), time.perf_counter()))
        signalled.set()

    monkeypatch.setattr(module, "os", SimpleNamespace(killpg=kill_group))
    clock = SimpleNamespace(value=10.0)
    clock.monotonic = lambda: clock.value
    control = SimpleNamespace(_accepted=10.0, _authorization_deadline=20.0)
    launch = SimpleNamespace(
        control=control, start_deadline=15.0, operation_deadline=30.0, teardown_seconds=2.0,
    )

    class Parent:
        def is_cancelled(self):
            pytest.fail("independent watchdog polled a potentially stalled parent/broker")

    stop = _Stop(Parent())
    monitor = module._ProcessWatchdog(4321, launch, stop, clock)
    monitor.start()
    accepted = time.perf_counter()
    try:
        if cause == "cancel":
            stop.stop(c.ReasonCode.CANCELLED)
        elif cause == "startup":
            clock.value = 15.0
        elif cause == "authorization":
            monitor.ready.set()
            clock.value = 20.0
        else:
            clock.value = 9.0
        assert signalled.wait(1.0)
    finally:
        assert monitor.close()
    assert len(calls) == 1 and calls[0][0] == 4321
    assert calls[0][2] - accepted < 2.0
    assert stop.is_cancelled()
    record_property("fake_group_" + cause + "_accepted_perf_seconds", accepted)
    record_property("fake_group_" + cause + "_signal_perf_seconds", calls[0][2])
    record_property("fake_group_" + cause + "_signal_delay_seconds", calls[0][2] - accepted)
