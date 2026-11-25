"""Author regressions for attributed local review findings; no real OS effects."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from netops.ansible import contracts as c
from netops.ansible.controller import ControllerInstallation, ControllerLauncher, ProcessResult
from netops.ansible.controller_control import _Stop
from tests.test_controller_cancellation import Sink
from tests.test_controller_cancellation import host as host
from tests.test_controller_cancellation import prepared as prepared

pytest_plugins = ("tests.test_controller_protocol",)


@pytest.mark.parametrize("stalled", ["verify", "process", "snapshot"])
def test_parent_port_cancel_is_observed_independently_during_stalls(host, prepared, stalled):
    control, broker, state, clock, parent, _, _ = host
    credentials, resolver = prepared
    entered, release = threading.Event(), threading.Event()

    def wait():
        entered.set()
        if not release.wait(5.0):
            raise RuntimeError("synthetic-stall-timeout")

    class Process:
        def verify(self, context, state):
            if stalled == "verify":
                wait()
            return ControllerInstallation(context, "linux", "/owned/python", "a" * 64, "b" * 64)

        def run(self, launch, private, stop):
            if stalled == "process":
                wait()
            return ProcessResult((), 130, c.CleanupOutcome("succeeded"))

    if stalled == "snapshot":
        snapshot = state.snapshot

        def blocked_snapshot(operation):
            wait()
            return snapshot(operation)

        state.snapshot = blocked_snapshot
    launcher = ControllerLauncher(Process(), resolver, None, clock, Sink())
    request = c.ControllerRequest(c.OperationRequest(
        control._operation, control._plan.operation, control._plan.requested_mode,
        c.Scope(control._plan.targets), control._plan.context,
    ), control._plan)
    with ThreadPoolExecutor(max_workers=1) as pool:
        executing = pool.submit(launcher.run, request, credentials, parent)
        assert entered.wait(1.0)
        active = launcher._active[control._operation]
        parent.event.set()
        try:
            observed = active._event.wait(0.5)
        finally:
            release.set()
        result = executing.result(timeout=3.0)
    assert observed, "independent watcher waited for stalled main loop to sample parent port"
    assert broker.is_revoked(control._operation)
    assert result.status != c.OutcomeStatus.SUCCEEDED and launcher._active == {}


def test_owned_process_watchdog_samples_parent_port_without_main_loop(monkeypatch, record_property):
    from netops.ansible import controller_process as module

    parent = SimpleNamespace(cancelled=False)
    parent.is_cancelled = lambda: parent.cancelled
    calls = []
    signalled = threading.Event()

    def signal(pid, value):
        calls.append((pid, value, time.perf_counter()))
        signalled.set()

    monkeypatch.setattr(module, "os", SimpleNamespace(killpg=signal))
    launch = SimpleNamespace(
        control=SimpleNamespace(_accepted=10.0, _authorization_deadline=20.0),
        start_deadline=15.0, operation_deadline=30.0, teardown_seconds=2.0,
    )
    stop = _Stop(parent)
    monitor = module._ProcessWatchdog(
        4321, launch, stop, SimpleNamespace(monotonic=lambda: 10.0),
    )
    monitor.start()
    received = time.perf_counter()
    parent.cancelled = True
    try:
        observed = signalled.wait(0.5)
    finally:
        assert monitor.close()
    assert observed, "parent port never latched without main-loop polling"
    assert len(calls) == 1 and calls[0][0] == 4321
    assert calls[0][2] - received < 2.0 and stop.reason == c.ReasonCode.CANCELLED
    record_property("fake_parent_cancel_perf_seconds", received)
    record_property("fake_owned_group_signal_perf_seconds", calls[0][2])


@pytest.mark.parametrize("fails", ["control", "resolver", "both"])
def test_revoke_failures_preserve_all_prior_cleanup_and_attempt_both_owners(
    host, prepared, monkeypatch, fails,
):
    control, _, _, clock, cancel, _, _ = host
    credentials, _ = prepared
    original = c.SafeError(
        c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
        next_action="preserve-original-private-directory",
    )
    primary = c.SafeError(
        c.ErrorCategory.EXECUTION, c.ReasonCode.CONTROL_LOST, c.Stage.CONTROLLER,
    )
    called = []
    revoke = control.revoke

    def revoke_control(operation):
        called.append("control")
        if fails in ("control", "both"):
            raise RuntimeError("synthetic-control-revoke")
        revoke(operation)

    def revoke_credentials(operation):
        called.append("resolver")
        if fails in ("resolver", "both"):
            raise RuntimeError("synthetic-resolver-revoke")

    monkeypatch.setattr(control, "revoke", revoke_control)

    class Process:
        def verify(self, context, state):
            return ControllerInstallation(context, "linux", "/owned/python", "a" * 64, "b" * 64)

        def run(self, launch, private, stop):
            return ProcessResult((), 1, c.CleanupOutcome(
                "failed", ("owned-private-directory",), (original,),
            ), primary)

    launcher = ControllerLauncher(
        Process(), SimpleNamespace(revoke=revoke_credentials), None, clock, Sink(),
    )
    result = launcher.run(c.ControllerRequest(c.OperationRequest(
        control._operation, control._plan.operation, control._plan.requested_mode,
        c.Scope(control._plan.targets), control._plan.context,
    ), control._plan), credentials, cancel)
    assert called == ["control", "resolver"]
    assert result.cleanup.remaining_refs == ("owned-private-directory",)
    assert original in result.cleanup.errors and primary in result.errors
    assert len(result.cleanup.errors) == (3 if fails == "both" else 2)


def test_control_revocation_latch_denies_new_phases_without_entering_held_broker(host):
    from netops.ansible.controller_protocol import DispatchBinding, ProtocolError

    control, broker, _, _, parent, _, _ = host
    entry = control._invocations[0]
    binding = DispatchBinding(
        control._operation, entry.binding.plan.plan_digest,
        entry.binding.plan.controller_digest, entry.invocation_id,
        entry.binding.occurrence_id, entry.binding.target_id, entry.binding.step_id,
        "credential", 0,
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        with broker._lock:
            control._signal_revoke()
            future = pool.submit(control.request_dispatch, binding, parent)
            with pytest.raises(ProtocolError):
                future.result(timeout=0.5)
    assert control._next[entry.binding.occurrence_id] == 0


def test_actual_private_input_write_stall_still_signals_only_owned_group(monkeypatch):
    from netops.ansible.controller_protocol import _encode_frame
    from tests.test_nov19_independent_controller_process import process_case

    env, adapter, launch, _, _, fake_os, _, private, _ = process_case.__wrapped__(
        monkeypatch, SimpleNamespace(param=None),
    )
    entered, release, signalled = threading.Event(), threading.Event(), threading.Event()
    write, signal = private.write, fake_os.killpg

    def stalled(value):
        entered.set()
        assert release.wait(5)
        return write(value)

    def observed_signal(pid, value):
        signal(pid, value)
        signalled.set()

    private.write = stalled
    monkeypatch.setattr(fake_os, "killpg", observed_signal)
    stop = _Stop(env[5])
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(adapter.run, launch, _encode_frame({"private": "SYNTHETIC"}), stop)
        assert entered.wait(1)
        env[5].value = True
        try:
            assert signalled.wait(0.5)
            assert stop.reason == c.ReasonCode.CANCELLED
        finally:
            release.set()
        result = future.result(timeout=3)
    assert result.exit_code != 0
    assert fake_os.signals and all(pid == 7331001 for pid, _ in fake_os.signals)


def test_watchdog_revocation_collects_independent_failure_and_pending_cleanup():
    from netops.ansible.controller import _WatchdogRevocations

    entered, release, failed = threading.Event(), threading.Event(), threading.Event()

    def blocked():
        entered.set()
        assert release.wait(5)

    def throwing():
        failed.set()
        raise RuntimeError("SYNTHETIC-PRIVATE-DETAIL")

    original = c.SafeError(
        c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
        next_action="preserve-prior-owned-error",
    )
    revocations = _WatchdogRevocations()
    revocations.start((("pending-owner", blocked), ("throwing-owner", throwing)))
    assert entered.wait(1) and failed.wait(1)
    try:
        observed = revocations.collect(c.CleanupOutcome("failed", ("prior-owned",), (original,)))
        assert observed.remaining_refs == ("prior-owned", "pending-owner")
        assert original in observed.errors and len(observed.errors) == 3
        assert "SYNTHETIC-PRIVATE-DETAIL" not in repr(observed)
    finally:
        release.set()
