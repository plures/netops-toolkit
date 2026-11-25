"""Independent successor safety oracles; all consequential effect ports are fake."""

from __future__ import annotations

import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from netops.ansible import contracts as c
from netops.ansible.controller_control import _Stop
from netops.ansible.controller_process import _ProcessWatchdog
from netops.dependencies._assets import AssetResponse
from netops.dependencies.service import DependencyRegistry
from tests import test_i02_author_assets as assets
from tests import test_nov19_independent_controller_execution as host
from tests import test_nov19_independent_controller_process as process
from tests.policy import test_lifecycle_execution as lifecycle


@pytest.mark.parametrize("barrier", ["verifier", "private-input", "host-snapshot"])
def test_parent_cancel_revokes_actual_host_authority_while_port_stalls(
    monkeypatch, tmp_path, barrier,
):
    """Cancellation must not depend on the stalled dispatch thread polling it."""
    env, credentials, processes, revokes, _, launcher = host.launcher_case.__wrapped__(
        monkeypatch, tmp_path,
    )
    entered, release, revoked = threading.Event(), threading.Event(), threading.Event()
    outcomes, errors = [], []
    original_revoke = revokes.revoke

    def observe_revoke(operation):
        original_revoke(operation)
        revoked.set()

    monkeypatch.setattr(revokes, "revoke", observe_revoke)
    if barrier == "verifier":
        owner, method = processes, "verify"
    elif barrier == "private-input":
        owner, method = processes, "run"
    else:
        owner, method = env[2], "snapshot"
    original = getattr(owner, method)

    def stalled(*args, **kwargs):
        entered.set()
        if not release.wait(5):
            raise RuntimeError("independent barrier timeout")
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, method, stalled)

    def run():
        try:
            outcomes.append(launcher.run(c.ControllerRequest(env[0], env[1]), credentials, env[5]))
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert entered.wait(1), "Actual selected external port was never reached"
        env[5].value = True
        assert revoked.wait(2.2), "Independent watchdog never revoked the credential resolver"
        stop = launcher._active[env[0].operation_id]
        assert stop._event.is_set()
        assert stop.reason == c.ReasonCode.CANCELLED
        # Inspect the actual broker's revocation fact, not a dispatch read of parent cancellation.
        assert env[3].is_revoked(env[0].operation_id)
        assert env[0].operation_id in revokes.operations
    finally:
        release.set()
        worker.join(3)
    assert not worker.is_alive()
    assert not errors
    assert outcomes[0].status != c.OutcomeStatus.SUCCEEDED


def test_owned_process_watchdog_samples_parent_and_signals_only_exact_owned_pid(monkeypatch):
    """A running monitor must terminate the fake owned group without host polling."""
    env, _, launch, _, _, fake_os, _, _, child = process.process_case.__wrapped__(
        monkeypatch, SimpleNamespace(param=None),
    )
    sampled, signalled = threading.Event(), threading.Event()
    original = fake_os.killpg

    def signal(pid, value):
        original(pid, value)
        signalled.set()

    monkeypatch.setattr(fake_os, "killpg", signal)

    class Clock:
        def monotonic(self):
            sampled.set()
            return env[4].now

    stop = _Stop(env[5])
    monitor = _ProcessWatchdog(child.pid, launch, stop, Clock())
    monitor.start()
    try:
        assert sampled.wait(1)
        env[5].value = True
        assert signalled.wait(2.2), "Parent cancellation never reached the actual owned monitor"
        assert stop.reason == c.ReasonCode.CANCELLED
        assert fake_os.signals[0] == (7331001, 15)
        assert all(pid == 7331001 for pid, _ in fake_os.signals)
    finally:
        assert monitor.close()


@pytest.mark.parametrize("control_throws", [False, True])
def test_cleanup_preserves_all_prior_refs_errors_and_attempts_both_revocations(
    monkeypatch, tmp_path, control_throws,
):
    """Secondary revoke failures may neither overwrite facts nor short-circuit teardown."""
    env, credentials, processes, revokes, _, launcher = host.launcher_case.__wrapped__(
        monkeypatch, tmp_path,
    )
    original = processes.run
    prior = tuple(c.SafeError(
        c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
        next_action=label,
    ) for label in ("preserve-owned-directory", "preserve-private-channel"))
    refs = ("owned-controller-private-dir", "owned-controller-channel")
    primary = c.SafeError(
        c.ErrorCategory.EXECUTION, c.ReasonCode.CONTROL_LOST, c.Stage.CONTROLLER,
    )

    def failed_cleanup(*args):
        return replace(
            original(*args), cleanup=c.CleanupOutcome("failed", refs, prior),
            exit_code=1, error=primary,
        )

    monkeypatch.setattr(processes, "run", failed_cleanup)
    control_attempts = []
    original_revoke = credentials._control.revoke

    def revoke(operation):
        control_attempts.append(operation)
        original_revoke(operation)
        if control_throws:
            raise RuntimeError("private-control-revoke-detail")

    monkeypatch.setattr(credentials._control, "revoke", revoke)
    revokes.throw = True
    outcome = launcher.run(c.ControllerRequest(env[0], env[1]), credentials, env[5])
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert primary in outcome.errors
    assert outcome.cleanup.status == "failed"
    assert outcome.cleanup.remaining_refs == refs
    assert all(error in outcome.cleanup.errors for error in prior)
    assert len(outcome.cleanup.errors) == len(prior) + 1 + int(control_throws)
    assert control_attempts == [env[0].operation_id]
    assert revokes.operations == [env[0].operation_id]
    assert "private-control-revoke-detail" not in c.canonical_bytes(outcome).decode()


@pytest.mark.parametrize("invalid", [-1.0, float("nan"), float("inf"), float("-inf"), 5.0])
@pytest.mark.parametrize("position,expected_calls", [
    ("before-first-transport", 0), ("retry-delay", 1),
    ("before-retry-transport", 1), ("post-response", 1),
    ("second-retry-delay", 2), ("before-second-retry", 2),
    ("post-retried-response", 3),
])
def test_invalid_acquisition_clock_never_adds_transport_or_reenters_permit(
    tmp_path, invalid, position, expected_calls, monkeypatch,
):
    """Reject each invalid sample; the one-use permit cannot fund a recovery retry."""
    policy = lifecycle.policy.__wrapped__()
    responses = (AssetResponse(assets.URL, lifecycle.DATA),)
    if position in ("retry-delay", "before-retry-transport"):
        responses = (ConnectionError("fake-transient"), *responses)
    if position in ("second-retry-delay", "before-second-retry", "post-retried-response"):
        responses = (ConnectionError("fake-transient-1"), ConnectionError("fake-transient-2"), *responses)
    acquisition, lock, permit, invocation, transport, _, _ = assets.admitted(
        tmp_path, policy, responses,
    )
    prefix = {
        "before-first-transport": [10.0],
        "retry-delay": [10.0, 10.0],
        "before-retry-transport": [10.0, 10.0, 10.0],
        "post-response": [10.0, 10.0],
        "second-retry-delay": [10.0] * 4,
        "before-second-retry": [10.0] * 5,
        "post-retried-response": [10.0] * 6,
    }[position]
    values = iter([*prefix, invalid])

    class Clock:
        def monotonic(self):
            return next(values, 10.0)

    acquisition._clock = Clock()
    entered = []
    real_enter = acquisition._authorization.enter_lifecycle

    def enter(*args):
        result = real_enter(*args)
        entered.append(args)
        return result

    monkeypatch.setattr(acquisition._authorization, "enter_lifecycle", enter)
    entry, cancel = DependencyRegistry.load().entry("paramiko"), assets.WaitingCancel()
    with pytest.raises((c.ContractError, ValueError, InterruptedError)):
        acquisition.download(entry, lock, permit, invocation, cancel)
    assert len(transport.calls) == expected_calls
    assert len(entered) == 1
    with pytest.raises(Exception):
        acquisition.download(entry, lock, permit, invocation, cancel)
    assert len(transport.calls) == expected_calls
    assert len(entered) == 1, "A rejected clock may not re-enter consumed lifecycle authority"


def test_valid_download_keeps_original_budget_and_single_entry(tmp_path):
    """Positive control proves the denial tests are not testing an inert downloader."""
    acquisition, lock, permit, invocation, transport, _, _ = assets.admitted(
        tmp_path, lifecycle.policy.__wrapped__(), (AssetResponse(assets.URL, lifecycle.DATA),),
    )
    result = acquisition.download(
        DependencyRegistry.load().entry("paramiko"), lock, permit, invocation,
        assets.WaitingCancel(),
    )
    assert result.content == lifecycle.DATA
    assert len(transport.calls) == 1
    assert 0 < transport.calls[0][1] <= 20.0
