"""Source-only finalization controls using existing fake external OS effects."""

import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from netops.ansible import contracts as c
from netops.ansible import controller_process as module
from netops.ansible.controller_control import _Stop
from netops.ansible.controller_protocol import ProtocolError, _encode_frame
from tests.test_nov19_independent_controller_process import process_case as process_case


@pytest.mark.parametrize("boundary,reference", (
    ("revoke", "owned-controller-control"),
    ("child", "owned-controller-child-descriptor"),
    ("channel", "owned-controller-channel"),
    ("stdin", "owned-controller-input"),
    ("teardown", "owned-posix-controller-group"),
))
def test_independent_cleanup_cannot_be_skipped_after_other_owner_failure(process_case, monkeypatch, boundary, reference):
    env, adapter, launch, frames, _, fake_os, child, input_pipe, _ = process_case
    calls = []
    original_teardown = adapter._teardown

    def teardown(*args):
        calls.append("teardown")
        if boundary == "teardown":
            raise OSError("synthetic teardown failure")
        return original_teardown(*args)

    def fail(*_):
        calls.append(boundary)
        raise OSError("synthetic independent owner failure")

    monkeypatch.setattr(adapter, "_teardown", teardown)
    frames.messages = iter([ProtocolError(c.ReasonCode.DEADLINE_EXCEEDED)])
    if boundary == "revoke":
        monkeypatch.setattr(launch.control, "revoke", fail)
    elif boundary == "child":
        close = child.close
        child_closes = []

        def close_child():
            child_closes.append(True)
            if len(child_closes) > 1:
                fail()
            close()

        monkeypatch.setattr(child, "close", close_child)
    elif boundary == "channel":
        monkeypatch.setattr(frames, "close", fail)
    elif boundary == "stdin":
        monkeypatch.setattr(input_pipe, "close", fail)
    result = adapter.run(launch, _encode_frame({"source-only": True}), _Stop(env[5]))
    assert result.error.reason == c.ReasonCode.DEADLINE_EXCEEDED
    assert result.cleanup.status == "failed"
    # Async revocation failure has a safe cleanup error; other known failed
    # resources additionally retain their exact closed ownership reference.
    assert reference in result.cleanup.remaining_refs or boundary == "revoke"
    assert "teardown" in calls
    assert boundary == "child" or child.closed
    assert boundary == "channel" or frames.closed
    assert boundary == "stdin" or input_pipe.closed
    assert boundary == "teardown" or any(sig != 0 for _, sig in fake_os.signals)


def test_stalled_broker_revocation_does_not_prevent_owned_group_teardown(process_case, monkeypatch):
    env, adapter, launch, frames, _, fake_os, _, _, _ = process_case
    entered, release = threading.Event(), threading.Event()
    frames.messages = iter([ProtocolError(c.ReasonCode.CANCELLED)])

    def stall(*_):
        entered.set()
        release.wait(2.0)

    monkeypatch.setattr(launch.control, "revoke", stall)
    try:
        result = adapter.run(launch, _encode_frame({"source-only": True}), _Stop(env[5]))
        assert entered.is_set()
        assert any(sig != 0 for _, sig in fake_os.signals)
        assert result.error.reason == c.ReasonCode.CANCELLED
        assert "owned-controller-control" in result.cleanup.remaining_refs
    finally:
        release.set()


def test_teardown_failure_preserves_received_worker_cleanup_references(process_case, monkeypatch):
    env, adapter, launch, frames, _, _, _, _, _ = process_case
    from netops.ansible._controller_wsl import _control_message

    def handler(*args):
        outcome = _control_message(*args)
        if outcome is not None:
            return c.aggregate_outcome(
                launch.request.request, outcome.targets, executed_mode=launch.request.request.mode,
                cleanup=c.CleanupOutcome("failed", ("worker-owned-reference",)),
            )
        return None

    monkeypatch.setattr("netops.ansible._controller_wsl._control_message", handler)
    monkeypatch.setattr(adapter, "_teardown", lambda *_: c.CleanupOutcome(
        "failed", ("owned-posix-controller-group",),
    ))
    result = adapter.run(launch, _encode_frame({"source-only": True}), _Stop(env[5]))
    assert result.targets[0].status == c.OutcomeStatus.SUCCEEDED
    assert result.cleanup.remaining_refs == ("worker-owned-reference", "owned-posix-controller-group")


@pytest.mark.parametrize("branch", ("wrong-ready", "budget-in-input", "spawn-failure", "expired-start", "expired-after-spawn", "missing-stdin", "watchdog-join"))
def test_fixed_adapter_negative_startup_and_finalization_branches(process_case, monkeypatch, branch):
    env, adapter, launch, frames, _, _, child, input_pipe, process = process_case
    private = _encode_frame({"source-only": True})
    if branch == "wrong-ready":
        frames.messages = iter([{"kind": "wrong", "nonce": "a" * 64}])
    elif branch == "budget-in-input":
        private = _encode_frame({"budget": {}})
    elif branch == "spawn-failure":
        def fail(*_, **__):
            raise OSError("synthetic fixed spawn failure")

        monkeypatch.setattr(module.subprocess, "Popen", fail)
    elif branch == "expired-start":
        launch = replace(launch, start_deadline=env[4].now)
    elif branch == "expired-after-spawn":
        close = child.close

        def advance():
            env[4].now = launch.start_deadline
            close()

        monkeypatch.setattr(child, "close", advance)
    elif branch == "missing-stdin":
        process.stdin = None
    else:
        class Monitor:
            def __init__(self, *_):
                self.ready = threading.Event()

            def start(self):
                pass

            def close(self):
                return False

        monkeypatch.setattr(module, "_ProcessWatchdog", Monitor)
    if branch == "expired-start":
        with pytest.raises(ProtocolError):
            adapter.run(launch, private, _Stop(env[5]))
        return
    result = adapter.run(launch, private, _Stop(env[5]))
    if branch == "watchdog-join":
        assert "owned-controller-watchdog" in result.cleanup.remaining_refs
    else:
        assert result.error is not None
    assert child.closed and frames.closed
    assert branch == "missing-stdin" or input_pipe.closed or branch == "spawn-failure"


def test_adapter_verification_never_qualifies_missing_or_nonposix_source(process_case):
    env, adapter, launch, _, _, fake_os, _, _, _ = process_case
    context = launch.installation.context
    adapter._verifier = SimpleNamespace(verify=lambda *_: None)
    assert adapter.verify(context, object()) is None
    adapter._verifier = SimpleNamespace(verify=lambda *_: launch.installation)
    assert adapter.verify(context, object()) == launch.installation
    fake_os.name = "nt"
    assert adapter.verify(context, object()) is None
    with pytest.raises(ProtocolError):
        adapter.run(launch, b"source-only", _Stop(env[5]))


def test_process_watchdog_deadline_and_signal_failures_use_only_owned_fake_group(process_case):
    env, _, launch, _, _, fake_os, _, _, _ = process_case
    stop = _Stop(env[5])
    monitor = module._ProcessWatchdog(7331001, launch, stop, env[4])
    env[4].now = launch.start_deadline
    waits = iter((False, False))
    monitor._finished = SimpleNamespace(wait=lambda _: next(waits), is_set=lambda: False)
    monitor._watch()
    assert stop.reason == c.ReasonCode.DEADLINE_EXCEEDED
    assert (7331001, 15) in fake_os.signals and (7331001, 9) in fake_os.signals
    fake_os.alive = False
    monitor._signal(15)
    monitor._finished = SimpleNamespace(is_set=lambda: True)
    before = tuple(fake_os.signals)
    monitor._signal(15)
    assert tuple(fake_os.signals) == before


def test_stubborn_or_already_absent_group_never_invents_teardown_success(process_case):
    _, adapter, _, _, _, fake_os, _, _, process = process_case
    fake_os.alive = False
    assert adapter._teardown(process, 0.01).status == "succeeded"
    fake_os.alive = True
    fake_os.stubborn = True
    result = adapter._teardown(process, 0.01)
    assert result.status == "failed"
    assert result.remaining_refs == ("owned-posix-controller-group",)
