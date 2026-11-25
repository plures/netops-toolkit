"""Independent S02 concrete process-adapter tests with only fake OS effect ports."""

from __future__ import annotations

import io
import json
import os
from types import SimpleNamespace

import pytest

from netops.ansible import contracts as c
from netops.ansible import controller_process as module
from netops.ansible.controller import ControllerInstallation, FixedLaunch
from netops.ansible.controller_control import _Stop
from netops.ansible.controller_protocol import ProtocolError, _decode_frame, _encode_frame
from tests.test_nov19_independent_controller_execution import (
    NONCE,
    actual_host,
    bridge,
    dispatch,
)
from tests.test_nov19_independent_credentials import SENTINEL


class PrivateInput(io.BytesIO):
    def close(self):
        if not self.closed:
            self.value_before_close = self.getvalue()
        super().close()


class Child:
    def __init__(self):
        self.closed = False

    def fileno(self):
        return 17

    def close(self):
        self.closed = True


class Frames:
    def __init__(self, messages):
        self.messages = iter(messages)
        self.sent = []
        self.closed = False

    def receive(self, timeout, cancel):
        assert 0 < timeout <= 30.0
        message = next(self.messages)
        if isinstance(message, Exception):
            raise message
        return message

    def send(self, value):
        self.sent.append(value)

    def close(self):
        self.closed = True


class OS:
    """Fake group signals, never inspect or signal a real process identifier."""

    name = "posix"
    path = os.path

    def __init__(self):
        self.signals = []
        self.alive = True
        self.stubborn = False
        self.forbidden = []

    def killpg(self, pid, sig):
        assert pid == 7331001, "The process adapter must not touch any unrelated process"
        self.signals.append((pid, sig))
        if not self.alive:
            raise ProcessLookupError()
        if sig == 9 and not self.stubborn:
            self.alive = False


class Time:
    def __init__(self):
        self.value = 900000.0

    def monotonic(self):
        self.value += 0.1
        return self.value

    def sleep(self, duration):
        self.value += duration


@pytest.fixture
def process_case(monkeypatch, request):
    mutation = getattr(request, "param", None) == "apply"
    env = actual_host(c.Mode.APPLY, "apply", enforce=True) if mutation else actual_host()
    request, plan, _, _, clock, cancel, _ = env
    control = bridge(env)
    installation = ControllerInstallation(
        c.ControllerContext(request.context), "linux", "/owned/controller/bin/python",
        "1" * 64, "2" * 64,
    )
    launch = FixedLaunch(
        installation, c.ControllerRequest(request, plan), control,
        clock.now + 30.0, clock.now + 300.0,
    )
    success = c.aggregate_outcome(
        request, (c.TargetOutcome("router", c.OutcomeStatus.SUCCEEDED, True),),
        executed_mode=request.mode,
    )
    frames = Frames([
        {"kind": "ready", "nonce": NONCE},
        {"kind": "dispatch", "binding": dispatch(env)._wire()},
        {"kind": "dispatch", "binding": dispatch(env, "task", 1)._wire()},
        {"kind": "result", "outcome": json.loads(c.canonical_bytes(success))},
    ])
    fake_os, child, input_pipe, launches = OS(), Child(), PrivateInput(), []
    process = SimpleNamespace(pid=7331001, stdin=input_pipe, wait=lambda timeout: 0)

    def popen(argv, **kwargs):
        launches.append((argv, kwargs))
        return process

    # Replace only OS/transport effect ports. The process adapter, real host
    # broker, budget/admission and actual group-teardown algorithm all execute.
    monkeypatch.setattr(module, "os", fake_os)
    monkeypatch.setattr(module, "time", Time())
    monkeypatch.setattr(module, "signal", SimpleNamespace(SIGTERM=15, SIGKILL=9))
    monkeypatch.setattr(module, "socket", SimpleNamespace(
        SOCK_STREAM=1, socketpair=lambda *args: (object(), child),
    ))
    monkeypatch.setattr(module, "_unix_family", lambda: "fake-unix-effect-port")
    monkeypatch.setattr(module, "_SocketFrames", lambda channel: frames)
    monkeypatch.setattr(module.subprocess, "Popen", popen)
    adapter = module.OwnedPosixProcesses(object(), clock, "/owned/private")
    return env, adapter, launch, frames, launches, fake_os, child, input_pipe, process


def test_t13_concrete_launch_allowlists_environment_and_uses_private_stdin(process_case):
    env, adapter, launch, _, launches, fake_os, child, input_pipe, _ = process_case
    result = adapter.run(launch, _encode_frame({"private": SENTINEL}), _Stop(env[5]))
    assert result.exit_code == 0
    assert result.cleanup.status == "succeeded"
    assert len(launches) == 1
    argv, options = launches[0]
    assert argv == (
        "/owned/controller/bin/python", "-I", "-m", "netops.ansible.worker",
        "--control-fd", "17", "--private-root", "/owned/private",
    )
    assert options["env"] == {"LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1"}
    assert options["shell"] is False
    assert options["start_new_session"] is True
    assert options["close_fds"] is True
    assert options["pass_fds"] == (17,)
    assert SENTINEL not in repr((argv, options))
    sent = _decode_frame(input_pipe.value_before_close)
    assert sent["private"] == SENTINEL
    assert sent["budget"]["ready_nonce"] == NONCE
    assert "expires_at" not in repr(sent["budget"])
    assert child.closed
    assert fake_os.signals[0] == (7331001, 15)
    assert (7331001, 9) in fake_os.signals


@pytest.mark.parametrize("failure", ["lost-ready", "malformed-ready", "lost-control", "bad-result"])
def test_t30_concrete_process_failure_always_revokes_and_tears_down_owned_group(process_case, failure):
    env, adapter, launch, frames, launches, fake_os, child, _, _ = process_case
    messages = {
        "lost-ready": [ProtocolError(c.ReasonCode.CONTROL_LOST)],
        "malformed-ready": [{"kind": "ready", "nonce": NONCE, "allow": True}],
        "lost-control": [
            {"kind": "ready", "nonce": NONCE},
            ProtocolError(c.ReasonCode.CONTROL_LOST),
        ],
        "bad-result": [
            {"kind": "ready", "nonce": NONCE},
            {"kind": "result", "outcome": {"stdout": SENTINEL}},
        ],
    }
    frames.messages = iter(messages[failure])
    result = adapter.run(launch, _encode_frame({"private": SENTINEL}), _Stop(env[5]))
    assert result.exit_code != 0
    assert result.error is not None
    assert result.cleanup.status == "succeeded"
    assert env[3].is_revoked(env[0].operation_id)
    assert len(launches) == 1, "Lost control may not replay a controller process"
    assert child.closed and frames.closed
    assert fake_os.signals
    assert SENTINEL not in repr(result)


def test_t30_exited_leader_is_not_proof_owned_fork_group_is_gone(process_case):
    _, adapter, _, _, _, fake_os, _, _, process = process_case
    # No poll() or wait() result substitutes for the independently observed group.
    process.poll = lambda: 0
    result = adapter._teardown(process, 2.0)
    assert result.status == "succeeded"
    assert fake_os.signals[0] == (7331001, 15)
    assert (7331001, 9) in fake_os.signals


def test_t30_stubborn_owned_group_is_cleanup_failure_not_success(process_case):
    _, adapter, _, _, _, fake_os, _, _, process = process_case
    fake_os.stubborn = True
    result = adapter._teardown(process, 2.0)
    assert result.status == "failed"
    assert result.errors[0].reason == c.ReasonCode.CLEANUP_FAILED


@pytest.mark.parametrize("process_case", ["apply"], indirect=True)
def test_t14_issued_mutation_with_lost_reply_is_uncertain_without_replay(process_case):
    env, adapter, launch, frames, launches, _, _, _, _ = process_case
    frames.messages = iter([
        {"kind": "ready", "nonce": NONCE},
        {"kind": "dispatch", "binding": dispatch(env)._wire()},
        {"kind": "dispatch", "binding": dispatch(env, "task", 1)._wire()},
        {"kind": "dispatch", "binding": dispatch(env, "mutation", 2)._wire()},
        ProtocolError(c.ReasonCode.CONTROL_LOST),
    ])
    result = adapter.run(launch, _encode_frame({"private": SENTINEL}), _Stop(env[5]))
    assert result.exit_code != 0
    assert result.targets[0].target_id == "router"
    assert result.targets[0].attempted is True
    assert result.targets[0].remote_state == "uncertain"
    assert result.targets[0].errors[0].reason == c.ReasonCode.REMOTE_STATE_UNCERTAIN
    assert env[3].is_revoked(env[0].operation_id)
    assert len(launches) == 1
