"""Real private WSL adapter algorithms with only external effects replaced.

No fixture is a platform qualification record. No WSL process or Linux signal
is executed; the tests prove source contracts, not actual Q03 performance.
"""

import io
import json
import struct
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops.ansible import _controller_wsl as wsl
from netops.ansible import _worker_group as group_module
from netops.ansible import contracts as c
from netops.ansible import controller_transport as sockets
from netops.ansible._controller_pipe import _PipeFrames
from netops.ansible._worker_group import _OwnedLinuxGroup
from netops.ansible.controller import ControllerInstallation, FixedLaunch
from netops.ansible.controller_control import _Stop
from netops.ansible.controller_protocol import ProtocolError, _decode_frame, _encode_frame
from tests.test_nov19_independent_controller_execution import NONCE, actual_host, bridge, dispatch
from tests.test_nov19_independent_credentials import SENTINEL

REAL_QUALIFICATION_LOCK = wsl._OwnedInstallationVerifier._qualification_lock


def installation(request):
    return ControllerInstallation(
        c.ControllerContext(request.context), "windows-wsl", "/owned/controller/bin/python",
        "1" * 64, "2" * 64, r"C:\Windows\System32\wsl.exe", "Owned-Netops",
    )


class Frames:
    def __init__(self, outcome, failure=None):
        self.outcome, self.failure = outcome, failure
        self.sent = []
        self.closed = False

    def send(self, value, timeout=2.0):
        assert 0 < timeout <= 2.0
        # Actual serialization copy: clearing sender's buffer cannot erase proof.
        self.sent.append(_decode_frame(_encode_frame(value)))

    def receive(self, timeout, cancel=None):
        assert 0 < timeout <= 30.0
        start = self.sent[0]
        if not any(item["kind"] == "input" for item in self.sent):
            if self.failure == "lost-ready":
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
            return {
                "kind": "ready", "nonce": NONCE,
                "proof": "0" * 64 if self.failure == "wrong-proof" else wsl._proof(
                    start["key"], "ready", NONCE, start["binding"], start["challenge"],
                ),
            }
        if self.sent[-1]["kind"] == "stop":
            cleanup = json.loads(c.canonical_bytes(
                c.CleanupOutcome("failed", remaining_refs=("unit-owned-leftover",))
                if self.failure == "group-failed" else c.CleanupOutcome("succeeded")
            ))
            if self.failure == "lost-stop":
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
            return {
                "kind": "stopped", "cleanup": cleanup,
                "proof": "0" * 64 if self.failure == "forged-stop" else wsl._proof(
                    start["key"], "stopped", NONCE, start["binding"], cleanup,
                ),
            }
        if self.failure == "lost-control":
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
        return {"kind": "result", "outcome": json.loads(c.canonical_bytes(self.outcome))}

    def close(self):
        self.closed = True
        return self.failure != "pipe-stalled"


class Io:
    def __init__(self, frames):
        self.channel = frames
        self.launches = []
        self.closed = []

    def launch(self, selected):
        self.launches.append(selected)
        return object()

    def frames(self, process):
        return self.channel

    def close_launcher(self, process):
        self.closed.append(process)
        return c.CleanupOutcome("succeeded")

    def launcher_bytes(self, path):
        assert path == r"C:\Windows\System32\wsl.exe"
        return "a" * 64


@pytest.fixture
def case(monkeypatch):
    env = actual_host()
    request, plan, _, _, clock, _, _ = env
    control = bridge(env)
    selected = installation(request)
    launch = FixedLaunch(
        selected, c.ControllerRequest(request, plan), control, clock.now + 30.0, clock.now + 300.0,
    )
    outcome = c.aggregate_outcome(
        request, (c.TargetOutcome("router", c.OutcomeStatus.SUCCEEDED, True),),
        executed_mode=request.mode,
    )
    frames = Frames(outcome)
    ports = Io(frames)
    # External collector/catalog inputs are fake only in this test process.
    # The actual adapter's exact tuple/byte/owned-state validation still runs.
    # This never changes the packaged Q03 lock or qualifies a real installation.
    catalog = {
        "state": "qualified", "required_tuple": ("unit-context",),
        "qualified": [{
            "installation_digest": selected.installation_digest,
            "context_digest": c.digest(selected.context), "evidence_digest": selected.qualification_digest,
            "state": "qualified", "platform": "windows-wsl",
            "wsl_distribution": selected.wsl_distribution, "python": selected.python,
            "tuple": {"unit-context": "synthetic-external-port-only"},
            "wsl_executable_digest": "a" * 64,
        }],
    }
    monkeypatch.setattr(
        wsl._OwnedInstallationVerifier, "_qualification_lock", staticmethod(lambda: catalog),
    )
    verifier = SimpleNamespace(verify=lambda context, state: selected)
    adapter = wsl._OwnedWslProcesses(verifier, clock, "/owned/private", ports)
    owned_state = object()
    assert adapter.verify(selected.context, owned_state) == selected
    return env, adapter, launch, frames, ports


def test_actual_wsl_launch_uses_absolute_verified_exec_and_distribution(monkeypatch):
    selected = installation(actual_host()[0])
    calls = []
    process = wsl._WindowsProcess(
        SimpleNamespace(), 101, 102, 103, io.BytesIO(), io.BytesIO(),
    )

    def start(executable, argv, root):
        calls.append((executable, argv, root))
        return process

    # Current external seam owns suspended creation + exact job assignment,
    # not a legacy unowned Popen. Actual minimal CreateProcess environment and
    # private handle inheritance have separate unchanged native controls.
    monkeypatch.setattr(wsl, "_start_job_process", start)
    assert wsl._WslProcessIo().launch(selected) is process
    assert len(calls) == 1
    executable, argv, root = calls[0]
    assert argv == (
        r"C:\Windows\System32\wsl.exe", "--distribution", "Owned-Netops", "--exec",
        "/owned/controller/bin/python", "-I", "-m", "netops.ansible.worker", "--stdio-control",
    )
    assert executable == selected.wsl_executable == argv[0]
    assert root == str(Path(selected.wsl_executable).parent)
    assert process._assigned and not process._closed
    assert SENTINEL not in repr(calls)


def test_actual_wsl_private_frame_nonce_budget_and_authenticated_group_stop(case):
    env, adapter, launch, frames, ports = case
    result = adapter.run(launch, _encode_frame({"credential": SENTINEL}), _Stop(env[5]))
    assert result.exit_code == 0 and result.error is None
    assert result.cleanup.status == "succeeded"
    assert result.targets[0].status == c.OutcomeStatus.SUCCEEDED
    assert len(ports.launches) == 1 and len(ports.closed) == 1 and frames.closed
    assert [item["kind"] for item in frames.sent] == ["start", "input", "stop"]
    assert SENTINEL not in repr(frames.sent[0]) and SENTINEL not in repr(frames.sent[-1])
    assert frames.sent[1]["payload"]["credential"] == SENTINEL
    budget = frames.sent[1]["payload"]["budget"]
    assert budget["ready_nonce"] == NONCE
    assert "expires_at" not in repr(budget), "Host monotonic origin cannot be sent as worker expiry"
    assert SENTINEL not in repr(result)


@pytest.mark.parametrize("failure", [
    "lost-ready", "wrong-proof", "lost-control", "lost-stop", "forged-stop", "pipe-stalled",
])
def test_actual_wsl_failure_retains_linux_group_or_pipe_ref_and_never_replays(case, failure):
    env, adapter, launch, frames, ports = case
    frames.failure = failure
    result = adapter.run(launch, _encode_frame({"credential": SENTINEL}), _Stop(env[5]))
    assert len(ports.launches) == 1 and len(ports.closed) == 1
    assert frames.closed and SENTINEL not in repr(result)
    if failure in ("lost-ready", "wrong-proof", "lost-control"):
        assert result.exit_code != 0 and result.error is not None
        assert launch.control._revocation_signal.is_set()
        with pytest.raises(ProtocolError):
            launch.control.check()
    if failure != "lost-control":
        assert result.cleanup.status == "failed"
        expected = "owned-private-pipes" if failure == "pipe-stalled" else "owned-linux-runner-group"
        assert expected in result.cleanup.remaining_refs


def test_wsl_rejects_caller_budget_before_launch(case):
    env, adapter, launch, _, ports = case
    with pytest.raises(ProtocolError):
        adapter.run(launch, _encode_frame({"budget": {}}), _Stop(env[5]))
    assert not ports.launches


def test_authenticated_failed_linux_cleanup_preserves_exact_owned_remaining_reference(case):
    env, adapter, launch, frames, _ = case
    frames.failure = "group-failed"
    result = adapter.run(launch, _encode_frame({"private": SENTINEL}), _Stop(env[5]))
    assert result.targets[0].status == c.OutcomeStatus.SUCCEEDED
    assert result.cleanup.status == "failed"
    assert "unit-owned-leftover" in result.cleanup.remaining_refs


@pytest.mark.parametrize("change", ["bytes", "zero-qualification", "distribution", "context"])
def test_actual_wsl_reverification_blocks_drift_before_private_input_or_launch(case, change):
    env, adapter, launch, frames, ports = case
    selected = launch.installation
    if change == "bytes":
        ports.launcher_bytes = lambda path: "f" * 64
    else:
        changed = {
            "zero-qualification": replace(selected, qualification_digest="0" * 64),
            "distribution": replace(selected, wsl_distribution="Other-Distribution"),
            "context": replace(selected, context=c.ControllerContext(
                replace(selected.context.context, controller_id="other-owned-context"),
            )),
        }[change]
        adapter._verifier.verify = lambda context, state: changed
    with pytest.raises(ProtocolError):
        adapter.run(launch, _encode_frame({"private": SENTINEL}), _Stop(env[5]))
    assert not ports.launches and not frames.sent


def test_wsl_verified_owned_state_cannot_be_replaced_by_another_state_object(case):
    _, adapter, launch, _, ports = case
    assert adapter.verify(launch.installation.context, object()) is None
    assert not ports.launches


def test_consumed_controller_request_scope_has_literal_serialization_pin(case):
    request = case[2].request.request
    assert c.canonical_bytes(request.scope).decode() == (
        '{"exclusions":[],"limit":100,"target_ids":["router"]}'
    )


def test_actual_public_operation_outcome_has_literal_serialization_pin():
    outcome = c.OperationOutcome(
        "b9de32d8-9943-4f4b-8042-2baedc0b9a2c", c.Mode.OBSERVE, c.Mode.OBSERVE,
        c.ReadinessProjection("ready", "not-requested", "not-requested"),
        (), (), c.OutcomeStatus.SUCCEEDED, False, (), (), (),
        c.CleanupOutcome("succeeded"), c.public_object({}),
    )
    assert c.canonical_bytes(outcome).decode() == (
        '{"artifacts":[],"changed":false,"cleanup":{"errors":[],"remaining_refs":[],'
        '"status":"succeeded"},"errors":[],"executed_mode":"observe","findings":[],'
        '"operation_id":"b9de32d8-9943-4f4b-8042-2baedc0b9a2c","provenance":{},'
        '"readiness":{"companion":"not-requested","enhanced":"not-requested","errors":[],'
        '"native":"ready"},"requested_mode":"observe","schema_version":"1.0",'
        '"status":"succeeded","steps":[],"targets":[]}'
    )


@pytest.mark.parametrize("status,refs", [
    ("succeeded", ()), ("failed", ("unit-owned-leftover",)),
])
def test_actual_cleanup_wire_json_arrays_are_consumed_without_losing_owned_refs(status, refs):
    cleanup = c.CleanupOutcome(status, refs)
    wire = json.loads(c.canonical_bytes(cleanup))
    assert wsl._cleanup_frame(wire) == cleanup
    if status == "succeeded":
        assert c.canonical_bytes(cleanup).decode() == (
            '{"errors":[],"remaining_refs":[],"status":"succeeded"}'
        )
    else:
        assert c.canonical_bytes(cleanup).decode() == (
            '{"errors":[],"remaining_refs":["unit-owned-leftover"],"status":"failed"}'
        )


def test_packaged_unqualified_wsl_tuple_cannot_be_promoted_by_fake_verifier(case, monkeypatch):
    _, adapter, launch, _, ports = case
    adapter._verifier = SimpleNamespace(verify=lambda context, state: launch.installation)
    monkeypatch.setattr(
        wsl._OwnedInstallationVerifier, "_qualification_lock", staticmethod(REAL_QUALIFICATION_LOCK),
    )
    assert adapter.verify(launch.installation.context, object()) is None
    assert not ports.launches, "Unit fixtures must never qualify an actual installed WSL tuple"


@pytest.mark.parametrize("root", ["relative", "/owned/../foreign", "/owned/\nprivate"])
def test_invalid_private_root_fails_before_external_ports(root):
    with pytest.raises(c.ContractError):
        wsl._OwnedWslProcesses(object(), object(), root, object())


class GroupSystem:
    """Own only the factory's object; all OS effects are fake."""

    def __init__(self, *, identity=True, remains=False, signal_error=False):
        self.valid, self.remains, self.signal_error = identity, remains, signal_error
        self.calls = []

    def identity(self, process):
        self.calls.append(("identity", process))
        return self.valid

    def finished(self, process):
        self.calls.append(("finished", process))
        return True

    def signal(self, process, selected):
        self.calls.append(("signal", process, selected))
        if self.signal_error:
            raise PermissionError()

    def pause(self, seconds):
        self.calls.append(("pause", seconds))

    def exists(self, process):
        self.calls.append(("exists", process))
        return self.remains


def child(system):
    process = SimpleNamespace()
    process.wait = lambda timeout: system.calls.append(("wait", process, timeout))
    return process


@pytest.fixture(autouse=True)
def linux_signal_constants(monkeypatch):
    monkeypatch.setattr(group_module, "signal", SimpleNamespace(SIGTERM=15, SIGKILL=9))


def test_linux_group_signals_exact_unreaped_owned_child_before_wait_and_never_after():
    system = GroupSystem()
    group, process = _OwnedLinuxGroup(system), child(system)
    assert group.launch(lambda: process, "operation") is process
    assert group.finished()
    result = group.close()
    assert result.status == "succeeded"
    signals = [item for item in system.calls if item[0] == "signal"]
    assert signals == [("signal", process, 15), ("signal", process, 9)]
    assert max(system.calls.index(item) for item in signals) < next(
        i for i, item in enumerate(system.calls) if item[0] == "wait"
    )
    before = list(system.calls)
    assert group.close() == result and system.calls == before


@pytest.mark.parametrize("failure", ["identity", "remains", "signal", "busy"])
def test_linux_group_unproved_teardown_retains_exact_owned_reference(failure):
    system = GroupSystem(
        identity=failure != "identity", remains=failure == "remains", signal_error=failure == "signal",
    )
    group, process = _OwnedLinuxGroup(system), child(system)
    if failure == "identity":
        with pytest.raises(ProtocolError):
            group.attach(process, "operation")
    else:
        group.attach(process, "operation")
    if failure == "busy":
        group._lock.acquire()
    try:
        result = group.close()
    finally:
        if failure == "busy":
            group._lock.release()
    assert result.status == "failed"
    assert result.remaining_refs == ("owned-linux-runner-group",)
    if failure in ("identity", "busy"):
        assert not any(item[0] == "signal" for item in system.calls)


def test_cancelled_linux_group_never_invokes_new_factory():
    group, calls = _OwnedLinuxGroup(GroupSystem()), []
    assert group.close().status == "succeeded"
    with pytest.raises(ProtocolError):
        group.launch(lambda: calls.append("spawn"), "operation")
    assert not calls


class BlockingSource:
    def __init__(self):
        self.release = threading.Event()

    def read(self, size):
        self.release.wait(2.0)
        return b""

    def close(self):
        self.release.set()


def test_pipe_fragmented_write_is_exact_and_stalled_receive_revokes_without_retry():
    class PartialSink(io.BytesIO):
        def write(self, data):
            return super().write(data[:2])

    source, sink = BlockingSource(), PartialSink()
    frames = _PipeFrames(source, sink)
    try:
        frames.send({"credential": SENTINEL}, 0.5)
        assert _decode_frame(sink.getvalue()) == {"credential": SENTINEL}
        with pytest.raises(ProtocolError):
            frames.receive(0.03)
        assert frames.failed.is_set()
        with pytest.raises(ProtocolError):
            frames.send({"kind": "retry"}, 0.03)
        assert _decode_frame(sink.getvalue()) == {"credential": SENTINEL}
    finally:
        assert frames.close()


@pytest.mark.parametrize("timeout", [0.0, -1.0, 121.0, 1, float("nan"), float("inf")])
def test_pipe_invalid_budget_never_starts_io(timeout):
    with pytest.raises(ProtocolError):
        _PipeFrames._deadline(timeout)


def test_wsl_control_dispatch_is_real_host_one_use_admission(case):
    env, _, launch, frames, _ = case
    launch.control.ready(NONCE)
    binding = dispatch(env)
    assert wsl._control_message(
        frames, {"kind": "dispatch", "binding": binding._wire()}, launch, _Stop(env[5]),
    ) is None
    assert frames.sent[-1]["kind"] == "permit"
    assert frames.sent[-1]["binding"] == json.loads(c.canonical_bytes(c.public_object(binding._wire())))
    with pytest.raises(ProtocolError):
        wsl._control_message(
            frames, {"kind": "dispatch", "binding": binding._wire()}, launch, _Stop(env[5]),
        )
    assert env[3].is_revoked(env[0].operation_id)


class SocketPort:
    def __init__(self, parts=(), error=False):
        self.parts = iter(parts)
        self.error = error
        self.sent = []
        self.closed = False
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendall(self, data):
        if self.error:
            raise OSError("synthetic private-channel send failure")
        self.sent.append(data)

    def recv(self, size):
        if self.error:
            raise OSError("synthetic private-channel receive failure")
        return next(self.parts, b"")

    def close(self):
        self.closed = True


@pytest.fixture
def fake_socket_time(monkeypatch):
    now = [8000000.0]

    def tick():
        now[0] += 0.001
        return now[0]

    monkeypatch.setattr(sockets, "time", SimpleNamespace(monotonic=tick))
    monkeypatch.setattr(sockets.select, "select", lambda inputs, *args: (inputs, [], []))


def test_socket_private_fragmented_frames_keep_residual_bytes_without_new_reader(fake_socket_time):
    first, second = {"kind": "pulse"}, {"kind": "ready", "nonce": NONCE}
    encoded = _encode_frame(first) + _encode_frame(second)
    port = SocketPort([encoded[:2], encoded[2:5], encoded[5:]])
    frames = sockets._SocketFrames(port)
    assert frames.receive(0.5) == first
    assert frames.receive(0.5) == second
    frames.send(first, 0.2)
    assert port.sent == [_encode_frame(first)] and port.timeouts[-1] == 0.2
    frames.close()
    assert port.closed


@pytest.mark.parametrize("fault", ["zero", "oversized", "eof", "cancel", "timeout", "read-error"])
def test_socket_channel_fault_revokes_without_fallback_or_retry(fake_socket_time, fault):
    size = 0 if fault == "zero" else 0xFFFFFFFF
    parts = [struct.pack(">I", size)] if fault in ("zero", "oversized") else []
    frames = sockets._SocketFrames(SocketPort(parts, error=fault == "read-error"))
    cancel = SimpleNamespace(is_cancelled=lambda: fault == "cancel")
    with pytest.raises(ProtocolError):
        frames.receive(0.0001 if fault == "timeout" else 0.5, cancel)


def test_socket_send_error_is_closed_control_loss(fake_socket_time):
    with pytest.raises(ProtocolError) as error:
        sockets._SocketFrames(SocketPort(error=True)).send({"kind": "pulse"})
    assert error.value.reason == c.ReasonCode.CONTROL_LOST


@pytest.mark.parametrize("tail", [b"", b"x", _encode_frame({"kind": "second"})])
def test_socket_individual_broker_connection_requires_exact_one_frame_and_eof(fake_socket_time, tail):
    value = {"kind": "pulse"}
    frames = sockets._SocketFrames(SocketPort([_encode_frame(value) + tail, b""]))
    if tail:
        with pytest.raises(ProtocolError):
            frames.receive_one(0.5)
    else:
        assert frames.receive_one(0.5) == value


def test_pipe_cancel_invalidates_entire_channel_and_closes_owned_streams():
    source, sink = BlockingSource(), io.BytesIO()
    frames = _PipeFrames(source, sink)
    try:
        with pytest.raises(ProtocolError):
            frames.receive(0.5, SimpleNamespace(is_cancelled=lambda: True))
        assert frames.failed.is_set()
    finally:
        assert frames.close()


@pytest.mark.parametrize("count", [None, 0, -1, 100000])
def test_pipe_invalid_write_progress_revokes_without_second_writer(count):
    class InvalidSink(io.BytesIO):
        def write(self, data):
            return count

    source, sink = BlockingSource(), InvalidSink()
    frames = _PipeFrames(source, sink)
    try:
        with pytest.raises(ProtocolError):
            frames.send({"kind": "pulse"}, 0.1)
        assert frames.failed.is_set()
    finally:
        assert frames.close()


def test_linux_group_missing_attachment_duplicate_attachment_and_stopped_finished_are_closed():
    system = GroupSystem()
    group, process = _OwnedLinuxGroup(system), child(system)
    with pytest.raises(ProtocolError):
        group.finished()
    group.attach(process, "owned")
    with pytest.raises(ProtocolError):
        group.attach(child(system), "other")
    group.close()
    with pytest.raises(ProtocolError):
        group.finished()


@pytest.mark.parametrize("already_gone", [False, True])
def test_linux_system_uses_only_created_process_identity_not_any_received_pid(monkeypatch, already_gone):
    calls = []
    process = SimpleNamespace(pid=7331001)

    def killpg(pid, selected):
        assert pid == process.pid
        calls.append(("killpg", pid, selected))
        if already_gone:
            raise ProcessLookupError()

    monkeypatch.setattr(group_module, "os", SimpleNamespace(
        getpgid=lambda pid: pid, getsid=lambda pid: pid, killpg=killpg,
        waitid=lambda *args: object(), P_PID=1, WEXITED=2, WNOHANG=4, WNOWAIT=8,
    ))
    system = group_module._LinuxGroupSystem()
    assert system.identity(process) and system.finished(process)
    assert system.exists(process) is not already_gone
    if not already_gone:
        system.signal(process, 15)
        assert calls[-1] == ("killpg", process.pid, 15)
