"""Actual WSL adapter/group source with fake external I/O, not qualification."""

from __future__ import annotations

import hashlib
import io
import json
import queue
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops.ansible import _controller_wsl as wsl
from netops.ansible import _worker_group as groups
from netops.ansible import _worker_wsl as linux
from netops.ansible import contracts as c
from netops.ansible._controller_pipe import _PipeFrames
from netops.ansible.controller import ControllerInstallation, FixedLaunch
from netops.ansible.controller_control import _Stop
from netops.ansible.controller_observations import _ControllerIo
from netops.ansible.controller_protocol import (
    ControllerBudget,
    ProtocolError,
    _BudgetWindow,
    _decode_frame,
    _encode_frame,
)
from netops.ansible.worker import _Cancelled

pytest_plugins = ("tests.test_controller_cancellation",)
NONCE = "c" * 64
SECRET = "SYNTHETIC-S02-must-not-leak"


@pytest.fixture(autouse=True)
def fake_existing_tuple(monkeypatch, scope):
    entry = {
        "state": "qualified", "platform": "windows-wsl", "installation_digest": "a" * 64,
        "context_digest": c.digest(scope.context), "evidence_digest": "b" * 64,
        "python": "/owned/bin/python", "wsl_distribution": "Qualified-Only",
        "wsl_executable_digest": "a" * 64, "tuple": {"kernel": "fake-external-Q03-port"},
    }
    monkeypatch.setattr(wsl._OwnedInstallationVerifier, "_qualification_lock", lambda: {
        "state": "qualified", "qualified": [entry], "required_tuple": ["kernel"],
    })


class Frames:
    def __init__(self, request, binding, *, fault=""):
        self.request, self.binding, self.fault = request, binding, fault
        self.start = None
        self.messages = queue.Queue()
        self.sent = []
        self.stop_received = threading.Event()

    def send(self, value, timeout=2.0):
        self.sent.append(value)
        if value["kind"] == "start":
            self.start = value
            self.messages.put({
                "kind": "ready", "nonce": NONCE,
                "proof": "0" * 64 if self.fault == "proof" else wsl._proof(
                    value["key"], "ready", NONCE, value["binding"], value["challenge"],
                ),
            })
        elif value["kind"] == "input":
            assert value["payload"]["budget"]["ready_nonce"] == NONCE
            if self.fault == "stall":
                return
            self.messages.put({"kind": "dispatch", "binding": self.binding._wire()})
            self.messages.put({
                "kind": "dispatch",
                "binding": replace(self.binding, phase="task", sequence=1)._wire(),
            })
            result = c.aggregate_outcome(self.request, (c.TargetOutcome(
                self.binding.target_id, c.OutcomeStatus.SUCCEEDED, True,
            ),), executed_mode=self.request.mode)
            wire = json.loads(c.canonical_bytes(result))
            if self.fault == "result":
                wire["operation_id"] = "00000000-0000-0000-0000-000000000000"
            if self.fault == "late":
                self.messages.put(ProtocolError(c.ReasonCode.CONTROL_LOST))
            self.messages.put({"kind": "result", "outcome": wire})
        elif value["kind"] == "stop":
            self.stop_received.set()
            if self.fault == "lost":
                self.messages.put(ProtocolError(c.ReasonCode.CONTROL_LOST))
                return
            cleanup = c.CleanupOutcome("succeeded")
            if self.fault == "group":
                cleanup = c.CleanupOutcome(
                    "failed", remaining_refs=("owned-linux-runner-group", "owned-unit-leftover"),
                    errors=groups._OwnedLinuxGroup._failure().errors,
                )
            wire = json.loads(c.canonical_bytes(cleanup))
            self.messages.put({
                "kind": "stopped", "cleanup": wire,
                "proof": wsl._proof(
                    self.start["key"], "stopped", NONCE, self.start["binding"], wire,
                ),
            })

    def receive(self, timeout, cancel=None):
        assert 0 < timeout <= 30.0
        if self.fault == "stall" and self.start is not None and not self.stop_received.is_set():
            if not self.messages.empty():
                return self.messages.get_nowait()
            assert self.stop_received.wait(1.5)
            raise ProtocolError(c.ReasonCode.CANCELLED)
        value = self.messages.get(timeout=timeout)
        if isinstance(value, Exception):
            raise value
        return value

    def close(self):
        return self.fault != "pipes"


class Ports(wsl._WslProcessIo):
    def __init__(self, frames, *, launcher_failure=False):
        self.channel = frames
        self.launcher_failure = launcher_failure
        self.launches = []
        self.closed = []

    def launch(self, installation):
        self.launches.append(installation)
        return SimpleNamespace(pid=990001)

    def frames(self, process):
        return self.channel

    def close_launcher(self, process):
        self.closed.append(process.pid)
        return c.CleanupOutcome(
            "failed" if self.launcher_failure else "succeeded",
            remaining_refs=("owned-wsl-launcher",) if self.launcher_failure else (),
        )

    def launcher_bytes(self, path):
        return "a" * 64


def setup(host, request, binding, fault="", launcher_failure=False):
    control, _, _, clock, parent, _, _ = host
    installation = ControllerInstallation(
        c.ControllerContext(request.context), "windows-wsl", "/owned/bin/python",
        "a" * 64, "b" * 64, r"C:\Windows\System32\wsl.exe", "Qualified-Only",
    )
    launch = FixedLaunch(
        installation, c.ControllerRequest(request, control._plan), control, 40.0, 50.0,
    )
    frames = Frames(request, binding, fault=fault)
    ports = Ports(frames, launcher_failure=launcher_failure)
    stop = _Stop(parent)
    verifier = SimpleNamespace(verify=lambda context, state: installation)
    adapter = wsl._OwnedWslProcesses(verifier, clock, "/owned/private", ports)
    assert adapter.verify(installation.context, object()) == installation
    return adapter, launch, stop, ports


@pytest.mark.parametrize("fault,expected", [
    ("", "succeeded"), ("lost", "failed"), ("group", "failed"),
    ("pipes", "failed"), ("proof", "failed"), ("result", "succeeded"),
])
def test_real_adapter_handshake_dispatch_and_teardown(host, operation_request, binding, fault, expected):
    adapter, launch, stop, ports = setup(host, operation_request, binding, fault)
    result = adapter.run(launch, _encode_frame({"sentinel": SECRET}), stop)
    assert result.cleanup.status == expected
    assert ports.closed == [990001]
    assert len(ports.launches) == 1
    if fault not in ("proof", "result"):
        assert result.targets[0].status == c.OutcomeStatus.SUCCEEDED
        assert launch.control._next[binding.occurrence_id] == 2
    if fault == "lost":
        assert "owned-linux-runner-group" in result.cleanup.remaining_refs
        assert result.targets[0].attempted
    if fault == "pipes":
        assert "owned-private-pipes" in result.cleanup.remaining_refs
    if fault == "group":
        assert "owned-unit-leftover" in result.cleanup.remaining_refs
    if fault in ("proof", "result"):
        assert result.error is not None
    if fault == "result":
        # Malformed execution result remains a primary error. Independently
        # authenticated observed teardown is still a factual cleanup success.
        assert result.targets == () and result.exit_code == 1


def test_independent_parent_cancel_interrupts_stalled_adapter(host, operation_request, binding):
    adapter, launch, stop, ports = setup(host, operation_request, binding, "stall")
    parent = host[4]
    timer = threading.Timer(0.05, parent.event.set)
    timer.start()
    started = time.perf_counter()
    result = adapter.run(launch, _encode_frame({"sentinel": SECRET}), stop)
    timer.join()
    assert time.perf_counter() - started < 2.0
    assert ports.channel.stop_received.is_set()
    assert launch.control._revocation_signal.is_set() and stop._event.is_set()
    assert result.error.reason == c.ReasonCode.CANCELLED
    assert launch.control._next[binding.occurrence_id] == 0


def test_launcher_cleanup_does_not_overwrite_group_or_target_facts(host, operation_request, binding):
    adapter, launch, stop, _ = setup(host, operation_request, binding, "lost", True)
    result = adapter.run(launch, _encode_frame({}), stop)
    assert result.targets[0].status == c.OutcomeStatus.SUCCEEDED
    assert set(result.cleanup.remaining_refs) == {"owned-linux-runner-group", "owned-wsl-launcher"}


def test_real_fixed_spawn_argv_and_private_environment(monkeypatch, scope):
    observed = []
    # Only the actual private owned-job seam is replaced. Kernel inheritance/
    # environment are exercised separately by the native job controls.
    monkeypatch.setattr(wsl, "_start_job_process",
                        lambda executable, argv, root: observed.append((executable, argv, root)))
    installation = ControllerInstallation(
        scope.context, "windows-wsl", "/owned/bin/python", "a" * 64, "b" * 64,
        r"C:\Windows\System32\wsl.exe", "Qualified-Only",
    )
    wsl._WslProcessIo().launch(installation)
    executable, argv, root = observed[0]
    assert argv == (
        r"C:\Windows\System32\wsl.exe", "--distribution", "Qualified-Only", "--exec",
        "/owned/bin/python", "-I", "-m", "netops.ansible.worker", "--stdio-control",
    )
    assert executable == installation.wsl_executable
    assert root == str(Path(installation.wsl_executable).parent)
    assert SECRET not in repr((argv, executable, root))
    assert "--control-fd" not in argv and "bash" not in argv


@pytest.mark.parametrize("fault", ["absent", "hash", "context", "tuple", "distribution", "inert"])
def test_consuming_verifier_and_actual_byte_requirement(monkeypatch, scope, fault):
    installation = ControllerInstallation(
        scope.context, "windows-wsl", "/owned/bin/python", "a" * 64, "b" * 64,
        r"C:\Windows\System32\wsl.exe", "Qualified-Only",
    )
    entry = {
        "state": "qualified", "platform": "windows-wsl",
        "installation_digest": "a" * 64, "context_digest": c.digest(scope.context),
        "evidence_digest": "b" * 64, "python": installation.python,
        "wsl_distribution": installation.wsl_distribution,
        "wsl_executable_digest": "a" * 64, "tuple": {"kernel": "Q03"},
    }
    lock = {"state": "qualified", "required_tuple": ["kernel"], "qualified": [entry]}
    ports = Ports(None)
    verifier = SimpleNamespace(verify=lambda context, state: installation)
    adapter = wsl._OwnedWslProcesses(verifier, None, "/owned/private", ports)
    monkeypatch.setattr(wsl._OwnedInstallationVerifier, "_qualification_lock", lambda: lock)
    state = object()
    assert adapter.verify(scope.context, state) == installation
    if fault == "absent":
        lock["qualified"] = []
    elif fault == "hash":
        entry["wsl_executable_digest"] = "f" * 64
    elif fault == "context":
        entry["context_digest"] = "f" * 64
    elif fault == "tuple":
        entry["tuple"] = {}
    elif fault == "distribution":
        entry["wsl_distribution"] = "Another"
    else:
        lock["state"] = "inert"
    assert adapter.verify(scope.context, state) is None
    assert ports.launches == []


class Child:
    pid = 7331001
    returncode = None

    def __init__(self):
        self.reaped = False

    def wait(self, timeout):
        self.reaped = True
        self.returncode = 0


class GroupSystem(groups._LinuxGroupSystem):
    def __init__(self, *, valid=True, stubborn=False, signal_failure=False):
        self.valid, self.stubborn, self.signal_failure = valid, stubborn, signal_failure
        self.signals = []

    def identity(self, process):
        assert process.pid == 7331001 and not process.reaped
        return self.valid

    def finished(self, process):
        assert not process.reaped
        return True

    def signal(self, process, selected):
        assert process.pid == 7331001 and not process.reaped
        self.signals.append(selected)
        if self.signal_failure:
            raise OSError("SYNTHETIC-S02-must-not-leak")

    def exists(self, process):
        assert process.reaped
        return self.stubborn

    def pause(self, seconds):
        assert seconds == 0.05


@pytest.mark.parametrize("fault", ["", "identity", "stubborn", "signal"])
def test_actual_owned_group_retain_unreaped_leader_and_conservative_failure(monkeypatch, fault, caplog):
    monkeypatch.setattr(groups.signal, "SIGKILL", 9, raising=False)
    system = GroupSystem(
        valid=fault != "identity", stubborn=fault == "stubborn", signal_failure=fault == "signal",
    )
    owner = groups._OwnedLinuxGroup(system)
    child = Child()
    if fault == "identity":
        with pytest.raises(ProtocolError):
            owner.attach(child, "operation")
    else:
        owner.attach(child, "operation")
        assert owner.finished()
    with caplog.at_level("INFO"):
        result = owner.close()
    assert result.status == ("failed" if fault else "succeeded")
    before = list(system.signals)
    assert owner.close() == result and system.signals == before
    if fault == "identity":
        assert system.signals == [] and not child.reaped
    elif not fault:
        assert system.signals == [15, 9] and child.reaped
    assert SECRET not in caplog.text
    if fault == "stubborn":
        records = [r for r in caplog.records if getattr(r, "boundary", "") == "worker.group"]
        assert [r.outcome for r in records] == ["started", "failed"]
        assert records[-1].category == "cleanup"


def test_cancel_during_spawn_cannot_acknowledge_an_unobserved_child(monkeypatch):
    monkeypatch.setattr(groups.signal, "SIGKILL", 9, raising=False)
    entered, release = threading.Event(), threading.Event()
    system = GroupSystem()
    owner = groups._OwnedLinuxGroup(system)
    failures = []

    def spawn():
        entered.set()
        assert release.wait(1.0)
        return Child()

    def launch():
        try:
            owner.launch(spawn, "operation")
        except ProtocolError as error:
            failures.append(error.reason)

    thread = threading.Thread(target=launch)
    thread.start()
    assert entered.wait(0.5)
    first = owner.close()
    assert first.status == "failed" and first.remaining_refs
    release.set()
    thread.join(1.0)
    assert failures == [c.ReasonCode.CANCELLED]
    assert system.signals == [15, 9]
    assert owner.close().status == "succeeded"


class LinuxFrames:
    def __init__(self):
        self.incoming = queue.Queue()
        self.sent = []

    def send(self, value, timeout=2.0):
        self.sent.append(value)

    def receive(self, timeout, cancel=None):
        item = self.incoming.get(timeout=timeout)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.mark.parametrize("fault", ["", "key", "extra", "lost", "context"])
def test_actual_linux_private_control_auth_and_revocation(monkeypatch, fault, operation_request, plan):
    monkeypatch.setattr(groups.signal, "SIGKILL", 9, raising=False)
    frames, cancel = LinuxFrames(), _Cancelled()
    system = GroupSystem()
    owner = groups._OwnedLinuxGroup(system)
    owner.attach(Child(), operation_request.operation_id)
    bound = wsl._binding(operation_request, plan.plan_digest)
    start = {
        "key": "a" * 64, "binding": bound, "challenge": "b" * 64,
        "context_digest": c.digest(c.ControllerContext(operation_request.context)),
    }
    exits = []
    channel = linux._WslWorkerFrames(frames, start, cancel, owner, exit_process=exits.append)
    try:
        channel.send({"kind": "ready", "nonce": NONCE})
        window = _BudgetWindow(SimpleNamespace(monotonic=lambda: 9000000.0), NONCE, plan.plan_digest)
        window.accept(ControllerBudget(NONCE, 10000, 10000), plan.plan_digest)
        if fault == "context":
            with pytest.raises(ProtocolError):
                channel.bind(operation_request, "f" * 64, window)
        else:
            channel.bind(operation_request, plan.plan_digest, window)
        proof = wsl._proof(
            "f" * 64 if fault == "key" else start["key"], "stop", NONCE, bound,
        )
        command = {"kind": "stop", "proof": proof}
        if fault == "extra":
            command["pid"] = 1
        frames.incoming.put(ProtocolError() if fault == "lost" else command)
        assert cancel._event.wait(0.5)
        end = time.monotonic() + 0.5
        while not system.signals and time.monotonic() < end:
            time.sleep(0.001)
        assert system.signals == [15, 9]
        with pytest.raises(ProtocolError):
            window.check()
        if fault in ("key", "extra", "lost"):
            assert not any(item["kind"] == "stopped" for item in frames.sent)
    finally:
        channel.close()


def test_private_pipe_partial_frames_and_sink_failure_are_not_retried():
    class Source(io.BytesIO):
        def read(self, size):
            return super().read(min(size, 1))

    sink = io.BytesIO()
    pipes = _PipeFrames(Source(_encode_frame({"kind": "one"})), sink)
    try:
        assert pipes.receive(0.5) == {"kind": "one"}
        with pytest.raises(ProtocolError):
            pipes.receive(0.1)
        with pytest.raises(ProtocolError):
            pipes.send({"secret": SECRET}, 0.1)
        assert sink.getvalue() == b""
    finally:
        pipes.close()


def test_cleanup_observation_keeps_returned_failure_and_pairing_when_sink_throws(monkeypatch):
    observer = _ControllerIo()
    monkeypatch.setattr(observer._logger, "info", lambda *a, **k: (_ for _ in ()).throw(RuntimeError()))
    expected = c.CleanupOutcome("failed", remaining_refs=("owned-resource",))
    actual = observer.cleanup("worker.cleanup", "private-operation", lambda: expected)
    assert actual is expected and observer.sink_failures == 2
    assert sum(observer.counts.values()) == 2
    assert any(key[1] == "failed" for key in observer.counts)
    assert not any(key[1] == "succeeded" for key in observer.counts)
    assert _decode_frame(_encode_frame({"kind": "safe"})) == {"kind": "safe"}


def test_linux_runtime_proof_consumes_real_pinned_bytes_and_rejects_extra_tree(
    monkeypatch, tmp_path, scope,
):
    required = (
        "bin/python", "netops/ansible/worker.py", "netops/ansible/controller_runner.py",
        "netops/ansible/action_runtime.py", "netops/ansible/_action_mutation.py",
        "netops/ansible/_action_health.py", "netops/ansible/_windows_job.py",
        "netops/ansible/action_plugins/netops_workflow.py", "ansible/plugins/action/__init__.py",
        "netops/ansible/_controller_pipe.py", "netops/ansible/_controller_wsl.py",
        "netops/ansible/_worker_group.py", "netops/ansible/_worker_wsl.py",
    )
    pins = []
    for name in required:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        content = ("own-unit-byte-pin:" + name).encode()
        path.write_bytes(content)
        pins.append({"path": path.as_posix(), "digest": hashlib.sha256(content).hexdigest()})
    start = {
        "context_digest": c.digest(scope.context), "installation_digest": "a" * 64,
        "qualification_digest": "b" * 64,
    }
    entry = {
        "state": "qualified", "platform": "windows-wsl", **start,
        "evidence_digest": start["qualification_digest"],
        "linux_root": tmp_path.as_posix(), "python": pins[0]["path"],
        "runtime_pins": pins, "tuple": {"kernel": "own-unit-fake-Q03"},
    }
    lock = {"state": "qualified", "qualified": [entry], "required_tuple": ["kernel"]}
    monkeypatch.setattr(linux._OwnedInstallationVerifier, "_qualification_lock", lambda: lock)
    # Fake platform ownership I/O, NOT a passing Windows POSIX/Ansible tuple.
    monkeypatch.setattr(
        linux._OwnedInstallationVerifier, "_private", lambda path, **kwargs: path.lstat(),
    )
    # Windows fstat inode reporting is not a POSIX identity proof. Fake this
    # external metadata seam explicitly; production's full stamp stays intact.
    monkeypatch.setattr(
        linux._OwnedInstallationVerifier, "_stamp",
        lambda info: (info.st_size, info.st_mtime_ns),
    )
    monkeypatch.setattr(linux.sys, "executable", pins[0]["path"])
    linux._runtime_evidence(start)
    (tmp_path / "netops/ansible/_worker_group.py").write_bytes(b"tampered")
    with pytest.raises(ProtocolError):
        linux._runtime_evidence(start)
    (tmp_path / "netops/ansible/_worker_group.py").write_bytes(
        b"own-unit-byte-pin:netops/ansible/_worker_group.py",
    )
    (tmp_path / "unlisted.py").write_bytes(b"must-not-be-adopted")
    with pytest.raises(ProtocolError):
        linux._runtime_evidence(start)


def test_actual_launcher_hash_consumes_bytes_and_rejects_link(tmp_path):
    selected = tmp_path / "wsl.exe"
    selected.write_bytes(b"unit-only-not-an-executable")
    assert wsl._WslProcessIo().launcher_bytes(str(selected)) == hashlib.sha256(
        b"unit-only-not-an-executable",
    ).hexdigest()
    assert not list(tmp_path.glob("*.json"))


def test_group_identity_observation_exception_never_signals_unverified_pid():
    system = GroupSystem()
    system.identity = lambda process: (_ for _ in ()).throw(OSError(SECRET))
    owner = groups._OwnedLinuxGroup(system)
    with pytest.raises(ProtocolError):
        owner.attach(Child(), "operation")
    assert owner.close().status == "failed" and system.signals == []


def test_thrown_launcher_or_pipe_cleanup_preserves_existing_target_fact(
    host, operation_request, binding,
):
    adapter, launch, stop, ports = setup(host, operation_request, binding)
    ports.close_launcher = lambda process: (_ for _ in ()).throw(OSError(SECRET))
    ports.channel.close = lambda: (_ for _ in ()).throw(OSError(SECRET))
    result = adapter.run(launch, _encode_frame({}), stop)
    assert result.targets[0].status == c.OutcomeStatus.SUCCEEDED
    assert result.cleanup.status == "failed"
    assert set(result.cleanup.remaining_refs) == {"owned-private-pipes", "owned-wsl-launcher"}


def test_malformed_worker_input_closes_private_source_before_any_broker(monkeypatch, tmp_path):
    from netops.ansible import worker

    source = io.BytesIO(_encode_frame({"unknown": SECRET}))
    frames = LinuxFrames()
    touched = []
    monkeypatch.setattr(worker, "_WorkerBroker", lambda *a: touched.append(a))
    with pytest.raises(ProtocolError):
        worker._run_private(
            source, frames, tmp_path, SimpleNamespace(monotonic=lambda: 1000.0), _Cancelled(),
        )
    assert source.closed and touched == []


def test_pipe_stalled_io_deadline_and_bounded_close():
    release = threading.Event()

    class Source(io.BytesIO):
        def read(self, size):
            release.wait(1.0)
            return b""

    pipes = _PipeFrames(Source(), io.BytesIO())
    try:
        started = time.monotonic()
        with pytest.raises(ProtocolError):
            pipes.receive(0.05)
        assert time.monotonic() - started < 0.2
        assert pipes.close() is False
    finally:
        release.set()


def test_expired_launch_never_starts_wsl_and_invalid_existing_tuple_is_not_ready(
    host, operation_request, binding,
):
    adapter, launch, stop, ports = setup(host, operation_request, binding)
    host[3].value = launch.start_deadline
    with pytest.raises(ProtocolError):
        adapter.run(launch, _encode_frame({}), stop)
    assert ports.launches == []


def test_real_worker_consumes_one_envelope_and_owns_group_cleanup(
    monkeypatch, tmp_path, envelope, operation_request,
):
    from netops.ansible import worker

    monkeypatch.setattr(groups.signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(worker.secrets, "token_hex", lambda count: NONCE)
    system = GroupSystem()
    owner = groups._OwnedLinuxGroup(system)
    child = Child()
    touched = []
    scoped = []
    consumers = []
    frames = LinuxFrames()
    # Final control close is external I/O loss, not a fabricated live permission.
    frames.incoming.put(ProtocolError(c.ReasonCode.CONTROL_LOST))

    class BrokerIo:
        def __init__(self, root, credentials, intents, host, window, concurrency, mutations, health):
            self._directory = root
            self._next = {binding.occurrence_id: 0 for binding, kind in intents}

        def start(self):
            touched.append("broker")

        def _bootstrap(self):
            return {"protocol": 1}

        def close(self):
            return c.CleanupOutcome("failed", remaining_refs=("owned-unit-broker",))

        def results(self):
            return (c.TargetOutcome("r1", c.OutcomeStatus.SUCCEEDED, True),)

    def launch(read_fd, selected, directory, *, owned_group=False):
        assert owned_group is True
        assert selected.request == operation_request
        assert selected.credentials["targets"][0]["fields"]["password"] == SECRET
        assert directory == tmp_path
        # Consume the actual anonymous pipe to avoid a write-blocking fake.
        import os

        duplicate = os.dup(read_fd)

        def consume():
            with os.fdopen(duplicate, "rb") as stream:
                scoped.append(stream.read())

        thread = threading.Thread(target=consume, daemon=True)
        consumers.append(thread)
        thread.start()
        return child

    monkeypatch.setattr(worker, "_WorkerBroker", BrokerIo)
    monkeypatch.setattr(worker, "_launch_runner", launch)
    source = io.BytesIO(_encode_frame(envelope))
    result = worker._run_private(
        source, frames, tmp_path, SimpleNamespace(monotonic=lambda: 9000000.0),
        _Cancelled(), group=owner,
    )
    assert result == 0 and source.closed
    for thread in consumers:
        thread.join(0.5)
        assert not thread.is_alive()
    assert touched == ["broker"] and child.reaped and system.signals == [15, 9]
    wire = next(item["outcome"] for item in frames.sent if item["kind"] == "result")
    outcome = c.OperationOutcome.from_json(json.dumps(wire).encode())
    assert outcome.targets[0].status == c.OutcomeStatus.SUCCEEDED
    assert outcome.cleanup.remaining_refs == ("owned-unit-broker",)


def test_missing_or_replaced_current_qualification_denies_run_before_process(
    host, operation_request, binding, monkeypatch,
):
    adapter, launch, stop, ports = setup(host, operation_request, binding)
    monkeypatch.setattr(wsl._OwnedInstallationVerifier, "_qualification_lock", lambda: {
        "state": "unqualified", "qualified": [],
    })
    with pytest.raises(ProtocolError):
        adapter.run(launch, _encode_frame({}), stop)
    assert ports.launches == []


def test_actual_wsl_io_has_bounded_paired_dimensions_and_no_auth_logging(
    host, operation_request, binding, caplog,
):
    adapter, launch, stop, ports = setup(host, operation_request, binding, "group")
    with caplog.at_level("INFO"):
        result = adapter.run(launch, _encode_frame({"sentinel": SECRET}), stop)
    records = [record for record in caplog.records if record.msg == "controller.io"]
    assert records
    assert any(record.outcome == "failed" for record in records)
    for record in records:
        assert set(record.metric_dimensions) == {"boundary", "outcome", "stage", "reason"}
        assert record.metric == "netops.controller.io.count"
        assert record.duration_metric == "netops.controller.io.duration_seconds"
        assert record.duration >= 0.0
        assert SECRET not in repr(record.__dict__)
        assert ports.channel.start["key"] not in repr(record.__dict__)
        assert NONCE not in repr(record.__dict__)
        if record.outcome == "failed":
            assert record.category != "none" and record.next_action != "none"
    assert result.cleanup.status == "failed"


def test_actual_adapter_throwing_observability_sink_does_not_drop_target_facts(
    host, operation_request, binding, monkeypatch,
):
    adapter, launch, stop, _ = setup(host, operation_request, binding)
    monkeypatch.setattr(
        adapter._io._logger, "info", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(SECRET)),
    )
    result = adapter.run(launch, _encode_frame({}), stop)
    assert result.targets[0].status == c.OutcomeStatus.SUCCEEDED
    assert result.cleanup.status == "succeeded" and adapter._io.sink_failures > 0


def test_exact_late_result_is_retained_after_control_loss_without_new_admission(
    host, operation_request, binding,
):
    adapter, launch, stop, ports = setup(host, operation_request, binding, "late")
    result = adapter.run(launch, _encode_frame({}), stop)
    assert result.targets[0].status == c.OutcomeStatus.SUCCEEDED
    assert result.error.reason == c.ReasonCode.CONTROL_LOST
    assert result.exit_code == 1 and result.cleanup.status == "succeeded"
    assert launch.control._next[binding.occurrence_id] == 2
    assert launch.control._revocation_signal.is_set() and ports.channel.stop_received.is_set()


@pytest.mark.parametrize("waiting", ["input", "response"])
def test_linux_control_cancellation_interrupts_waiters_without_full_timeout(
    monkeypatch, waiting, operation_request, plan,
):
    monkeypatch.setattr(groups.signal, "SIGKILL", 9, raising=False)
    frames, cancel = LinuxFrames(), _Cancelled()
    owner = groups._OwnedLinuxGroup(GroupSystem())
    owner.attach(Child(), operation_request.operation_id)
    bound = wsl._binding(operation_request, plan.plan_digest)
    start = {
        "key": "a" * 64, "challenge": "b" * 64, "binding": bound,
        "context_digest": c.digest(c.ControllerContext(operation_request.context)),
    }
    channel = linux._WslWorkerFrames(frames, start, cancel, owner, exit_process=lambda code: None)
    completed = threading.Event()
    entered = threading.Event()

    def wait():
        entered.set()
        try:
            channel.input() if waiting == "input" else channel.receive(2.0)
        except ProtocolError:
            completed.set()

    thread = threading.Thread(target=wait)
    try:
        channel.send({"kind": "ready", "nonce": NONCE})
        thread.start()
        assert entered.wait(0.5)
        frames.incoming.put({
            "kind": "stop", "proof": wsl._proof(start["key"], "stop", NONCE, bound),
        })
        assert completed.wait(0.3)
    finally:
        channel.close()
        thread.join(0.5)
        assert not thread.is_alive()


@pytest.mark.parametrize("failure", ["expiry", "lost", "backwards"])
def test_linux_stalled_verification_startup_watch_is_bounded_without_renewal(failure):
    clock = SimpleNamespace(value=9000000.0)
    clock.monotonic = lambda: clock.value
    pipes = SimpleNamespace(failed=threading.Event())
    exited = threading.Event()
    calls = []

    def exit_process(code):
        calls.append(code)
        exited.set()

    watcher = linux._StartupWatch(clock, pipes, exit_process)
    try:
        clock.value += 0.5
        watcher.accept(1000)
        # Receipt did not become the new origin.
        assert watcher._deadline == 9000001.0
        with pytest.raises(ProtocolError):
            watcher.accept(10000)
        if failure == "expiry":
            clock.value = 9000001.0
        elif failure == "lost":
            pipes.failed.set()
        else:
            clock.value = 8999999.0
        assert exited.wait(0.3) and calls == [3]
    finally:
        watcher.close()
