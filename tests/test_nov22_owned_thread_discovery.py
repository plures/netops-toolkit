"""Exact-owned production activation and inert refusal controls from frozen AC-011."""

import io
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from netops.ansible.artifact_cleanup import (
    StorageCleanupError,
    _storage_diagnostics,
    cleanup_errors,
)
from netops.dependencies import _installation_process as runner
from netops.dependencies import _installation_windows as native
from netops.dependencies import _setup
from tests.test_nov22_storage_consuming_independent import observe_owned_child


def test_actual_creation_retains_native_identity_before_job_resume(
    tmp_path, monkeypatch, record_property,
):
    observed = observe_owned_child(monkeypatch)
    result = runner._run(
        (sys.executable, "-I", "-B", "-c", "import sys; sys.stdout.buffer.write(b'owned')"),
        tmp_path, _setup._Clock(), _setup._Cancel(), time.monotonic() + 30,
    )
    hp, ht, pid, tid = observed["captured"][0]
    assert hp and ht and hp != ht and pid and tid
    assert result == b"owned"
    assert observed["assign"] == [pid]
    assert observed["activation"] == [(pid, tid, ht)]
    child, = observed["processes"]
    assert child._joined and child._handle == child.thread_handle == 0
    assert child.stdout.closed and child.stderr.closed
    assert observed["jobs"][0].handle is None
    for key, value in zip(("hp", "ht", "pid", "tid"), (hp, ht, pid, tid)):
        record_property("captured_" + key, value)
    record_property("job_before_resume", True)
    record_property("no_global_discovery_guard", True)


def inert_job(*, process_id=71, thread_process_id=71, thread_id=91, missing=False):
    """Only inert scoped API ports: no real handles, processes or native activation."""
    calls = []
    job = object.__new__(native._WindowsJob)
    job.handle, job._temporary, job._stopped = 31, set(), False

    def forbidden(*args):
        pytest.fail("No global fallback or activation is allowed in refusal controls")

    ports = {
        "GetProcessId": lambda handle: process_id,
        "GetProcessIdOfThread": lambda handle: thread_process_id,
        "AssignProcessToJobObject": lambda *args: calls.append(("assign", args)) or 1,
        "ResumeThread": lambda *args: calls.append(("resume", args)) or 1,
        "CreateToolhelp32Snapshot": forbidden, "Thread32First": forbidden,
        "Thread32Next": forbidden, "OpenThread": forbidden,
    }
    if not missing:
        ports["GetThreadId"] = lambda handle: thread_id
    job.kernel = SimpleNamespace(**ports)
    return job, calls


@pytest.mark.parametrize("damage", ["process", "thread-process", "thread-id"])
def test_wrong_captured_identity_refuses_before_assignment_or_resume(damage):
    job, calls = inert_job(**{
        "process": {"process_id": 72},
        "thread-process": {"thread_process_id": 72},
        "thread-id": {"thread_id": 92},
    }[damage])
    with pytest.raises(OSError, match="installation-thread-identity-mismatch"):
        job.assign(71, 101, 102, 91)
    assert calls == []


def test_missing_owned_identity_export_blocks_without_any_fallback():
    job, calls = inert_job(missing=True)
    with pytest.raises(AttributeError, match="GetThreadId"):
        job.assign(71, 101, 102, 91)
    assert calls == []


@pytest.mark.parametrize("damage", ["process", "thread-process", "thread-id", "missing-export"])
def test_actual_suspended_child_refuses_mocked_identity_before_native_resume(
    tmp_path, monkeypatch, record_property, damage,
):
    observed = observe_owned_child(monkeypatch)
    original_assign = native._WindowsJob.assign
    primary, starts = [], []
    original_start = threading.Thread.start

    def start(reader):
        starts.append(reader)
        return original_start(reader)

    def assign(job, pid, hp, ht, tid):
        assert observed["captured"] == [(hp, ht, pid, tid)]
        assert observed["processes"][0].poll() is None
        if damage == "missing-export":
            kernel = job.kernel

            class MissingExport:
                def __getattr__(self, name):
                    if name == "GetThreadId":
                        raise AttributeError("GetThreadId unavailable: injected exact job port")
                    return getattr(kernel, name)

            job.kernel = MissingExport()
        else:
            name, value = {
                "process": ("GetProcessId", pid + 1),
                "thread-process": ("GetProcessIdOfThread", pid + 1),
                "thread-id": ("GetThreadId", tid + 1),
            }[damage]
            setattr(job.kernel, name, lambda handle: value)
        try:
            return original_assign(job, pid, hp, ht, tid)
        except (OSError, AttributeError) as error:
            primary.append(error)
            raise

    monkeypatch.setattr(native._WindowsJob, "assign", assign)
    monkeypatch.setattr(threading.Thread, "start", start)
    expected = AttributeError if damage == "missing-export" else OSError
    with pytest.raises(expected) as rejected:
        runner._run(
            (sys.executable, "-I", "-B", "-c", "raise AssertionError('must stay suspended')"),
            tmp_path, _setup._Clock(), _setup._Cancel(), time.monotonic() + 30,
        )
    child, = observed["processes"]
    record_property("owned_child_pid", child.pid)
    record_property("failure_port", "mocked exact job identity export; not platform qualification")
    assert rejected.value is primary[0]
    assert observed["activation"] == starts == []
    assert observed["assign"] == []
    assert child._joined and child._handle == child.thread_handle == 0
    assert child.stdout.closed and child.stderr.closed
    assert observed["jobs"][0].handle is None
    assert len(observed["native_closes"]) == 3


def test_actual_failed_native_close_retains_only_rightful_handle(
    tmp_path, monkeypatch, record_property,
):
    observed = observe_owned_child(monkeypatch)
    child_factory = native._InstallationChild
    failures, successful = [], []

    def child(*args):
        process = child_factory(*args)
        close = process.api.CloseHandle
        retained = process.thread_handle

        def close_owned(handle):
            if handle == retained and not failures:
                error = OSError("exact-owned-close-injection")
                error.winerror = 6
                failures.append(error)
                raise error
            if handle == retained:
                assert process.thread_handle == retained != 0
            close(handle)
            successful.append(handle)

        process.api.CloseHandle = close_owned
        return process

    monkeypatch.setattr(native, "_InstallationChild", child)
    with pytest.raises(OSError) as rejected:
        runner._run(
            (sys.executable, "-I", "-B", "-c", "raise SystemExit(0)"),
            tmp_path, _setup._Clock(), _setup._Cancel(), time.monotonic() + 30,
        )
    process, = observed["processes"]
    record_property("owned_child_pid", process.pid)
    assert cleanup_errors(rejected.value)
    hp, ht, _, _ = observed["captured"][0]
    assert successful == [hp, ht]
    assert process._joined and process._handle == process.thread_handle == 0
    assert failures[0].winerror == 6
    process.close()
    assert successful == [hp, ht]


def test_concurrent_native_children_have_disjoint_retained_authority(tmp_path, monkeypatch):
    observed = observe_owned_child(monkeypatch)
    roots = [tmp_path / "a", tmp_path / "b"]
    for root in roots:
        root.mkdir()
    gate = threading.Barrier(2)
    original = native._WindowsJob.assign

    def assign(job, *args):
        gate.wait(timeout=3)
        return original(job, *args)

    monkeypatch.setattr(native._WindowsJob, "assign", assign)

    def execute(root):
        return runner._run(
            (sys.executable, "-I", "-B", "-c", "import sys;sys.stdout.buffer.write(b'isolated')"),
            root, _setup._Clock(), _setup._Cancel(), time.monotonic() + 30,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(execute, roots)) == [b"isolated", b"isolated"]
    assert len(observed["captured"]) == 2
    assert len({row[0] for row in observed["captured"]}) == 2
    assert len({row[1] for row in observed["captured"]}) == 2
    assert len({row[2] for row in observed["captured"]}) == 2
    assert len({row[3] for row in observed["captured"]}) == 2
    assert sorted(observed["activation"]) == sorted(
        (pid, tid, ht) for _, ht, pid, tid in observed["captured"]
    )
    assert all(child._joined and child._handle == child.thread_handle == 0
               for child in observed["processes"])
    assert len({id(child.api) for child in observed["processes"]}) == 2
    assert len({id(job.kernel) for job in observed["jobs"]}) == 2
    assert all(job.handle is None for job in observed["jobs"])


@pytest.mark.parametrize("fail_first_kill", [False, True])
def test_inert_assignment_cleanup_retries_only_failed_kill(monkeypatch, tmp_path, fail_first_kill):
    """Load-bearing runner proof; inert child never executes an OS operation."""
    primary = OSError("inert-assignment-refusal")
    calls = []

    class Child:
        pid, _handle, thread_handle, tid = 71, 101, 102, 91
        returncode = None

        def __init__(self, *args):
            self.stdout, self.stderr = io.BytesIO(), io.BytesIO()

        def kill(self):
            calls.append("kill")
            if fail_first_kill and calls.count("kill") == 1:
                raise OSError("inert-kill-failure")
            self.returncode = 1

        def wait(self, timeout):
            calls.append("wait")
            assert self.returncode == 1
            return 1

        def close(self):
            calls.append("close-child")
            self._handle = self.thread_handle = 0

    class Job:
        handle, _temporary = 31, set()

        def assign(self, *args):
            raise primary

        def stop(self):
            calls.append("stop")

        def close(self):
            calls.append("close-job")
            self.handle = None

    monkeypatch.setattr(native, "_InstallationChild", Child)
    monkeypatch.setattr(native, "_WindowsJob", Job)
    with pytest.raises(OSError) as rejected:
        runner._run(("inert",), tmp_path, _setup._Clock(), _setup._Cancel(),
                    time.monotonic() + 30)
    assert rejected.value is primary
    assert calls.count("kill") == (2 if fail_first_kill else 1)
    assert calls.count("wait") == 1
    assert calls.count("close-job") == 1
    assert calls.index("kill") < calls.index("wait")


def test_inert_failed_thread_close_retains_exact_right_until_success():
    child = object.__new__(native._InstallationChild)
    child._handle, child.thread_handle = 0, 102
    child._temporary, child._descriptors = set(), set()
    calls = []

    def close(handle):
        calls.append(handle)
        if len(calls) == 1:
            error = OSError("inert-owned-close-failure")
            error.winerror = 6
            raise error

    child.api = SimpleNamespace(CloseHandle=close)
    with pytest.raises(StorageCleanupError, match="protected-storage-cleanup") as rejected:
        child.close()
    assert cleanup_errors(rejected.value)
    assert any(item.winerror == 6 for item in _storage_diagnostics(rejected.value))
    assert child.thread_handle == 102
    child.close()
    assert child.thread_handle == 0 and calls == [102, 102]
    child.close()
    assert calls == [102, 102]


def completed_ports(monkeypatch):
    calls = []

    class Child:
        pid, _handle, thread_handle, tid = 71, 101, 102, 91
        returncode = 0

        def __init__(self, *args):
            self.stdout, self.stderr = io.BytesIO(), io.BytesIO()

        def poll(self):
            return 0

        def wait(self, timeout):
            calls.append(("wait", timeout))
            return 0

        def kill(self):
            pytest.fail("Completed inert child must not be killed")

        def close(self):
            self._handle = self.thread_handle = 0

    class Job:
        handle, _temporary = 31, set()

        def assign(self, *args):
            calls.append(("assign", args))

        def stop(self):
            calls.append(("stop",))

        def close(self):
            self.handle = None

    monkeypatch.setattr(native, "_InstallationChild", Child)
    monkeypatch.setattr(native, "_WindowsJob", Job)
    return calls


def test_inert_reader_remains_unjoined_and_failure_is_bounded(monkeypatch, tmp_path):
    completed_ports(monkeypatch)
    original = threading.Thread
    release, reached = threading.Event(), threading.Event()
    readers, timeouts = [], []

    class Reader(original):
        def __init__(self, *, target, args, daemon):
            def read():
                target(*args)
                if args[1]:
                    reached.set()
                    release.wait()

            super().__init__(target=read, daemon=daemon)
            readers.append(self)

        def join(self, timeout=None):
            timeouts.append(timeout)
            return super().join(timeout)

    monkeypatch.setattr(runner.threading, "Thread", Reader)
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="installation-reader-unjoined"):
            runner._run(("inert",), tmp_path, _setup._Clock(), _setup._Cancel(),
                        time.monotonic() + 30)
        assert reached.is_set() and readers[0].is_alive()
        assert time.monotonic() - started < 3
        assert all(value is not None and 0 <= value <= 1 for value in timeouts)
        assert all(a >= b for a, b in zip(timeouts, timeouts[1:]))
    finally:
        release.set()
        for reader in readers:
            original.join(reader, timeout=3)
            assert not reader.is_alive()


def test_inert_original_source_rejection_precedes_reader_start(monkeypatch, tmp_path):
    calls = completed_ports(monkeypatch)
    primary = OSError("inert-source-drift")
    guards, starts = [], []
    original_start = threading.Thread.start

    def start(reader):
        starts.append(reader)
        return original_start(reader)

    def guard():
        guards.append("guard")
        if len(guards) == 4:
            raise primary

    monkeypatch.setattr(threading.Thread, "start", start)
    with pytest.raises(OSError) as rejected:
        runner._run(("inert",), tmp_path, _setup._Clock(), _setup._Cancel(),
                    time.monotonic() + 30, _source_guard=guard)
    assert rejected.value is primary and len(guards) == 4
    assert starts == []
    assert calls[0][0] == "assign"
