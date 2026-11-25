"""Independent owned-cleanup controls; fault ports are not platform qualification."""

import ctypes
import sys
import threading
import time

import pytest

from netops.ansible import contracts as c
from netops.ansible.artifact_cleanup import _storage_diagnostics, cleanup_errors
from netops.dependencies import _installation_process, _setup
from netops.dependencies import _installation_windows as native
from netops.dependencies._installation_windows import _WindowsJob
from tests.test_nov22_storage_consuming_independent import observe_owned_child


def assignment_case(monkeypatch, *, fail_kill):
    """Fail only the native assignment and, separately, exact child kill API."""
    observed = observe_owned_child(monkeypatch)
    original_init = _WindowsJob.__init__
    original_assign = _WindowsJob.assign
    original_start = threading.Thread.start
    original_child = native._InstallationChild
    observed.update(primary=[], kill=[], starts=[], timeouts=[], activation=[])

    def init(job):
        original_init(job)
        resume = job.kernel.ResumeThread

        def assign(handle, process_handle):
            process = observed["processes"][0]
            assert int(handle) == job.handle
            assert int(process_handle) == int(process._handle)
            assert process.poll() is None
            ctypes.set_last_error(5)
            return 0

        def activate(handle):
            return resume(handle)

        job.kernel.AssignProcessToJobObject = assign
        job.kernel.ResumeThread = activate

    def assign(job, *args):
        try:
            return original_assign(job, *args)
        except OSError as error:
            observed["primary"].append(error)
            raise

    def child(*args, **kwargs):
        process = original_child(*args, **kwargs)
        observed["pinned_handle"] = int(process._handle)
        observed["terminate"] = process.api.TerminateProcess

        def kill(handle, code):
            assert int(handle) == int(process._handle) and int(handle) != 0
            observed["kill"].append((int(handle), process.poll() is None))
            if fail_kill:
                error = OSError("exact owned TerminateProcess contract failure")
                error.winerror = 6
                raise error
            return observed["terminate"](handle, code)

        process.api.TerminateProcess = kill
        wait = process.wait

        def wait_owned(*args, **kwargs):
            observed["timeouts"].append(kwargs.get("timeout"))
            return wait(*args, **kwargs)

        process.wait = wait_owned
        return process

    def start(reader):
        observed["starts"].append(reader)
        return original_start(reader)

    monkeypatch.setattr(_WindowsJob, "__init__", init)
    monkeypatch.setattr(_WindowsJob, "assign", assign)
    monkeypatch.setattr(native, "_InstallationChild", child)
    monkeypatch.setattr(threading.Thread, "start", start)
    return observed, lambda handle, code: observed["terminate"](handle, code)


def assert_secondary(error):
    errors = cleanup_errors(error)
    assert errors
    assert all(
        item.category == c.ErrorCategory.CLEANUP
        and item.reason == c.ReasonCode.CLEANUP_FAILED
        and item.stage == c.Stage.FINALIZE
        and item.next_action
        for item in errors
    )


def finish_owned(observed, terminate):
    """Rightful retry uses only the retained exact child handle, never a scan."""
    for process in observed["processes"]:
        if process.poll() is None:
            terminate(process._handle, 1)
        process.wait(timeout=3.0)
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
        process.close()
    for job in observed["jobs"]:
        job.close()


def test_ac011_assignment_failure_before_activation_preserves_exact_primary_and_cleanup(
    tmp_path, monkeypatch, record_property,
):
    observed, terminate = assignment_case(monkeypatch, fail_kill=False)
    marker = tmp_path / "activation-must-not-occur"
    try:
        with pytest.raises(OSError) as rejected:
            _installation_process._run(
                (sys.executable, "-I", "-B", "-c",
                 "from pathlib import Path; Path('activation-must-not-occur').write_bytes(b'bad')"),
                tmp_path, _setup._Clock(), _setup._Cancel(), time.monotonic() + 30.0,
            )
        process, = observed["processes"]
        job, = observed["jobs"]
        record_property("owned_child_pid", process.pid)
        assert rejected.value is observed["primary"][0]
        assert rejected.value.winerror == 5
        assert observed["activation"] == observed["starts"] == []
        assert not marker.exists()
        assert observed["kill"] == [(observed["pinned_handle"], True)]
        assert observed["wait"] == [process.pid]
        assert len(observed["timeouts"]) == 1 and 0 <= observed["timeouts"][0] <= 1.0
        assert process._handle == process.thread_handle == 0
        assert process.poll() is not None
        assert job.handle is None and job._temporary == set()
        assert observed["pipe_closes"] == {"stdout": 1, "stderr": 1}
        successful = [handle for handle, success in observed["native_closes"] if success]
        assert len(successful) == len(set(successful)) == 3
        assert all(handle != 0 and success for handle, success in observed["native_closes"])
        assert cleanup_errors(rejected.value) == ()
    finally:
        finish_owned(observed, terminate)


def test_ac011_failed_exact_child_kill_retains_handle_for_rightful_retry_without_double_close(
    tmp_path, monkeypatch, record_property,
):
    observed, terminate = assignment_case(monkeypatch, fail_kill=True)
    sentinel = tmp_path / "user-state"
    sentinel.write_bytes(b"unchanged")
    started = time.monotonic()
    try:
        with pytest.raises(OSError) as rejected:
            _installation_process._run(
                (sys.executable, "-I", "-B", "-c", "raise AssertionError('must stay suspended')"),
                tmp_path, _setup._Clock(), _setup._Cancel(), time.monotonic() + 30.0,
            )
        process, = observed["processes"]
        job, = observed["jobs"]
        record_property("owned_child_pid", process.pid)
        assert rejected.value is observed["primary"][0] and rejected.value.winerror == 5
        assert time.monotonic() - started < 3.0
        assert observed["kill"] == [(observed["pinned_handle"], True)] * 2
        assert observed["activation"] == observed["starts"] == observed["wait"] == []
        assert process.poll() is None
        assert int(process._handle) == observed["pinned_handle"] != 0
        assert len(observed["timeouts"]) == 2
        assert 1.0 >= observed["timeouts"][0] >= observed["timeouts"][1] >= 0.0
        assert job.handle is None and job._temporary == set()
        assert process.stdout.closed and process.stderr.closed
        assert observed["pipe_closes"] == {"stdout": 1, "stderr": 1}
        assert len(observed["close_attempts"]) == 1
        assert len(observed["native_closes"]) == 2
        assert all(success for _, success in observed["native_closes"])
        assert process.thread_handle == 0
        assert_secondary(rejected.value)
        assert any(item.winerror == 6 for item in _storage_diagnostics(
            rejected.value, cleanup=True,
        ))
        assert sentinel.read_bytes() == b"unchanged"
        terminate(process._handle, 1)
        process.wait(timeout=3.0)
        assert process.poll() is not None
        assert int(process._handle) == observed["pinned_handle"]
        assert observed["pipe_closes"] == {"stdout": 1, "stderr": 1}
    finally:
        finish_owned(observed, terminate)


@pytest.mark.parametrize("main_outcome", ["success", "failure"])
def test_ac011_independent_stuck_reader_after_child_completed_is_bounded_and_retained(
    tmp_path, monkeypatch, record_property, main_outcome,
):
    observed = observe_owned_child(monkeypatch)
    original_thread = threading.Thread
    original_init = _WindowsJob.__init__
    original_stop = _WindowsJob.stop
    release, reached = threading.Event(), threading.Event()
    readers, joins, failures = [], [], []
    fault_pending = [main_outcome == "failure"]

    class OwnedReader(original_thread):
        def __init__(self, *, target, args, daemon):
            save = args[1]

            def held_reader():
                target(*args)
                if save:
                    reached.set()
                    release.wait()

            super().__init__(target=held_reader, daemon=daemon)
            self.held = save
            readers.append(self)

        def join(self, timeout=None):
            process = observed["processes"][0]
            joins.append((self.held, timeout, process.poll()))
            return super().join(timeout)

    def init(job):
        original_init(job)
        native = job.kernel.TerminateJobObject

        def stop(handle, code):
            assert observed["processes"][0].poll() == 0
            if fault_pending[0]:
                fault_pending[0] = False
                ctypes.set_last_error(6)
                return 0
            return native(handle, code)

        job.kernel.TerminateJobObject = stop

    def stop(job):
        try:
            return original_stop(job)
        except OSError as error:
            failures.append(error)
            raise

    monkeypatch.setattr(threading, "Thread", OwnedReader)
    monkeypatch.setattr(_WindowsJob, "__init__", init)
    monkeypatch.setattr(_WindowsJob, "stop", stop)
    started = time.monotonic()
    try:
        with pytest.raises(OSError) as rejected:
            _installation_process._run(
                (sys.executable, "-I", "-B", "-c", "raise SystemExit(0)"),
                tmp_path, _setup._Clock(), _setup._Cancel(), time.monotonic() + 30.0,
            )
        process, = observed["processes"]
        job, = observed["jobs"]
        record_property("owned_child_pid", process.pid)
        assert reached.is_set() and process.poll() == 0
        assert time.monotonic() - started < 3.0
        assert len(readers) == 2 and all(reader.daemon for reader in readers)
        assert readers[0].is_alive() and not readers[1].is_alive()
        assert all(code == 0 and timeout is not None and 0 <= timeout <= 1.0
                   for _, timeout, code in joins)
        assert all(a[1] >= b[1] for a, b in zip(joins, joins[1:]))
        held = [row for row in joins if row[0]]
        assert len(held) == (3 if main_outcome == "success" else 2)
        assert len(joins) - len(held) == 1
        assert observed["wait"] == [process.pid]
        assert job.handle is None and job._temporary == set()
        assert observed["pipe_closes"] == {"stdout": 0, "stderr": 1}
        assert not process.stdout.closed and process.stderr.closed
        assert_secondary(rejected.value)
        if main_outcome == "failure":
            assert rejected.value is failures[0] and rejected.value.winerror == 6
        else:
            assert failures == [] and type(rejected.value) is TimeoutError
            assert rejected.value.args == ("installation-reader-unjoined",)
        successful = [handle for handle, success in observed["native_closes"] if success]
        assert len(successful) == len(set(successful)) == 3
        assert all(handle != 0 and success for handle, success in observed["native_closes"])
    finally:
        release.set()
        for reader in readers:
            original_thread.join(reader, timeout=3.0)
            assert not reader.is_alive()
        for process in observed["processes"]:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3.0)
            for stream in (process.stdout, process.stderr):
                if not stream.closed:
                    stream.close()
            process.close()
        for job in observed["jobs"]:
            job.close()
