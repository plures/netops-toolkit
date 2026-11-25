"""Criteria-derived local consuming controls, not publisher/platform qualification."""

import hashlib
import json
import pickle
import sys
import threading
import time
from copy import copy
from dataclasses import replace
from pathlib import Path

import pytest

from netops import setup
from netops.ansible import contracts as c
from netops.ansible.artifact_cleanup import _storage_diagnostics, cleanup_errors
from netops.ansible.policy.authorization import AuthorizationError
from netops.dependencies import _installation_process, _setup
from netops.dependencies._assets import AssetResponse, HttpsAssetTransport
from netops.dependencies._family_lock import _FamilyResolver, _Target
from netops.dependencies._publisher_metadata import _registered_publishers
from tests.test_nov21_bootstrap_layout_postfix_independent import drift, producer
from tests.test_nov21_publisher_consumption_independent import Cancel, Clock, fixture


@pytest.mark.parametrize("selection", [[], ["--companion", "health"], ["--enhanced"]])
@pytest.mark.parametrize("action", ["install", "update", "resume"])
def test_ac001_public_compound_missing_original_actors_is_zero_effect_before_observation(
    tmp_path, monkeypatch, capsys, selection, action,
):
    root = tmp_path / "never-created-managed"
    sentinel = tmp_path / "native-user-state"
    sentinel.write_bytes(b"unchanged native state")
    observed, asked = [], []

    def external(self, *args):
        observed.append(args)
        pytest.fail("Missing original actors must reject before publisher HTTP.")

    def input_boundary(prompt):
        asked.append(prompt)
        pytest.fail("Missing original actors must reject before consent.")

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", external)
    monkeypatch.setattr(HttpsAssetTransport, "read", external)
    monkeypatch.setattr("builtins.input", input_boundary)
    metadata = setup.SetupMetadata.publishers(None, (), (), (
        _Target("native", sys.platform, "x86_64", "3.12.8", "cp312",
                ("py3-none-any",), "c" * 64),
    ))
    result = setup.main([action, "--root", str(root), *selection], metadata=metadata)
    output = capsys.readouterr().out.strip()
    expected = {
        "status": "NeedsInput", "reason": "live-selected-family-contributions-required",
        "effects_performed": [], "consent_issued": False,
        "fields": ["original-qualified-native-producer", "each-selected-subset-issuer"],
        "choices": ["compose-current-source-and-replan", "cancel"],
    }
    assert result == 3
    assert json.loads(output) == expected
    assert output == c.canonical_bytes(c.public_object(expected)).decode("utf-8")
    assert observed == [] and asked == []
    assert not root.exists()
    assert sentinel.read_bytes() == b"unchanged native state"
    assert tuple(p.name for p in tmp_path.iterdir()) == ("native-user-state",)


def closed_actor(monkeypatch):
    """Only HTTP is synthetic; original closed client/resolver issue the actor.

    These are adversarial metadata/source controls: no executable archive,
    private producer, artifact acquisition or platform qualification is issued.
    """
    item, transport, _ = fixture()
    calls = []

    def external(self, url, timeout, limit, clock, cancel):
        calls.append((url, timeout, limit, cancel))
        return AssetResponse(url, transport.content)

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", external)
    from tests.test_nov21_publisher_consumption_independent import TARGET

    engine = _FamilyResolver(_registered_publishers((item,), HttpsAssetTransport()))
    clock, cancel = Clock(), Cancel()
    result = engine.resolve((item.requirement,), (TARGET,), "b" * 64,
                            clock, cancel, 40.0)
    assert result.lock is not None and result.needs == ()
    assert result.contributions is not None
    result.contributions.guard(clock, cancel, 40.0)
    assert len(calls) == 1
    assert calls[0][0] != item.artifact.url
    return result.contributions, clock, cancel, calls


@pytest.mark.parametrize("damage", [
    "copied-actor", "copied-subset", "omitted-subset", "client", "transport",
    "configuration", "expired", "backward", "cancelled", "cross-thread",
])
def test_ac003_original_closed_actor_rejects_identity_and_lifetime_drift(
    monkeypatch, damage,
):
    actor, clock, cancel, calls = closed_actor(monkeypatch)
    assert actor._contributions[0].release is actor._lock.releases[0]
    with pytest.raises(TypeError):
        pickle.dumps(actor)
    with pytest.raises(TypeError):
        pickle.dumps(actor._contributions[0])
    if damage == "copied-actor":
        with pytest.raises(TypeError):
            copy(actor)
        actor.guard(clock, cancel, 40.0)
        assert len(calls) == 1
        return
    elif damage == "copied-subset":
        actor._contributions = (replace(actor._contributions[0]),)
    elif damage == "omitted-subset":
        actor._contributions = ()
    elif damage == "client":
        original = actor._contributions[0].source
        actor._issuer._sources[original.source] = replace(original, port=copy(original.port))
    elif damage == "transport":
        object.__setattr__(actor._contributions[0].port, "transport", HttpsAssetTransport())
    elif damage == "configuration":
        actor._issuer._sources[actor._contributions[0].source.source] = replace(
            actor._contributions[0].source, metadata_digest="e" * 64,
        )
    elif damage == "expired":
        clock.value = actor._lock.observations[0].expires_at
    elif damage == "backward":
        clock.value = 9.0
    elif damage == "cancelled":
        cancel.value = True
    if damage == "cross-thread":
        outcomes = []

        def foreign_thread():
            try:
                actor.guard(clock, cancel, 40.0)
            except BaseException as error:
                outcomes.append(error)

        thread = threading.Thread(target=foreign_thread)
        thread.start()
        thread.join()
        assert len(outcomes) == 1 and type(outcomes[0]) is AuthorizationError
    else:
        expected = (
            InterruptedError if damage == "cancelled" else
            (AuthorizationError, TimeoutError) if damage == "expired" else AuthorizationError
        )
        with pytest.raises(expected):
            actor.guard(clock, cancel, 40.0)
    assert len(calls) == 1


def test_ac001_each_original_transitive_subset_is_retained_by_actual_closed_resolver(monkeypatch):
    """No artifact acquisition: synthetic HTTP documents are source controls only."""
    from tests.test_nov21_publisher_consumption_independent import TARGET

    base, _, _ = fixture()
    items, documents = [], {}
    for name, dependencies in (
        ("original-helper", []), ("original-parent", ["original-helper==1.0"]),
    ):
        filename = name.replace("-", "_") + "-1.0-py3-none-any.whl"
        artifact = replace(
            base.artifact, source_id="pypi:" + name, dependency=name,
            url="https://files.pythonhosted.org/packages/SOURCE-ONLY/" + filename,
        )
        document = {
            "info": {"name": name, "version": "1.0", "requires_python": ">=3.9",
                     "provides_extra": [], "requires_dist": dependencies},
            "urls": [{"url": artifact.url, "packagetype": "bdist_wheel", "yanked": False,
                      "size": artifact.size, "digests": {"sha256": artifact.sha256},
                      "filename": filename}],
        }
        content = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        requirement = replace(base.requirement, name=name, source="pypi:" + name)
        item = replace(
            base, requirement=requirement, artifact=artifact,
            metadata_digest=hashlib.sha256(content).hexdigest(),
            requires=() if not items else (items[0].requirement,),
            members=(replace(base.members[0], path=name.replace("-", "_") + ".py"),),
        )
        items.append(item)
        documents["https://pypi.org/pypi/" + name + "/1.0/json"] = content
    calls = []

    def external(self, url, timeout, limit, clock, cancel):
        calls.append(url)
        return AssetResponse(url, documents[url])

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", external)
    engine = _FamilyResolver(_registered_publishers(tuple(items), HttpsAssetTransport()))
    result = engine.resolve((items[-1].requirement,), (TARGET,), "b" * 64,
                            Clock(), Cancel(), 40.0)
    assert result.lock is not None and result.contributions is not None
    assert [item.requirement.name for item in result.lock.releases] == [
        "original-helper", "original-parent",
    ]
    actor = result.contributions
    assert len({id(part) for part in actor._contributions}) == 2
    assert all(part.release is selected for part, selected in zip(
        actor._contributions, result.lock.releases,
    ))
    actor.guard(Clock(), Cancel(), 40.0)
    assert set(calls) == set(documents) and len(calls) == 2
    actor._contributions = actor._contributions[1:]
    with pytest.raises(AuthorizationError):
        actor.guard(Clock(), Cancel(), 40.0)
    assert len(calls) == 2


def observe_owned_child(monkeypatch, *, after_assign=None, after_wait=None, close_fault=None):
    """Observe native creation handles through instance-local ports, without discovery."""
    from netops.dependencies import _installation_windows as native
    from netops.dependencies._installation_windows import _WindowsJob

    original_init = _WindowsJob.__init__
    original_assign = _WindowsJob.assign
    original_stop = _WindowsJob.stop
    original_close = _WindowsJob.close
    original_child = native._InstallationChild
    observed = {"jobs": [], "processes": [], "assign": [], "wait": [],
                "stop": [], "close_attempts": [], "native_closes": [],
                "pipe_closes": {"stdout": 0, "stderr": 0}, "captured": [], "activation": []}
    fault = [close_fault]

    def init(job):
        original_init(job)
        observed["jobs"].append(job)
        close_handle = job.kernel.CloseHandle
        def forbidden(*args):
            pytest.fail("Global thread/process discovery is forbidden")

        for name in ("CreateToolhelp32Snapshot", "Thread32First", "Thread32Next", "OpenThread"):
            setattr(job.kernel, name, forbidden)
        assign_native = job.kernel.AssignProcessToJobObject
        resume_native = job.kernel.ResumeThread
        assigned = []

        def assign_native_owned(handle, process_handle):
            result = assign_native(handle, process_handle)
            if result:
                assigned.append(int(process_handle))
            return result

        def resume_owned(handle):
            process, = [item for item in observed["processes"] if item.thread_handle == int(handle)]
            assert assigned == [process._handle]
            assert int(handle) == process.thread_handle
            assert job.kernel.GetProcessId(process._handle) == process.pid
            assert job.kernel.GetProcessIdOfThread(handle) == process.pid
            assert job.kernel.GetThreadId(handle) == process.tid
            observed["activation"].append((process.pid, process.tid, int(handle)))
            return resume_native(handle)

        job.kernel.AssignProcessToJobObject = assign_native_owned
        job.kernel.ResumeThread = resume_owned

        def close_native(handle):
            result = close_handle(handle)
            observed["native_closes"].append((int(handle), bool(result)))
            return result

        job.kernel.CloseHandle = close_native

    def assign(job, pid, handle, thread_handle, tid):
        original_assign(job, pid, handle, thread_handle, tid)
        observed["assign"].append(pid)
        if after_assign is not None:
            after_assign()

    def stop(job):
        observed["stop"].append(job.handle)
        return original_stop(job)

    def close(job):
        observed["close_attempts"].append(job.handle)
        if fault[0] == "job":
            fault[0] = None
            error = OSError("owned boundary close injection")
            error.winerror = 6
            raise error
        return original_close(job)

    def child(*args, **kwargs):
        process = original_child(*args, **kwargs)
        observed["processes"].append(process)
        observed["captured"].append((process._handle, process.thread_handle, process.pid, process.tid))
        native_close = process.api.CloseHandle

        def close_child(handle):
            native_close(handle)
            observed["native_closes"].append((int(handle), True))

        process.api.CloseHandle = close_child
        wait = process.wait

        def wait_owned(*args, **kwargs):
            result = wait(*args, **kwargs)
            observed["wait"].append(process.pid)
            if after_wait is not None:
                after_wait()
            return result

        process.wait = wait_owned
        for name in ("stdout", "stderr"):
            stream = getattr(process, name)
            original_close_pipe = stream.close

            def close_pipe(name=name, original=original_close_pipe):
                observed["pipe_closes"][name] += 1
                if name == "stdout" and fault[0] == "pipe":
                    fault[0] = None
                    error = OSError("owned pipe close boundary injection")
                    error.winerror = 6
                    raise error
                return original()

            stream.close = close_pipe
        return process

    monkeypatch.setattr(_WindowsJob, "__init__", init)
    monkeypatch.setattr(_WindowsJob, "assign", assign)
    monkeypatch.setattr(_WindowsJob, "stop", stop)
    monkeypatch.setattr(_WindowsJob, "close", close)
    monkeypatch.setattr(native, "_InstallationChild", child)
    return observed


def assert_released(observed):
    assert len(observed["jobs"]) == len(observed["processes"]) == 1
    job, = observed["jobs"]
    process, = observed["processes"]
    assert observed["assign"] == [process.pid]
    assert observed["wait"] == [process.pid]
    assert job.handle is None and job._temporary == set()
    assert process.poll() is not None
    assert process._handle == process.thread_handle == 0
    assert process.stdout.closed and process.stderr.closed
    assert len(observed["stop"]) == 1
    successful = [handle for handle, success in observed["native_closes"] if success]
    assert len(successful) == len(set(successful)) == 3
    assert all(success for _, success in observed["native_closes"])


@pytest.mark.parametrize("boundary", ["postspawn", "postjoin"])
def test_ac011_actual_original_source_drift_after_child_boundary_closes_exact_owned_resources(
    tmp_path, monkeypatch, boundary,
):
    host, source, manifest, _ = producer(tmp_path, monkeypatch)
    guard_calls = []
    rejection_phase = []
    reader_starts = []
    original_start = threading.Thread.start
    observed = None

    def start_reader(reader):
        reader_starts.append(reader.name)
        return original_start(reader)

    monkeypatch.setattr(threading.Thread, "start", start_reader)

    def guard():
        guard_calls.append("guard")
        try:
            source.guard(manifest, Clock(), Cancel(), 100.0)
        except BaseException:
            rejection_phase.append((tuple(reader_starts), tuple(observed["wait"])))
            raise

    observed = observe_owned_child(
        monkeypatch,
        after_assign=(lambda: drift(host, "source")) if boundary == "postspawn" else None,
        after_wait=(lambda: drift(host, "cache")) if boundary == "postjoin" else None,
    )
    with pytest.raises((AuthorizationError, c.ContractError, OSError)):
        _installation_process._run(
            (sys.executable, "-I", "-B", "-c", "raise SystemExit(0)"),
            Path(host.consuming_root.path), _setup._Clock(), _setup._Cancel(),
            time.monotonic() + 30.0, _source_guard=guard,
        )
    assert len(guard_calls) == (4 if boundary == "postspawn" else 5)
    assert len(rejection_phase) == 1
    if boundary == "postspawn":
        assert rejection_phase == [((), ())], "Original source rejection must precede readers/wait"
    else:
        assert len(rejection_phase[0][0]) == 2
        assert rejection_phase[0][1] == (observed["processes"][0].pid,)
    assert_released(observed)
    assert len(observed["close_attempts"]) == 1


@pytest.mark.parametrize("recover", [False, True])
def test_ac011_live_owned_child_simultaneous_native_stop_close_failures_are_bounded(
    tmp_path, monkeypatch, recover, record_property,
):
    import ctypes

    observed = observe_owned_child(monkeypatch)
    cancel = _setup._Cancel()
    original_start = threading.Thread.start
    original_join = threading.Thread.join
    events, waits, joins, live = [], [], [], []
    originals = {}
    primary = InterruptedError()

    def start_reader(reader):
        result = original_start(reader)
        cancel.event.set()
        return result

    def join_reader(reader, *args, **kwargs):
        joins.append(kwargs.get("timeout"))
        return original_join(reader, *args, **kwargs)

    def guard():
        if not observed["assign"] or originals:
            return
        job = observed["jobs"][0]
        process = observed["processes"][0]
        record_property("owned_child_pid", process.pid)
        originals["stop"] = job.kernel.TerminateJobObject
        originals["close"] = job.kernel.CloseHandle
        stop_count = [0]
        close_count = [0]

        def stop(handle, code):
            live.append(process.poll() is None)
            stop_count[0] += 1
            events.append("stop")
            if recover and stop_count[0] > 1:
                return originals["stop"](handle, code)
            ctypes.set_last_error(6)
            return 0

        def close(handle):
            if int(handle) != job.handle:
                return originals["close"](handle)
            close_count[0] += 1
            events.append("close")
            if recover and close_count[0] > 2:
                return originals["close"](handle)
            ctypes.set_last_error(6)
            return 0

        original_wait = process.wait

        def wait(*args, **kwargs):
            events.append("wait")
            waits.append(kwargs.get("timeout"))
            return original_wait(*args, **kwargs)

        job.kernel.TerminateJobObject = stop
        job.kernel.CloseHandle = close
        process.wait = wait

    def cancelled():
        if cancel.is_cancelled():
            raise primary
        return False

    monkeypatch.setattr(threading.Thread, "start", start_reader)
    monkeypatch.setattr(threading.Thread, "join", join_reader)
    checked_cancel = type("CheckedCancel", (), {
        "is_cancelled": staticmethod(cancelled), "wait": staticmethod(cancel.wait),
    })()
    started = time.monotonic()
    try:
        with pytest.raises(InterruptedError) as rejected:
            _installation_process._run(
                (sys.executable, "-I", "-B", "-c",
                 "import threading; threading.Event().wait(20)"),
                tmp_path, _setup._Clock(), checked_cancel, time.monotonic() + 30.0,
                _source_guard=guard,
            )
        assert rejected.value is primary
        assert time.monotonic() - started < 3.0
        assert live[0] is True
        assert events[:5] == ["stop", "close", "close", "stop", "close"]
        assert waits and joins
        assert all(value is not None and 0 <= value <= 1.0 for value in waits + joins)
        assert all(a >= b for a, b in zip(waits + joins, (waits + joins)[1:]))
        assert any(item.winerror == 6 for item in _storage_diagnostics(primary, cleanup=True))
        if recover:
            assert observed["jobs"][0].handle is None
            assert observed["jobs"][0]._temporary == set()
            assert observed["processes"][0].poll() is not None
            assert observed["wait"] == [observed["processes"][0].pid]
            successful = [handle for handle, success in observed["native_closes"] if success]
            assert len(successful) == len(set(successful)) == 3
            assert len(waits) == 1 and len(joins) == 2
            assert observed["pipe_closes"] == {"stdout": 1, "stderr": 1}
        else:
            assert observed["processes"][0].poll() is None
            assert observed["jobs"][0].handle is not None
            assert len(waits) == 2 and len(joins) == 4
            assert observed["pipe_closes"] == {"stdout": 0, "stderr": 0}
            errors = cleanup_errors(primary)
            assert len(errors) >= 6
            assert all(
                error.category == c.ErrorCategory.CLEANUP
                and error.reason == c.ReasonCode.CLEANUP_FAILED
                and error.stage == c.Stage.FINALIZE
                for error in errors
            )
    finally:
        for process in observed["processes"]:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3.0)
        for job in observed["jobs"]:
            if originals:
                job.kernel.TerminateJobObject = originals["stop"]
                job.kernel.CloseHandle = originals["close"]
            job.close()
        for process in observed["processes"]:
            for stream in (process.stdout, process.stderr):
                stream.close()
            process.close()


@pytest.mark.parametrize("fault", ["reader", "pipe"])
def test_ac011_actual_child_remaining_release_retry_never_repeats_successful_resources(
    tmp_path, monkeypatch, fault,
):
    observed = observe_owned_child(monkeypatch, close_fault="pipe" if fault == "pipe" else None)
    joined = {}
    original_join = threading.Thread.join
    injection_pending = [fault == "reader"]
    primary = OSError("owned reader join boundary injection")
    primary.winerror = 6

    def join_reader(thread, *args, **kwargs):
        if thread.name not in joined:
            joined[thread.name] = 0
        joined[thread.name] += 1
        if injection_pending[0]:
            injection_pending[0] = False
            raise primary
        return original_join(thread, *args, **kwargs)

    monkeypatch.setattr(threading.Thread, "join", join_reader)
    with pytest.raises(OSError) as rejected:
        _installation_process._run(
            (sys.executable, "-I", "-B", "-c", "raise SystemExit(0)"),
            tmp_path, _setup._Clock(), _setup._Cancel(), time.monotonic() + 30.0,
        )
    if fault == "reader":
        assert rejected.value is primary
        assert sorted(joined.values()) == [1, 2]
        assert observed["pipe_closes"] == {"stdout": 1, "stderr": 1}
    else:
        assert cleanup_errors(rejected.value)
        assert sorted(joined.values()) == [1, 1]
        assert observed["pipe_closes"] == {"stdout": 2, "stderr": 1}
    assert_released(observed)
    assert len(observed["close_attempts"]) == 1


@pytest.mark.parametrize("terminal", ["cancel", "timeout"])
def test_ac011_actual_postspawn_terminal_preserves_primary_with_remaining_only_job_retry(
    tmp_path, monkeypatch, terminal,
):
    cancel = _setup._Cancel()
    primary = InterruptedError() if terminal == "cancel" else TimeoutError()
    observed = None

    def guard():
        if observed is not None and observed["assign"]:
            if terminal == "cancel":
                cancel.event.set()
            raise primary

    observed = observe_owned_child(monkeypatch, close_fault="job")
    with pytest.raises(type(primary)) as rejected:
        _installation_process._run(
            (sys.executable, "-I", "-B", "-c", "raise SystemExit(0)"),
            tmp_path, _setup._Clock(), cancel, time.monotonic() + 30.0,
            _source_guard=guard,
        )
    assert rejected.value is primary
    assert cleanup_errors(primary)
    diagnostics = _storage_diagnostics(primary, cleanup=True)
    assert any(item.winerror == 6 for item in diagnostics)
    assert_released(observed)
    assert len(observed["close_attempts"]) == 2


@pytest.mark.parametrize("terminal", ["cancel", "deadline"])
def test_ac011_real_postspawn_original_cancel_or_deadline_joins_child_once(
    tmp_path, monkeypatch, terminal,
):
    cancel = _setup._Cancel()
    observed = observe_owned_child(
        monkeypatch, after_assign=cancel.event.set if terminal == "cancel" else None,
    )
    with pytest.raises(InterruptedError if terminal == "cancel" else TimeoutError):
        _installation_process._run(
            (sys.executable, "-I", "-B", "-c", "import threading; threading.Event().wait(20)"),
            tmp_path, _setup._Clock(), cancel, time.monotonic() + 1.0,
        )
    assert cancel.is_cancelled() is (terminal == "cancel")
    assert_released(observed)
    assert len(observed["close_attempts"]) == 1
