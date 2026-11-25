"""Actual backend ownership exits under deterministic native primitive faults."""

import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops.ansible import artifact_platform as platform
from netops.ansible import artifacts
from netops.ansible.artifact_cleanup import StorageCleanupError, cleanup_errors
from netops.ansible.contracts import OutputIntent, canonical_bytes, digest
from tests.test_artifact_store import Clock, Events, binding
from tests.test_c02_publication_completion import local_memory as local_memory


@pytest.fixture
def backend():
    value = object.__new__(platform.WindowsHandles)
    value._paths = {}
    value._mutex = threading.RLock()
    value._locks = threading.local()
    return value


@pytest.mark.parametrize("operation", ["rename", "remove"])
@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit, RuntimeError])
@pytest.mark.parametrize("secondary_type", [KeyboardInterrupt, SystemExit, RuntimeError])
def test_native_mutation_primary_identity_and_safe_secondary(
    backend, monkeypatch, operation, primary_type, secondary_type,
):
    primary = primary_type("private-primary")
    closed = []

    def mutate(*args):
        raise primary

    def close(handle):
        closed.append(handle)
        raise secondary_type("private-secondary")

    monkeypatch.setattr(backend, "path", lambda parent, name: Path(name))
    monkeypatch.setattr(backend, "_open", lambda *args, **kwargs: 71)
    backend.kernel = SimpleNamespace(
        SetFileInformationByHandle=mutate, GetFileAttributesW=lambda path: 0,
        CloseHandle=close,
    )
    args = (1, "source", "dest", True) if operation == "rename" else (1, "source")
    with pytest.raises(BaseException) as caught:
        getattr(backend, operation)(*args)
    assert caught.value is primary
    assert closed == [71]
    assert len(cleanup_errors(primary)) == 1
    assert "private" not in repr(cleanup_errors(primary))


@pytest.mark.parametrize("allocation", ["security", "sid", "token"])
def test_native_output_allocation_owned_before_cancellation(backend, allocation):
    primary = KeyboardInterrupt("private-primary")
    freed = []
    backend.sid = "fixture"

    def allocate(*args):
        output = args[-2] if allocation == "security" else args[-1]
        output._obj.value = 71
        raise primary

    def free(pointer):
        freed.append(pointer.value)
        raise SystemExit("private-secondary")

    backend.advapi = SimpleNamespace(
        ConvertStringSecurityDescriptorToSecurityDescriptorW=allocate,
        ConvertSidToStringSidW=allocate, OpenProcessToken=allocate,
    )
    backend.kernel = SimpleNamespace(
        LocalFree=free, CloseHandle=free, GetCurrentProcess=lambda: 1,
    )
    with pytest.raises(KeyboardInterrupt) as caught:
        if allocation == "security":
            with backend._security():
                pytest.fail("unreachable")
        elif allocation == "sid":
            backend._sid_string(1)
        else:
            backend._current_sid()
    assert caught.value is primary
    assert freed == [71]
    assert len(cleanup_errors(primary)) == 1


@pytest.mark.parametrize("failure_point", ["proof", "security-exit"])
def test_native_open_owns_handle_before_security_context_exits(
    backend, monkeypatch, failure_point,
):
    primary = KeyboardInterrupt("private-primary")
    closed = []

    @contextmanager
    def security():
        yield platform._SecurityAttributes()
        if failure_point == "security-exit":
            raise primary

    def proof(*args):
        raise primary

    def close(handle):
        closed.append(handle)
        raise SystemExit("private-secondary")

    monkeypatch.setattr(backend, "_security", security)
    monkeypatch.setattr(backend, "prove", proof)
    backend.kernel = SimpleNamespace(CreateFileW=lambda *args: 71, CloseHandle=close)
    with pytest.raises(KeyboardInterrupt) as caught:
        backend._open(Path("member"), False, create=True)
    assert caught.value is primary
    assert closed == [71]
    assert len(cleanup_errors(primary)) == 1
    assert not backend._paths


def test_completed_native_rename_is_not_retried_after_close_failure(backend, monkeypatch):
    effects = []

    def mutate(*args):
        effects.append("committed")
        return 1

    def close(handle):
        raise RuntimeError("private-secondary")

    monkeypatch.setattr(backend, "path", lambda parent, name: Path(name))
    monkeypatch.setattr(backend, "_open", lambda *args, **kwargs: 71)
    backend.kernel = SimpleNamespace(
        SetFileInformationByHandle=mutate, GetFileAttributesW=lambda path: 0,
        CloseHandle=close,
    )
    with pytest.raises(StorageCleanupError) as caught:
        backend.rename(1, "source", "dest", True)
    assert effects == ["committed"]
    assert len(cleanup_errors(caught.value)) == 1


def test_complete_store_preserves_committed_pointer_after_native_close_fault(
    backend, local_memory, monkeypatch,
):
    fs = artifacts.LocalProtectedFilesystem()
    store = artifacts.ArtifactStore(fs, Clock(), Events())
    effect = binding("selected-root")
    intent = OutputIntent(("text",), "selected-root", overwrite="replace")
    prior = store.publish(intent, b"prior", effect)
    pointer = "publication-" + digest(effect) + ".json"
    memory_rename = platform.rename
    effects = []

    def close(handle):
        raise RuntimeError("private-secondary")

    def committed(*args):
        parent, source, dest, replace = effects[-1]
        memory_rename(parent, source, dest, replace)
        return 1

    def rename(parent, source, dest, replace=False):
        if dest == pointer:
            effects.append((parent, source, dest, replace))
            backend.rename(parent, source, dest, replace)
        else:
            memory_rename(parent, source, dest, replace)

    monkeypatch.setattr(backend, "path", lambda parent, name: Path(name))
    monkeypatch.setattr(backend, "_open", lambda *args, **kwargs: 71)
    backend.kernel = SimpleNamespace(
        SetFileInformationByHandle=committed, GetFileAttributesW=lambda path: 0,
        CloseHandle=close,
    )
    monkeypatch.setattr(platform, "rename", rename)
    with pytest.raises(artifacts.ArtifactError) as caught:
        store.publish(intent, b"replacement", effect)
    assert len(effects) == 1
    assert len(cleanup_errors(caught.value)) == 1
    assert local_memory[1][pointer] != canonical_bytes(prior)
    assert fs.read(prior) == b"prior"
    replacements = [
        handle for name, handle in local_memory[1].items()
        if name.startswith("artifact-") and name != prior.owning_resource
    ]
    assert len(replacements) == 1
    assert local_memory[replacements[0]]["content"] == b"replacement"
    assert not any(name.startswith("pending-") for name in local_memory[1])


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit, RuntimeError])
def test_native_lock_attempts_every_owned_stream(backend, monkeypatch, primary_type):
    import msvcrt

    primary = primary_type("private-primary")
    closed = []
    next_fd = iter([81, 82, 83])

    @contextmanager
    def security():
        yield platform._SecurityAttributes()

    class Stream:
        def __init__(self, fd):
            self.fd = fd

        def close(self):
            closed.append(self.fd)
            raise SystemExit("private-secondary")

    monkeypatch.setattr(backend, "_security", security)
    monkeypatch.setattr(backend, "info", lambda fd: SimpleNamespace(st_dev=1, st_ino=2))
    monkeypatch.setattr(backend, "path", lambda parent, name: Path(name))
    monkeypatch.setattr(backend, "prove", lambda *args: None)
    monkeypatch.setattr(msvcrt, "open_osfhandle", lambda *args: next(next_fd))
    monkeypatch.setattr(msvcrt, "locking", lambda *args: None)
    monkeypatch.setattr(platform.os, "fdopen", lambda fd, *args, **kwargs: Stream(fd))
    backend.kernel = SimpleNamespace(CreateFileW=lambda *args: 71)
    with pytest.raises(BaseException) as caught, backend.lock(1, ("a", "b", "c"), 0.0):
        raise primary
    assert caught.value is primary
    assert closed == [83, 82, 81]
    assert not backend._locks.held
    assert len(cleanup_errors(primary)) == 3


def test_native_lock_fdopen_failure_releases_transferred_fd(backend, monkeypatch):
    import msvcrt

    primary = KeyboardInterrupt("private-primary")
    closed = []

    @contextmanager
    def security():
        yield platform._SecurityAttributes()

    def fdopen(*args, **kwargs):
        raise primary

    def close(fd):
        closed.append(fd)
        raise RuntimeError("private-secondary")

    monkeypatch.setattr(backend, "_security", security)
    monkeypatch.setattr(backend, "info", lambda fd: SimpleNamespace(st_dev=1, st_ino=2))
    monkeypatch.setattr(backend, "path", lambda parent, name: Path(name))
    monkeypatch.setattr(backend, "prove", lambda *args: None)
    monkeypatch.setattr(msvcrt, "open_osfhandle", lambda *args: 81)
    monkeypatch.setattr(platform.os, "fdopen", fdopen)
    monkeypatch.setattr(platform.os, "close", close)
    backend.kernel = SimpleNamespace(CreateFileW=lambda *args: 71)
    with pytest.raises(KeyboardInterrupt) as caught, backend.lock(1, ("a",), 0.0):
        pytest.fail("unreachable")
    assert caught.value is primary
    assert closed == [81]
    assert len(cleanup_errors(primary)) == 1


@pytest.mark.parametrize("operation", ["read", "write"])
def test_posix_stream_and_fd_cleanup_preserve_cancellation(monkeypatch, operation):
    primary = KeyboardInterrupt("private-primary")
    closed = []

    class Stream:
        def read(self, size):
            raise primary

        def write(self, content):
            raise primary

        def close(self):
            closed.append("stream")
            raise SystemExit("private-secondary")

    def close(fd):
        closed.append(fd)
        raise RuntimeError("private-secondary")

    monkeypatch.setattr(artifacts, "os", SimpleNamespace(
        name="posix", O_RDONLY=0, O_WRONLY=1, O_CREAT=2, O_EXCL=4,
        O_NOFOLLOW=8, O_NONBLOCK=16, open=lambda *args, **kwargs: 81,
        fdopen=lambda *args, **kwargs: Stream(), close=close,
    ))
    monkeypatch.setattr(artifacts, "_private", lambda *args: None)
    monkeypatch.setattr(platform, "info", lambda fd: SimpleNamespace(st_size=4))
    with pytest.raises(KeyboardInterrupt) as caught:
        if operation == "read":
            artifacts._read_file(1, "content")
        else:
            artifacts._write_file(1, "content", b"safe")
    assert caught.value is primary
    assert closed == ["stream", 81]
    assert len(cleanup_errors(primary)) == 2
