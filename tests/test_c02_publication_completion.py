"""C02 offline algorithm fixtures, never native platform qualification."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import logging
import sys
import threading
import time
import zlib
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest

from netops.ansible import artifact_platform as platform
from netops.ansible import artifacts
from netops.ansible.artifact_git import snapshot_files
from netops.ansible.artifacts import ArtifactError, ArtifactStore
from netops.ansible.contracts import OutputIntent
from tests.test_artifact_store import Clock, Events, MemoryFilesystem, binding


def test_binary_public_pdf_preserves_bytes_and_checks_known_credentials() -> None:
    fs = MemoryFilesystem()
    store = ArtifactStore(fs, Clock(), Events())
    intent = OutputIntent(("pdf",), "selected-root")
    content = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
    selected = binding("selected-root")
    descriptor = store.publish(intent, content, selected)
    assert store.read(descriptor, selected) == content
    before = fs.calls
    with pytest.raises(ArtifactError):
        store.publish(intent, content.replace(b"<<>>", b"(password sentinel-value)"), selected)
    assert fs.calls == before


def test_publication_and_cleanup_have_paired_safe_observations(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = ArtifactStore(MemoryFilesystem(), Clock(), Events())
    selected = binding("selected-root")
    with caplog.at_level(logging.INFO):
        store.publish(OutputIntent(("text",), "selected-root"), b"safe", selected)
        store.cleanup(())
    records = {record.msg: record for record in caplog.records}
    published = records["artifact.publish"]
    cleaned = records["cleanup.result"]
    assert published.metric == "netops.artifact.publish.count"
    assert cleaned.metric == "netops.cleanup.result.count"
    assert published.operation_id == selected.effect.plan.operation_id
    for dimensions in (published.metric_dimensions, cleaned.metric_dimensions):
        assert not any(key.endswith("_id") for key in dimensions)
    assert sum(row[-1] for row in store.observations.counters()) == 2


@pytest.mark.parametrize("key", [
    "authPassword", "auth_passphrase", "PRIV-PASSWORD", "privPassphrase",
    "sharedSecret", "readCommunity", "ansibleSshPass", "jumpUsername",
])
def test_text_credentials_use_the_structured_key_domain(key: str) -> None:
    fs = MemoryFilesystem()
    store = ArtifactStore(fs, Clock(), Events())
    with pytest.raises(ArtifactError):
        store.publish(
            OutputIntent(("yaml",), "selected-root"),
            f"{key}: synthetic-regression-value\n".encode(), binding("selected-root"),
        )
    assert fs.calls == 0


def test_structured_public_metadata_still_publishes() -> None:
    store = ArtifactStore(MemoryFilesystem(), Clock(), Events())
    store.publish(
        OutputIntent(("json",), "selected-root"),
        b'{"summary":{"status":"safe"}}', binding("selected-root"),
    )


def test_throwing_log_handler_preserves_effect_and_cleanup_without_recounting() -> None:
    class BrokenHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            raise RuntimeError("synthetic-private-log-value")

    logger = logging.getLogger("netops.ansible.artifact_observations")
    handler = BrokenHandler()
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    store = ArtifactStore(MemoryFilesystem(), Clock(), Events())
    selected = binding("selected-root")
    try:
        descriptor = store.publish(
            OutputIntent(("text",), "selected-root"), b"safe", selected,
        )
        assert store.read(descriptor, selected) == b"safe"
        store.cleanup(())
        assert sum(row[-1] for row in store.observations.counters()) == 2
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


def test_windows_owned_lock_pins_checked_root_until_native_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    @contextmanager
    def selected_root(root: artifacts.ProtectedRoot) -> Iterator[int]:
        events.append("root-open")
        try:
            yield 41
        finally:
            events.append("root-close")

    @contextmanager
    def native_lock(parent: int, names: tuple[str, ...], timeout: float) -> Iterator[None]:
        assert parent == 41
        events.append("lock-open")
        try:
            yield
        finally:
            events.append("lock-close")

    monkeypatch.setattr(artifacts, "_supported", lambda: None)
    monkeypatch.setattr(artifacts, "_root", selected_root)
    monkeypatch.setattr(artifacts, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(platform, "windows", lambda: SimpleNamespace(lock=native_lock))
    root = artifacts.ProtectedRoot(
        "selected-root", 1, 41, OutputIntent(("text",), "selected-root"), "fixture",
    )
    with artifacts.OwnedLock(root, ("target-route",), 0.0):
        assert events == ["root-open", "lock-open"]
    assert events == ["root-open", "lock-open", "lock-close", "root-close"]


@pytest.fixture
def local_memory(monkeypatch: pytest.MonkeyPatch) -> dict[int, dict[str, object]]:
    """Exercise the real publication/CAS algorithm, substituting only OS primitives."""
    directories: dict[int, dict[str, object]] = {1: {}}

    @contextmanager
    def directory(path: str) -> Iterator[int]:
        yield 1

    def mkdir(parent: int, name: str) -> None:
        if name in directories[parent]:
            raise FileExistsError()
        handle = max(directories) + 1
        directories[handle] = {}
        directories[parent][name] = handle

    def opened(parent: int, name: str) -> int:
        item = directories[parent].get(name)
        if not isinstance(item, int):
            raise FileNotFoundError()
        return item

    def read(parent: int, name: str, limit: int = 1024 * 1024) -> bytes:
        item = directories[parent].get(name)
        if item is None:
            raise FileNotFoundError()
        if not isinstance(item, bytes) or len(item) > limit:
            raise OSError()
        return item

    def write(parent: int, name: str, value: bytes) -> None:
        if name in directories[parent]:
            raise FileExistsError()
        directories[parent][name] = value

    def rename(parent: int, source: str, dest: str, replace: bool = False) -> None:
        if dest in directories[parent] and not replace:
            raise FileExistsError()
        directories[parent][dest] = directories[parent].pop(source)

    def remove(parent: int, name: str, directory: bool = False) -> None:
        if name not in directories[parent]:
            raise FileNotFoundError()
        item = directories[parent][name]
        if directory and isinstance(item, int) and directories[item]:
            raise OSError()
        del directories[parent][name]

    monkeypatch.setattr(artifacts, "_directory", directory)
    monkeypatch.setattr(artifacts, "_supported", lambda: None)
    monkeypatch.setattr(artifacts, "_private", lambda *_: None)
    monkeypatch.setattr(artifacts, "_read_file", read)
    monkeypatch.setattr(artifacts, "_write_file", write)
    monkeypatch.setattr(artifacts.OwnedLock, "__enter__", lambda self: self)
    monkeypatch.setattr(artifacts.storage, "info", lambda fd: SimpleNamespace(st_dev=1, st_ino=fd))
    monkeypatch.setattr(artifacts.storage, "mkdir", mkdir)
    monkeypatch.setattr(artifacts.storage, "open_directory", opened)
    monkeypatch.setattr(artifacts.storage, "close", lambda *_: None)
    monkeypatch.setattr(artifacts.storage, "sync", lambda *_: None)
    monkeypatch.setattr(artifacts.storage, "rename", rename)
    monkeypatch.setattr(artifacts.storage, "remove", remove)
    monkeypatch.setattr(artifacts.storage, "names", lambda fd: list(directories[fd]))
    return directories


@pytest.mark.parametrize("pointer", [False, True])
def test_publication_retains_secondary_failure_for_unexpected_error_and_cancellation(
    local_memory: dict[int, dict[str, object]], monkeypatch: pytest.MonkeyPatch,
    pointer: bool,
) -> None:
    fs = artifacts.LocalProtectedFilesystem()
    store = ArtifactStore(fs, Clock(), Events())
    original = artifacts._write_file
    primary = KeyboardInterrupt("synthetic-cancel") if pointer else RuntimeError("synthetic-write")

    def write(parent: int, name: str, content: bytes) -> None:
        if not pointer or (parent == 1 and name.startswith("pending-")):
            raise primary
        original(parent, name, content)

    def remove(*args: object) -> None:
        raise OSError("synthetic-cleanup")

    monkeypatch.setattr(artifacts, "_write_file", write)
    if pointer:
        monkeypatch.setattr(artifacts.storage, "remove", remove)
    else:
        monkeypatch.setattr(fs, "_remove_pending", remove)
    with pytest.raises(KeyboardInterrupt if pointer else ArtifactError) as caught:
        store.publish(
            OutputIntent(("text",), "selected-root"), b"safe", binding("selected-root"),
        )
    assert len(caught.value.cleanup_errors) == 1
    assert caught.value.cleanup_errors[0].category.value == "cleanup"
    if pointer:
        assert caught.value is primary
    else:
        assert "synthetic-write" not in repr(caught.value)


@pytest.mark.parametrize("git", [False, True])
def test_selected_git_replace_and_manifest_only_cleanup(
    local_memory: dict[int, dict[str, object]], git: bool,
) -> None:
    fs = artifacts.LocalProtectedFilesystem()
    store = ArtifactStore(fs, Clock(), Events())
    selected = binding("selected-root")
    intent = OutputIntent(("text",), "selected-root", git=git)
    first = store.publish(intent, b"first", selected)
    with pytest.raises(ArtifactError):
        store.publish(intent, b"second", selected)
    root = fs.validate(replace(intent, overwrite="replace"))
    second = store.publish(root.intent, b"second", selected)
    assert first.ref != second.ref
    assert store.read(first, selected) == b"first"
    assert store.read(second, selected) == b"second"
    first_dir = local_memory[1][first.owning_resource]
    assert isinstance(first_dir, int)
    assert ("git" in local_memory[first_dir]) is git
    assert store.cleanup((artifacts.OwnedResource(first, root, True),)).status == "succeeded"
    assert store.read(second, selected) == b"second"
    assert store.cleanup((artifacts.OwnedResource(second, root, True),)).status == "succeeded"
    assert local_memory[1] == {}


def test_git_objects_are_integrity_bound_and_have_no_external_effects() -> None:
    files = snapshot_files(b"exact\r\nsnapshot", b"receipt")
    for path, compressed in files.items():
        if path.startswith("objects/"):
            raw = zlib.decompress(compressed)
            assert hashlib.sha1(raw).hexdigest() == path.replace("objects/", "").replace("/", "")
    commit_id = files["refs/heads/artifacts"].strip().decode()
    commit = zlib.decompress(files["objects/" + commit_id[:2] + "/" + commit_id[2:]])
    assert b"tree " in commit
    assert b"parent " not in commit
    assert b"remote" not in files["config"]


def test_pointer_commit_failure_preserves_prior_publication(
    local_memory: dict[int, dict[str, object]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    fs = artifacts.LocalProtectedFilesystem()
    store = ArtifactStore(fs, Clock(), Events())
    selected = binding("selected-root")
    intent = OutputIntent(("text",), "selected-root", overwrite="replace")
    first = store.publish(intent, b"first", selected)
    pointer = "publication-" + first.input_binding + ".json"
    prior = local_memory[1][pointer]
    original = artifacts.storage.rename

    def failed(parent: int, source: str, dest: str, replace: bool = False) -> None:
        if dest.startswith("publication-"):
            raise OSError("sentinel-private-path")
        original(parent, source, dest, replace)

    monkeypatch.setattr(artifacts.storage, "rename", failed)
    with pytest.raises(ArtifactError):
        store.publish(intent, b"second", selected)
    assert local_memory[1][pointer] == prior
    assert store.read(first, selected) == b"first"


def test_unknown_git_member_is_preserved_with_separate_cleanup_error(
    local_memory: dict[int, dict[str, object]],
) -> None:
    fs = artifacts.LocalProtectedFilesystem()
    intent = OutputIntent(("text",), "selected-root", git=True)
    root = fs.validate(intent)
    store = ArtifactStore(fs, Clock(), Events())
    descriptor = store.publish(intent, b"safe", binding("selected-root"))
    artifact = local_memory[1][descriptor.owning_resource]
    assert isinstance(artifact, int)
    git = local_memory[artifact]["git"]
    assert isinstance(git, int)
    local_memory[git]["user-file"] = b"preserve"
    outcome = store.cleanup((artifacts.OwnedResource(descriptor, root, True),))
    assert outcome.status == "failed"
    assert outcome.errors[0].category.value == "cleanup"
    assert local_memory[git]["user-file"] == b"preserve"
    assert local_memory[artifact]["content"] == b"safe"


@pytest.mark.parametrize("acl_result,acl_errno,valid,allowed", [
    (-1, errno.EINVAL, 0, True), (0, 0, 0, False),
    (-1, errno.EIO, 0, False), (-1, errno.EINVAL, -1, False),
])
def test_macos_acl_enforcement_uses_darwin_entry_semantics(
    monkeypatch: pytest.MonkeyPatch, acl_result: int, acl_errno: int,
    valid: int, allowed: bool,
) -> None:
    class Function:
        def __init__(self, value: int, entry: bool = False) -> None:
            self.value, self.entry = value, entry

        def __call__(self, *args: object) -> int:
            if self.entry:
                ctypes.set_errno(acl_errno)
            return self.value

    freed: list[object] = []
    libc = SimpleNamespace(
        acl_get_fd_np=Function(123), acl_get_entry=Function(acl_result, True),
        acl_valid=Function(valid), acl_free=Function(0),
    )
    libc.acl_free = lambda value: freed.append(value)
    monkeypatch.setattr(platform.ctypes, "CDLL", lambda *args, **kwargs: libc)
    if allowed:
        platform.macos_acl(17)
    else:
        with pytest.raises(OSError):
            platform.macos_acl(17)
    assert freed == [123]


@pytest.mark.parametrize("defect", [
    "none", "foreign-owner", "foreign-ace", "inherit-only", "unprotected",
    "null-dacl", "reparse", "hardlink", "insufficient-rights",
])
def test_windows_owner_acl_and_handle_checks_are_not_trust_flags(
    defect: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = platform.WindowsHandles.__new__(platform.WindowsHandles)
    ace = ctypes.create_string_buffer(32)
    ace[0] = 0
    ace[1] = 8 if defect == "inherit-only" else 0
    ctypes.c_uint32.from_buffer(ace, 4).value = (
        1 if defect == "insufficient-rights" else 0x1F01FF
    )
    address = ctypes.addressof(ace)
    freed: list[object] = []

    def file_info(handle: int, pointer: object) -> int:
        value = pointer._obj
        value.attributes = 0x400 if defect == "reparse" else 0
        value.links = 2 if defect == "hardlink" else 1
        return 1

    def security(
        handle: int, kind: int, flags: int, owner: object, group: object,
        dacl: object, sacl: object, descriptor: object,
    ) -> int:
        owner._obj.value = 101
        dacl._obj.value = None if defect == "null-dacl" else 102
        descriptor._obj.value = 103
        return 0

    def control(descriptor: object, output: object, revision: object) -> int:
        output._obj.value = 0 if defect == "unprotected" else 0x1000
        return 1

    def acl_info(acl: object, output: object, size: int, kind: int) -> int:
        output._obj.count = 1
        return 1

    def get_ace(acl: object, index: int, output: object) -> int:
        output._obj.value = address
        return 1

    def sid_string(sid: object) -> str:
        value = sid.value if isinstance(sid, ctypes.c_void_p) else sid
        if (value == 101 and defect == "foreign-owner") or (
            value == address + 8 and defect == "foreign-ace"
        ):
            return "foreign-user"
        return "current-user"

    native.sid = "current-user"
    native.kernel = SimpleNamespace(GetFileInformationByHandle=file_info, LocalFree=freed.append)
    native.advapi = SimpleNamespace(
        GetSecurityInfo=security, GetSecurityDescriptorControl=control,
        GetAclInformation=acl_info, GetAce=get_ace,
    )
    monkeypatch.setattr(native, "_sid_string", sid_string)
    if defect == "none":
        assert native.prove(17, False).links == 1
    else:
        with pytest.raises(OSError):
            native.prove(17, False)
    if defect not in ("reparse", "hardlink"):
        assert len(freed) == 1


def test_windows_protection_failure_precedes_sensitive_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = platform.WindowsHandles.__new__(platform.WindowsHandles)
    writes: list[object] = []
    closed: list[object] = []
    native.kernel = SimpleNamespace(
        CreateFileW=lambda *args: 123, CloseHandle=closed.append,
        WriteFile=lambda *args: writes.append(args),
    )
    native._paths = {}
    native._mutex = threading.RLock()

    @contextmanager
    def security() -> Iterator[platform._SecurityAttributes]:
        yield platform._SecurityAttributes()

    def deny(handle: int, directory: bool) -> None:
        raise OSError("protected-storage-owner")

    monkeypatch.setattr(native, "_security", security)
    monkeypatch.setattr(native, "path", lambda *args: artifacts.Path("owned-content"))
    monkeypatch.setattr(native, "prove", deny)
    with pytest.raises(OSError):
        native.write(1, "content", b"password sentinel-value")
    assert writes == []
    assert closed == [123]


@pytest.mark.skipif(sys.platform != "win32", reason="Real FILE_RENAME_INFO requires Windows")
@pytest.mark.parametrize("replace_existing", [False, True])
def test_windows_rename_and_delete_use_the_verified_native_handle(
    monkeypatch: pytest.MonkeyPatch, tmp_path, replace_existing,
) -> None:
    native = platform.WindowsHandles()
    root = tmp_path / "task-owned-publication"
    with native._security() as security:
        assert native.kernel.CreateDirectoryW(str(root), ctypes.byref(security))
    closed: list[int] = []
    calls: list[tuple[int, int, object]] = []
    real_set = native.kernel.SetFileInformationByHandle
    real_close = native.close
    real_open = native._open

    def set_info(handle: int, kind: int, pointer: object, size: int) -> int:
        value = pointer._obj
        if kind == 3:
            encoded = str(root / "publication-\N{GREEK SMALL LETTER OMEGA}.json").encode("utf-16-le")
            assert value.parent is None
            assert value.length == len(encoded)
            assert size == ctypes.sizeof(value)
            assert ctypes.string_at(
                ctypes.addressof(value) + type(value).name.offset, value.length,
            ) == encoded
            calls.append((handle, kind, (value.parent, encoded, value.replace)))
        else:
            assert kind == 4 and size == 1
            calls.append((handle, kind, value.value))
        return real_set(handle, kind, pointer, size)

    def close(handle: int) -> None:
        closed.append(handle)
        real_close(handle)

    def opened(path: object, directory: bool, **kwargs: object) -> int:
        assert kwargs["delete"] is True
        assert path.parent == root and not directory
        handle = real_open(path, directory, **kwargs)
        assert native.prove(handle, False).links == 1
        return handle

    try:
        with native.directory(str(root)) as parent:
            identity = native.info(parent)
            native.write(parent, "pending", b"exact publication bytes")
            monkeypatch.setattr(native.kernel, "SetFileInformationByHandle", set_info)
            monkeypatch.setattr(native, "close", close)
            monkeypatch.setattr(native, "_open", opened)
            native.rename(
                parent, "pending", "publication-\N{GREEK SMALL LETTER OMEGA}.json", replace_existing,
            )
            native.remove(parent, "publication-\N{GREEK SMALL LETTER OMEGA}.json")
            assert [row[1] for row in calls] == [3, 4]
            assert calls[0][2][2] == int(replace_existing) and calls[1][2] == 1
            assert closed == [row[0] for row in calls]
            assert parent not in closed
            assert native.info(parent) == identity and native.names(parent) == []
            monkeypatch.setattr(native, "_open", real_open)
    finally:
        monkeypatch.setattr(native, "_open", real_open)
        root.rmdir()


@pytest.mark.skipif(sys.platform != "win32", reason="Real pinned Windows parent and DACL guards")
def test_windows_native_rename_retains_all_protected_parent_and_member_guards(tmp_path):
    native = platform.WindowsHandles()
    root = tmp_path / "task-owned-rename-guards"
    with native._security() as security:
        assert native.kernel.CreateDirectoryW(str(root), ctypes.byref(security))
    pending, destination = root / "pending", root / "publication.json"
    alias = root / "hardlink"
    try:
        with native.directory(str(root)) as parent:
            native.write(parent, pending.name, b"source bytes")
            native.write(parent, destination.name, b"existing bytes")
            for name in ("..\\escape", str(tmp_path / "foreign.json"), "publication.json:ads",
                         ".", "..", "publication."):
                with pytest.raises(OSError, match="protected-storage-member"):
                    native.rename(parent, pending.name, name, True)
                with pytest.raises(OSError, match="protected-storage-member"):
                    native.rename(parent, name, destination.name, True)
            with pytest.raises(OSError):
                root.rename(tmp_path / "renamed-parent")
            with pytest.raises(OSError):
                native.rename(parent, pending.name, destination.name, False)
            assert native.read(parent, pending.name, 64) == b"source bytes"
            assert native.read(parent, destination.name, 64) == b"existing bytes"
            import os

            os.link(pending, alias)
            with pytest.raises(OSError):
                native.rename(parent, pending.name, destination.name, True)
            assert destination.read_bytes() == b"existing bytes"
            alias.unlink()
            assert native.prove(parent, True).links == 1
        with pytest.raises(OSError):
            native.rename(parent, pending.name, destination.name, True)
        assert pending.read_bytes() == b"source bytes"
        assert destination.read_bytes() == b"existing bytes"
    finally:
        for path in (alias, pending, destination):
            path.unlink(missing_ok=True)
        root.rmdir()


def test_failed_event_sink_cannot_hide_primary_failure_or_double_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class BrokenEvents:
        def emit(self, event: object) -> None:
            raise RuntimeError("sentinel-private-message")

    store = ArtifactStore(MemoryFilesystem(), Clock(), BrokenEvents())
    with caplog.at_level(logging.INFO), pytest.raises(ArtifactError) as caught:
        store.publish(
            OutputIntent(("text",), "selected-root"), b"password sentinel-value",
            binding("selected-root"),
        )
    assert caught.value.error.category.value == "precondition"
    records = [row for row in caplog.records if row.msg == "artifact.publish"]
    assert len(records) == 1
    assert records[0].reason == "output-rejected"
    assert records[0].error_category == "precondition"
    assert "sentinel" not in repr(records[0].__dict__)
    assert sum(row[-1] for row in store.observations.counters()) == 1


def test_pdf_compressed_known_credentials_reject_before_io() -> None:
    fs = MemoryFilesystem()
    store = ArtifactStore(fs, Clock(), Events())
    compressed = zlib.compress(b"password sentinel-value")
    content = b"%PDF-1.7\nstream\n" + compressed + b"\nendstream\n%%EOF\n"
    with pytest.raises(ArtifactError):
        store.publish(OutputIntent(("pdf",), "selected-root"), content, binding("selected-root"))
    assert fs.calls == 0


def test_cancel_with_failed_staging_cleanup_keeps_primary_and_secondary(
    local_memory: dict[int, dict[str, object]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    fs = artifacts.LocalProtectedFilesystem()
    intent = OutputIntent(("text",), "selected-root")
    root = fs.validate(intent)

    def cancel(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt()

    def cleanup_failure(*args: object) -> None:
        raise OSError("sentinel-private-path")

    monkeypatch.setattr(artifacts.storage, "rename", cancel)
    monkeypatch.setattr(fs, "_remove_pending", cleanup_failure)
    with pytest.raises(KeyboardInterrupt) as caught:
        fs.publish(root, b"safe", binding("selected-root"))
    assert caught.value.cleanup_errors[0].category.value == "cleanup"
    assert "sentinel" not in repr(caught.value.cleanup_errors)


def test_selected_git_corruption_is_failure_not_publication_downgrade(
    local_memory: dict[int, dict[str, object]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    fs = artifacts.LocalProtectedFilesystem()
    store = ArtifactStore(fs, Clock(), Events())
    intent = OutputIntent(("text",), "selected-root", git=True)
    original = artifacts._write_file

    def corrupt(parent: int, name: str, content: bytes) -> None:
        original(parent, name, b"wrong-git-head" if name == "HEAD" else content)

    monkeypatch.setattr(artifacts, "_write_file", corrupt)
    with pytest.raises(ArtifactError) as caught:
        store.publish(intent, b"safe", binding("selected-root"))
    assert caught.value.error.reason.value == "ownership-invalid"
    assert caught.value.cleanup_errors[0].category.value == "cleanup"
    assert not any(name.startswith("publication-") for name in local_memory[1])


def test_corrupt_pointer_cannot_be_authorized_by_replace_selection(
    local_memory: dict[int, dict[str, object]],
) -> None:
    fs = artifacts.LocalProtectedFilesystem()
    store = ArtifactStore(fs, Clock(), Events())
    selected = binding("selected-root")
    intent = OutputIntent(("text",), "selected-root", overwrite="replace")
    descriptor = store.publish(intent, b"first", selected)
    pointer = "publication-" + descriptor.input_binding + ".json"
    original = local_memory[1][pointer]
    assert isinstance(original, bytes)
    local_memory[1][pointer] = original[:-1] + b',"unknown":"preserve"}'
    before = dict(local_memory[1])
    with pytest.raises(ArtifactError):
        store.publish(intent, b"second", selected)
    assert local_memory[1] == before
    assert store.read(descriptor, selected) == b"first"


@pytest.mark.parametrize("busy", [False, True])
def test_windows_native_lock_fixture_is_reentrant_bounded_and_releases(
    monkeypatch: pytest.MonkeyPatch, busy: bool,
) -> None:
    native = platform.WindowsHandles.__new__(platform.WindowsHandles)
    native._locks = threading.local()
    native._paths = {}
    native._mutex = threading.RLock()
    events: list[str] = []

    class Stream:
        def close(self) -> None:
            events.append("close")

    @contextmanager
    def directory(path: str) -> Iterator[int]:
        yield 17

    @contextmanager
    def security() -> Iterator[platform._SecurityAttributes]:
        yield platform._SecurityAttributes()

    def create(*args: object) -> int:
        assert args[4] == 4  # OPEN_ALWAYS with a protected creation descriptor.
        events.append("open")
        return 55

    def lock(fd: int, mode: int, count: int) -> None:
        events.append("lock")
        if busy:
            raise OSError()

    native.kernel = SimpleNamespace(CreateFileW=create, CloseHandle=lambda _: events.append("native-close"))
    monkeypatch.setattr(native, "directory", directory)
    monkeypatch.setattr(native, "_security", security)
    monkeypatch.setattr(native, "path", lambda *args: artifacts.Path("owned-lock"))
    monkeypatch.setattr(native, "prove", lambda *args: events.append("proof"))
    monkeypatch.setattr(native, "info", lambda _: SimpleNamespace(st_dev=1, st_ino=17))
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(
        open_osfhandle=lambda *args: 123, locking=lock, LK_NBLCK=1,
    ))
    monkeypatch.setattr(platform.os, "fdopen", lambda *args, **kwargs: Stream())
    monkeypatch.setattr(platform.os, "O_BINARY", 0, raising=False)
    if busy:
        with pytest.raises(BlockingIOError), native.lock(17, ("lock-a",), 0.0):
            pytest.fail("contended native lock was admitted")
    else:
        with native.lock(17, ("lock-a",), 0.0):
            with native.lock(17, ("lock-a",), 0.0):
                assert events == ["open", "proof", "lock"]
            assert events == ["open", "proof", "lock"]
    assert events == ["open", "proof", "lock", "close"]


def test_clock_failure_after_effect_is_safe_and_not_a_success_descriptor(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class BrokenClock(Clock):
        calls = 0

        def monotonic(self) -> float:
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError("sentinel-private-clock")
            return 0.0

    store = ArtifactStore(MemoryFilesystem(), BrokenClock(), Events())
    with caplog.at_level(logging.INFO), pytest.raises(ArtifactError) as caught:
        store.publish(
            OutputIntent(("text",), "selected-root"), b"safe", binding("selected-root"),
        )
    assert caught.value.error.category.value == "execution"
    assert "sentinel" not in repr(caught.value)
    record = next(row for row in caplog.records if row.msg == "artifact.publish")
    assert record.stage == "Unhandled"
    assert record.status == "failed"


def test_unexpected_cleanup_failure_is_separate_and_safe(
    local_memory: dict[int, dict[str, object]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    fs = artifacts.LocalProtectedFilesystem()
    store = ArtifactStore(fs, Clock(), Events())
    intent = OutputIntent(("text",), "selected-root")
    descriptor = store.publish(intent, b"safe", binding("selected-root"))
    root = fs.validate(intent)

    def broken(*args: object) -> bytes:
        raise RuntimeError("sentinel-private-cleanup")

    monkeypatch.setattr(fs, "read", broken)
    outcome = store.cleanup((artifacts.OwnedResource(descriptor, root, True),))
    assert outcome.status == "failed"
    assert outcome.remaining_refs == (descriptor.owning_resource,)
    assert "sentinel" not in repr(outcome)


def test_native_adapter_initialization_is_single_owner_under_concurrent_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[object] = []

    def constructor() -> object:
        instance = object()
        created.append(instance)
        time.sleep(0.02)
        return instance

    monkeypatch.setattr(platform, "_WINDOWS", None)
    monkeypatch.setattr(platform, "WindowsHandles", constructor)
    with ThreadPoolExecutor(max_workers=4) as pool:
        adapters = tuple(pool.map(lambda _: platform.windows(), range(4)))
    assert len(created) == 1
    assert all(adapter is adapters[0] for adapter in adapters)
