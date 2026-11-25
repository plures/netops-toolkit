"""Owned v1 metadata and CAS tests; injected memory I/O is not platform proof."""

from __future__ import annotations

import json
import os
import sys
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from pathlib import Path

import pytest

import netops.ansible.artifacts as artifacts
from netops.ansible.artifacts import (
    ArtifactError,
    LocalProtectedFilesystem,
    OwnedLock,
    OwnedRecord,
    OwnedState,
    ProtectedRoot,
    validate_member_path,
)
from netops.ansible.contracts import (
    MAX_SAFE_INT,
    ContractError,
    OutputIntent,
    PolicyIdentity,
    public_object,
)

OWNER = "1" * 64
IDENTITY = PolicyIdentity(
    "6d367fe673756dabaa6085bc6b5202debaaabe6f", "a" * 64, "a" * 64, "a" * 64,
    ("netops.companion.test",), "1",
)


@pytest.fixture(autouse=True)
def offline_native_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    """Native protection qualification requires a separately approved invocation."""
    if os.name == "nt" or sys.platform == "darwin":
        def unavailable() -> None:
            raise artifacts._failure(
                artifacts.ReasonCode.OUTPUT_REJECTED, artifacts.ErrorCategory.PLATFORM,
            )
        monkeypatch.setattr(artifacts, "_supported", unavailable)


def record(revision: int = 0, **changes: object) -> OwnedRecord:
    value = OwnedRecord(
        "active", "active", revision, 0, OWNER, "a" * 64, "1",
        public_object({
            "environment_id": "env-1", "prior_id": None, "content_digest": "b" * 64,
            "state_revision": revision,
        }),
        IDENTITY,
    )
    if len(changes) != 0:
        return replace(value, **changes)
    return value


@pytest.mark.parametrize("field", ["revision", "generation"])
@pytest.mark.parametrize("value", [-1, True, 1.0, MAX_SAFE_INT + 1, "1", None])
def test_restored_numeric_values_reject_before_hydration(field: str, value: object) -> None:
    payload = json.loads(record().to_bytes())
    payload[field] = value
    with pytest.raises(ArtifactError):
        OwnedRecord.from_bytes(json.dumps(payload).encode())


@pytest.mark.parametrize("change", [
    {"schema_version": "0.1"}, {"schema_version": "2.0"}, {"schema_version": "1.1"},
    {"ownership_token": "unknown"}, {"kind": "migration"}, {"unknown": "field"},
    {"payload": {"permit": "sentinel-private-authority"}},
    {"payload": {"password": "sentinel-secret"}},
])
def test_unknown_corrupt_and_private_metadata_is_not_adopted(change: dict[str, object]) -> None:
    payload = json.loads(record().to_bytes())
    payload.update(change)
    with pytest.raises(ArtifactError):
        OwnedRecord.from_bytes(json.dumps(payload).encode())


def test_duplicate_keys_and_large_metadata_reject() -> None:
    with pytest.raises(ArtifactError):
        OwnedRecord.from_bytes(b'{"revision":0,"revision":1}')
    with pytest.raises(ArtifactError):
        OwnedRecord.from_bytes(b" " * (1024 * 1024 + 1))


@pytest.fixture
def memory_state(monkeypatch: pytest.MonkeyPatch) -> tuple[OwnedState, dict[str, bytes]]:
    files: dict[str, bytes] = {}
    root = ProtectedRoot("memory-root", 0, 0, OutputIntent(("json",), "memory-root"), "fake-only")

    @contextmanager
    def opened(root: ProtectedRoot) -> Iterator[int]:
        yield 1

    def read(parent: int, name: str, limit: int = 1024 * 1024) -> bytes:
        if name not in files:
            raise FileNotFoundError()
        return files[name]

    def write(parent: int, name: str, content: bytes) -> None:
        if name in files:
            raise FileExistsError()
        files[name] = content

    def replace_file(parent: int, source: str, destination: str, replace: bool = False) -> None:
        files[destination] = files.pop(source)

    def unlink(parent: int, name: str, directory: bool = False) -> None:
        if name not in files:
            raise FileNotFoundError()
        del files[name]

    monkeypatch.setattr(artifacts, "_root", opened)
    monkeypatch.setattr(artifacts, "_read_file", read)
    monkeypatch.setattr(artifacts, "_write_file", write)
    monkeypatch.setattr(OwnedState, "lock", lambda *args: nullcontext())
    monkeypatch.setattr(artifacts.storage, "rename", replace_file)
    monkeypatch.setattr(artifacts.storage, "remove", unlink)
    monkeypatch.setattr(artifacts.storage, "sync", lambda fd: None)
    return OwnedState(root, OWNER), files


def test_v1_creation_cas_retained_revision_and_explicit_restore(
    memory_state: tuple[OwnedState, dict[str, bytes]],
) -> None:
    state, files = memory_state
    first = state.compare_replace("active", 0, record())
    assert first == state.read("active")
    second = replace(record(1), generation=1, payload=public_object({
        "environment_id": "env-2", "prior_id": "env-1", "content_digest": "c" * 64,
        "state_revision": 1,
    }))
    state.compare_replace("active", 0, second)
    assert state.retained("active", 0) == first
    before = dict(files)
    with pytest.raises(ArtifactError):
        state.compare_replace("active", 0, record(1))
    assert files == before
    restored = replace(state.retained("active", 0), revision=2, payload=public_object({
        "environment_id": "env-1", "prior_id": "env-2", "content_digest": "b" * 64,
        "state_revision": 2,
    }))
    state.compare_replace("active", 1, restored)
    assert state.read("active").generation == 0
    assert state.retained("active", 1) == second


def test_corrupt_owner_and_unknown_schema_never_repair_or_write(
    memory_state: tuple[OwnedState, dict[str, bytes]],
) -> None:
    state, files = memory_state
    state.compare_replace("active", 0, record())
    name = state._filename("active")
    for changed in ({"schema_version": "2.0"}, {"ownership_token": "2" * 64}):
        data = json.loads(record().to_bytes())
        data.update(changed)
        files[name] = json.dumps(data).encode()
        before = dict(files)
        with pytest.raises(ArtifactError):
            state.compare_replace("active", 0, record(1))
        assert files == before


def test_exhaustion_preserves_pointer_and_never_computes_max_plus_one(
    memory_state: tuple[OwnedState, dict[str, bytes]],
) -> None:
    state, files = memory_state
    files[state._filename("active")] = record(MAX_SAFE_INT).to_bytes()
    before = dict(files)
    with pytest.raises(ArtifactError):
        state.compare_replace("active", MAX_SAFE_INT, record(MAX_SAFE_INT))
    assert files == before
    with pytest.raises(ContractError):
        state.compare_replace("active", True, record())
    assert files == before


def test_native_state_and_lock_cell(tmp_path: Path) -> None:
    intent = OutputIntent(("json",), str(tmp_path))
    if os.name != "posix" or sys.platform == "darwin":
        with pytest.raises(ArtifactError):
            LocalProtectedFilesystem().validate(intent)
        return
    tmp_path.chmod(0o700)
    root = LocalProtectedFilesystem().validate(intent)
    state = OwnedState(root, OWNER)
    state.compare_replace("active", 0, record())
    with OwnedLock(root, ("target-route",), 0.0):
        with OwnedLock(root, ("target-route",), 0.0):
            assert state.read("active").revision == 0

        def contend() -> str:
            with pytest.raises(ArtifactError) as caught:
                with OwnedLock(root, ("target-route",), 0.0):
                    pytest.fail("Another thread must not enter the OS lock")
            return caught.value.error.reason.value

        with ThreadPoolExecutor(max_workers=1) as executor:
            assert executor.submit(contend).result(timeout=2) == "resource-busy"
    with OwnedLock(root, ("target-route",), 0.0):
        assert state.read("active").revision == 0


@pytest.mark.parametrize("path", [
    "../escape", "/absolute", "a/../b", "a//b", "C:\\escape", "\\\\server\\share",
    "https://example.invalid/x", "a:stream", "a/CON.txt", "a/aux", "a/trailing.", "",
])
def test_hostile_archive_and_manifest_members_fail_closed(path: str) -> None:
    with pytest.raises(ArtifactError):
        validate_member_path(path)


def test_cancel_before_atomic_replace_preserves_original_pointer_and_owned_cleanup(
    memory_state: tuple[OwnedState, dict[str, bytes]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, files = memory_state
    state.compare_replace("active", 0, record())
    old = state.read("active").to_bytes()
    replacement = replace(record(1), payload=public_object({
        "environment_id": "env-2", "prior_id": "env-1", "content_digest": "c" * 64,
        "state_revision": 1,
    }))

    def cancelled(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt()

    monkeypatch.setattr(artifacts.storage, "rename", cancelled)
    with pytest.raises(KeyboardInterrupt):
        state.compare_replace("active", 0, replacement)
    assert state.read("active").to_bytes() == old
    assert state.retained("active", 0).to_bytes() == old
    assert not any(name.startswith("pending-") for name in files)


def test_wrong_prior_pointer_and_corrupt_retained_revision_are_not_repaired(
    memory_state: tuple[OwnedState, dict[str, bytes]],
) -> None:
    state, files = memory_state
    state.compare_replace("active", 0, record())
    before = dict(files)
    with pytest.raises(ArtifactError):
        state.compare_replace("active", 0, record(1))
    assert files == before
    files[state._filename("active") + ".r0"] = b"corrupt"
    with pytest.raises(ArtifactError):
        state.compare_replace("active", 0, replace(record(1), payload=public_object({
            "environment_id": "env-2", "prior_id": "env-1", "content_digest": "c" * 64,
            "state_revision": 1,
        })))
    assert state.read("active").revision == 0


@pytest.mark.parametrize("field,value", [
    ("policy_identity", None), ("reducer_version", "other"), ("policy_digest", "b" * 64),
    ("payload", {"environment_id": "env", "content_digest": "b" * 64, "prior_id": None}),
])
def test_checkpoint_policy_and_reducer_identity_are_bound(field: str, value: object) -> None:
    data = json.loads(record().to_bytes())
    data[field] = value
    with pytest.raises(ArtifactError):
        OwnedRecord.from_bytes(json.dumps(data).encode())


def test_native_two_writer_cas_cell(tmp_path: Path) -> None:
    intent = OutputIntent(("json",), str(tmp_path))
    if os.name != "posix" or sys.platform == "darwin":
        with pytest.raises(ArtifactError):
            LocalProtectedFilesystem().validate(intent)
        return
    tmp_path.chmod(0o700)
    root = LocalProtectedFilesystem().validate(intent)
    state = OwnedState(root, OWNER)
    state.compare_replace("active", 0, record())
    barrier = threading.Barrier(2)

    def writer(environment: str) -> str:
        proposed = replace(record(1), payload=public_object({
            "environment_id": environment, "prior_id": "env-1", "content_digest": "c" * 64,
            "state_revision": 1,
        }))
        barrier.wait(timeout=2)
        try:
            state.compare_replace("active", 0, proposed)
            return "succeeded"
        except ArtifactError:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(writer, environment) for environment in ("env-2", "env-3")]
        results = [future.result(timeout=3) for future in futures]
    assert sorted(results) == ["conflict", "succeeded"]
    assert state.read("active").revision == 1
    assert state.retained("active", 0).payload["environment_id"] == "env-1"


def test_install_manifests_and_operation_chunks_are_integrity_bound_v1_metadata() -> None:
    install = replace(record(), resource_id="installs/env-1", kind="install", payload=public_object({
        "manifest": [{"path": "managed/file", "kind": "file", "digest": "b" * 64}],
        "plan_digest": "a" * 64, "controller_digest": "b" * 64, "registry_digest": "c" * 64,
        "steps": {}, "original_errors": [], "pending_actions": [], "previous_id": None,
    }))
    assert OwnedRecord.from_bytes(install.to_bytes()) == install
    data = json.loads(install.to_bytes())
    data["payload"]["manifest"][0]["path"] = "../unowned"
    with pytest.raises(ArtifactError):
        OwnedRecord.from_bytes(json.dumps(data).encode())
    operation = replace(
        record(), resource_id="operations/ebd792c8-4086-4220-8d55-f79190cf8878", kind="operation",
        payload=public_object({
            "request": {}, "plan": {}, "outcome": {}, "provenance": {}, "artifacts": [],
            "primary_errors": [], "cleanup_errors": [],
            "chunks": [{"ref": "chunks/chunk-1", "digest": "b" * 64, "size": 20}],
            "diagnostic_ttl_days": 7,
        }),
    )
    assert OwnedRecord.from_bytes(operation.to_bytes()) == operation
    for ttl in (0, 366, True, 1.0):
        data = json.loads(operation.to_bytes())
        data["payload"]["diagnostic_ttl_days"] = ttl
        with pytest.raises(ArtifactError):
            OwnedRecord.from_bytes(json.dumps(data).encode())
