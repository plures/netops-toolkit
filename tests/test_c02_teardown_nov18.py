"""C02 teardown double-fault regressions using injected OS primitives only."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from netops.ansible import artifacts
from netops.ansible.contracts import OutputIntent
from tests import test_c02_publication_completion as completion
from tests import test_owned_state as owned
from tests.test_artifact_store import Clock, Events, binding

local_memory = completion.local_memory
memory_state = owned.memory_state


@pytest.mark.parametrize("secondary_type", [RuntimeError, KeyboardInterrupt, asyncio.CancelledError])
@pytest.mark.parametrize("boundary", ["generation", "pointer", "handle"])
def test_publication_teardown_preserves_primary_and_pending_uncertainty(
    local_memory: dict[int, dict[str, object]], monkeypatch: pytest.MonkeyPatch,
    secondary_type: type[BaseException], boundary: str,
) -> None:
    fs = artifacts.LocalProtectedFilesystem()
    store = artifacts.ArtifactStore(fs, Clock(), Events())
    primary = KeyboardInterrupt("private-primary-sentinel")
    original_write = artifacts._write_file

    def write(parent: int, name: str, content: bytes) -> None:
        if boundary != "pointer" or parent == 1:
            raise primary
        original_write(parent, name, content)

    def fail(*args: object) -> None:
        raise secondary_type("private-secondary-sentinel")

    monkeypatch.setattr(artifacts, "_write_file", write)
    if boundary == "generation":
        monkeypatch.setattr(fs, "_remove_pending", fail)
    elif boundary == "pointer":
        monkeypatch.setattr(artifacts.storage, "remove", fail)
    else:
        monkeypatch.setattr(artifacts.storage, "close", fail)
        monkeypatch.setattr(fs, "_remove_pending", lambda *_: None)
    with pytest.raises(BaseException) as caught:
        store.publish(OutputIntent(("text",), "selected-root"), b"safe", binding("selected-root"))
    assert caught.value is primary
    errors = artifacts._cleanup_errors(primary)
    assert len(errors) == 1
    assert errors[0].category.value == "cleanup"
    assert "sentinel" not in repr(errors)
    prefix = "artifact-" if boundary == "pointer" else "pending-"
    assert any(name.startswith(prefix) for name in local_memory[1])
    assert not any(name.startswith("publication-") for name in local_memory[1])


def test_sibling_teardowns_both_run_and_retain_safe_evidence(
    local_memory: dict[int, dict[str, object]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    fs = artifacts.LocalProtectedFilesystem()
    primary = asyncio.CancelledError("private-primary-sentinel")
    calls: list[str] = []

    def write(*args: object) -> None:
        raise primary

    def close(*args: object) -> None:
        calls.append("close")
        raise RuntimeError("private-close-sentinel")

    def remove(*args: object) -> None:
        calls.append("remove")
        raise KeyboardInterrupt("private-remove-sentinel")

    monkeypatch.setattr(artifacts, "_write_file", write)
    monkeypatch.setattr(artifacts.storage, "close", close)
    monkeypatch.setattr(fs, "_remove_pending", remove)
    with pytest.raises(BaseException) as caught:
        artifacts.ArtifactStore(fs, Clock(), Events()).publish(
            OutputIntent(("text",), "selected-root"), b"safe", binding("selected-root"),
        )
    assert caught.value is primary
    assert calls == ["close", "remove"]
    errors = artifacts._cleanup_errors(primary)
    assert len(errors) == 2
    assert "sentinel" not in repr(errors)
    assert len(local_memory[1]) == 1


@pytest.mark.parametrize("secondary_type", [RuntimeError, KeyboardInterrupt, asyncio.CancelledError])
def test_state_pending_teardown_preserves_primary_and_prior_revision(
    memory_state: tuple[artifacts.OwnedState, dict[str, bytes]], monkeypatch: pytest.MonkeyPatch,
    secondary_type: type[BaseException],
) -> None:
    state, files = memory_state
    first = state.compare_replace("active", 0, owned.record())
    previous = files["active.json"]
    primary = asyncio.CancelledError("private-primary-sentinel")

    def rename(*args: object, **kwargs: object) -> None:
        raise primary

    def remove(*args: object) -> None:
        raise secondary_type("private-secondary-sentinel")

    monkeypatch.setattr(artifacts.storage, "rename", rename)
    monkeypatch.setattr(artifacts.storage, "remove", remove)
    with pytest.raises(BaseException) as caught:
        state.compare_replace("active", 0, owned.record(revision=1, payload={
            "environment_id": "env-2", "prior_id": "env-1", "content_digest": "c" * 64,
            "state_revision": 1,
        }))
    assert caught.value is primary
    assert len(artifacts._cleanup_errors(primary)) == 1
    assert files["active.json"] == previous
    assert state.read("active") == first
    assert any(name.startswith("pending-") for name in files)
    assert "sentinel" not in repr(artifacts._cleanup_errors(primary))


@pytest.mark.parametrize("secondary_type", [RuntimeError, KeyboardInterrupt, asyncio.CancelledError])
def test_cleanup_without_primary_is_safe_and_does_not_swallow_cancellation(
    monkeypatch: pytest.MonkeyPatch, secondary_type: type[BaseException],
) -> None:
    secondary = secondary_type("private-secondary-sentinel")

    def remove(*args: object) -> None:
        raise secondary

    monkeypatch.setattr(artifacts.storage, "remove", remove)
    expected = artifacts.ArtifactError if secondary_type is RuntimeError else secondary_type
    with pytest.raises(expected) as caught:
        artifacts._remove_pending_file(1, "pending-owned")
    if secondary_type is RuntimeError:
        assert caught.value.error.category.value == "cleanup"
        assert "sentinel" not in repr(caught.value)
    else:
        assert caught.value is secondary
        assert len(artifacts._cleanup_errors(secondary)) == 1
        assert "sentinel" not in repr(artifacts._cleanup_errors(secondary))


@pytest.mark.parametrize("cancel", [False, True])
def test_sibling_handle_release_attempts_all_and_keeps_first_failure(
    monkeypatch: pytest.MonkeyPatch, cancel: bool,
) -> None:
    first = asyncio.CancelledError("private-first-sentinel") if cancel else RuntimeError(
        "private-first-sentinel",
    )
    calls: list[int] = []

    def close(handle: int) -> None:
        calls.append(handle)
        if handle == 2:
            raise first
        raise KeyboardInterrupt("private-second-sentinel")

    monkeypatch.setattr(artifacts.storage, "close", close)
    with pytest.raises(BaseException) as caught:
        artifacts._close_handles((1, 2))
    assert calls == [2, 1]
    if cancel:
        assert caught.value is first
        assert len(artifacts._cleanup_errors(first)) == 2
    else:
        assert isinstance(caught.value, artifacts.ArtifactError)
        assert caught.value.error.category.value == "cleanup"
        assert len(caught.value.cleanup_errors) == 1
        assert "sentinel" not in repr(caught.value)
    assert "sentinel" not in repr(artifacts._cleanup_errors(caught.value))


def test_lock_release_preserves_cancellation_and_attempts_every_owned_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = asyncio.CancelledError("private-primary-sentinel")
    calls: list[str] = []

    def close() -> None:
        calls.append("close")
        raise KeyboardInterrupt("private-secondary-sentinel")

    first = (1, 2, 3, "first")
    second = (1, 2, 3, "second")
    held = {first: (SimpleNamespace(close=close), 1), second: (SimpleNamespace(close=close), 1)}
    monkeypatch.setattr(artifacts._HELD_LOCKS, "values", held)
    root = artifacts.ProtectedRoot(
        "selected-root", 2, 3, OutputIntent(("text",), "selected-root"), "fixture",
    )
    lock = artifacts.OwnedLock(root, ("owned",), 0.0)
    lock._keys = [first, second]
    lock.__exit__(type(primary), primary, None)
    assert calls == ["close", "close"]
    assert len(artifacts._cleanup_errors(primary)) == 2
    assert not held
    assert not lock._keys
    assert "sentinel" not in repr(artifacts._cleanup_errors(primary))


def test_native_directory_teardown_preserves_active_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = asyncio.CancelledError("private-primary-sentinel")

    @contextmanager
    def directory(path: str) -> Iterator[int]:
        try:
            yield 41
        finally:
            raise KeyboardInterrupt("private-secondary-sentinel")

    monkeypatch.setattr(artifacts, "_supported", lambda: None)
    monkeypatch.setattr(artifacts, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(artifacts.storage, "windows", lambda: SimpleNamespace(directory=directory))
    with pytest.raises(BaseException) as caught, artifacts._directory("selected-root"):
        raise primary
    assert caught.value is primary
    assert len(artifacts._cleanup_errors(primary)) == 1
    assert "sentinel" not in repr(artifacts._cleanup_errors(primary))


def test_read_wrapper_retains_actual_handle_cleanup_uncertainty(
    local_memory: dict[int, dict[str, object]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    fs = artifacts.LocalProtectedFilesystem()
    store = artifacts.ArtifactStore(fs, Clock(), Events())
    selected = binding("selected-root")
    descriptor = store.publish(OutputIntent(("text",), "selected-root"), b"safe", selected)

    def read(*args: object) -> bytes:
        raise OSError("private-read-sentinel")

    def close(*args: object) -> None:
        raise RuntimeError("private-close-sentinel")

    monkeypatch.setattr(artifacts, "_read_file", read)
    monkeypatch.setattr(artifacts.storage, "close", close)
    with pytest.raises(artifacts.ArtifactError) as caught:
        store.read(descriptor, selected)
    assert len(caught.value.cleanup_errors) == 1
    assert caught.value.cleanup_errors[0].category.value == "cleanup"
    assert "sentinel" not in repr(caught.value)
    assert "sentinel" not in repr(caught.value.cleanup_errors)
    assert descriptor.owning_resource in local_memory[1]
