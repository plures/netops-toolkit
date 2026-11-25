"""C02 unit boundaries; fake-port tests are not OS qualification."""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from netops.ansible import artifacts
from netops.ansible.artifacts import (
    ArtifactError,
    ArtifactStore,
    LocalProtectedFilesystem,
    OwnedResource,
    ProtectedRoot,
    selected_state_root,
)
from netops.ansible.contracts import (
    ArtifactBinding,
    ArtifactDescriptor,
    EffectBinding,
    OutcomeStatus,
    OutputIntent,
    PlanBinding,
    SafeEvent,
    digest,
)


class Clock:
    def monotonic(self) -> float:
        return 10.0

    def utc_now(self) -> datetime:
        return datetime(2026, 1, 1, tzinfo=timezone.utc)


class Events:
    def __init__(self) -> None:
        self.events: list[SafeEvent] = []

    def emit(self, event: SafeEvent) -> None:
        self.events.append(event)


@pytest.fixture(autouse=True)
def offline_native_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep foreign/native qualification outside this offline test invocation."""
    if os.name == "nt" or sys.platform == "darwin":
        def unavailable() -> None:
            raise artifacts._failure(
                artifacts.ReasonCode.OUTPUT_REJECTED, artifacts.ErrorCategory.PLATFORM,
            )
        monkeypatch.setattr(artifacts, "_supported", unavailable)


def binding(root: str, classification: str = "public") -> ArtifactBinding:
    plan = PlanBinding(str(uuid4()), *("a" * 64,) * 7, root, 0, ())
    return ArtifactBinding(
        EffectBinding(plan, str(uuid4()), 0, "output-1", "target-1", "publish", ()),
        classification,
    )


class MemoryFilesystem:
    def __init__(self) -> None:
        self.content = b""
        self.calls = 0
        self.corrupt = False

    def validate(self, intent: OutputIntent) -> ProtectedRoot:
        self.calls += 1
        return ProtectedRoot(str(intent.root_ref), 0, 0, intent, "test-only-not-OS-proof")

    def publish(
        self, root: ProtectedRoot, content: bytes, binding: ArtifactBinding,
    ) -> ArtifactDescriptor:
        self.calls += 1
        self.content = content
        return ArtifactDescriptor(
            "test-ref", hashlib.sha256(content).hexdigest(), len(content),
            artifacts._KINDS[root.intent.kinds[0]],
            binding.classification, "test-only-not-OS-proof", "explicit",
            "test-resource", "0" * 64 if self.corrupt else digest(binding),
        )

    def read(self, descriptor: ArtifactDescriptor) -> bytes:
        self.calls += 1
        return self.content


def test_publish_exact_and_reject_swapped_binding_before_read() -> None:
    fs, events = MemoryFilesystem(), Events()
    store = ArtifactStore(fs, Clock(), events)
    selected = binding("selected-root")
    descriptor = store.publish(OutputIntent(("text",), "selected-root"), b"safe\nbytes\n", selected)
    assert store.read(descriptor, selected) == b"safe\nbytes\n"
    calls = fs.calls
    with pytest.raises(ArtifactError):
        store.read(descriptor, binding("selected-root"))
    assert fs.calls == calls
    assert events.events[-1].status == OutcomeStatus.SUCCEEDED


@pytest.mark.parametrize("content", [
    b"password sentinel-value", b"snmp-server community sentinel-value ro",
    b"snmp-server user u g v3 auth sha sentinel-value",
    b"radius server r\n key sentinel-value",
    b'{"nested":{"authKey":"sentinel-value"}}',
    b"authKey: sentinel-value", b"privacy_key: sentinel-value",
    b'[{"sharedSecret":"sentinel-value"}]', b"password_hash: sentinel-value",
])
def test_public_secret_rejected_before_io_or_hash(content: bytes) -> None:
    fs, events = MemoryFilesystem(), Events()
    store = ArtifactStore(fs, Clock(), events)
    with pytest.raises(ArtifactError) as caught:
        store.publish(OutputIntent(("text",), "selected-root"), content, binding("selected-root"))
    assert fs.calls == 0
    assert "sentinel-value" not in repr(caught.value)
    assert "sentinel-value" not in repr(events.events)


def test_sensitive_requires_explicit_retention_and_preserves_exact_bytes() -> None:
    fs = MemoryFilesystem()
    store = ArtifactStore(fs, Clock(), Events())
    selected = binding("selected-root", "sensitive")
    content = b"\xffpassword sentinel-value\r\n"
    with pytest.raises(ArtifactError):
        store.publish(OutputIntent(("text",), "selected-root"), content, selected)
    assert fs.calls == 0
    descriptor = store.publish(
        OutputIntent(("text",), "selected-root", retention=True), content, selected,
    )
    assert store.read(descriptor, selected) == content


def test_no_descriptor_for_adapter_binding_lie_or_content_change() -> None:
    fs = MemoryFilesystem()
    fs.corrupt = True
    store = ArtifactStore(fs, Clock(), Events())
    selected = binding("selected-root")
    with pytest.raises(ArtifactError):
        store.publish(OutputIntent(("text",), "selected-root"), b"safe", selected)
    fs.corrupt = False
    descriptor = store.publish(OutputIntent(("text",), "selected-root"), b"safe", selected)
    fs.content = b"tampered"
    with pytest.raises(ArtifactError):
        store.read(descriptor, selected)


@pytest.mark.parametrize("root", ["relative", "..", "..\\escape"])
def test_explicit_state_root_requires_absolute_selection(root: str) -> None:
    with pytest.raises(ArtifactError):
        selected_state_root(root)


def test_unsupported_platform_blocks_before_creating_files(tmp_path: Path) -> None:
    if os.name == "posix" and sys.platform != "darwin":
        tmp_path.chmod(0o700)
        root = LocalProtectedFilesystem().validate(OutputIntent(("text",), str(tmp_path)))
        assert root.permissions_proof == "posix-owner-0700-0600"
    else:
        with pytest.raises(ArtifactError) as caught:
            LocalProtectedFilesystem().validate(OutputIntent(("text",), str(tmp_path)))
        assert caught.value.error.category.value == "platform"
        assert list(tmp_path.iterdir()) == []


def test_native_owned_publication_and_cleanup_cell(tmp_path: Path) -> None:
    """Execute only supported native semantics; Windows is explicitly blocked, not qualified."""
    fs, events = LocalProtectedFilesystem(), Events()
    intent = OutputIntent(("text",), str(tmp_path))
    if os.name != "posix" or sys.platform == "darwin":
        with pytest.raises(ArtifactError):
            fs.validate(intent)
        return
    tmp_path.chmod(0o700)
    root = fs.validate(intent)
    store = ArtifactStore(fs, Clock(), events)
    selected = binding(str(tmp_path))
    descriptor = store.publish(intent, b"exact\r\noutput", selected)
    assert fs.read(descriptor) == b"exact\r\noutput"
    assert Path(descriptor.ref).stat().st_mode & 0o777 == 0o600
    with pytest.raises(ArtifactError):
        store.publish(intent, b"different", selected)
    unknown = tmp_path / "user-file"
    unknown.write_text("preserve")
    assert store.cleanup((OwnedResource(descriptor, root),)).status == "succeeded"
    assert Path(descriptor.ref).exists()
    assert store.cleanup((OwnedResource(descriptor, root, True),)).status == "succeeded"
    assert not Path(descriptor.ref).exists()
    assert unknown.read_text() == "preserve"


def test_native_symlink_permissions_and_manifest_tamper_cell(tmp_path: Path) -> None:
    if os.name != "posix" or sys.platform == "darwin":
        with pytest.raises(ArtifactError):
            LocalProtectedFilesystem().validate(OutputIntent(("text",), str(tmp_path)))
        return
    tmp_path.chmod(0o700)
    fs = LocalProtectedFilesystem()
    intent = OutputIntent(("text",), str(tmp_path))
    root = fs.validate(intent)
    descriptor = fs.publish(root, b"safe", binding(str(tmp_path)))
    content = Path(descriptor.ref)
    content.chmod(0o644)
    with pytest.raises(ArtifactError):
        fs.read(descriptor)
    content.chmod(0o600)
    receipt = content.parent / "receipt.json"
    receipt.write_text("{}")
    with pytest.raises(ArtifactError):
        fs.read(descriptor)
    link = tmp_path / "escape"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ArtifactError):
        fs.validate(replace(intent, root_ref=str(link)))


def test_adapter_errors_are_safe_and_sensitive_cleanup_is_never_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fs, events = MemoryFilesystem(), Events()
    store = ArtifactStore(fs, Clock(), events)
    selected = binding("selected-root")

    def broken(*args: object) -> ArtifactDescriptor:
        raise OSError("sentinel-private-path-and-secret")

    monkeypatch.setattr(fs, "publish", broken)
    with pytest.raises(ArtifactError) as caught:
        store.publish(OutputIntent(("text",), "selected-root"), b"safe", selected)
    assert "sentinel-private" not in repr(caught.value)
    assert "sentinel-private" not in repr(events.events)
    assert events.events[-1].status == OutcomeStatus.FAILED
    descriptor = ArtifactDescriptor(
        "sensitive-ref", "a" * 64, 1, "text/plain", "sensitive", "fake-only",
        "explicit", "sensitive-resource", "b" * 64,
    )
    root = ProtectedRoot("memory-root", 0, 0, OutputIntent(("text",), "memory-root"), "fake-only")
    calls = fs.calls
    assert store.cleanup((OwnedResource(descriptor, root, True),)).status == "succeeded"
    assert fs.calls == calls


def test_native_cancel_and_unknown_cleanup_children_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fs = LocalProtectedFilesystem()
    intent = OutputIntent(("text",), str(tmp_path))
    if os.name != "posix" or sys.platform == "darwin":
        with pytest.raises(ArtifactError):
            fs.validate(intent)
        return
    tmp_path.chmod(0o700)
    root = fs.validate(intent)

    def cancelled(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt()

    with monkeypatch.context() as scoped:
        scoped.setattr(artifacts.storage, "rename", cancelled)
        with pytest.raises(KeyboardInterrupt):
            fs.publish(root, b"safe", binding(str(tmp_path)))
    assert not any(path.name.startswith(("pending-", "artifact-")) for path in tmp_path.iterdir())
    store = ArtifactStore(fs, Clock(), Events())
    descriptor = store.publish(intent, b"safe", binding(str(tmp_path)))
    unknown = Path(descriptor.ref).parent / "unknown-user-child"
    unknown.write_text("preserve")
    outcome = store.cleanup((OwnedResource(descriptor, root, True),))
    assert outcome.status == "failed"
    assert Path(descriptor.ref).read_bytes() == b"safe"
    assert unknown.read_text() == "preserve"
