"""Owned I/O fault injection, not producer or platform qualification."""

import errno
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from netops.ansible import artifact_cleanup as cleanup
from netops.ansible import contracts as c
from netops.ansible.artifacts import ArtifactError
from netops.ansible.policy.authorization import AuthorizationError
from netops.dependencies import _managed
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel
from tests.test_i02_corrective_managed import admitted


@pytest.mark.parametrize("native,expected", [
    (5, "native-access-denied"), (32, "native-sharing-violation"),
    (None, "unknown-io"),
])
def test_native_stage_failure_retains_safe_cause_and_staging_intent(
    policy, monkeypatch, caplog, native, expected,
):
    handler, manifest, content, permit, effect, owned, files, _ = admitted(policy)
    primary = OSError("private-path password=DO-NOT-LOG raw-output")
    if native is not None:
        primary.winerror = native

    def fail(*args):
        raise primary

    monkeypatch.setattr(files, "stage", fail)
    with caplog.at_level("INFO"), pytest.raises(ArtifactError) as raised:
        handler.stage(manifest, content, permit, effect, Cancel())
    error = raised.value
    assert error.error.reason == c.ReasonCode.PROVISION_FAILED
    assert error.error.stage == c.Stage.PROVISION
    diagnostic, = cleanup._storage_diagnostics(error)
    assert diagnostic.cause_class == expected
    assert diagnostic.winerror == native
    assert diagnostic.errno is None
    assert diagnostic.stage == "managed-stage"
    assert diagnostic.operation == "stage-files"
    assert diagnostic.resource_sha256 == c.digest((
        effect.lifecycle.root.resource_id, c.digest(manifest),
    ))
    assert error.error.detail == "storage-diagnostic:" + diagnostic.reference
    records = [row for row in caplog.records if row.msg == "install.native.failure"]
    assert len(records) == 1
    assert records[0].diagnostic_ref == diagnostic.reference
    assert records[0].operation_sha256 == c.digest(effect.lifecycle.lifecycle_id)
    assert "private-path" not in repr(error) + repr(asdict(diagnostic)) + caplog.text
    assert "DO-NOT-LOG" not in json.dumps(c.wire(error.error)) + caplog.text
    assert owned.record.payload["generations"][0]["state"] == "staging"
    assert not handler._pending
    with pytest.raises(AuthorizationError):
        handler.complete(permit)


def test_first_primary_and_separate_cleanup_refs_survive_public_wrapper(policy, monkeypatch):
    handler, manifest, content, permit, effect, _, files, _ = admitted(policy)
    primary = OSError(errno.ENOSPC, "private disk detail", "private member")
    secondary = OSError("private close detail")
    secondary.winerror = 32

    def fail(*args):
        with cleanup._storage_io("managed-stage", "write-member", "a" * 64):
            try:
                raise primary
            finally:
                with cleanup.teardown():
                    with cleanup._storage_io("owned-cleanup", "close-handle", "b" * 64):
                        raise secondary

    monkeypatch.setattr(files, "stage", fail)
    with pytest.raises(ArtifactError) as raised:
        handler.stage(manifest, content, permit, effect, Cancel())
    assert len(raised.value.cleanup_errors) == 1
    diagnostic, = cleanup._storage_diagnostics(raised.value)
    retained, = cleanup._storage_diagnostics(raised.value, cleanup=True)
    assert diagnostic.errno == errno.ENOSPC
    assert diagnostic.operation == "write-member"
    assert diagnostic.resource_sha256 == "a" * 64
    assert retained.winerror == 32
    assert retained.operation == "close-handle"
    assert retained.resource_sha256 == "b" * 64
    assert retained.reference != diagnostic.reference
    assert cleanup._storage_diagnostics(primary) == (diagnostic,)
    assert cleanup._storage_diagnostics(primary, cleanup=True) == (retained,)


@pytest.mark.parametrize("succeeds", [True, False])
def test_interrupting_observation_cannot_replace_primary_or_completed_stage(
    policy, monkeypatch, succeeds,
):
    handler, manifest, content, permit, effect, _, files, events = admitted(policy)
    files.fail = not succeeds

    def broken(*args, **kwargs):
        raise SystemExit("private sink failure")

    monkeypatch.setattr(_managed._LOG, "info", broken)
    monkeypatch.setattr(events, "emit", broken)
    if succeeds:
        receipt = handler.stage(manifest, content, permit, effect, Cancel())
        assert handler.complete(permit) == receipt
    else:
        with pytest.raises(ArtifactError) as raised:
            handler.stage(manifest, content, permit, effect, Cancel())
        assert raised.value.error.reason == c.ReasonCode.PROVISION_FAILED
        assert not handler._pending


@pytest.mark.parametrize("native", [5, 32, None])
def test_actual_owned_partial_tree_preserves_native_publication_error(
        policy, monkeypatch, tmp_path, native,
):
        from netops.dependencies._setup import _owned
        from tests.test_i02_corrective_managed import (
            Clock,
            archive_bytes,
            manifest_for,
        )

        root = _owned(tmp_path / "owned", True)
        content = archive_bytes()
        manifest = manifest_for(policy[0], content)
        port = _managed.ProtectedGenerationFiles(root)
        primary = OSError(errno.ENOSPC if native is None else errno.EACCES, "private rename")
        if native is not None:
            primary.winerror = native
        calls = []

        def fail(*args, **kwargs):
            calls.append(True)
            raise primary

        monkeypatch.setattr(_managed.platform, "rename", fail)
        files = _managed.unpack(manifest, content, Clock(), Cancel(), 20.0)
        with pytest.raises(OSError) as raised:
            port.stage(manifest, files, Clock(), Cancel(), 20.0)
        assert raised.value is primary
        diagnostic, = cleanup._storage_diagnostics(primary)
        assert diagnostic.stage == "managed-stage"
        assert diagnostic.operation == "publish-generation"
        assert diagnostic.winerror == native
        assert diagnostic.errno == primary.errno
        assert len(calls) == 1
        assert (tmp_path / "owned" / port._pending_directory(manifest)).is_dir()
        assert not (tmp_path / "owned" / port._directory(manifest)).exists()


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_actual_owned_atomic_replace_keeps_native_and_cleanup_facts(
    policy, monkeypatch, tmp_path, cleanup_fails,
):
        from dataclasses import replace

        from netops.ansible import artifacts
        from netops.dependencies._setup import _owned

        root = _owned(tmp_path / "atomic", True)
        identity = policy[0]
        state = artifacts.OwnedState(root, "a" * 64)
        original = artifacts.OwnedRecord(
            "root", "checkpoint", 0, 0, "a" * 64, identity.bundle_sha256,
            identity.reducer_version, c.public_object({"value": "original"}), identity,
        )
        state.compare_replace("root", 0, original)
        primary = OSError(errno.EACCES, "private destination")
        primary.winerror = 32

        def fail(*args, **kwargs):
            raise primary

        monkeypatch.setattr(artifacts.storage, "rename", fail)
        if cleanup_fails:
            secondary = OSError("private cleanup")
            secondary.winerror = 5

            def remove(*args, **kwargs):
                raise secondary

            monkeypatch.setattr(artifacts.storage, "remove", remove)
        with pytest.raises(ArtifactError) as raised:
            state.compare_replace("root", 0, replace(
                original, revision=1, payload=c.public_object({"value": "new"}),
            ))
        diagnostic, = cleanup._storage_diagnostics(raised.value)
        assert diagnostic.operation == "replace-record"
        assert diagnostic.winerror == 32
        assert diagnostic.errno == errno.EACCES
        assert raised.value.native_code == 32
        assert raised.value.error.detail == "storage-diagnostic:" + diagnostic.reference
        assert state.read("root") == original
        assert state.retained("root", 0) == original
        assert bool(raised.value.cleanup_errors) is cleanup_fails
        if cleanup_fails:
            retained, = cleanup._storage_diagnostics(raised.value, cleanup=True)
            assert retained.winerror == 5
            assert retained.reference != diagnostic.reference


def test_fixed_venv_child_preserves_actual_native_error_without_raw_stderr(tmp_path):
    from netops.dependencies._installation_process import _VENV, _NativeChildFailure, _run
    from netops.dependencies._setup import _Clock
    from tests.test_i02_offline_installation import Cancel as NativeCancel

    blocker = tmp_path / "private-user-data"
    blocker.write_bytes(b"untouched")
    target = blocker / "uncreated"
    with pytest.raises(OSError) as reference:
        target.mkdir()
    clock, cancel = _Clock(), NativeCancel()
    python = str(Path(sys.base_prefix) / "python.exe") if os.name == "nt" else sys.executable
    with pytest.raises(_NativeChildFailure) as raised:
        _run(
            (python, "-I", "-B", "-c", _VENV, str(target)),
            tmp_path, clock, cancel, time.monotonic() + 15,
        )
    diagnostic, = cleanup._storage_diagnostics(raised.value)
    assert diagnostic.origin == "child"
    assert diagnostic.operation == "create-environment"
    assert diagnostic.winerror == getattr(reference.value, "winerror", None)
    assert diagnostic.errno == reference.value.errno
    assert blocker.read_bytes() == b"untouched"
    assert not target.exists()
    assert str(tmp_path) not in repr(raised.value) + repr(asdict(diagnostic))


def test_cleanup_failure_during_revocation_does_not_replace_first_stage_error(policy, monkeypatch):
    handler, manifest, content, permit, effect, _, files, _ = admitted(policy)
    primary = OSError("first private native error")
    primary.winerror = 5

    def fail(*args):
        raise primary

    def revoke(*args):
        raise OSError("later private revoke error")

    monkeypatch.setattr(files, "stage", fail)
    monkeypatch.setattr(handler._authorization, "revoke_lifecycle", revoke)
    with pytest.raises(ArtifactError) as raised:
        handler.stage(manifest, content, permit, effect, Cancel())
    diagnostic, = cleanup._storage_diagnostics(raised.value)
    assert diagnostic.winerror == 5
    assert raised.value.error.reason == c.ReasonCode.PROVISION_FAILED
    assert raised.value.cleanup_errors
    assert not handler._pending


def test_native_reference_never_reclassifies_existing_protected_storage_error(policy, monkeypatch):
    handler, manifest, content, permit, effect, _, files, _ = admitted(policy)
    safe = c.SafeError(c.ErrorCategory.PRECONDITION, c.ReasonCode.OWNERSHIP_INVALID, c.Stage.PUBLISH)
    primary = ArtifactError(safe, native_code=5)

    def fail(*args):
        try:
            with cleanup._storage_io("owned-state", "replace-record", "a" * 64):
                native = OSError("private owned state")
                native.winerror = 5
                raise native
        except OSError as error:
            cleanup._carry_storage_diagnostics(error, primary)
        raise primary

    monkeypatch.setattr(files, "stage", fail)
    with pytest.raises(ArtifactError) as raised:
        handler.stage(manifest, content, permit, effect, Cancel())
    assert raised.value is primary
    assert raised.value.error == safe
    assert raised.value.native_code == 5
    assert cleanup._storage_diagnostics(raised.value)[0].winerror == 5


def test_private_native_logger_cannot_replace_primary(monkeypatch):
    native = OSError("private original")
    native.winerror = 32

    def sink(*args, **kwargs):
        raise KeyboardInterrupt("private telemetry")

    monkeypatch.setattr(cleanup._NATIVE_LOG, "info", sink)
    with pytest.raises(OSError) as raised:
        with cleanup._storage_io("managed-stage", "write-member", "a" * 64):
            raise native
    assert raised.value is native
    assert cleanup._storage_diagnostics(native)[0].winerror == 32
