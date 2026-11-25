"""Original AC-001/011 precise primary failure and cleanup preservation.

Only the external generation-files port fails synthetically. Broker entry,
managed handler, staging intent and public safe-error wrapper are real SOURCE.
"""

import errno
import json
from dataclasses import asdict

import pytest

from netops.ansible import artifact_cleanup as cleanup
from netops.ansible import contracts as c
from netops.ansible.artifacts import ArtifactError
from netops.ansible.policy.authorization import AuthorizationError
from netops.dependencies import _managed
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel
from tests.test_i02_corrective_managed import admitted


@pytest.mark.parametrize("native,cause", [
    (5, "native-access-denied"), (32, "native-sharing-violation"),
    (267, "native-invalid-directory"),
])
def test_ac011_admitted_stage_preserves_exact_native_cause_without_secret_payload(
    policy, monkeypatch, caplog, native, cause,
):
    handler, manifest, content, permit, effect, owned, files, _ = admitted(policy)
    error = OSError(errno.ENOTDIR if native == 267 else errno.EACCES,
                    "password=independent-secret", "sensitive-native-resource")
    error.winerror = native

    def failed_stage(*args):
        raise error

    monkeypatch.setattr(files, "stage", failed_stage)
    with caplog.at_level("INFO"), pytest.raises(ArtifactError) as raised:
        handler.stage(manifest, content, permit, effect, Cancel())
    primary = raised.value
    diagnostic, = cleanup._storage_diagnostics(primary)
    assert (diagnostic.winerror, diagnostic.errno) == (native, error.errno)
    assert diagnostic.cause_class == cause
    assert diagnostic.stage == "managed-stage" and diagnostic.operation == "stage-files"
    assert diagnostic.resource_sha256 == c.digest((
        effect.lifecycle.root.resource_id, c.digest(manifest),
    ))
    assert diagnostic.operation_sha256 == c.digest(effect.lifecycle.lifecycle_id)
    assert primary.native_code == native
    assert primary.error.reason == c.ReasonCode.PROVISION_FAILED
    assert primary.error.detail == "storage-diagnostic:" + diagnostic.reference
    expected_wire = (
        '{"category":"dependency","detail":"storage-diagnostic:'
        + diagnostic.reference
        + '","next_action":"Inspect the exact retained staging manifest before a new reviewed plan.",'
        '"reason":"provision-failed","retryable":false,"stage":"provision",'
        '"step_id":null,"target_id":null}'
    )
    assert c.canonical_bytes(primary.error).decode("utf-8") == expected_wire
    assert owned.record.payload["generations"][0]["state"] == "staging"
    assert not handler._pending
    with pytest.raises(AuthorizationError):
        handler.complete(permit)
    observations = [row for row in caplog.records if row.msg == "install.native.failure"]
    assert len(observations) == 1
    safe = json.dumps(c.wire(primary.error)) + json.dumps(asdict(diagnostic)) + caplog.text
    assert "independent-secret" not in safe and "sensitive-native-resource" not in safe


def test_ac011_distinct_cleanup_reference_never_replaces_primary_failure(policy, monkeypatch):
    handler, manifest, content, permit, effect, _, files, _ = admitted(policy)
    primary = OSError(errno.ENOSPC, "private-primary-resource")
    secondary = OSError(errno.EACCES, "private-cleanup-resource")
    secondary.winerror = 32

    def failed_stage(*args):
        with cleanup._storage_io("installation", "install-files", "a" * 64):
            try:
                raise primary
            finally:
                with cleanup.teardown():
                    with cleanup._storage_io("owned-cleanup", "close-handle", "b" * 64):
                        raise secondary

    monkeypatch.setattr(files, "stage", failed_stage)
    with pytest.raises(ArtifactError) as raised:
        handler.stage(manifest, content, permit, effect, Cancel())
    cause, = cleanup._storage_diagnostics(raised.value)
    finalizer, = cleanup._storage_diagnostics(raised.value, cleanup=True)
    assert cause.cause_class == "storage-full" and cause.errno == errno.ENOSPC
    assert cause.stage == "installation" and cause.operation == "install-files"
    assert cause.resource_sha256 == "a" * 64
    assert finalizer.cause_class == "native-sharing-violation" and finalizer.winerror == 32
    assert finalizer.resource_sha256 == "b" * 64 and finalizer.operation == "close-handle"
    assert finalizer.reference != cause.reference
    assert raised.value.error.detail == "storage-diagnostic:" + cause.reference
    assert len(raised.value.cleanup_errors) == 1
    assert raised.value.cleanup_errors[0].detail == "storage-diagnostic:" + finalizer.reference


@pytest.mark.parametrize("sink", ["diagnostic", "handler", "events"])
def test_ac011_interrupting_observer_cannot_mask_original_admitted_failure(
    policy, monkeypatch, sink,
):
    handler, manifest, content, permit, effect, _, files, events = admitted(policy)
    primary = OSError(errno.ENOTDIR, "sensitive-primary")
    primary.winerror = 267

    def failed_stage(*args):
        raise primary

    def failed_observer(*args, **kwargs):
        raise SystemExit("sensitive-observer")

    monkeypatch.setattr(files, "stage", failed_stage)
    if sink == "diagnostic":
        monkeypatch.setattr(cleanup._NATIVE_LOG, "info", failed_observer)
    elif sink == "handler":
        monkeypatch.setattr(_managed._LOG, "info", failed_observer)
    else:
        monkeypatch.setattr(events, "emit", failed_observer)
    with pytest.raises(ArtifactError) as raised:
        handler.stage(manifest, content, permit, effect, Cancel())
    diagnostic, = cleanup._storage_diagnostics(raised.value)
    assert diagnostic.winerror == 267 and diagnostic.errno == errno.ENOTDIR
    assert raised.value.error.reason == c.ReasonCode.PROVISION_FAILED
    assert raised.value.error.detail == "storage-diagnostic:" + diagnostic.reference
    assert not handler._pending
