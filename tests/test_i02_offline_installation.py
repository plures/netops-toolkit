"""Author installation controls; actual owned processes, never Q03 qualification."""

import hashlib
import io
import json
import os
import sys
import tarfile
import threading
import time
from dataclasses import fields, replace
from pathlib import Path
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.dependencies._installation import (
    _Collection,
    _InstallationIOError,
    _InstallationSpec,
    _OfflineInstallation,
    _validate_collection,
    _Wheel,
)
from netops.dependencies._installation_process import _run
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_public_flow import public_case


class Clock:
    def monotonic(self):
        return time.monotonic()


class Cancel:
    def __init__(self):
        self.event = threading.Event()

    def is_cancelled(self):
        return self.event.is_set()

    def wait(self, timeout):
        return self.event.wait(timeout)


def python():
    return str(Path(sys.base_prefix) / "python.exe") if os.name == "nt" else sys.executable


def spec(**changes):
    value = _InstallationSpec(
        python(), "a" * 64, "3.12.10", sys.platform,
        (_Wheel("wheels/netops_toolkit-1.0-py3-none-any.whl", "netops-toolkit", "1.0", "b" * 64),),
    )
    return replace(value, **changes)


def test_real_owned_offline_process_returns_joined_output(tmp_path):
    result = _run((python(), "-I", "-B", "-c", "print('actual-owned-process')"),
                  tmp_path, Clock(), Cancel(), time.monotonic() + 10)
    assert result.strip() == b"actual-owned-process"


def test_real_owned_offline_process_enforces_original_deadline(tmp_path):
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        _run((python(), "-I", "-B", "-c", "import time; time.sleep(30)"),
             tmp_path, Clock(), Cancel(), start + 0.3)
    assert time.monotonic() - start < 5


def test_real_owned_offline_process_rejects_output_overflow_and_joins(tmp_path):
    with pytest.raises(c.ContractError):
        _run((python(), "-I", "-B", "-c", "print('x' * 2097152)"),
             tmp_path, Clock(), Cancel(), time.monotonic() + 10)


def test_cancel_before_spawn_has_no_process_or_file_effect(tmp_path):
    cancel = Cancel()
    cancel.event.set()
    with pytest.raises(InterruptedError):
        _run((python(), "-I", "-B", "-c", "raise AssertionError()"),
             tmp_path, Clock(), cancel, time.monotonic() + 10)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("changes", [
    {"python": "relative-python"}, {"python_digest": "missing"}, {"python_version": "3"},
    {"platform": "unknown"}, {"wheels": ()}, {"controller": 1},
])
def test_descriptor_rejects_unpinned_or_ambiguous_inputs(changes):
    with pytest.raises(c.ContractError):
        spec(**changes)


def test_native_windows_packages_cannot_be_an_ansible_controller():
    with pytest.raises(c.ContractError):
        spec(platform="win32", controller=True)


def test_collection_descriptor_requires_registered_names_and_controller():
    with pytest.raises(c.ContractError):
        _Collection("collections/unsafe.tar.gz", "unknown.namespace", "1.0", "c" * 64)
    collection = _Collection("collections/netcommon.tar.gz", "ansible.netcommon", "1.0", "c" * 64)
    with pytest.raises(c.ContractError):
        spec(collections=(collection,))


def collection_archive(*, dependency=None, link=False):
    result = io.BytesIO()
    metadata = json.dumps({"collection_info": {
        "namespace": "ansible", "name": "netcommon", "version": "1.0",
        "dependencies": dependency or {},
    }}).encode()
    with tarfile.open(fileobj=result, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo("MANIFEST.json")
        member.size = len(metadata)
        archive.addfile(member, io.BytesIO(metadata))
        if link:
            member = tarfile.TarInfo("unsafe")
            member.type = tarfile.SYMTYPE
            member.linkname = "../outside"
            archive.addfile(member)
    return result.getvalue()


@pytest.mark.parametrize("fault", ("digest", "dependency", "link"))
def test_actual_collection_metadata_rejects_bad_digest_links_and_missing_closure(fault):
    content = collection_archive(dependency={"ansible.utils": ">=1.0"} if fault == "dependency"
                                 else None, link=fault == "link")
    selected = _Collection("collections/netcommon.tar.gz", "ansible.netcommon", "1.0",
                           "c" * 64 if fault == "digest" else hashlib.sha256(content).hexdigest())
    value = spec(platform="linux", controller=True, wheels=(
        _Wheel("wheels/netops.whl", "netops-toolkit", "1.0", "b" * 64),
        _Wheel("wheels/ansible.whl", "ansible-core", "2.18", "b" * 64),
        _Wheel("wheels/molecule.whl", "molecule", "25.0", "b" * 64),
    ), collections=(selected,))
    with pytest.raises(c.ContractError):
        _validate_collection(content, selected, value)


def test_real_collection_metadata_validates_exact_declared_offline_closure():
    content = collection_archive()
    selected = _Collection("collections/netcommon.tar.gz", "ansible.netcommon", "1.0",
                           hashlib.sha256(content).hexdigest())
    value = spec(platform="linux", controller=True, wheels=(
        _Wheel("wheels/netops.whl", "netops-toolkit", "1.0", "b" * 64),
        _Wheel("wheels/ansible.whl", "ansible-core", "2.18", "b" * 64),
        _Wheel("wheels/molecule.whl", "molecule", "25.0", "b" * 64),
    ), collections=(selected,))
    _validate_collection(content, selected, value)


def test_runtime_location_is_stable_before_consuming_context_digest(tmp_path):
    generation = str(uuid4())
    # Location depends on the generation, never the manifest digest which
    # includes this location's consuming-context digest.
    instance = _OfflineInstallation(type("Root", (), {"path": str(tmp_path)})())
    manifest = type("Manifest", (), {"generation_id": generation})()
    assert instance.path(manifest).name == "installation-" + c.digest(generation)


def test_native_io_reason_does_not_override_public_contract_error():
    error = _InstallationIOError("installation-security-access")
    assert error.io_reason == "installation-security-access"
    assert error.reason == "invalid-request"


def test_legacy_manifest_retains_exact_canonical_descriptor_and_hash(tmp_path, policy):
    case = public_case(tmp_path, policy)
    manifest = case[4].manifests[0]
    legacy = c.public_object({
        item.name: c.wire(getattr(manifest, item.name)) for item in fields(manifest)
        if item.name not in ("entries", "installation", "bootstrap_digest")
    })
    assert c.canonical_bytes(manifest) == c.canonical_bytes(legacy)
    assert c.digest(manifest) == c.digest(legacy)
    assert "installation" not in c.wire(manifest)
    assert "bootstrap_digest" not in c.wire(manifest)
    assert case[0].plan(case[1], case[2]).lifecycle is not None


def test_installation_descriptor_is_bound_into_manifest_hash(tmp_path, policy):
    from netops.dependencies._managed import ManagedMember

    manifest = public_case(tmp_path, policy)[4].manifests[0]
    selected = spec()
    member = ManagedMember(selected.wheels[0].member, selected.wheels[0].digest, 1)
    installed = replace(manifest, members=(member,), installation=selected)
    changed = replace(installed, installation=replace(selected, python_digest="d" * 64))
    assert c.digest(installed) != c.digest(changed)
    assert c.wire(installed)["installation"] == c.wire(selected)


@pytest.mark.skipif(os.name != "nt", reason="Private Windows Job cleanup failure control")
def test_failed_explicit_job_stop_still_closes_job_and_joins_readers(tmp_path, monkeypatch):
    from netops.dependencies._installation_windows import _WindowsJob

    before = set(threading.enumerate())

    def failed_stop(self):
        raise OSError("installation-job-stop")

    monkeypatch.setattr(_WindowsJob, "stop", failed_stop)
    with pytest.raises(OSError, match="installation-job-stop"):
        _run((python(), "-I", "-B", "-c", "print('stop-failure-control')"),
             tmp_path, Clock(), Cancel(), time.monotonic() + 10)
    assert set(threading.enumerate()) <= before


def test_cancellation_stops_spawned_owned_grandchild_before_late_write(tmp_path):
    child_result = tmp_path / "late-child-result"
    spawned = tmp_path / "owned-child-spawned"
    child = "import time,pathlib,sys;time.sleep(2);pathlib.Path(sys.argv[1]).write_bytes(b'late')"
    parent = (
        "import subprocess,sys,time,pathlib;"
        "subprocess.Popen([sys.executable,'-I','-B','-c',sys.argv[1],sys.argv[2]]);"
        "pathlib.Path(sys.argv[3]).write_bytes(b'spawned');time.sleep(30)"
    )
    class CancelAfterSpawn(Cancel):
        def wait(self, timeout):
            if spawned.exists():
                self.event.set()
            return super().wait(timeout)

    with pytest.raises(InterruptedError):
        _run((python(), "-I", "-B", "-c", parent, child, str(child_result), str(spawned)),
             tmp_path, Clock(), CancelAfterSpawn(), time.monotonic() + 10)
    assert spawned.read_bytes() == b"spawned"
    time.sleep(4)
    assert not child_result.exists()


@pytest.mark.parametrize("failure", ("equal", "changed", "ownership", "cleanup"))
def test_immutable_owned_receipt_retry_never_adopts_or_masks_cleanup(
    tmp_path, policy, monkeypatch, failure,
):
    from netops.ansible.artifacts import ArtifactError
    from netops.ansible.policy.authorization import AuthorizationError

    state = public_case(tmp_path, policy)[4]
    port = state._state
    record = replace(state._facts(), resource_id="unit-installation-receipt",
                     revision=0, payload=c.public_object({"schema": "unit-receipt", "value": "fixed"}))
    state._write_immutable(record)
    before = port.filename(record.resource_id).read_bytes()
    if failure == "changed":
        port.seed(record.resource_id, {"schema": "unit-receipt", "value": "changed"})
        before = port.filename(record.resource_id).read_bytes()
    reason = (c.ReasonCode.OWNERSHIP_INVALID if failure == "ownership"
              else c.ReasonCode.CONSENT_STALE)
    error = c.SafeError(c.ErrorCategory.PRECONDITION, reason, c.Stage.PUBLISH)
    fault = ArtifactError(error, (error,) if failure == "cleanup" else ())

    def conflicting(resource, expected, following):
        raise fault

    monkeypatch.setattr(port, "compare_replace", conflicting)
    if failure == "equal":
        assert state._write_immutable(record) == record
    else:
        with pytest.raises(AuthorizationError if failure == "changed" else ArtifactError):
            state._write_immutable(record)
    assert port.filename(record.resource_id).read_bytes() == before


def test_unreadable_installed_subtree_cannot_be_silently_omitted(tmp_path, monkeypatch):
    from netops.dependencies._installation import _tree

    def unreadable(path, *, followlinks, onerror):
        onerror(PermissionError("installation-unreadable-directory"))

    monkeypatch.setattr(os, "walk", unreadable)
    with pytest.raises(PermissionError, match="installation-unreadable-directory"):
        _tree(tmp_path, Clock(), Cancel(), time.monotonic() + 10)


def test_collection_validation_honors_original_cancel_before_parsing():
    content = collection_archive()
    selected = _Collection("collections/netcommon.tar.gz", "ansible.netcommon", "1.0",
                           hashlib.sha256(content).hexdigest())
    cancel = Cancel()
    cancel.event.set()
    with pytest.raises(InterruptedError):
        _validate_collection(content, selected, spec(), Clock(), cancel, time.monotonic() + 10)


@pytest.mark.skipif(os.name != "nt", reason="Private Windows Job assignment failure control")
def test_assignment_failure_closes_owned_job_before_return(tmp_path, monkeypatch):
    from netops.dependencies._installation_windows import _WindowsJob

    assign, close = _WindowsJob.assign, _WindowsJob.close
    closed = []

    def failed_assign(self, pid, handle, thread_handle, tid):
        assign(self, pid, handle, thread_handle, tid)
        raise OSError("installation-assignment-control")

    def closed_job(self):
        close(self)
        closed.append(self.handle is None)

    monkeypatch.setattr(_WindowsJob, "assign", failed_assign)
    monkeypatch.setattr(_WindowsJob, "close", closed_job)
    with pytest.raises(OSError, match="installation-assignment-control"):
        _run((python(), "-I", "-B", "-c", "import threading;threading.Event().wait(30)"),
             tmp_path, Clock(), Cancel(), time.monotonic() + 10)
    assert closed and all(closed)
