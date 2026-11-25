"""Actual manifest/parser/handler controls with fake storage, never qualification."""

import hashlib
import io
import stat
import tarfile
import threading
import zipfile
from contextlib import contextmanager
from dataclasses import replace
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.artifacts import ArtifactError, OwnedRecord
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    LifecycleSnapshot,
    TrustedConsentAdapter,
    TrustedLifecycleConsentAdapter,
    bind_lifecycle,
    lifecycle_plan_digest,
)
from netops.ansible.policy.lifecycle_evidence import LifecycleEvidence, lifecycle_arguments_digest
from netops.dependencies._assets import LockedAsset
from netops.dependencies._managed import (
    ManagedGenerationHandler,
    ManagedGenerationManifest,
    ManagedMember,
    unpack,
)
from tests.policy.test_a01_lifecycle_admission import Review
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel

DATA = b"reviewed package bytes, never executed by this test"
MEMBER = "lib/python/site-packages/example/__init__.py"


class Clock:
    def monotonic(self):
        return 10.0


class Events:
    def __init__(self):
        self.records = []
        self.fail = False

    def emit(self, event):
        self.records.append(event)
        if self.fail:
            raise RuntimeError("sink")


def archive_bytes(path=MEMBER, content=DATA, kind="zip", mode=None):
    buffer = io.BytesIO()
    if kind == "zip":
        with zipfile.ZipFile(buffer, "w") as archive:
            info = zipfile.ZipInfo(path)
            info.external_attr = (stat.S_IFREG | 0o644 if mode is None else mode) << 16
            archive.writestr(info, content)
    else:
        with tarfile.open(fileobj=buffer, mode="w:gz" if kind == "tar.gz" else "w",
                          format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo(path)
            info.size = len(content)
            if mode is not None:
                info.type = mode
                info.linkname = "outside"
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def manifest_for(identity, content, path=MEMBER, kind="zip"):
    context = c.InstallContext(c.Context(
        "controller", "1" * 64, "inventory", "2" * 64, identity, "3" * 64, "4" * 64,
    ))
    return ManagedGenerationManifest(
        str(uuid4()), LockedAsset(
            "reviewed-wheel", "example", "https://files.pythonhosted.org/exact.whl",
            hashlib.sha256(content).hexdigest(), len(content),
        ), kind, (ManagedMember(path, hashlib.sha256(DATA).hexdigest(), len(DATA)),),
        c.InstallScope(("native.stdlib",), (), False, False), context, ("5" * 64,),
    )


@pytest.mark.parametrize("kind", ["zip", "tar", "tar.gz"])
def test_safe_exact_package_tree_members_are_extracted_without_execution(policy, kind):
    content = archive_bytes(kind=kind)
    manifest = manifest_for(policy[0], content, kind=kind)
    result = unpack(manifest, content, Clock(), Cancel(), 20.0)
    assert tuple(item.member.path for item in result) == (MEMBER,)
    assert result[0].content == DATA
    assert "qualified" not in c.wire(manifest)


@pytest.mark.parametrize("path", [
    "../outside", "/absolute", "C:/outside", "a\\b", "a//b", "a/../b", "a/.",
    "CON", "a/NUL.txt", "a/name.", "netops-generation.json",
])
def test_manifest_rejects_traversal_aliases_streams_and_ownership_sentinel(policy, path):
    content = archive_bytes()
    with pytest.raises(c.ContractError):
        manifest_for(policy[0], content, path)


@pytest.mark.parametrize("kind,mode", [
    ("zip", stat.S_IFLNK | 0o777), ("zip", stat.S_IFREG | stat.S_ISUID | 0o755),
    ("tar", tarfile.SYMTYPE), ("tar", tarfile.LNKTYPE), ("tar", tarfile.CHRTYPE),
])
def test_archive_links_devices_and_special_modes_never_become_owned_files(policy, kind, mode):
    content = archive_bytes(kind=kind, mode=mode)
    manifest = manifest_for(policy[0], content, kind=kind)
    with pytest.raises(c.ContractError):
        unpack(manifest, content, Clock(), Cancel(), 20.0)


def test_unlisted_member_rejected_even_when_archive_digest_is_exact(policy):
    content = archive_bytes(path="unexpected.py")
    manifest = manifest_for(policy[0], content)
    with pytest.raises(c.ContractError):
        unpack(manifest, content, Clock(), Cancel(), 20.0)


def test_case_alias_and_file_directory_collisions_fail_before_io(policy):
    content = archive_bytes()
    manifest = manifest_for(policy[0], content)
    for path in (MEMBER.upper(), "lib"):
        with pytest.raises(c.ContractError):
            replace(manifest, members=(*manifest.members, ManagedMember(path, "a" * 64, 1)))


def test_cancel_and_deadline_are_checked_inside_archive_work(policy):
    content = archive_bytes()
    manifest = manifest_for(policy[0], content)
    cancel = Cancel()
    cancel.value = True
    with pytest.raises(InterruptedError):
        unpack(manifest, content, Clock(), cancel, 20.0)
    with pytest.raises(TimeoutError):
        unpack(manifest, content, Clock(), Cancel(), 10.0)


class Records:
    def __init__(self, record):
        self.record = record
        self.writes = []
        self.mutex = threading.RLock()

    def read(self, resource):
        assert resource == self.record.resource_id
        return self.record

    def compare_replace(self, resource, expected, record):
        assert resource == self.record.resource_id
        if expected != self.record.revision or record.revision != expected + 1:
            raise AuthorizationError()
        self.record = record
        self.writes.append(record)
        return record

    @contextmanager
    def lock(self, resources, timeout):
        with self.mutex:
            yield


class Files:
    """Fake product-tree I/O port, not an inert A02 generation or factory mock."""

    def __init__(self):
        self.calls = []
        self.content = None
        self.fail = False

    def stage(self, manifest, files, clock, cancel, deadline):
        self.calls.append("stage")
        if self.fail:
            raise PermissionError("fake protected write denial")
        self.content = tuple((item.member.path, item.content) for item in files)

    def verify(self, manifest, clock, cancel, deadline):
        self.calls.append("verify")
        assert self.content == ((MEMBER, DATA),)


class ManagedState:
    """Fake root/pointer observation port; only exact staging is admitted."""

    def __init__(self, owned, binding):
        self._state, self.binding = owned, binding
        self.evidence = LifecycleEvidence(
            binding.root, (binding.generation,), binding.content["steps"], (), None,
        )

    def lock_lifecycle(self, binding):
        return self._state.mutex

    def snapshot_lifecycle(self, binding):
        return LifecycleSnapshot(
            self.binding, self._state.record.revision, False, True, True, True, True,
            self.evidence,
        )

    def compare_lifecycle_revision(self, binding, expected, following):
        if self._state.record.revision != expected:
            return False
        self._state.compare_replace(
            binding.root.resource_id, expected, replace(self._state.record, revision=following),
        )
        return True

    def compare_replace_lifecycle(self, binding, expected, following_revision):
        raise AssertionError("A staging handler must never change a pointer")


def admitted(policy):
    identity, engine = policy[:2]
    content = archive_bytes()
    manifest = manifest_for(identity, content)
    root_manifest = c.public_object({"owner": "fake-unit-managed-root"})
    generation = lc.GenerationBinding(
        manifest.generation_id, 0, manifest.content_digest, c.digest(manifest),
    )
    step = c.public_object({
        "occurrence_id": "stage-tree", "generation_id": generation.generation_id,
        "source": {
            "source_id": manifest.asset.source_id, "registry_digest": "3" * 64,
            "artifact_digest": manifest.asset.sha256, "descriptor_digest": c.digest(manifest.asset),
        },
        "destination": {
            "resource_id": "managed-tree", "root_resource_id": "managed-root",
            "segments": ("generations", generation.generation_id), "manifest_digest": c.digest(manifest),
        }, "reuse": None, "consequential": (),
    })
    effect = lc.LifecycleEffectOccurrence(
        "stage-tree", 0, "stage-tree", "managed-tree", "dependency-stage",
        lifecycle_arguments_digest(step),
    )
    plan = lc.InstallPlan(
        "1.0", str(uuid4()), str(uuid4()), "0" * 64, c.digest(manifest.context),
        lc.OwnedRootBinding("managed-root", c.digest(root_manifest)), generation,
        lc.AbsentPointer("absent", 0), identity, "3" * 64, "6" * 64, (effect,), (),
        c.public_object({
            "schema": "1.0", "steps": (step,), "verification": None,
            "pins": (), "cancel_scope": ("stage-tree",),
        }), "install", manifest.scope,
    )
    plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    binding = bind_lifecycle(plan)
    owned = Records(OwnedRecord(
        "managed-root", "checkpoint", 0, 0, "7" * 64, identity.bundle_sha256,
        identity.reducer_version, c.public_object({
            "schema": "i02-managed-generations-v1", "root_manifest": root_manifest, "generations": (),
        }), identity,
    ))
    state, review = ManagedState(owned, binding), Review()
    consent = TrustedLifecycleConsentAdapter(review)
    broker = AuthorizationBroker(
        object(), TrustedConsentAdapter(review), lifecycle_state=state, lifecycle_consent=consent,
    )
    facts = lc.DecisionFacts(c.public_object({
        "binding": {"input_valid": True, "plan_current": True, "policy_current": True},
        "request": {"area": "setup", "operation": "install", "mode": "apply"},
        "control": {"cancelled": False, "remaining_ms": 10000},
        "consent": {"present": True, "binding_matches": True, "effects_match": True,
                    "recovery_matches": True, "remaining_ms": 10000},
        "consequential": {"required": False, "granted": False},
        "ownership": {"valid": True}, "lifecycle": {"next_effect_kind": "dependency-stage"},
    }))
    event = lc.DecisionEvent(
        str(uuid4()), lc.EventKind.INSTALL_CONSENTED, 0, plan.plan_digest,
        plan.context_digest, identity.bundle_sha256, "managed-root", "stage-tree",
        c.public_object({
            "lifecycle_kind": "install", "plan_id": plan.plan_id,
            "lifecycle_binding_digest": c.digest(binding), "private_consent_reference": "unit-private",
        }), install_id=plan.lifecycle_id,
    )
    decision = engine.decide(event, facts)
    grant = broker.issue_lifecycle(plan, consent.review(plan, 10.0, 20.0), decision, 10.0)
    session = broker.consume_lifecycle(grant, binding, 10.0)
    occurrence = lc.LifecycleEffectBinding(binding, str(uuid4()), 0, "stage-tree")
    permit = broker.permit_lifecycle(session, occurrence, 10.0)
    files, events = Files(), Events()
    handler = ManagedGenerationHandler(owned, files, broker, Clock(), events)
    return handler, manifest, content, permit, occurrence, owned, files, events


def test_actual_private_broker_stages_real_manifest_format_and_completes_once(policy):
    handler, manifest, content, permit, effect, owned, files, events = admitted(policy)
    receipt = handler.stage(manifest, content, permit, effect, Cancel())
    assert receipt.content_digest == manifest.content_digest
    assert files.calls == ["stage", "verify"]
    assert owned.record.payload["generations"][0]["state"] == "staged"
    assert owned.record.payload["generations"][0]["manifest"]["schema"] == "i02-managed-generation-v1"
    assert handler.complete(permit) == receipt
    assert len(owned.writes) == 4  # reserve, staging intent, staged CAS, factual completion
    assert events.records[-1].status == c.OutcomeStatus.SUCCEEDED
    with pytest.raises(AuthorizationError):
        handler.complete(permit)
    with pytest.raises(AuthorizationError):
        handler.stage(manifest, content, permit, effect, Cancel())
    assert files.calls == ["stage", "verify"]


def test_inert_a02_schema_cannot_be_relabelled_as_managed_ownership(policy):
    handler, manifest, content, permit, effect, owned, files, _ = admitted(policy)
    owned.record = replace(owned.record, payload=c.public_object({
        **dict(owned.record.payload), "schema": "a02-owned-inert-v1",
    }))
    before = len(owned.writes)
    with pytest.raises(AuthorizationError):
        handler.stage(manifest, content, permit, effect, Cancel())
    assert len(owned.writes) == before and not files.calls


def test_corrupt_content_never_enters_or_records_generation(policy):
    handler, manifest, content, permit, effect, owned, files, _ = admitted(policy)
    before = len(owned.writes)
    with pytest.raises(c.ContractError):
        handler.stage(manifest, content + b"x", permit, effect, Cancel())
    assert len(owned.writes) == before and not files.calls


def test_failed_stage_retains_intent_without_false_staged_or_completion(policy):
    handler, manifest, content, permit, effect, owned, files, _ = admitted(policy)
    files.fail = True
    with pytest.raises(ArtifactError) as raised:
        handler.stage(manifest, content, permit, effect, Cancel())
    assert raised.value.error.reason == c.ReasonCode.PROVISION_FAILED
    assert owned.record.payload["generations"][0]["state"] == "staging"
    with pytest.raises(AuthorizationError):
        handler.complete(permit)


def test_throwing_observation_does_not_replace_actual_managed_stage(policy):
    handler, manifest, content, permit, effect, _, _, events = admitted(policy)
    events.fail = True
    receipt = handler.stage(manifest, content, permit, effect, Cancel())
    assert handler.complete(permit) == receipt


def test_managed_stage_uses_same_latched_clock_guard_before_any_write(policy, monkeypatch):
    handler, manifest, content, permit, effect, owned, files, _ = admitted(policy)
    readings = iter((10.0, 5.0))
    monkeypatch.setattr(handler._clock, "monotonic", lambda: next(readings))
    before = len(owned.writes)
    with pytest.raises(c.ContractError):
        handler.stage(manifest, content, permit, effect, Cancel())
    assert len(owned.writes) == before
    assert not files.calls and not handler._pending


def test_clock_rollback_after_file_verification_never_claims_staged_success(policy, monkeypatch):
    handler, manifest, content, permit, effect, owned, files, _ = admitted(policy)

    class MutableClock(Clock):
        value = 10.0

        def monotonic(self):
            return self.value

    clock = MutableClock()
    handler._clock = clock
    original = files.verify

    def verify(*args):
        original(*args)
        clock.value = 5.0

    monkeypatch.setattr(files, "verify", verify)
    with pytest.raises(c.ContractError):
        handler.stage(manifest, content, permit, effect, Cancel())
    assert files.calls == ["stage", "verify"]
    assert owned.record.payload["generations"][0]["state"] == "staging"
    assert not handler._pending


def test_real_broker_stage_and_completion_do_not_require_a_reentrant_os_root_lock(policy):
    handler, manifest, content, permit, effect, owned, files, _ = admitted(policy)

    class RejectNestedRoot:
        def __init__(self):
            self.lock = threading.Lock()

        def __enter__(self):
            if not self.lock.acquire(blocking=False):
                raise RuntimeError("Nested OS root acquisition is not allowed")
            return self

        def __exit__(self, *args):
            self.lock.release()

    owned.mutex = RejectNestedRoot()
    receipt = handler.stage(manifest, content, permit, effect, Cancel())
    assert files.calls == ["stage", "verify"]
    assert handler.complete(permit) == receipt


@pytest.mark.parametrize("change", (
    {"cancelled": True}, {"setup_enabled": False}, {"owned_valid": False},
    {"pins_valid": False}, {"probes_valid": False}, {"cancelled": 1},
    {"revision": 99},
))
def test_current_root_facts_are_rechecked_after_broker_entry_before_writes(policy, monkeypatch, change):
    handler, manifest, content, permit, effect, owned, files, _ = admitted(policy)
    state = handler._authorization._lifecycle_state
    original = state.snapshot_lifecycle
    calls = [0]

    def snapshot(binding):
        calls[0] += 1
        current = original(binding)
        return replace(current, **change) if calls[0] == 2 else current

    monkeypatch.setattr(state, "snapshot_lifecycle", snapshot)
    before = len(owned.writes)
    with pytest.raises((c.ContractError, AuthorizationError)):
        handler.stage(manifest, content, permit, effect, Cancel())
    assert len(owned.writes) == before and not files.calls
