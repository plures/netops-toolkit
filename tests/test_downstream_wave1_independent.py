"""Independent task-criteria probes; synthetic ports never qualify a platform."""

from __future__ import annotations

import copy
import hashlib
import json
import pickle
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.artifacts import (
    ArtifactError,
    ArtifactStore,
    LocalProtectedFilesystem,
    OwnedRecord,
    validate_member_path,
)
from netops.ansible.credentials import (
    CredentialError,
    CredentialScope,
    CredentialTarget,
    RouteBinding,
    ScopedCredentialResolver,
    UnlockSession,
)
from netops.ansible.policy.authorization import (
    AdmissionSnapshot,
    AuthorizationBroker,
    AuthorizationError,
    TrustedConsentAdapter,
    bind_plan,
)
from netops.ansible.policy.contracts import (
    MAX_SAFE_INT,
    DecisionResult,
    EffectDescriptor,
    FrozenObject,
    PolicyIdentity,
)
from netops.ansible.workflows import plan_digest
from netops.core.vault import CredentialVault
from netops.dependencies import DependencyRegistry, RegistryError

D = "a" * 64


@pytest.fixture
def identity():
    root = Path("netops") / "ansible" / "policy"
    bundle = (root / "bundle.json").read_bytes()
    parsed = json.loads(bundle)
    return PolicyIdentity(
        parsed["canonical_revision"],
        hashlib.sha256((root / "ansible_molecule.px").read_bytes()).hexdigest(),
        hashlib.sha256((root / "ansible_molecule.contracts.px").read_bytes()).hexdigest(),
        hashlib.sha256(bundle).hexdigest(),
        tuple(item["id"] for item in parsed["manifest"]),
        parsed["reducer_version"],
    )


class HostState:
    def __init__(self, binding):
        self.binding = binding
        self.revision = 0
        self.cancelled = False
        self.mutex = threading.RLock()

    def lock(self, operation_id):
        return self.mutex

    def snapshot(self, operation_id):
        return AdmissionSnapshot(self.binding, self.revision, self.cancelled, True)

    def compare_revision(self, operation_id, expected_revision, next_revision):
        if self.revision != expected_revision:
            return False
        self.revision = next_revision
        return True


@pytest.fixture
def admission(identity):
    effects = tuple(c.PlannedEffect(f"occ-{i}", i, "gather", "r1", f"step-{i}") for i in range(2))
    plan = c.OperationPlan(
        str(uuid4()), "health.gather", c.Mode.OBSERVE, ("r1",),
        (FrozenObject((("target_id", "r1"),)),),
        c.Context("controller", D, "fixture", D, identity, D, D),
        D, D, identity.bundle_sha256, identity.reducer_version, effects, (), (),
        FrozenObject(), c.OutputIntent(), 1, 10000, (), D,
    )
    plan = replace(plan, plan_digest=plan_digest(plan))
    binding = bind_plan(plan, "private-root", 0)
    state = HostState(binding)
    adapter = TrustedConsentAdapter(Mock(confirm=Mock(return_value=True)))
    broker = AuthorizationBroker(state, adapter)
    decision = DecisionResult(
        "allow", ("test.independent",), "allowed",
        tuple(EffectDescriptor("request_effect", FrozenObject((("kind", e.kind),))) for e in effects),
        plan.policy_digest,
    )
    grant = broker.issue(plan, adapter.review(plan, binding, 10.0, 5.0), decision, 10.0)
    return broker, state, binding, grant


def effect(binding, index=0, revision=0):
    return c.EffectBinding(
        binding, str(uuid4()), revision, f"occ-{index}", "r1", f"step-{index}", (),
    )


def test_a01_concurrent_consume_and_occurrence_reservation(admission):
    broker, state, binding, grant = admission

    def race(action):
        barrier = threading.Barrier(2)

        def attempt(_):
            barrier.wait(timeout=3)
            try:
                return action()
            except AuthorizationError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            return list(pool.map(attempt, range(2)))

    sessions = race(lambda: broker.consume(grant, binding, 11.0))
    assert sum(value is not None for value in sessions) == 1
    session = next(value for value in sessions if value is not None)
    permits = race(lambda: broker.permit(session, effect(binding), 12.0))
    assert sum(value is not None for value in permits) == 1
    assert state.revision == 1


@pytest.mark.parametrize("field", tuple(c.PlanBinding.__dataclass_fields__))
def test_a01_every_binding_dimension_rejected_without_spending(admission, field):
    broker, state, binding, grant = admission
    changes = {"operation_id": str(uuid4()), "root_ref": "other", "generation": 1,
               "recovery_scope": ("other",)}
    changed = replace(binding, **{field: changes.get(field, "b" * 64)})
    with pytest.raises(AuthorizationError):
        broker.consume(grant, changed, 11.0)
    assert state.revision == 0
    assert isinstance(broker.consume(grant, binding, 11.0), c.AdmissionSession)


def test_a01_forged_instance_and_serialization_never_transfer_authority(admission):
    broker, _, binding, grant = admission
    with pytest.raises(AuthorizationError):
        broker.consume(object.__new__(type(grant)), binding, 11.0)
    for serializer in (pickle.dumps, copy.copy, copy.deepcopy, c.public_object):
        with pytest.raises((TypeError, ValueError)):
            serializer(grant)


def test_a01_cancel_after_reservation_prevents_entry_but_retains_reconciliation(admission):
    broker, state, binding, grant = admission
    session = broker.consume(grant, binding, 11.0)
    selected = effect(binding)
    permit = broker.permit(session, selected, 12.0)
    broker.revoke(binding.operation_id)
    with pytest.raises(AuthorizationError):
        broker.enter(permit, selected, 12.1)
    assert broker.reconcile(permit) == selected
    assert state.revision == 1
    assert broker.is_revoked(binding.operation_id)


def test_a01_revision_exhaustion_does_not_disable_revoke(admission):
    broker, state, binding, grant = admission
    session = broker.consume(grant, binding, 11.0)
    state.revision = MAX_SAFE_INT - 1
    broker.permit(session, effect(binding, revision=MAX_SAFE_INT - 1), 12.0)
    with pytest.raises(AuthorizationError):
        broker.permit(session, effect(binding, 1, MAX_SAFE_INT), 12.0)
    broker.revoke(binding.operation_id)
    assert broker.is_revoked(binding.operation_id)
    assert state.revision == MAX_SAFE_INT


@pytest.mark.parametrize("now", [15.0, float("nan"), float("inf")])
def test_a01_original_deadline_not_renewed(admission, now):
    broker, state, binding, grant = admission
    session = broker.consume(grant, binding, 14.0)
    with pytest.raises(AuthorizationError):
        broker.permit(session, effect(binding), now)
    assert state.revision == 0


@pytest.mark.parametrize("damage", ["adapter", "cycle", "consumer", "collection"])
def test_i01_registry_rejects_unregistered_execution_or_missing_consumers(damage):
    root = Path("netops") / "dependencies"
    registry = json.loads((root / "registry.json").read_text())
    operations = json.loads((root / "operations.json").read_text())
    qualification = json.loads((root / "qualification.json").read_text())
    if damage == "adapter":
        registry["entries"][0]["adapter"] = "arbitrary-shell"
    elif damage == "cycle":
        registry["entries"][0]["requires"] = [registry["entries"][0]["id"]]
    elif damage == "consumer":
        registry["entries"][0]["consumers"] = []
    else:
        next(x for x in registry["entries"] if x["id"] == "ansible.netcommon")["kind"] = "pip"
    with pytest.raises(RegistryError):
        DependencyRegistry.from_data(registry, operations, qualification)


def test_i01_actual_public_surfaces_and_empty_qualification():
    registry = DependencyRegistry.load()
    registry.validate_public_sources(Path("netops"))
    assert registry.qualification["qualified"] == []
    assert not registry.is_qualified({"os": "Windows", "core": ">=2.16"})
    with pytest.raises(RegistryError):
        registry.validate_exports({"netops.report.mailer": ("unregistered_public_function",)})


def test_i01_current_packaging_contains_no_galaxy_collection_as_pip():
    """This AC must pass against the actual manifest, not a locally repaired string."""
    DependencyRegistry.load().validate_package_metadata(Path("pyproject.toml").read_text("utf-8"))


@pytest.mark.parametrize("content", [b'{"password":"redacted-fixture"}',
                                     b"snmp-server community redacted-fixture ro"],
                         ids=["json-secret-field", "snmp-secret-line"])
def test_c02_public_secret_rejected_before_any_filesystem_operation(content):
    fs, events = Mock(), Mock()
    store = ArtifactStore(fs, Mock(monotonic=Mock(return_value=10.0)), events)
    plan = c.PlanBinding(str(uuid4()), *((D,) * 7), "root", 0, ())
    binding = c.ArtifactBinding(effect(plan), "public")
    with pytest.raises(ArtifactError):
        store.publish(c.OutputIntent(("text",), "root"), content, binding)
    fs.validate.assert_not_called()
    fs.publish.assert_not_called()
    assert content.decode() not in repr(events.mock_calls)


def test_c02_native_protection_enforced_or_fails_closed(tmp_path):
    import os
    import sys

    if os.name != "posix" or sys.platform == "darwin":
        with pytest.raises(ArtifactError):
            LocalProtectedFilesystem().validate(c.OutputIntent(("text",), str(tmp_path)))
        assert not list(tmp_path.iterdir())
    else:
        tmp_path.chmod(0o700)
        root = LocalProtectedFilesystem().validate(c.OutputIntent(("text",), str(tmp_path)))
        assert root.permissions_proof == "posix-owner-0700-0600"


@pytest.mark.parametrize("field,value", [
    ("schema_version", "2.0"), ("revision", True), ("revision", MAX_SAFE_INT + 1),
    ("generation", -1), ("ownership_token", "untrusted"),
], ids=["unknown-major", "boolean-revision", "overflow", "negative-generation", "bad-owner"])
def test_c02_owned_metadata_corruption_rejected_before_hydration(identity, field, value):
    record = OwnedRecord(
        "active", "active", 0, 0, D, identity.bundle_sha256, identity.reducer_version,
        c.public_object({
            "environment_id": "env-1", "prior_id": None, "content_digest": D,
            "state_revision": 0,
        }), identity,
    )
    serialized = json.loads(record.to_bytes())
    serialized[field] = value
    with pytest.raises(ArtifactError):
        OwnedRecord.from_bytes(json.dumps(serialized).encode())


@pytest.mark.parametrize("member", ["../escape", "/absolute", "C:\\escape", "a/../../escape"])
def test_c02_archive_escape_rejected(member):
    with pytest.raises(ArtifactError):
        validate_member_path(member)


class CredentialHost:
    def __init__(self):
        self.live = True

    @contextmanager
    def admit(self, scope):
        if not self.live:
            raise RuntimeError("cancelled")
        yield

    validate = admit


@pytest.fixture
def credentials(identity, tmp_path, monkeypatch):
    monkeypatch.setenv("NETOPS_CRED_WAVE1_USER", "fixture-user")
    monkeypatch.setenv("NETOPS_CRED_WAVE1_PASS", "fixture-value")
    target = CredentialTarget(
        "wave1", "health", "wave1", "192.0.2.55", "cisco_ios", "ssh", 22,
        (), ("username",), known_hosts_ref="controller-known-hosts",
    )
    scope = CredentialScope(
        str(uuid4()), c.ControllerContext(c.Context("controller", D, "fixture", D, identity, D, D)),
        D, D, (target,), 20.0,
    )
    route = RouteBinding(D, D, scope.targets, D, True, True, "reject", True)
    routes = Mock(validate=Mock(return_value=route))
    clock = Mock(monotonic=Mock(return_value=10.0))
    host = CredentialHost()
    resolver = ScopedCredentialResolver(CredentialVault(tmp_path / "never-created"), routes, clock)
    return resolver, scope, host, routes, clock


def test_s01_private_minimal_frame_single_use_and_no_vault_write(credentials, tmp_path):
    resolver, scope, host, _, _ = credentials
    value = resolver.resolve(scope, UnlockSession(scope, None, host))
    assert repr(value) == "<private>"
    for serializer in (pickle.dumps, copy.copy, c.public_object):
        with pytest.raises((TypeError, ValueError)):
            serializer(value)
    payload = json.loads(value._protected_payload(scope))
    assert payload["targets"][0]["fields"] == {"username": "fixture-user"}
    with pytest.raises(CredentialError):
        value._protected_payload(scope)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("mutation", ["host", "controller", "route", "fields", "cancel", "expiry"])
def test_s01_bound_identity_and_current_authority_rechecked_at_delivery(credentials, mutation):
    resolver, scope, host, routes, clock = credentials
    value = resolver.resolve(scope, UnlockSession(scope, None, host))
    if mutation == "host":
        scope = replace(scope, targets=(replace(scope.targets[0], host="192.0.2.56"),))
    elif mutation == "controller":
        scope = replace(scope, controller_digest="b" * 64)
    elif mutation == "route":
        routes.validate.return_value = replace(routes.validate.return_value, route_digest="b" * 64)
    elif mutation == "fields":
        scope = replace(scope, targets=(replace(scope.targets[0], fields=("password",)),))
    elif mutation == "cancel":
        host.live = False
    else:
        clock.monotonic.return_value = 20.0
    with pytest.raises(CredentialError):
        value._protected_payload(scope)
    resolver.revoke(scope.operation_id)
    resolver.revoke(scope.operation_id)
