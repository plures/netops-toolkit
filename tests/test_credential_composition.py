"""Offline tests of real A01 admission with S01 private credential composition."""

import json
import os
import pickle
import socket
import stat
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops.ansible import contracts as c
from netops.ansible.credentials import (
    CredentialError,
    CredentialScope,
    RouteBinding,
    ScopedCredentialResolver,
    UnlockSession,
)
from netops.ansible.policy.authorization import (
    AdmissionSnapshot,
    AuthorizationBroker,
    TrustedConsentAdapter,
    bind_plan,
)
from netops.ansible.policy.contracts import DecisionResult, EffectDescriptor, FrozenObject
from netops.ansible.workflows import plan_digest

pytest_plugins = ("tests.test_scoped_credentials",)
SENTINEL = "SYNTHETIC-S01-only-credential"
MASTER = "SYNTHETIC-S01-only-master"
D = "a" * 64


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        ("key", ("transport", "route-unavailable", "connect")),
        ("known-host", ("transport", "host-key-invalid", "connect")),
        ("scope", ("credentials", "credential-scope-invalid", "controller")),
    ],
)
def test_actual_adapter_failures_preserve_complete_safe_error(composition, vault, failure, expected):
    scope, _, state, _, _, clock, admission, routes, root = composition
    if failure == "key":
        (root / "key").unlink()
    elif failure == "known-host":
        (root / "hosts").write_text("synthetic-changed-known-hosts", encoding="utf-8")
    else:
        scope = replace(scope, targets=(replace(scope.targets[0], fields=("username",)),))
    resolver = ScopedCredentialResolver(vault, routes, clock)
    with pytest.raises(CredentialError) as caught:
        resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    error = caught.value.error
    assert (error.category.value, error.reason.value, error.stage.value) == expected
    assert str(caught.value) == expected[1]
    assert state.advances == ([] if failure == "scope" else [(0, 1)])


class State:
    def __init__(self, binding):
        self.binding = binding
        self.revision = 0
        self.cancelled = False
        self.dispatch_enabled = True
        self.mutex = threading.RLock()
        self.advances = []

    def lock(self, operation_id):
        return self.mutex

    def snapshot(self, operation_id):
        assert operation_id == self.binding.operation_id
        return AdmissionSnapshot(self.binding, self.revision, self.cancelled, self.dispatch_enabled)

    def compare_revision(self, operation_id, expected_revision, next_revision):
        if self.revision != expected_revision:
            return False
        self.advances.append((expected_revision, next_revision))
        self.revision = next_revision
        return True


class Review:
    def confirm(self, plan, binding, deadline):
        return True


class Clock:
    value = 10.0

    def monotonic(self):
        return self.value


@pytest.fixture(autouse=True)
def forbid_effects(monkeypatch, request):
    # This module is also a pytest plugin; exported autouse fixtures are global.
    if request.module.__name__ != __name__ and "composition" not in request.fixturenames:
        yield
        return

    def forbidden(*args, **kwargs):
        pytest.fail("composition test attempted process/network/bastion activity")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr("netops.core.bastion.active_bastion", forbidden)
    yield


@pytest.fixture
def composition(scope, owned_root):
    from netops.ansible.credential_admission import HostCredentialAdmission
    from netops.ansible.credential_routes import ApprovedRouteFile, ControllerOriginRoutePolicy

    target = replace(scope.targets[0], task_id="resolve", known_hosts_ref="hosts", key_ref="key")
    route = c.public_object({
        "target_id": target.target_id, "resolved": True, "host": target.host,
        "port": target.port, "vendor": target.vendor, "transport": target.transport,
        "controller_id": scope.context.context.controller_id,
        "route_digest": scope.route_digest,
    })
    effect = c.PlannedEffect("resolve-1", 0, "resolve-for-run", target.target_id, target.task_id)
    plan = c.OperationPlan(
        scope.operation_id, "vault.resolve-for-run", c.Mode.OBSERVE, (target.target_id,),
        (route,), scope.context.context, D, D, scope.context.context.policy_identity.bundle_sha256,
        scope.context.context.policy_identity.reducer_version, (effect,), (), (),
        FrozenObject(), c.OutputIntent(), 1, 10000, (), D,
    )
    plan = replace(plan, plan_digest=plan_digest(plan))
    binding = bind_plan(plan, "synthetic-owned-root", 0)
    state = State(binding)
    consent = TrustedConsentAdapter(Review())
    broker = AuthorizationBroker(state, consent)
    decision = DecisionResult(
        "allow", ("netops.companion.test",), "allowed",
        (EffectDescriptor("request_effect", FrozenObject((("kind", "resolve-for-run"),))),),
        plan.policy_digest,
    )
    receipt = consent.review(plan, binding, 10.0, 10.0)
    session = broker.consume(broker.issue(plan, receipt, decision, 10.0), binding, 10.0)
    scope = CredentialScope(
        scope.operation_id, scope.context, binding.controller_digest, scope.route_digest,
        (target,), 20.0,
    )
    clock = Clock()
    admission = HostCredentialAdmission(broker, session, plan, scope, clock)
    files = []
    for ref, purpose in (("hosts", "known-hosts"), ("key", "private-key")):
        path = owned_root / ref
        path.write_text("synthetic-public-metadata-fixture", encoding="utf-8")
        path.chmod(0o600)
        files.append(ApprovedRouteFile.observe(ref, path, purpose))
    approved = RouteBinding(
        scope.controller_digest, scope.route_digest, scope.targets, D, True, True, "reject", True,
    )
    routes = ControllerOriginRoutePolicy(scope.context, approved, tuple(files))
    return scope, plan, state, broker, session, clock, admission, routes, owned_root


def resolve(composition, vault):
    scope, _, _, _, _, clock, admission, routes, _ = composition
    resolver = ScopedCredentialResolver(vault, routes, clock)
    return resolver, resolver.resolve(scope, UnlockSession(scope, MASTER, admission))


def test_real_broker_resolution_delivery_is_non_consuming_and_one_use(composition, vault):
    scope, _, state, broker, _, _, admission, _, _ = composition
    resolver, value = resolve(composition, vault)
    assert state.advances == [(0, 1)]
    with admission.validate(scope):
        pass
    with admission.validate(scope):
        pass
    assert state.advances == [(0, 1)]
    payload = value._protected_payload(scope)
    assert json.loads(payload)["targets"][0]["fields"]["password"] == SENTINEL + "-device"
    assert state.advances == [(0, 1)]
    assert len(broker._pending) == 1
    with pytest.raises(CredentialError):
        value._protected_payload(scope)
    resolver.revoke(scope.operation_id)


@pytest.mark.parametrize("change", ["deadline", "cancel", "revoke", "kill", "binding", "clock-back"])
def test_live_original_host_authority_blocks_delivery(composition, vault, change):
    scope, _, state, broker, _, clock, _, _, _ = composition
    _, value = resolve(composition, vault)
    if change == "deadline":
        clock.value = 20.0
    elif change == "cancel":
        state.cancelled = True
    elif change == "revoke":
        broker.revoke(scope.operation_id)
    elif change == "kill":
        state.dispatch_enabled = False
    elif change == "binding":
        state.binding = replace(state.binding, generation=1)
    else:
        clock.value = 9.0
    with pytest.raises(CredentialError) as caught:
        value._protected_payload(scope)
    assert SENTINEL not in str(caught.value)
    assert state.advances == [(0, 1)]
    with pytest.raises(CredentialError):
        value._protected_payload(scope)


@pytest.mark.parametrize("change", ["host", "task", "fields", "controller", "expiry"])
def test_scope_mutation_cannot_open_vault_or_reserve_effect(composition, vault, monkeypatch, change):
    scope, _, state, _, _, clock, admission, routes, _ = composition
    target = scope.targets[0]
    changed = {
        "host": replace(scope, targets=(replace(target, host="192.0.2.77"),)),
        "task": replace(scope, targets=(replace(target, task_id="other"),)),
        "fields": replace(scope, targets=(replace(target, fields=("enable_password",)),)),
        "controller": replace(scope, controller_digest="b" * 64),
        "expiry": replace(scope, expires_at=100.0),
    }[change]

    def forbidden():
        pytest.fail("rejected scope reached vault")

    monkeypatch.setattr(vault, "private_session", forbidden)
    resolver = ScopedCredentialResolver(vault, routes, clock)
    with pytest.raises(CredentialError):
        resolver.resolve(changed, UnlockSession(changed, MASTER, admission))
    assert state.advances == []


def test_forged_session_and_wrong_effect_do_not_reserve(composition):
    from netops.ansible.credential_admission import HostCredentialAdmission

    scope, plan, state, broker, session, clock, _, _, _ = composition
    for forged in (True, object(), object.__new__(type(session))):
        with pytest.raises(CredentialError):
            HostCredentialAdmission(broker, forged, plan, scope, clock)
    changed = replace(plan, effects=(replace(plan.effects[0], kind="gather"),))
    changed = replace(changed, plan_digest=plan_digest(changed))
    with pytest.raises(CredentialError):
        HostCredentialAdmission(broker, session, changed, scope, clock)
    assert state.advances == []


@pytest.mark.parametrize("change", ["known-hosts", "key", "missing", "directory"])
def test_changed_origin_files_reject_before_vault_access(composition, vault, monkeypatch, change):
    scope, _, state, _, _, clock, admission, routes, root = composition
    path = root / ("key" if change == "key" else "hosts")
    if change in ("missing", "directory"):
        path.unlink()
        if change == "directory":
            path.mkdir()
    else:
        path.write_text("changed-approved-file", encoding="utf-8")

    def forbidden():
        pytest.fail("route rejection reached vault")

    monkeypatch.setattr(vault, "private_session", forbidden)
    with pytest.raises(CredentialError):
        ScopedCredentialResolver(vault, routes, clock).resolve(
            scope, UnlockSession(scope, MASTER, admission),
        )
    # Admission occurred, but no secret or delivery was produced.
    assert state.advances == [(0, 1)]


def test_origin_and_references_cannot_be_substituted(composition):
    scope, _, _, _, _, _, _, routes, _ = composition
    changed = c.ControllerContext(replace(scope.context.context, controller_id="other-controller"))
    with pytest.raises(CredentialError):
        routes.validate(changed, scope)
    changed = replace(scope, targets=(replace(scope.targets[0], key_ref="unapproved"),))
    with pytest.raises(CredentialError):
        routes.validate(scope.context, changed)


def test_key_files_are_metadata_only_and_never_copied(composition, vault, monkeypatch):
    import netops.ansible.credential_routes as routes_module

    def forbidden(*args, **kwargs):
        pytest.fail("route adapter read private key bytes")

    monkeypatch.setattr(routes_module.os, "read", forbidden)
    before_env = dict(os.environ)
    scope = composition[0]
    _, value = resolve(composition, vault)
    raw = value._protected_payload(scope)
    assert b"synthetic-public-metadata-fixture" not in raw
    assert MASTER.encode() not in raw
    assert dict(os.environ) == before_env


def test_concurrent_resolution_reserves_exactly_once(composition, vault):
    scope, _, state, _, _, clock, admission, routes, _ = composition
    resolver = ScopedCredentialResolver(vault, routes, clock)
    barrier = threading.Barrier(2)

    def attempt(_):
        barrier.wait()
        try:
            return resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
        except CredentialError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, range(2)))
    assert sum(value is not None for value in results) == 1
    assert state.advances == [(0, 1)]
    resolver.revoke(scope.operation_id)


@pytest.mark.parametrize("change", ["cancel", "expiry"])
def test_guard_exit_rejection_drops_newly_resolved_private_buffers(composition, vault, monkeypatch, change):
    scope, _, state, _, _, clock, admission, routes, _ = composition
    original = vault.private_session

    @contextmanager
    def changed_during_read():
        with original() as reader:
            yield reader
        if change == "cancel":
            state.cancelled = True
        else:
            clock.value = 20.0

    monkeypatch.setattr(vault, "private_session", changed_during_read)
    resolver = ScopedCredentialResolver(vault, routes, clock)
    with pytest.raises(CredentialError):
        resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    assert resolver._values == {}
    with pytest.raises(CredentialError):
        with admission.validate(scope):
            pytest.fail("post-failure private delivery became available")


def test_original_deadline_cannot_be_extended_by_new_scope(composition):
    from netops.ansible.credential_admission import HostCredentialAdmission

    scope, plan, state, broker, session, clock, _, _, _ = composition
    with pytest.raises(CredentialError):
        HostCredentialAdmission(broker, session, plan, replace(scope, expires_at=21.0), clock)
    assert state.advances == []


def test_delivery_validation_holds_host_lock_without_another_reservation(composition, vault):
    scope, _, state, _, _, _, admission, _, _ = composition
    resolver, _ = resolve(composition, vault)
    started = threading.Event()
    acquired = threading.Event()

    def writer():
        started.set()
        with state.mutex:
            acquired.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with admission.validate(scope):
            future = pool.submit(writer)
            assert started.wait(2)
            assert not acquired.is_set()
            assert state.advances == [(0, 1)]
        future.result(timeout=2)
    assert acquired.is_set()
    resolver.revoke(scope.operation_id)


@pytest.mark.parametrize("flag", ["private_channel_qualified", "keys_accessible", "controller_local"])
def test_origin_adapter_never_promotes_unqualified_route(composition, flag):
    from netops.ansible.credential_routes import ControllerOriginRoutePolicy

    scope, _, _, _, _, _, _, routes, _ = composition
    approved = replace(routes._approved, **{flag: False})
    unqualified = ControllerOriginRoutePolicy(scope.context, approved, routes._files)
    with pytest.raises(CredentialError):
        unqualified.validate(scope.context, scope)


def test_origin_parent_symlink_is_rejected_without_opening_key(composition, monkeypatch):
    import netops.ansible.credential_routes as module

    scope, _, _, _, _, _, _, routes, root = composition
    original = Path.lstat

    def alias(path):
        if path == root:
            return SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
        return original(path)

    def forbidden(*args, **kwargs):
        pytest.fail("symlink route reached file open")

    monkeypatch.setattr(Path, "lstat", alias)
    monkeypatch.setattr(module.os, "open", forbidden)
    with pytest.raises(CredentialError):
        routes.validate(scope.context, scope)


def test_route_rejection_pairs_safe_metric_and_log_once(composition, vault, caplog):
    scope, _, _, _, _, _, admission, routes, root = composition
    (root / "hosts").write_text("changed-only-fixture", encoding="utf-8")
    with pytest.raises(CredentialError):
        resolve(composition, vault)
    assert routes._telemetry.counters() == (("credential-route", "host-key-invalid", 1),)
    assert admission._telemetry.counters() == ()
    records = [record for record in caplog.records if record.msg == "credential.rejected"]
    assert len(records) == 1
    assert records[0].metric == "credential_rejections_total"
    assert records[0].stage == "credential-route"
    assert records[0].reason == "host-key-invalid"
    assert SENTINEL not in caplog.text
    assert MASTER not in caplog.text
    assert str(root) not in caplog.text
    assert scope.operation_id not in caplog.text


def test_saturated_observation_does_not_restore_host_authority(composition, vault, caplog):
    scope, _, state, _, _, _, admission, _, _ = composition
    state.cancelled = True
    admission._telemetry._counts[("credential-admission", "credential-scope-invalid")] = 9007199254740991
    for _ in range(2):
        with pytest.raises(CredentialError):
            resolve(composition, vault)
    saturation = [record for record in caplog.records if record.msg == "credential.telemetry.saturated"]
    assert len(saturation) == 1
    assert saturation[0].metric == "credential_telemetry_saturated"
    assert saturation[0].outcome == "Failure"
    assert state.advances == []
    assert SENTINEL not in caplog.text


@pytest.mark.parametrize("kind", ["unc", "alternate-stream"])
def test_nonlocal_and_alternate_stream_paths_reject_before_filesystem_probe(composition, monkeypatch, kind):
    from netops.ansible.credential_routes import ApprovedRouteFile

    root = composition[-1]
    path = Path(r"\\untrusted.invalid\share\key") if kind == "unc" else root / "key:stream"

    def forbidden(*args, **kwargs):
        pytest.fail("unapproved network/device path reached filesystem")

    monkeypatch.setattr(Path, "lstat", forbidden)
    with pytest.raises(CredentialError):
        ApprovedRouteFile.observe("key", path, "private-key")


def test_actual_admission_adapter_cannot_be_serialized_or_reconstructed(composition):
    admission = composition[6]
    with pytest.raises(TypeError):
        pickle.dumps(admission)
    with pytest.raises(c.ContractError):
        c.public_object({"admission": admission})
