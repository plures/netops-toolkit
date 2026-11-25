"""Synthetic-only tests for the S01 private resolver boundary."""

import copy
import hashlib
import json
import os
import pickle
import shutil
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, replace
from pathlib import Path
from uuid import uuid4

import pytest

from netops.ansible.contracts import Context, ControllerContext, ReasonCode, public_object
from netops.ansible.credentials import (
    CredentialError,
    CredentialScope,
    CredentialTarget,
    RouteBinding,
    ScopedCredentialResolver,
    UnlockSession,
)
from netops.ansible.policy import PolicyIdentity
from netops.core.inventory import Device
from netops.core.vault import CredentialVault

D = "a" * 64
OTHER = "b" * 64
SENTINEL = "SYNTHETIC-S01-only-credential"
MASTER = "SYNTHETIC-S01-only-master"


class Clock:
    def __init__(self):
        self.value = 10.0

    def monotonic(self):
        return self.value


class Admission:
    def __init__(self, scope):
        self.scope = scope
        self.allowed = True
        self.calls = 0
        self.active = False

    @contextmanager
    def admit(self, scope):
        self.calls += 1
        if not self.allowed or scope != self.scope:
            raise RuntimeError(SENTINEL)
        self.active = True
        try:
            yield
        finally:
            self.active = False

    @contextmanager
    def validate(self, scope):
        if not self.allowed or scope != self.scope:
            raise RuntimeError(SENTINEL)
        yield


class Routes:
    def __init__(self, scope, admission):
        self.binding = RouteBinding(D, D, scope.targets, D, True, True, "reject", True)
        self.admission = admission
        self.calls = 0
        self.failure = None

    def validate(self, context, scope):
        self.calls += 1
        if self.failure:
            raise RuntimeError(SENTINEL)
        assert context == scope.context
        return self.binding


@pytest.fixture(autouse=True)
def forbid_external_effects(monkeypatch, request):
    # Plugin registration must not turn this module's guard into a suite-wide ban.
    if request.module.__name__ != __name__:
        yield
        return

    def forbidden(*args, **kwargs):
        pytest.fail("credential unit test attempted a network/process/bastion effect")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr("netops.core.bastion.active_bastion", forbidden)
    for hostname in ("R1", "JUMP"):
        for field in ("USER", "PASS", "ENABLE"):
            monkeypatch.delenv(f"NETOPS_CRED_{hostname}_{field}", raising=False)
    yield


@pytest.fixture(scope="module")
def identity():
    root = Path(__file__).resolve().parents[1] / "netops" / "ansible" / "policy"
    source = (root / "ansible_molecule.px").read_bytes()
    contracts = (root / "ansible_molecule.contracts.px").read_bytes()
    bundle = (root / "bundle.json").read_bytes()
    parsed = json.loads(bundle)
    return PolicyIdentity(
        canonical_revision=parsed["canonical_revision"],
        source_sha256=hashlib.sha256(source).hexdigest(),
        contracts_sha256=hashlib.sha256(contracts).hexdigest(),
        bundle_sha256=hashlib.sha256(bundle).hexdigest(),
        rule_manifest=tuple(item["id"] for item in parsed["manifest"]),
        reducer_version=parsed["reducer_version"],
    )


@pytest.fixture
def scope(identity):
    target = CredentialTarget.from_device(
        Device("r1", "192.0.2.1", "cisco_ios", groups=["first", "second"]),
        "health", ("username", "password"), known_hosts_ref="controller-known-hosts",
    )
    return CredentialScope(
        str(uuid4()), ControllerContext(Context("controller", D, "fixture", D, identity, D, D)),
        D, D, (target,), 100.0,
    )


@pytest.fixture
def owned_root():
    root = Path(__file__).resolve().parents[1] / ".sdlc" / "s01-test-owned" / uuid4().hex
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        for attempt in range(3):
            try:
                shutil.rmtree(root)
                break
            except PermissionError:
                if attempt == 2:
                    raise
                time.sleep(0.2 * (attempt + 1))


@pytest.fixture
def vault(owned_root):
    selected = CredentialVault(owned_root / "synthetic-vault.yaml")
    selected.init(MASTER)
    selected.set_default("default-user", SENTINEL + "-default")
    selected.set_group("second", "second-user", SENTINEL + "-second")
    selected.set_group("first", "first-user", SENTINEL + "-first")
    selected.set_device("r1", "device-user", SENTINEL + "-device", SENTINEL + "-enable")
    selected.save(MASTER)
    return selected


def setup_resolver(vault, scope):
    clock = Clock()
    admission = Admission(scope)
    routes = Routes(scope, admission)
    return ScopedCredentialResolver(vault, routes, clock), admission, routes, clock


def consume(credentials, scope):
    return json.loads(credentials._protected_payload(scope))


def test_private_delivery_is_spent_before_host_guard_release(vault, scope, monkeypatch):
    resolver, admission, _, _ = setup_resolver(vault, scope)
    value = resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    original = admission.validate
    nested = []

    @contextmanager
    def release_boundary(selected):
        with original(selected):
            yield
        if not nested:
            nested.append("attempted")
            try:
                value._protected_payload(scope)
            except CredentialError:
                nested.append("rejected")
            else:
                nested.append("duplicate-secret")

    monkeypatch.setattr(admission, "validate", release_boundary)
    assert SENTINEL.encode() in value._protected_payload(scope)
    assert nested == ["attempted", "rejected"]


@pytest.mark.parametrize(
    ("removed_device", "groups", "env", "expected"),
    [
        (False, ("first", "second"), False, "device"),
        (True, ("first", "second"), False, "first"),
        (True, ("second", "first"), False, "second"),
        (True, (), False, "default"),
        (False, ("first", "second"), True, "environment"),
    ],
)
def test_native_encrypted_precedence(vault, scope, monkeypatch, removed_device, groups, env, expected):
    if removed_device:
        vault.delete_device("r1")
        vault.save(MASTER)
    scope = replace(scope, targets=(replace(scope.targets[0], groups=groups),))
    if env:
        monkeypatch.setenv("NETOPS_CRED_R1_USER", "env-user")
        monkeypatch.setenv("NETOPS_CRED_R1_PASS", SENTINEL + "-environment")
    resolver, admission, _, _ = setup_resolver(vault, scope)
    value = resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    assert SENTINEL not in repr(value)
    payload = consume(value, scope)
    assert payload["targets"][0]["fields"]["password"] == SENTINEL + "-" + expected
    assert set(payload["targets"][0]["fields"]) == {"username", "password"}
    assert admission.calls == 1


def test_environment_selected_before_unlock_and_without_vault_file(owned_root, scope, monkeypatch):
    vault = CredentialVault(owned_root / "does-not-exist")
    monkeypatch.setenv("NETOPS_CRED_R1_USER", "env-user")
    monkeypatch.setenv("NETOPS_CRED_R1_PASS", SENTINEL)
    resolver, admission, _, _ = setup_resolver(vault, scope)
    result = consume(resolver.resolve(scope, UnlockSession(scope, None, admission)), scope)
    assert result["targets"][0]["fields"]["password"] == SENTINEL
    assert not (owned_root / "does-not-exist").exists()


@pytest.mark.parametrize(
    ("password", "missing", "reason"),
    [
        (None, False, ReasonCode.VAULT_LOCKED),
        ("synthetic-wrong-password", False, ReasonCode.VAULT_PASSWORD_INVALID),
        (MASTER, True, ReasonCode.VAULT_MISSING),
    ],
)
def test_safe_distinct_unlock_errors(vault, scope, password, missing, reason, caplog):
    if missing:
        vault._path.unlink()
    resolver, admission, _, _ = setup_resolver(vault, scope)
    with pytest.raises(CredentialError) as caught:
        resolver.resolve(scope, UnlockSession(scope, password, admission))
    assert caught.value.error.reason is reason
    assert caught.value.error.category.value == "credentials"
    assert caught.value.error.stage.value == "credentials"
    assert SENTINEL not in str(caught.value)
    assert MASTER not in caplog.text
    # Native caller state is never changed by failed companion unlocks.
    assert vault.get_credentials("r1")["password"] == SENTINEL + "-device"


def test_only_selected_identity_and_fields_are_exported(vault, scope):
    vault.set_device("unselected", "forbidden-user", SENTINEL + "-unselected")
    vault.save(MASTER)
    scope = replace(scope, targets=(replace(scope.targets[0], fields=("username",)),))
    resolver, admission, _, _ = setup_resolver(vault, scope)
    payload = consume(resolver.resolve(scope, UnlockSession(scope, MASTER, admission)), scope)
    assert payload["targets"][0]["fields"] == {"username": "device-user"}
    assert "unselected" not in repr(payload)
    assert SENTINEL not in repr(payload)
    assert MASTER not in repr(payload)


def test_no_admission_means_no_route_or_vault_access(vault, scope, monkeypatch):
    resolver, admission, routes, _ = setup_resolver(vault, scope)
    admission.allowed = False

    def forbidden():
        pytest.fail("vault was accessed before host effect admission")

    monkeypatch.setattr(vault, "private_session", forbidden)
    with pytest.raises(CredentialError) as caught:
        resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    assert caught.value.error.reason is ReasonCode.CREDENTIAL_SCOPE_INVALID
    assert routes.calls == 0
    assert SENTINEL not in str(caught.value)


@pytest.mark.parametrize("change", ["operation", "controller", "route", "target", "task", "fields"])
def test_scope_substitution_rejected_before_access(vault, scope, change):
    resolver, admission, routes, _ = setup_resolver(vault, scope)
    session = UnlockSession(scope, MASTER, admission)
    changes = {
        "operation": lambda: replace(scope, operation_id=str(uuid4())),
        "controller": lambda: replace(scope, controller_digest=OTHER),
        "route": lambda: replace(
            scope, route_digest=OTHER,
            context=ControllerContext(replace(scope.context.context, route_digest=OTHER)),
        ),
        "target": lambda: replace(scope, targets=(replace(scope.targets[0], host="192.0.2.9"),)),
        "task": lambda: replace(scope, targets=(replace(scope.targets[0], task_id="other"),)),
        "fields": lambda: replace(scope, targets=(replace(scope.targets[0], fields=("password",)),)),
    }
    with pytest.raises(CredentialError):
        resolver.resolve(changes[change](), session)
    assert admission.calls == routes.calls == 0
    with pytest.raises(CredentialError):
        resolver.resolve(scope, session)


@pytest.mark.parametrize("now", [100.0, 101.0, float("nan"), float("inf")])
def test_expired_or_invalid_host_clock_blocks(vault, scope, now):
    resolver, admission, routes, clock = setup_resolver(vault, scope)
    clock.value = now
    with pytest.raises(CredentialError):
        resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    assert routes.calls == 0


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("controller_digest", OTHER, ReasonCode.ROUTE_UNAVAILABLE),
        ("route_digest", OTHER, ReasonCode.ROUTE_UNAVAILABLE),
        ("controller_local", False, ReasonCode.ROUTE_UNAVAILABLE),
        ("private_channel_qualified", False, ReasonCode.ROUTE_UNAVAILABLE),
        ("keys_accessible", False, ReasonCode.ROUTE_UNAVAILABLE),
        ("host_key_policy", "auto-add", ReasonCode.HOST_KEY_INVALID),
    ],
)
def test_route_rejects_weakened_or_changed_controller(vault, scope, field, value, reason):
    resolver, admission, routes, _ = setup_resolver(vault, scope)
    routes.binding = replace(routes.binding, **{field: value})
    with pytest.raises(CredentialError) as caught:
        resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    assert caught.value.error.reason is reason


def test_separate_bastion_identity_never_becomes_command_target(vault, scope):
    vault.set_device("jump", "jump-user", SENTINEL + "-jump")
    vault.save(MASTER)
    resolver, admission, routes, _ = setup_resolver(vault, scope)
    jump = replace(
        scope.targets[0], target_id="jump-id", hostname="jump", host="192.0.2.2",
        task_id="route", port=2222,
    )
    routes.binding = replace(routes.binding, jump=jump)
    payload = consume(resolver.resolve(scope, UnlockSession(scope, MASTER, admission)), scope)
    assert [t["target_id"] for t in payload["targets"]] == ["r1"]
    assert payload["jump"]["target_id"] == "jump-id"
    assert payload["jump"]["fields"]["password"] == SENTINEL + "-jump"
    assert payload["jump"]["port"] == 2222


@pytest.mark.parametrize(
    "action", ["revoke", "expiry", "route", "qualification", "replay", "host-cancel"],
)
def test_private_use_rechecks_binding_lifetime_and_is_single_use(vault, scope, action):
    resolver, admission, routes, clock = setup_resolver(vault, scope)
    value = resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    if action == "revoke":
        resolver.revoke(scope.operation_id)
        resolver.revoke(scope.operation_id)
    elif action == "expiry":
        clock.value = scope.expires_at
    elif action == "route":
        routes.binding = replace(routes.binding, keys_accessible=False)
    elif action == "qualification":
        routes.binding = replace(routes.binding, qualification_digest=OTHER)
    elif action == "host-cancel":
        admission.allowed = False
    else:
        consume(value, scope)
    with pytest.raises(CredentialError):
        consume(value, scope)


@pytest.mark.parametrize("serializer", [pickle.dumps, copy.copy, copy.deepcopy, asdict, vars, json.dumps])
def test_private_material_cannot_be_ordinary_serialized(vault, scope, serializer):
    resolver, admission, _, _ = setup_resolver(vault, scope)
    session = UnlockSession(scope, MASTER, admission)
    value = resolver.resolve(scope, session)
    for private in (session, value):
        try:
            serialized = serializer(private)
        except (TypeError, ValueError):
            continue
        assert SENTINEL not in repr(serialized)
        assert MASTER not in repr(serialized)
    with pytest.raises(ValueError):
        public_object({"result": value})
    resolver.revoke(scope.operation_id)


def test_session_close_and_reuse_are_blocked(vault, scope):
    resolver, admission, _, _ = setup_resolver(vault, scope)
    session = UnlockSession(scope, MASTER, admission)
    session.close()
    session.close()
    with pytest.raises(CredentialError):
        resolver.resolve(scope, session)
    session = UnlockSession(scope, MASTER, admission)
    resolver.resolve(scope, session)
    with pytest.raises(CredentialError):
        resolver.resolve(scope, session)


@pytest.mark.parametrize(("transport", "port", "expected"), [
    ("ssh", None, 22), ("ssh2", None, 22), ("telnet", None, 23), ("ssh", 2200, 2200),
])
def test_canonical_inventory_preserves_native_port_semantics(transport, port, expected):
    target = CredentialTarget.from_device(
        Device("r1", "192.0.2.1", "cisco_ios", transport=transport, port=port),
        "health", ("username",),
    )
    assert target.port == expected


def test_telnet_has_no_plaintext_companion_fallback(vault, scope):
    target = replace(scope.targets[0], transport="telnet", port=23)
    scope = replace(scope, targets=(target,))
    resolver, admission, _, _ = setup_resolver(vault, scope)
    with pytest.raises(CredentialError) as caught:
        resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    assert caught.value.error.reason is ReasonCode.ROUTE_UNAVAILABLE


@pytest.mark.parametrize("port", [0, -1, True, 65536, 22.0])
def test_invalid_explicit_port_cannot_become_default(port):
    with pytest.raises(CredentialError):
        CredentialTarget.from_device(
            Device("r1", "192.0.2.1", "cisco_ios", port=port), "health", ("username",),
        )


def test_native_session_clears_isolated_reader_on_failure(vault):
    original_key = vault._key
    original_data = vault._data
    with pytest.raises(RuntimeError, match="deliberate-test-failure"):
        with vault.private_session() as reader:
            reader.unlock(MASTER)
            assert reader.get_credentials("r1")["password"] == SENTINEL + "-device"
            raise RuntimeError("deliberate-test-failure")
    assert reader._key is None
    assert reader._data == {}
    assert vault._key is original_key
    assert vault._data is original_data


def test_ntp_uses_only_selected_private_field_reference(vault, scope):
    # Native encrypted data can hold private task fields; references, never
    # these values, appear in the public scope.
    vault._data["devices"]["r1"]["ntp_authentication_key"] = SENTINEL + "-ntp"
    vault.save(MASTER)
    scope = replace(
        scope, targets=(replace(scope.targets[0], fields=("ntp_authentication_key",)),),
    )
    resolver, admission, _, _ = setup_resolver(vault, scope)
    assert SENTINEL not in repr(scope)
    payload = consume(resolver.resolve(scope, UnlockSession(scope, MASTER, admission)), scope)
    assert payload["targets"][0]["fields"] == {"ntp_authentication_key": SENTINEL + "-ntp"}


def test_sentinel_inspection_has_a_deliberate_leak_negative_control(vault, scope, caplog, capsys):
    def assert_clean(value):
        assert SENTINEL not in value and MASTER not in value

    resolver, admission, _, _ = setup_resolver(vault, scope)
    session = UnlockSession(scope, MASTER, admission)
    credentials = resolver.resolve(scope, session)
    captured = capsys.readouterr()
    assert_clean(repr(scope) + repr(session) + repr(credentials))
    assert_clean(caplog.text + captured.out + captured.err)
    with pytest.raises(AssertionError):
        assert_clean("deliberately injected leak: " + SENTINEL)
    resolver.revoke(scope.operation_id)


def test_no_credential_exports_to_argv_environment_or_owned_staging(vault, scope, owned_root):
    before_env = dict(os.environ)
    before_argv = tuple(sys.argv)
    before_files = set(owned_root.rglob("*"))
    resolver, admission, _, _ = setup_resolver(vault, scope)
    credentials = resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    assert dict(os.environ) == before_env
    assert tuple(sys.argv) == before_argv
    assert set(owned_root.rglob("*")) == before_files
    for path in before_files:
        if path.is_file():
            contents = path.read_bytes()
            assert SENTINEL.encode() not in contents
            assert MASTER.encode() not in contents
    resolver.revoke(scope.operation_id)
    with pytest.raises(CredentialError):
        consume(credentials, scope)


def test_oversize_private_subsection_is_rejected(vault, scope):
    vault.set_device("r1", "device-user", SENTINEL + "x" * (1024 * 1024))
    vault.save(MASTER)
    resolver, admission, _, _ = setup_resolver(vault, scope)
    with pytest.raises(CredentialError) as caught:
        resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    assert caught.value.error.reason is ReasonCode.HANDOFF_INVALID
    assert resolver._values == {}


def test_jump_key_passphrase_is_separate_and_only_a_local_key_reference_is_sent(vault, scope):
    vault.set_device("jump", "jump-user", SENTINEL + "-not-selected")
    vault._data["devices"]["jump"]["key_passphrase"] = SENTINEL + "-key-passphrase"
    vault.save(MASTER)
    resolver, admission, routes, _ = setup_resolver(vault, scope)
    routes.binding = replace(routes.binding, jump=replace(
        scope.targets[0], target_id="jump-id", hostname="jump", host="192.0.2.2",
        task_id="route", fields=("username", "key_passphrase"), key_ref="approved-controller-key",
    ))
    payload = consume(resolver.resolve(scope, UnlockSession(scope, MASTER, admission)), scope)
    assert payload["jump"]["key_ref"] == "approved-controller-key"
    assert payload["jump"]["fields"] == {
        "username": "jump-user", "key_passphrase": SENTINEL + "-key-passphrase",
    }
    assert "private_key" not in repr(payload)
    assert "key_passphrase" not in payload["targets"][0]["fields"]


def test_host_guard_is_acquired_before_resolver_lock_for_cancel_safety(vault, scope):
    class LockOrderAdmission(Admission):
        def check_lock_order(self):
            acquired = []

            def probe():
                locked = resolver._lock.acquire(blocking=False)
                acquired.append(locked)
                if locked:
                    resolver._lock.release()

            worker = threading.Thread(target=probe)
            worker.start()
            worker.join(timeout=2)
            assert not worker.is_alive()
            assert acquired == [True], "resolver lock must not be held while entering host guard"

        @contextmanager
        def admit(self, selected):
            self.check_lock_order()
            with super().admit(selected):
                yield

        @contextmanager
        def validate(self, selected):
            self.check_lock_order()
            with super().validate(selected):
                yield

    admission = LockOrderAdmission(scope)
    routes = Routes(scope, admission)
    resolver = ScopedCredentialResolver(vault, routes, Clock())
    credentials = resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    assert consume(credentials, scope)["targets"][0]["target_id"] == "r1"
