"""Independent AC-006/011 private credential controls for S02 consumption.

Derived from frozen T13/T14, not the resolver implementation's existing tests.
The only effects are the native vault's isolated in-memory/environment lookup.
"""

from __future__ import annotations

import hashlib
import json
import pickle
from contextlib import contextmanager
from dataclasses import replace
from importlib import resources

import pytest

from netops.ansible import contracts as c
from netops.ansible.credentials import (
    CredentialError,
    CredentialScope,
    CredentialTarget,
    RouteBinding,
    ScopedCredentialResolver,
    UnlockSession,
)
from netops.ansible.policy.contracts import PolicyIdentity
from netops.core.vault import CredentialVault

SENTINEL = "NOV19_PRIVATE_DEVICE_SENTINEL_c91fb562"
UNSELECTED = "NOV19_UNSELECTED_ENABLE_SENTINEL_1b02"
MASTER = "NOV19_MASTER_SENTINEL_533a02"
OPERATION = "b9de32d8-9943-4f4b-8042-2baedc0b9a2c"


def policy_identity():
    root = resources.files("netops.ansible.policy")
    source = root.joinpath("ansible_molecule.px").read_bytes()
    contracts = root.joinpath("ansible_molecule.contracts.px").read_bytes()
    bundle = root.joinpath("bundle.json").read_bytes()
    value = json.loads(bundle)
    return PolicyIdentity(
        value["canonical_revision"], hashlib.sha256(source).hexdigest(),
        hashlib.sha256(contracts).hexdigest(), hashlib.sha256(bundle).hexdigest(),
        tuple(item["id"] for item in value["manifest"]), value["reducer_version"],
    )


class Clock:
    def __init__(self):
        self.now = 700001.0

    def monotonic(self):
        return self.now

    def utc(self):
        return "2026-11-20T02:20:00Z"


class Admission:
    """Fake host effect port, not a credential resolver replacement."""

    def __init__(self):
        self.admissions = 0
        self.validations = 0
        self.revoked = False

    @contextmanager
    def admit(self, scope):
        self.admissions += 1
        if self.revoked:
            raise CredentialError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        yield

    @contextmanager
    def validate(self, scope):
        self.validations += 1
        if self.revoked:
            raise CredentialError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        yield


class Routes:
    def __init__(self, scope):
        self.observation = RouteBinding(
            scope.controller_digest, scope.route_digest, scope.targets, "e" * 64,
            True, True, "reject", True,
        )
        self.calls = 0

    def validate(self, context, scope):
        self.calls += 1
        return self.observation


@pytest.fixture
def private_case(monkeypatch, tmp_path):
    clock = Clock()
    context = c.ControllerContext(c.Context(
        "qualified-owned-controller", "a" * 64, "selected-inventory", "b" * 64,
        policy_identity(), "c" * 64, "d" * 64,
    ))
    target = CredentialTarget(
        "nov19-router", "collect", "nov19-router", "192.0.2.90", "cisco_ios",
        "ssh", 22, (), ("username", "password"), known_hosts_ref="owned-known-hosts",
    )
    scope = CredentialScope(
        OPERATION, context, "f" * 64, "a" * 64, (target,), clock.now + 60.0,
    )
    monkeypatch.setenv("NETOPS_CRED_NOV19_ROUTER_USER", "operator")
    monkeypatch.setenv("NETOPS_CRED_NOV19_ROUTER_PASS", SENTINEL)
    monkeypatch.setenv("NETOPS_CRED_NOV19_ROUTER_ENABLE", UNSELECTED)
    admission, routes = Admission(), Routes(scope)
    vault = CredentialVault(tmp_path / "never-created-vault.yaml")
    resolver = ScopedCredentialResolver(vault, routes, clock)
    return scope, resolver, admission, routes, clock, vault


def test_t13_private_resolution_minimizes_fields_and_is_one_use(private_case, caplog):
    scope, resolver, admission, _, _, vault = private_case
    session = UnlockSession(scope, MASTER, admission)
    private = resolver.resolve(scope, session)
    assert repr(private) == "<private>"
    assert repr(session) == "<private>"
    with pytest.raises(TypeError):
        pickle.dumps(private)
    with pytest.raises(c.ContractError):
        c.canonical_bytes(private)
    frame = private._protected_payload(scope)
    assert SENTINEL.encode() in frame
    assert UNSELECTED.encode() not in frame
    assert MASTER.encode() not in frame
    decoded = json.loads(frame)
    assert decoded["targets"][0]["fields"] == {"username": "operator", "password": SENTINEL}
    assert decoded["jump"] is None
    with pytest.raises(CredentialError):
        private._protected_payload(scope)
    with pytest.raises(CredentialError):
        resolver.resolve(scope, session)
    assert admission.admissions == 1
    assert not vault._path.exists()
    assert all(secret not in caplog.text for secret in (SENTINEL, UNSELECTED, MASTER))


@pytest.mark.parametrize("drift", ["route", "controller", "host-key", "channel", "key"])
def test_t13_route_reprobe_blocks_drift_before_private_handoff(private_case, drift):
    scope, resolver, admission, routes, _, _ = private_case
    private = resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    changes = {
        "route": {"route_digest": "0" * 64},
        "controller": {"controller_digest": "0" * 64},
        "host-key": {"host_key_policy": "auto-add"},
        "channel": {"private_channel_qualified": False},
        "key": {"keys_accessible": False},
    }
    routes.observation = replace(routes.observation, **changes[drift])
    with pytest.raises(CredentialError):
        private._protected_payload(scope)
    # A rejected handoff spends/clears the value; repairing facts cannot revive it.
    routes.observation = replace(
        routes.observation, route_digest=scope.route_digest,
        controller_digest=scope.controller_digest, host_key_policy="reject",
        private_channel_qualified=True, keys_accessible=True,
    )
    with pytest.raises(CredentialError):
        private._protected_payload(scope)


@pytest.mark.parametrize("stop", ["expiry", "host-revoke", "resolver-revoke"])
def test_t14_cancel_or_expiry_cannot_resurrect_resolved_secret(private_case, stop):
    scope, resolver, admission, _, clock, _ = private_case
    private = resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    if stop == "expiry":
        clock.now = scope.expires_at
    elif stop == "host-revoke":
        admission.revoked = True
    else:
        resolver.revoke(scope.operation_id)
        resolver.revoke(scope.operation_id)
    with pytest.raises(CredentialError):
        private._protected_payload(scope)


def test_t13_wrong_task_scope_spends_private_value_without_secret_return(private_case):
    scope, resolver, admission, _, _, _ = private_case
    private = resolver.resolve(scope, UnlockSession(scope, MASTER, admission))
    wrong = replace(scope, targets=(replace(scope.targets[0], task_id="apply"),))
    with pytest.raises(CredentialError):
        private._protected_payload(wrong)
    with pytest.raises(CredentialError):
        private._protected_payload(scope)
