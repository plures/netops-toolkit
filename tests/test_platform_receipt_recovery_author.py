"""Actual owner/ledger recovery; only the external platform process is fake."""

import sys

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.dependencies._family_ledger import _OwnedFamilyLedger
from netops.dependencies._family_provider import _operation
from netops.dependencies._platform_host import _NativePlatformIO
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_default_provider_completion_author import platform_public_case
from tests.test_i02_offline_installation import Cancel


def boundary(monkeypatch):
    calls = []
    enabled = False

    def run(self, call, authority):
        nonlocal enabled
        authority.check()
        call.__post_init__()
        calls.append(call.kind)
        if call.kind == "feature-query":
            return b"State : Enabled\r\n" if enabled else b"State : Disabled\r\n"
        if call.kind == "feature-enable":
            enabled = True
            return b""
        assert call.kind == "runtime-version"
        return b"podman version 1.0\n"

    monkeypatch.setattr(_NativePlatformIO, "run", run)
    return calls


def lose_ack(monkeypatch, action, family):
    original = _OwnedFamilyLedger.record
    issued = []

    def record(self, root, operation, result, expected_revision):
        if operation.action == action and operation.release_digest == c.digest(family) and not issued:
            issued.append((operation, result))
            raise OSError("injected storage-boundary acknowledgement loss")
        return original(self, root, operation, result, expected_revision)

    monkeypatch.setattr(_OwnedFamilyLedger, "record", record)
    return issued


@pytest.mark.parametrize("damage", [None, "missing", "manifest"])
def test_platform_install_lost_ack_reconciles_only_exact_receipt_and_fresh_query(
    tmp_path, policy, monkeypatch, damage,
):
    service, scope, context, port, state, lock, ledger_id, root = platform_public_case(
        tmp_path, policy,
    )
    calls = boundary(monkeypatch)
    platform = lock.releases[0]
    issued = lose_ack(monkeypatch, "install", platform)
    plan = service.plan(scope, context)
    first = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    assert first.status != c.OutcomeStatus.SUCCEEDED and issued
    operation, actual = issued[0]
    receipt_id = "platform-result-" + c.digest(operation)
    receipt = state._read(receipt_id)
    assert receipt.payload["result"]["identity_digest"] == actual.identity_digest
    pending = port.read(ledger_id).payload["pending"]
    assert c.public_object(c.wire(operation)) in pending
    # Damage only the external owned-state boundary, not private authority.
    if damage == "missing":
        original_read = state._read

        def missing(resource):
            if resource == receipt_id:
                raise FileNotFoundError()
            return original_read(resource)

        monkeypatch.setattr(state, "_read", missing)
    elif damage == "manifest":
        port.seed(receipt_id, {**dict(receipt.payload), "manifest_digest": "f" * 64})
    before = len(calls)
    plan = service.plan(scope, context)
    assert all(effect.kind != "dependency-stage" for effect in plan.lifecycle.effects)
    following = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    assert calls.count("feature-enable") == (1 if sys.platform == "win32" else 0)
    assert set(calls[before:]) <= {"feature-query", "runtime-version"}
    retained = port.read(ledger_id).payload["pending"]
    if damage is None:
        assert following.pending_actions == ("review-activation-plan",)
        assert not retained and not following.errors
        assert port.read(ledger_id).payload["resources"]
    else:
        assert following.status != c.OutcomeStatus.SUCCEEDED
        assert c.public_object(c.wire(operation)) in retained
    assert root.path and type(state.pointer()) is lc.AbsentPointer


def test_platform_remove_lost_ack_is_fresh_readonly_reconciliation_not_replay(
    tmp_path, policy, monkeypatch,
):
    service, scope, context, port, state, lock, ledger_id, root = platform_public_case(
        tmp_path, policy,
    )
    calls = boundary(monkeypatch)
    plan = service.plan(scope, context)
    installed = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    assert installed.pending_actions == ("review-activation-plan",) and not installed.errors
    platform = lock.releases[0]
    issued = lose_ack(monkeypatch, "remove", platform)
    plan = service.plan_uninstall(state.manifests[0].generation_id, context)
    consent = service.authorization._lifecycle_consent.review(plan, 10.0, 20.0)
    first = service.uninstall(plan, consent)
    assert first.status != c.OutcomeStatus.SUCCEEDED and issued
    operation = _operation(lock, platform, "remove", state.manifests[0].generation_id)
    assert c.public_object(c.wire(operation)) in port.read(ledger_id).payload["pending"]
    before = len(calls)
    plan = service.plan_uninstall(state.manifests[0].generation_id, context)
    consent = service.authorization._lifecycle_consent.review(plan, 10.0, 20.0)
    following = service.uninstall(plan, consent)
    assert following.status == c.OutcomeStatus.SUCCEEDED
    assert calls.count("feature-enable") == (1 if sys.platform == "win32" else 0)
    assert set(calls[before:]) <= {"feature-query", "runtime-version"}
    assert port.read(ledger_id).payload["pending"] == ()
    assert port.read(ledger_id).payload["resources"] == ()
    assert type(state.pointer()) is lc.AbsentPointer and root.path
