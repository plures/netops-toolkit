"""Registry-clock regression controls for the real A01/S01 composition."""

from copy import deepcopy
from uuid import uuid4

import pytest

from netops.ansible.credentials import CredentialError
from netops.ansible.policy.authorization import AuthorizationError

pytest_plugins = ("tests.test_credential_composition",)


@pytest.mark.parametrize("boundary", ["admit", "validate"])
@pytest.mark.parametrize("malformed", [False, True])
def test_bridge_expiry_retires_authority_before_scope_projection(
    composition, boundary, malformed,
):
    scope, _, state, broker, session, clock, admission, _, _ = composition
    with admission.admit(scope):
        pass
    permit, binding = admission._permits[0]
    supplied = deepcopy(scope)
    if malformed:
        object.__delattr__(supplied, "operation_id")
    clock.value = 20.0
    with pytest.raises(CredentialError):
        with getattr(admission, boundary)(supplied):
            pytest.fail("expired credential bridge entered")
    assert broker.is_revoked(scope.operation_id)
    assert broker.reconcile(permit) == binding
    clock.value = 10.0
    with pytest.raises(CredentialError):
        with admission.validate(scope):
            pytest.fail("backdated delivery restored authority")
    with pytest.raises(AuthorizationError):
        broker.permit(session, binding, clock.value)
    assert state.advances == [(0, 1)]
    # Outstanding factual completion remains possible, without reopening admission.
    broker.complete(permit, str(uuid4()), state.revision, 21.0)
    assert state.advances == [(0, 1), (1, 2)]
    assert broker.is_revoked(scope.operation_id)


@pytest.mark.parametrize("boundary", ["admit", "validate"])
@pytest.mark.parametrize("following", [20.0, 9.0])
def test_bridge_exit_observes_terminal_clock_without_refunding_receipts(
    composition, boundary, following,
):
    scope, _, state, broker, _, clock, admission, _, _ = composition
    if boundary == "validate":
        with admission.admit(scope):
            pass
    with pytest.raises(CredentialError):
        with getattr(admission, boundary)(scope):
            clock.value = following
    assert broker.is_revoked(scope.operation_id)
    assert state.advances == [(0, 1)]
    assert len(broker._pending) == 1
    permit = next(iter(broker._pending))
    binding = broker.reconcile(permit)
    with pytest.raises(AuthorizationError):
        broker.enter(permit, binding, 10.0)


def test_rejected_unexpired_scope_cannot_refund_bridge_clock(composition):
    scope, _, state, broker, session, clock, admission, _, _ = composition
    malformed = deepcopy(scope)
    object.__delattr__(malformed, "operation_id")
    clock.value = 15.0
    with pytest.raises(CredentialError):
        with admission.admit(malformed):
            pytest.fail("malformed credential scope entered")
    assert not broker.is_revoked(scope.operation_id)
    assert state.advances == []
    clock.value = 14.0
    with pytest.raises(CredentialError):
        with admission.admit(scope):
            pytest.fail("rejected scope refunded host clock")
    assert broker.is_revoked(scope.operation_id)
    assert session not in broker._sessions
    assert state.advances == []


@pytest.mark.parametrize("read", [1, 2, 3, 4], ids=["entry", "permit", "enter", "return"])
@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
def test_bridge_clock_provider_failure_retires_owned_scope(
    composition, monkeypatch, read, failure_type,
):
    scope, _, state, broker, session, clock, admission, _, _ = composition
    healthy_clock = clock.monotonic
    failure = failure_type("private-clock-failure")
    calls = 0

    def failing_clock():
        nonlocal calls
        calls += 1
        if calls == read:
            raise failure
        return healthy_clock()

    monkeypatch.setattr(clock, "monotonic", failing_clock)
    expected = CredentialError if failure_type is RuntimeError else KeyboardInterrupt
    with pytest.raises(expected) as caught, admission.admit(scope):
        pass
    if failure_type is KeyboardInterrupt:
        assert caught.value is failure
    else:
        assert "private-clock-failure" not in str(caught.value)
    assert broker.is_revoked(scope.operation_id)
    assert session not in broker._sessions
    assert state.advances == ([] if read < 3 else [(0, 1)])
    monkeypatch.setattr(clock, "monotonic", healthy_clock)
    with pytest.raises(CredentialError), admission.validate(scope):
        pytest.fail("restored provider revived admission")
    if read == 4:
        permit = next(iter(broker._pending))
        broker.reconcile(permit)
        broker.complete(permit, str(uuid4()), state.revision, 21.0)
        assert state.advances == [(0, 1), (1, 2)]
        assert broker.is_revoked(scope.operation_id)
