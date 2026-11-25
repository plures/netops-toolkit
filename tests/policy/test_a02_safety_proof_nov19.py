"""Focused actual-owner safety proofs; no controller or feature-acceptance claim."""

import hashlib

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import AuthorizationError
from tests.policy.test_lifecycle_execution import (
    environment,
    issue,
    reserve,
)
from tests.policy.test_lifecycle_execution import (
    policy as policy,
)
from tests.test_workflow_execution import composed as native_composed


@pytest.fixture
def composed(policy):
    """Adapt only the policy tuple shape for the existing native owner fixture."""
    return native_composed.__wrapped__(policy[:2])


class ThrowingClock:
    """Throw the original object until explicitly recovered."""

    def __init__(self, failure):
        self.failure = failure
        self.calls = 0

    def monotonic(self):
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return 12.0


@pytest.mark.parametrize("failure_type", (RuntimeError, KeyboardInterrupt))
def test_native_owner_clock_guard_itself_retires_reviewed_authority(composed, failure_type):
    """Prove the concrete guard, independently of outer redundant revocation."""
    service, host, request, _, effects = composed
    grant = host.review(service, request)
    failure = failure_type("actual owner clock exception")
    clock = ThrowingClock(failure)
    host._clock = clock
    with pytest.raises(failure_type) as caught:
        host._now(request.operation_id)
    assert caught.value is failure
    assert clock.calls == 1
    assert host.authorization.is_revoked(request.operation_id)
    clock.failure = None
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert effects.calls == []


def test_native_admitted_owner_throwing_clock_revokes_before_dispatch(composed):
    """A clock exception before consume must retire even a valid reviewed grant."""
    service, host, request, _, effects = composed
    grant = host.review(service, request)
    failure = KeyboardInterrupt("owned clock failed")
    clock = ThrowingClock(failure)
    host._clock = clock
    with pytest.raises(KeyboardInterrupt) as caught:
        service.execute(request, grant)
    assert caught.value is failure
    assert clock.calls == 1
    assert host.authorization.is_revoked(request.operation_id)
    assert effects.calls == []
    clock.failure = None
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert host.authorization.is_revoked(request.operation_id)
    assert effects.calls == []


def test_native_completion_clock_failure_retains_exact_backend_fact(composed):
    """A later clock failure cannot erase a successful actual native result."""
    service, host, request, _, effects = composed
    grant = host.review(service, request)
    clock = ThrowingClock(None)
    host._clock = clock
    failure = RuntimeError("completion clock failed")

    def fail_after_backend():
        clock.failure = failure

    effects.before_return = fail_after_backend
    result = service.execute(request, grant)
    assert len(effects.calls) == 1
    assert len(result.steps) == 1
    assert result.steps[0].status == c.OutcomeStatus.SUCCEEDED
    assert result.steps[0].native_payload == c.public_object({
        "output": ("native", "r1"), "reading": 5,
    })
    assert host.authorization.is_revoked(request.operation_id)
    clock.failure = None
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(effects.calls) == 1


@pytest.mark.parametrize("failure_type", (RuntimeError, KeyboardInterrupt))
def test_lifecycle_admitted_owner_throwing_clock_retires_permit(
    tmp_path, policy, failure_type,
):
    """Real reserved authority cannot recover eligibility after a clock throws."""
    env = environment(tmp_path, policy)
    _, binding, port, _, _, _, broker, _, executor = env
    permit, effect = reserve(env, policy)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    writes_before = tuple(port.writes)
    failure = failure_type("owned lifecycle clock failed")
    clock = ThrowingClock(failure)
    executor._clock = clock
    with pytest.raises(failure_type) as caught:
        executor.enter(permit, effect)
    assert caught.value is failure
    assert clock.calls == 1
    assert (binding.kind, binding.plan_id) in broker._life_revoked
    assert executor.reconcile(permit) is None
    assert tuple(port.writes) == writes_before
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before
    clock.failure = None
    with pytest.raises(AuthorizationError):
        executor.enter(permit, effect)
    assert tuple(port.writes) == writes_before
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_lifecycle_completion_clock_failure_preserves_factual_receipt(tmp_path, policy):
    """Already changed bytes remain factual and cannot authorize a second entry."""
    env = environment(tmp_path, policy)
    _, binding, port, state, _, _, broker, _, executor = env
    permit, effect = reserve(env, policy)
    receipt = executor.enter(permit, effect)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    failure = RuntimeError("factual completion clock failed")
    clock = ThrowingClock(failure)
    executor._clock = clock
    with pytest.raises(RuntimeError) as caught:
        executor.complete(permit)
    assert caught.value is failure
    assert (binding.kind, binding.plan_id) in broker._life_revoked
    assert executor.reconcile(permit) is receipt
    assert state.inspect_receipt(effect)["phase"] == "observed"
    assert state.artifact("destination") == b"owned inert bytes; never executable"
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before
    clock.failure = None
    with pytest.raises(AuthorizationError):
        executor.enter(permit, effect)
    assert executor.reconcile(permit) is receipt
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before
    assert len(port.writes) > 0


def test_self_consistent_changed_source_rejects_stale_review_before_receipt(tmp_path, policy):
    """Self-digest integrity is not equivalence to the separately reviewed source."""
    env = environment(tmp_path, policy)
    plan, binding, port, state, _, _, _, _, executor = env
    grant = issue(env, policy)
    record = port.read("source")
    changed = b"changed but internally consistent owned inert bytes"
    payload = dict(record.payload.items())
    payload.update(content=tuple(changed), content_digest=hashlib.sha256(changed).hexdigest())
    port.seed("source", payload)
    assert state.artifact("source") == changed
    assert payload["content_digest"] != binding.content["steps"][0]["source"]["artifact_digest"]
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    snapshot = state.snapshot_lifecycle(binding)
    assert snapshot.binding == binding
    assert snapshot.evidence is None
    with pytest.raises((AuthorizationError, c.ContractError)):
        executor.execute(plan, grant)
    assert port.writes == []
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before
    assert not executor._pending
    assert not executor._receipts
