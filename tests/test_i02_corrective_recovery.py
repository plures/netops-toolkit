"""Author recovery regressions using real service/broker and fake owned I/O."""

from dataclasses import replace
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import AuthorizationError, lifecycle_plan_digest
from netops.dependencies._recovery import RecoveryStore
from netops.dependencies.service import DependencyService
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel, product_service


def fresh(plan):
    plan = replace(plan, plan_id=str(uuid4()))
    return replace(plan, plan_digest=lifecycle_plan_digest(plan))


def test_restart_resume_uses_owned_scope_and_context_but_never_a_stored_grant(tmp_path, policy):
    service, plan, _, port, state, _, consent, broker, clock = product_service(tmp_path, policy)

    class CancelAfterCheckpoint(Cancel):
        def is_cancelled(self):
            return port.filename("dependency-recovery-" + plan.lifecycle_id).exists()

    # Interrupt after durable selection but BEFORE staging. Replaying a plan
    # that claimed an absent destination after successful staging is not a
    # valid positive resume fixture: it needs newly reviewed reuse evidence.
    first = service.provision(plan, consent.review(plan, 10.0, 20.0), CancelAfterCheckpoint())
    assert first.status == c.OutcomeStatus.CANCELLED
    assert not any(step.status == c.OutcomeStatus.SUCCEEDED for step in first.steps)
    selected = RecoveryStore(state).read(plan.lifecycle_id)
    assert selected.scope == plan.scope
    assert selected.generation == plan.generation
    replacement = DependencyService(
        service.registry, service.adapters, state, service.policy, broker, clock, service.events,
    )
    assert not replacement._lifecycle._contexts and not replacement._lifecycle._plans
    next_plan = fresh(plan)
    before = len(port.writes)
    outcome = replacement.resume(
        plan.lifecycle_id, consent.review(next_plan, 10.0, 20.0), Cancel(),
    )
    assert outcome.steps[0].status == c.OutcomeStatus.SUCCEEDED
    assert len(port.writes) > before
    assert outcome.status != c.OutcomeStatus.SUCCEEDED  # inert staging never means install ready
    assert RecoveryStore(state).read(plan.lifecycle_id).plan_id == next_plan.plan_id
    with pytest.raises(AuthorizationError):
        replacement.resume(plan.lifecycle_id, lc.InstallConsent(), Cancel())


def test_changed_probe_status_blocks_resume_before_any_effect_or_recovery_write(tmp_path, policy):
    service, plan, _, port, _, _, consent, *_ = product_service(tmp_path, policy)
    first = service.provision(plan, consent.review(plan, 10.0, 20.0), Cancel())
    assert first.steps[0].status == c.OutcomeStatus.SUCCEEDED
    next_plan = fresh(plan)
    receipt = consent.review(next_plan, 10.0, 20.0)
    for adapter in service.adapters.values():
        adapter.missing = ("native-python",)
    before = len(port.writes)
    result = service.resume(plan.lifecycle_id, receipt, Cancel())
    assert result.status == c.OutcomeStatus.BLOCKED
    assert result.errors[0].reason == c.ReasonCode.CONSENT_STALE
    assert len(port.writes) == before


def test_consuming_context_identity_drift_blocks_even_with_available_probe(tmp_path, policy):
    service, plan, _, port, _, _, consent, *_ = product_service(tmp_path, policy)
    service.provision(plan, consent.review(plan, 10.0, 20.0), Cancel())
    next_plan = fresh(plan)
    receipt = consent.review(next_plan, 10.0, 20.0)
    for adapter in service.adapters.values():
        adapter.contexts["native"] = replace(adapter.contexts["native"], id="different-process")
    before = len(port.writes)
    result = service.resume(plan.lifecycle_id, receipt, Cancel())
    assert result.status == c.OutcomeStatus.BLOCKED
    assert len(port.writes) == before


def test_corrupt_or_foreign_recovery_is_not_reconstructed_from_memory(tmp_path, policy):
    service, plan, _, port, _, _, consent, *_ = product_service(tmp_path, policy)
    service.provision(plan, consent.review(plan, 10.0, 20.0), Cancel())
    resource = "dependency-recovery-" + plan.lifecycle_id
    record = port.read(resource)
    port.filename(resource).write_bytes(replace(record, ownership_token="9" * 64).to_bytes())
    next_plan = fresh(plan)
    before = len(port.writes)
    with pytest.raises((c.ContractError, AuthorizationError)):
        service.resume(plan.lifecycle_id, consent.review(next_plan, 10.0, 20.0), Cancel())
    assert len(port.writes) == before


def test_retained_scope_requires_exact_content_and_manifest_not_generation_name(tmp_path, policy):
    service, plan, _, _, state, _, consent, *_ = product_service(tmp_path, policy)
    service.provision(plan, consent.review(plan, 10.0, 20.0), Cancel())
    selected = RecoveryStore(state).retained(plan.generation)
    assert selected.scope == plan.scope
    with pytest.raises((c.ContractError, AuthorizationError, KeyError)):
        RecoveryStore(state).retained(replace(plan.generation, content_digest="b" * 64))
