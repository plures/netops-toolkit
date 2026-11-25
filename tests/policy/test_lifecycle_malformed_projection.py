"""Malformed lifecycle projections cannot bypass terminal clock observation."""

import copy

import pytest
from test_lifecycle_admission_completion import effect, environment

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import AuthorizationError


@pytest.mark.parametrize("boundary", ("issue", "consume", "permit", "enter"))
@pytest.mark.parametrize("observed", (15.0, 30.0))
def test_missing_projection_field_rejects_safely_without_clock_refund(boundary, observed):
    env = environment("restore")
    plan, binding, state, _, adapter, _, broker, decision = env
    receipt = adapter.review(plan, 10.0, 20.0)
    grant = session = permit = None
    eb = effect(binding)
    if boundary != "issue":
        grant = broker.issue_lifecycle(plan, receipt, decision, 10.0)
    if boundary in ("permit", "enter"):
        session = broker.consume_lifecycle(grant, binding, 11.0)
    if boundary == "enter":
        permit = broker.permit_lifecycle(session, eb, 12.0)
    projection = copy.copy(
        plan if boundary == "issue" else binding if boundary == "consume" else eb
    )
    object.__delattr__(projection, "kind" if boundary in ("issue", "consume") else "lifecycle")
    before = list(state.cas)
    with pytest.raises((AuthorizationError, c.ContractError)):
        if boundary == "issue":
            broker.issue_lifecycle(projection, receipt, decision, observed)
        elif boundary == "consume":
            broker.consume_lifecycle(grant, projection, observed)
        elif boundary == "permit":
            broker.permit_lifecycle(session, projection, observed)
        else:
            broker.enter_lifecycle(permit, projection, observed)
    with pytest.raises(AuthorizationError):
        if boundary == "issue":
            broker.issue_lifecycle(plan, receipt, decision, 14.0)
        elif boundary == "consume":
            broker.consume_lifecycle(grant, binding, 14.0)
        elif boundary == "permit":
            broker.permit_lifecycle(session, eb, 14.0)
        else:
            broker.enter_lifecycle(permit, eb, 14.0)
    assert state.cas == before
    assert state.pointer_cas == []
