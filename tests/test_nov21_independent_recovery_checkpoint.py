"""Independent AC-001/003: only completed post-install observations become recovery facts.

The canonical policy, broker, reducer, protected records and public service are
real. External download/interpreter effects use existing explicit test ports;
this is not producer-origin or platform qualification.
"""

from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import AuthorizationError
from netops.dependencies._recovery import RecoveryStore
from tests.test_i02_author_lifecycle import Cancel
from tests.test_i02_public_flow import policy as policy
from tests.test_i02_public_flow import public_case


@pytest.mark.parametrize("completion", ["allow", "deny-broker", "deny-reducer"])
def test_ac001_only_fully_completed_observation_becomes_recovery_baseline(
    tmp_path, policy, monkeypatch, completion,
):
    service, scope, context, _, state, effects, engine, _ = public_case(tmp_path, policy)
    adapter = next(iter(service.adapters.values()))
    adapter.missing = ("native-python",)
    before = service.verify(scope, context)
    verify_effect = effects.verify

    def install_then_verify(*args):
        verify_effect(*args)
        adapter.missing = ()

    monkeypatch.setattr(effects, "verify", install_then_verify)
    if completion == "deny-broker":
        complete = service.authorization.complete_lifecycle
        calls = []

        def finish(permit, *args):
            calls.append(permit)
            if len(calls) == 3:
                raise AuthorizationError()
            return complete(permit, *args)

        monkeypatch.setattr(service.authorization, "complete_lifecycle", finish)
    if completion == "deny-reducer":
        reduce = engine.reduce
        calls = []

        def reduce_selected(policy_state, event, facts):
            result = reduce(policy_state, event, facts)
            if event.kind.value == "StepCompleted":
                calls.append(event)
                if len(calls) == 3:
                    return replace(
                        result, decision=replace(result.decision, decision="deny", effects=()),
                    )
            return result

        monkeypatch.setattr(engine, "reduce", reduce_selected)
    plan = service.plan(scope, context)
    assert not plan.blocked
    pointer = state.pointer()
    consent = service.review(plan, 10.0, 20.0)
    result = service.provision(plan, consent, Cancel())
    after = service.verify(scope, context)
    assert c.digest(before) != c.digest(after)
    assert state.pointer() == pointer
    checkpoint = RecoveryStore(state).read(result.installation_id)
    if completion == "allow":
        assert not result.errors
        assert result.pending_actions == ("review-activation-plan",)
        assert checkpoint.observation_digest == c.digest(after)
    else:
        assert result.errors
        assert checkpoint.observation_digest == c.digest(before)
    # Neither a completed observation nor an immutable recovery record is
    # permission to replay the same consumed consent.
    with pytest.raises(AuthorizationError):
        service.resume(result.installation_id, consent, Cancel())
