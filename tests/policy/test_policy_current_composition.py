"""FR-018/024: explicit backup occurrences, output intent and current PX parity.

These are policy decisions, not device execution or authorization-broker proof.
Expectations come from frozen backup protection/retention/Git intent requirements.
"""

import hashlib
import json

import pytest
from test_policy_derivation import (
    CONTRACTS,
    SOURCE,
    cancellation_facts,
    full_occurrence_case,
)
from test_policy_derivation import canonical_context as canonical_context

from netops.ansible.policy import contracts as c
from netops.ansible.policy.engine import LocalReferencePolicyEngine
from netops.ansible.policy.loader import load_policy

TARGETS = {
    "collect": "netops_companion_config_collect_operation_requested_backup_collect",
    "backup": "netops_companion_config_collect_operation_requested_backup",
    "retention": "netops_companion_config_collect_operation_requested_backup_retention",
    "git": "netops_companion_config_collect_operation_requested_backup_git",
}


@pytest.fixture(scope="module")
def runtime():
    source, contracts, raw = SOURCE.read_bytes(), CONTRACTS.read_bytes(), (
        SOURCE.with_name("bundle.json").read_bytes()
    )
    bundle = json.loads(raw)
    identity = c.PolicyIdentity(
        canonical_revision="6d367fe673756dabaa6085bc6b5202debaaabe6f",
        source_sha256=hashlib.sha256(source).hexdigest(),
        contracts_sha256=hashlib.sha256(contracts).hexdigest(),
        bundle_sha256=hashlib.sha256(raw).hexdigest(),
        rule_manifest=tuple(item["id"] for item in bundle["manifest"]),
        reducer_version=bundle["reducer_version"],
    )
    return LocalReferencePolicyEngine(load_policy(source, contracts, raw, identity)), identity


def backup_input(kind, mode="output"):
    """Complete independent nonsecret policy facts; no corpus-derived defaults."""
    facts = cancellation_facts("backup", False, 1000, False)
    facts["request"] = {"area": "config", "operation": "backup", "mode": mode}
    facts["operational"] = {"next_effect_kind": kind}
    facts["output"] = {"retention_requested": True, "git_requested": True}
    return {
        "state": {"phase": "Planned", "revision": 1},
        "event": {
            "schema": "1.0", "kind": "OperationRequested", "expected_revision": 1,
            "event_id": "40000000-0000-4000-8000-000000000004",
            "operation_id": "60000000-0000-4000-8000-000000000006",
            "plan_digest": "1" * 64, "context_digest": "2" * 64,
            "policy_digest": "9" * 64, "target_id": "owned-backup",
            "step_id": "explicit-occurrence",
            "payload": {"request_digest": "3" * 64, "loaded_input_digest": "4" * 64,
                        "plan_digest": "1" * 64, "mode": mode},
        },
        "facts": facts,
    }


def decide(runtime, inputs):
    engine, identity = runtime
    facts = inputs["facts"]
    event = c.DecisionEvent(
        schema="1.0", event_id="40000000-0000-4000-8000-000000000004",
        operation_id="60000000-0000-4000-8000-000000000006",
        kind=c.EventKind.OPERATION_REQUESTED, expected_revision=1,
        plan_digest="1" * 64, context_digest="2" * 64,
        policy_digest=identity.bundle_sha256, target_id="owned-backup",
        step_id="explicit-occurrence",
        payload={"request_digest": "3" * 64, "loaded_input_digest": "4" * 64,
                 "plan_digest": "1" * 64, "mode": facts["request"]["mode"]},
    )
    result = engine.decide(event, c.DecisionFacts(
        values=facts, state_phase=c.Phase.PLANNED, state_revision=1,
    ))
    return result.decision, [
        {"name": effect.name, "params": dict(effect.params)} for effect in result.effects
    ]


@pytest.mark.parametrize("kind", TARGETS)
def test_current_backup_occurrence_has_one_exact_canonical_and_runtime_intent(
    canonical_context, runtime, kind
):
    inputs = backup_input(kind)
    actions = [{"name": "request_effect", "params": {"kind": kind}}]
    canonical = full_occurrence_case(canonical_context, TARGETS[kind], inputs, actions)
    assert canonical["combined"]["decision"] == "allow"
    assert canonical["combined"]["actions"] == actions
    assert decide(runtime, inputs) == ("allow", actions)


@pytest.mark.parametrize("kind", TARGETS)
@pytest.mark.parametrize("mutation", [
    "preview", "check", "wrong-resource", "no-next-occurrence", "missing-consent",
    "expired-consent", "binding-mismatch", "effects-mismatch", "cancelled",
])
def test_backup_wrong_mode_resource_or_unconsented_output_never_dispatches(
    canonical_context, runtime, kind, mutation
):
    inputs = backup_input(kind)
    facts = inputs["facts"]
    fires = True
    if mutation in ("preview", "check"):
        facts["request"]["mode"] = mutation
        inputs["event"]["payload"]["mode"] = mutation
        fires = False
    elif mutation == "wrong-resource":
        facts["request"]["area"] = "inventory"
        fires = False
    elif mutation == "no-next-occurrence":
        facts["operational"]["next_effect_kind"] = "none"
        fires = False
    elif mutation == "cancelled":
        facts["control"]["cancelled"] = True
    else:
        field, value = {
            "missing-consent": ("present", False), "expired-consent": ("remaining_ms", 0),
            "binding-mismatch": ("binding_matches", False),
            "effects-mismatch": ("effects_match", False),
        }[mutation]
        facts["consent"][field] = value
    actions = [{"name": "request_effect", "params": {"kind": kind}}] if fires else []
    canonical = full_occurrence_case(canonical_context, TARGETS[kind], inputs, actions, fires)
    combined = canonical["combined"]
    assert not [effect for effect in combined["actions"] if effect["name"] == "request_effect"]
    if mutation not in ("preview", "check"):
        assert combined["decision"] == "deny"
    assert decide(runtime, inputs) == (combined["decision"], combined["actions"])


@pytest.mark.parametrize("kind,flag", [
    ("retention", "retention_requested"), ("git", "git_requested"),
])
def test_backup_followups_require_their_own_explicit_output_intent(
    canonical_context, runtime, kind, flag
):
    inputs = backup_input(kind)
    inputs["facts"]["output"][flag] = False
    canonical = full_occurrence_case(
        canonical_context, TARGETS[kind], inputs, [], fires=False,
    )
    assert canonical["combined"]["decision"] == "deny"
    assert canonical["combined"]["actions"] == []
    assert decide(runtime, inputs) == ("deny", [])


@pytest.mark.parametrize("kind", TARGETS)
def test_backup_observe_can_only_collect_and_never_publish_or_run_followups(
    canonical_context, runtime, kind
):
    """FR-024 separates read-only collection from each sensitive output effect."""
    inputs = backup_input(kind, "observe")
    actions = (
        [{"name": "request_effect", "params": {"kind": "collect"}}] if kind == "collect" else []
    )
    canonical = full_occurrence_case(
        canonical_context, TARGETS[kind], inputs, actions, fires=kind == "collect",
    )
    expected_decision = "allow" if kind == "collect" else "deny"
    assert canonical["combined"]["decision"] == expected_decision
    assert canonical["combined"]["actions"] == actions
    assert decide(runtime, inputs) == (expected_decision, actions)
