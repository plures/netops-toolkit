"""Criteria-derived P02 acceptance closeout; synthetic host facts are not permits.

Frozen authority: P02 AC1--4, FR-011/012, typed lifecycle and N1 continuation.
Canonical215 remains untouched; all added expectations are independent host
expectations. Isolated internal validators are explicitly labeled, not fictional
end-to-end admitted programs exceeding earlier legitimate input bounds.
"""

import ast
import copy
import dataclasses
import json
from unittest import mock

import pytest
import test_reference_engine_p02_acceptance as base
import test_reference_engine_p02_safety as safety

from netops.ansible.policy import _validation as v
from netops.ansible.policy import contracts as c
from netops.ansible.policy import engine as eng
from netops.ansible.policy import loader

loaded = safety.loaded
CONTROLS = []
RUN_ID = "it-s-now-time-to-implement-full-ansible-and-mole-20261104-225210156-fb1f9495"


def lifecycle(loaded, kind="StepCompleted", phase="Staging", operation="install",
              next_kind="dependency-stage", pending=True):
    """Complete typed bound prerequisites, never host-authenticated qualification."""
    case = copy.deepcopy(next(x for x in base.HOST if x["case_id"] ==
                             "netops_companion_setup_consent_install_consented_restore_example_3"))
    raw = case["input"]["event"]
    raw["kind"] = kind
    raw["payload"] = {
        "invocation_id": "completion-i", "effect_id": "completion-e",
        "target_id": raw["target_id"], "step_id": raw["step_id"],
        "safe_result_digest": "3" * 64, "primary": "success", "cleanup": "success",
        "remote_uncertain": False,
    }
    if kind == "CandidateVerified":
        raw["payload"] = dict(
            candidate_digest="3" * 64, registry_digest="4" * 64, assets_digest="5" * 64,
            policy_digest=loaded[1].identity.bundle_sha256,
            qualification_digest="6" * 64, functional_evidence_ref="synthetic-qualified-receipt",
        )
    case["input"]["state"]["phase"] = phase
    values = case["input"]["facts"]
    values["request"]["operation"] = operation
    values["lifecycle"]["next_effect_kind"] = next_kind
    values["result"].update(selected=2 if pending else 1, completed=1, unsuccessful=0)
    engine, state, event, facts = safety.context(loaded, case)
    steps = (c.StepDisposition(
        event.target_id, event.step_id, invocation_id="completion-i", effect_id="completion-e",
    ),)
    if pending:
        steps += (c.StepDisposition("owned-next-target", "next-step",
                                   invocation_id="next-i", effect_id="next-e"),)
    return engine, dataclasses.replace(state, dispositions=steps), event, facts


def observation(loaded, status="failed", health="healthy"):
    case = copy.deepcopy(next(x for x in base.HOST if x["case_id"] ==
                             "netops_companion_health_observed_success_example_3"))
    case["input"]["facts"].pop("result")
    case["input"]["event"]["payload"]["disposition"] = status
    h = case["input"]["facts"]["health"]
    if health == "alert":
        h["reading"] = h["threshold"]
    elif health == "unknown":
        h["reading_present"] = False
    elif health == "unsupported":
        h["check_supported"] = False
    return safety.context(loaded, case)


def assert_error(exc, reason, call):
    """Exact safe reason and exception category; no partial returned permission."""
    with pytest.raises(exc) as caught:
        call()
    assert str(caught.value) == reason


@pytest.mark.parametrize("phase,operation,next_kind", [
    ("Staging", "install", "dependency-stage"),
    ("Verified", "install", "dependency-activate"),
    ("Admitted", "uninstall", "dependency-uninstall"),
    ("Admitted", "uninstall", "restore-active-pointer"),
])
def test_host_lifecycle_correlated_completion_retains_pending_and_next_intent(
    loaded, phase, operation, next_kind,
):
    engine, state, event, facts = lifecycle(
        loaded, phase=phase, operation=operation, next_kind=next_kind,
    )
    before = copy.deepcopy(state)
    decision = engine.decide(event, facts)
    assert decision.decision == "allow"
    assert [a.params["kind"] for a in decision.effects if a.name == "request_effect"] == [
        next_kind,
    ]
    transition = engine.reduce(state, event, facts)
    assert state == before
    result = transition.next_state
    assert result.phase not in (c.Phase.COMPLETED, c.Phase.ACTIVE)
    assert result.revision == state.revision + 1
    assert result.dispositions[0].disposition == c.Disposition.SUCCEEDED
    assert result.dispositions[0].result_digest == event.payload["safe_result_digest"]
    assert result.dispositions[1] == state.dispositions[1]
    assert result.dispositions[1].disposition == c.Disposition.NOT_REQUESTED
    assert result.consumed_effect_receipts == ("completion-e",)
    assert transition.effects == decision.effects


def test_host_no_completed_state_plus_lifecycle_next_intent_even_one_step_index(loaded):
    engine, state, event, facts = lifecycle(loaded, pending=False)
    result = engine.reduce(state, event, facts)
    assert any(a.name == "request_effect" for a in result.effects)
    assert result.next_state.phase != c.Phase.COMPLETED


def test_host_candidate_verified_staging_has_genuine_typed_activation_path(loaded):
    engine, state, event, facts = lifecycle(
        loaded, kind="CandidateVerified", next_kind="dependency-activate",
    )
    decision = engine.decide(event, facts)
    assert decision.decision == "allow"
    assert base._actions(decision.effects) == [
        {"name": "set_phase", "params": {"phase": "Verified"}},
        {"name": "request_effect", "params": {"kind": "dependency-activate"}},
    ]
    result = engine.reduce(state, event, facts)
    assert result.next_state.phase == c.Phase.VERIFIED
    assert result.next_state.dispositions == state.dispositions
    assert result.next_state.consumed_effect_receipts == ()


@pytest.mark.parametrize("group,field", [
    ("candidate", "verified"), ("candidate", "pointer_matches"),
    ("readiness", "selected_complete"), ("ownership", "valid"),
    ("consent", "binding_matches"), ("consent", "present"),
    ("consent", "effects_match"), ("binding", "plan_current"),
])
def test_host_candidate_activation_rechecks_each_bound_prerequisite(loaded, group, field):
    engine, state, event, facts = lifecycle(
        loaded, kind="CandidateVerified", next_kind="dependency-activate",
    )
    values = eng._wire(facts.values)
    values[group][field] = False
    changed = dataclasses.replace(facts, values=values)
    result = engine.reduce(state, event, changed)
    assert not any(a.name == "request_effect" for a in result.effects)
    assert state.revision == 1
    assert result.next_state.phase != c.Phase.ACTIVE


@pytest.mark.parametrize("kind", ("StepCompleted", "CandidateVerified"))
@pytest.mark.parametrize("guard", ("cancelled", "expired", "wrong-phase"))
def test_host_lifecycle_cancel_deadline_and_wrong_phase_no_activation(loaded, kind, guard):
    engine, state, event, facts = lifecycle(
        loaded, kind=kind, phase="Verified" if kind == "StepCompleted" else "Staging",
        next_kind="dependency-activate",
    )
    values = eng._wire(facts.values)
    if guard == "cancelled":
        values["control"]["cancelled"] = True
    elif guard == "expired":
        values["control"]["remaining_ms"] = 0
    else:
        state = dataclasses.replace(state, phase=c.Phase.OBSERVING)
        facts = dataclasses.replace(facts, state_phase=state.phase)
    facts = dataclasses.replace(facts, values=values)
    # Some wrong phases are missing-admit deny, others exact event conflict.
    decision = engine.decide(event, facts)
    if decision.decision == "deny":
        assert decision.effects == ()
        assert engine.reduce(state, event, facts).next_state == state
    else:
        assert_error(c.PolicyInputError, "policy-event-conflict",
                     lambda: engine.reduce(state, event, facts))


@pytest.mark.parametrize("status", ("success", "failed", "blocked", "unsupported", "cancelled"))
@pytest.mark.parametrize("health", ("healthy", "alert", "unknown", "unsupported"))
def test_host_observation_failure_cannot_be_promoted_by_findings(loaded, status, health):
    engine, state, event, facts = observation(loaded, status, health)
    result = engine.reduce(state, event, facts)
    finding = {"healthy": "success", "alert": "failed", "unknown": "failed",
               "unsupported": "unsupported"}[health]
    expected = (
        status if status != "success" else
        finding
    )
    disposition = c.Disposition.SUCCEEDED if expected == "success" else c.Disposition(expected)
    assert result.next_state.dispositions[0].disposition == disposition
    # FR-011/012 and LLD2.9: retain factual category, aggregate failure precedence.
    primary = next(s for s in ("failed", "cancelled", "unsupported", "blocked", "success")
                   if s in (status, finding))
    assert result.next_state.primary == primary
    assert result.next_state.dispositions[0].result_digest == event.payload["observation_digest"]
    assert result.next_state.phase == c.Phase.OBSERVING
    assert state.dispositions[0].disposition == c.Disposition.NOT_REQUESTED


def test_host_same_identity_semantic_copy_is_not_a_valid_program(loaded):
    program = loaded[1]
    rule = next(r for r in program.rules if
                r.id == "netops.companion.catalog_operation_requested_set_phase")
    changed = dataclasses.replace(rule, actions=(
        c.EffectDescriptor("set_phase", c.object_value({"phase": "Active"})),
    ))
    examples = []
    for example in program.examples:
        raw = eng._wire(example)
        if raw["rule_id"] == rule.id and raw["expect"]["decision"] == "allow":
            raw["expect"]["actions"] = base._actions(changed.actions)
        examples.append(c.object_value(raw))
    impostor = dataclasses.replace(
        program, rules=tuple(changed if r == rule else r for r in program.rules),
        examples=tuple(examples),
    )
    assert impostor.identity == program.identity
    assert impostor.content_digest == program.content_digest
    assert_error(c.PolicyLoadError, "policy-load-invalid",
                 lambda: eng.LocalReferencePolicyEngine(impostor))
    assert eng.LocalReferencePolicyEngine(program)._program == program


class MutableDescriptor:
    """Ordinary structural lookalike; no Python sandbox or host-permit claim."""

    def __init__(self):
        self.name = "set_phase"
        self.params = c.object_value({"phase": "Planned"})

    def __eq__(self, other):
        return self.name == other.name and self.params == other.params

    def __hash__(self):
        return hash((self.name, self.params))


@pytest.mark.parametrize("subclass", (False, True))
def test_host_mutable_descriptor_impostors_and_subclasses_are_rejected(loaded, subclass):
    class DerivedDescriptor(c.EffectDescriptor):
        pass

    descriptor = DerivedDescriptor("set_phase", {"phase": "Planned"}) if subclass else (
        MutableDescriptor()
    )
    program = loaded[1]
    rule = next(r for r in program.rules if
                r.id == "netops.companion.catalog_operation_requested_set_phase")
    changed = dataclasses.replace(rule, actions=(descriptor,))
    impostor = dataclasses.replace(
        program, rules=tuple(changed if r == rule else r for r in program.rules),
    )
    assert_error(c.PolicyLoadError, "policy-load-invalid",
                 lambda: eng.LocalReferencePolicyEngine(impostor))


def test_host_descriptor_parameter_detachment_and_previous_decision_stability(loaded):
    original = {"phase": "Planned"}
    descriptor = c.EffectDescriptor("set_phase", original)
    original["phase"] = "Active"
    assert dict(descriptor.params) == {"phase": "Planned"}
    engine, _, event, facts = safety.context(loaded)
    first = engine.decide(event, facts)
    snapshot = base._actions(first.effects)
    assert all(type(a) is c.EffectDescriptor for a in first.effects)
    assert base._actions(engine.decide(event, facts).effects) == snapshot
    assert base._actions(first.effects) == snapshot


@pytest.mark.parametrize("group", ("control", "consent"))
@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -float("inf"),
                                c.MAX_SAFE_INT + 1, True, 1.0, -1])
def test_host_supplied_remaining_ms_rejects_nonfinite_overflow_and_coercion(loaded, group, bad):
    engine, _, event, facts = safety.context(loaded)
    values = eng._wire(facts.values)
    values[group]["remaining_ms"] = bad
    assert_error(c.PolicyInputError, "policy-input-invalid",
                 lambda: engine.decide(event, dataclasses.replace(facts, values=values)))


@pytest.mark.parametrize("values,path", [
    ({}, ("request", "mode")), ({"request": {}}, ("request", "mode")),
    ({"request": True}, ("request", "mode")),
])
def test_host_isolated_missing_applicable_root_and_nested_fact(values, path):
    assert_error(c.PolicyInputError, "policy-input-invalid",
                 lambda: v.lookup(c.object_value(values), path))


@pytest.mark.parametrize("bad", [None, [], (), 1, "object"])
def test_host_isolated_object_value_requires_an_object(bad):
    assert_error(c.PolicyInputError, "policy-input-invalid", lambda: c.object_value(bad))


def test_host_exact_freeze_wrapper_depth_and_rejected_successor():
    value = True
    for _ in range(c.MAX_DEPTH + 8):
        value = [value]
    assert c.freeze(value) is not None
    assert_error(c.PolicyInputError, "policy-input-invalid", lambda: c.freeze([value]))


@pytest.mark.parametrize("bytes_per_char,char", [(1, "x"), (2, "é")])
def test_host_exact_utf8_text_boundary_is_bytes(bytes_per_char, char):
    at_limit = char * (4096 // bytes_per_char)
    assert len(at_limit.encode("utf-8")) == 4096
    assert v.text(at_limit) == at_limit
    assert_error(c.PolicyInputError, "policy-input-invalid", lambda: v.text(at_limit + "x"))


def test_host_isolated_expression_exact_node_depth_and_successor_guards():
    literal = c.object_value(base._literal("bool", True))
    builder = loader._Builder()
    for _ in range(c.MAX_NODES):
        assert builder.boolean(literal).value is True
    assert builder.nodes == 32768
    assert_error(c.PolicyInputError, "policy-input-invalid", lambda: builder.boolean(literal))
    assert builder.nodes == 32769
    nested = base._literal("bool", True)
    for _ in range(32):
        nested = {"kind": "paren", "operand": nested}
    assert loader._Builder().boolean(c.object_value(nested)).value_type == "bool"
    assert_error(c.PolicyInputError, "policy-input-invalid",
                 lambda: loader._Builder().boolean(
                     c.object_value({"kind": "paren", "operand": nested})))


def test_host_isolated_example_exact_depth_and_node_guards():
    # Explicit internal validator: earlier byte/wrapper limits can dominate load.
    nested = True
    for _ in range(32):
        nested = (nested,)
    assert loader._example_budget(nested) == 33
    assert_error(c.PolicyInputError, "policy-input-invalid",
                 lambda: loader._example_budget((nested,)))
    assert loader._example_budget((True,) * 32767) == 32768
    assert_error(c.PolicyInputError, "policy-input-invalid",
                 lambda: loader._example_budget((True,) * 32768))


EVENT_PAYLOADS = {
    "OperationRequested": dict(request_digest="1" * 64, loaded_input_digest="2" * 64,
                               plan_digest="1" * 64, mode="preview"),
    "DependencyObserved": dict(dependency_id="dep", context_digest="2" * 64,
                               probe_receipt="probe", probe_digest="3" * 64, readiness="ready"),
    "InstallConsented": dict(lifecycle_kind="install",
                            plan_id="30000000-0000-4000-8000-000000000003",
                            lifecycle_binding_digest="3" * 64, private_consent_reference="consent"),
    "Observed": dict(invocation_id="i", target_id="router-A", step_id="collect",
                     observation_ref="observation", observation_digest="3" * 64,
                     disposition="success"),
    "ApplyConsented": dict(plan_digest="1" * 64, approved_effect_ids=["effect"],
                           approved_recovery_ids=["recovery"], private_consent_reference="consent"),
    "StepCompleted": dict(invocation_id="i", effect_id="e", target_id="router-A", step_id="collect",
                          safe_result_digest="3" * 64, primary="success", cleanup="success",
                          remote_uncertain=False),
    "CandidateVerified": dict(candidate_digest="3" * 64, registry_digest="4" * 64,
                              assets_digest="5" * 64, policy_digest="9" * 64,
                              qualification_digest="6" * 64, functional_evidence_ref="synthetic"),
    "Activated": dict(expected_pointer_digest="3" * 64, current_pointer_digest="3" * 64,
                      new_pointer_digest="4" * 64, cas_receipt="cas"),
    "Cancelled": dict(accepted_host_receipt="cancel", revocation_revision=1, safe_reason="cancel"),
}


def typed_event(kind):
    install = kind in ("InstallConsented", "CandidateVerified", "Activated")
    return c.DecisionEvent(
        "40000000-0000-4000-8000-000000000004", c.EventKind(kind), 1,
        "1" * 64, "2" * 64, "9" * 64, "router-A", "collect", EVENT_PAYLOADS[kind],
        operation_id=None if install else "60000000-0000-4000-8000-000000000006",
        install_id="30000000-0000-4000-8000-000000000003" if install else None,
    )


@pytest.mark.parametrize("kind", tuple(EVENT_PAYLOADS))
def test_host_every_typed_event_requires_each_exact_payload_field(kind):
    event = typed_event(kind)
    assert v.event_value(event)["kind"] == kind
    for name in EVENT_PAYLOADS[kind]:
        changed = copy.deepcopy(EVENT_PAYLOADS[kind])
        del changed[name]
        assert_error(c.PolicyInputError, "policy-input-invalid",
                     lambda: v.event_value(dataclasses.replace(event, payload=changed)))
    changed = dict(EVENT_PAYLOADS[kind], unexpected=True)
    assert_error(c.PolicyInputError, "policy-input-invalid",
                 lambda: v.event_value(dataclasses.replace(event, payload=changed)))


@pytest.mark.parametrize("kind", [
    "OperationRequested", "Observed", "ApplyConsented",
    "InstallConsented", "CandidateVerified", "Activated",
])
def test_host_event_wrong_operation_install_namespace_rejected(kind):
    event = typed_event(kind)
    wrong = dataclasses.replace(event, operation_id=event.install_id, install_id=event.operation_id)
    assert_error(c.PolicyInputError, "policy-input-invalid", lambda: v.event_value(wrong))


@pytest.mark.parametrize("kind,field,bad", [
    ("OperationRequested", "mode", "execute"),
    ("DependencyObserved", "readiness", "healthy"),
    ("InstallConsented", "lifecycle_kind", "remove"),
    ("Observed", "disposition", "healthy"),
    ("StepCompleted", "primary", "healthy"), ("StepCompleted", "cleanup", "healthy"),
    ("OperationRequested", "plan_digest", "4" * 64),
    ("DependencyObserved", "context_digest", "4" * 64),
    ("CandidateVerified", "policy_digest", "4" * 64),
    ("Observed", "target_id", "other"), ("Observed", "step_id", "other"),
    ("StepCompleted", "target_id", "other"), ("StepCompleted", "step_id", "other"),
    ("Activated", "current_pointer_digest", "5" * 64),
])
def test_host_payload_domains_and_metadata_bindings_exact_guard(kind, field, bad):
    event = typed_event(kind)
    assert v.event_value(event)["kind"] == kind
    payload = copy.deepcopy(EVENT_PAYLOADS[kind])
    payload[field] = bad
    assert_error(c.PolicyInputError, "policy-input-invalid",
                 lambda: v.event_value(dataclasses.replace(event, payload=payload)))


@pytest.mark.parametrize("kind", ("uninstall", "restore"))
def test_host_lifecycle_plan_id_is_not_interchangeable_with_install_identity(kind):
    event = typed_event("InstallConsented")
    payload = dict(EVENT_PAYLOADS["InstallConsented"], lifecycle_kind=kind)
    assert v.event_value(dataclasses.replace(event, payload=payload))["kind"] == "InstallConsented"
    payload["plan_id"] = "50000000-0000-4000-8000-000000000005"
    assert_error(c.PolicyInputError, "policy-input-invalid",
                 lambda: v.event_value(dataclasses.replace(event, payload=payload)))


@pytest.mark.parametrize("field,bad", [
    ("path", []), ("children", []), ("path", ("request", "mode")),
    ("op", "Eq"), ("children", (c.Expression("literal", "bool", False),)),
    ("value_type", "int"),
])
def test_host_caller_expression_revalidation_is_distinct_from_raw_loading(loaded, field, bad):
    program = loaded[1]
    rule = program.rules[0]
    expression = c.Expression("literal", "bool", True)
    changed = dataclasses.replace(expression, **{field: bad})
    altered = dataclasses.replace(rule, conditions=(changed,))
    impostor = dataclasses.replace(program, rules=(altered,) + program.rules[1:])
    assert_error(c.PolicyLoadError, "policy-load-invalid",
                 lambda: eng.LocalReferencePolicyEngine(impostor))


@pytest.mark.parametrize("mode", ("no-facts", "wrong-phase", "mode-disagreement"))
def test_host_input_type_phase_and_payload_mode_rejection(loaded, mode):
    engine, _, event, facts = safety.context(loaded)
    if mode == "no-facts":
        facts = {}
    elif mode == "wrong-phase":
        facts = dataclasses.replace(facts, state_phase="Planned")
    else:
        # Valid distinct domains on both sides, so this reaches the equality guard.
        event = dataclasses.replace(event, payload=dict(eng._wire(event.payload), mode="check"))
    assert_error(c.PolicyInputError, "policy-input-invalid",
                 lambda: engine.decide(event, facts))


@pytest.mark.parametrize("fault", (
    "state-type", "revision-gap", "missing-selected", "wrong-invocation",
    "already-completed", "wrong-effect", "reused-effect", "factual-partial",
))
def test_host_correlated_completion_rejects_exact_pending_receipt_defects(loaded, fault):
    engine, state, event, facts = lifecycle(loaded, next_kind="none", pending=False,
                                            phase="Executing")
    if fault == "state-type":
        state = None
    elif fault == "revision-gap":
        state = dataclasses.replace(state, revision=2)
    elif fault == "missing-selected":
        state = dataclasses.replace(state, dispositions=())
    elif fault in ("wrong-invocation", "wrong-effect", "factual-partial"):
        key, value = {
            "wrong-invocation": ("invocation_id", "wrong-i"),
            "wrong-effect": ("effect_id", "wrong-e"), "factual-partial": ("primary", "partial"),
        }[fault]
        event = dataclasses.replace(event, payload=dict(eng._wire(event.payload), **{key: value}))
    else:
        first = dataclasses.replace(state.dispositions[0], disposition=c.Disposition.SUCCEEDED,
                                    result_digest="3" * 64)
        if fault == "already-completed":
            state = dataclasses.replace(state, dispositions=(first,))
        else:
            # Valid restored receipt index; wrong completion cannot consume it again.
            second = dataclasses.replace(first, target_id="prior", step_id="prior",
                                         invocation_id="prior-i")
            pending = dataclasses.replace(state.dispositions[0], effect_id="new-e")
            state = dataclasses.replace(state, dispositions=(pending, second),
                                        consumed_effect_receipts=("completion-e",))
    reason = "policy-input-invalid" if fault in ("state-type", "factual-partial") else (
        "policy-event-conflict"
    )
    before = copy.deepcopy(state)
    assert_error(c.PolicyInputError, reason, lambda: engine.reduce(state, event, facts))
    assert state == before


@pytest.mark.parametrize("value", (1, [], True))
def test_host_isolated_loader_sequence_and_expression_shapes(value):
    assert_error(c.PolicyInputError, "policy-input-invalid", lambda: loader._sequence(value))
    assert_error(c.PolicyInputError, "policy-input-invalid",
                 lambda: loader._Builder().boolean(value))


@pytest.mark.parametrize("node", [
    {"kind": "not", "operand": base._literal("int", 1)}, base._literal("int", 1),
])
def test_host_isolated_nonboolean_not_rule_guard_require(node):
    assert_error(c.PolicyInputError, "policy-input-invalid",
                 lambda: loader._Builder().boolean(c.object_value(node)))


@pytest.mark.parametrize("field,value", [
    ("profile", "other"), ("numeric_profile", "other"), ("schema", "2.0"),
    ("reducer_version", "other"), ("canonical_revision", "0" * 40),
    ("max_safe_int", True), ("max_safe_int", c.MAX_SAFE_INT - 1),
    ("source_digests", {"source": "0" * 64, "contracts": "0" * 64}),
    ("content_digest", "g" * 64),
])
def test_host_embedded_identity_drift_reaches_inner_loader_guard(loaded, field, value):
    assets = loaded[0]
    changed = base._mutated_assets(assets, lambda data: data.update({field: value}))
    if field == "content_digest":
        data = json.loads(changed[2])
        data[field] = value
        changed = (*changed[:2], base._json(data))
    expected = dataclasses.replace(loaded[1].identity, bundle_sha256=base._sha(changed[2]))
    assert expected.source_sha256 == base._sha(changed[0])
    assert_error(c.PolicyLoadError, "policy-load-invalid",
                 lambda: loader.load_policy(*changed, expected))


@pytest.mark.parametrize("index", (0, 1, 2))
@pytest.mark.parametrize("bad", (b"", b"\xff", b"x" * (c.MAX_BYTES + 1), bytearray(b"abc")),
                         ids=("empty", "invalid-utf8", "limit-plus-one", "wrong-type"))
def test_host_each_raw_operand_empty_type_utf8_and_immediate_byte_successor(loaded, index, bad):
    assets = list(loaded[0])
    assets[index] = bad
    names = ("source_sha256", "contracts_sha256", "bundle_sha256")
    expected = dataclasses.replace(loaded[1].identity, **{names[index]: base._sha(bad)})
    assert_error(c.PolicyLoadError, "policy-load-invalid",
                 lambda: loader.load_policy(*assets, expected))


@pytest.mark.parametrize("kind", ("source", "contracts", "bundle"))
def test_host_exact_asset_byte_limit_has_a_valid_positive(loaded, kind):
    """Rebind all identities, preserving producer bytes; no parser requalification."""
    assets = list(loaded[0])
    data = json.loads(assets[2])
    index = {"source": 0, "contracts": 1, "bundle": 2}[kind]
    if index < 2:
        assets[index] += b" " * (c.MAX_BYTES - len(assets[index]))
        data["source_digests"][kind] = base._sha(assets[index])
    data.pop("content_digest")
    without = base._json(data)
    if index == 2:
        # Digest member costs exactly 84 bytes: comma, quoted name, colon, quotes, hash.
        empty_member = b',"content_digest":"' + b"0" * 64 + b'"'
        padding = c.MAX_BYTES - len(without) - len(empty_member)
        assert padding >= 0
        data["content_digest"] = base._sha(without + b" " * padding)
        assets[2] = base._json(data) + b" " * padding
    else:
        data["content_digest"] = base._sha(without)
        assets[2] = base._json(data)
    assert len(assets[index]) == c.MAX_BYTES
    expected = base._identity(c, tuple(assets))
    result = loader.load_policy(*assets, expected)
    assert result.identity == expected


@pytest.mark.parametrize("field,bad", [
    ("decision", "permit"), ("next_phase", "Other"), ("aggregate", "healthy"),
    ("error", "secret-error"), ("constraint_outcomes", []),
    ("constraint_outcomes", {"unknown": "satisfied"}),
])
def test_host_example_expectations_have_closed_domains(loaded, field, bad):
    value = eng._wire(loaded[1].examples[0])
    value["expect"][field] = bad
    assert_error(c.PolicyInputError, "policy-input-invalid", lambda: loader._example(
        c.object_value(value), set(loaded[1].identity.rule_manifest),
        {d.id for d in loaded[1].constraints},
    ))


@pytest.mark.parametrize("section", ("state", "event", "facts"))
def test_host_example_containers_are_not_scalar_or_sequence(loaded, section):
    value = eng._wire(loaded[1].examples[0])
    value["input"][section] = []
    assert_error(c.PolicyInputError, "policy-input-invalid", lambda: loader._example(
        c.object_value(value), set(loaded[1].identity.rule_manifest),
        {d.id for d in loaded[1].constraints},
    ))


@pytest.mark.parametrize("mode", ("duplicate-actions", "conflicting-actions", "outcome-value",
                                 "reserved-facts", "mismatched-actions", "nonobject-facts"))
def test_host_example_actions_bindings_and_constraint_outcomes_reject(loaded, mode):
    example = next(e for e in loaded[1].examples if
                   e["expect"]["decision"] == "allow" and len(e["expect"]["actions"]) == 1)
    value = eng._wire(example)
    if mode == "duplicate-actions":
        value["expect"]["actions"] *= 2
    elif mode == "conflicting-actions":
        value["expect"]["actions"] = [
            {"name": "set_phase", "params": {"phase": "Planned"}},
            {"name": "set_phase", "params": {"phase": "Active"}},
        ]
    elif mode == "outcome-value":
        value["expect"]["constraint_outcomes"] = {
            loaded[1].constraints[0].id: "passed",
        }
    elif mode == "reserved-facts":
        value["input"]["facts"]["state"] = {"phase": "Planned"}
    elif mode == "mismatched-actions":
        value["expect"]["actions"] = [{"name": "revoke_pending", "params": {"scope": "operation"}}]
    else:
        value["input"]["facts"] = []
    frozen = c.object_value(value)
    if mode in ("reserved-facts", "mismatched-actions", "nonobject-facts"):
        def call():
            return loader.validate_example_bindings(
                (frozen,), loaded[1].rules + loaded[1].constraints,
            )
    else:
        def call():
            return loader._example(frozen, set(loaded[1].identity.rule_manifest),
                                   {d.id for d in loaded[1].constraints})
    assert_error(c.PolicyInputError, "policy-input-invalid", call)


@pytest.mark.parametrize("fault", ("selected-size", "category-count", "remote-uncertainty",
                                  "retained-cleanup-unreported"))
def test_host_terminal_complete_index_and_retained_flags_reject_exact_disagreement(loaded, fault):
    engine, state, event, facts = lifecycle(
        loaded, phase="Executing", next_kind="none", pending=False,
    )
    values = eng._wire(facts.values)
    if fault == "selected-size":
        values["result"].update(selected=2, completed=2)
    elif fault == "category-count":
        values["result"].update(completed=0, unsuccessful=1, failed=1)
    elif fault == "remote-uncertainty":
        state = dataclasses.replace(state, remote_uncertain=True)
    else:
        state = dataclasses.replace(state, cleanup="failed")
    changed = dataclasses.replace(facts, values=values)
    assert_error(c.PolicyInputError, "policy-input-invalid",
                 lambda: engine.reduce(state, event, changed))


@pytest.mark.parametrize("prior_uncertain", (False, True))
@pytest.mark.parametrize("current_uncertain", (False, True))
def test_host_remote_uncertainty_never_disappears(loaded, prior_uncertain, current_uncertain):
    engine, state, event, facts = lifecycle(
        loaded, phase="Executing", next_kind="none", pending=False,
    )
    state = dataclasses.replace(state, remote_uncertain=prior_uncertain)
    event = dataclasses.replace(
        event, payload=dict(eng._wire(event.payload), remote_uncertain=current_uncertain),
    )
    values = eng._wire(facts.values)
    values["result"]["remote_uncertain"] = prior_uncertain or current_uncertain
    result = engine.reduce(state, event, dataclasses.replace(facts, values=values))
    assert result.next_state.remote_uncertain is (prior_uncertain or current_uncertain)
    assert result.next_state.phase == (
        c.Phase.UNCERTAIN if prior_uncertain or current_uncertain else c.Phase.COMPLETED
    )


@pytest.mark.parametrize("current_cleanup", ("success", "failed"))
def test_host_retained_cleanup_failure_with_reported_flag_cannot_be_erased(loaded, current_cleanup):
    engine, state, event, facts = lifecycle(
        loaded, phase="Executing", next_kind="none", pending=False,
    )
    state = dataclasses.replace(state, cleanup="failed")
    event = dataclasses.replace(
        event, payload=dict(eng._wire(event.payload), cleanup=current_cleanup),
    )
    values = eng._wire(facts.values)
    values["result"]["cleanup_failed"] = True
    result = engine.reduce(state, event, dataclasses.replace(facts, values=values))
    assert result.next_state.cleanup == "failed"
    assert result.next_state.primary == "failed"


def test_host_invalid_zero_unsuccessful_with_nonzero_category_cannot_pass_final_counter():
    good = dict(selected=1, completed=1, unsuccessful=0, failed=0, cancelled=0, unsupported=0,
                blocked=0, policy_failed=False, cleanup_failed=False, remote_uncertain=False)
    v.final_counters(c.object_value(good))
    for key in ("failed", "cancelled", "unsupported", "blocked"):
        assert_error(c.PolicyInputError, "policy-input-invalid",
                     lambda: v.final_counters(c.object_value(dict(good, **{key: 1}))))


def _assert_operator_semantics():
    node = safety.expression("Eq", 1, 1, "int")
    assert eng._Evaluation(c.FrozenObject()).boolean(node) is True
    assert eng._Evaluation(c.FrozenObject()).boolean(
        safety.expression("Gt", -0.0, 0.0, "float"),
    ) is False


def _assert_failed_observation(loaded):
    engine, state, event, facts = observation(loaded)
    result = engine.reduce(state, event, facts)
    assert result.next_state.dispositions[0].disposition == c.Disposition.FAILED
    assert result.next_state.primary == "failed"


def control(facet, assertion, owner, name, replacement, expected=AssertionError):
    assertion()
    with mock.patch.object(owner, name, replacement):
        with pytest.raises(expected):
            assertion()
    assertion()
    CONTROLS.append(dict(facet=facet, assertion=assertion.__name__, positive="pass",
                         narrow_regression="failed", restored="pass", owner=str(owner),
                         predicate=name, not_a_whole_criterion_revert=True))


def test_load_bearing_ac1_permitted_operator_semantics():
    original = eng._Evaluation.evaluate

    def wrong_equality(self, expr):
        if expr.kind == "binary" and expr.op == "Eq":
            return False
        return original(self, expr)

    control("AC1.exact-allowed-operator", _assert_operator_semantics,
            eng._Evaluation, "evaluate", wrong_equality)


def test_load_bearing_ac2_same_identity_semantic_copy(loaded):
    control("AC2.program-identity", lambda: test_host_same_identity_semantic_copy_is_not_a_valid_program(
        loaded), eng.LocalReferencePolicyEngine, "_validate_program", staticmethod(lambda program: None),
        pytest.fail.Exception)


def test_load_bearing_ac3_failed_observation_preservation(loaded):
    original = eng.LocalReferencePolicyEngine.reduce

    def promote(self, state, event, facts):
        result = original(self, state, event, facts)
        green = tuple(dataclasses.replace(step, disposition=c.Disposition.SUCCEEDED)
                      for step in result.next_state.dispositions)
        return dataclasses.replace(result, next_state=dataclasses.replace(
            result.next_state, dispositions=green, primary="success",
        ))

    control("AC3.factual-status-preservation", lambda: _assert_failed_observation(loaded),
            eng.LocalReferencePolicyEngine, "reduce", promote)


def assert_docs_contract(api_doc, architecture):
    """Actual same-change contract pins; references to a method alone are inadequate."""
    api = api_doc.split("## P02 pure local reference policy core", 1)[1]
    arch = architecture.split("## P02 local runtime boundary", 1)[1]
    for text in (
        "load_policy(source: bytes, contracts: bytes, bundle: bytes,",
        "expected: PolicyIdentity) -> PolicyProgram",
        "LocalReferencePolicyEngine(program: PolicyProgram)",
        "engine.decide(event: DecisionEvent, facts: DecisionFacts) -> DecisionResult",
        "engine.reduce(state: PolicyState, event: DecisionEvent,",
        "facts: DecisionFacts) -> PolicyTransition",
        "intents", "never consent", "1 MiB", "512 declarations",
        "32,768", "200,000", "4,096", "exact-int53-finite-order-v1",
    ):
        assert text in api, text
    for text in ("LocalPolicyPort.decide", "reduce", "Frozen", "constraints", "no", "Python"):
        assert text.lower() in arch.lower(), text
    assert not hasattr(eng.LocalReferencePolicyEngine, "authorize")


def assert_stdlib_runtime(sources):
    allowed = {
        "__future__", "collections", "dataclasses", "enum", "hashlib", "json", "math", "typing",
    }
    for text in sources.values():
        tree = ast.parse(text, feature_version=(3, 9))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(n.name.split(".")[0] in allowed for n in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                assert node.module.split(".")[0] in allowed
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec", "compile", "__import__"}


def test_load_bearing_ac4_actual_same_change_docs_contract():
    api_path = base.ROOT / "docs/api/ansible.md"
    arch_path = base.ROOT / "documentation/ansible-px-reference/ansible-px-reference-architecture.md"
    api, arch = api_path.read_text(encoding="utf-8"), arch_path.read_text(encoding="utf-8")
    assert_docs_contract(api, arch)
    for original, changed in (
        (api, api.replace("facts: DecisionFacts) -> DecisionResult", "facts: str) -> bool")),
        (api, api.replace("expected: PolicyIdentity) -> PolicyProgram", "expected: str) -> bool")),
    ):
        assert original != changed
        with pytest.raises(AssertionError):
            assert_docs_contract(changed, arch)
    with pytest.raises((AssertionError, IndexError)):
        assert_docs_contract(api, arch.split("## P02 local runtime boundary")[0])
    assert_docs_contract(api, arch)
    CONTROLS.append(dict(facet="AC4.same-change-docs", positive="pass",
                         narrow_regressions=3, regression="failed", restored="pass",
                         actual_files=[str(api_path), str(arch_path)]))


def test_load_bearing_ac4_actual_stdlib_runtime_contract():
    sources = {n: (base.POLICY / n).read_text(encoding="utf-8") for n in (
        "__init__.py", "contracts.py", "_validation.py", "loader.py", "engine.py",
    )}
    assert_stdlib_runtime(sources)
    for bad in ("import subprocess", "import px_napi", "import requests", "import node"):
        changed = dict(sources)
        changed["engine.py"] += "\n" + bad
        with pytest.raises(AssertionError):
            assert_stdlib_runtime(changed)
    assert_stdlib_runtime(sources)
    CONTROLS.append(dict(facet="AC4.stdlib-runtime", positive="pass",
                         regression="failed", restored="pass", regressions=4))


def bounded_program_assets(loaded, action_groups):
    """Host-authored valid strict profile, not new canonical derivation evidence."""
    data = json.loads(loaded[0][2])
    data.update(rules=[], constraints=[], manifest=[], contracts=[])
    for index, actions in enumerate(action_groups):
        name = f"netops.companion.boundary_{index:04d}"
        source_id = f"netops_companion_boundary_{index:04d}"
        data["manifest"].append(dict(id=name, source_id=source_id, required_paths=[]))
        data["rules"].append(dict(id=name, source_id=source_id, kind="rule", order=index,
                                  conditions=[base._literal("bool", True)], actions=actions))
        data["contracts"].append(dict(
            case_id=source_id + "_example_0", rule_id=name,
            input=dict(state={"phase": "Planned"}, event={"kind": "OperationRequested"}, facts={}),
            expect=dict(decision="allow", reason=None, actions=actions, next_phase=None,
                        aggregate=None, constraint_outcomes={}, error=None),
        ))
    data.pop("content_digest")
    data["content_digest"] = base._sha(base._json(data))
    assets = (*loaded[0][:2], base._json(data))
    assert len(assets[2]) < c.MAX_BYTES
    return assets, base._identity(c, assets)


def test_host_exact_unique_declaration_count_512_accepts_513_rejects(loaded):
    action = [{"name": "set_phase", "params": {"phase": "Planned"}}]
    accepted, identity = bounded_program_assets(loaded, [action] * 512)
    program = loader.load_policy(*accepted, identity)
    assert len(program.rules) == len(set(identity.rule_manifest)) == 512
    assert eng.LocalReferencePolicyEngine(program)._program.identity == identity
    rejected, identity = bounded_program_assets(loaded, [action] * 513)
    # Unique names, consecutive orders, valid actions and <1MiB: exact count guard.
    assert len(set(identity.rule_manifest)) == 513
    assert_error(c.PolicyLoadError, "policy-load-invalid",
                 lambda: loader.load_policy(*rejected, identity))


@pytest.mark.parametrize("actions", [
    [[{"name": "request_effect", "params": {"kind": "collect"}}],
     [{"name": "request_effect", "params": {"kind": "gather"}}]],
    [[{"name": "set_phase", "params": {"phase": "Planned"}}],
     [{"name": "set_phase", "params": {"phase": "Planned"}}]],
    [[{"name": "set_phase", "params": {"phase": "Planned"}}],
     [{"name": "set_phase", "params": {"phase": "Active"}}]],
    [[{"name": "record_step", "params": {"disposition": "success"}}],
     [{"name": "record_step", "params": {"disposition": "failed"}}]],
    [[{"name": "record_outcome", "params": {"status": "success"}}],
     [{"name": "record_outcome", "params": {"status": "failed"}}]],
], ids=("multiple-effect-rules", "duplicate", "phase-conflict", "step-conflict", "outcome-conflict"))
def test_host_valid_loaded_program_ambiguous_decision_returns_no_partial_allow(loaded, actions):
    assets, identity = bounded_program_assets(loaded, actions)
    engine = eng.LocalReferencePolicyEngine(loader.load_policy(*assets, identity))
    _, _, event, facts = safety.context(loaded)
    event = dataclasses.replace(event, policy_digest=identity.bundle_sha256)
    assert_error(c.PolicyEvaluationError, "policy-evaluation-failed",
                 lambda: engine.decide(event, facts))


@pytest.mark.parametrize("action,kind", [
    ({"name": "record_step", "params": {"disposition": "partial"}}, "StepCompleted"),
    ({"name": "record_outcome", "params": {"status": "partial"}}, "Observed"),
    ({"name": "record_step", "params": {"disposition": "success"}}, "OperationRequested"),
])
def test_host_typed_action_single_disposition_and_missing_receipt_guards(loaded, action, kind):
    assets, identity = bounded_program_assets(loaded, [[action]])
    program = loader.load_policy(*assets, identity)
    engine = eng.LocalReferencePolicyEngine(program)
    if kind == "StepCompleted":
        _, state, event, facts = lifecycle(
            loaded, phase="Executing", pending=False, next_kind="none",
        )
    elif kind == "Observed":
        _, state, event, facts = observation(loaded, "success")
    else:
        _, state, event, facts = safety.context(loaded)
    event = dataclasses.replace(event, policy_digest=identity.bundle_sha256)
    state = dataclasses.replace(state, identity=identity, policy_digest=identity.bundle_sha256)
    assert_error(c.PolicyInputError, "policy-input-invalid",
                 lambda: engine.reduce(state, event, facts))


@pytest.mark.parametrize("status", ("success", "failed"))
def test_host_record_step_valid_correlated_results_preserve_exact_disposition(loaded, status):
    assets, identity = bounded_program_assets(loaded, [[
        {"name": "record_step", "params": {"disposition": status}},
    ]])
    program = loader.load_policy(*assets, identity)
    engine = eng.LocalReferencePolicyEngine(program)
    _, state, event, facts = lifecycle(
        loaded, phase="Executing", next_kind="none", pending=False,
    )
    values = eng._wire(facts.values)
    values["result"].update(completed=int(status == "success"), unsuccessful=int(status != "success"),
                            failed=int(status == "failed"))
    facts = dataclasses.replace(facts, values=values)
    payload = dict(eng._wire(event.payload), primary=status)
    event = dataclasses.replace(event, policy_digest=identity.bundle_sha256, payload=payload)
    state = dataclasses.replace(state, identity=identity, policy_digest=identity.bundle_sha256)
    result = engine.reduce(state, event, facts)
    assert result.next_state.dispositions[0].disposition == (
        c.Disposition.SUCCEEDED if status == "success" else c.Disposition.FAILED
    )
