"""Independent frozen-P02 safety gaps; canonical and host expectations stay separate.

No product writes, live clients, acquisition, or canonical tool invocation. The
exact T29 benchmark needs WorkflowService.preview(request, loaded); this module
does not mislabel repeated engine decisions as that unavailable benchmark.
"""

import copy
import dataclasses
import importlib
import math
import operator
import sys
from unittest import mock

import pytest
import test_reference_engine_p02_acceptance as base

from netops.ansible.policy import _validation as v
from netops.ansible.policy import contracts as c
from netops.ansible.policy import engine as eng
from netops.ansible.policy import loader

OPS = {
    "Eq": operator.eq, "Neq": operator.ne, "Gt": operator.gt,
    "Lt": operator.lt, "Gte": operator.ge, "Lte": operator.le,
}
INTS = (-base.MAX_INT, -base.MAX_INT + 1, -1, 0, 1, base.MAX_INT - 1, base.MAX_INT)
FLOATS = (-sys.float_info.max, -5e-324, -0.0, 0.0, 5e-324, sys.float_info.max)
MUTATION_RESULTS = []
BUDGET_RESULTS = {}


@pytest.fixture(scope="module")
def loaded():
    """Load real frozen bytes once; new tests do not alter packaged resources."""
    assets = tuple((base.POLICY / n).read_bytes() for n in (
        "ansible_molecule.px", "ansible_molecule.contracts.px", "bundle.json",
    ))
    identity = base._identity(c, assets)
    program = loader.load_policy(*assets, identity)
    return assets, program, eng.LocalReferencePolicyEngine(program)


def context(loaded, case=None):
    """Build a strict real catalog envelope with independently retained state."""
    _, program, engine = loaded
    case = copy.deepcopy(case or base.HOST[0])
    event = base._event(c, program, case["input"]["event"])
    facts = base._facts(c, case["input"]["facts"], case["input"]["state"])
    state = base._state(c, program, event, case["input"]["state"])
    return engine, state, event, facts


def expression(op, left, right, ty):
    return loader._Builder().boolean(c.object_value(
        base._binary(op, base._literal(ty, left), base._literal(ty, right)),
    ))


@pytest.mark.parametrize("op", tuple(OPS))
@pytest.mark.parametrize("left", INTS)
@pytest.mark.parametrize("right", INTS)
def test_host_int53_all_six_operator_boundary_cross_product(op, left, right):
    """Host mathematical oracle; NOT new canonical evaluator output."""
    node = expression(op, left, right, "int")
    assert eng._Evaluation(c.FrozenObject()).boolean(node) is OPS[op](left, right)


@pytest.mark.parametrize("op", ("Gt", "Lt", "Gte", "Lte"))
@pytest.mark.parametrize("left", FLOATS)
@pytest.mark.parametrize("right", FLOATS)
def test_host_finite_binary64_order_boundary_cross_product(op, left, right):
    assert math.isfinite(left) and math.isfinite(right)
    node = expression(op, left, right, "float")
    assert eng._Evaluation(c.FrozenObject()).boolean(node) is OPS[op](left, right)


@pytest.mark.parametrize("ty,left,right", [
    ("bool", True, False), ("bool", True, True), ("string", "", ""),
    ("string", "é", "e"), ("string", "same", "same"),
])
@pytest.mark.parametrize("op", ("Eq", "Neq"))
def test_host_same_type_boolean_string_equality(ty, left, right, op):
    assert eng._Evaluation(c.FrozenObject()).boolean(
        expression(op, left, right, ty),
    ) is OPS[op](left, right)


@pytest.mark.parametrize("case", base.CASES, ids=lambda x: x["case_id"])
def test_canonical_all_recorded_expression_values(loaded, case):
    """Replay pinned P01 expression oracle, including minimal non-host examples."""
    _, program, _ = loaded
    declaration = next(d for d in program.rules + program.constraints if d.id == case["rule_id"])
    raw = case["input"]
    values = c.object_value(dict(raw["facts"], event=raw["event"], state=raw["state"]))
    evaluation = eng._Evaluation(values)
    nodes = declaration.conditions
    if declaration.required is not None:
        nodes += (declaration.required,)
    actual = [evaluation.evaluate(node) for node in nodes]
    assert actual == case["canonical"]["expression_values"]


@pytest.mark.parametrize("op", ("And", "Or"))
@pytest.mark.parametrize("left", (True, False))
@pytest.mark.parametrize("right", (True, False))
def test_host_boolean_operators_and_short_circuit(op, left, right):
    evaluation = eng._Evaluation(c.FrozenObject())
    assert evaluation.boolean(expression(op, left, right, "bool")) is (
        (left and right) if op == "And" else (left or right)
    )
    assert evaluation.visits == (2 if (op == "And" and not left) or (
        op == "Or" and left
    ) else 3)


@pytest.mark.parametrize("kind", ("not", "paren"))
@pytest.mark.parametrize("value", (True, False))
def test_host_unary_and_parentheses(kind, value):
    node = loader._Builder().boolean(c.object_value({
        "kind": kind, "operand": base._literal("bool", value),
    }))
    assert eng._Evaluation(c.FrozenObject()).boolean(node) is (
        not value if kind == "not" else value
    )


@pytest.mark.parametrize("bad", [
    {}, {"request": {}}, {"event": {"kind": "OperationRequested"}},
    {"state": {"revision": 1}}, {"request": {"mode": "unknown"}},
    {"health": {"reading": 1}}, {"request": {"__class__": "x"}},
])
def test_host_closed_fact_tree_rejects_empty_reserved_and_wrong_types(loaded, bad):
    engine, _, event, facts = context(loaded)
    with pytest.raises(c.PolicyInputError, match="policy-input-invalid"):
        engine.decide(event, dataclasses.replace(facts, values=bad))


@pytest.mark.parametrize("field,bad", [
    ("operation_id", None), ("operation_id", "not-uuid"), ("install_id", "1" * 36),
    ("event_id", "0" * 36), ("target_id", ""), ("step_id", "line\nbreak"),
    ("context_digest", "g" * 64), ("policy_digest", "0" * 64),
    ("kind", "OperationRequested"), ("schema", None),
])
def test_host_event_metadata_identity_and_namespace_rejected(loaded, field, bad):
    engine, _, event, facts = context(loaded)
    with pytest.raises(c.PolicyInputError):
        engine.decide(dataclasses.replace(event, **{field: bad}), facts)


@pytest.mark.parametrize("field,bad", [
    ("schema", "2.0"), ("namespace", "restore"), ("phase", "Planned"),
    ("policy_digest", "0" * 64), ("last_event_id", "1" * 36),
    ("last_event_digest", "1" * 64), ("remote_uncertain", 1),
    ("primary", "healthy"), ("cleanup", "healthy"),
    ("consumed_effect_receipts", ("unissued",)), ("dispositions", []),
    ("identity", None), ("operation_id", "bad"), ("revision", -1),
])
def test_host_restored_state_is_closed_and_identity_bound(loaded, field, bad):
    engine, state, event, facts = context(loaded)
    before = copy.deepcopy(state)
    with pytest.raises(c.PolicyInputError):
        engine.reduce(dataclasses.replace(state, **{field: bad}), event, facts)
    assert state == before


@pytest.mark.parametrize("mode", [
    "duplicate-key", "duplicate-invocation", "duplicate-effect", "missing-result",
    "pending-result", "wrong-status", "wrong-step-type",
])
def test_host_selected_disposition_index_integrity(loaded, mode):
    engine, state, event, facts = context(loaded)
    first = c.StepDisposition("router-A", "collect", invocation_id="i", effect_id="e")
    second = c.StepDisposition("router-B", "collect", invocation_id="j", effect_id="f")
    if mode == "duplicate-key":
        second = dataclasses.replace(second, target_id="router-A")
    elif mode == "duplicate-invocation":
        second = dataclasses.replace(second, invocation_id="i")
    elif mode == "duplicate-effect":
        second = dataclasses.replace(second, effect_id="e")
    elif mode == "missing-result":
        first = dataclasses.replace(first, disposition=c.Disposition.FAILED)
    elif mode == "pending-result":
        first = dataclasses.replace(first, result_digest="1" * 64)
    elif mode == "wrong-status":
        first = dataclasses.replace(first, disposition="succeeded")
    else:
        first = "not-a-step"
    with pytest.raises(c.PolicyInputError):
        engine.reduce(dataclasses.replace(state, dispositions=(first, second)), event, facts)


@pytest.mark.parametrize("status", ("success", "failed", "blocked", "unsupported", "cancelled"))
def test_host_observation_records_exact_selected_disposition(loaded, status):
    case = copy.deepcopy(next(x for x in base.HOST if x["case_id"] ==
                             "netops_companion_health_observed_success_example_3"))
    del case["input"]["facts"]["result"]
    case["input"]["event"]["payload"]["disposition"] = status
    engine, state, event, facts = context(loaded, case)
    transition = engine.reduce(state, event, facts)
    # Frozen FR-011/012: a healthy finding cannot erase execution failure.
    assert state.dispositions[0].result_digest is None
    assert transition.next_state.dispositions[0].result_digest == event.payload["observation_digest"]
    assert transition.next_state.revision == state.revision + 1
    expected = c.Disposition.SUCCEEDED if status == "success" else c.Disposition(status)
    assert transition.next_state.dispositions[0].disposition == expected
    assert transition.next_state.primary == status


@pytest.mark.parametrize("field,bad", [
    ("operation_id", "70000000-0000-4000-8000-000000000007"),
    ("namespace", "install"), ("plan_digest", "7" * 64), ("context_digest", "7" * 64),
])
def test_host_reducer_binding_drift_rejects_before_transition(loaded, field, bad):
    engine, state, event, facts = context(loaded)
    with pytest.raises(c.PolicyInputError):
        engine.reduce(dataclasses.replace(state, **{field: bad}), event, facts)


def test_host_revision_max_minus_one_once_then_exhaustion_unchanged(loaded):
    engine, state, event, facts = context(loaded)
    event = dataclasses.replace(event, expected_revision=c.MAX_SAFE_INT - 1)
    facts = dataclasses.replace(facts, state_revision=c.MAX_SAFE_INT - 1)
    state = dataclasses.replace(state, revision=c.MAX_SAFE_INT - 1)
    result = engine.reduce(state, event, facts)
    assert result.next_state.revision == c.MAX_SAFE_INT
    assert state.revision == c.MAX_SAFE_INT - 1
    event = dataclasses.replace(event, expected_revision=c.MAX_SAFE_INT,
                                event_id="80000000-0000-4000-8000-000000000008")
    facts = dataclasses.replace(facts, state_revision=c.MAX_SAFE_INT)
    at_max = dataclasses.replace(state, revision=c.MAX_SAFE_INT)
    with pytest.raises(c.PolicyInputError, match="policy-input-invalid"):
        engine.reduce(at_max, event, facts)
    assert at_max.revision == c.MAX_SAFE_INT


def test_host_exact_duplicate_is_idempotent_changed_digest_conflicts(loaded):
    engine, state, event, facts = context(loaded)
    first = engine.reduce(state, event, facts)
    duplicate = engine.reduce(first.next_state, event,
                              dataclasses.replace(facts, state_phase=first.next_state.phase))
    assert duplicate.next_state is first.next_state
    assert duplicate.effects == ()
    assert duplicate.decision.reason == "event-already-recorded"
    changed = dataclasses.replace(event, target_id="other-target")
    with pytest.raises(c.PolicyInputError, match="policy-event-conflict"):
        engine.reduce(first.next_state, changed,
                      dataclasses.replace(facts, state_phase=first.next_state.phase))


@pytest.mark.parametrize("bad", [
    (("a", 1), ("a", 2)), ((1, "x"),), (("a", 1, 2),), ["a"],
])
def test_host_immutable_mapping_rejects_malformed_entries(bad):
    with pytest.raises(c.PolicyInputError):
        c.FrozenObject(bad)


@pytest.mark.parametrize("bad", [object(), {1: "not-string"}, [0] * 32769])
def test_host_freeze_rejects_non_json_and_oversized_sequences(bad):
    with pytest.raises(c.PolicyInputError):
        c.freeze(bad)


@pytest.mark.parametrize("field,bad", [
    ("rules", []), ("node_count", 1), ("identity", None),
    ("content_digest", ""), ("examples", []),
])
def test_host_engine_constructor_revalidates_caller_program(loaded, field, bad):
    with pytest.raises(c.PolicyLoadError):
        eng.LocalReferencePolicyEngine(dataclasses.replace(loaded[1], **{field: bad}))


def test_host_actual_200000_visits_then_200001_fails_no_partial_decision(loaded):
    """Real fixed budget, never lower MAX_VISITS to make exhaustion convenient.

    An admitted acyclic program has <=32768 static nodes, each visited at most
    once per decision. Natural 200001-visit exhaustion is not reachable today.
    Exercise the actual counter and inject a genuinely consumed evaluator at the
    decision seam separately, without claiming an accepted huge program.
    """
    assert c.MAX_VISITS == eng.MAX_VISITS == 200000
    node = c.Expression("literal", "bool", True)
    evaluation = eng._Evaluation(c.FrozenObject())
    for _ in range(200000):
        assert evaluation.boolean(node) is True
    assert evaluation.visits == 200000
    engine, _, event, facts = context(loaded)
    original_init = eng._Evaluation.__init__

    def exhausted_init(self, values):
        original_init(self, values)
        # Use the real recorded consumed count, not a smaller replacement limit.
        self.visits = evaluation.visits

    with mock.patch.object(eng._Evaluation, "__init__", exhausted_init):
        with pytest.raises(c.PolicyBudgetError, match="policy-evaluation-failed"):
            engine.decide(event, facts)
    with pytest.raises(c.PolicyBudgetError, match="policy-evaluation-failed"):
        evaluation.boolean(node)
    assert evaluation.visits == 200001
    assert engine.decide(event, facts).decision == "allow"
    BUDGET_RESULTS.update(limit=200000, accepted_visits=200000, failed_visit=200001,
                          natural_decision_exhaustion="unreachable under static node limit",
                          decision_seam="preconsumed evaluator injected; no partial allow")


@pytest.mark.parametrize("text", ["\ud800", "x" * 4097, "\x7f", ""])
def test_host_safe_text_rejects_unencodable_control_empty_and_oversize(text):
    with pytest.raises(c.PolicyInputError):
        v.text(text, safe=True)


@pytest.mark.parametrize("values", [[], ("same", "same"), ("",)])
def test_host_identifier_receipts_strict_unique_and_safe(values):
    with pytest.raises(c.PolicyInputError):
        v.identifiers(values)


def test_host_load_decide_reduce_are_pure_together(loaded):
    engine, state, event, facts = context(loaded)
    assets, program, _ = loaded
    with mock.patch("builtins.open", side_effect=AssertionError("forbidden I/O")), \
            mock.patch("time.time", side_effect=AssertionError("forbidden clock")), \
            mock.patch("time.monotonic", side_effect=AssertionError("forbidden clock")):
        assert loader.load_policy(*assets, program.identity) == program
        assert engine.decide(event, facts).decision == "allow"
        result = engine.reduce(state, event, facts)
    assert result.expected_revision == state.revision
    assert result.next_state.revision == state.revision + 1


def _assert_bad_event_counter(loaded):
    engine, _, event, facts = context(loaded)
    with pytest.raises(c.PolicyInputError):
        engine.decide(dataclasses.replace(event, expected_revision=-1),
                      dataclasses.replace(facts, state_revision=-1))


def _assert_bad_state_identity(loaded):
    engine, state, event, facts = context(loaded)
    changed = dataclasses.replace(state.identity, bundle_sha256="0" * 64)
    with pytest.raises(c.PolicyInputError):
        engine.reduce(dataclasses.replace(state, identity=changed), event, facts)


def _assert_pure_decide(loaded):
    engine, _, event, facts = context(loaded)
    with mock.patch("builtins.open", side_effect=AssertionError("forbidden I/O")):
        assert engine.decide(event, facts).decision == "allow"


@pytest.mark.parametrize("ac,assertion,owner,name,replacement,predicate", [
    ("P02-AC1", _assert_bad_event_counter, v, "counter", lambda value: value,
     "counter exact nonnegative int53 validation bypassed"),
    ("P02-AC2", _assert_bad_state_identity, eng.LocalReferencePolicyEngine, "_state",
     lambda self, state: None, "restored-state identity validator bypassed"),
])
def test_load_bearing_exact_rejection_predicate_controls(
    loaded, ac, assertion, owner, name, replacement, predicate,
):
    """Require the very same assertion to fail under bypass and pass restored."""
    assertion(loaded)
    with mock.patch.object(owner, name, replacement):
        with pytest.raises(pytest.fail.Exception):
            assertion(loaded)
    assertion(loaded)
    MUTATION_RESULTS.append(dict(
        ac_id=ac, test="test_load_bearing_exact_rejection_predicate_controls",
        assertion=assertion.__name__, altered_predicate=predicate,
        positive_before="pass", mutation="failed_on_revert", restored="pass",
    ))


def test_load_bearing_pure_decision_forbidden_io_control(loaded):
    _assert_pure_decide(loaded)
    original = eng.LocalReferencePolicyEngine.decide

    def impure(self, event, facts):
        # Sentinel interception occurs before any OS I/O. No file is created.
        with open("P02_FORBIDDEN_TEST_ONLY_SENTINEL", "rb"):
            pass
        return original(self, event, facts)

    with mock.patch.object(eng.LocalReferencePolicyEngine, "decide", impure):
        with pytest.raises(AssertionError, match="forbidden I/O"):
            _assert_pure_decide(loaded)
    _assert_pure_decide(loaded)
    MUTATION_RESULTS.append(dict(
        ac_id="P02-AC3", test="test_load_bearing_pure_decision_forbidden_io_control",
        assertion="_assert_pure_decide", altered_predicate="decide gains forbidden open before evaluation",
        positive_before="pass", mutation="failed_on_revert", restored="pass",
    ))


def test_runtime_all_five_modules_python39_and_no_dynamic_execution():
    """Include _validation omitted by prior four-module source guard."""
    import ast

    for name in ("__init__.py", "contracts.py", "_validation.py", "loader.py", "engine.py"):
        tree = ast.parse((base.POLICY / name).read_text(encoding="utf-8"), feature_version=(3, 9))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec", "compile", "__import__"}
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [item.name for item in node.names]
                if isinstance(node, ast.ImportFrom) and node.module:
                    names.append(node.module)
                assert not any(n.split(".")[0] in {
                    "subprocess", "socket", "requests", "urllib", "px_napi",
                } for n in names)
    assert importlib.import_module("netops.ansible.policy.engine") is eng


@pytest.mark.parametrize("kind", ("install", "uninstall", "restore"))
@pytest.mark.parametrize("next_kind", base.NEXT_KINDS)
def test_host_lifecycle_all_three_namespaces_seven_kinds_and_none(loaded, kind, next_kind):
    """Host-authored lifecycle matrix, not fabricated canonical output."""
    case = copy.deepcopy(next(x for x in base.HOST if x["case_id"] ==
                             "netops_companion_setup_consent_install_consented_restore_example_3"))
    case["input"]["event"]["payload"]["lifecycle_kind"] = kind
    case["input"]["facts"]["request"]["operation"] = kind
    case["input"]["facts"]["lifecycle"]["next_effect_kind"] = next_kind
    engine, state, event, facts = context(loaded, case)
    permitted = {
        "install": base.NEXT_KINDS[:5],
        "uninstall": ("dependency-uninstall",),
        "restore": ("restore-active-pointer",),
    }
    result = engine.decide(event, facts)
    expected = next_kind in permitted[kind]
    if kind == "install" and next_kind in {
        "dependency-activate", "dependency-uninstall", "restore-active-pointer", "none",
    }:
        # InstallConsented/Planned admits staging, not activation or dispatch.
        # These four exact expectations follow lifecycle-review-v2.
        assert result.decision == "allow"
        assert result.rule_ids == ("netops.companion.setup_consent_install_consented_set_phase",)
        assert len(result.effects) == 1
        assert result.effects[0].name == "set_phase"
        assert dict(result.effects[0].params) == {"phase": "Staging"}
        assert not any(effect.name == "request_effect" for effect in result.effects)
        transition = engine.reduce(state, event, facts)
        assert transition.effects == result.effects
        assert state.revision == 1
        assert transition.next_state.revision == 2
        assert transition.next_state.phase == c.Phase.STAGING
        return
    assert result.decision == ("allow" if expected else "deny")
    requests = [effect.params["kind"] for effect in result.effects
                if effect.name == "request_effect"]
    assert requests == ([next_kind] if expected else [])
    transition = engine.reduce(state, event, facts)
    assert transition.effects == result.effects
    assert state.revision == 1
    assert transition.next_state.revision == (2 if expected else 1)


@pytest.mark.parametrize("status", ("success", "failed", "blocked", "unsupported", "cancelled"))
def test_host_complete_selected_finalization_exact_status_and_receipt(loaded, status):
    """Every selected result remains accounted, including unsuccessful categories."""
    engine, state, old_event, facts = context(loaded)
    raw = copy.deepcopy(base.HOST[0]["input"]["event"])
    raw.update(kind="StepCompleted", payload={
        "invocation_id": "completion-i", "effect_id": "completion-e",
        "target_id": old_event.target_id, "step_id": old_event.step_id,
        "safe_result_digest": "3" * 64, "primary": status, "cleanup": "success",
        "remote_uncertain": False,
    })
    event = base._event(c, loaded[1], raw)
    state = dataclasses.replace(
        state, phase=c.Phase.EXECUTING,
        dispositions=(c.StepDisposition(
            event.target_id, event.step_id, invocation_id="completion-i",
            effect_id="completion-e",
        ),),
    )
    values = copy.deepcopy(base.HOST[0]["input"]["facts"])
    values["result"].update(
        selected=1, completed=int(status == "success"), unsuccessful=int(status != "success"),
        failed=int(status == "failed"), blocked=int(status == "blocked"),
        unsupported=int(status == "unsupported"), cancelled=int(status == "cancelled"),
        policy_failed=False, cleanup_failed=False, remote_uncertain=False,
    )
    facts = c.DecisionFacts(values, state_phase=c.Phase.EXECUTING, state_revision=1)
    transition = engine.reduce(state, event, facts)
    expected = c.Disposition.SUCCEEDED if status == "success" else c.Disposition(status)
    assert transition.next_state.phase == c.Phase.COMPLETED
    assert transition.next_state.primary == status
    assert transition.next_state.dispositions[0].disposition == expected
    assert transition.next_state.consumed_effect_receipts == ("completion-e",)
    assert state.consumed_effect_receipts == ()
    assert state.dispositions[0].disposition == c.Disposition.NOT_REQUESTED


@pytest.mark.parametrize("field,bad", [
    ("conditions", ()), ("conditions", []), ("actions", ()), ("actions", []),
    ("source_id", "wrong_source"), ("required_paths", ()),
    ("reason", "unsafe\nreason"), ("order", -1),
])
def test_host_caller_declaration_revalidation_rejects_drift(loaded, field, bad):
    program = loaded[1]
    rule = dataclasses.replace(program.rules[0], **{field: bad})
    changed = dataclasses.replace(program, rules=(rule,) + program.rules[1:])
    with pytest.raises(c.PolicyLoadError):
        eng.LocalReferencePolicyEngine(changed)
