"""Remaining reachable P02 guards and explicit isolated post-validation defenses."""

import copy
import dataclasses
import gzip
import hashlib
import json
import operator
import os
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

import pytest
import test_reference_engine_p02_acceptance as base
import test_reference_engine_p02_close as close
import test_reference_engine_p02_safety as safety

from netops.ansible.policy import _validation as v
from netops.ansible.policy import contracts as c
from netops.ansible.policy import engine as eng
from netops.ansible.policy import loader

loaded = safety.loaded


def assert_engine_guard(exc, reason, call, method, line):
    """Distinguish the intended predicate from an earlier provenance rejection."""
    with pytest.raises(exc) as caught:
        call()
    assert str(caught.value) == reason
    error = caught.value.__context__ if exc is c.PolicyLoadError else caught.value
    assert type(error) is c.PolicyInputError
    sites = [number for frame, number in traceback.walk_tb(error.__traceback__)
             if frame.f_code is method.__code__]
    assert sites == [line]


def original_operand_copy(program):
    """Own a shallow fixture clone without resetting loader-only init=False fields."""
    clone = copy.copy(program)
    assert clone is not program
    assert clone._load_bytes is program._load_bytes
    assert clone == program
    assert eng.LocalReferencePolicyEngine(clone)._program is clone
    assert eng.LocalReferencePolicyEngine(program)._program is program
    return clone


@pytest.mark.parametrize("kind,value", [
    ("literal", c.Expression("literal", "bool", True, path=("request", "mode"))),
    ("literal-op", c.Expression("literal", "bool", True, op="Eq")),
    ("literal-child", c.Expression("literal", "bool", True,
                                  children=(c.Expression("literal", "bool", False),))),
    ("nonliteral-value", c.Expression("path", "bool", True)),
    ("path-op", c.Expression("path", "string", path=("request", "mode"), op="Eq")),
    ("path-child", c.Expression("path", "string", path=("request", "mode"),
                               children=(c.Expression("literal", "bool", True),))),
    ("nonpath-path", c.Expression("paren", "bool", path=("request", "mode"))),
    ("wrong-type", True),
    ("non-tuple-path", c.Expression("path", "string", path=["request", "mode"])),
    ("non-tuple-children", c.Expression("paren", "bool", children=[])),
    ("wrong-arity", c.Expression("binary", "bool", op="Eq", children=())),
    ("unknown-kind", c.Expression("call", "bool")),
])
def test_host_isolated_caller_expression_shape_defenses(kind, value):
    """Direct defensive validator, not a purported admitted malformed program."""
    close.assert_error(c.PolicyInputError, "policy-input-invalid",
                       lambda: eng._expression_value(value))


def test_host_isolated_caller_expression_depth_defense():
    value = c.Expression("literal", "bool", True)
    for _ in range(32):
        value = c.Expression("paren", "bool", children=(value,))
    assert eng._expression_value(value)["kind"] == "paren"
    close.assert_error(c.PolicyInputError, "policy-input-invalid", lambda: eng._expression_value(
        c.Expression("paren", "bool", children=(value,)),
    ))


@pytest.mark.parametrize("field,bad", [
    ("rules", ("rule",)), ("constraints", ("constraint",)),
    ("rules", c.FrozenObject()),
    ("node_count", True), ("node_count", 0), ("node_count", c.MAX_NODES + 1),
    ("examples", (True,)), ("identity", "identity"),
])
def test_host_program_exact_types_and_counts_revalidated(loaded, field, bad):
    changed = dataclasses.replace(loaded[1], **{field: bad})
    close.assert_error(c.PolicyLoadError, "policy-load-invalid",
                       lambda: eng.LocalReferencePolicyEngine(changed))


@pytest.mark.parametrize("mode", ("duplicate-order", "bad-constraint-actions",
                                 "missing-constraint-require", "multiple-constraint-guards",
                                 "rule-with-require", "mismatched-claimed-expression-type"))
def test_host_caller_declaration_families_and_orders_revalidated(loaded, mode):
    program = loaded[1]
    if mode == "duplicate-order":
        rule = dataclasses.replace(program.rules[1], order=program.rules[0].order)
        changed = dataclasses.replace(program, rules=(program.rules[0], rule) + program.rules[2:])
    elif mode.startswith("bad-") or mode in ("missing-constraint-require", "multiple-constraint-guards"):
        constraint = program.constraints[0]
        fields = {
            "bad-constraint-actions": {"actions": program.rules[0].actions},
            "missing-constraint-require": {"required": None},
            "multiple-constraint-guards": {"conditions": constraint.conditions * 2},
        }[mode]
        constraint = dataclasses.replace(constraint, **fields)
        changed = dataclasses.replace(program, constraints=(constraint,) + program.constraints[1:])
    else:
        rule = program.rules[0]
        if mode == "rule-with-require":
            rule = dataclasses.replace(rule, required=rule.conditions[0])
        else:
            node = dataclasses.replace(rule.conditions[0], value_type="string")
            rule = dataclasses.replace(rule, conditions=(node,) + rule.conditions[1:])
        changed = dataclasses.replace(program, rules=(rule,) + program.rules[1:])
    if mode in ("bad-constraint-actions", "missing-constraint-require",
                "multiple-constraint-guards", "rule-with-require"):
        # Preserve every earlier valid bound so this tests the family guard,
        # rather than merely failing the expression-node or required-path count.
        builder = loader._Builder()

        def rebind(declaration):
            paths = set()
            nodes = declaration.conditions
            if declaration.required is not None:
                nodes += (declaration.required,)
            for expression in nodes:
                builder.boolean(eng._expression_value(expression))
                paths.update(loader._paths(expression))
            return dataclasses.replace(declaration, required_paths=tuple(sorted(paths)))

        rules = tuple(rebind(r) for r in changed.rules)
        constraints = tuple(rebind(r) for r in changed.constraints)
        changed = dataclasses.replace(changed, rules=rules, constraints=constraints,
                                      node_count=builder.nodes)
    close.assert_error(c.PolicyLoadError, "policy-load-invalid",
                       lambda: eng.LocalReferencePolicyEngine(changed))


@pytest.mark.parametrize("mode", ("missing", "completed"))
def test_host_request_effect_requires_one_pending_selected_occurrence(loaded, mode):
    engine, state, event, facts = close.lifecycle(
        loaded, kind="CandidateVerified", next_kind="dependency-activate",
    )
    assert any(a.name == "request_effect" for a in engine.decide(event, facts).effects)
    steps = () if mode == "missing" else (
        dataclasses.replace(state.dispositions[0], disposition=c.Disposition.SUCCEEDED,
                            result_digest="3" * 64),
    )
    changed = dataclasses.replace(state, dispositions=steps)
    close.assert_error(c.PolicyInputError, "policy-event-conflict",
                       lambda: engine.reduce(changed, event, facts))


@pytest.mark.parametrize("phase", ("Active", "Completed", "Cancelled"))
def test_host_terminal_cancel_never_reissues_intent_or_advances_terminal_state(loaded, phase):
    _, state, old_event, facts = safety.context(loaded)
    event = dataclasses.replace(
        old_event, kind=c.EventKind.CANCELLED, payload=close.EVENT_PAYLOADS["Cancelled"],
    )
    state = dataclasses.replace(state, phase=c.Phase(phase))
    facts = dataclasses.replace(facts, state_phase=state.phase)
    result = loaded[2].reduce(state, event, facts)
    assert result.effects == ()
    assert result.next_state is state


def test_host_observed_partial_is_not_a_single_factual_disposition(loaded):
    engine, state, event, facts = close.observation(loaded, "partial")
    close.assert_error(c.PolicyInputError, "policy-input-invalid",
                       lambda: engine.reduce(state, event, facts))


def test_host_multitarget_mixed_selected_results_are_partial_and_complete(loaded):
    engine, state, event, facts = close.lifecycle(
        loaded, phase="Executing", next_kind="none", pending=True,
    )
    previous = dataclasses.replace(
        state.dispositions[1], disposition=c.Disposition.SUCCEEDED, result_digest="5" * 64,
    )
    state = dataclasses.replace(state, dispositions=(state.dispositions[0], previous))
    event = dataclasses.replace(
        event, payload=dict(eng._wire(event.payload), primary="failed"),
    )
    values = eng._wire(facts.values)
    values["result"].update(selected=2, completed=1, unsuccessful=1, failed=1)
    result = engine.reduce(state, event, dataclasses.replace(facts, values=values))
    assert result.next_state.primary == "partial"
    assert result.next_state.phase == c.Phase.COMPLETED
    assert [s.disposition for s in result.next_state.dispositions] == [
        c.Disposition.FAILED, c.Disposition.SUCCEEDED,
    ]


@pytest.mark.parametrize("field", ("approved_effect_ids", "approved_recovery_ids"))
@pytest.mark.parametrize("bad", [["same", "same"], [""], [1]])
def test_host_typed_approved_occurrence_lists_remain_unique_safe_exact_strings(field, bad):
    event = close.typed_event("ApplyConsented")
    payload = dict(close.EVENT_PAYLOADS["ApplyConsented"], **{field: bad})
    close.assert_error(c.PolicyInputError, "policy-input-invalid",
                       lambda: v.event_value(dataclasses.replace(event, payload=payload)))


@pytest.mark.parametrize("mutation", (
    "manifest-unsorted-paths", "manifest-duplicate-path", "manifest-source-drift",
    "manifest-missing-id", "declaration-source-drift", "constraint-kind",
    "constraint-severity", "rule-kind", "rule-order-gap", "rule-order-duplicate",
    "empty-conditions", "empty-actions", "duplicate-actions", "two-phases",
    "required-path-drift", "case-gap", "missing-case-family",
))
def test_host_raw_projection_rejection_inventory_with_rebound_outer_identity(loaded, mutation):
    def mutate(data):
        rule = data["rules"][0]
        if mutation == "manifest-unsorted-paths":
            row = next(r for r in data["manifest"] if len(r["required_paths"]) > 1)
            row["required_paths"] = list(reversed(row["required_paths"]))
        elif mutation == "manifest-duplicate-path":
            row = next(r for r in data["manifest"] if r["required_paths"])
            row["required_paths"] *= 2
        elif mutation == "manifest-source-drift":
            data["manifest"][0]["source_id"] = "netops_companion_other"
        elif mutation == "manifest-missing-id":
            data["manifest"].pop()
        elif mutation == "declaration-source-drift":
            rule["source_id"] = "netops_companion_other"
        elif mutation == "constraint-kind":
            data["constraints"][0]["kind"] = "rule"
        elif mutation == "constraint-severity":
            data["constraints"][0]["severity"] = "warning"
        elif mutation == "rule-kind":
            rule["kind"] = "constraint"
        elif mutation == "rule-order-gap":
            rule["order"] = 900
        elif mutation == "rule-order-duplicate":
            data["rules"][1]["order"] = rule["order"]
        elif mutation == "empty-conditions":
            rule["conditions"] = []
        elif mutation == "empty-actions":
            rule["actions"] = []
        elif mutation == "duplicate-actions":
            rule["actions"] *= 2
        elif mutation == "two-phases":
            rule["actions"] = [
                {"name": "set_phase", "params": {"phase": "Planned"}},
                {"name": "set_phase", "params": {"phase": "Active"}},
            ]
        elif mutation == "required-path-drift":
            row = next(r for r in data["manifest"] if r["id"] == rule["id"])
            row["required_paths"] = []
        elif mutation == "case-gap":
            data["contracts"][0]["case_id"] += "_gap"
        else:
            name = data["contracts"][0]["rule_id"]
            data["contracts"] = [r for r in data["contracts"] if r["rule_id"] != name]
    changed = base._mutated_assets(loaded[0], mutate)
    identity = base._identity(c, changed)
    assert all(len(value) < c.MAX_BYTES for value in changed)
    close.assert_error(c.PolicyLoadError, "policy-load-invalid",
                       lambda: loader.load_policy(*changed, identity))


def assert_coverage_contract(report):
    totals = report["totals"]
    assert totals["num_statements"] > 0 and totals["num_branches"] > 0
    assert totals["covered_lines"] / totals["num_statements"] >= 0.8
    assert totals["covered_branches"] / totals["num_branches"] >= 0.8
    assert set(report["files"]) == {
        "netops/ansible/policy/" + n for n in
        ("__init__.py", "_validation.py", "contracts.py", "engine.py", "loader.py")
    }


def bound_fresh_coverage(binding_path, expected_sha256, attempt, root):
    """Validate an explicit measurement binding against the consuming installation."""
    raw = Path(binding_path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected_sha256, "coverage binding drift"
    binding = json.loads(raw)
    assert binding["schema"] == 1
    assert attempt and binding["attempt"] == attempt, "coverage attempt mismatch"
    assert binding["command"] and "--cov-branch" in binding["command"]
    assert binding["exit_code"] == 0
    operands = {}
    for key in ("report", "junit"):
        operand = binding[key]
        path = Path(operand["path"])
        assert path.is_absolute(), "coverage operand must be absolute"
        data = path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == operand["sha256"], key + " drift"
        operands[key] = data
    sources = {"netops/ansible/policy/" + name for name in
               ("__init__.py", "_validation.py", "contracts.py", "engine.py", "loader.py")}
    tests = {"tests/policy/test_reference_engine_p02_" + name + ".py" for name in
             ("acceptance", "safety", "close", "guards")}
    assert set(binding["sources"]) == sources, "incomplete measured source manifest"
    assert set(binding["tests"]) == tests, "incomplete measured test manifest"
    for group in ("sources", "tests"):
        for name, digest in binding[group].items():
            assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, (
                "measured " + group + " drift: " + name
            )
    suites = list(ET.fromstring(operands["junit"]).iter("testsuite"))
    assert suites and sum(int(s.get("tests", 0)) for s in suites) >= 1000
    assert all(int(s.get(key, 0)) == 0 for s in suites
               for key in ("failures", "errors", "skipped")), "measurement suite not clean"
    report = json.loads(operands["report"])
    assert report["meta"]["branch_coverage"] is True
    report["files"] = {name.replace("\\", "/"): value
                       for name, value in report["files"].items()}
    assert_coverage_contract(report)
    return report


def test_load_bearing_ac4_actual_fresh_coverage_thresholds():
    """Coverage from this attempt, never the older current1277 report."""
    binding = os.environ.get("NETOPS_P02_COVERAGE_BINDING")
    if binding:
        path = Path(binding)
        report = bound_fresh_coverage(
            path, os.environ["NETOPS_P02_COVERAGE_BINDING_SHA256"],
            os.environ["NETOPS_P02_COVERAGE_ATTEMPT"], base.ROOT,
        )
    else:
        path = (base.ROOT / ".sdlc/runs" / close.RUN_ID / "local-campaign-p01-evidence-v1"
                / "p02-acceptance-close-v5/stable-full-a3-coverage.json")
        # Retained checkout-only historical control. Installed runs must explicitly
        # bind a fresh source-and-suite-identical measurement, never copy this file.
        assert (base.ROOT / "pyproject.toml").is_file(), "fresh coverage binding required"
        report = json.loads(path.read_bytes() if path.exists()
                            else gzip.decompress(path.with_name(path.name + ".gz").read_bytes()))
    normalized = {str(k).replace("\\", "/"): value for k, value in report["files"].items()}
    report["files"] = normalized
    assert_coverage_contract(report)
    for key, total in (("covered_lines", "num_statements"), ("covered_branches", "num_branches")):
        bad = copy.deepcopy(report)
        bad["totals"][key] = int(bad["totals"][total] * 0.79)
        with pytest.raises(AssertionError):
            assert_coverage_contract(bad)
    assert_coverage_contract(report)
    close.CONTROLS.append(dict(facet="AC4.actual-fresh-80-line-and-branch", actual=str(path),
                               positive="pass", regressions=2, negative="failed", restored="pass"))


@pytest.mark.parametrize("node", [
    c.Expression("literal", "bool"),
    c.Expression("not", "bool", children=(c.Expression("literal", "int", 1),)),
    c.Expression("binary", "bool", op="Eq", children=(
        c.Expression("literal", "int", 1), c.Expression("literal", "bool", True))),
    c.Expression("binary", "bool", op="And", children=(
        c.Expression("literal", "int", 1), c.Expression("literal", "int", 2))),
    c.Expression("binary", "bool", op="Eq", children=(
        c.Expression("literal", "float", 1.0), c.Expression("literal", "float", 1.0))),
    c.Expression("binary", "bool", op="Gt", children=(
        c.Expression("literal", "string", "a"), c.Expression("literal", "string", "b"))),
    c.Expression("binary", "bool", op="Unknown", children=(
        c.Expression("literal", "int", 1), c.Expression("literal", "int", 2))),
])
def test_isolated_evaluator_rejects_malformed_nodes_without_partial_permission(node):
    """Exercise post-validation defenses, not pretend these nodes load as PX."""
    evaluator = eng._Evaluation(c.FrozenObject())
    with pytest.raises(c.PolicyEvaluationError, match="^policy-evaluation-failed$"):
        evaluator.evaluate(node)
    with pytest.raises(c.PolicyInputError, match="^policy-input-invalid$"):
        loader._Builder().boolean(eng._expression_value(node))
    assert evaluator.values == c.FrozenObject()
    assert eng._Evaluation(c.FrozenObject()).boolean(c.Expression("literal", "bool", True))


def test_isolated_boolean_context_and_wire_reject_unsupported_values():
    with pytest.raises(c.PolicyEvaluationError, match="^policy-evaluation-failed$"):
        eng._Evaluation(c.FrozenObject()).boolean(c.Expression("literal", "int", 1))
    with pytest.raises(c.PolicyInputError, match="^policy-input-invalid$"):
        eng._wire(object())
    assert eng._wire((True, 1, None)) == [True, 1, None]


def test_closed_schema_rejects_duplicate_required_field_declaration():
    value = c.object_value({"selected": 1})
    with pytest.raises(c.PolicyInputError, match="^policy-input-invalid$"):
        v.keys(value, ("selected", "selected"))
    assert v.keys(value, ("selected",)) is value


def test_operation_mode_payload_must_match_facts_before_decision(loaded):
    case = next(case for case in base.HOST
                if case["input"]["event"]["kind"] == "OperationRequested")
    engine, state, event, facts = safety.context(loaded, case)
    values = eng._wire(facts.values)
    original = event.payload["mode"]
    values.setdefault("request", {})["mode"] = "check" if original != "check" else "preview"
    changed = dataclasses.replace(facts, values=values)
    before = copy.deepcopy(state)
    with pytest.raises(c.PolicyInputError, match="^policy-input-invalid$"):
        engine.decide(event, changed)
    with pytest.raises(c.PolicyInputError, match="^policy-input-invalid$"):
        engine.reduce(state, event, changed)
    assert state == before
    assert engine.decide(event, facts) == engine.decide(event, facts)


@pytest.mark.parametrize("shape", ("missing-mode", "missing-request"))
def test_operation_missing_mode_projects_but_never_grants_permission(loaded, shape):
    case = next(case for case in base.HOST
                if case["input"]["event"]["kind"] == "OperationRequested")
    engine, state, event, facts = safety.context(loaded, case)
    values = eng._wire(facts.values)
    if shape == "missing-mode":
        values["request"].pop("mode")
    else:
        values.pop("request")
    changed = dataclasses.replace(facts, values=values)
    before = copy.deepcopy(state)
    # Projection may omit an unused fact; the real applicable PX rules still
    # demand request.mode and must fail closed instead of granting permission.
    assert engine._inputs(event, changed)["event"]["kind"] == "OperationRequested"
    with pytest.raises(c.PolicyInputError, match="^policy-input-invalid$"):
        engine.decide(event, changed)
    with pytest.raises(c.PolicyInputError, match="^policy-input-invalid$"):
        engine.reduce(state, event, changed)
    assert state == before
    assert engine.decide(event, facts) == engine.decide(event, facts)


def test_isolated_corrupted_constraint_is_rejected_not_silently_ignored(loaded):
    """An unconstructible engine is used only to exercise its last defense."""
    engine, _, event, facts = safety.context(loaded)
    values = engine._inputs(event, facts)
    constraint = next(item for item in loaded[1].constraints
                      if eng._Evaluation(values).boolean(item.conditions[0]))
    broken = dataclasses.replace(constraint, required=None)
    program = dataclasses.replace(loaded[1], constraints=(broken,))
    with pytest.raises(c.PolicyLoadError, match="^policy-load-invalid$"):
        eng.LocalReferencePolicyEngine(program)
    isolated = object.__new__(eng.LocalReferencePolicyEngine)
    isolated._program = program
    with pytest.raises(c.PolicyEvaluationError, match="^policy-evaluation-failed$"):
        isolated.decide(event, facts)
    assert engine._program is loaded[1]


def test_real_lifecycle_selector_allow_does_not_bypass_completion_phase_guard(loaded):
    engine, state, event, facts = close.lifecycle(loaded)
    planned = dataclasses.replace(state, phase=c.Phase.PLANNED)
    planned_facts = dataclasses.replace(facts, state_phase=c.Phase.PLANNED)
    before = copy.deepcopy(planned)
    decision = engine.decide(event, planned_facts)
    # The frozen selector admits install continuation in Planned or Staging;
    # a completion in Planned is nevertheless not a valid reducer transition.
    assert decision.decision == "allow"
    assert any(effect.name == "request_effect" for effect in decision.effects)
    with pytest.raises(c.PolicyInputError, match="^policy-event-conflict$"):
        engine.reduce(planned, event, planned_facts)
    assert planned == before
    assert planned.consumed_effect_receipts == state.consumed_effect_receipts
    assert engine.reduce(state, event, facts).next_state.revision == state.revision + 1


@pytest.mark.parametrize("mutation", [
    "none", "binding-bytes", "attempt", "command", "exit", "report-bytes",
    "junit-bytes", "relative-path", "source", "test", "source-manifest",
    "test-manifest", "failure", "skip", "empty-suite", "no-branches", "low-line",
    "low-branch",
])
def test_fresh_coverage_binding_rejects_drift_and_unclean_measurements(tmp_path, mutation):
    """Synthetic parser fixtures only: these counters are NOT coverage evidence."""
    root = tmp_path / "consumer"
    sources = {"netops/ansible/policy/" + name: "source fixture" for name in
               ("__init__.py", "_validation.py", "contracts.py", "engine.py", "loader.py")}
    tests = {"tests/policy/test_reference_engine_p02_" + name + ".py": "test fixture"
             for name in ("acceptance", "safety", "close", "guards")}
    for name, text in dict(sources, **tests).items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    report = {"meta": {"branch_coverage": mutation != "no-branches"},
              "totals": {"num_statements": 100, "covered_lines": 79 if mutation == "low-line" else 90,
                         "num_branches": 100, "covered_branches": 79 if mutation == "low-branch" else 90},
              "files": dict.fromkeys(sources, {})}
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuites><testsuite tests="1000" failures="'
        + ("1" if mutation == "failure" else "0") + '" errors="0" skipped="'
        + ("1" if mutation == "skip" else "0") + '"/></testsuites>'
        if mutation != "empty-suite" else "<testsuites/>", encoding="utf-8",
    )
    binding = {"schema": 1, "attempt": "unit-fixture", "command": ["pytest", "--cov-branch"],
               "exit_code": 0}
    for key, path in (("report", report_path), ("junit", junit)):
        binding[key] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    for key, files in (("sources", sources), ("tests", tests)):
        binding[key] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                        for name in files}
    if mutation == "command":
        binding["command"] = ["pytest"]
    elif mutation == "exit":
        binding["exit_code"] = 1
    elif mutation == "relative-path":
        binding["report"]["path"] = "report.json"
    elif mutation in ("source-manifest", "test-manifest"):
        binding["sources" if mutation == "source-manifest" else "tests"].popitem()
    binding_path = tmp_path / "binding.json"
    binding_path.write_text(json.dumps(binding), encoding="utf-8")
    digest = hashlib.sha256(binding_path.read_bytes()).hexdigest()
    if mutation in ("binding-bytes", "report-bytes", "junit-bytes"):
        target = {"binding-bytes": binding_path, "report-bytes": report_path,
                  "junit-bytes": junit}[mutation]
        target.write_bytes(target.read_bytes() + b" ")
    elif mutation in ("source", "test"):
        (root / next(iter(sources if mutation == "source" else tests))).write_bytes(b"drift")
    attempt = "other-attempt" if mutation == "attempt" else "unit-fixture"
    if mutation == "none":
        assert bound_fresh_coverage(binding_path, digest, attempt, root) == report
    else:
        with pytest.raises(AssertionError):
            bound_fresh_coverage(binding_path, digest, attempt, root)


@pytest.mark.parametrize("op", ("Eq", "Neq", "Gt", "Lt", "Gte", "Lte", "And", "Or"))
def test_load_bearing_ac1_each_permitted_binary_operator(op):
    left, right, ty = (True, False, "bool") if op in ("And", "Or") else (1, 2, "int")
    expected = {"Eq": operator.eq, "Neq": operator.ne, "Gt": operator.gt, "Lt": operator.lt,
                "Gte": operator.ge, "Lte": operator.le,
                "And": lambda a, b: a and b, "Or": lambda a, b: a or b}[op](left, right)

    def assertion():
        actual = eng._Evaluation(c.FrozenObject()).boolean(safety.expression(op, left, right, ty))
        assert actual is expected

    original = eng._Evaluation.evaluate

    def regression(self, expression):
        value = original(self, expression)
        return not value if expression.kind == "binary" and expression.op == op else value

    close.control("AC1.operator." + op, assertion, eng._Evaluation, "evaluate", regression)


@pytest.mark.parametrize("kind", ("not", "paren"))
def test_load_bearing_ac1_unary_and_parentheses_semantics(kind):
    node = loader._Builder().boolean(c.object_value(
        {"kind": kind, "operand": base._literal("bool", True)},
    ))
    expected = kind == "paren"

    def assertion():
        assert eng._Evaluation(c.FrozenObject()).boolean(node) is expected

    original = eng._Evaluation.evaluate

    def regression(self, expression):
        value = original(self, expression)
        return not value if expression.kind == kind else value

    close.control("AC1.operator." + kind, assertion, eng._Evaluation, "evaluate", regression)


def test_load_bearing_ac2_duplicate_key_intended_guard():
    def assertion():
        close.assert_error(c.PolicyLoadError, "policy-load-invalid",
                           lambda: loader._pairs([("same", 1), ("same", 1)]))

    close.control("AC2.duplicate-key", assertion, loader, "_pairs", dict, pytest.fail.Exception)


@pytest.mark.parametrize("node,facet", [
    (base._binary("Eq", base._literal("float", 1.0), base._literal("float", 1.0)),
     "float-equality"),
    (base._literal("int", True), "bool-as-int"),
    (base._binary("Eq", base._literal("int", 1), base._literal("float", 1.0)), "mixed-type"),
])
def test_load_bearing_ac1_forbidden_type_coercions_intended_guard(node, facet):
    frozen = c.object_value(node)

    def assertion():
        close.assert_error(c.PolicyInputError, "policy-input-invalid",
                           lambda: loader._Builder().boolean(frozen))

    with mock.patch.object(loader._Builder, "expression",
                           lambda self, value: c.Expression("literal", "bool", True)):
        with pytest.raises(pytest.fail.Exception):
            assertion()
    assertion()
    close.CONTROLS.append(dict(facet="AC1.rejection." + facet, positive="pass",
                               narrow_regression="failed", restored="pass",
                               isolated_validator=True))


def test_load_bearing_ac3_pending_lifecycle_is_not_a_terminal_counter_partition(loaded):
    def assertion():
        close.test_host_lifecycle_correlated_completion_retains_pending_and_next_intent(
            loaded, "Staging", "install", "dependency-stage",
        )

    original = eng.LocalReferencePolicyEngine._inputs

    def regression(self, event, facts):
        # Exact old defect: a valid intermediate receipt is forced through final counts.
        if "result" in facts.values:
            v.final_counters(facts.values["result"])
        return original(self, event, facts)

    close.control("AC3.pending-lifecycle", assertion, eng.LocalReferencePolicyEngine,
                  "_inputs", regression, c.PolicyInputError)


def test_load_bearing_ac3_complete_selected_index_is_not_only_scalar_totals(loaded):
    def assertion():
        close.test_host_terminal_complete_index_and_retained_flags_reject_exact_disagreement(
            loaded, "selected-size",
        )

    close.control("AC3.complete-selected-index", assertion, eng, "_completion_counters",
                  lambda value, dispositions: value, pytest.fail.Exception)


@pytest.mark.parametrize("group", ("control", "consent"))
def test_load_bearing_ac2_supplied_remaining_ms_exact_int53_guard(loaded, group):
    def assertion():
        close.test_host_supplied_remaining_ms_rejects_nonfinite_overflow_and_coercion(
            loaded, group, c.MAX_SAFE_INT + 1,
        )

    original = v.leaf

    def regression(path, value):
        if path != (group, "remaining_ms"):
            return original(path, value)
        return None

    close.control("AC2.supplied-clock." + group, assertion, v, "leaf", regression,
                  pytest.fail.Exception)


@pytest.mark.parametrize("bad", (None, (), (b"x", b"y"), ("bytes-impostor", b"x", b"y")))
def test_host_new_loader_operand_identity_boundary_is_exact_bytes_tuple(loaded, bad):
    original = loaded[1]
    program = original_operand_copy(original)
    operands = original._load_bytes
    object.__setattr__(program, "_load_bytes", bad)
    assert program == original
    assert_engine_guard(
        c.PolicyLoadError, "policy-load-invalid",
        lambda: eng.LocalReferencePolicyEngine(program),
        eng.LocalReferencePolicyEngine._validate_program,
        302 if type(bad) is tuple and len(bad) == 3 else 300,
    )
    assert original._load_bytes is operands
    assert eng.LocalReferencePolicyEngine(original)._program is original


def test_host_constructor_wrong_program_type_is_not_structural_duck_typing():
    close.assert_error(c.PolicyLoadError, "policy-load-invalid",
                       lambda: eng.LocalReferencePolicyEngine(None))


def test_host_isolated_recursive_immutability_depth_and_tuple_size_guards():
    eng._immutable(True, 144)
    close.assert_error(c.PolicyInputError, "policy-input-invalid", lambda: eng._immutable(True, 145))
    eng._immutable((True,) * c.MAX_NODES)
    close.assert_error(c.PolicyInputError, "policy-input-invalid",
                       lambda: eng._immutable((True,) * (c.MAX_NODES + 1)))


def test_host_final_partition_rejects_pending_but_intermediate_counter_accepts_it():
    value = c.object_value(dict(selected=2, completed=1, unsuccessful=0, failed=0, cancelled=0,
                                unsupported=0, blocked=0, policy_failed=False,
                                cleanup_failed=False, remote_uncertain=False))
    v.result_counters(value)
    close.assert_error(c.PolicyInputError, "policy-input-invalid", lambda: v.final_counters(value))


def test_host_unsuccessful_scalar_cannot_count_a_pending_selected_disposition(loaded):
    _, state, _, _ = close.lifecycle(loaded)
    dispositions = (
        dataclasses.replace(state.dispositions[0], disposition=c.Disposition.SUCCEEDED,
                            result_digest="3" * 64), state.dispositions[1],
    )
    value = c.object_value(dict(selected=2, completed=1, unsuccessful=1, failed=0, cancelled=0,
                                unsupported=0, blocked=0, policy_failed=False,
                                cleanup_failed=False, remote_uncertain=False))
    # All per-category counts agree; only unsuccessful-versus-pending is wrong.
    close.assert_error(c.PolicyInputError, "policy-input-invalid",
                       lambda: eng._completion_counters(value, dispositions))


def test_host_well_formed_content_digest_mismatch_and_expected_manifest_mismatch(loaded):
    assets = loaded[0]
    data = json.loads(assets[2])
    original = data["content_digest"].encode()
    changed = (*assets[:2], assets[2].replace(original, b"0" * 64, 1))
    expected = dataclasses.replace(loaded[1].identity, bundle_sha256=base._sha(changed[2]))
    close.assert_error(c.PolicyLoadError, "policy-load-invalid",
                       lambda: loader.load_policy(*changed, expected))
    expected = dataclasses.replace(loaded[1].identity,
                                   rule_manifest=loaded[1].identity.rule_manifest[1:])
    close.assert_error(c.PolicyLoadError, "policy-load-invalid",
                       lambda: loader.load_policy(*assets, expected))


def test_host_semantic_copy_reaches_actual_rederivation_identity_guard(loaded):
    assets, identity = close.bounded_program_assets(loaded, [[
        {"name": "set_phase", "params": {"phase": "Planned"}},
    ]])
    program = loader.load_policy(*assets, identity)
    changed = original_operand_copy(program)
    active = c.EffectDescriptor("set_phase", {"phase": "Active"})
    rule = dataclasses.replace(program.rules[0], actions=(active,))
    raw = eng._wire(program.examples[0])
    raw["expect"]["actions"] = base._actions((active,))
    object.__setattr__(changed, "rules", (rule,))
    object.__setattr__(changed, "examples", (c.object_value(raw),))
    assert changed._load_bytes is program._load_bytes
    assert changed.identity is program.identity
    assert changed.node_count == program.node_count
    assert changed.content_digest == program.content_digest
    for field in dataclasses.fields(program):
        if field.name not in ("rules", "examples"):
            assert getattr(changed, field.name) == getattr(program, field.name)

    def assertion():
        assert_engine_guard(
            c.PolicyLoadError, "policy-load-invalid",
            lambda: eng.LocalReferencePolicyEngine(changed),
            eng.LocalReferencePolicyEngine._validate_program, 307,
        )

    with mock.patch.object(eng, "load_policy", wraps=loader.load_policy) as rederive:
        assertion()
    assert rederive.call_count == 1, "An earlier structural guard is not semantic identity proof"
    assert rederive.call_args.args == (*assets, identity)
    with mock.patch.object(eng, "load_policy", return_value=changed):
        with pytest.raises(pytest.fail.Exception):
            assertion()
    with mock.patch.object(eng, "load_policy", wraps=loader.load_policy) as restored:
        assertion()
    assert restored.call_args_list == [mock.call(*assets, identity)]
    assert program.rules[0].actions[0].params["phase"] == "Planned"
    assert program.examples[0]["expect"]["actions"][0]["params"]["phase"] == "Planned"
    assert eng.LocalReferencePolicyEngine(program)._program is program
    close.CONTROLS.append(dict(
        facet="AC2.original-byte-semantic-rederivation", positive="pass",
        narrow_regression="failed", restored="pass", intended_guard="engine.py:307",
        not_a_whole_criterion_revert=True,
    ))


def test_host_constructor_manifest_mismatch_reaches_exact_guard(loaded):
    assets, identity = close.bounded_program_assets(loaded, [[
        {"name": "set_phase", "params": {"phase": "Planned"}},
    ]])
    program = loader.load_policy(*assets, identity)
    changed = original_operand_copy(program)
    changed_identity = dataclasses.replace(
        identity, rule_manifest=("netops.companion.boundary_0001",),
    )
    loader.validate_identity(changed_identity)
    object.__setattr__(changed, "identity", changed_identity)
    assert changed.rules is program.rules
    assert changed._load_bytes is program._load_bytes
    assert_engine_guard(
        c.PolicyLoadError, "policy-load-invalid",
        lambda: eng.LocalReferencePolicyEngine(changed),
        eng.LocalReferencePolicyEngine._validate_program, 251,
    )
    assert program.identity is identity
    assert eng.LocalReferencePolicyEngine(program)._program is program


def test_host_lifecycle_decision_in_unrelated_phase_is_fail_closed(loaded):
    engine, state, event, facts = close.lifecycle(loaded)
    before = copy.deepcopy(state)
    assert engine.reduce(state, event, facts).next_state.revision == state.revision + 1
    wrong_state = dataclasses.replace(state, phase=c.Phase.OBSERVING)
    wrong_facts = dataclasses.replace(facts, state_phase=c.Phase.OBSERVING)
    decision = engine.decide(event, wrong_facts)
    assert decision.decision == "deny"
    assert decision.reason == "policy-rejected"
    assert decision.effects == ()
    assert decision.rule_ids == ()
    transition = engine.reduce(wrong_state, event, wrong_facts)
    assert transition.decision == decision
    assert transition.effects == ()
    assert transition.next_state is wrong_state
    assert transition.expected_revision == wrong_state.revision
    assert transition.next_state.consumed_effect_receipts == before.consumed_effect_receipts
    assert transition.next_state.dispositions == before.dispositions
    assert wrong_state == dataclasses.replace(before, phase=c.Phase.OBSERVING)
    assert state == before
    assert engine.reduce(state, event, facts).next_state.revision == state.revision + 1


def test_host_typed_dto_action_impostor_and_exact_bool_node_count_intended_guards(loaded):
    assets, identity = close.bounded_program_assets(loaded, [[
        {"name": "set_phase", "params": {"phase": "Planned"}},
    ]])
    program = loader.load_policy(*assets, identity)
    assert program.node_count == 1
    close.assert_error(c.PolicyLoadError, "policy-load-invalid", lambda: eng.LocalReferencePolicyEngine(
        dataclasses.replace(program, node_count=True),
    ))
    # This is recursively immutable and a genuine allowed DTO, but NOT an effect.
    rule = dataclasses.replace(program.rules[0], actions=(c.Expression("literal", "bool", True),))
    close.assert_error(c.PolicyLoadError, "policy-load-invalid", lambda: eng.LocalReferencePolicyEngine(
        dataclasses.replace(program, rules=(rule,)),
    ))
