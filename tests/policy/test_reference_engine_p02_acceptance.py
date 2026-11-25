"""Independent frozen-P02 acceptance tests; no producer tests are imported.

Authority: local-task-plan-v4 P02, local-lld-contract-v3 sections 4--7/12,
and nov11-contract-delta-v3. Canonical combined decisions and independently
authored host expectations are deliberately separate. These tests do not
qualify a broker, controller, installed package, platform or foundation.
"""

import copy
import dataclasses
import hashlib
import importlib
import inspect
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "netops" / "ansible" / "policy"
MAX_INT = 9007199254740991
PIN = "6d367fe673756dabaa6085bc6b5202debaaabe6f"
CORPUS = json.loads((ROOT / "tests/policy/canonical-corpus.json").read_bytes())
CASES = CORPUS["cases"]
COMBINED = [case for case in CASES if case["canonical"]["combined"] is not None]
HOST = [case for case in COMBINED if case["input"]["event"].get("schema") == "1.0"]
NEXT_KINDS = (
    "dependency-probe", "dependency-download", "dependency-stage",
    "dependency-verify", "dependency-activate", "dependency-uninstall",
    "restore-active-pointer", "none",
)


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@pytest.fixture
def api():
    """Missing real public types are errors, never skips or substitute engines."""
    contracts = importlib.import_module("netops.ansible.policy.contracts")
    loader = importlib.import_module("netops.ansible.policy.loader")
    engine = importlib.import_module("netops.ansible.policy.engine")
    for name in (
        "PolicyIdentity", "PolicyProgram", "DecisionEvent", "DecisionFacts", "PolicyState",
        "DecisionResult", "PolicyTransition", "EffectDescriptor", "LocalPolicyPort",
        "PolicyLoadError", "PolicyInputError", "PolicyBudgetError", "PolicyEvaluationError",
    ):
        assert hasattr(contracts, name), "Frozen P02 public contract missing: " + name
    return contracts, loader.load_policy, engine.LocalReferencePolicyEngine


@pytest.fixture
def assets():
    source = (POLICY / "ansible_molecule.px").read_bytes()
    contracts = (POLICY / "ansible_molecule.contracts.px").read_bytes()
    bundle = (POLICY / "bundle.json").read_bytes()
    return source, contracts, bundle


def _identity(types, assets, **overrides):
    source, contracts, bundle = assets
    data = json.loads(bundle)
    values = {
        "profile": "netops-reference-v1",
        "numeric_profile": "exact-int53-finite-order-v1",
        "schema": "1.0",
        "canonical_revision": PIN,
        "source_sha256": _sha(source),
        "contracts_sha256": _sha(contracts),
        "bundle_sha256": _sha(bundle),
        "rule_manifest": tuple(item["id"] for item in data["manifest"]),
        "reducer_version": data["reducer_version"],
    }
    values.update(overrides)
    return types.PolicyIdentity(**values)


def _load(api, assets):
    types, load, engine = api
    program = load(*assets, _identity(types, assets))
    return program, engine(program)


def _mutated_assets(assets, mutate):
    """Rebind declared byte/content identities so malformed ASTs reach validation.

    A rejection is not by itself proof that the intended inner branch ran;
    coverage must establish that separately. No PX source is rewritten.
    """
    source, contracts, raw = assets
    bundle = json.loads(raw)
    mutate(bundle)
    bundle.pop("content_digest", None)
    bundle["content_digest"] = _sha(_json(bundle))
    return source, contracts, _json(bundle)


def _event(types, program, raw):
    """Complete legacy minimal fixture metadata outside the engine, not permission."""
    values = {
        "schema": "1.0",
        "event_id": "40000000-0000-4000-8000-000000000004",
        "operation_id": "60000000-0000-4000-8000-000000000006",
        "kind": raw["kind"],
        "expected_revision": 1,
        "plan_digest": "1" * 64,
        "context_digest": "2" * 64,
        "policy_digest": program.identity.bundle_sha256,
        "target_id": "router-A",
        "step_id": "collect",
        "payload": {},
    }
    values.update(copy.deepcopy(raw))
    values["policy_digest"] = program.identity.bundle_sha256
    if "install_id" in raw:
        values.pop("operation_id")
    payload = values["payload"]
    if "policy_digest" in payload:
        payload["policy_digest"] = values["policy_digest"]
    if values["kind"] in {kind.value for kind in types.EventKind}:
        values["kind"] = types.EventKind(values["kind"])
    return types.DecisionEvent(**values)


def _facts(types, values, state=None):
    state = state or {"phase": "Planned", "revision": 1}
    return types.DecisionFacts(
        values=copy.deepcopy(values), state_phase=types.Phase(state["phase"]),
        state_revision=state.get("revision", 1),
    )


def _state(types, program, event, raw):
    """Supply explicit pinned state identity and pending selected-work bindings."""
    phase = raw["phase"]
    if phase in {item.value for item in types.Phase}:
        phase = types.Phase(phase)
    dispositions = ()
    if event.kind in (
        types.EventKind.STEP_COMPLETED, types.EventKind.OBSERVED,
        types.EventKind.OPERATION_REQUESTED, types.EventKind.APPLY_CONSENTED,
        types.EventKind.INSTALL_CONSENTED,
    ):
        dispositions = (
            types.StepDisposition(
                target_id=event.target_id, step_id=event.step_id,
                invocation_id=event.payload.get("invocation_id"),
                effect_id=event.payload.get("effect_id"),
            ),
        )
    return types.PolicyState(
        identity=program.identity, operation_id=event.operation_id or event.install_id,
        revision=raw["revision"], phase=phase, plan_digest=event.plan_digest,
        context_digest=event.context_digest, policy_digest=event.policy_digest,
        dispositions=dispositions, namespace="install" if event.install_id else "operation",
    )


def _actions(effects):
    """Use only the closed action contract, never permit/action-string aliases."""
    return [
        {"name": effect.name, "params": dict(effect.params)}
        for effect in effects
    ]


def _literal(kind, value):
    return {"kind": "literal", "type": kind, "value": value}


def _binary(op, left, right):
    return {"kind": "binary", "op": op, "left": left, "right": right}


def test_p02_public_methods_and_no_authorize_alias(api):
    types, load, engine = api
    assert tuple(inspect.signature(load).parameters) == ("source", "contracts", "bundle", "expected")
    assert tuple(inspect.signature(engine.decide).parameters) == ("self", "event", "facts")
    assert tuple(inspect.signature(engine.reduce).parameters) == ("self", "state", "event", "facts")
    assert not hasattr(engine, "authorize")
    assert not hasattr(types.LocalPolicyPort, "authorize")


@pytest.mark.parametrize("name", [
    "PolicyIdentity", "PolicyProgram", "DecisionEvent", "DecisionFacts", "PolicyState",
    "DecisionResult", "PolicyTransition", "EffectDescriptor",
])
def test_p02_values_are_frozen_dataclasses(api, name):
    cls = getattr(api[0], name)
    assert dataclasses.is_dataclass(cls)
    assert cls.__dataclass_params__.frozen is True
    for field in dataclasses.fields(cls):
        assert not isinstance(field.default, (dict, list, set))


def test_p02_exact_packaged_bytes_load_to_immutable_program(api, assets):
    program, _ = _load(api, assets)
    assert isinstance(program, api[0].PolicyProgram)
    assert program.identity == _identity(api[0], assets)
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError, TypeError)):
        program.identity = None


@pytest.mark.parametrize("field,value", [
    ("profile", "other"), ("numeric_profile", "other"), ("schema", "2.0"),
    ("canonical_revision", "0" * 40), ("source_sha256", "0" * 64),
    ("contracts_sha256", "0" * 64), ("bundle_sha256", "0" * 64),
    ("rule_manifest", ()), ("reducer_version", ""), ("reducer_version", "other"),
])
def test_p02_expected_identity_is_strict(api, assets, field, value):
    types, load, _ = api
    with pytest.raises(types.PolicyLoadError):
        load(*assets, _identity(types, assets, **{field: value}))


@pytest.mark.parametrize("index", range(3), ids=["source", "contracts", "bundle"])
def test_p02_changed_byte_rejects_before_dispatch(api, assets, index):
    changed = list(assets)
    changed[index] += b" "
    with pytest.raises(api[0].PolicyLoadError):
        api[1](*changed, _identity(api[0], assets))


@pytest.mark.parametrize("field", [
    "profile", "numeric_profile", "schema", "canonical_revision", "source_digests",
    "manifest", "reducer_version", "max_safe_int", "rules", "constraints", "contracts",
])
def test_p02_missing_bundle_field_is_not_a_wildcard(api, assets, field):
    changed = _mutated_assets(assets, lambda data: data.pop(field))
    expected = dataclasses.replace(_identity(api[0], assets), bundle_sha256=_sha(changed[2]))
    with pytest.raises(api[0].PolicyLoadError):
        api[1](*changed, expected)


@pytest.mark.parametrize("location", ["bundle", "rule", "constraint", "contract", "expression"])
def test_p02_unknown_fields_reject_at_every_projection_level(api, assets, location):
    def mutate(data):
        target = {
            "bundle": data, "rule": data["rules"][0], "constraint": data["constraints"][0],
            "contract": data["contracts"][0], "expression": data["rules"][0]["conditions"][0],
        }[location]
        target["unexpected"] = True
    changed = _mutated_assets(assets, mutate)
    with pytest.raises(api[0].PolicyLoadError):
        api[1](*changed, _identity(api[0], changed))


@pytest.mark.parametrize("mode", ["duplicate", "omitted", "orphan", "duplicate_case"])
def test_p02_complete_unique_manifest_and_examples(api, assets, mode):
    def mutate(data):
        if mode == "duplicate":
            data["manifest"].append(copy.deepcopy(data["manifest"][0]))
        elif mode == "omitted":
            data["manifest"].pop()
        elif mode == "orphan":
            data["contracts"][0]["rule_id"] = "netops.companion.not_declared"
        else:
            data["contracts"][1]["case_id"] = data["contracts"][0]["case_id"]
    changed = _mutated_assets(assets, mutate)
    with pytest.raises(api[0].PolicyLoadError):
        api[1](*changed, _identity(api[0], changed))


@pytest.mark.parametrize("index", range(len(CASES)), ids=[case["case_id"] for case in CASES])
def test_p02_every_contract_example_validates_irrelevant_numeric_fields(api, assets, index):
    def mutate(data):
        data["contracts"][index]["input"]["facts"].setdefault("scope", {})[
            "selected_count"
        ] = MAX_INT + 1
    changed = _mutated_assets(assets, mutate)
    with pytest.raises(api[0].PolicyLoadError):
        api[1](*changed, _identity(api[0], changed))


@pytest.mark.parametrize("duplicate", ["profile", "numeric_profile", "reducer_version"])
def test_p02_duplicate_json_keys_rejected_even_when_values_match(api, assets, duplicate):
    data = json.loads(assets[2])
    prefix = _json({duplicate: data[duplicate]})[:-1] + b","
    changed = (assets[0], assets[1], prefix + assets[2].lstrip()[1:])
    with pytest.raises(api[0].PolicyLoadError):
        api[1](*changed, _identity(api[0], changed))


@pytest.mark.parametrize("node", [
    _literal("int", True), _literal("int", MAX_INT + 1), _literal("int", -MAX_INT - 1),
    _literal("int", 1.0), _literal("int", "1"), _literal("float", 1),
    _literal("float", float("nan")), _literal("float", float("inf")),
    _literal("float", -float("inf")), _literal("bool", 1), _literal("string", None),
    {"kind": "call", "name": "eval", "args": []},
    {"kind": "path", "segments": ["__class__", "__subclasses__"]},
    {"kind": "path", "segments": ["lifecycle", "next_effect_ordinal"]},
    {"kind": "unary", "op": "Neg", "operand": {"kind": "path", "segments": ["result", "selected"]}},
])
@pytest.mark.parametrize("short_circuit", ["And", "Or"])
def test_p02_dead_branch_is_fully_validated(api, assets, node, short_circuit):
    def mutate(data):
        data["rules"][0]["conditions"] = [
            _binary(short_circuit, _literal("bool", short_circuit == "Or"), node)
        ]
    changed = _mutated_assets(assets, mutate)
    with pytest.raises(api[0].PolicyLoadError):
        api[1](*changed, _identity(api[0], changed))


@pytest.mark.parametrize("op", ["Eq", "Neq"])
@pytest.mark.parametrize("left,right", [(0.0, 1e-16), (1.0, 1.0), (-0.0, 0.0)])
def test_p02_float_equality_rejected_statically(api, assets, op, left, right):
    changed = _mutated_assets(assets, lambda data: data["rules"][0].update(
        conditions=[_binary(op, _literal("float", left), _literal("float", right))]
    ))
    with pytest.raises(api[0].PolicyLoadError):
        api[1](*changed, _identity(api[0], changed))


@pytest.mark.parametrize("op,left,right", [
    ("Eq", _literal("bool", True), _literal("int", 1)),
    ("Neq", _literal("int", 1), _literal("float", 1.0)),
    ("Gt", _literal("string", "2"), _literal("string", "1")),
    ("Gte", _literal("bool", True), _literal("bool", False)),
    ("Lt", _literal("int", 1), _literal("string", "2")),
    ("Add", _literal("int", 1), _literal("int", 2)),
])
def test_p02_no_coercion_or_extra_operators(api, assets, op, left, right):
    changed = _mutated_assets(assets, lambda data: data["rules"][0].update(
        conditions=[_binary(op, left, right)]
    ))
    with pytest.raises(api[0].PolicyLoadError):
        api[1](*changed, _identity(api[0], changed))


@pytest.mark.parametrize("action", [
    {"name": "authorize", "params": {}},
    {"name": "request_effect", "params": {"kind": "arbitrary-executable"}},
    {"name": "set_phase", "params": {"phase": "New"}},
    {"name": "record_step", "params": {"disposition": "healthy"}},
    {"name": "request_effect", "params": {"kind": "save", "callback": "eval"}},
])
def test_p02_static_action_vocabulary_is_closed(api, assets, action):
    changed = _mutated_assets(assets, lambda data: data["rules"][0].update(actions=[action]))
    with pytest.raises(api[0].PolicyLoadError):
        api[1](*changed, _identity(api[0], changed))


@pytest.mark.parametrize("limit", ["bytes", "depth", "nodes", "string", "declarations"])
def test_p02_load_limits_fail_closed_without_truncation(api, assets, limit):
    def mutate(data):
        if limit == "depth":
            expression = _literal("bool", True)
            for _ in range(34):
                expression = {"kind": "paren", "operand": expression}
            data["rules"][0]["conditions"] = [expression]
        elif limit == "nodes":
            data["rules"][0]["conditions"] = [_literal("bool", True)] * 32769
        elif limit == "string":
            data["rules"][0]["conditions"] = [_literal("string", "é" * 2049)]
        elif limit == "declarations":
            data["rules"] = [copy.deepcopy(data["rules"][0]) for _ in range(513)]
        else:
            data["unexpected"] = "x" * 1048577
    changed = _mutated_assets(assets, mutate)
    with pytest.raises(api[0].PolicyLoadError):
        api[1](*changed, _identity(api[0], changed))


@pytest.mark.parametrize("case", HOST, ids=lambda case: case["case_id"])
def test_p02_canonical_composed_decisions_and_ordered_actions(api, assets, case):
    """Only complete typed combined cases are public-engine oracle inputs."""
    program, engine = _load(api, assets)
    event = _event(api[0], program, case["input"]["event"])
    facts = _facts(api[0], case["input"]["facts"], case["input"]["state"])
    if case["case_id"] == (
        "netops_companion_setup_consent_install_consented_restore_example_20"
    ):
        assert event.expected_revision == 0
        assert facts.state_revision == 1
        with pytest.raises(api[0].PolicyInputError, match="policy-input-invalid"):
            engine.decide(event, facts)
        return
    result = engine.decide(event, facts)
    expected = case["canonical"]["combined"]
    assert result.decision == expected["decision"]
    assert tuple(expected["rule_ids"]) == tuple(sorted(set(expected["rule_ids"])))
    assert result.rule_ids == tuple(sorted(set(result.rule_ids)))
    assert result.rule_ids == tuple(expected["rule_ids"])
    assert _actions(result.effects) == expected["actions"]
    if expected["decision"] == "deny":
        assert result.effects == ()
    assert isinstance(result.effects, tuple)
    assert all(isinstance(effect, api[0].EffectDescriptor) for effect in result.effects)
    assert result.policy_digest == program.identity.bundle_sha256
    assert engine.decide(event, facts) == result


@pytest.mark.parametrize("bad", [True, -1, MAX_INT + 1, 1.0, "1", None])
@pytest.mark.parametrize("path", [
    ("scope", "selected_count"), ("control", "remaining_ms"),
    ("consent", "remaining_ms"), ("result", "selected"), ("result", "completed"),
])
def test_p02_irrelevant_fact_counters_never_coerce(api, assets, path, bad):
    program, engine = _load(api, assets)
    case = copy.deepcopy(HOST[0])
    case["input"]["facts"][path[0]][path[1]] = bad
    with pytest.raises(api[0].PolicyInputError):
        facts = _facts(api[0], case["input"]["facts"])
        engine.decide(_event(api[0], program, case["input"]["event"]), facts)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -float("inf"), 1, True, None, "1.0"])
@pytest.mark.parametrize("field", ["reading", "threshold"])
def test_p02_irrelevant_float_facts_require_finite_binary64(api, assets, field, bad):
    program, engine = _load(api, assets)
    case = copy.deepcopy(HOST[0])
    case["input"]["facts"]["health"][field] = bad
    with pytest.raises(api[0].PolicyInputError):
        facts = _facts(api[0], case["input"]["facts"])
        engine.decide(_event(api[0], program, case["input"]["event"]), facts)


@pytest.mark.parametrize("bad", [None, True, "", "NONE", "dependency-execute", 1])
def test_p02_next_effect_kind_domain_is_not_an_extensible_callback(api, assets, bad):
    program, engine = _load(api, assets)
    case = copy.deepcopy(HOST[0])
    case["input"]["facts"]["lifecycle"]["next_effect_kind"] = bad
    with pytest.raises(api[0].PolicyInputError):
        facts = _facts(api[0], case["input"]["facts"])
        engine.decide(_event(api[0], program, case["input"]["event"]), facts)


@pytest.mark.parametrize("kind", NEXT_KINDS)
def test_p02_closed_next_effect_fact_accepts_all_seven_and_none(api, assets, kind):
    program, engine = _load(api, assets)
    case = copy.deepcopy(HOST[0])
    case["input"]["facts"]["lifecycle"]["next_effect_kind"] = kind
    result = engine.decide(
        _event(api[0], program, case["input"]["event"]),
        _facts(api[0], case["input"]["facts"]),
    )
    assert result.decision in ("allow", "deny")
    # This operation is not lifecycle setup: a selector fact cannot add an install intent.
    assert all(action["params"].get("kind") not in NEXT_KINDS for action in _actions(result.effects))


@pytest.mark.parametrize("bad", [True, -1, MAX_INT + 1, 1.0, None])
def test_p02_typed_event_revision_is_strict(api, assets, bad):
    program, engine = _load(api, assets)
    case = copy.deepcopy(HOST[0])
    case["input"]["event"]["expected_revision"] = bad
    with pytest.raises(api[0].PolicyInputError):
        event = _event(api[0], program, case["input"]["event"])
        engine.decide(event, _facts(api[0], case["input"]["facts"]))


@pytest.mark.parametrize("section,field,value", [
    ("event", "schema", "2.0"), ("event", "event_id", "not-a-uuid"),
    ("event", "plan_digest", "1"), ("event", "unknown", True),
    ("payload", "unknown", True), ("facts", "unknown", {"enabled": True}),
    ("lifecycle", "next_effect_id", "untrusted"),
    ("request", "mode", "execute"), ("request", "area", "arbitrary"),
    ("request", "operation", "arbitrary"), ("binding", "input_valid", 1),
])
def test_p02_closed_typed_input_fields_reject_drift(api, assets, section, field, value):
    program, engine = _load(api, assets)
    case = copy.deepcopy(HOST[0])
    raw_event, raw_facts = case["input"]["event"], case["input"]["facts"]
    if section == "event":
        raw_event[field] = value
    elif section == "payload":
        raw_event["payload"][field] = value
    elif section == "facts":
        raw_facts[field] = value
    else:
        raw_facts[section][field] = value
    with pytest.raises((api[0].PolicyInputError, TypeError)):
        engine.decide(_event(api[0], program, raw_event), _facts(api[0], raw_facts))


@pytest.mark.parametrize("completed,unsuccessful", [(3, 0), (0, 3), (2, 1)])
def test_p02_selected_coverage_cannot_disappear_in_finalization(
    api, assets, completed, unsuccessful
):
    program, engine = _load(api, assets)
    state, event, facts = _finalization_fixture(
        api[0], program, completed=completed, unsuccessful=unsuccessful,
    )
    before = copy.deepcopy(state)
    with pytest.raises(api[0].PolicyInputError, match="policy-input-invalid"):
        engine.reduce(state, event, facts)
    assert state == before


def _finalization_fixture(types, program, completed, unsuccessful):
    """Valid typed completion envelope; only final selected counters are invalid."""
    case = copy.deepcopy(HOST[0])
    case["input"]["facts"]["result"].update(
        selected=2, completed=completed, unsuccessful=unsuccessful,
    )
    raw_event = copy.deepcopy(case["input"]["event"])
    raw_event["kind"] = "StepCompleted"
    raw_event["payload"] = {
        "invocation_id": "invocation-1", "effect_id": "effect-1",
        "target_id": raw_event["target_id"], "step_id": raw_event["step_id"],
        "safe_result_digest": "3" * 64, "primary": "success", "cleanup": "success",
        "remote_uncertain": False,
    }
    event = _event(types, program, raw_event)
    raw_state = {"phase": "Executing", "revision": 1}
    state = _state(types, program, event, raw_state)
    state = dataclasses.replace(state, dispositions=state.dispositions + (
        types.StepDisposition(target_id="router-B", step_id="collect",
                              invocation_id="pending-B"),
    ))
    return state, event, _facts(types, case["input"]["facts"], raw_state)


def test_p02_incomplete_selected_work_cannot_become_terminal_success(api, assets):
    program, engine = _load(api, assets)
    state, event, facts = _finalization_fixture(api[0], program, completed=1, unsuccessful=0)
    before = copy.deepcopy(state)
    transition = engine.reduce(state, event, facts)
    # Frozen missing-admit semantics: this vault completion has no valid final
    # aggregate and no continuation. Denial must preserve the complete pending
    # index; rejecting a final counter partition is not required for every
    # intermediate fact group (ACCEPT-01). No terminal success is manufactured.
    assert transition.decision.decision == "deny"
    assert transition.decision.reason == "policy-rejected"
    assert transition.effects == ()
    assert transition.next_state is state
    assert transition.next_state.phase == api[0].Phase.EXECUTING
    assert transition.next_state.revision == 1
    assert transition.next_state.consumed_effect_receipts == ()
    assert all(step.result_digest is None for step in transition.next_state.dispositions)
    assert state == before


def test_p02_valid_pending_observation_is_not_terminal_selected_success(api, assets):
    types = api[0]
    program, engine = _load(api, assets)
    case = copy.deepcopy(next(
        case for case in HOST
        if case["case_id"] == "netops_companion_health_observed_success_example_3"
    ))
    del case["input"]["facts"]["result"]  # Optional non-finalization group only.
    event = _event(types, program, case["input"]["event"])
    state = _state(types, program, event, case["input"]["state"])
    second = types.StepDisposition(
        target_id="router-B", step_id="collect", invocation_id="pending-B",
    )
    state = dataclasses.replace(state, dispositions=state.dispositions + (second,))
    before = copy.deepcopy(state)
    transition = engine.reduce(
        state, event, _facts(types, case["input"]["facts"], case["input"]["state"]),
    )
    assert state == before
    assert transition.expected_revision == 1
    assert transition.next_state.revision == 2
    assert transition.next_state.phase == types.Phase.OBSERVING
    assert transition.next_state.dispositions[0].disposition == types.Disposition.SUCCEEDED
    assert transition.next_state.dispositions[0].result_digest == event.payload["observation_digest"]
    assert transition.next_state.dispositions[1] == second
    assert transition.next_state.consumed_effect_receipts == ()
    assert all(effect.name != "request_effect" for effect in transition.effects)


def test_p02_missing_admit_is_deny_and_never_permission(api, assets):
    program, engine = _load(api, assets)
    case = next(
        case for case in HOST if case["case_id"] ==
        "netops_companion_setup_consent_install_consented_restore_example_4"
    )
    assert case["input"]["facts"]["lifecycle"]["next_effect_kind"] == "dependency-probe"
    assert {key: case["canonical"]["combined"][key] for key in (
        "decision", "rule_ids", "actions", "violations",
    )} == {
        "decision": "deny", "rule_ids": [], "actions": [], "violations": [],
    }
    result = engine.decide(
        _event(api[0], program, case["input"]["event"]),
        _facts(api[0], case["input"]["facts"]),
    )
    assert result.decision == "deny"
    assert result.rule_ids == ()
    assert result.effects == ()


@pytest.mark.parametrize("case", HOST, ids=lambda case: case["case_id"])
def test_p02_host_transition_expected_old_revision_is_not_canonical_state(api, assets, case):
    """Host-authored expectations; do not relabel these as canonical state output."""
    program, engine = _load(api, assets)
    event = _event(api[0], program, case["input"]["event"])
    facts = _facts(api[0], case["input"]["facts"], case["input"]["state"])
    raw_state = copy.deepcopy(case["input"]["state"])
    state = _state(api[0], program, event, raw_state)
    before = copy.deepcopy(state)
    if case["case_id"] == (
        "netops_companion_setup_consent_install_consented_restore_example_20"
    ):
        assert event.expected_revision == 0
        assert state.revision == facts.state_revision == 1
        with pytest.raises(api[0].PolicyInputError, match="policy-input-invalid"):
            engine.reduce(state, event, facts)
        assert state == before
        return
    transition = engine.reduce(state, event, facts)
    assert isinstance(transition, api[0].PolicyTransition)
    assert transition.expected_revision == state.revision
    assert state == before
    assert isinstance(transition.effects, tuple)
    assert transition.decision == engine.decide(event, facts)
    expected = case["canonical"]["combined"]
    assert transition.decision.decision == expected["decision"]
    assert transition.decision.rule_ids == tuple(expected["rule_ids"])
    assert _actions(transition.effects) == expected["actions"]
    if expected["decision"] == "deny":
        assert transition.next_state == before
        assert transition.effects == ()
    else:
        phase = state.phase
        for action in expected["actions"]:
            if action["name"] == "set_phase":
                phase = action["params"]["phase"]
            elif action["name"] == "record_outcome" and event.kind == api[0].EventKind.STEP_COMPLETED:
                phase = "Uncertain" if event.payload["remote_uncertain"] else "Completed"
        assert transition.next_state.phase == phase
        assert transition.next_state.revision == state.revision + 1


@pytest.mark.parametrize("revision", [True, -1, MAX_INT + 1, 1.0, None, MAX_INT])
def test_p02_host_restored_or_exhausted_revision_rejects_unchanged(api, assets, revision):
    program, engine = _load(api, assets)
    case = copy.deepcopy(HOST[0])
    with pytest.raises(api[0].PolicyInputError):
        raw_event = copy.deepcopy(case["input"]["event"])
        raw_event["expected_revision"] = revision
        event = _event(api[0], program, raw_event)
        state = _state(api[0], program, event, {"phase": "Planned", "revision": revision})
        engine.reduce(
            state, event,
            _facts(api[0], case["input"]["facts"]),
        )


def test_p02_load_and_decide_have_no_io_env_clock_process_or_network(api, assets):
    program, engine = _load(api, assets)
    case = HOST[0]
    event = _event(api[0], program, case["input"]["event"])
    facts = _facts(api[0], case["input"]["facts"])
    identity = _identity(api[0], assets)
    targets = [
        (Path, "open"), (os, "getenv"), (os, "getcwd"), (time, "time"),
        (time, "monotonic"), (socket, "socket"), (socket, "create_connection"),
        (subprocess, "Popen"),
    ]
    patches = [mock.patch.object(owner, name, side_effect=AssertionError("forbidden effect"))
               for owner, name in targets]
    with mock.patch("builtins.open", side_effect=AssertionError("forbidden file I/O")):
        for patch in patches:
            patch.start()
        try:
            loaded = api[1](*assets, identity)
            result = engine.decide(event, facts)
        finally:
            for patch in reversed(patches):
                patch.stop()
    assert loaded == program
    assert result.decision in ("allow", "deny")


def test_p02_runtime_sources_remain_python39_and_no_dynamic_execution(api):
    """Parse only four owned implementation files, not unrelated legacy code."""
    import ast
    for name in ("__init__.py", "contracts.py", "loader.py", "engine.py"):
        tree = ast.parse((POLICY / name).read_text(encoding="utf-8"), feature_version=(3, 9))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec", "compile", "__import__"}
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [item.name for item in node.names]
                if isinstance(node, ast.ImportFrom) and node.module:
                    names.append(node.module)
                assert not any(name.split(".")[0] in {
                    "subprocess", "socket", "requests", "urllib", "px_napi",
                } for name in names)
