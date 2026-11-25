"""P01 contract tests; canonical cases require independently qualified prerequisites.

No fixture builds, downloads, substitutes an oracle, or skips missing prerequisites.
This source is not proof of policy, host admission, event reduction, or P01 completion.
Scratch and an already qualified executable must be explicitly supplied inside the repo.
"""

import hashlib
import itertools
import json
import operator
import os
import subprocess
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "netops" / "ansible" / "policy" / "ansible_molecule.px"
CONTRACTS = SOURCE.with_name("ansible_molecule.contracts.px")
REVISION = "6d367fe673756dabaa6085bc6b5202debaaabe6f"
MAX_INT = 9_007_199_254_740_991
ASSETS = ("bundle.json", "canonical-corpus.json")
RULE = "netops_companion_catalog_normalization_probe"


@pytest.fixture
def canonical_context():
    """Fail closed without the later independently qualified local tool and lock."""
    for name in ("NETOPS_CANONICAL_ADAPTER", "NETOPS_POLICY_TEST_ROOT"):
        if not os.environ.get(name):
            pytest.fail(f"{name} absent: canonical execution prerequisites are not qualified")
    binary = Path(os.environ["NETOPS_CANONICAL_ADAPTER"]).resolve(strict=True)
    scratch = Path(os.environ["NETOPS_POLICY_TEST_ROOT"]).resolve(strict=True)
    for path in (binary, scratch):
        assert ROOT in path.parents, "Only explicitly qualified repository-local paths are allowed"
        assert not path.is_symlink()
    assert binary.is_file() and scratch.is_dir()
    lock = ROOT / "tools" / "ansible_px_reference" / "Cargo.lock"
    assert lock.is_file(), "No locked canonical dependency resolution: do not build here"
    work = scratch / f"policy-{uuid.uuid4().hex}"
    work.mkdir()
    yield binary, work
    # Keep outputs for later authorized provenance review, never delete an unknown root.


def invoke(context, source, contracts, output, mode="--emit-dir"):
    binary, work = context
    output.mkdir(exist_ok=True)
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", TMP=str(work), TEMP=str(work))
    result = subprocess.run(
        [
            str(binary), "--source", str(source), "--contracts", str(contracts),
            mode, str(output),
        ],
        cwd=ROOT, env=environment, capture_output=True, timeout=30, check=False,
    )
    return result


def decode_assets(output):
    return tuple(json.loads((output / name).read_bytes()) for name in ASSETS)


def fixture_text(expression="true", reason="null"):
    """Author expectations independently; only the real adapter supplies canonical results."""
    source = (
        f"rule {RULE}:\n  when:\n"
        '    - event.kind == "OperationRequested"\n'
        f'    - request.mode != "observe" and ({expression})\n'
        '  then:\n    - action: set_phase phase: "Planned"\n'
    )
    examples = []
    for mode, decision in (("preview", "allow"), ("check", "allow"), ("observe", "deny")):
        actions = '[{name: "set_phase", params: {phase: "Planned"}}]'
        if decision == "deny":
            actions = "[]"
        examples.append(
            '    - input: {state: {phase: "Planned"}, '
            'event: {kind: "OperationRequested"}, facts: {request: {mode: "'
            + mode
            + '"}}}\n      expect: {decision: "'
            + decision
            + f'", reason: {reason}, actions: {actions}, next_phase: null, '
            + "aggregate: null, constraint_outcomes: {}, error: null}\n"
        )
    contracts = (
        f'contract {RULE}_contract:\n  given: "Loaded inputs"\n'
        '  when: "Explicit preview or check"\n  then: "A phase intent only"\n'
        "  examples:\n" + "".join(examples)
    )
    return source, contracts


def derive_fixture(context, expression="true", source_edit=None, contract_edit=None, reason="null"):
    _, work = context
    source, contracts = fixture_text(expression, reason)
    if source_edit:
        source = source_edit(source)
    if contract_edit:
        contracts = contract_edit(contracts)
    source_path, contract_path = work / "probe.px", work / "probe.contracts.px"
    source_path.write_text(source, encoding="utf-8")
    contract_path.write_text(contracts, encoding="utf-8")
    output = work / "emit"
    result = invoke(context, source_path, contract_path, output)
    return result, output


def assert_rejected(result, output):
    assert result.returncode == 2, result.stderr.decode(errors="replace")
    assert not any((output / name).exists() for name in ASSETS)


def test_authored_example_lists_are_contiguous():
    """Guard the exact authored layout, not a substitute for pinned parsing."""
    contracts = CONTRACTS.read_text(encoding="utf-8")
    declarations = contracts.split("\ncontract ")[1:]
    # FR-024: collection, retention and Git each require their own explicit intent.
    added_contracts = {
        "netops_companion_config_collect_operation_requested_backup_collect_contract": 5,
        "netops_companion_config_collect_operation_requested_backup_retention_contract": 4,
        "netops_companion_config_collect_operation_requested_backup_git_contract": 4,
        "netops_companion_compare_operation_requested_save_contract": 7,
    }
    assert len(declarations) == 58 + len(added_contracts)
    examples_by_contract = {}
    for declaration in declarations:
        name, _, body = declaration.partition(":\n")
        assert name not in examples_by_contract, f"Duplicate authored contract: {name}"
        _, marker, body = body.partition("  examples:\n")
        assert marker, name
        lines = body.splitlines()
        last_expect = max(
            index for index, line in enumerate(lines) if line.startswith("      expect:")
        )
        example_lines = lines[:last_expect + 1]
        assert len(example_lines) % 2 == 0, name
        for index in range(0, len(example_lines), 2):
            assert example_lines[index].startswith("    - input:"), (
                f"{name}: a blank/comment line terminates the pinned example_list"
            )
            assert example_lines[index + 1].startswith("      expect:"), name
        examples_by_contract[name] = len(example_lines) // 2
    assert {
        name: examples_by_contract.get(name) for name in added_contracts
    } == added_contracts, "Retain distinct backup collection/retention/Git boundary examples"
    assert examples_by_contract["netops_companion_aggregate_step_completed_success_contract"] == 10
    assert sum(
        count for name, count in examples_by_contract.items() if name not in added_contracts
    ) == 215 + 1 + 4, (
        "Retain original170, all45 semantic cases, the I02 not-requested readiness case "
        "and four terminal uninstall controls"
    )


@pytest.mark.parametrize("separator", [
    "\n",
    "# These are lifecycle payload identities, not trusted host consent or expression facts.\n",
    "\n# Complete expression-fact fixtures, not trusted host envelopes. Target-local\n"
    "# allow below must not hide a different constraints-first combined decision.\n",
])
def test_pinned_example_list_rejects_interior_document_separators(canonical_context, separator):
    """Original Parse253:5: separators belong before the declaration, not a list item."""
    source, contracts = fixture_text()
    result, output = derive_texts(
        canonical_context, source, separator + contracts, "document-boundary"
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    _, corpus = decode_assets(output)
    assert len(corpus["cases"]) == 3
    assert [case["input"]["facts"]["request"]["mode"] for case in corpus["cases"]] == [
        "preview", "check", "observe",
    ]
    assert [case["host_expectations"]["decision"] for case in corpus["cases"]] == [
        "allow", "allow", "deny",
    ]
    position = contracts.rindex("    - input:")
    interrupted = contracts[:position] + separator + contracts[position:]
    result, output = derive_texts(
        canonical_context, source, interrupted, "interrupted-example-list"
    )
    assert_rejected(result, output)


def test_full_policy_derives_twice_and_checks_packaged_bytes(canonical_context):
    """PX01/PX02: real canonical bytes, not hand-authored oracle snapshots."""
    _, work = canonical_context
    first, second = work / "first", work / "second"
    for destination in (first, second):
        result = invoke(canonical_context, SOURCE, CONTRACTS, destination)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
    for name in ASSETS:
        assert (first / name).read_bytes() == (second / name).read_bytes()
    bundle, corpus = decode_assets(first)
    assert bundle["canonical_revision"] == corpus["canonical_revision"] == REVISION
    assert bundle["profile"] == corpus["profile"] == "netops-reference-v1"
    assert bundle["numeric_profile"] == "exact-int53-finite-order-v1"
    assert bundle["max_safe_int"] == MAX_INT
    assert bundle["source_digests"] == {
        "source": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "contracts": hashlib.sha256(CONTRACTS.read_bytes()).hexdigest(),
    }
    assert corpus["bundle_content_digest"] == bundle["content_digest"]
    declarations = bundle["rules"] + bundle["constraints"]
    ids = {item["id"] for item in declarations}
    assert len(ids) == len(declarations) == len(bundle["manifest"])
    assert {case["rule_id"] for case in corpus["cases"]} == ids
    case_ids = [case["case_id"] for case in corpus["cases"]]
    assert len(case_ids) == len(set(case_ids))
    for declaration in declarations:
        examples = [c for c in corpus["cases"] if c["rule_id"] == declaration["id"]]
        decisions = {c["host_expectations"]["decision"] for c in examples}
        if declaration["kind"] == "rule":
            assert len(examples) >= 3 and decisions == {"allow", "deny"}
            inputs = {json.dumps(c["input"], sort_keys=True) for c in examples}
            assert len(inputs) >= 3, "A repeated fixture is not a distinct boundary example"
        else:
            assert declaration["severity"] == "error"
            assert "deny" in decisions, "Every invariant needs a violating example"
    for case in corpus["cases"]:
        actual = case["canonical"]
        expected = case["host_expectations"]
        assert actual["fired_actions"] == [a["name"] for a in expected["actions"]]
        assert actual["constraint_outcomes"] == expected["constraint_outcomes"]
    packaged = {
        "bundle.json": SOURCE.with_name("bundle.json"),
        "canonical-corpus.json": ROOT / "tests" / "policy" / "canonical-corpus.json",
    }
    for name, path in packaged.items():
        assert path.is_file(), "Missing genuine generated asset; never synthesize expected bytes"
        assert path.read_bytes() == (first / name).read_bytes()
    assert invoke(canonical_context, SOURCE, CONTRACTS, first, "--check-dir").returncode == 0


@pytest.mark.parametrize("asset", ASSETS)
def test_byte_mutation_is_drift_not_success(canonical_context, asset):
    _, work = canonical_context
    output = work / "original"
    assert invoke(canonical_context, SOURCE, CONTRACTS, output).returncode == 0
    path = output / asset
    path.write_bytes(path.read_bytes() + b" ")
    assert invoke(canonical_context, SOURCE, CONTRACTS, output, "--check-dir").returncode == 3


@pytest.mark.parametrize("expression", ["true", "not false", "(true)", "true and not false"])
def test_only_exact_expression_boolean_paths_normalize(canonical_context, expression):
    result, output = derive_fixture(canonical_context, expression)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    bundle, corpus = decode_assets(output)
    assert all("true" not in p and "false" not in p for p in bundle["manifest"][0]["required_paths"])
    assert corpus["cases"][0]["canonical"]["fired_actions"] == ["set_phase"]
    assert corpus["cases"][2]["canonical"]["fired_actions"] == []


@pytest.mark.parametrize("word", ["true", "false", "null"])
def test_nullable_contract_leaves_and_quoted_sentinels_stay_data(canonical_context, word):
    result, output = derive_fixture(canonical_context, reason=json.dumps(word))
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    bundle, _ = decode_assets(output)
    for example in bundle["contracts"]:
        assert example["expect"]["reason"] == word
        for key in ("next_phase", "aggregate", "error"):
            assert example["expect"][key] is None


@pytest.mark.parametrize(
    "expression",
    [
        "True", "FALSE", "null", "true_value", "facts.true", "facts.false",
        "unknown.field", "true or unknown.field", "false and unknown.field",
        "1 + 1 == 2", "true == 1", "1 == 1.0", "1.0 == 1.0", "1.0 != 1.0",
        "true or (1.0 == 1.0)", "false and (1 == true)", "lookup()",
        "9007199254740992 == 9007199254740992",
        "-9007199254740992 < 0", "9007199254740993 > 0",
        "0.0 == 1e-16", "-0.0 == 0.0", "1e309 > 0.0",
        "4.9406564584124654e-324 > 0.0",
        "-4.9406564584124654e-324 < 0.0",
        "1.7976931348623157e308 > 1.0",
        "-1.7976931348623157e308 < -1.0",
        "NaN > 0.0", "Infinity > 0.0", '"1" == 1', "null == null",
        'true > false', '"a" < "b"',
    ],
)
def test_unsupported_numeric_paths_and_dead_branches_reject(canonical_context, expression):
    result, output = derive_fixture(canonical_context, expression)
    assert_rejected(result, output)


@pytest.mark.parametrize(
    "old,new",
    [
        ("reason: null", "reason: (null)"),
        ("reason: null", "reason: nullish"),
        ("reason: null", "reason: true"),
        ("reason: null", "reason: false"),
        ('decision: "allow"', "decision: null"),
        ('decision: "allow"', 'decision: "allow", decision: "allow"'),
        ('mode: "preview"', 'mode: "preview", mode: "check"'),
        ('mode: "preview"', "mode: null"),
        ('mode: "preview"', "mode: true"),
        ('phase: "Planned"', "phase: null"),
    ],
)
def test_contract_normalization_never_expands_schema(canonical_context, old, new):
    result, output = derive_fixture(
        canonical_context, contract_edit=lambda text: text.replace(old, new, 1)
    )
    assert_rejected(result, output)


@pytest.mark.parametrize(
    "edit",
    [
        lambda text: text + text,
        lambda text: text.replace('phase: "Planned"', 'phase: "Planned" phase: "Active"'),
        lambda text: text.replace('phase: "Planned"', "phase: null"),
        lambda text: text.replace("set_phase", "unregistered_action"),
        lambda text: text.replace("event.kind", "event.unknown"),
    ],
)
def test_duplicate_declarations_parameters_and_unknown_actions_reject(canonical_context, edit):
    result, output = derive_fixture(canonical_context, source_edit=edit)
    assert_rejected(result, output)


@pytest.mark.parametrize(
    "expression",
    [
        f"-{MAX_INT} < -{MAX_INT - 1}",
        f"-{MAX_INT} == -{MAX_INT}",
        f"{MAX_INT - 1} < {MAX_INT}",
        f"{MAX_INT} == {MAX_INT}",
        f"{MAX_INT} != {MAX_INT - 1}",
        f"{MAX_INT} >= {MAX_INT}",
        f"-{MAX_INT} <= -{MAX_INT}",
        "0 > -1",
        "0 == 0",
        "-0.0 <= 0.0",
        "0.0 >= -0.0",
        "0." + "0" * 323 + "5 > 0.0",
        "-0." + "0" * 323 + "5 < 0.0",
        "17976931348623157" + "0" * 292 + ".0 > 1.0",
        "-17976931348623157" + "0" * 292 + ".0 < -1.0",
    ],
)
def test_actual_numeric_source_spellings_match_canonical_results(canonical_context, expression):
    """PX02: signed parsing and canonical comparison, not manually constructed ASTs."""
    result, output = derive_fixture(canonical_context, expression)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    _, corpus = decode_assets(output)
    assert corpus["cases"][0]["canonical"]["expression_values"] == [True, True]
    assert corpus["cases"][2]["canonical"]["expression_values"] == [True, False]


INTEGER_VALUES = (-MAX_INT, -MAX_INT + 1, -1, 0, 1, MAX_INT - 1, MAX_INT)
COMPARISONS = (
    ("==", operator.eq), ("!=", operator.ne), (">", operator.gt),
    ("<", operator.lt), (">=", operator.ge), ("<=", operator.le),
)


@pytest.mark.parametrize("left,right", tuple(itertools.product(INTEGER_VALUES, repeat=2)))
@pytest.mark.parametrize("symbol,comparison", COMPARISONS)
def test_every_int53_operator_at_all_required_boundaries(
    canonical_context, left, right, symbol, comparison
):
    expression = f"{left} {symbol} {right}"
    if not comparison(left, right):
        expression = f"not ({expression})"
    result, output = derive_fixture(canonical_context, expression)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    _, corpus = decode_assets(output)
    assert corpus["cases"][0]["canonical"]["expression_values"] == [True, True]


def test_source_budget_rejects_before_any_asset_publication(canonical_context):
    result, output = derive_fixture(
        canonical_context, source_edit=lambda text: text + "\n#" + "x" * 1_048_576
    )
    assert_rejected(result, output)


def test_wrong_authored_expectation_cannot_become_canonical_truth(canonical_context):
    result, output = derive_fixture(
        canonical_context,
        contract_edit=lambda text: text.replace('decision: "allow"', 'decision: "deny"', 1),
    )
    assert_rejected(result, output)


def test_missing_same_name_contract_is_rejected(canonical_context):
    result, output = derive_fixture(canonical_context, contract_edit=lambda text: "")
    assert_rejected(result, output)


def test_keyword_spelling_mutation_changes_bound_identity(canonical_context):
    _, work = canonical_context
    source, contracts = fixture_text("true")
    source_path, contract_path = work / "identity.px", work / "identity.contracts.px"
    source_path.write_text(source, encoding="utf-8")
    contract_path.write_text(contracts, encoding="utf-8")
    first, second = work / "before", work / "after"
    assert invoke(canonical_context, source_path, contract_path, first).returncode == 0
    source_path.write_text(source + "\n# identity-bound source change\n", encoding="utf-8")
    assert invoke(canonical_context, source_path, contract_path, first, "--check-dir").returncode == 3
    assert invoke(canonical_context, source_path, contract_path, second).returncode == 0
    before, before_corpus = decode_assets(first)
    after, after_corpus = decode_assets(second)
    assert before["source_digests"] != after["source_digests"]
    assert before["content_digest"] != after["content_digest"]
    assert before_corpus["bundle_content_digest"] != after_corpus["bundle_content_digest"]


def px_data(value):
    """Render authored fixture data, never parse or evaluate policy."""
    if isinstance(value, dict):
        return "{" + ", ".join(f"{key}: {px_data(item)}" for key, item in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(px_data(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


def expected(actions=(), decision="allow", outcomes=None, reason=None):
    return {
        "decision": decision, "reason": reason, "actions": list(actions),
        "next_phase": None, "aggregate": None,
        "constraint_outcomes": {} if outcomes is None else outcomes, "error": None,
    }


def contract_text(name, examples):
    return (
        f'contract {name}_contract:\n  given: "Frozen P01 build boundary"\n'
        '  when: "Explicit authored facts"\n  then: "Canonical evidence only"\n  examples:\n'
        + "".join(
            f"    - input: {px_data(inputs)}\n      expect: {px_data(expectation)}\n"
            for inputs, expectation in examples
        )
    )


def derive_texts(context, source, contracts, label="probe"):
    _, work = context
    source_path, contract_path = work / f"{label}.px", work / f"{label}.contracts.px"
    source_path.write_text(source, encoding="utf-8")
    contract_path.write_text(contracts, encoding="utf-8")
    output = work / label
    return invoke(context, source_path, contract_path, output), output


def lifecycle_payload(kind):
    """Nonsecret authored metadata from v3 §4/§6, not a host binding or consent receipt."""
    plan_id, digest = {
        "install": ("10000000-0000-4000-8000-000000000001", "a" * 64),
        "uninstall": ("20000000-0000-4000-8000-000000000002", "b" * 64),
        "restore": ("30000000-0000-4000-8000-000000000003", "c" * 64),
    }[kind]
    return {"lifecycle_kind": kind, "plan_id": plan_id, "lifecycle_binding_digest": digest}


def lifecycle_metadata_fixture(kind="install", edit=None, expression=None):
    """Supply closed lifecycle payloads while keeping metadata outside PX predicates."""
    name = "netops_companion_setup_consent_install_consented_metadata_probe"
    phase = {"install": "Staging", "uninstall": "Admitted", "restore": "Admitted"}[kind]
    predicate = f'event.payload.lifecycle_kind == "{kind}"' if expression is None else expression
    source = (
        f"rule {name}:\n  when:\n"
        '    - event.kind == "InstallConsented"\n'
        f"    - {predicate}\n"
        f'  then:\n    - action: set_phase phase: "{phase}"\n'
    )
    actions = [{"name": "set_phase", "params": {"phase": phase}}]
    examples = []
    for candidate in ("install", "uninstall", "restore"):
        inputs = {
            "state": {"phase": "Planned"},
            "event": {"kind": "InstallConsented", "payload": lifecycle_payload(candidate)},
            "facts": {},
        }
        if edit is not None and candidate == kind:
            edit(inputs)
        examples.append((
            inputs, expected(actions) if candidate == kind else expected(decision="deny"),
        ))
    return source, contract_text(name, examples)


@pytest.mark.parametrize("kind", ("install", "uninstall", "restore"))
def test_lifecycle_metadata_preserved_without_expanding_expression_paths(canonical_context, kind):
    """G07/PX02: metadata survives the artifact but never becomes an expression variable."""
    source, contracts = lifecycle_metadata_fixture(kind)
    result, output = derive_texts(canonical_context, source, contracts)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    bundle, corpus = decode_assets(output)
    assert len(corpus["cases"]) == 3
    assert bundle["manifest"][0]["required_paths"] == [
        ["event", "kind"], ["event", "payload", "lifecycle_kind"],
    ]
    for case, candidate in zip(corpus["cases"], ("install", "uninstall", "restore")):
        assert case["input"]["event"]["payload"] == lifecycle_payload(candidate)
        assert case["canonical"]["fired_actions"] == (["set_phase"] if candidate == kind else [])


@pytest.mark.parametrize("field", ("lifecycle_kind", "plan_id", "lifecycle_binding_digest"))
def test_lifecycle_metadata_missing_payload_fields_reject(canonical_context, field):
    source, contracts = lifecycle_metadata_fixture(
        edit=lambda inputs: inputs["event"]["payload"].pop(field),
    )
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


@pytest.mark.parametrize("field", ("lifecycle_kind", "plan_id", "lifecycle_binding_digest"))
@pytest.mark.parametrize("value", (None, True, False, 0, 1.0, [], {}))
def test_lifecycle_metadata_wrong_types_never_coerce(canonical_context, field, value):
    source, contracts = lifecycle_metadata_fixture(
        edit=lambda inputs: inputs["event"]["payload"].update({field: value}),
    )
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


@pytest.mark.parametrize("value", (None, True, 0, 1.0, [], "install"))
def test_lifecycle_metadata_payload_requires_an_object(canonical_context, value):
    source, contracts = lifecycle_metadata_fixture(
        edit=lambda inputs: inputs["event"].update(payload=value),
    )
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


@pytest.mark.parametrize("field,value", (
    ("lifecycle_kind", "operation"), ("lifecycle_kind", ""),
    ("plan_id", ""), ("plan_id", "install:10000000-0000-4000-8000-000000000001"),
    ("plan_id", "10000000000040008000000000000001"),
    ("plan_id", "10000000_0000-4000-8000-000000000001"),
    ("plan_id", "g0000000-0000-4000-8000-000000000001"),
    ("plan_id", "10000000-0000-4000-8000-000000000001 "),
    ("lifecycle_binding_digest", ""), ("lifecycle_binding_digest", "a" * 63),
    ("lifecycle_binding_digest", "a" * 65), ("lifecycle_binding_digest", "g" * 64),
    ("lifecycle_binding_digest", "sha256:" + "a" * 64),
))
def test_lifecycle_metadata_malformed_identity_spellings_reject(canonical_context, field, value):
    source, contracts = lifecycle_metadata_fixture(
        edit=lambda inputs: inputs["event"]["payload"].update({field: value}),
    )
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


@pytest.mark.parametrize("field", ("unknown", "operation_id", "plan_digest"))
def test_lifecycle_metadata_unknown_payload_fields_reject(canonical_context, field):
    source, contracts = lifecycle_metadata_fixture(
        edit=lambda inputs: inputs["event"]["payload"].update({field: "unrecognized"}),
    )
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


@pytest.mark.parametrize("namespace", ("event", "state", "facts"))
@pytest.mark.parametrize("field", ("plan_id", "lifecycle_binding_digest"))
def test_lifecycle_metadata_wrong_namespace_cannot_supply_payload(canonical_context, namespace, field):
    def move(inputs):
        inputs[namespace][field] = inputs["event"]["payload"].pop(field)

    source, contracts = lifecycle_metadata_fixture(edit=move)
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


@pytest.mark.parametrize("namespace", ("event", "state", "facts"))
@pytest.mark.parametrize("field", ("plan_id", "lifecycle_binding_digest"))
def test_lifecycle_metadata_shadow_namespace_rejects_even_with_valid_payload(
    canonical_context, namespace, field
):
    source, contracts = lifecycle_metadata_fixture(
        edit=lambda inputs: inputs[namespace].update({field: lifecycle_payload("install")[field]}),
    )
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


@pytest.mark.parametrize("field", ("plan_id", "lifecycle_binding_digest"))
def test_lifecycle_metadata_duplicate_keys_reject(canonical_context, field):
    source, contracts = lifecycle_metadata_fixture()
    value = json.dumps(lifecycle_payload("install")[field])
    contracts = contracts.replace(f"{field}: {value}", f"{field}: {value}, {field}: {value}", 1)
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


@pytest.mark.parametrize("expression", (
    'event.payload.plan_id == "10000000-0000-4000-8000-000000000001"',
    'event.payload.lifecycle_binding_digest == "' + "a" * 64 + '"',
    "true or event.payload.plan_id == event.payload.plan_id",
    "false and event.payload.lifecycle_binding_digest == event.payload.lifecycle_binding_digest",
))
def test_lifecycle_metadata_is_not_an_expression_fact_even_in_dead_branches(
    canonical_context, expression
):
    source, contracts = lifecycle_metadata_fixture(expression=expression)
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


@pytest.mark.parametrize("kind", ("OperationRequested", "InstallConsented"))
def test_lifecycle_metadata_does_not_invent_payload_for_sparse_expression_fixture(
    canonical_context, kind
):
    source, contracts = fixture_text()
    source = source.replace("OperationRequested", kind)
    contracts = contracts.replace("OperationRequested", kind)
    result, output = derive_texts(canonical_context, source, contracts)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    _, corpus = decode_assets(output)
    assert all(case["input"]["event"] == {"kind": kind} for case in corpus["cases"])


@pytest.mark.parametrize("kind", ("OperationRequested", "ApplyConsented"))
def test_lifecycle_metadata_cannot_be_adopted_by_operational_event_namespace(canonical_context, kind):
    source, contracts = fixture_text()
    source = source.replace("OperationRequested", kind)
    contracts = contracts.replace(
        'event: {kind: "OperationRequested"}',
        f'event: {px_data({"kind": kind, "payload": lifecycle_payload("install")})}',
    )
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


def test_packaged_assets_bind_the_current_source_and_each_other():
    """PX01/PX12: missing/stale deliverables fail even before a compiler is available."""
    bundle_path = SOURCE.with_name("bundle.json")
    corpus_path = ROOT / "tests" / "policy" / "canonical-corpus.json"
    assert bundle_path.is_file(), "P01 generated bundle has not been delivered"
    assert corpus_path.is_file(), "P01 canonical corpus has not been delivered"
    bundle = json.loads(bundle_path.read_bytes())
    corpus = json.loads(corpus_path.read_bytes())
    assert bundle["source_digests"] == {
        "source": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "contracts": hashlib.sha256(CONTRACTS.read_bytes()).hexdigest(),
    }
    assert corpus["bundle_content_digest"] == bundle["content_digest"]
    assert corpus["canonical_revision"] == bundle["canonical_revision"] == REVISION
    assert {(c["case_id"], c["rule_id"]) for c in corpus["cases"]} == {
        (c["case_id"], c["rule_id"]) for c in bundle["contracts"]
    }


def test_predicate_mutation_with_unchanged_expectations_rejects(canonical_context):
    result, output = derive_fixture(
        canonical_context,
        source_edit=lambda text: text.replace('request.mode != "observe"', 'request.mode == "observe"'),
    )
    assert_rejected(result, output)


@pytest.mark.parametrize("position", ("source", "contracts"))
def test_invalid_utf8_input_never_publishes_assets(canonical_context, position):
    _, work = canonical_context
    source, contracts = fixture_text()
    paths = {"source": work / "utf8.px", "contracts": work / "utf8.contracts.px"}
    paths["source"].write_text(source, encoding="utf-8")
    paths["contracts"].write_text(contracts, encoding="utf-8")
    paths[position].write_bytes(paths[position].read_bytes() + b"\xff")
    output = work / "utf8-output"
    assert_rejected(invoke(canonical_context, paths["source"], paths["contracts"], output), output)


@pytest.mark.parametrize("old,new", [
    ('phase: "Planned"', 'phase: "Planned", phase: "Active"'),
    ('facts: {request:', 'facts: {state: {phase: "Planned"}, request:'),
    ('reason: null', "reason: unknown.path"),
    ('reason: null', "reason: (true)"),
    ('reason: null', "reason: Null"),
    ('reason: null', "reason: null_value"),
    ('reason: null', 'unknown: null, reason: null'),
    ('error: null', 'error: null, error: null'),
])
def test_recursive_duplicates_dynamic_contract_values_and_shadowing_reject(
    canonical_context, old, new
):
    result, output = derive_fixture(
        canonical_context, contract_edit=lambda text: text.replace(old, new, 1)
    )
    assert_rejected(result, output)


@pytest.mark.parametrize("field,value", [
    ("mode", "null"), ("mode", "false"), ("mode", "0"),
    ("mode", '"not-a-mode"'), ("mode", '["preview"]'),
])
def test_supplied_fact_types_and_enums_are_validated_before_evaluation(
    canonical_context, field, value
):
    result, output = derive_fixture(
        canonical_context,
        contract_edit=lambda text: text.replace(f'{field}: "preview"', f"{field}: {value}", 1),
    )
    assert_rejected(result, output)


@pytest.mark.parametrize("asset", ASSETS)
def test_structured_corpus_or_bundle_mutation_is_byte_drift(canonical_context, asset):
    _, work = canonical_context
    source, contracts = fixture_text()
    source_path, contracts_path = work / "mutation.px", work / "mutation.contracts.px"
    source_path.write_text(source, encoding="utf-8")
    contracts_path.write_text(contracts, encoding="utf-8")
    output = work / "mutation"
    assert invoke(canonical_context, source_path, contracts_path, output).returncode == 0
    path = output / asset
    document = json.loads(path.read_bytes())
    if asset == "canonical-corpus.json":
        document["cases"][0]["canonical"]["fired_actions"] = []
    else:
        document["rules"][0]["actions"][0]["params"]["phase"] = "Active"
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    result = invoke(canonical_context, source_path, contracts_path, output, "--check-dir")
    assert result.returncode == 3, result.stderr.decode(errors="replace")


@pytest.mark.parametrize("asset", ASSETS)
def test_existing_output_is_never_overwritten(canonical_context, asset):
    _, work = canonical_context
    source, contracts = fixture_text()
    source_path, contracts_path = work / "overwrite.px", work / "overwrite.contracts.px"
    source_path.write_text(source, encoding="utf-8")
    contracts_path.write_text(contracts, encoding="utf-8")
    output = work / "existing"
    output.mkdir()
    sentinel = b"owned-by-another-operation\n"
    (output / asset).write_bytes(sentinel)
    result = invoke(canonical_context, source_path, contracts_path, output)
    assert result.returncode == 2, result.stderr.decode(errors="replace")
    assert (output / asset).read_bytes() == sentinel


@pytest.mark.parametrize("dimension", (
    "contract-bytes", "declarations", "nodes", "depth", "visits",
    "string-bytes", "utf8-string-bytes", "generated-asset-bytes",
))
def test_each_closed_profile_budget_rejects_without_partial_assets(canonical_context, dimension):
    source, contracts = fixture_text()
    if dimension == "contract-bytes":
        contracts += "\n#" + "x" * 1_048_576
    elif dimension == "declarations":
        originals = source, contracts
        source, contracts = "", ""
        for index in range(257):
            name = f"netops_companion_catalog_operation_requested_budget_{index}"
            source += originals[0].replace(RULE, name)
            contracts += originals[1].replace(RULE, name)
    elif dimension == "nodes":
        source = source.replace("  then:", "    - true\n" * 32_769 + "  then:")
    elif dimension == "depth":
        source, contracts = fixture_text("(" * 34 + "true" + ")" * 34)
    elif dimension == "visits":
        source = source.replace("  then:", "    - true\n" * 500 + "  then:")
    elif dimension in ("string-bytes", "utf8-string-bytes"):
        word = "x" * 4097 if dimension == "string-bytes" else "é" * 2049
        encoded = json.dumps(word, ensure_ascii=False)
        source, contracts = fixture_text(f"{encoded} == {encoded}")
    else:
        originals = fixture_text(f'{json.dumps("x" * 4000)} == {json.dumps("x" * 4000)}')
        source, contracts = "", ""
        for index in range(120):
            name = f"netops_companion_catalog_operation_requested_size_{index}"
            source += originals[0].replace(RULE, name)
            contracts += originals[1].replace(RULE, name)
    if dimension not in ("contract-bytes",):
        assert len(source.encode("utf-8")) <= 1_048_576
        assert len(contracts.encode("utf-8")) <= 1_048_576
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


COUNTER_FIELDS = ("selected", "completed", "unsuccessful", "failed", "cancelled", "unsupported", "blocked")
FAILURE_FLAGS = ("policy_failed", "cleanup_failed", "remote_uncertain")


def final_counts(selected=1, completed=1, unsuccessful=0):
    return {
        "selected": selected, "completed": completed, "unsuccessful": unsuccessful,
        "failed": 0, "cancelled": 0, "unsupported": 0, "blocked": 0,
        "policy_failed": False, "cleanup_failed": False, "remote_uncertain": False,
    }


def aggregate_validation_fixture(result):
    """Exercise final-count schema, not replace the real aggregate policy predicates."""
    name = "netops_companion_aggregate_step_completed_validation_probe"
    source = (
        f"rule {name}:\n  when:\n"
        '    - event.kind == "StepCompleted"\n    - request.mode != "observe"\n'
        '  then:\n    - action: record_outcome status: "failed"\n'
    )
    actions = [{"name": "record_outcome", "params": {"status": "failed"}}]
    examples = []
    for mode, counts, expectation in (
        ("preview", result, expected(actions)),
        ("observe", final_counts(), expected(decision="deny")),
        ("check", final_counts(0, 0), expected(actions)),
    ):
        examples.append((
            {"state": {"phase": "Executing"}, "event": {"kind": "StepCompleted"},
             "facts": {"request": {"mode": mode}, "result": counts}},
            expectation,
        ))
    return source, contract_text(name, examples)


@pytest.mark.parametrize("field", COUNTER_FIELDS)
@pytest.mark.parametrize("value", (True, False, 1.0, -1, MAX_INT + 1, None, "1"))
def test_final_counter_types_ranges_and_null_never_coerce(canonical_context, field, value):
    counts = final_counts()
    counts[field] = value
    source, contracts = aggregate_validation_fixture(counts)
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


@pytest.mark.parametrize("field", COUNTER_FIELDS + FAILURE_FLAGS)
def test_final_counters_and_independent_flags_are_required(canonical_context, field):
    counts = final_counts()
    del counts[field]
    source, contracts = aggregate_validation_fixture(counts)
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


@pytest.mark.parametrize("patch", (
    {"unknown": 0}, {"completed": 2}, {"unsuccessful": 2},
    {"completed": 0, "unsuccessful": 0}, {"completed": 1, "unsuccessful": 1},
    {"failed": 1}, {"cancelled": 1}, {"unsupported": 1}, {"blocked": 1},
    {"selected": MAX_INT, "completed": MAX_INT, "unsuccessful": 1},
))
def test_final_coverage_missing_double_counted_and_contradictory_categories_reject(
    canonical_context, patch
):
    counts = final_counts()
    counts.update(patch)
    source, contracts = aggregate_validation_fixture(counts)
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


@pytest.mark.parametrize("flag", FAILURE_FLAGS)
@pytest.mark.parametrize("value", (0, 1, "false", None))
def test_independent_failure_flags_require_exact_booleans(canonical_context, flag, value):
    counts = final_counts()
    counts[flag] = value
    source, contracts = aggregate_validation_fixture(counts)
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)


@pytest.mark.parametrize("counts", (
    final_counts(0, 0), final_counts(MAX_INT, MAX_INT),
    dict(final_counts(1, 0, 1), failed=1, cancelled=1, unsupported=1, blocked=1),
    dict(final_counts(), policy_failed=True, cleanup_failed=True, remote_uncertain=True),
))
def test_valid_final_counts_do_not_invent_category_partition_or_hide_flags(canonical_context, counts):
    source, contracts = aggregate_validation_fixture(counts)
    result, output = derive_texts(canonical_context, source, contracts)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    _, corpus = decode_assets(output)
    assert corpus["cases"][0]["input"]["facts"]["result"] == counts


@pytest.mark.parametrize("actions", (
    ('set_phase phase: "Planned"', 'set_phase phase: "Active"'),
    ('record_outcome status: "failed"', 'record_outcome status: "blocked"'),
    ('record_step disposition: "failed"', 'record_step disposition: "success"'),
    ('request_effect kind: "scan"', 'request_effect kind: "collect"'),
    ('set_phase phase: "Planned"', 'set_phase phase: "Planned"'),
))
def test_jointly_matching_conflicting_or_duplicate_actions_reject(canonical_context, actions):
    sources, examples_by_rule = [], []
    for index, action in enumerate(actions):
        name = f"netops_companion_catalog_operation_requested_conflict_{index}"
        source = (
            f"rule {name}:\n  when:\n"
            '    - event.kind == "OperationRequested"\n    - request.mode != "observe"\n'
            f"  then:\n    - action: {action}\n"
        )
        action_name, parameter = action.split(" ", 1)
        key, value = parameter.split(": ", 1)
        descriptor = {"name": action_name, "params": {key: json.loads(value)}}
        examples = []
        for mode in ("preview", "observe", "check"):
            examples.append((
                {"state": {"phase": "Planned"}, "event": {"kind": "OperationRequested"},
                 "facts": {"request": {"mode": mode}}},
                expected([descriptor]) if mode != "observe" else expected(decision="deny"),
            ))
        contracts = contract_text(name, examples)
        accepted, accepted_output = derive_texts(
            canonical_context, source, contracts, label=f"single-{index}"
        )
        assert accepted.returncode == 0, accepted.stderr.decode(errors="replace")
        assert len(decode_assets(accepted_output)[0]["rules"]) == 1
        sources.append(source)
        examples_by_rule.append(contracts)
    result, output = derive_texts(canonical_context, "".join(sources), "".join(examples_by_rule))
    assert_rejected(result, output)


@pytest.mark.parametrize("kind", ("cancelled", "output-without-consent"))
def test_constraint_violation_denies_combined_actions_without_rewriting_target_evidence(
    canonical_context, kind
):
    """PX01/PX02: target-local allow is never a constraints-first effect permit."""
    if kind == "cancelled":
        invariant = "netops_companion_invariant_cancellation"
        guard = 'event.kind == "OperationRequested"'
        require = "control.cancelled == false"
        observations = (
            ("preview", {"control": {"cancelled": False}}, "satisfied"),
            ("check", {"control": {"cancelled": True}}, "violated"),
            ("observe", {"control": {"cancelled": False}}, "satisfied"),
        )
    else:
        invariant = "netops_companion_invariant_output_safety"
        guard = 'request.mode == "output"'
        require = "consent.present == true"
        observations = (
            ("preview", {"consent": {"present": True}}, "not-applicable"),
            ("output", {"consent": {"present": False}}, "violated"),
            ("observe", {"consent": {"present": True}}, "not-applicable"),
        )
    source, _ = fixture_text()
    source += (
        f"\nconstraint {invariant}:\n  when: {guard}\n"
        f"  require: {require}\n  severity: error\n"
        '  message: "policy-input-invalid"\n'
    )
    actions = [{"name": "set_phase", "params": {"phase": "Planned"}}]
    rule_examples, constraint_examples = [], []
    for mode, observation, status in observations:
        inputs = {
            "state": {"phase": "Planned"}, "event": {"kind": "OperationRequested"},
            "facts": {"request": {"mode": mode}, **observation},
        }
        rule_examples.append((
            inputs, expected(actions) if mode != "observe" else expected(decision="deny"),
        ))
        constraint_examples.append((
            inputs,
            expected(
                decision="allow" if status == "satisfied" else "deny",
                outcomes={invariant: status},
                reason="policy-input-invalid" if status == "violated" else None,
            ),
        ))
    contracts = contract_text(RULE, rule_examples) + contract_text(invariant, constraint_examples)
    result, output = derive_texts(canonical_context, source, contracts)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    _, corpus = decode_assets(output)
    current, cancelled, no_admit = corpus["cases"][:3]
    assert current["canonical"]["combined"]["decision"] == "allow"
    assert current["canonical"]["combined"]["actions"] == actions
    assert cancelled["canonical"]["fired_actions"] == ["set_phase"]
    assert cancelled["canonical"]["combined"]["decision"] == "deny"
    assert cancelled["canonical"]["combined"]["actions"] == []
    assert cancelled["canonical"]["combined"]["violations"] == [
        invariant.replace("netops_companion_", "netops.companion.", 1),
    ]
    assert no_admit["canonical"]["combined"]["decision"] == "deny"
    assert no_admit["canonical"]["combined"]["actions"] == []


def test_full_policy_stale_revision_is_not_hidden_by_target_local_allow(canonical_context):
    """AC-003/PX06 policy facet, not an actual host CAS or private-permit test."""
    _, work = canonical_context
    output = work / "stale-revision"
    result = invoke(canonical_context, SOURCE, CONTRACTS, output)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    _, corpus = decode_assets(output)
    rule_id = "netops.companion.candidate_lifecycle_candidate_verified_set_phase"
    cases = [case for case in corpus["cases"] if case["rule_id"] == rule_id]
    current = next(
        case for case in cases
        if case["input"]["event"].get("expected_revision") == 1
        and case["input"]["state"].get("revision") == 1
    )
    stale = next(
        case for case in cases
        if case["input"]["event"].get("expected_revision") == 0
        and case["input"]["state"].get("revision") == 1
    )
    assert current["canonical"]["combined"]["decision"] == "allow"
    assert stale["canonical"]["fired_actions"] == ["set_phase"]
    assert stale["canonical"]["combined"]["decision"] == "deny"
    assert stale["canonical"]["combined"]["actions"] == []
    assert "netops.companion.invariant_identity" in stale["canonical"]["combined"]["violations"]
    assert stale["host_expectations"]["next_phase"] is None
    assert stale["host_expectations"]["error"] == "policy-input-invalid"


@pytest.mark.parametrize("family", ("config_mutate", "recovery"))
def test_full_policy_completion_requires_poststate_and_never_issues_retry(canonical_context, family):
    """FR-026/036: bookkeeping intents do not imply that a real change was confirmed."""
    _, work = canonical_context
    output = work / "completion"
    result = invoke(canonical_context, SOURCE, CONTRACTS, output)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    bundle, corpus = decode_assets(output)
    prefix = f"netops.companion.{family}_step_completed_"
    cases = [case for case in corpus["cases"] if case["rule_id"].startswith(prefix)]
    assert cases, "No actual post-state/reconciliation examples"
    for case in cases:
        assert "request_effect" not in case["canonical"]["fired_actions"]
        counts = case["input"]["facts"].get("result", {})
        change = case["input"]["facts"].get("change", {})
        actions = case["host_expectations"]["actions"]
        if {"name": "record_step", "params": {"disposition": "success"}} in actions:
            assert change.get("poststate_verified") is True
            assert counts.get("remote_uncertain") is False
    uncertain = [
        case for case in cases
        if case["input"]["facts"].get("result", {}).get("remote_uncertain") is True
        and case["host_expectations"]["decision"] == "allow"
    ]
    assert uncertain
    for case in uncertain:
        assert {"name": "set_phase", "params": {"phase": "Uncertain"}} in (
            case["host_expectations"]["actions"]
        )
    for rule in bundle["rules"]:
        if rule["id"].startswith(prefix):
            assert all(action["name"] != "request_effect" for action in rule["actions"])


REVOCATION_CONTROLS = (
    pytest.param(True, 1000, id="cancel-with-budget"),
    pytest.param(False, 0, id="deadline-without-cancel-flag"),
    pytest.param(True, 0, id="cancel-and-deadline"),
)


def cancellation_facts(operation, cancelled, remaining_ms, uncertain):
    """Closed nonsecret facts; pending-invocation correlation belongs to the later host."""
    counts = final_counts(1, 0, 1) if uncertain else final_counts()
    counts.update(failed=int(uncertain), remote_uncertain=uncertain)
    return {
        "request": {"area": "config", "operation": operation, "mode": operation},
        "binding": {"input_valid": True, "plan_current": True, "policy_current": True},
        "scope": {"selected_count": 1, "exclusions_valid": True},
        "config": {"enabled": True, "mode": "enforce"},
        "control": {"cancelled": cancelled, "remaining_ms": remaining_ms},
        "readiness": {
            "native": "ready", "companion": "ready", "enhanced": "ready",
            "selected_complete": True,
        },
        "controller": {"qualified": True},
        "route": {"qualified": True},
        "credentials": {"channel_qualified": True},
        "ownership": {"valid": True},
        "storage": {"sensitive_ready": True},
        "consent": {
            "present": True, "binding_matches": True, "remaining_ms": 1000,
            "effects_match": True, "recovery_matches": True,
        },
        "consequential": {"required": False, "granted": False},
        "inventory": {"source_valid": True, "cache_binding_valid": True, "hostvars_safe": True},
        "discovery": {"scope_valid": True},
        "change": {
            "prestate_bound": True, "vendor_recovery_qualified": True,
            "poststate_verified": not uncertain,
        },
        "health": {
            "reading_present": True, "reading_finite": True, "check_supported": True,
            "reading": 1.0, "threshold": 2.0,
        },
        "compare": {"inputs_bound": True, "vendor_supported": True},
        "report": {"coverage_complete": True, "pdf_ready": True, "output_safe": True},
        "candidate": {"verified": True, "pointer_matches": True, "retained_owned": True},
        "lifecycle": {"next_effect_kind": "none"},
        "result": counts,
    }


def cancellation_examples(family, cancelled, remaining_ms, uncertain):
    """Model the issued-effect sequence without claiming actual host reduction or dispatch."""
    operation = "apply" if family == "config_mutate" else "rollback"

    def inputs(kind, phase, revision, revoked=True, output=False):
        facts = cancellation_facts(
            operation, cancelled if revoked else False,
            remaining_ms if revoked else 1000, uncertain,
        )
        if output:
            facts["request"] = {"area": "scan", "operation": "save", "mode": "output"}
        return {
            "state": {"phase": phase, "revision": revision},
            "event": {
                "kind": kind, "expected_revision": revision,
                "payload": {"lifecycle_kind": "install"},
            },
            "facts": facts,
        }

    admission = f"netops_companion_{family}_apply_consented_request_effect"
    dispatch = [
        {"name": "set_phase", "params": {"phase": "Admitted"}},
        {"name": "request_effect", "params": {"kind": operation}},
    ]
    completion = [{"name": "record_step", "params": {"disposition": "success"}}]
    if uncertain:
        completion = [
            {"name": "set_phase", "params": {"phase": "Uncertain"}},
            {"name": "record_step", "params": {"disposition": "failed"}},
        ]
    save_rule = "netops_companion_scan_operation_requested_save"
    save = [{"name": "request_effect", "params": {"kind": "save"}}]
    stale = inputs("StepCompleted", "Cancelling", 11)
    stale["event"]["expected_revision"] = 10
    completion_rule = (
        f"netops_companion_{family}_step_completed_{'uncertain' if uncertain else 'record_step'}"
    )
    return [
        ("admission-positive", admission,
         inputs("ApplyConsented", "Planned", 10, revoked=False), dispatch, True),
        ("cancel", "netops_companion_cancel_control_cancelled_revoke_pending",
         inputs("Cancelled", "Executing", 10), [
             {"name": "revoke_pending", "params": {"scope": "operation"}},
             {"name": "set_phase", "params": {"phase": "Cancelling"}},
         ], True),
        ("late-completion", completion_rule,
         inputs("StepCompleted", "Cancelling", 11), completion, True),
        ("stale-completion", completion_rule, stale, completion, False),
        # A caller's fresh Planned phase cannot override the retained revocation facts.
        ("revoked-admission", admission,
         inputs("ApplyConsented", "Planned", 12), dispatch, False),
        ("output-positive", save_rule,
         inputs("OperationRequested", "Planned", 12, revoked=False, output=True), save, True),
        ("revoked-output", save_rule,
         inputs("OperationRequested", "Planned", 12, output=True), save, False),
    ]


def append_contract_example(contracts, rule, inputs, actions):
    """Insert authored data into an existing contract, not parse or evaluate PX."""
    header = f"contract {rule}_contract:\n"
    assert contracts.count(header) == 1, f"Missing or duplicate fixture target: {rule}"
    before, _, body = contracts.partition(header)
    current, separator, after = body.partition("\ncontract ")
    example = (
        f"    - input: {px_data(inputs)}\n"
        f"      expect: {px_data(expected(actions))}\n"
    )
    return before + header + current.rstrip() + "\n" + example + (
        separator + after if separator else ""
    )


@pytest.mark.parametrize("family", ("config_mutate", "recovery"))
@pytest.mark.parametrize("cancelled,remaining_ms", REVOCATION_CONTROLS)
@pytest.mark.parametrize("uncertain", (False, True), ids=("verified-success", "remote-uncertain"))
def test_full_policy_cancelled_late_completion_preserves_revocation(
    canonical_context, family, cancelled, remaining_ms, uncertain
):
    """A02/PX06/PX08: factual bookkeeping stays admissible, never a new mutation grant."""
    examples = cancellation_examples(family, cancelled, remaining_ms, uncertain)
    contracts = CONTRACTS.read_text(encoding="utf-8")
    for _, rule, inputs, actions, _ in examples:
        contracts = append_contract_example(contracts, rule, inputs, actions)
    result, output = derive_texts(
        canonical_context, SOURCE.read_text(encoding="utf-8"), contracts, "cancel-completion"
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    _, corpus = decode_assets(output)
    for label, rule, inputs, actions, admitted in examples:
        logical_id = rule.replace("netops_companion_", "netops.companion.", 1)
        matches = [
            case for case in corpus["cases"]
            if case["rule_id"] == logical_id and case["input"] == inputs
        ]
        assert len(matches) == 1, f"Missing/duplicate actual canonical case: {label}"
        combined = matches[0]["canonical"]["combined"]
        assert combined is not None, f"Missing actual full-policy combined observation: {label}"
        assert combined["decision"] == ("allow" if admitted else "deny"), label
        if not admitted:
            assert combined["actions"] == [], label
            invariant = "identity" if label == "stale-completion" else "cancellation"
            assert f"netops.companion.invariant_{invariant}" in combined["violations"], label
            continue
        assert combined["violations"] == [], label
        for action in actions:
            assert action in combined["actions"], label
        if label == "late-completion":
            assert not any(action["name"] == "request_effect" for action in combined["actions"])
            assert not any(
                action["name"] == "set_phase"
                and action["params"]["phase"] in {
                    "Planned", "Admitted", "Executing", "Observing", "Staging", "Verified", "Active",
                }
                for action in combined["actions"]
            )
            assert {"name": "record_outcome", "params": {
                "status": "failed" if uncertain else "success",
            }} in combined["actions"]


@pytest.mark.parametrize("spelling,value,kind", [
    ("-0", 0, "int"), ("-1", -1, "int"), (f"-{MAX_INT}", -MAX_INT, "int"),
    (f"-{MAX_INT - 1}", -MAX_INT + 1, "int"), ("-0.0", -0.0, "float"),
    ("-1.0", -1.0, "float"),
])
def test_signed_raw_source_preserves_literal_type_and_zero_sign(
    canonical_context, spelling, value, kind
):
    """S1: inspect the real parser projection, not canonical intermediate JSON."""
    operand = "0.0" if kind == "float" else "0"
    result, output = derive_fixture(canonical_context, f"{spelling} <= {operand}")
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    bundle, corpus = decode_assets(output)

    def literals(node):
        if isinstance(node, dict):
            if node.get("kind") == "literal" and node.get("type") == kind:
                yield node
            for child in node.values():
                yield from literals(child)
        elif isinstance(node, list):
            for child in node:
                yield from literals(child)

    matches = [node for node in literals(bundle["rules"]) if node["value"] == value]
    assert matches
    if spelling == "-0.0":
        assert any(json.dumps(node["value"]) == "-0.0" for node in matches)
    assert corpus["cases"][0]["canonical"]["expression_values"] == [True, True]


@pytest.mark.parametrize("expression", [
    "-request.mode == 0", "-health.reading < 0.0", "-lookup() < 0",
    "-(1) < 0", "-(-1) > 0", "-(1 + 1) < 0",
    "true or (-health.reading < 0.0)", "false and (-(1 + 1) < 0)",
    "-true == -1", '-"1" == -1', "-null == 0", "-9007199254740992 < 0",
    "-9007199254740993 < 0", "-9223372036854775808 < 0",
    "-1.0 == -1.0", "-1.0 != -1.0", "-1 == -1.0", "-0.0 == 0.0",
    "-" + "9" * 309 + ".0 < 0.0", "-NaN < 0.0", "-Infinity < 0.0",
])
def test_signed_raw_source_rejects_nonconstant_and_out_of_profile_shapes(
    canonical_context, expression
):
    """S1 rejects every branch before publishing, including unreachable operands."""
    result, output = derive_fixture(canonical_context, expression)
    assert_rejected(result, output)


@pytest.mark.parametrize("expression", ["(-1) < 0", "((-1)) < 0", "(-0.0) <= 0.0"])
def test_signed_outer_parentheses_do_not_admit_parenthesized_operands(
    canonical_context, expression
):
    result, output = derive_fixture(canonical_context, expression)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    _, corpus = decode_assets(output)
    assert corpus["cases"][0]["canonical"]["expression_values"] == [True, True]


def test_signed_raw_double_minus_is_one_negated_signed_literal(canonical_context):
    """Pinned neg_expr consumes an atom containing signed integer -1, not another Neg."""
    result, output = derive_fixture(canonical_context, "--1 > 0")
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    bundle, corpus = decode_assets(output)
    comparison = bundle["rules"][0]["conditions"][1]["right"]["operand"]
    assert comparison == {
        "kind": "binary", "op": "Gt",
        "left": {"kind": "literal", "type": "int", "value": 1},
        "right": {"kind": "literal", "type": "int", "value": 0},
    }
    assert [case["canonical"]["expression_values"] for case in corpus["cases"]] == [
        [True, True], [True, True], [True, False],
    ]
    assert [case["canonical"]["fired_actions"] for case in corpus["cases"]] == [
        ["set_phase"], ["set_phase"], [],
    ]


LIFECYCLE_EFFECTS = (
    "dependency-probe", "dependency-download", "dependency-stage", "dependency-verify",
    "dependency-activate", "dependency-uninstall", "restore-active-pointer",
)


def next_occurrence_fixture(value="none", edit=None, expression=None):
    """An authored closed fact is not trusted occurrence hydration or admission."""
    predicate = 'lifecycle.next_effect_kind == "none"' if expression is None else expression
    source = (
        f"rule {RULE}:\n  when:\n"
        '    - event.kind == "OperationRequested"\n'
        f"    - {predicate}\n"
        '  then:\n    - action: set_phase phase: "Planned"\n'
    )
    actions = [{"name": "set_phase", "params": {"phase": "Planned"}}]
    candidates = [value] + [
        kind for kind in ("none", "dependency-probe", "dependency-download") if kind != value
    ][:2]
    examples = []
    for index, candidate in enumerate(candidates):
        inputs = {
            "state": {"phase": "Planned"}, "event": {"kind": "OperationRequested"},
            "facts": {"lifecycle": {"next_effect_kind": candidate}},
        }
        if edit and index == 0:
            edit(inputs)
        expectation = expected(actions) if candidate == "none" else expected(decision="deny")
        examples.append((inputs, expectation))
    return source, contract_text(RULE, examples)


@pytest.mark.parametrize("kind", LIFECYCLE_EFFECTS + ("none",))
def test_next_occurrence_closed_domain_preserves_exact_fact(canonical_context, kind):
    source, contracts = next_occurrence_fixture(kind)
    result, output = derive_texts(canonical_context, source, contracts)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    bundle, corpus = decode_assets(output)
    assert bundle["rules"][0]["conditions"] == [
        {"kind": "binary", "op": "Eq",
         "left": {"kind": "path", "segments": ["event", "kind"]},
         "right": {"kind": "literal", "type": "string", "value": "OperationRequested"}},
        {"kind": "binary", "op": "Eq",
         "left": {"kind": "path", "segments": ["lifecycle", "next_effect_kind"]},
         "right": {"kind": "literal", "type": "string", "value": "none"}},
    ]
    assert corpus["cases"][0]["input"]["facts"]["lifecycle"] == {"next_effect_kind": kind}
    assert corpus["cases"][0]["canonical"]["fired_actions"] == (
        ["set_phase"] if kind == "none" else []
    )
    for case in corpus["cases"]:
        is_none = case["input"]["facts"]["lifecycle"]["next_effect_kind"] == "none"
        assert case["canonical"]["expression_values"] == [True, is_none]
        assert case["canonical"]["fired_actions"] == (["set_phase"] if is_none else [])
        assert case["canonical"]["combined"]["decision"] == ("allow" if is_none else "deny")
        assert case["canonical"]["combined"]["actions"] == (
            [{"name": "set_phase", "params": {"phase": "Planned"}}] if is_none else []
        )


@pytest.mark.parametrize("value", [
    None, True, False, 0, 1.0, [], {}, "", "None", "NONE", " dependency-probe",
    "dependency-probe ", "Dependency-Probe", "apply", "restore", "none\x00",
])
def test_next_occurrence_missing_malformed_or_wrong_type_rejects(canonical_context, value):
    source, contracts = next_occurrence_fixture(value)
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)
    assert b"rule lacks explicit event-kind guard" not in result.stderr


@pytest.mark.parametrize("edit", [
    lambda data: data["facts"].pop("lifecycle"),
    lambda data: data["facts"]["lifecycle"].pop("next_effect_kind"),
    lambda data: data["facts"]["lifecycle"].update(ordinal=0),
    lambda data: data["facts"]["lifecycle"].update(plan_id="stale"),
    lambda data: data["facts"].update(next_effect_kind="none"),
    lambda data: data["event"].update(next_effect_kind="none"),
])
def test_next_occurrence_is_required_closed_and_cannot_be_shadowed(canonical_context, edit):
    source, contracts = next_occurrence_fixture(edit=edit)
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)
    assert b"rule lacks explicit event-kind guard" not in result.stderr


@pytest.mark.parametrize("expression", [
    "lifecycle.ordinal == 0", 'lifecycle.plan_id == "stale"',
    'lifecycle.next_effect_kind.value == "none"', 'lifecycle.next_effect_kind() == "none"',
    'true or lifecycle.arguments_digest == "a"', 'false and lifecycle.revision == 0',
])
def test_next_occurrence_does_not_expand_paths_or_call_surface(canonical_context, expression):
    source, contracts = next_occurrence_fixture(expression=expression)
    result, output = derive_texts(canonical_context, source, contracts)
    assert_rejected(result, output)
    assert b"rule lacks explicit event-kind guard" not in result.stderr


def setup_occurrence_input(operation, kind, event="StepCompleted"):
    facts = cancellation_facts("apply", False, 1000, False)
    facts["request"] = {"area": "setup", "operation": operation, "mode": "apply"}
    facts["lifecycle"] = {"next_effect_kind": kind}
    phase = "Admitted" if operation == "uninstall" else "Staging"
    if event == "InstallConsented":
        phase = "Planned"
    return {
        "state": {"phase": phase, "revision": 1},
        "event": {"kind": event, "expected_revision": 1,
                  "payload": (lifecycle_payload(operation) if event == "InstallConsented"
                              else {"lifecycle_kind": operation})},
        "facts": facts,
    }


def full_occurrence_case(context, target, inputs, actions=(), fires=True):
    contracts = append_contract_example(
        CONTRACTS.read_text(encoding="utf-8"), target, inputs, actions
    )
    if not fires:
        # Author the isolated target deny without confusing it with combined denial.
        marker = f"    - input: {px_data(inputs)}\n      expect: {px_data(expected(actions))}\n"
        replacement = (
            f"    - input: {px_data(inputs)}\n"
            f"      expect: {px_data(expected(decision='deny'))}\n"
        )
        assert contracts.count(marker) == 1
        contracts = contracts.replace(marker, replacement)
    result, output = derive_texts(context, SOURCE.read_text(encoding="utf-8"), contracts)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    _, corpus = decode_assets(output)
    logical = target.replace("netops_companion_", "netops.companion.", 1)
    matches = [case for case in corpus["cases"]
               if case["rule_id"] == logical and case["input"] == inputs]
    assert len(matches) == 1
    assert matches[0]["canonical"]["combined"] is not None
    return matches[0]["canonical"]


@pytest.mark.parametrize("kind", LIFECYCLE_EFFECTS)
def test_full_policy_next_occurrence_selects_one_exact_existing_intent(canonical_context, kind):
    operation = "uninstall" if kind in LIFECYCLE_EFFECTS[-2:] else "install"
    event = "CandidateVerified" if kind == "dependency-activate" else "StepCompleted"
    suffix = "restore" if kind == "restore-active-pointer" else kind.removeprefix("dependency-")
    target = f"netops_companion_candidate_lifecycle_{operation}_next_{suffix}"
    inputs = setup_occurrence_input(operation, kind, event)
    action = {"name": "request_effect", "params": {"kind": kind}}
    observation = full_occurrence_case(canonical_context, target, inputs, [action])
    combined = observation["combined"]
    assert combined["decision"] == "allow"
    assert combined["violations"] == []
    assert [a for a in combined["actions"] if a["name"] == "request_effect"] == [action]


@pytest.mark.parametrize("field,value", [
    ("present", False), ("binding_matches", False), ("effects_match", False),
    ("remaining_ms", 0),
])
@pytest.mark.parametrize("event", ["StepCompleted", "CandidateVerified"])
def test_full_policy_next_occurrence_requires_current_complete_consent(
    canonical_context, field, value, event
):
    kind = "dependency-activate" if event == "CandidateVerified" else "dependency-probe"
    target = ("netops_companion_candidate_lifecycle_install_next_"
              + ("activate" if event == "CandidateVerified" else "probe"))
    inputs = setup_occurrence_input("install", kind, event)
    inputs["facts"]["consent"][field] = value
    fires = field not in ("binding_matches", "effects_match")
    actions = [{"name": "request_effect", "params": {"kind": kind}}] if fires else []
    observation = full_occurrence_case(canonical_context, target, inputs, actions, fires)
    assert observation["combined"]["decision"] == "deny"
    assert observation["combined"]["actions"] == []
    assert "netops.companion.invariant_consent" in observation["combined"]["violations"]


@pytest.mark.parametrize("mode", ["preview", "check"])
@pytest.mark.parametrize("event", ["StepCompleted", "CandidateVerified"])
def test_full_policy_next_occurrence_preview_and_check_never_dispatch(
    canonical_context, mode, event
):
    kind = "dependency-activate" if event == "CandidateVerified" else "dependency-probe"
    target = ("netops_companion_candidate_lifecycle_install_next_"
              + ("activate" if event == "CandidateVerified" else "probe"))
    inputs = setup_occurrence_input("install", kind, event)
    inputs["facts"]["request"]["mode"] = mode
    action = {"name": "request_effect", "params": {"kind": kind}}
    observation = full_occurrence_case(canonical_context, target, inputs, [action])
    assert observation["combined"]["decision"] == "deny"
    assert observation["combined"]["actions"] == []
    assert "netops.companion.invariant_consent" in observation["combined"]["violations"]


def test_full_policy_no_remaining_is_bookkeeping_not_a_consent_renewal(canonical_context):
    inputs = setup_occurrence_input("install", "none", "CandidateVerified")
    inputs["facts"]["consent"].update(present=False, remaining_ms=0)
    target = "netops_companion_candidate_lifecycle_candidate_verified_set_phase"
    actions = [{"name": "set_phase", "params": {"phase": "Verified"}}]
    observation = full_occurrence_case(canonical_context, target, inputs, actions)
    assert observation["combined"]["decision"] == "allow"
    assert observation["combined"]["violations"] == []
    assert observation["combined"]["actions"] == actions
    assert inputs["facts"]["consent"]["remaining_ms"] == 0


@pytest.mark.parametrize("mutation", ["stale-revision", "stale-plan", "stale-policy",
                                     "invalid-input", "cancelled", "wrong-operation",
                                     "wrong-event"])
def test_full_policy_next_occurrence_never_repairs_missing_current_binding(
    canonical_context, mutation
):
    inputs = setup_occurrence_input("install", "dependency-probe")
    target = "netops_companion_candidate_lifecycle_install_next_probe"
    if mutation == "stale-revision":
        inputs["event"]["expected_revision"] = 0
    elif mutation in ("stale-plan", "stale-policy", "invalid-input"):
        field = {"stale-plan": "plan_current", "stale-policy": "policy_current",
                 "invalid-input": "input_valid"}[mutation]
        inputs["facts"]["binding"][field] = False
    elif mutation == "cancelled":
        inputs["facts"]["control"]["cancelled"] = True
    elif mutation == "wrong-operation":
        inputs["facts"]["request"]["operation"] = "restore"
    else:
        inputs["event"]["kind"] = "DependencyObserved"
    fires = mutation not in ("cancelled", "wrong-operation", "wrong-event")
    action = {"name": "request_effect", "params": {"kind": "dependency-probe"}}
    observation = full_occurrence_case(
        canonical_context, target, inputs, [action] if fires else [], fires
    )
    assert not any(a["name"] == "request_effect" for a in observation["combined"]["actions"])
    if fires:
        assert observation["combined"]["decision"] == "deny"
        assert observation["combined"]["violations"]


def test_full_policy_repeated_kinds_remain_separate_authored_occurrences(canonical_context):
    """N1 only: repeated kinds do not prove trusted prefix hydration by the later host."""
    contracts = CONTRACTS.read_text(encoding="utf-8")
    authored = []
    for ordinal, kind in enumerate([
        "dependency-probe", "dependency-probe", "dependency-download",
        "dependency-stage", "dependency-verify", "dependency-activate",
    ]):
        inputs = setup_occurrence_input("install", kind)
        inputs["state"]["revision"] = ordinal + 1
        inputs["event"]["expected_revision"] = ordinal + 1
        if kind == "dependency-activate":
            inputs["state"]["phase"] = "Verified"
        target = ("netops_companion_candidate_lifecycle_install_next_"
                  + kind.removeprefix("dependency-"))
        action = {"name": "request_effect", "params": {"kind": kind}}
        contracts = append_contract_example(contracts, target, inputs, [action])
        authored.append((target.replace("netops_companion_", "netops.companion.", 1),
                         inputs, action))
    result, output = derive_texts(
        canonical_context, SOURCE.read_text(encoding="utf-8"), contracts, "repeated-kind"
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    _, corpus = decode_assets(output)
    for target, inputs, action in authored:
        cases = [case for case in corpus["cases"]
                 if case["rule_id"] == target and case["input"] == inputs]
        assert len(cases) == 1
        combined = cases[0]["canonical"]["combined"]
        assert combined is not None and combined["decision"] == "allow"
        assert combined["violations"] == []
        assert [a for a in combined["actions"] if a["name"] == "request_effect"] == [action]


@pytest.mark.parametrize("namespace,field", [
    ("binding", "input_valid"), ("binding", "plan_current"), ("binding", "policy_current"),
    ("state", "revision"), ("event", "expected_revision"),
    ("lifecycle", "next_effect_kind"),
])
def test_missing_occurrence_bindings_never_manufacture_combined_admission_evidence(
    canonical_context, namespace, field
):
    """Target-local fixtures cannot certify missing current full-policy host bindings."""
    inputs = setup_occurrence_input("install", "dependency-probe")
    if namespace in ("state", "event"):
        inputs[namespace].pop(field)
    else:
        inputs["facts"][namespace].pop(field)
    target = "netops_companion_candidate_lifecycle_install_next_probe"
    action = {"name": "request_effect", "params": {"kind": "dependency-probe"}}
    contracts = append_contract_example(
        CONTRACTS.read_text(encoding="utf-8"), target, inputs, [action]
    )
    result, output = derive_texts(canonical_context, SOURCE.read_text(encoding="utf-8"), contracts)
    if namespace == "lifecycle":
        assert_rejected(result, output)
        return
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    _, corpus = decode_assets(output)
    cases = [case for case in corpus["cases"] if case["input"] == inputs]
    assert len(cases) == 1
    assert cases[0]["canonical"]["combined"] is None


@pytest.mark.parametrize("name", [
    "signed_int_boundaries", "signed_float_boundaries_and_negative_zero",
    "dynamic_nested_paren_and_arithmetic_negation_reject", "unary_budget_counts_both_nodes",
    "unary_mixed_types_and_float_equality_reject", "closed_next_occurrence_leaf_and_path",
])
def test_direct_ast_independent_rust_contracts_require_real_execution(name):
    """Run only an explicitly qualified harness; a missing binary fails, never skips."""
    setting = os.environ.get("NETOPS_CANONICAL_AST_TEST_BINARY")
    assert setting, "Independent direct-AST Rust harness has not been built and qualified"
    binary = Path(setting).resolve(strict=True)
    assert ROOT in binary.parents and binary.is_file() and not binary.is_symlink()
    result = subprocess.run(
        [str(binary), "--exact", f"nov11_independent::{name}", "--nocapture"],
        cwd=ROOT, capture_output=True, timeout=30, check=False,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert b"1 passed; 0 failed" in result.stdout, result.stdout.decode(errors="replace")
