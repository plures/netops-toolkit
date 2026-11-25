"""Independent frozen P01 semantics, not broker/installer execution evidence.

The canonical adapter evaluates real PX. Host vectors are separately authored
expectations and must never be reported as execution of a host reducer or CAS.
Original sparse fixtures remain untouched.
"""

import hashlib
import json
import math
import struct
import uuid
from pathlib import Path

import pytest
from test_policy_derivation import (
    CONTRACTS,
    LIFECYCLE_EFFECTS,
    MAX_INT,
    ROOT,
    SOURCE,
    append_contract_example,
    assert_rejected,
    decode_assets,
    derive_texts,
    expected,
    full_occurrence_case,
    px_data,
    setup_occurrence_input,
)
from test_policy_derivation import canonical_context as canonical_context

from tests.policy.fixtures.p01_semantic_expectations import SEMANTIC_VECTORS

RESTORE = "netops_companion_setup_consent_install_consented_restore"
ADMITTED = {"name": "set_phase", "params": {"phase": "Admitted"}}
POINTER = {"name": "request_effect", "params": {"kind": "restore-active-pointer"}}
RESTORE_ACTIONS = [ADMITTED, POINTER]
EVENT_KINDS = (
    "OperationRequested", "DependencyObserved", "InstallConsented", "Observed",
    "ApplyConsented", "StepCompleted", "CandidateVerified", "Activated", "Cancelled",
)
VECTOR_INDEX = Path(__file__).with_name("fixtures") / "p01_semantic_expectations.py"


def restore_input():
    """Deliberately complete facts for this operation, never sparse-fixture hydration."""
    inputs = setup_occurrence_input("restore", "restore-active-pointer", "InstallConsented")
    inputs["state"]["revision"] = inputs["event"]["expected_revision"] = 17
    inputs["event"]["payload"]["plan_id"] = "70000000-0000-4000-8000-000000000007"
    return inputs


def assert_no_dispatch(combined):
    assert combined is not None, "A sparse target-local example is not combined policy proof"
    assert not [action for action in combined["actions"] if action["name"] == "request_effect"]


def restore_observation(context, inputs, fires=True):
    return full_occurrence_case(
        context, RESTORE, inputs, RESTORE_ACTIONS if fires else [], fires
    )


def test_restore_complete_admission_is_exact_single_pointer_intent(canonical_context):
    """FR-007/044; AC-001/015; PX05/LA03/LA06/T05/T28."""
    inputs = restore_input()
    payload = inputs["event"]["payload"]
    assert payload["lifecycle_kind"] == "restore"
    assert len(payload["plan_id"]) == 36 and len(payload["lifecycle_binding_digest"]) == 64
    observed = restore_observation(canonical_context, inputs)
    assert observed["fired_actions"] == ["set_phase", "request_effect"]
    assert observed["combined"]["decision"] == "allow"
    assert observed["combined"]["violations"] == []
    assert observed["combined"]["actions"] == RESTORE_ACTIONS


@pytest.mark.parametrize("kind", [kind for kind in LIFECYCLE_EFFECTS if kind != "restore-active-pointer"] + ["none"])
def test_restore_rejects_every_other_next_kind(canonical_context, kind):
    """A restore is not an install/repair/uninstall plan, even with valid consent."""
    inputs = restore_input()
    inputs["facts"]["lifecycle"]["next_effect_kind"] = kind
    observed = restore_observation(canonical_context, inputs, fires=False)
    assert observed["fired_actions"] == []
    assert observed["combined"]["decision"] == "deny"
    assert_no_dispatch(observed["combined"])


@pytest.mark.parametrize("field", ["verified", "retained_owned", "pointer_matches"])
def test_restore_candidate_failures_deny_target_and_combined(canonical_context, field):
    inputs = restore_input()
    inputs["facts"]["candidate"][field] = False
    observed = restore_observation(canonical_context, inputs, fires=False)
    assert observed["fired_actions"] == []
    assert observed["combined"]["decision"] == "deny"
    assert_no_dispatch(observed["combined"])


@pytest.mark.parametrize("field,value", [
    ("present", False), ("remaining_ms", 0), ("binding_matches", False),
    ("effects_match", False),
])
def test_restore_separates_local_match_from_consent_denial(canonical_context, field, value):
    """A fired rule is never consent evidence: complete constraints suppress its intent."""
    inputs = restore_input()
    inputs["facts"]["consent"][field] = value
    observed = restore_observation(canonical_context, inputs)
    assert observed["fired_actions"] == ["set_phase", "request_effect"]
    assert observed["combined"]["decision"] == "deny"
    assert "netops.companion.invariant_consent" in observed["combined"]["violations"]
    assert observed["combined"]["actions"] == []


@pytest.mark.parametrize("mode", ["preview", "check"])
def test_restore_preview_check_do_not_admit_pointer(canonical_context, mode):
    inputs = restore_input()
    inputs["facts"]["request"]["mode"] = mode
    observed = restore_observation(canonical_context, inputs)
    assert observed["fired_actions"] == ["set_phase", "request_effect"]
    assert observed["combined"]["decision"] == "deny"
    assert "netops.companion.invariant_consent" in observed["combined"]["violations"]
    assert observed["combined"]["actions"] == []


@pytest.mark.parametrize("mutation", [
    "stale-revision", "stale-plan", "stale-policy", "invalid-input",
    "cancelled", "expired-control", "unowned",
])
def test_restore_stale_revoked_or_unowned_input_never_dispatches(canonical_context, mutation):
    inputs = restore_input()
    facts = inputs["facts"]
    invariant = "identity"
    if mutation == "stale-revision":
        inputs["event"]["expected_revision"] = 0
    elif mutation in ("stale-plan", "stale-policy", "invalid-input"):
        field = {
            "stale-plan": "plan_current", "stale-policy": "policy_current",
            "invalid-input": "input_valid",
        }[mutation]
        facts["binding"][field] = False
        if mutation == "invalid-input":
            invariant = "input_binding"
    elif mutation in ("cancelled", "expired-control"):
        facts["control"]["cancelled" if mutation == "cancelled" else "remaining_ms"] = (
            True if mutation == "cancelled" else 0
        )
        invariant = "cancellation"
    else:
        facts["ownership"]["valid"] = False
        invariant = "ownership"
    observed = restore_observation(canonical_context, inputs)
    assert observed["fired_actions"] == ["set_phase", "request_effect"]
    assert observed["combined"]["decision"] == "deny"
    assert f"netops.companion.invariant_{invariant}" in observed["combined"]["violations"]
    assert observed["combined"]["actions"] == []


@pytest.mark.parametrize("field", ["present", "binding_matches", "effects_match", "remaining_ms"])
def test_restore_missing_consent_cannot_manufacture_combined_proof(canonical_context, field):
    inputs = restore_input()
    inputs["facts"]["consent"].pop(field)
    contracts = append_contract_example(
        CONTRACTS.read_text(encoding="utf-8"), RESTORE, inputs, RESTORE_ACTIONS
    )
    result, output = derive_texts(
        canonical_context, SOURCE.read_text(encoding="utf-8"), contracts
    )
    # Missing a required target-local path rejects; missing only a combined path
    # may retain local evidence, but can never manufacture a full-policy allow.
    if result.returncode == 2:
        assert_rejected(result, output)
    else:
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        _, corpus = decode_assets(output)
        matches = [case for case in corpus["cases"] if case["input"] == inputs]
        assert len(matches) == 1
        assert matches[0]["canonical"]["combined"] is None


@pytest.mark.parametrize("revoked", [False, True])
def test_restore_completed_sole_occurrence_is_bookkeeping_only(canonical_context, revoked):
    """FR-007/015/044; explicit none never renews the consumed pointer grant."""
    inputs = setup_occurrence_input("restore", "none", "StepCompleted")
    inputs["state"]["phase"] = "Executing"
    inputs["state"]["revision"] = inputs["event"]["expected_revision"] = 18
    inputs["facts"]["consent"].update(present=False, remaining_ms=0)
    inputs["facts"]["control"].update(cancelled=revoked, remaining_ms=0 if revoked else 1000)
    target = "netops_companion_aggregate_step_completed_success"
    actions = [{"name": "record_outcome", "params": {"status": "success"}}]
    observed = full_occurrence_case(canonical_context, target, inputs, actions)
    assert observed["fired_actions"] == ["record_outcome"]
    assert observed["combined"]["decision"] == "allow"
    assert observed["combined"]["violations"] == []
    assert observed["combined"]["actions"] == actions
    assert_no_dispatch(observed["combined"])


def test_restore_actual_source_missing_next_guard_is_detected(canonical_context):
    """PX01/PX02 sensitivity: mutate a copy of the actual PX, not a toy oracle.

    This is current-source mutation sensitivity, not a claimed historical revert.
    Neither shared PX nor its packaged contracts/assets is changed.
    """
    source = SOURCE.read_text(encoding="utf-8")
    contracts = CONTRACTS.read_text(encoding="utf-8")
    inputs = restore_input()
    inputs["facts"]["lifecycle"]["next_effect_kind"] = "dependency-download"
    contracts = append_contract_example(contracts, RESTORE, inputs, [])
    allow = f"    - input: {px_data(inputs)}\n      expect: {px_data(expected([]))}\n"
    deny = f"    - input: {px_data(inputs)}\n      expect: {px_data(expected(decision='deny'))}\n"
    assert contracts.count(allow) == 1
    contracts = contracts.replace(allow, deny)
    header = f"rule {RESTORE}:\n"
    before, separator, after = source.partition(header)
    assert separator
    body, next_rule, remainder = after.partition("\nrule ")
    guard = '    - lifecycle.next_effect_kind == "restore-active-pointer"\n'
    assert body.count(guard) == 1
    mutant = before + separator + body.replace(guard, "") + next_rule + remainder
    mutated, mutated_output = derive_texts(
        canonical_context, mutant, contracts, "restore-real-predicate-mutant"
    )
    assert_rejected(mutated, mutated_output)
    assert b"canonical" in mutated.stderr and b"expectation mismatch" in mutated.stderr
    restored, restored_output = derive_texts(
        canonical_context, source, contracts, "restore-real-predicate-restored"
    )
    assert restored.returncode == 0, restored.stderr.decode(errors="replace")
    _, corpus = decode_assets(restored_output)
    case = next(case for case in corpus["cases"] if case["input"] == inputs)
    assert case["canonical"]["fired_actions"] == []
    assert case["canonical"]["combined"]["decision"] == "deny"
    assert_no_dispatch(case["canonical"]["combined"])


@pytest.fixture(scope="module")
def packaged_corpus():
    """Inspect actual packaged canonical observations; never synthesize missing cases."""
    bundle = json.loads(SOURCE.with_name("bundle.json").read_bytes())
    corpus = json.loads((ROOT / "tests" / "policy" / "canonical-corpus.json").read_bytes())
    assert corpus["bundle_content_digest"] == bundle["content_digest"]
    assert corpus["canonical_revision"] == bundle["canonical_revision"]
    assert corpus["profile"] == bundle["profile"] == "netops-reference-v1"
    assert bundle["source_digests"] == {
        "source": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "contracts": hashlib.sha256(CONTRACTS.read_bytes()).hexdigest(),
    }, "Historical packaged assets are not canonical evidence for changed source/contracts"
    return bundle, corpus["cases"]


def complete_restore_cases(cases, event_kind="InstallConsented"):
    return [
        case for case in cases
        if case["input"]["event"]["kind"] == event_kind
        and case["input"]["facts"].get("request", {}).get("area") == "setup"
        and case["input"]["facts"]["request"].get("operation") == "restore"
        and case["canonical"]["combined"] is not None
    ]


def test_packaged_restore_positive_is_actual_complete_policy_not_sparse_credit(packaged_corpus):
    """The original three sparse restore examples are not replaced or overcredited."""
    _, cases = packaged_corpus
    positives = [
        case for case in complete_restore_cases(cases)
        if case["canonical"]["combined"]["decision"] == "allow"
    ]
    assert positives, "Missing authored complete-fact restore admission in actual canonical corpus"
    for case in positives:
        inputs = case["input"]
        assert inputs["state"]["phase"] == "Planned"
        assert inputs["event"]["payload"]["lifecycle_kind"] == "restore"
        assert str(uuid.UUID(inputs["event"]["payload"]["plan_id"])) == (
            inputs["event"]["payload"]["plan_id"].lower()
        )
        assert len(inputs["event"]["payload"]["lifecycle_binding_digest"]) == 64
        assert inputs["facts"]["lifecycle"]["next_effect_kind"] == "restore-active-pointer"
        assert case["canonical"]["fired_actions"] == ["set_phase", "request_effect"]
        assert case["host_expectations"]["actions"] == RESTORE_ACTIONS
        assert case["host_expectations"]["next_phase"] == "Admitted"
        assert case["canonical"]["combined"]["violations"] == []
        assert case["canonical"]["combined"]["actions"] == RESTORE_ACTIONS


@pytest.mark.parametrize("kind", [kind for kind in LIFECYCLE_EFFECTS if kind != "restore-active-pointer"] + ["none"])
def test_packaged_restore_wrong_next_kinds_have_explicit_rejections(packaged_corpus, kind):
    _, cases = packaged_corpus
    wrong_next = [
        case for case in complete_restore_cases(cases)
        if case["input"]["facts"].get("lifecycle", {}).get("next_effect_kind") == kind
    ]
    assert wrong_next, f"Missing distinct complete restore rejection for next occurrence {kind}"
    for case in wrong_next:
        assert case["canonical"]["fired_actions"] == []
        assert case["host_expectations"]["decision"] == "deny"
        assert case["canonical"]["combined"]["decision"] == "deny"
        assert_no_dispatch(case["canonical"]["combined"])


def test_packaged_restore_completion_exposes_no_second_pointer_intent(packaged_corpus):
    _, cases = packaged_corpus
    terminal = [
        case for case in complete_restore_cases(cases, "StepCompleted")
        if case["input"]["facts"].get("lifecycle", {}).get("next_effect_kind") == "none"
    ]
    assert terminal, "Missing separately authored sole restore occurrence completion"
    for case in terminal:
        combined = case["canonical"]["combined"]
        assert combined["decision"] == "allow"
        assert_no_dispatch(combined)
        assert case["input"]["facts"]["result"]["selected"] == 1
        assert case["input"]["facts"]["result"]["completed"] == 1
        assert {"name": "record_outcome", "params": {"status": "success"}} in combined["actions"]


@pytest.fixture(scope="module")
def semantic_vectors():
    """Portable authored expectations, not a historical or current proof receipt."""
    assert VECTOR_INDEX.is_file(), "Actual authored semantic vector index is not yet available"
    assert hashlib.sha256(VECTOR_INDEX.read_bytes()).hexdigest() == (
        "398d698ad514206bc17de768a7b5633497c4fcbcea0d6e680121115ace75d7a6"
    ), "Retain the independently authored 45 policy cases and 233 host vectors unchanged"
    index = SEMANTIC_VECTORS
    assert index["record_kind"] == "AUTHORED_P01_SEMANTIC_EXPECTATIONS"
    assert index["original_examples_retained"] == 170
    assert len(index["policy_cases"]) == 45 and len(index["host_vectors"]) == 233
    # Exact current source/contract/packaged-byte binding is independently executed
    # by test_full_policy_derives_twice_and_checks_packaged_bytes. These authored
    # vectors remain expectations; matching current projection is checked below.
    records = index["policy_cases"] + index["host_vectors"]
    assert len({case["id"] for case in records}) == len(records)
    return index


@pytest.fixture(scope="module")
def host_vectors(semantic_vectors):
    """These checks validate host expectations, not executed host transitions."""
    records = semantic_vectors["host_vectors"]
    assert records
    return {case["id"]: case for case in records}


def vector(vectors, identifier):
    assert identifier in vectors, f"Missing distinct authored frozen vector: {identifier}"
    record = vectors[identifier]
    assert record["input"] and record["expect"] and record["trace"]
    return record["input"], record["expect"]


def test_host_registry_readiness_reuse_failure_and_incomplete_selection(host_vectors):
    """FR-001–007; AC-001/003; PX05/T01–T05."""
    inputs, outcome = vector(host_vectors, "registry.selected-reuse.unselected-enhanced")
    assert inputs["selected_tiers"] == ["native", "companion"]
    assert [
        (step["tier"], step["observation"], step["reuse"])
        for step in inputs["registry_steps"]
    ] == [
        ("native", "probe-passed", "verified-existing"),
        ("companion", "probe-passed", "verified-existing"),
        ("enhanced", "not-requested", "not-requested"),
    ]
    assert [outcome[tier] for tier in ("native", "companion", "enhanced")] == [
        "ready", "ready", "not-requested",
    ]
    assert outcome["selected_complete"] is True and outcome["effects"] == []
    for identifier, native in [
        ("registry.failed-native.blocks-dependent", "blocked"),
        ("registry.incomplete-selected.no-success", "ready"),
    ]:
        inputs, outcome = vector(host_vectors, identifier)
        assert inputs["registry_steps"][1]["observation"] != "probe-passed"
        assert [outcome[tier] for tier in ("native", "companion", "enhanced")] == [
            native, "blocked", "not-requested",
        ]
        assert outcome["selected_complete"] is False
        assert outcome["aggregate"] == "blocked" and outcome["effects"] == []


@pytest.mark.parametrize("tier", ["native", "companion", "enhanced"])
def test_host_registry_unselected_is_public_only_and_resume_requires_new_plan(host_vectors, tier):
    inputs, outcome = vector(host_vectors, f"registry.independent-selection.{tier}")
    assert inputs["selected_tiers"] == [tier]
    assert {
        name: outcome[name] for name in ("native", "companion", "enhanced")
    } == {
        name: "ready" if name == tier else "not-requested"
        for name in ("native", "companion", "enhanced")
    }
    assert outcome["effects"] == [] and outcome["canonical_readiness_domain_extended"] is False
    inputs, outcome = vector(host_vectors, "registry.resume.fresh-plan-not-restored-grant")
    assert uuid.UUID(inputs["new_plan_id"]) != uuid.UUID(inputs["old_plan_id"])
    assert inputs["retained_history"] and inputs["persisted_grant"] is None
    assert inputs["fresh_probes"] == "required" and inputs["fresh_consent"] == "absent"
    for field in ("reprobe_required", "replan_required", "history_retained", "fresh_consent_required"):
        assert outcome[field] is True
    assert outcome["old_plan_reusable"] is False and outcome["effects"] == []


def test_host_restore_binding_retains_exact_namespace_and_six_field_occurrence(host_vectors):
    """FR-007/040/044; LA01–LA06: no scalar grant or same-kind substitution."""
    inputs, outcome = vector(host_vectors, "lifecycle.restore.exact-binding")
    binding = inputs["plan_binding"]
    assert binding == inputs["current_binding"]
    assert binding["schema"] == "1.0" and binding["kind"] == "restore"
    assert uuid.UUID(binding["plan_id"]) == uuid.UUID(binding["lifecycle_id"])
    assert binding["expected_pointer"]["kind"] == "present"
    effects = binding["effects"]
    assert len(effects) == 1
    assert set(effects[0]) == {
        "occurrence_id", "ordinal", "step_id", "resource_id", "kind", "arguments_digest",
    }
    assert effects[0]["ordinal"] == 0 and effects[0]["kind"] == "restore-active-pointer"
    assert len(bytes.fromhex(effects[0]["arguments_digest"])) == 32
    assert inputs["private_host_fixture"]["ordered_effects"] == effects
    assert inputs["private_host_fixture"]["already_consumed_occurrences"] == []
    assert outcome["admitted"] is True and outcome["next_phase"] == "Admitted"
    assert outcome["effect_occurrences"] == effects and outcome["device_effects"] == []
    assert outcome["private_receipt_persisted"] is False
    assert outcome["original_deadline_extended"] is False
    for path in (
        "kind", "plan_id", "plan_digest", "root.ownership_manifest_digest",
        "generation.content_digest", "expected_pointer.pointer_digest",
        "expected_pointer.revision", "policy.bundle_digest",
        "registry_digest", "qualification_digest",
    ):
        changed_input, rejected = vector(host_vectors, "lifecycle.restore.reject.current_binding." + path)
        old, new = inputs["current_binding"], changed_input["current_binding"]
        for field in path.split("."):
            old, new = old[field], new[field]
        assert old != new, f"Rejection does not actually vary {path}"
        assert rejected["admitted"] is False and rejected["effects"] == []
        assert rejected["state_unchanged"] is True and rejected["selected_unchanged"] is True


@pytest.mark.parametrize("category", [
    "elevation", "wsl-change", "vm-change", "reboot", "runtime-install", "security-change",
])
def test_host_consequential_categories_bind_each_exact_receipt_and_reject_defects(host_vectors, category):
    inputs, outcome = vector(host_vectors, f"consequential.{category}.exact")
    binding = inputs["plan_binding"]
    requirement, = binding["required_consequential"]
    grant, = inputs["private_host_fixture"]["consequential_receipts"]
    assert requirement["category"] == grant["category"] == category
    assert requirement["occurrence_ids"] == grant["occurrence_ids"] == [
        effect["occurrence_id"] for effect in binding["effects"]
    ]
    for field in (
        "kind", "plan_id", "plan_digest", "root", "generation",
        "expected_pointer", "policy", "registry_digest", "qualification_digest",
    ):
        assert grant[field] == binding[field]
    assert grant["origin"] == "separate-trusted-prompt"
    assert grant["remaining_original_deadline_ms"] > 0 and outcome["admitted"] is True
    for defect in ("missing", "excess", "expired", "wrong-kind", "wrong-occurrence"):
        bad, rejected = vector(host_vectors, f"consequential.{category}.{defect}")
        receipts = bad["private_host_fixture"]["consequential_receipts"]
        if defect == "missing":
            assert receipts == []
        elif defect == "excess":
            assert len(receipts) == 2 and receipts[1]["category"] != category
        elif defect == "expired":
            assert receipts[0]["remaining_original_deadline_ms"] == 0
        elif defect == "wrong-kind":
            assert receipts[0]["kind"] != binding["kind"]
        else:
            assert receipts[0]["occurrence_ids"] != requirement["occurrence_ids"]
        assert rejected["admitted"] is False and rejected["effects"] == []
        assert rejected["state_unchanged"] is True and rejected["selected_unchanged"] is True


def test_host_repeated_kind_occurrences_use_full_ordered_identity_and_namespace(host_vectors):
    """LA01/LA02/LA04/LA06: same action strings do not collapse two occurrences."""
    first, first_result = vector(host_vectors, "lifecycle.uninstall.repeated-kind.first")
    second, second_result = vector(host_vectors, "lifecycle.uninstall.repeated-kind.second")
    binding = first["plan_binding"]
    effects = binding["effects"]
    assert binding["kind"] == "uninstall" and binding["plan_id"] == binding["lifecycle_id"]
    assert len(effects) == 2 and effects[0]["kind"] == effects[1]["kind"] == "dependency-uninstall"
    assert [effect["ordinal"] for effect in effects] == [0, 1]
    assert len({effect["occurrence_id"] for effect in effects}) == 2
    for effect in effects:
        assert set(effect) == {
            "occurrence_id", "ordinal", "step_id", "resource_id", "kind", "arguments_digest",
        }
    assert first["requested_occurrence"] == effects[0]
    assert first["private_host_fixture"]["already_consumed_occurrences"] == []
    assert first_result["effects"] == [effects[0]]
    assert first_result["second_occurrence_reserved_early"] is False
    assert second["plan_binding"] == binding
    assert second["private_host_fixture"]["already_consumed_occurrences"] == [
        effects[0]["occurrence_id"]
    ]
    assert second["requested_occurrence"] == effects[1]
    assert second["event"]["expected_revision"] == second["private_host_fixture"]["checkpoint_revision"]
    assert second_result["effects"] == [effects[1]] and second_result["first_occurrence_reissued"] is False
    for defect in ("duplicate", "skipped", "reordered", "wrong-arguments", "noncontiguous"):
        inputs, rejected = vector(host_vectors, f"lifecycle.uninstall.repeated-kind.reject-{defect}")
        if defect == "duplicate":
            assert inputs["requested_occurrence"]["occurrence_id"] in (
                inputs["private_host_fixture"]["already_consumed_occurrences"]
            )
        elif defect == "skipped":
            assert inputs["requested_occurrence"] == effects[1]
            assert inputs["private_host_fixture"]["already_consumed_occurrences"] == []
        elif defect == "reordered":
            assert inputs["private_host_fixture"]["ordered_effects"] == list(reversed(effects))
            assert inputs["plan_binding"]["effects"] == effects
        elif defect == "wrong-arguments":
            assert inputs["requested_occurrence"]["occurrence_id"] == effects[0]["occurrence_id"]
            assert inputs["requested_occurrence"]["arguments_digest"] != effects[0]["arguments_digest"]
        else:
            assert [effect["ordinal"] for effect in inputs["plan_binding"]["effects"]] != [0, 1]
        assert rejected["admitted"] is False and rejected["effects"] == []
        assert rejected["state_unchanged"] is True and rejected["selected_unchanged"] is True
    for kind in ("install", "uninstall"):
        inputs, rejected = vector(host_vectors, f"lifecycle.namespace.same-event.reject-{kind}")
        assert inputs["event"]["payload"]["lifecycle_kind"] == "restore"
        assert inputs["private_host_fixture"]["kind"] == kind
        assert inputs["private_host_fixture"]["same_event_bytes_as_restore"] is True
        assert rejected["admitted"] is False and rejected["effects"] == []


@pytest.mark.parametrize("dimension", ["source", "context", "schema", "controller", "route", "remaining_ms"])
def test_host_source_cache_each_identity_mismatch_projects_rejection(host_vectors, dimension):
    """FR-016–019/033; AC-004/005; PX09/T11/T12/T21."""
    inputs, outcome = vector(host_vectors, f"source-cache.reject.{dimension}")
    assert inputs["source"]["valid"] is True
    assert inputs["cache"][dimension] != inputs["expected"][dimension]
    assert {
        key for key in inputs["expected"] if inputs["expected"][key] != inputs["cache"][key]
    } == {dimension}
    assert outcome["projected_cache_binding_valid"] is False
    assert outcome["cache_used"] is False and outcome["effects"] == []
    assert outcome["source_unchanged"] is True and outcome["result"] == "blocked"
    for label in ("malformed", "changed"):
        invalid, rejected = vector(host_vectors, f"source-cache.source-{label}")
        if label == "malformed":
            assert invalid["source"]["valid"] is False
        else:
            assert invalid["source"]["digest"] != invalid["expected"]["source"]
        assert rejected["source_validation_precedes_cache"] is True
        assert rejected["cache_used"] is False and rejected["result"] == "blocked"


@pytest.mark.parametrize("conflict", ["duplicate-hostname", "duplicate-address"])
def test_host_merge_proposals_preserve_originals_and_require_output_consent(host_vectors, conflict):
    inputs, outcome = vector(host_vectors, f"merge.{conflict}")
    original, = inputs["originals"]
    discovered, = inputs["discovered"]
    field = "hostname" if conflict == "duplicate-hostname" else "address"
    other = "address" if field == "hostname" else "hostname"
    assert original[field] == discovered[field] and original[other] != discovered[other]
    assert outcome["originals_after"] == inputs["originals"]
    assert outcome["overwrite"] is False and outcome["conflicts"] == [conflict]
    assert outcome["effects"] == []
    inputs, outcome = vector(host_vectors, "merge.preview-save.same-proposal")
    assert outcome["proposal_in_both_modes"] == inputs["originals"] + inputs["discovered"]
    assert inputs["preview_consent"] is None and inputs["save_consent"] is None
    assert outcome["source_unchanged_before_output_consent"] is True
    assert outcome["save_requires_fresh_output_consent"] is True and outcome["effects"] == []


@pytest.mark.parametrize("native_outcome", ["locked", "missing", "wrong-password"])
def test_host_credential_outcomes_remain_distinct_safe_and_task_target_scoped(host_vectors, native_outcome):
    """FR-020–022/033; AC-006/011; PX04/PX09/T13/T14/T21."""
    inputs, outcome = vector(host_vectors, f"credential.native-outcome.{native_outcome}")
    assert inputs["native_vault_outcome"] == outcome["safe_outcome_category"] == native_outcome
    assert inputs["task"] == "observe-config" and inputs["target_id"] == "router-A"
    assert inputs["requested_fields"] == ["username", "password"]
    assert outcome["projected_channel_qualified"] is False
    assert outcome["credential_values_exposed"] is False
    assert outcome["fallback"] is None and outcome["effects"] == []


def test_host_credential_precedence_matches_native_environment_device_group_default(host_vectors):
    """Native vault.py:266–303 is credited; companion expectations must not contradict it."""
    inputs, outcome = vector(host_vectors, "credential.native-precedence.task-target-scope")
    precedence = inputs["native_precedence"]
    assert len(precedence) == 4, "Native order is environment/device/first matching group/default"
    assert precedence[0] in ("environment", "environment-variables")
    assert precedence[1] in ("device", "device-explicit", "device-vault")
    assert precedence[2] in ("first-matching-group", "first-group")
    assert precedence[3] in ("default", "default-vault")
    assert outcome["chosen_source_category"] == next(
        source for source in precedence if source in inputs["available_sources"]
    )
    assert outcome["resolved_target_id"] == inputs["target_id"]
    assert outcome["resolved_fields"] == inputs["requested_fields"]
    assert outcome["unrequested_fields_resolved"] == []
    assert outcome["credential_values_exposed"] is False


@pytest.mark.parametrize("defect", ["expiry", "route-substitution"])
def test_host_credential_channel_expiry_is_not_lifecycle_expiry_or_route_fallback(host_vectors, defect):
    inputs, outcome = vector(host_vectors, f"credential.channel.{defect}")
    assert inputs["lifecycle_consent_remaining_ms"] > 0
    if defect == "expiry":
        assert inputs["channel_remaining_ms"] == 0
        assert inputs["channel_route"] == inputs["expected_route"]
    else:
        assert inputs["channel_remaining_ms"] > 0
        assert inputs["channel_route"] != inputs["expected_route"]
    assert outcome["admitted"] is False and outcome["effects"] == []
    assert outcome["fallback"] is None and outcome["credential_values_exposed"] is False


def test_host_cancel_recovery_is_prior_authorized_continuation_not_new_admission(host_vectors):
    """FR-015/025/026/036; AC-008/011; PX06/PX08/T10/T16/T17/T23/T30."""
    inputs, outcome = vector(host_vectors, "recovery.pre-authorized-issued-continuation")
    prior = inputs["original_session"]
    assert inputs["control"] == "cancelled" and inputs["issued_mutation"]
    assert prior["recovery_authorized_before_cancel"] is True
    assert prior["remaining_original_deadline_ms"] > 0 and prior["private_session_ref"]
    assert inputs["requested_recovery"] == prior["recovery_scope"]
    assert outcome["already_authorized_recovery_only"] == prior["recovery_scope"]
    assert outcome["new_apply_admission"] is False and outcome["new_rollback_admission"] is False
    assert outcome["deadline_extended"] is False
    for defect in ("not-pre-authorized", "expired", "wrong-target"):
        bad, rejected = vector(host_vectors, f"recovery.continuation.reject.{defect}")
        if defect == "not-pre-authorized":
            assert bad["original_session"]["recovery_authorized_before_cancel"] is False
        elif defect == "expired":
            assert bad["original_session"]["remaining_original_deadline_ms"] == 0
        else:
            assert bad["requested_recovery"] != bad["original_session"]["recovery_scope"]
        assert rejected["new_admission"] is False and rejected["recovery_dispatch"] == []
        assert rejected["remote_uncertainty_retained"] is True
    inputs, outcome = vector(host_vectors, "recovery.reject-generic-image-snapshot")
    assert inputs["issued_operation"] == "image-update"
    assert inputs["recovery_material"] == "generic-config-snapshot"
    assert inputs["vendor_image_recovery_qualified"] is False
    assert outcome["admitted"] is False and outcome["effects"] == []
    assert outcome["remote_uncertainty_retained"] is True


@pytest.mark.parametrize("issued", [False, True])
@pytest.mark.parametrize("cleanup", ["success", "failed"])
def test_host_teardown_preserves_primary_cleanup_uncertainty_and_selected_coverage(host_vectors, issued, cleanup):
    identifier = f"teardown.{'after-issued' if issued else 'before-issued'}.{cleanup}"
    inputs, outcome = vector(host_vectors, identifier)
    assert inputs["phase"] == "Cancelling" and inputs["issued_mutation"] is issued
    assert outcome["phase"] == ("Uncertain" if issued else "Cancelled")
    assert outcome["primary"] == inputs["primary"] == "cancelled"
    assert outcome["cleanup"] == inputs["cleanup"] == cleanup
    assert outcome["remote_uncertain"] is inputs["remote_uncertain"] is issued
    assert outcome["aggregate"] == (
        "failed" if issued or cleanup == "failed" else "cancelled"
    )
    assert outcome["selected_count"] == inputs["selected_count"] == 1
    assert outcome["new_effects"] == []


@pytest.mark.parametrize("case_id", ["verified-publish", "failed-publish", "integrity-failed"])
def test_host_output_descriptor_requires_successful_verified_publish(host_vectors, case_id):
    """FR-031/032/035/036; AC-012; PX09/PX10/T22/T23."""
    inputs, outcome = vector(host_vectors, f"output.{case_id}")
    assert inputs["rendered_in_memory"] is True and inputs["output_consent"] == "matching"
    published = inputs["publish_completed"] and inputs["integrity_verified"]
    assert outcome["descriptor_exposed"] is published
    assert outcome["aggregate"] == ("success" if published else "failed")
    assert outcome["remote_fetch"] is False


def test_host_output_pdf_unavailable_is_not_html_unavailable_or_format_substitution(host_vectors):
    for fmt in ("pdf", "html"):
        inputs, outcome = vector(host_vectors, f"output.requested-format.{fmt}")
        assert inputs["requested_format"] == fmt
        assert inputs["pdf_ready"] is False and inputs["html_ready"] is True
        assert outcome["render_intent"] is (fmt == "html")
        assert outcome["descriptor_exposed"] is False and outcome["format_substitution"] is False
        if fmt == "pdf":
            assert outcome["success"] is False
    inputs, outcome = vector(host_vectors, "output.source-failed-render-success")
    assert inputs["source_aggregate"] == "failed"
    assert inputs["render_completed"] is True and inputs["publish_integrity_verified"] is True
    assert outcome["aggregate"] == "failed" and outcome["source_failure_retained"] is True


@pytest.mark.parametrize("field", [
    "tuple", "tier", "assets", "registry", "policy", "reducer",
    "qualification", "phase_owner_evidence",
])
def test_host_qualification_each_actual_identity_dimension_has_distinct_rejection(host_vectors, field):
    """FR-037–045; AC-013/014/015; PX12/T24–T28/T31."""
    good, good_expectation = vector(host_vectors, "qualification.exact-identities")
    assert good["expected"] == good["observed"]
    assert good_expectation["identity_check"] == "match"
    assert good_expectation["platform_qualification_executed"] is False
    for defect in ("missing", "mismatched"):
        inputs, outcome = vector(host_vectors, f"qualification.reject.{field}.{defect}")
        assert inputs["candidate_verified_scalar"] is True and inputs["policy_current_scalar"] is True
        if defect == "missing":
            assert field not in inputs["observed"]
        else:
            assert inputs["expected"][field] != inputs["observed"][field]
        assert outcome["qualified"] is False and outcome["promoted"] is False
        assert outcome["effects"] == []
    inputs, outcome = vector(host_vectors, "qualification.reject.stale-tuple")
    assert inputs["evidence_remaining_ms"] == 0
    assert outcome["qualified"] is False and outcome["promoted"] is False
    assert outcome["effects"] == []


@pytest.mark.parametrize("kind", EVENT_KINDS)
def test_host_typed_event_common_and_specific_identity_is_internally_bound(host_vectors, kind):
    """FR-007/010/013–015/034–036/040/042/044; G07/PX01/PX02/PX06.

    Validate real authored metadata without claiming the historical producer
    projects it or that a private host adapter has enforced it.
    """
    inputs, outcome = vector(host_vectors, f"event.{kind}.complete")
    event, state = inputs["event"], inputs["state"]
    assert event["kind"] == kind and event["schema"] == "1.0"
    assert str(uuid.UUID(event["event_id"])) == event["event_id"].lower()
    assert ("operation_id" in event) != ("install_id" in event)
    identity = event.get("operation_id", event.get("install_id"))
    assert str(uuid.UUID(identity)) == identity.lower()
    assert type(event["expected_revision"]) is int
    assert event["expected_revision"] == state["revision"]
    binding = inputs["plan_binding"]
    assert event["plan_digest"] == binding["plan_digest"]
    assert event["context_digest"] == binding["context_digest"]
    binding_policy = (
        binding["policy"]["bundle_digest"] if "policy" in binding else binding["policy_digest"]
    )
    assert event["policy_digest"] == binding_policy
    for field in ("plan_digest", "context_digest", "policy_digest"):
        assert len(bytes.fromhex(event[field])) == 32
    payload = event["payload"]
    if kind == "OperationRequested":
        assert payload["plan_digest"] == event["plan_digest"]
        assert len(bytes.fromhex(payload["request_digest"])) == 32
        assert len(bytes.fromhex(payload["loaded_input_digest"])) == 32
        assert payload["mode"] in ("preview", "check") and outcome["preview_effects"] == []
    elif kind == "DependencyObserved":
        assert payload["context_digest"] == event["context_digest"]
        assert payload["probe_receipt"] and payload["dependency_id"]
        assert len(bytes.fromhex(payload["probe_digest"])) == 32
        assert payload["readiness"] in ("ready", "blocked", "unsupported")
    elif kind == "InstallConsented":
        assert payload["lifecycle_kind"] == binding["kind"]
        assert payload["plan_id"] == binding["plan_id"]
        assert payload["private_consent_reference"]
        assert outcome["private_values_checkpointed"] is False
    elif kind in ("Observed", "StepCompleted"):
        pending = inputs["pending_invocation"]
        assert payload["invocation_id"] == pending["invocation_id"]
        assert payload["target_id"] == event["target_id"] == pending["target_id"]
        assert payload["step_id"] == event["step_id"] == pending["step_id"]
        assert pending["completed"] is False
        if kind == "StepCompleted":
            assert payload["effect_id"] == pending["effect_id"]
            assert type(payload["remote_uncertain"]) is bool
            assert outcome["aggregate_before_all_selected_disposed"] is False
        else:
            assert payload["observation_ref"]
            assert len(bytes.fromhex(payload["observation_digest"])) == 32
            assert outcome["observation_grants_mutation"] is False
    elif kind == "ApplyConsented":
        assert payload["plan_digest"] == event["plan_digest"]
        assert payload["approved_effect_ids"] and payload["approved_recovery_ids"]
        assert set(payload["approved_effect_ids"]).isdisjoint(payload["approved_recovery_ids"])
    elif kind == "CandidateVerified":
        assert len(bytes.fromhex(payload["candidate_digest"])) == 32
        assert payload["registry_digest"] == binding["registry_digest"]
        assert payload["policy_digest"] == event["policy_digest"]
        assert payload["qualification_digest"] == binding["qualification_digest"]
        assert len(bytes.fromhex(payload["assets_digest"])) == 32
        assert payload["functional_evidence_ref"]
    elif kind == "Activated":
        assert payload["expected_pointer_digest"] == payload["current_pointer_digest"]
        assert payload["expected_pointer_digest"] == binding["expected_pointer"]["pointer_digest"]
        assert payload["new_pointer_digest"] != payload["current_pointer_digest"]
        assert payload["cas_receipt"] and outcome["pointer_transition_requires_actual_cas"] is True
    else:
        assert payload["accepted_host_receipt"] and payload["safe_reason"] == "cancelled"
        assert type(payload["revocation_revision"]) is int
        assert payload["revocation_revision"] >= state["revision"]
    assert outcome["accepted"] is True
    assert outcome["phase"] == {
        "OperationRequested": "Planned", "DependencyObserved": "Staging",
        "InstallConsented": "Admitted", "Observed": "Observing", "ApplyConsented": "Admitted",
        "StepCompleted": "Executing", "CandidateVerified": "Verified",
        "Activated": "Active", "Cancelled": "Cancelling",
    }[kind]


@pytest.mark.parametrize("kind", EVENT_KINDS)
def test_host_typed_event_missing_wrong_extra_digest_and_each_payload_field_reject(host_vectors, kind):
    good, _ = vector(host_vectors, f"event.{kind}.complete")
    for defect in ("missing", "wrong", "extra", "digest"):
        inputs, outcome = vector(host_vectors, f"event.{kind}.reject-{defect}")
        event = inputs["event"]
        if defect == "missing":
            assert "schema" not in event
        elif defect == "wrong":
            assert type(event["expected_revision"]) is not int
        elif defect == "extra":
            assert event["extra_permission"] is True
        else:
            assert event["plan_digest"] != inputs["plan_binding"]["plan_digest"]
        assert outcome["accepted"] is False and outcome["effects"] == []
        assert outcome["state_unchanged"] is True
        assert outcome["selected_dispositions_unchanged"] is True
    for field in good["event"]["payload"]:
        inputs, outcome = vector(host_vectors, f"event.{kind}.missing-payload.{field}")
        assert field not in inputs["event"]["payload"]
        assert outcome["accepted"] is False and outcome["effects"] == []
        assert outcome["state_unchanged"] is True
        assert outcome["selected_dispositions_unchanged"] is True


@pytest.mark.parametrize("defect", [
    "same-event-different-digest", "duplicate-occurrence", "skipped-occurrence",
    "reordered-occurrences", "wrong-arguments", "unexpected-invocation",
    "missing-invocation", "wrong-target", "wrong-step", "stale-pointer",
])
def test_host_occurrence_replay_rejections_represent_actual_identity_defects(host_vectors, defect):
    inputs, outcome = vector(host_vectors, f"occurrence.reject.{defect}")
    fault = inputs["occurrence_test"]
    if defect == "same-event-different-digest":
        assert fault["prior_event_digest"] != fault["incoming_event_digest"]
    elif defect == "duplicate-occurrence":
        assert fault["requested_occurrence"] in fault["reserved_occurrences"]
    elif defect == "skipped-occurrence":
        assert fault["requested_ordinal"] > fault["expected_ordinal"]
    elif defect == "reordered-occurrences":
        assert fault["requested_ids"] != fault["expected_ids"]
        assert sorted(fault["requested_ids"]) == sorted(fault["expected_ids"])
    elif defect == "wrong-arguments":
        assert fault["expected_arguments_digest"] == inputs["plan_binding"]["effects"][0]["arguments_digest"]
        assert fault["actual_arguments_digest"] != fault["expected_arguments_digest"]
    elif defect in ("unexpected-invocation", "missing-invocation"):
        assert fault["pending_invocation_id"] != fault["completion_invocation_id"]
    elif defect == "wrong-target":
        assert fault["pending_target"] != fault["completion_target"]
    elif defect == "wrong-step":
        assert fault["pending_step"] != fault["completion_step"]
    else:
        assert fault["expected_pointer_revision"] == inputs["plan_binding"]["expected_pointer"]["revision"]
        assert fault["current_pointer_revision"] != fault["expected_pointer_revision"]
    assert outcome["accepted"] is False and outcome["effects"] == []
    assert outcome["state_unchanged"] is True and outcome["selected_dispositions_unchanged"] is True
    inputs, outcome = vector(host_vectors, "occurrence.duplicate-identical-completion")
    assert inputs["prior_event_digest"] == inputs["incoming_event_digest"]
    assert inputs["already_completed_invocation"]
    assert outcome["idempotent"] is True and outcome["revision_unchanged"] is True
    assert outcome["effects"] == [] and outcome["new_dispositions"] == []


@pytest.mark.parametrize("defect", ["duplicate", "missing", "wrong-target", "wrong-step"])
def test_host_selected_identity_index_cannot_be_substituted_by_equal_scalar_totals(host_vectors, defect):
    """FR-010/011/012/036; AC-002/011/012; PX01/PX02/PX06/PX10/T08/T23."""
    good, outcome = vector(host_vectors, "selected.exact-identity-index")
    selected = [(item["target_id"], item["step_id"]) for item in good["selected"]]
    disposed = [(item["target_id"], item["step_id"]) for item in good["dispositions"]]
    assert len(set(selected)) == len(selected) == good["selected_count"]
    assert sorted(selected) == sorted(disposed)
    assert outcome["can_finalize"] is True and outcome["aggregate"] == "success"
    inputs, rejected = vector(host_vectors, f"selected.reject.{defect}")
    assert inputs["selected"] == good["selected"]
    actual = [(item["target_id"], item["step_id"]) for item in inputs["dispositions"]]
    assert sorted(actual) != sorted(selected)
    if defect in ("duplicate", "wrong-target", "wrong-step"):
        assert inputs["completed_count"] == inputs["selected_count"], "Keep equal-total negative control"
    assert rejected["can_finalize"] is False and rejected["success"] is False
    assert rejected["selected_unchanged"] is True and rejected["effects"] == []


def test_host_numeric_max_progression_competition_and_exhaustion_preserve_exact_revision(host_vectors):
    """FR-010/015/036/040/042; PX02/PX06/PX08/T23/T27/T30, not actual CAS execution."""
    inputs, outcome = vector(host_vectors, "numeric.max-minus-one.advance-once")
    assert inputs["revision"] == MAX_INT - 1
    assert outcome["revision"] == inputs["revision"] + 1 == MAX_INT
    assert outcome["accepted_completion_ids"] == inputs["completion_ids"]
    for field in ("wrap", "reset", "clamp"):
        assert outcome[field] is False
    inputs, outcome = vector(host_vectors, "numeric.max-minus-one.competing-completions")
    assert inputs["simultaneous_expected_revisions"] == [MAX_INT - 1, MAX_INT - 1]
    assert len(set(inputs["completion_ids"])) == 2
    assert outcome["revision"] == MAX_INT and outcome["maximum_accepted_completions"] == 1
    assert outcome["second_completion_changes_state"] is False and outcome["duplicate_dispatch"] is False
    inputs, outcome = vector(host_vectors, "numeric.max.reject-next-increment")
    assert inputs["revision"] == MAX_INT and inputs["required_increment"] == 1
    assert outcome["revision"] == MAX_INT and outcome["accepted"] is False
    assert outcome["effects"] == [] and outcome["pending_admissions_revoked"] is True
    assert outcome["checkpoint_unchanged"] is True
    for field in ("wrap", "reset", "clamp"):
        assert outcome[field] is False


@pytest.mark.parametrize("category", ["replayed-event", "restored-checkpoint"])
@pytest.mark.parametrize("invalid", [-1, MAX_INT + 1, MAX_INT + 2])
def test_host_numeric_invalid_replay_and_checkpoint_preserve_prior_state(host_vectors, category, invalid):
    inputs, outcome = vector(host_vectors, f"numeric.reject.{category}.{invalid}")
    assert inputs["input_category"] == category and inputs["revision"] == invalid
    assert not 0 <= invalid <= MAX_INT
    assert outcome["accepted"] is False and outcome["effects"] == []
    assert outcome["revision"] == inputs["current_revision"]
    assert outcome["checkpoint_unchanged"] is True


@pytest.mark.parametrize("clock", ["nan", "positive-infinity", "negative-infinity"])
def test_host_numeric_nonfinite_clock_and_overflow_never_extend_deadline(host_vectors, clock):
    inputs, outcome = vector(host_vectors, f"numeric.clock.reject.{clock}")
    value, = struct.unpack(">d", bytes.fromhex(inputs["clock_binary64_bits"]))
    assert not math.isfinite(value)
    assert outcome["accepted"] is False and outcome["effects"] == []
    assert outcome["deadline_extended"] is False and outcome["revision"] == inputs["revision"]
    inputs, outcome = vector(host_vectors, "numeric.clock.deadline-overflow")
    assert inputs["monotonic_ms"] + inputs["requested_duration_ms"] > MAX_INT
    assert outcome["accepted"] is False and outcome["deadline_created"] is False
    assert outcome["effects"] == []


def test_host_numeric_exhausted_cancel_and_telemetry_saturation_do_not_reauthorize(host_vectors):
    inputs, outcome = vector(host_vectors, "numeric.exhausted.cancel-and-issued-reconciliation")
    assert inputs["revision"] == outcome["revision"] == MAX_INT
    assert inputs["cancel_requested"] is True and inputs["already_issued"]
    assert outcome["new_dispatch"] == [] and outcome["pending_admissions_revoked"] is True
    assert outcome["issued_reconciliation_available"] is True
    assert outcome["remote_uncertain"] is inputs["remote_uncertain"] is True
    assert outcome["selected"] == inputs["selected"] and outcome["grant_renewed"] is False
    inputs, outcome = vector(host_vectors, "numeric.observational-saturation-no-policy-effect")
    assert inputs["exporter_count"] == MAX_INT and inputs["increment"] == 1
    assert outcome["exporter_count"] == MAX_INT and outcome["latch"] is True
    assert outcome["paired_failure_logs"] == 1
    assert outcome["reason"] == "numeric-telemetry-saturated" and outcome["monitoring"] == "Degraded"
    for field in ("policy_revision", "selected_count", "authorization_remaining_ms"):
        assert outcome[field] == inputs[field]
    assert outcome["exported_count_used_as_policy_input"] is False


def test_canonical_authored_semantic_cases_match_actual_projected_assets(semantic_vectors, packaged_corpus):
    """Only real emitted source/corpus matches can prove canonical projection."""
    bundle, corpus = packaged_corpus
    cases = {case["case_id"]: case for case in corpus}
    projected = {case["case_id"]: case for case in bundle["contracts"]}
    for authored in semantic_vectors["policy_cases"]:
        identifier = authored["canonical_case_id"]
        assert identifier in cases, f"Current authored case is absent from canonical assets: {authored['id']}"
        actual = cases[identifier]
        assert actual["input"] == projected[identifier]["input"] == authored["input"]
        assert actual["host_expectations"] == projected[identifier]["expect"] == (
            authored["target_expectations"]
        )
        assert actual["canonical"]["fired_actions"] == [
            action["name"] for action in authored["target_expectations"]["actions"]
        ]
        combined = actual["canonical"]["combined"]
        assert combined is not None, authored["id"]
        for field in ("decision", "actions", "violations"):
            assert combined[field] == authored["combined_expectations"][field], authored["id"]
