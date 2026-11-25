"""Original T04/AC-011 exact cancellation and detached prohibited-mutation proofs."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.artifacts import ArtifactError
from tests.nov21_cancel_oracle import assert_exact_cancel, capture_state, observe_cas
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel
from tests.test_nov20_successor_public_lifecycle import retained_source_case

MUTATIONS = (
    "operative-pointer-change", "admission-change", "root-generation-change",
    "pin-change", "original-file-change", "original-file-removal",
    "third-file-even-history-looking", "third-CAS-even-history-looking",
    "effect-dispatch", "history-head-digest-change", "unallowlisted-history-head",
    "event-ownership-change", "event-unknown-authority-field",
    "false-success", "false-changed-outcome", "duplicate-history-CAS",
    "event-generation-change", "event-policy-change", "false-readiness",
)


@pytest.fixture(scope="module")
def cancellation_observation(tmp_path_factory, policy):
    path = tmp_path_factory.mktemp("exact-cancel")
    service, host, port, effects, consent, context, target, _, runs, _ = (
        retained_source_case(path, policy)
    )
    (path / "native-user-vault-inventory-backups").write_bytes(b"unchanged user sentinel")
    plan = service.plan_restore(target.generation_id, context)
    grant = consent.review(plan, 10.0, 30.0)
    cancel = Cancel()
    cancel.value = True
    before = capture_state(path, host, port, runs, effects)
    with observe_cas(port) as calls:
        outcome = service.restore(plan, grant, cancel)
    after = capture_state(path, host, port, runs, effects)
    assert_exact_cancel(before, after, calls, plan, outcome)
    return before, after, calls, plan, outcome


def replace_record(after, calls, index, mutate):
    resource, expected, content = calls[index]
    record = json.loads(content)
    mutate(record)
    content = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    calls[index] = resource, expected, content
    after["files"][hashlib.sha256(resource.encode()).hexdigest() + ".json"] = content


@pytest.mark.parametrize("mutation", MUTATIONS)
def test_exact_cancel_baseline_rejects_prohibited_mutation_then_baseline_passes(
    cancellation_observation, mutation,
):
    before, actual, actual_calls, plan, outcome = cancellation_observation
    assert_exact_cancel(before, actual, actual_calls, plan, outcome)
    after, calls = copy.deepcopy(actual), copy.deepcopy(actual_calls)
    if mutation == "operative-pointer-change":
        after["pointer"]["revision"] += 1
    elif mutation == "admission-change":
        raw = json.loads(after["control"])
        raw["payload"]["admission_enabled"] = False
        after["control"] = json.dumps(raw).encode()
    elif mutation == "root-generation-change":
        raw = json.loads(after["root"])
        raw["generation"] += 1
        after["root"] = json.dumps(raw).encode()
    elif mutation == "pin-change":
        after["pins"][0]["holders"].append(str(uuid4()))
    elif mutation == "original-file-change":
        after["files"]["native-user-vault-inventory-backups"] = b"changed"
    elif mutation == "original-file-removal":
        del after["files"]["native-user-vault-inventory-backups"]
    elif mutation == "third-file-even-history-looking":
        after["files"][hashlib.sha256(b"dependency-outcome-event-third").hexdigest()
                       + ".json"] = calls[0][2]
    elif mutation in ("third-CAS-even-history-looking", "duplicate-history-CAS"):
        resource = ("dependency-outcome-event-" + str(uuid4()) if mutation.startswith("third")
                    else calls[0][0])
        calls.append((resource, 0, calls[0][2]))
        after["writes"].append((resource, 0, 0))
    elif mutation == "effect-dispatch":
        after["effects"].append(("verify", plan.generation.generation_id))
    elif mutation == "history-head-digest-change":
        replace_record(after, calls, 1, lambda row: row["payload"].update(latest_digest="0" * 64))
    elif mutation == "unallowlisted-history-head":
        resource, expected, content = calls[1]
        calls[1] = resource + "-other", expected, content
    elif mutation == "event-ownership-change":
        replace_record(after, calls, 0, lambda row: row.update(ownership_token="2" * 64))
    elif mutation == "event-generation-change":
        replace_record(after, calls, 0, lambda row: row.update(generation=1))
    elif mutation == "event-policy-change":
        replace_record(after, calls, 0, lambda row: row["policy_identity"].update(source_sha256="2" * 64))
    elif mutation == "event-unknown-authority-field":
        replace_record(after, calls, 0, lambda row: row["payload"].update(authority="forged"))
    elif mutation in ("false-success", "false-changed-outcome", "false-readiness"):
        outcome = (replace(outcome, status=c.OutcomeStatus.SUCCEEDED)
                   if mutation == "false-success" else
                   replace(outcome, readiness=replace(outcome.readiness, native="ready"))
                   if mutation == "false-readiness" else
                   replace(outcome, steps=(replace(outcome.steps[0], changed=True),)))
        replace_record(after, calls, 0, lambda row: row["payload"].update(outcome=c.wire(outcome)))
        digest = c.digest(c.public_object(json.loads(calls[0][2])["payload"]))
        replace_record(after, calls, 1, lambda row: row["payload"].update(latest_digest=digest))
    else:
        raise AssertionError("unknown oracle mutation")
    with pytest.raises((AssertionError, c.ContractError, ArtifactError)):
        assert_exact_cancel(before, after, calls, plan, outcome)
    assert_exact_cancel(before, actual, actual_calls, plan, cancellation_observation[-1])
