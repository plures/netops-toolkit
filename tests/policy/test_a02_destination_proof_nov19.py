"""Actual owned destination admission proofs; not protected-backend qualification."""

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import AuthorizationError
from tests.policy.test_lifecycle_execution import DATA, environment, issue
from tests.policy.test_lifecycle_execution import policy as policy


def test_reviewed_destination_unchanged_executes_owned_stage(tmp_path, policy):
    """A valid reviewed destination reaches the real stage handler and receipt."""
    env = environment(tmp_path, policy)
    plan, binding, port, state, _, _, _, _, executor = env
    grant = issue(env, policy)
    snapshot = state.snapshot_lifecycle(binding)
    assert snapshot.binding == binding
    assert snapshot.evidence is not None
    assert port.writes == []
    result = executor.execute(plan, grant)
    assert result.completed
    assert not result.pending
    assert not result.uncertain
    assert len(result.receipts) == 1
    assert result.receipts[0].kind == "dependency-stage"
    assert state.artifact("destination") == DATA
    assert port.writes
    assert set(executor._pending) == executor._completed
    assert all(
        state.inspect_receipt(effect)["phase"] == "observed"
        for effect in executor._pending.values()
    )
    assert not tuple(tmp_path.glob("*.pending"))


def test_reviewed_destination_manifest_drift_blocks_owned_stage(tmp_path, policy):
    """A well-formed same-owner destination cannot drift after reviewed consent."""
    env = environment(tmp_path, policy)
    plan, binding, port, state, _, _, _, _, executor = env
    grant = issue(env, policy)
    assert state.snapshot_lifecycle(binding).evidence is not None
    original = port.read("destination")
    reviewed_digest = binding.content["steps"][0]["destination"]["manifest_digest"]
    assert c.digest(original.payload["manifest"]) == reviewed_digest
    payload = dict(original.payload.items())
    payload["manifest"] = c.public_object({"member": "different-inert-bytes"})
    changed = port.seed(
        "destination", payload, revision=original.revision, owner=original.ownership_token,
    )
    assert changed.resource_id == original.resource_id
    assert changed.policy_identity == original.policy_identity
    assert changed.revision == original.revision
    assert changed.ownership_token == original.ownership_token
    assert changed.payload["reserved"] is True
    assert c.digest(changed.payload["manifest"]) != reviewed_digest
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    snapshot = state.snapshot_lifecycle(binding)
    assert snapshot.binding == binding
    with pytest.raises(AuthorizationError) as caught:
        executor.execute(plan, grant)
    assert str(caught.value) == "consent-stale"
    assert caught.value.reason == "consent-stale"
    assert caught.value.cause == "consent-stale"
    assert snapshot.evidence is None
    assert port.writes == []
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before
    assert not executor._pending
    assert not executor._receipts
    assert not tuple(tmp_path.glob("*.pending"))
