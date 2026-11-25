"""Retained locks are closed facts, never restored live source or effect authority."""

import copy
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import AuthorizationError
from netops.dependencies._family_codec import _decode_lock
from netops.dependencies._family_ledger import _OwnedFamilyLedger
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_family_provider_author import admitted
from tests.test_nov21_provider_stage_independent import release, resolve, resolver


def retained():
    helper = release("retained-helper")
    root = release("retained-root", requires=(helper.requirement,))
    engine, _ = resolver((helper, root))
    result = resolve(engine, (root.requirement,))
    assert result.lock is not None
    return result.lock


def test_ac011_exact_retained_lock_roundtrip_preserves_every_dependency_and_observation():
    lock = retained()
    decoded = _decode_lock(c.wire(lock))
    assert type(decoded) is type(lock) and decoded == lock and decoded is not lock
    assert decoded.digest == lock.digest
    assert [value.requirement.name for value in decoded.releases] == [
        "retained-helper", "retained-root",
    ]
    assert decoded.observations == lock.observations
    assert all(value is not original for value, original in zip(decoded.releases, lock.releases))


def test_ac001_retained_requested_extra_preserves_its_complete_transitive_lock():
    helper = release("retained-extra-helper")
    root = replace(release("retained-extra-root"),
                   extra_requires=(("render", (helper.requirement,)),))
    engine, _ = resolver((helper, root))
    result = resolve(engine, (replace(root.requirement, extras=("render",)),))
    assert result.lock is not None
    decoded = _decode_lock(c.wire(result.lock))
    assert decoded == result.lock
    assert decoded.selected_extras == ((root.requirement.key, ("render",)),)
    assert decoded.releases[-1].extra_requires == (("render", (helper.requirement,)),)


@pytest.mark.parametrize("where", [
    "lock", "root", "target", "release", "snapshot", "member", "asset",
])
def test_ac003_retained_fact_decoder_rejects_nested_actor_or_permission_fields(where):
    value = copy.deepcopy(c.wire(retained()))
    selected = {
        "lock": value,
        "root": value["roots"][0],
        "target": value["targets"][0],
        "release": value["releases"][0],
        "snapshot": value["observations"][0],
        "member": value["releases"][0]["members"][0],
        "asset": value["releases"][0]["artifact"],
    }[where]
    selected["trusted_actor"] = {"install_authorized": True}
    with pytest.raises(c.ContractError):
        _decode_lock(value)


@pytest.mark.parametrize("damage", ["omitted", "reordered", "wrong-context", "wrong-digest"])
def test_ac001_retained_lock_revalidates_exact_closure_not_only_json_shape(damage):
    value = copy.deepcopy(c.wire(retained()))
    if damage == "omitted":
        value["releases"] = value["releases"][1:]
    elif damage == "reordered":
        value["releases"].reverse()
    elif damage == "wrong-context":
        value["targets"][0]["context_digest"] = "e" * 64
    else:
        value["observations"][0]["metadata_digest"] = "not-a-digest"
    with pytest.raises(c.ContractError):
        _decode_lock(value)


@pytest.mark.parametrize("damage", ["unknown-field", "extra-pair", "over-limit", "not-sequence"])
def test_ac001_retained_extra_projection_is_closed_and_bounded(damage):
    value = copy.deepcopy(c.wire(retained()))
    if damage == "unknown-field":
        value["releases"][0]["extra_requires"] = [["render", [], "run-command"]]
    elif damage == "extra-pair":
        value["selected_extras"] = [[["native", "wheel", "retained-root"], [], "unbound"]]
    elif damage == "over-limit":
        value["roots"] = value["roots"] * 257
    else:
        value["targets"] = {"context": "native"}
    with pytest.raises(c.ContractError):
        _decode_lock(value)


def test_ac003_decoded_lock_cannot_reconstruct_a_consumed_live_effect_permit(tmp_path, policy):
    values = admitted(tmp_path, policy, owned_ledger=True)
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = values
    decoded = _decode_lock(c.wire(lock))
    assert decoded == lock
    with pytest.raises((c.ContractError, AuthorizationError)):
        driver.execute(decoded, item, operation, broker, None, effect, cancel)
    assert not host.calls
    assert ledger.read(effect.lifecycle.root, operation.resource_id) == (0, None, None)
    assert driver.execute(lock, item, operation, broker, permit, effect, cancel).result.verified


def test_ac011_registered_retained_lock_pin_does_not_adopt_unknown_root_or_issue_authority(
    tmp_path, policy,
):
    values = admitted(tmp_path, policy, owned_ledger=True)
    driver, lock, _, operation, _, _, effect, _, host, ledger, clock = values
    port = ledger._state
    facts = port.read(effect.lifecycle.root.resource_id)
    manifest = dict(facts.payload["root_manifest"])
    manifest.pop("family_lock_digest")
    manifest["family_locks"] = (("generation", c.wire(lock)),)
    manifest = c.public_object(manifest)
    pinned = replace(effect.lifecycle.root, manifest_digest=c.digest(manifest))
    port.seed(facts.resource_id, {**dict(facts.payload), "root_manifest": manifest},
              revision=facts.revision)
    record = port.read(ledger._resource_id)
    port.seed(record.resource_id, {**dict(record.payload), "root": c.wire(pinned)},
              revision=record.revision)
    known = _OwnedFamilyLedger(
        port, pinned, ledger._resource_id, ledger._owner, ledger._policy,
        lock, ledger._lifecycle, clock,
    )
    assert known.read(pinned, operation.resource_id) == (0, None, None)
    before = port.read(ledger._resource_id)
    with pytest.raises(AuthorizationError):
        known.read(replace(pinned, resource_id="unknown-user-root"), operation.resource_id)
    assert port.read(ledger._resource_id) == before and not host.calls
    assert driver._ledger is ledger


@pytest.mark.parametrize("revision", [1, 2])
def test_ac011_committed_ledger_write_with_lost_ack_retains_primary_and_factual_state(
    tmp_path, policy, monkeypatch, revision,
):
    values = admitted(tmp_path, policy, owned_ledger=True)
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = values
    port = ledger._state
    original = port.compare_replace
    primary = OSError("SOURCE-only lost persistence acknowledgement")

    def committed_then_interrupted(resource_id, expected_revision, following):
        actual = original(resource_id, expected_revision, following)
        if resource_id == ledger._resource_id and following.revision == revision:
            raise primary
        return actual

    monkeypatch.setattr(port, "compare_replace", committed_then_interrupted)
    with pytest.raises(OSError) as captured:
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert captured.value is primary
    actual_revision, resource, pending = ledger.read(effect.lifecycle.root, operation.resource_id)
    assert actual_revision == revision and len(host.calls) == revision - 1
    if revision == 1:
        assert resource is None and pending == operation
    else:
        assert resource is not None and resource.owned and pending is None
    before = port.read(ledger._resource_id)
    with pytest.raises(AuthorizationError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert port.read(ledger._resource_id) == before and len(host.calls) == revision - 1
