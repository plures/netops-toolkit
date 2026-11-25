"""AC-011 bounded nonoperative history retry; original failed assertion retained."""

from __future__ import annotations

from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel
from tests.test_nov20_successor_public_lifecycle import retained_source_case


def files(root):
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*") if path.is_file()
    }


def exact_history(port, root, before, writes, result):
    """Check exact allowlist, closed payloads and every original file byte."""
    delta = port.writes[writes:]
    assert len(delta) == 2
    event, head = delta
    prefix = "dependency-outcome-event-"
    assert event[0].startswith(prefix)
    c.uuid_text(event[0][len(prefix):])
    assert head[0] == "dependency-outcome-" + result.installation_id
    assert event[1:] == head[1:] == (0, 0)
    after = files(root)
    expected_files = {
        port.filename(event[0]).relative_to(root).as_posix(),
        port.filename(head[0]).relative_to(root).as_posix(),
    }
    assert after.keys() - before.keys() == expected_files
    assert before.keys() <= after.keys()
    assert all(after[name] == content for name, content in before.items())
    event_record, head_record = port.read(event[0]), port.read(head[0])
    assert event_record.kind == head_record.kind == "checkpoint"
    assert event_record.policy_identity == head_record.policy_identity == port.identity
    assert event_record.ownership_token == head_record.ownership_token
    assert set(event_record.payload) == {"schema", "outcome", "previous", "previous_digest"}
    assert set(head_record.payload) == {"schema", "latest", "latest_digest"}
    assert event_record.payload["schema"] == "i02-outcome-event-v1"
    assert event_record.payload["previous"] is event_record.payload["previous_digest"] is None
    assert event_record.payload["outcome"] == c.public_object(c.wire(result))
    assert c.canonical_bytes(head_record.payload).decode() == (
        '{"latest":"' + event[0] + '","latest_digest":"' + c.digest(event_record.payload)
        + '","schema":"i02-outcome-head-v1"}'
    )
    assert len(event_record.to_bytes()) < 1_048_576
    assert len(head_record.to_bytes()) < 1_048_576
    assert b"independent-private-secret-do-not-publish" not in event_record.to_bytes()
    assert b"independent-private-secret-do-not-publish" not in head_record.to_bytes()


def cancelled_case(tmp_path, policy):
    service, host, port, effects, consent, context, target, current, runs, pointer = (
        retained_source_case(tmp_path, policy)
    )
    user_file = tmp_path / "user-vault-inventory-backups"
    user_file.write_bytes(b"independent-private-secret-do-not-publish")
    plan = service.plan_restore(target.generation_id, context)
    grant = consent.review(plan, 10.0, 30.0)
    return service, host, port, effects, plan, grant, current, runs, pointer


def test_t04_pre_entry_cancel_writes_only_exact_bounded_nonoperative_history(
    tmp_path, policy, monkeypatch,
):
    service, host, port, effects, plan, grant, current, runs, pointer = cancelled_case(
        tmp_path, policy,
    )
    before, writes = files(tmp_path), len(port.writes)
    original_root, original_control = port.read("managed-root"), port.read("managed-control")
    original_pins = runs.pins()

    def forbidden(*args):
        pytest.fail("Pre-entry cancellation cannot stop/drain/start owned runs")

    monkeypatch.setattr(runs, "stop_admission", forbidden)
    monkeypatch.setattr(runs, "drain", forbidden)
    monkeypatch.setattr(runs, "start_admission", forbidden)
    cancel = Cancel()
    cancel.value = True
    result = service.restore(plan, grant, cancel)
    assert result.status == c.OutcomeStatus.CANCELLED
    assert result.active_generation_id == current.generation_id
    assert result.pointer_revision == pointer.revision
    assert result.errors and all(error.reason == c.ReasonCode.CANCELLED for error in result.errors)
    assert not result.cleanup_errors
    assert all(step.status != c.OutcomeStatus.SUCCEEDED for step in result.steps)
    assert host.pointer() == pointer
    assert port.read("managed-root") == original_root
    assert port.read("managed-control") == original_control
    assert runs.pins() == original_pins
    assert effects.calls == []
    exact_history(port, tmp_path, before, writes, result)
    with pytest.raises(c.ContractError):
        c.canonical_bytes(grant)
    replayed = service.restore(plan, grant, Cancel())
    assert replayed.status == c.OutcomeStatus.BLOCKED
    assert replayed.errors and replayed.errors[0].reason == c.ReasonCode.CONSENT_STALE
    assert all(step.status != c.OutcomeStatus.SUCCEEDED for step in replayed.steps)
    assert port.read("managed-control") == original_control
    assert effects.calls == []


@pytest.mark.parametrize("failing", ["event", "head"])
def test_t04_history_publication_failure_keeps_pointer_and_primary_cancel(
    tmp_path, policy, monkeypatch, failing,
):
    service, host, port, effects, plan, grant, _, runs, pointer = cancelled_case(tmp_path, policy)
    before = files(tmp_path)
    original_control, original_root = port.read("managed-control"), port.read("managed-root")
    original_pins = runs.pins()
    compare = port.compare_replace

    def fail_exact(resource, expected, record):
        prefix = "dependency-outcome-event-" if failing == "event" else "dependency-outcome-"
        if resource.startswith(prefix) and (
            failing == "event" or not resource.startswith("dependency-outcome-event-")
        ):
            raise OSError("owned history publication failed")
        return compare(resource, expected, record)

    monkeypatch.setattr(port, "compare_replace", fail_exact)
    cancel = Cancel()
    cancel.value = True
    result = service.restore(plan, grant, cancel)
    assert result.status == c.OutcomeStatus.FAILED
    assert result.errors and result.errors[0].reason == c.ReasonCode.CANCELLED
    assert result.cleanup_errors and result.cleanup_errors[0].reason == c.ReasonCode.OWNERSHIP_INVALID
    assert host.pointer() == pointer
    assert port.read("managed-control") == original_control
    assert port.read("managed-root") == original_root
    assert runs.pins() == original_pins and effects.calls == []
    after = files(tmp_path)
    assert all(after[name] == data for name, data in before.items())
    if failing == "event":
        assert after == before
    else:
        additions = after.keys() - before.keys()
        assert len(additions) == 1
        retained = next(path for path in tmp_path.rglob("*") if (
            path.is_file() and path.relative_to(tmp_path).as_posix() in additions
        ))
        assert b"i02-outcome-event-v1" in retained.read_bytes()


@pytest.mark.parametrize("mutation", ["third-file", "user-file", "pointer", "digest"])
def test_t04_exact_history_assertion_rejects_nonallowlisted_or_operative_changes(
    tmp_path, policy, mutation,
):
    service, _, port, _, plan, grant, _, _, _ = cancelled_case(tmp_path, policy)
    before, writes = files(tmp_path), len(port.writes)
    cancel = Cancel()
    cancel.value = True
    result = service.restore(plan, grant, cancel)
    exact_history(port, tmp_path, before, writes, result)
    if mutation == "third-file":
        (tmp_path / "third-nonallowlisted-metadata").write_bytes(b"forbidden")
    elif mutation == "user-file":
        (tmp_path / "user-vault-inventory-backups").write_bytes(b"forbidden")
    elif mutation == "pointer":
        record = port.read("managed-control")
        port.filename("managed-control").write_bytes(replace(
            record, payload=c.public_object({**dict(record.payload), "setup_enabled": False}),
        ).to_bytes())
    else:
        resource = port.writes[writes + 1][0]
        record = port.read(resource)
        port.filename(resource).write_bytes(replace(record, payload=c.public_object({
            **dict(record.payload), "latest_digest": "f" * 64,
        })).to_bytes())
    with pytest.raises(AssertionError):
        exact_history(port, tmp_path, before, writes, result)
