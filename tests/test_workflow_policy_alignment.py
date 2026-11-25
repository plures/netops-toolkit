"""A02 exact operational policy/handler regression tests; not platform qualification."""

from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed
from tests.test_workflow_execution import policy as policy


@pytest.fixture
def backup_composed(output_composed):
    from netops.ansible.artifact_git import snapshot_files
    from netops.ansible.artifacts import OwnedRecord
    from netops.ansible.execution import EffectResult
    from tests.policy.test_policy_recovery import ByteState

    service, host, sources, effects, fs, select = output_composed

    class State(ByteState):
        def __init__(self):
            super().__init__()
            self.records = {}

        def read(self, resource_id):
            if resource_id not in self.records:
                return super().read(resource_id)
            return OwnedRecord.from_bytes(self.records[resource_id])

        def compare_replace(self, resource_id, expected_revision, record):
            previous = self.records.get(resource_id)
            if previous is None:
                assert expected_revision == record.revision == 0
            else:
                assert OwnedRecord.from_bytes(previous).revision == expected_revision
                assert record.revision == expected_revision + 1
            self.records[resource_id] = record.to_bytes()
            self.content = record.to_bytes()
            self.writes += 1
            return OwnedRecord.from_bytes(self.content)

    class Backend(type(effects)):
        def __init__(self):
            super().__init__()
            self.contents = {}
            self.snapshots = {}
            self.retained = []
            self.failure = None

        def entered(self, effect):
            pending = [
                permit for permit, (binding, _) in host._pending.items()
                if binding.occurrence_id == effect.occurrence_id and permit in host._entered
            ]
            assert len(pending) == 1
            assert host.authorization.reconcile(pending[0]).occurrence_id == effect.occurrence_id
            self.calls.append(effect)
            if self.failure == effect.kind:
                raise RuntimeError("PRIVATE_FOLLOWUP_FAILURE")

        def backup_content(self, plan, effect, cancel):
            self.entered(effect)
            content = (effect.target_id + "\r\npassword PRIVATE_CONFIG_VALUE\r\n").encode()
            self.contents[effect.target_id] = content
            return content

        def retention(self, plan, effect, publications, cancel):
            self.entered(effect)
            assert len(publications) == len(plan.targets)
            assert plan.output_intent.retention is True
            self.retained = [descriptor for descriptor, _ in publications]
            return EffectResult(c.StepOutcome(
                effect.occurrence_id, c.OutcomeStatus.SUCCEEDED, True,
                native_payload=c.public_object({"retained": len(publications)}),
            ))

        def git(self, plan, effect, publications, cancel):
            self.entered(effect)
            assert plan.output_intent.git is True
            for descriptor, binding in publications:
                self.snapshots[binding.effect.target_id] = snapshot_files(
                    self.contents[binding.effect.target_id], c.canonical_bytes(descriptor),
                )
            return EffectResult(c.StepOutcome(
                effect.occurrence_id, c.OutcomeStatus.SUCCEEDED, True,
                native_payload=c.public_object({"snapshots": len(self.snapshots)}), changed=True,
            ))

    backend = Backend()
    host._owned = State()
    host._backend = backend
    original_publish = fs.publish
    fs.published_bytes = []
    fs.published_intents = []

    def publish(root, content, binding):
        fs.published_bytes.append(content)
        fs.published_intents.append(root.intent)
        assert root.intent.git is False
        return original_publish(root, content, binding)

    fs.publish = publish
    request = replace(
        select("inventory.export"), operation="config.backup", scope=c.Scope(("r1", "r2")),
        output_intent=c.OutputIntent(("text",), "owned", retention=True, git=True),
    )
    sources.value = replace(sources.value, request=request)
    return service, host, request, sources, backend, fs


def test_refresh_observe_reloads_native_inventory_without_publication(composed):
    service, host, request, sources, effects = composed
    request = replace(request, operation="inventory.refresh")
    sources.value = replace(sources.value, request=request)
    grant = host.review(service, request)
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.SUCCEEDED, outcome
    assert outcome.steps[0].native_payload["_meta"]["hostvars"]["r1"]["ansible_host"] == "192.0.2.1"
    assert outcome.steps[0].changed is False
    assert outcome.artifacts == ()
    assert effects.calls == []
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED


def test_backup_observe_collects_without_selecting_hidden_output(composed):
    service, host, request, sources, effects = composed
    request = replace(request, operation="config.backup")
    sources.value = replace(sources.value, request=request)
    grant = host.review(service, request)
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.SUCCEEDED, outcome
    assert [effect.kind for effect in effects.calls] == ["collect"]
    assert [step.native_payload for step in outcome.steps] == [
        c.public_object({"output": ("native", "r1"), "reading": 5}),
    ]
    assert outcome.artifacts == ()


def test_refresh_without_filter_preserves_all_current_inventory_devices(composed):
    service, host, request, sources, effects = composed
    request = replace(request, operation="inventory.refresh", scope=c.Scope(()))
    sources.value = replace(sources.value, request=request)
    outcome = service.execute(request, host.review(service, request))
    assert outcome.status == c.OutcomeStatus.SUCCEEDED
    assert set(outcome.steps[0].native_payload["_meta"]["hostvars"]) == {"r1", "r2"}
    assert effects.calls == []


def test_backup_output_preserves_collection_and_distinct_followups(backup_composed):
    service, host, request, sources, effects, fs = backup_composed
    grant = host.review(service, request)
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.SUCCEEDED, outcome
    assert [step.step_id for step in outcome.steps] == [
        request.operation_id + ":" + str(i) for i in range(6)
    ]
    assert [effect.kind for effect in effects.calls] == [
        "collect", "backup", "collect", "backup", "retention", "git",
    ]
    assert len(outcome.artifacts) == 2
    assert all(artifact["classification"] == "sensitive" for artifact in outcome.artifacts)
    assert fs.published_bytes == [effects.contents["r1"], effects.contents["r2"]]
    assert all(intent.git is False for intent in fs.published_intents)
    assert set(effects.snapshots) == {"r1", "r2"}
    assert len(effects.retained) == 2
    assert "PRIVATE_CONFIG_VALUE" not in repr(outcome)
    assert "PRIVATE_CONFIG_VALUE" not in repr(host._owned.records)
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(effects.calls) == 6


@pytest.mark.parametrize("kind", ["refresh", "backup", "retention", "git"])
def test_fixed_handlers_reject_direct_entry_without_real_pending_permit(backup_composed, kind):
    service, host, request, sources, effects, fs = backup_composed
    plan, _ = host._load(service, request)
    if kind == "refresh":
        request = replace(request, operation="inventory.refresh", mode=c.Mode.OBSERVE,
                          output_intent=c.OutputIntent())
        sources.value = replace(sources.value, request=request)
        plan, _ = host._load(service, request)
    effect = next(item for item in plan.effects if item.kind == kind)
    handler = {
        "refresh": host._refresh, "backup": host._backup,
        "retention": host._retention, "git": host._git,
    }[kind]
    with pytest.raises(RuntimeError, match="consent-stale"):
        handler(None, None, plan, effect)
    assert effects.calls == []
    assert fs.published_bytes == []


@pytest.mark.parametrize("operation", ["config.backup", "inventory.refresh"])
def test_new_paths_require_actual_private_consent_before_any_effect(backup_composed, operation):
    service, host, request, sources, effects, fs = backup_composed
    if operation == "inventory.refresh":
        request = replace(request, operation=operation, mode=c.Mode.OBSERVE,
                          output_intent=c.OutputIntent())
        sources.value = replace(sources.value, request=request)
    outcome = service.execute(request)
    assert outcome.status == c.OutcomeStatus.BLOCKED
    assert all(not step.attempted for step in outcome.steps)
    assert effects.calls == []
    assert fs.published_bytes == []


@pytest.mark.parametrize("change", ["resource", "context", "source", "kill-switch"])
def test_current_source_drift_and_revert_never_restore_reviewed_admission(backup_composed, change):
    service, host, request, sources, effects, fs = backup_composed
    grant = host.review(service, request)
    original = sources.value
    if change == "resource":
        sources.value = replace(original, request=replace(
            request, output_intent=replace(request.output_intent, root_ref="another-root"),
        ))
    elif change == "context":
        sources.value = replace(original, request=replace(
            request, context=replace(request.context, route_digest="f" * 64),
        ))
    elif change == "source":
        sources.value = replace(original, sources=(
            replace(original.sources[0], content=b'{"devices":{}}'),
        ))
    else:
        sources.value = replace(original, settings=replace(
            original.settings, ansible=replace(original.settings.ansible, enabled=False),
        ))
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    sources.value = original
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert effects.calls == []
    assert fs.published_bytes == []


def test_backup_root_swap_rejects_before_collection(backup_composed):
    service, host, request, sources, effects, fs = backup_composed
    grant = host.review(service, request)
    fs.inode += 1
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert effects.calls == []
    assert fs.published_bytes == []


def test_backup_without_selected_targets_cannot_run_orphaned_followups(backup_composed):
    service, host, request, sources, effects, fs = backup_composed
    with pytest.raises(c.ContractError):
        replace(request, scope=c.Scope(()))
    assert effects.calls == []
    assert fs.published_bytes == []


@pytest.mark.parametrize("mode", [c.Mode.PREVIEW, c.Mode.CHECK])
def test_pure_backup_modes_never_acquire_dispatch_authority(backup_composed, mode):
    service, host, request, sources, effects, fs = backup_composed
    request = replace(request, mode=mode)
    sources.value = replace(sources.value, request=request)
    with pytest.raises(RuntimeError, match="dependency-not-ready"):
        host.review(service, request)
    assert effects.calls == []
    assert fs.published_bytes == []


def test_backup_without_explicit_retention_never_publishes_or_prunes(backup_composed):
    service, host, request, sources, effects, fs = backup_composed
    request = replace(request, output_intent=replace(request.output_intent, retention=False))
    sources.value = replace(sources.value, request=request)
    with pytest.raises(RuntimeError, match="output-rejected"):
        host.review(service, request)
    assert effects.calls == []
    assert fs.published_bytes == []


def test_refresh_cannot_reuse_old_mapping_after_observed_source_failure_and_revert(composed):
    service, host, request, sources, effects = composed
    request = replace(request, operation="inventory.refresh")
    sources.value = replace(sources.value, request=request)
    grant = host.review(service, request)
    original = sources.value
    sources.value = replace(original, sources=(replace(
        original.sources[0], content=b'{"devices":{}}',
    ),))
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    sources.value = original
    reverted = service.execute(request, grant)
    assert reverted.status == c.OutcomeStatus.BLOCKED
    assert all(not step.attempted for step in reverted.steps)
    assert effects.calls == []


@pytest.mark.parametrize("kind", ["retention", "git"])
def test_followup_failure_preserves_actual_backup_bytes_and_never_redispatches(
    backup_composed, kind,
):
    service, host, request, sources, effects, fs = backup_composed
    effects.failure = kind
    grant = host.review(service, request)
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.PARTIAL
    assert len(outcome.artifacts) == 2
    assert fs.published_bytes == [effects.contents["r1"], effects.contents["r2"]]
    expected = ["collect", "backup", "collect", "backup", "retention"]
    if kind == "git":
        expected.append("git")
    assert [effect.kind for effect in effects.calls] == expected
    assert "PRIVATE_FOLLOWUP_FAILURE" not in repr(outcome)
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert [effect.kind for effect in effects.calls] == expected


def test_unselected_git_never_runs_inside_publication_or_retention(backup_composed):
    service, host, request, sources, effects, fs = backup_composed
    request = replace(request, output_intent=replace(request.output_intent, git=False))
    sources.value = replace(sources.value, request=request)
    outcome = service.execute(request, host.review(service, request))
    assert outcome.status == c.OutcomeStatus.SUCCEEDED
    assert [effect.kind for effect in effects.calls] == [
        "collect", "backup", "collect", "backup", "retention",
    ]
    assert effects.snapshots == {}
    assert all(not intent.git for intent in fs.published_intents)


def test_collection_failure_does_not_publish_or_hide_actual_target_failure(backup_composed):
    from netops.ansible.execution import EffectResult

    service, host, request, sources, effects, fs = backup_composed

    def fail_collect(plan, effect, cancel):
        effects.calls.append(effect)
        return EffectResult(c.StepOutcome(
            effect.occurrence_id, c.OutcomeStatus.FAILED, True,
            native_payload=c.public_object({"success": False, "error": "transport-unavailable"}),
        ))

    effects.collect = fail_collect
    outcome = service.execute(request, host.review(service, request))
    assert outcome.status == c.OutcomeStatus.FAILED
    assert outcome.targets[0].attempted is True
    assert outcome.targets[0].status == c.OutcomeStatus.FAILED
    assert outcome.targets[0].native_payload["success"] is False
    assert outcome.targets[1].attempted is False
    assert [effect.kind for effect in effects.calls] == ["collect"]
    assert fs.published_bytes == []


def test_drift_between_collect_and_backup_revokes_before_sensitive_publication(backup_composed):
    service, host, request, sources, effects, fs = backup_composed
    grant = host.review(service, request)

    def drift():
        sources.value = replace(sources.value, request=replace(
            request, context=replace(request.context, mapping_digest="f" * 64),
        ))

    effects.before_return = drift
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.PARTIAL
    assert [effect.kind for effect in effects.calls] == ["collect"]
    assert outcome.targets[0].attempted is True
    assert fs.published_bytes == []


@pytest.mark.parametrize("kind,flag", [("retention", "retention_requested"), ("git", "git_requested")])
def test_real_source_policy_rejects_missing_explicit_followup_intent(backup_composed, kind, flag):
    from netops.ansible.policy.contracts import DecisionFacts, object_value

    service, host, request, sources, effects, fs = backup_composed
    host.review(service, request)
    plan, _ = host._load(service, request)
    effect = next(item for item in plan.effects if item.kind == kind)
    event = host._requested(plan, effect)
    facts = host._facts(plan, plan.deadline_ms, effect=effect)
    actual = service._policy.decide(event, facts)
    assert actual.decision == "allow"
    assert [(item.name, item.params["kind"]) for item in actual.effects] == [("request_effect", kind)]
    values = dict(facts.values)
    values["output"] = dict(values["output"])
    values["output"][flag] = False
    denied = service._policy.decide(event, DecisionFacts(object_value(values)))
    assert denied.decision == "deny"
    assert denied.effects == ()


@pytest.mark.parametrize("selector", [None, "apply", "arbitrary", True])
def test_next_occurrence_selector_is_closed_and_never_defaulted(backup_composed, selector):
    from netops.ansible.policy.contracts import DecisionFacts, PolicyInputError, object_value

    service, host, request, sources, effects, fs = backup_composed
    host.review(service, request)
    plan, _ = host._load(service, request)
    effect = plan.effects[0]
    facts = host._facts(plan, plan.deadline_ms, effect=effect)
    values = dict(facts.values)
    values["operational"] = dict(values["operational"])
    if selector is None:
        del values["operational"]
    else:
        values["operational"]["next_effect_kind"] = selector
    with pytest.raises(PolicyInputError):
        service._policy.decide(host._requested(plan, effect), DecisionFacts(object_value(values)))


@pytest.mark.parametrize("kind", ["backup", "retention", "git"])
@pytest.mark.parametrize("mode", [c.Mode.OBSERVE, c.Mode.PREVIEW, c.Mode.CHECK])
def test_real_source_never_proposes_backup_writes_in_read_only_modes(backup_composed, kind, mode):
    from netops.ansible.policy.contracts import DecisionFacts, object_value

    service, host, request, sources, effects, fs = backup_composed
    host.review(service, request)
    plan, _ = host._load(service, request)
    effect = next(item for item in plan.effects if item.kind == kind)
    event = host._requested(plan, effect)
    event = replace(event, payload=c.public_object({**dict(event.payload), "mode": mode.value}))
    facts = host._facts(plan, plan.deadline_ms, effect=effect)
    values = dict(facts.values)
    values["request"] = {**dict(values["request"]), "mode": mode.value}
    decision = service._policy.decide(event, DecisionFacts(object_value(values)))
    assert not any(item.name == "request_effect" for item in decision.effects)
