"""A02 workflow control tests; no device, controller or platform qualification."""

import hashlib
import json
from dataclasses import replace
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    TrustedConsentAdapter,
)
from netops.ansible.workflows import WorkflowService
from tests.test_workflow_contracts import policy as policy


class Clock:
    def monotonic(self):
        return 12.0


class NoCalls:
    def __getattr__(self, name):
        raise AssertionError("Unexpected effect: " + name)


def broker():
    no_calls = NoCalls()
    return AuthorizationBroker(no_calls, TrustedConsentAdapter(no_calls))


def test_cancel_revokes_actual_admission_without_allocating_revision():
    host = broker()
    service = WorkflowService(None, host, None, None, None, None, Clock(), None)
    operation_id = str(uuid4())
    receipt = service.cancel(operation_id)
    assert host.is_revoked(operation_id) is True
    assert receipt.accepted is True
    assert receipt.reason == "cancelled"
    assert receipt.received_at == 12.0


def test_actual_broker_revocation_is_idempotent_without_state_or_review_calls():
    no_calls = NoCalls()
    host = broker()
    service = WorkflowService(None, host, no_calls, no_calls, no_calls, no_calls, Clock(), no_calls)
    operation_id = str(uuid4())
    assert service.cancel(operation_id).accepted is True
    assert service.cancel(operation_id).accepted is True
    assert host.is_revoked(operation_id) is True


def test_clock_failure_does_not_undo_revocation():
    class BrokenClock:
        def monotonic(self):
            raise RuntimeError("local-clock-unavailable")

    host = broker()
    service = WorkflowService(None, host, None, None, None, None, BrokenClock(), None)
    operation_id = str(uuid4())
    with pytest.raises(RuntimeError, match="local-clock-unavailable"):
        service.cancel(operation_id)
    assert host.is_revoked(operation_id) is True


def test_invalid_operation_cannot_revoke_another_scope():
    host = broker()
    service = WorkflowService(None, host, None, None, None, None, Clock(), None)
    with pytest.raises(c.ContractError):
        service.cancel("not-an-operation")
    assert host.is_revoked("not-an-operation") is False


class Sources:
    def __init__(self, value):
        self.value = value
        self.calls = 0

    def reload(self, operation_id):
        assert operation_id == self.value.request.operation_id
        self.calls += 1
        return self.value


class Effects:
    def __init__(self):
        self.calls = []
        self.before_return = None

    def gather(self, plan, effect, cancel):
        from netops.ansible.execution import EffectResult

        self.calls.append(effect)
        if self.before_return is not None:
            self.before_return()
        return EffectResult(c.StepOutcome(
            effect.occurrence_id, c.OutcomeStatus.SUCCEEDED, True,
            native_payload=c.public_object({"output": ("native", effect.target_id), "reading": 5}),
        ))

    def collect(self, plan, effect, cancel):
        return self.gather(plan, effect, cancel)

    def resolve_for_run(self, plan, effect, cancel):
        return self.gather(plan, effect, cancel)

    def scan(self, plan, effect, cancel):
        return self.gather(plan, effect, cancel)


@pytest.fixture
def composed(policy):
    from netops.ansible.execution import ExecutionHost, ExecutionInputs
    from netops.ansible.settings import AnsibleSettings, SettingsSnapshot
    from tests.policy.test_policy_recovery import ByteState

    identity, engine = policy
    content = b'{"devices":{"r1":{"host":"192.0.2.1"},"r2":{"host":"192.0.2.2"}}}'
    ref = c.InputRef("inventory", "owned-inventory", hashlib.sha256(content).hexdigest())
    request = c.OperationRequest(
        str(uuid4()), "health.gather", c.Mode.OBSERVE, c.Scope(("r1",)),
        c.Context("local", "a" * 64, "owned", "b" * 64, identity, "c" * 64, "d" * 64),
        (ref,),
    )
    sources = Sources(ExecutionInputs(
        request, (c.InputSource(ref, "json", content, "parser-1", "vendor-1"),),
        SettingsSnapshot(ansible=AnsibleSettings(enabled=True)),
        "owned", 0, c.ReadinessProjection(companion="ready"), True, True, True,
    ))

    class Reviewer:
        def confirm(self, plan, binding, deadline):
            return True

    effects, clock = Effects(), Clock()
    host = ExecutionHost(sources, ByteState(), Reviewer(), effects, clock, "1" * 64)
    service = WorkflowService(engine, host.authorization, None, None, host, None, clock, None)
    return service, host, request, sources, effects


def test_actual_execute_gather_preserves_exact_native_payload_and_consumes_once(composed):
    service, host, request, sources, effects = composed
    grant = host.review(service, request)
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    assert result.steps[0].native_payload == c.public_object({"output": ("native", "r1"), "reading": 5})
    assert result.targets[0].native_payload == result.steps[0].native_payload
    assert len(effects.calls) == 1
    assert sources.calls >= 5
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(effects.calls) == 1


def test_scan_enters_real_broker_and_preserves_native_result(composed):
    service, host, request, sources, effects = composed
    request = replace(request, operation="scan.discover")
    sources.value = replace(sources.value, request=request)
    grant = host.review(service, request)
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    assert [effect.kind for effect in effects.calls] == ["scan"]
    assert result.targets[0].native_payload == c.public_object({
        "output": ("native", "r1"), "reading": 5,
    })
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(effects.calls) == 1


def test_scan_loss_is_attributed_only_to_entered_target(composed):
    service, host, request, sources, effects = composed
    request = replace(request, operation="scan.discover", scope=c.Scope(("r1", "r2")))
    sources.value = replace(sources.value, request=request)
    grant = host.review(service, request)

    def lose_ack():
        raise RuntimeError("PRIVATE_SCAN_LOSS")

    effects.before_return = lose_ack
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.FAILED
    assert result.targets[0].attempted is True
    assert result.targets[0].remote_state == "uncertain"
    assert result.targets[1].attempted is False
    assert result.targets[1].remote_state == "unchanged"
    assert "PRIVATE_SCAN_LOSS" not in repr(result)
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(effects.calls) == 1


@pytest.fixture
def output_composed(composed):
    from netops.ansible.artifacts import ArtifactStore
    from tests.test_artifact_store import Events, MemoryFilesystem

    service, host, request, sources, effects = composed

    class Filesystem(MemoryFilesystem):
        def __init__(self):
            super().__init__()
            self.bindings = []
            self.fail_validation = False
            self.lose_ack = False
            self.inode = 0

        def validate(self, intent):
            if self.fail_validation:
                raise RuntimeError("PRIVATE_OUTPUT_VALIDATION")
            return replace(super().validate(intent), inode=self.inode)

        def publish(self, root, content, binding):
            assert host._owned.content is not None
            matches = [
                permit for permit, (pending, _) in host._pending.items()
                if pending == binding.effect and permit in host._entered
            ]
            assert len(matches) == 1
            assert host.authorization.reconcile(matches[0]) == binding.effect
            self.bindings.append(binding)
            descriptor = super().publish(root, content, binding)
            if self.lose_ack:
                raise RuntimeError("PRIVATE_OUTPUT_LOST_ACK")
            return descriptor

    fs = Filesystem()
    service._artifacts = ArtifactStore(fs, Clock(), Events())

    def select(operation):
        nonlocal request
        inputs = list(request.inputs)
        input_sources = list(sources.value.sources)
        if operation == "scan.save":
            content = b'{"devices":{"r1":{"host":"192.0.2.1","vendor":"cisco_ios"}}}'
            ref = c.InputRef("fragment", "owned-fragment", hashlib.sha256(content).hexdigest())
            inputs.append(ref)
            input_sources.append(c.InputSource(ref, "json", content, "parser-1", "vendor-1"))
        elif operation == "report.render":
            source_outcome = c.aggregate_outcome(
                request,
                (c.TargetOutcome("r1", c.OutcomeStatus.SUCCEEDED, True),),
                (c.StepOutcome("native-step", c.OutcomeStatus.SUCCEEDED, True),),
                executed_mode=c.Mode.OBSERVE,
            )
            content = c.canonical_bytes(source_outcome)
            ref = c.InputRef("outcomes", "owned-outcomes", hashlib.sha256(content).hexdigest())
            inputs.append(ref)
            input_sources.append(c.InputSource(ref, "json", content, "parser-1", "vendor-1"))
        request = replace(
            request, operation=operation, mode=c.Mode.OUTPUT, inputs=tuple(inputs),
            output_intent=c.OutputIntent(
                ("html",) if operation == "report.render" else ("json",), "owned",
            ),
        )
        sources.value = replace(sources.value, request=request, sources=tuple(input_sources))
        return request

    return service, host, sources, effects, fs, select


@pytest.mark.parametrize("operation", ["scan.save", "inventory.export", "report.render"])
def test_output_handlers_use_real_native_conversion_and_exact_admitted_artifact_port(
    output_composed, operation,
):
    service, host, sources, effects, fs, select = output_composed
    request = select(operation)
    grant = host.review(service, request)
    assert fs.bindings == []
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.SUCCEEDED, outcome
    assert outcome.changed is True
    assert len(outcome.artifacts) == len(fs.bindings) == 1
    assert effects.calls == []
    assert sources.calls >= 5
    if operation == "inventory.export":
        native = json.loads(fs.content)
        assert native["_meta"]["hostvars"]["r1"]["ansible_host"] == "192.0.2.1"
        assert native["all"]["hosts"] == ["r1"]
        assert "r2" not in native["_meta"]["hostvars"]
        assert outcome.steps[0].native_payload == c.public_object(native)
    elif operation == "scan.save":
        native = json.loads(fs.content)
        assert native["devices"]["r1"]["vendor"] == "cisco_ios"
        assert native["devices"]["r2"]["host"] == "192.0.2.2"
        assert outcome.steps[0].native_payload == c.public_object(native)
    else:
        assert fs.content.startswith(b"<!DOCTYPE html>")
        assert b"Selected outcomes" in fs.content
        assert b"r1" in fs.content
        assert outcome.steps[0].native_payload["sections"][0]["data"]["targets"][0]["target_id"] == "r1"
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(fs.bindings) == 1


@pytest.mark.parametrize("operation", ["scan.save", "inventory.export", "report.render"])
def test_output_root_revalidation_failure_prevents_publication(output_composed, operation):
    service, host, _, _, fs, select = output_composed
    request = select(operation)
    grant = host.review(service, request)
    fs.fail_validation = True
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.BLOCKED
    assert fs.bindings == []
    assert fs.content == b""
    assert "PRIVATE_OUTPUT_VALIDATION" not in repr(outcome)


@pytest.mark.parametrize("operation", ["scan.save", "inventory.export", "report.render"])
def test_output_lost_ack_retains_uncertainty_and_cannot_republish(output_composed, operation):
    service, host, _, _, fs, select = output_composed
    request = select(operation)
    grant = host.review(service, request)
    fs.lose_ack = True
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.FAILED
    assert outcome.steps[0].attempted is True
    assert outcome.steps[0].remote_state == "uncertain"
    assert fs.content != b""
    assert "PRIVATE_OUTPUT_LOST_ACK" not in repr(outcome)
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(fs.bindings) == 1


@pytest.mark.parametrize("operation", ["scan.save", "inventory.export", "report.render"])
def test_reviewed_output_root_replacement_never_publishes(output_composed, operation):
    service, host, _, _, fs, select = output_composed
    request = select(operation)
    grant = host.review(service, request)
    fs.inode = 1
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.BLOCKED
    assert fs.bindings == []
    assert fs.content == b""


def test_exact_output_consent_precedes_real_output_policy_admission(output_composed):
    service, host, _, _, fs, select = output_composed
    request = select("inventory.export")
    original = service._policy.decide
    decisions = []

    def decide(event, facts):
        if facts.values["request"]["mode"] == "output":
            assert request.operation_id in host._reviewed
            assert facts.values["consent"]["present"] is True
            assert facts.values["consent"]["effects_match"] is True
            assert facts.values["report"]["output_safe"] is True
            decisions.append(event)
        return original(event, facts)

    service._policy.decide = decide
    grant = host.review(service, request)
    assert decisions and not fs.bindings
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert len(fs.bindings) == 1


def test_repeated_review_cannot_renew_original_deadline(output_composed):
    service, host, _, _, fs, select = output_composed
    request = select("inventory.export")
    grant = host.review(service, request)
    deadline = host._deadlines[request.operation_id]
    with pytest.raises(RuntimeError, match="resource-busy"):
        host.review(service, request)
    assert host._deadlines[request.operation_id] == deadline
    assert service.execute(request, grant).status == c.OutcomeStatus.SUCCEEDED
    assert len(fs.bindings) == 1


def test_output_completed_bytes_and_descriptor_survive_checkpoint_failure(output_composed):
    service, host, _, _, fs, select = output_composed
    request = select("inventory.export")
    grant = host.review(service, request)
    original = host._owned.compare_replace

    def fail_completion(resource_id, expected_revision, record):
        if record.revision > 0:
            raise RuntimeError("PRIVATE_CHECKPOINT_FAILURE")
        return original(resource_id, expected_revision, record)

    host._owned.compare_replace = fail_completion
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.FAILED
    assert result.steps[0].changed is True
    assert result.steps[0].remote_state == "unchanged"
    assert result.artifacts[0]["digest"] == hashlib.sha256(fs.content).hexdigest()
    assert result.steps[0].native_payload == c.public_object(json.loads(fs.content))
    assert "PRIVATE_CHECKPOINT_FAILURE" not in repr(result)
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(fs.bindings) == 1


@pytest.mark.parametrize("operation", ["scan.save", "inventory.export"])
def test_output_native_yaml_preserves_metadata_and_manual_values(output_composed, operation):
    import yaml

    service, host, sources, _, fs, select = output_composed
    request = select(operation)
    inventory = c.public_object({
        "defaults": {"transport": "telnet", "vendor": "cisco_ios"},
        "devices": {
            "r1": {
                "host": "192.0.2.1", "vendor": "juniper_junos", "site": "dc-1",
                "role": "edge", "groups": ["explicit"], "tags": {"owner": "operator"},
            },
            "r2": {"host": "192.0.2.2"},
        },
    })
    content = c.canonical_bytes(inventory)
    ref = c.InputRef("inventory", "owned-inventory", hashlib.sha256(content).hexdigest())
    request = replace(
        request, inputs=(ref,) + request.inputs[1:],
        output_intent=replace(request.output_intent, kinds=("yaml",)),
    )
    sources.value = replace(
        sources.value, request=request,
        sources=(c.InputSource(ref, "json", content, "parser-1", "vendor-1"),)
        + sources.value.sources[1:],
    )
    result = service.execute(request, host.review(service, request))
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    native = yaml.safe_load(fs.content)
    if operation == "inventory.export":
        assert native["_meta"]["hostvars"]["r1"]["ansible_port"] == 23
        assert native["_meta"]["hostvars"]["r1"]["ansible_network_os"] == "juniper_junos"
        assert native["explicit"]["hosts"] == ["r1"]
        assert native["vendor_juniper_junos"]["hosts"] == ["r1"]
        assert native["site_dc_1"]["hosts"] == ["r1"]
        assert native["role_edge"]["hosts"] == ["r1"]
        assert "r2" not in native["_meta"]["hostvars"]
    else:
        assert native["devices"]["r1"]["vendor"] == "juniper_junos"
        assert native["devices"]["r1"]["tags"] == {"owner": "operator"}
        assert native["devices"]["r2"]["host"] == "192.0.2.2"
    assert result.artifacts[0]["digest"] == hashlib.sha256(fs.content).hexdigest()


@pytest.mark.parametrize("operation", ["scan.save", "inventory.export", "report.render"])
def test_output_missing_selected_target_cannot_review_or_publish(output_composed, operation):
    service, host, sources, _, fs, select = output_composed
    request = replace(select(operation), scope=c.Scope(("missing-target",)))
    sources.value = replace(sources.value, request=request)
    with pytest.raises(RuntimeError, match="input-binding-invalid"):
        host.review(service, request)
    assert fs.bindings == []
    assert request.operation_id not in host._reviewed


def test_output_trusted_review_rejection_never_issues_or_writes(output_composed):
    service, host, _, _, fs, select = output_composed
    request = select("inventory.export")
    host._consent._reviewer.confirm = lambda *args: False
    with pytest.raises(AuthorizationError):
        host.review(service, request)
    assert request.operation_id not in host._reviewed
    assert service.execute(request).status == c.OutcomeStatus.BLOCKED
    assert fs.bindings == []


@pytest.mark.parametrize("kind", ["retention", "git"])
def test_unadmitted_followup_remains_selected_and_never_implicitly_runs(output_composed, kind):
    service, host, sources, _, fs, select = output_composed
    request = select("inventory.export")
    request = replace(request, output_intent=replace(request.output_intent, **{kind: True}))
    sources.value = replace(sources.value, request=request)
    with pytest.raises(RuntimeError, match="dependency-not-ready"):
        host.review(service, request)
    result = service.execute(request)
    assert result.status == c.OutcomeStatus.BLOCKED
    assert [step.unapplied_effects for step in result.steps] == [("export",), (kind,)]
    assert result.targets[0].unapplied_effects == ("export", kind)
    assert all(not step.attempted for step in result.steps)
    assert fs.bindings == []


def test_unadmitted_backup_preserves_collection_and_publication_for_each_target(composed):
    service, _, request, sources, effects = composed
    request = replace(
        request, operation="config.backup", mode=c.Mode.OUTPUT, scope=c.Scope(("r1", "r2")),
        output_intent=c.OutputIntent(("text",), "owned", retention=True, git=True),
    )
    sources.value = replace(sources.value, request=request)
    result = service.execute(request)
    assert result.status == c.OutcomeStatus.BLOCKED
    assert [step.unapplied_effects for step in result.steps] == [
        ("collect",), ("backup",), ("collect",), ("backup",), ("retention",), ("git",),
    ]
    assert tuple(target.target_id for target in result.targets) == ("r1", "r2")
    assert all(target.unapplied_effects == ("collect", "backup") for target in result.targets)
    assert all(not step.attempted for step in result.steps)
    assert effects.calls == []


def test_cancel_after_native_render_before_publication_retains_known_unapplied_result(
    output_composed, monkeypatch,
):
    from netops.report.generator import ReportGenerator

    service, host, _, _, fs, select = output_composed
    request = select("report.render")
    grant = host.review(service, request)
    original = ReportGenerator.generate_html

    def render_and_cancel(generator, data, output_path=None):
        rendered = original(generator, data, output_path)
        assert service.cancel(request.operation_id).accepted is True
        return rendered

    monkeypatch.setattr(ReportGenerator, "generate_html", render_and_cancel)
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.CANCELLED, result
    assert result.steps[0].attempted is True
    assert result.steps[0].unapplied_effects == ("render",)
    assert result.steps[0].remote_state == "unchanged"
    assert result.steps[0].changed is False
    assert result.artifacts == ()
    assert fs.content == b""
    assert fs.bindings == []
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED


@pytest.mark.parametrize("drift", ["settings", "context", "generation", "cancelled", "route"])
def test_current_source_drift_between_review_and_execute_never_dispatches(composed, drift):
    service, host, request, sources, effects = composed
    grant = host.review(service, request)
    value = sources.value
    if drift == "settings":
        value = replace(value, settings=replace(value.settings, ansible=replace(
            value.settings.ansible, enabled=False,
        )))
    elif drift == "context":
        value = replace(value, request=replace(request, context=replace(
            request.context, mapping_digest="e" * 64,
        )))
    elif drift == "generation":
        value = replace(value, generation=1)
    elif drift == "route":
        value = replace(value, route_qualified=False)
    else:
        value = replace(value, cancelled=True)
    sources.value = value
    result = service.execute(request, grant)
    assert result.status in (c.OutcomeStatus.BLOCKED, c.OutcomeStatus.CANCELLED)
    assert effects.calls == []


def test_uncomposed_or_forged_authority_does_not_dispatch(composed):
    service, _, request, _, effects = composed
    assert service.execute(request).status == c.OutcomeStatus.BLOCKED
    assert service.execute(request, object()).status == c.OutcomeStatus.BLOCKED
    assert effects.calls == []


def test_public_concurrent_reentry_returns_busy_without_second_effect(composed):
    service, host, request, _, effects = composed
    grant = host.review(service, request)
    second = []
    effects.before_return = lambda: second.append(service.execute(request, grant))
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert second[0].errors[0].reason == c.ReasonCode.RESOURCE_BUSY
    assert len(effects.calls) == 1


def test_lost_native_acknowledgement_is_uncertain_and_never_redispatched(composed):
    service, host, request, _, effects = composed
    grant = host.review(service, request)

    def lost():
        raise RuntimeError("PRIVATE_SENTINEL")

    effects.before_return = lost
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.FAILED
    assert result.targets[0].remote_state == "uncertain"
    assert "PRIVATE_SENTINEL" not in repr(result)
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(effects.calls) == 1


@pytest.mark.parametrize("operation", ["health.gather", "config.collect"])
def test_all_selected_targets_have_ordered_exact_results(composed, operation):
    service, host, request, sources, effects = composed
    request = replace(request, operation=operation, scope=c.Scope(("r1", "r2")))
    sources.value = replace(sources.value, request=request)
    grant = host.review(service, request)
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    assert tuple(target.target_id for target in result.targets) == ("r1", "r2")
    assert tuple(effect.target_id for effect in effects.calls) == ("r1", "r2")
    assert tuple(step.native_payload["output"] for step in result.steps) == (
        ("native", "r1"), ("native", "r2"),
    )


def test_cancel_between_effects_retains_completion_and_revocation(composed):
    service, host, request, sources, effects = composed
    request = replace(request, scope=c.Scope(("r1", "r2")))
    sources.value = replace(sources.value, request=request)
    grant = host.review(service, request)
    effects.before_return = lambda: service.cancel(request.operation_id)
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.PARTIAL
    assert result.targets[0].status == c.OutcomeStatus.SUCCEEDED
    assert result.targets[1].attempted is False
    assert host.authorization.is_revoked(request.operation_id)
    assert len(effects.calls) == 1


def test_expiry_seen_during_hydration_cannot_be_hidden_by_later_clock(composed):
    service, host, request, sources, effects = composed
    grant = host.review(service, request)
    original = sources.reload

    def expired(operation_id):
        host._clock.monotonic = lambda: 10000.0
        return original(operation_id)

    sources.reload = expired
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.BLOCKED
    assert host.authorization.is_revoked(request.operation_id)
    assert effects.calls == []


def test_direct_fixed_handler_without_private_pending_permit_is_rejected(composed):
    service, host, request, _, effects = composed
    plan, inputs = host._load(service, request)
    from netops.ansible.policy.authorization import bind_plan

    binding = c.EffectBinding(
        bind_plan(plan, inputs.root_ref, inputs.generation), str(uuid4()), 0,
        plan.effects[0].occurrence_id, "r1", "gather", (),
    )
    with pytest.raises(RuntimeError):
        host._gather(object(), binding, plan, plan.effects[0])
    assert effects.calls == []


def test_explicit_owned_journal_blocks_restart_redispatch(composed):
    service, host, request, sources, effects = composed
    request = replace(request, output_intent=c.OutputIntent(("json",), "owned"))
    sources.value = replace(sources.value, request=request)
    result = service.execute(request, host.review(service, request))
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    assert host._owned.content is not None
    # Remove only process-private control objects to simulate a new host;
    # retained owned bytes are not authority to execute the old occurrence.
    from netops.ansible.execution import ExecutionHost

    restarted = ExecutionHost(
        sources, host._owned, host._consent._reviewer, effects, host._clock, "1" * 64,
    )
    other = WorkflowService(
        service._policy, restarted.authorization, None, None, restarted, None, host._clock, None,
    )
    again = other.execute(request, restarted.review(other, request))
    assert again.status != c.OutcomeStatus.SUCCEEDED
    assert len(effects.calls) == 1


def test_device_resource_aliases_contend_across_different_operations(composed):
    service, host, request, sources, effects = composed
    from netops.ansible.execution import ExecutionHost

    other_request = replace(request, operation_id=str(uuid4()))
    other_sources = Sources(replace(sources.value, request=other_request))
    other_host = ExecutionHost(
        other_sources, host._owned, host._consent._reviewer, effects, host._clock, "1" * 64,
    )
    other_service = WorkflowService(
        service._policy, other_host.authorization, None, None, other_host, None, host._clock, None,
    )
    other_grant = other_host.review(other_service, other_request)
    busy = []
    effects.before_return = lambda: busy.append(other_service.execute(other_request, other_grant))
    result = service.execute(request, host.review(service, request))
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert busy[0].errors[0].reason == c.ReasonCode.RESOURCE_BUSY
    assert len(effects.calls) == 1


def test_excluded_concrete_device_is_not_admitted(composed):
    service, host, request, sources, effects = composed
    request = replace(request, scope=c.Scope(("r1",), ("192.0.2.0/24",)))
    sources.value = replace(sources.value, request=request)
    with pytest.raises(RuntimeError):
        host.review(service, request)
    assert effects.calls == []


def test_exhausted_admission_revision_rejects_without_dispatch_and_cancel_still_works(composed):
    from netops.ansible.policy.contracts import MAX_SAFE_INT

    service, host, request, _, effects = composed
    host._state._revisions[request.operation_id] = MAX_SAFE_INT
    grant = host.review(service, request)
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.BLOCKED
    assert host._state._revisions[request.operation_id] == MAX_SAFE_INT
    assert service.cancel(request.operation_id).accepted
    assert effects.calls == []


def test_failed_completion_journal_retains_native_payload_and_never_redispatches(composed):
    service, host, request, _, effects = composed
    grant = host.review(service, request)
    original = host._memory.compare_replace

    def lost(resource_id, expected_revision, record):
        if record.revision > 0:
            raise RuntimeError("PRIVATE_STORAGE_SENTINEL")
        return original(resource_id, expected_revision, record)

    host._memory.compare_replace = lost
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.FAILED
    assert result.targets[0].native_payload["output"] == ("native", "r1")
    assert "PRIVATE_STORAGE_SENTINEL" not in repr(result)
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(effects.calls) == 1


@pytest.mark.parametrize("failure", ["native", "journal"])
def test_entry_uncertainty_never_contaminates_unentered_selected_target(composed, failure):
    service, host, request, sources, effects = composed
    request = replace(request, scope=c.Scope(("r1", "r2")))
    sources.value = replace(sources.value, request=request)
    grant = host.review(service, request)
    if failure == "native":
        def lost_native():
            raise RuntimeError("PRIVATE_NATIVE_LOSS")

        effects.before_return = lost_native
    else:
        original = host._memory.compare_replace

        def lost_journal(resource_id, expected_revision, record):
            if record.revision > 0:
                raise RuntimeError("PRIVATE_JOURNAL_LOSS")
            return original(resource_id, expected_revision, record)

        host._memory.compare_replace = lost_journal
    result = service.execute(request, grant)
    first, second = result.targets
    assert first.attempted is True
    assert first.remote_state == ("uncertain" if failure == "native" else "unchanged")
    assert second.attempted is False
    assert second.status == c.OutcomeStatus.BLOCKED
    assert second.remote_state == "unchanged"
    assert second.unapplied_effects == ("gather",)
    assert len(effects.calls) == 1
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(effects.calls) == 1


def test_fixed_local_resolve_preserves_actual_single_occurrence_with_empty_targets(composed):
    service, host, request, sources, effects = composed
    request = replace(
        request, operation="vault.resolve-for-run", scope=c.Scope(()),
    )
    sources.value = replace(sources.value, request=request)
    result = service.execute(request, host.review(service, request))
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    assert len(result.steps) == 1
    assert result.steps[0].step_id == request.operation_id + ":0"
    assert result.steps[0].attempted is True
    assert result.steps[0].native_payload["output"] == ("native", "local")
    assert result.targets == ()
    assert len(effects.calls) == 1
    assert effects.calls[0].kind == "resolve-for-run"
    assert c.OperationOutcome.from_json(c.canonical_bytes(result)) == result
    assert service.execute(request).status == c.OutcomeStatus.BLOCKED
    assert len(effects.calls) == 1


def test_private_resolve_fixed_entry_requires_actual_pending_permit(composed):
    from netops.ansible.policy.authorization import bind_plan

    service, host, request, sources, effects = composed
    request = replace(request, operation="vault.resolve-for-run", scope=c.Scope(()))
    sources.value = replace(sources.value, request=request)
    plan, inputs = host._load(service, request)
    effect = plan.effects[0]
    binding = c.EffectBinding(
        bind_plan(plan, inputs.root_ref, inputs.generation), str(uuid4()), 0,
        effect.occurrence_id, effect.target_id, effect.step_id, (),
    )
    with pytest.raises(RuntimeError, match="consent-stale"):
        host._resolve_for_run(object(), binding, plan, effect)
    assert effects.calls == []
