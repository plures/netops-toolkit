"""Actual native owners on inert selected connections, never device qualification."""

import hashlib
from contextlib import contextmanager
from dataclasses import replace
from uuid import uuid4

import pytest

from netops.change.push import run_push
from netops.core.connection import ConnectionParams
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed
from tests.test_workflow_execution import policy as policy
from tests.test_workflow_policy_alignment import backup_composed as backup_composed


class Device:
    def __init__(self):
        self.config = "hostname before\n"
        self.writes = []
        self.fail_apply = False

    def send(self, command):
        assert command == "show running-config"
        return self.config

    def send_config(self, commands):
        self.writes.append(tuple(commands))
        self.config = "\n".join(commands) + "\n"
        if self.fail_apply:
            raise RuntimeError("PRIVATE_DEVICE_FAILURE")
        return "PRIVATE_RAW_OUTPUT"


class Hooks:
    def __init__(self, device):
        self.device = device
        self.cancelled = False
        self.snapshots = []
        self.confirmed = False

    @contextmanager
    def connect(self, params):
        yield self.device

    def check(self):
        if self.cancelled:
            raise RuntimeError("cancelled")

    def prestate(self, content):
        self.snapshots.append(content)
        assert content == "hostname before\n"

    def mutating(self):
        self.check()

    def confirm(self, before, after):
        self.check()
        self.confirmed = after == "hostname after\n"
        return self.confirmed


def test_native_owner_uses_exact_injected_connection_snapshot_and_confirmation():
    device = Device()
    hooks = Hooks(device)
    record = run_push(
        ConnectionParams(host="192.0.2.1"), ["hostname after"], commit=True, hooks=hooks,
    )
    assert device.writes == [("hostname after",)]
    assert hooks.snapshots == ["hostname before\n"]
    assert hooks.confirmed is True
    assert record.committed is True and record.confirmed is True
    assert record.pre_config == "" and record.post_config is None and record.diff is None
    assert "PRIVATE" not in repr(record)


def test_native_guarded_failure_does_not_log_raw_exception_or_revert_without_permit(caplog):
    device = Device()
    device.fail_apply = True
    record = run_push(
        ConnectionParams(host="192.0.2.1"), ["hostname after"], commit=True, hooks=Hooks(device),
    )
    assert device.writes == [("hostname after",)]
    assert record.error == "apply-failed"
    assert record.rolled_back is False
    assert "PRIVATE_DEVICE_FAILURE" not in caplog.text
    assert "PRIVATE_DEVICE_FAILURE" not in repr(record)


def test_native_cancel_before_write_does_not_start_mutation():
    device = Device()
    hooks = Hooks(device)
    hooks.cancelled = True
    record = run_push(
        ConnectionParams(host="192.0.2.1"), ["hostname after"], commit=True, hooks=hooks,
    )
    assert device.writes == []
    assert record.committed is False


def test_native_guarded_path_rejects_raw_audit_before_any_io():
    device = Device()
    with pytest.raises(ValueError, match="guarded-output-required"):
        run_push(
            ConnectionParams(host="192.0.2.1"), ["hostname after"], commit=True,
            hooks=Hooks(device), changelog_path="forbidden-audit",
        )
    assert device.writes == []


@pytest.fixture
def mutation(backup_composed):
    from netops.ansible import contracts as c
    from netops.ansible.execution import EffectResult, _RecoveryQualification
    from netops.change.push import _rollback_to, _snapshot_config

    service, host, backup, sources, backend, fs = backup_composed
    device = Device()
    measured = {}
    connection_calls = []
    after_write = []
    originals = replace(sources.value, settings=replace(
        sources.value.settings, ansible=replace(sources.value.settings.ansible, mode="enforce"),
    ))
    inventory = c.canonical_bytes(c.public_object({
        "devices": {"r1": {"host": "192.0.2.1", "vendor": "cisco_ios"},
                    "r2": {"host": "192.0.2.2", "vendor": "cisco_ios"}},
    }))
    inventory_ref = c.InputRef("inventory", "owned-inventory", hashlib.sha256(inventory).hexdigest())
    inventory_source = c.InputSource(inventory_ref, "json", inventory, "parser-1", "vendor-1")
    backup = replace(
        backup, inputs=(inventory_ref,), scope=c.Scope(("r1",)),
        output_intent=c.OutputIntent(("text",), "owned", retention=True),
    )
    readings = {}

    def reload(operation_id):
        sources.calls += 1
        return readings[operation_id]

    sources.reload = reload
    readings[backup.operation_id] = replace(originals, request=backup, sources=(inventory_source,))

    def collect(plan, effect, cancel):
        backend.entered(effect)
        measured[effect.target_id] = _snapshot_config(device, "cisco_ios").encode()
        return EffectResult(c.StepOutcome(
            effect.occurrence_id, c.OutcomeStatus.SUCCEEDED, True,
            native_payload=c.public_object({"success": True, "config_available": True}),
        ))

    def backup_content(plan, effect, cancel):
        backend.entered(effect)
        return measured[effect.target_id]

    @contextmanager
    def connection(plan, effect):
        assert any(
            binding.occurrence_id == effect.occurrence_id and permit in host._entered
            for permit, (binding, _) in host._pending.items()
        )
        connection_calls.append((plan.operation_id, effect.kind, effect.target_id))
        yield device

    backend.collect = collect
    backend.backup_content = backup_content
    backend.mutation_connection = connection
    result = service.execute(backup, host.review(service, backup))
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    assert measured["r1"] == fs.content == b"hostname before\n"
    descriptor, _ = host._publications[backup.operation_id][0]

    # Measure a real native restore roundtrip on a separate inert selected
    # transport. This is native-hook qualification only, not a vendor claim.
    qualification_device = Device()
    qualification_device.config = "hostname changed\n"
    _rollback_to(qualification_device, "cisco_ios", measured["r1"].decode())
    qualification_bytes = _snapshot_config(qualification_device, "cisco_ios").encode()
    assert qualification_bytes == measured["r1"]
    route = c.public_object({
        "target_id": "r1", "resolved": True, "host": "192.0.2.1", "port": 22,
        "vendor": "cisco_ios", "transport": "ssh", "controller_id": backup.context.controller_id,
        "route_digest": backup.context.route_digest,
    })
    qualification = _RecoveryQualification(
        "r1", c.digest(backup.context), c.digest((route,)), descriptor.digest,
        hashlib.sha256(qualification_bytes + c.canonical_bytes(
            c.public_object({"writes": qualification_device.writes}),
        )).hexdigest(), 100.0,
    )
    intent = c.canonical_bytes(c.public_object({
        "kind": "configuration", "commands": ("hostname after",),
        "expected_digest": hashlib.sha256(b"hostname after\n").hexdigest(),
        "prestate": {"r1": descriptor.ref},
    }))
    intent_ref = c.InputRef("intent", "owned-intent", hashlib.sha256(intent).hexdigest())
    observation = c.Observation(
        "measured-backup", "r1", c.digest(backup.context), backup.context.route_digest,
        backup.context.controller_id, inventory_ref, inventory_ref.digest,
        "2026-11-18T19:00:00Z", 0.0,
    )
    input_sources = (
        replace(inventory_source, observations=(observation,)),
        c.InputSource(intent_ref, "json", intent, "parser-1", "vendor-1"),
    )
    apply = replace(
        backup, operation_id=str(uuid4()), operation="config.apply", mode=c.Mode.APPLY,
        inputs=(inventory_ref, intent_ref), output_intent=c.OutputIntent(),
    )
    rollback = replace(apply, operation_id=str(uuid4()), operation="config.rollback", mode=c.Mode.ROLLBACK)
    for request in (apply, rollback):
        readings[request.operation_id] = replace(
            originals, request=request, sources=input_sources,
            recovery_qualifications=(qualification,),
        )

    original_send = device.send_config

    def write(commands):
        output = original_send(commands)
        if after_write:
            after_write.pop(0)()
        return output

    device.send_config = write
    return service, host, apply, rollback, readings, device, connection_calls, after_write, fs


def test_actual_admitted_native_apply_and_explicit_rollback_preserve_protected_prestate(mutation):
    from netops.ansible import contracts as c

    service, host, apply, rollback, readings, device, calls, _, fs = mutation
    recovery_grant = host.review(service, rollback)
    grant = host.review(service, apply, recovery=(recovery_grant,))
    result = service.execute(apply, grant)
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    assert device.config == "hostname after\n"
    assert device.writes == [("hostname after",)]
    assert result.targets[0].remote_state == "confirmed"
    restored = service.execute(rollback, recovery_grant)
    assert restored.status == c.OutcomeStatus.SUCCEEDED, restored
    assert restored.targets[0].remote_state == "rolled-back"
    assert device.config == "hostname before\n"
    assert device.writes == [("hostname after",), ("hostname before",)]
    assert fs.content == b"hostname before\n"
    assert [kind for _, kind, _ in calls] == ["apply", "rollback"]
    assert "hostname before" not in repr(result)
    assert service.execute(apply, grant).status == c.OutcomeStatus.BLOCKED
    assert len(device.writes) == 2


def test_failed_native_apply_uses_distinct_preapproved_recovery_and_retains_primary_error(mutation):
    from netops.ansible import contracts as c

    service, host, apply, rollback, readings, device, calls, after_write, _ = mutation
    recovery_grant = host.review(service, rollback)
    grant = host.review(service, apply, recovery=(recovery_grant,))
    after_write.append(lambda: setattr(device, "config", "hostname unexpected\n"))
    result = service.execute(apply, grant)
    assert result.status == c.OutcomeStatus.FAILED, result
    assert result.steps[0].errors[0].reason == c.ReasonCode.APPLY_FAILED
    assert result.steps[0].native_payload["recovery_status"] == "succeeded", result
    assert result.targets[0].remote_state == "rolled-back"
    assert device.config == "hostname before\n"
    assert device.writes == [("hostname after",), ("hostname before",)]
    assert [kind for _, kind, _ in calls] == ["apply", "rollback"]
    assert apply.operation_id != rollback.operation_id


def test_cancellation_after_issued_apply_can_only_use_prior_specific_recovery(mutation):
    from netops.ansible import contracts as c

    service, host, apply, rollback, readings, device, calls, after_write, _ = mutation
    recovery_grant = host.review(service, rollback)
    grant = host.review(service, apply, recovery=(recovery_grant,))
    after_write.append(lambda: service.cancel(apply.operation_id))
    result = service.execute(apply, grant)
    assert result.status == c.OutcomeStatus.FAILED, result
    assert device.writes == [("hostname after",), ("hostname before",)]
    assert result.steps[0].native_payload["recovery_status"] == "succeeded"
    assert host.authorization.is_revoked(apply.operation_id)
    assert result.targets[0].remote_state == "rolled-back"


def test_missing_specific_recovery_never_promises_or_starts_apply(mutation):
    service, host, apply, _, _, device, calls, _, _ = mutation
    with pytest.raises(RuntimeError, match="consent-required"):
        host.review(service, apply)
    assert device.writes == [] and calls == []


@pytest.mark.parametrize("damage", ["prestate", "qualification", "route"])
def test_fresh_prestate_qualification_or_route_drift_blocks_all_mutation(mutation, damage):
    from netops.ansible import contracts as c

    service, host, apply, rollback, readings, device, calls, _, fs = mutation
    recovery_grant = host.review(service, rollback)
    grant = host.review(service, apply, recovery=(recovery_grant,))
    if damage == "prestate":
        fs.content = b"PRIVATE_SWAPPED_CONFIG"
    elif damage == "qualification":
        readings[apply.operation_id] = replace(readings[apply.operation_id], recovery_qualifications=())
    else:
        readings[apply.operation_id] = replace(readings[apply.operation_id], request=replace(
            apply, context=replace(apply.context, route_digest="f" * 64),
        ))
    result = service.execute(apply, grant)
    assert result.status == c.OutcomeStatus.BLOCKED, result
    assert all(not target.attempted for target in result.targets)
    assert device.writes == [] and calls == []
    assert "PRIVATE_SWAPPED_CONFIG" not in repr(result)


def test_running_prestate_drift_is_measured_before_write_not_recovered_by_exception(mutation):
    from netops.ansible import contracts as c

    service, host, apply, rollback, _, device, calls, _, _ = mutation
    recovery_grant = host.review(service, rollback)
    grant = host.review(service, apply, recovery=(recovery_grant,))
    device.config = "hostname external-change\n"
    result = service.execute(apply, grant)
    assert result.status == c.OutcomeStatus.FAILED, result
    assert device.writes == []
    assert result.targets[0].remote_state == "unchanged"
    assert [kind for _, kind, _ in calls] == ["apply"]
    assert result.steps[0].native_payload["issued"] is False


def test_failed_apply_and_failed_recovery_are_both_factual_and_never_false_success(mutation, caplog):
    from netops.ansible import contracts as c

    service, host, apply, rollback, _, device, calls, _, _ = mutation
    recovery_grant = host.review(service, rollback)
    grant = host.review(service, apply, recovery=(recovery_grant,))
    device.fail_apply = True
    result = service.execute(apply, grant)
    assert result.status == c.OutcomeStatus.FAILED, result
    assert result.steps[0].errors[0].reason == c.ReasonCode.APPLY_FAILED
    assert result.steps[0].native_payload["recovery_status"] == "failed"
    assert result.steps[0].native_payload["recovery"]["status"] == "failed"
    assert result.targets[0].remote_state == "uncertain"
    assert device.writes == [("hostname after",), ("hostname before",)]
    assert [kind for _, kind, _ in calls] == ["apply", "rollback"]
    assert "PRIVATE_DEVICE_FAILURE" not in caplog.text
    assert service.execute(apply, grant).status == c.OutcomeStatus.BLOCKED
    assert len(device.writes) == 2


def test_cancel_before_dispatch_never_uses_recovery_as_permission_to_apply(mutation):
    from netops.ansible import contracts as c

    service, host, apply, rollback, _, device, calls, _, _ = mutation
    recovery_grant = host.review(service, rollback)
    grant = host.review(service, apply, recovery=(recovery_grant,))
    service.cancel(apply.operation_id)
    result = service.execute(apply, grant)
    assert result.status == c.OutcomeStatus.BLOCKED
    assert device.writes == [] and calls == []
    assert result.targets[0].remote_state == "unchanged"


def test_expired_original_recovery_deadline_cannot_start_a_new_revert(mutation):
    from netops.ansible import contracts as c

    service, host, apply, rollback, _, device, calls, after_write, _ = mutation
    recovery_grant = host.review(service, rollback)
    grant = host.review(service, apply, recovery=(recovery_grant,))

    class Clock:
        def monotonic(self):
            return 1000.0

    after_write.append(lambda: setattr(host, "_clock", Clock()))
    result = service.execute(apply, grant)
    assert result.status == c.OutcomeStatus.FAILED, result
    assert device.writes == [("hostname after",)]
    assert [kind for _, kind, _ in calls] == ["apply"]
    assert result.targets[0].remote_state == "uncertain"
    assert result.steps[0].native_payload["recovery_status"] == "not-attempted"


def test_lost_completion_checkpoint_retains_pending_receipt_without_redispatch(mutation):
    from netops.ansible import contracts as c

    service, host, apply, rollback, _, device, calls, _, _ = mutation
    recovery_grant = host.review(service, rollback)
    grant = host.review(service, apply, recovery=(recovery_grant,))
    original = host._memory.compare_replace

    def compare_replace(resource, revision, record):
        if device.writes and record.revision > 0:
            raise RuntimeError("PRIVATE_CHECKPOINT_LOSS")
        return original(resource, revision, record)

    host._memory.compare_replace = compare_replace
    result = service.execute(apply, grant)
    assert result.status == c.OutcomeStatus.FAILED, result
    assert device.writes == [("hostname after",)]
    pending = tuple(
        (permit, binding) for permit, (binding, _) in host._pending.items()
        if binding.plan.operation_id == apply.operation_id
    )
    assert len(pending) == 1
    assert host.authorization.reconcile(pending[0][0]) == pending[0][1]
    assert service.execute(apply, grant).status == c.OutcomeStatus.BLOCKED
    assert len(device.writes) == 1
    assert "PRIVATE_CHECKPOINT_LOSS" not in repr(result)


def test_fixed_mutation_handler_cannot_be_called_with_plan_or_boolean_permission(mutation):
    from netops.ansible import contracts as c

    service, host, apply, rollback, _, device, calls, _, _ = mutation
    recovery_grant = host.review(service, rollback)
    host.review(service, apply, recovery=(recovery_grant,))
    plan, _ = host._load(service, apply)
    assert plan.recovery_scope
    with pytest.raises(RuntimeError, match=c.ReasonCode.CONSENT_STALE.value):
        host._mutate(True, None, plan, plan.effects[0])
    assert device.writes == [] and calls == []


@pytest.mark.parametrize("operation", ["apply", "rollback"])
def test_native_connection_cleanup_failure_preserves_verified_state_without_extra_mutation(
    mutation, operation, caplog,
):
    from netops.ansible import contracts as c

    service, host, apply, rollback, _, device, calls, _, _ = mutation
    recovery_grant = host.review(service, rollback)
    grant = host.review(service, apply, recovery=(recovery_grant,))
    original = host._backend.mutation_connection

    @contextmanager
    def failing_close(plan, effect):
        with original(plan, effect) as selected:
            yield selected
        raise RuntimeError("PRIVATE_CONNECTION_CLOSE_FAILURE")

    host._backend.mutation_connection = failing_close
    if operation == "rollback":
        device.config = "hostname after\n"
    result = service.execute(
        apply if operation == "apply" else rollback,
        grant if operation == "apply" else recovery_grant,
    )
    assert result.status == c.OutcomeStatus.FAILED
    assert result.cleanup.status == "failed"
    assert result.cleanup.errors[0].reason == c.ReasonCode.CLEANUP_FAILED
    assert result.steps[0].status == c.OutcomeStatus.SUCCEEDED
    assert result.targets[0].remote_state == ("confirmed" if operation == "apply" else "rolled-back")
    assert len(device.writes) == 1
    assert "PRIVATE_CONNECTION_CLOSE_FAILURE" not in repr(result)
    assert "PRIVATE_CONNECTION_CLOSE_FAILURE" not in caplog.text
