"""Author controls over the real accepted broker and inert file-port handlers.

These are fake-effect unit controls, not platform or installer qualification.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event
from unittest.mock import Mock
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import AuthorizationError, lifecycle_plan_digest
from netops.dependencies.service import (
    ADAPTERS,
    DependencyRegistry,
    DependencyService,
)
from tests.policy.test_lifecycle_execution import D, environment
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_dependency_probes import FixtureAdapter


class Cancel:
    def __init__(self):
        self.value = False

    def is_cancelled(self):
        return self.value

    def wait(self, timeout):
        return self.value


def product_service(tmp_path, policy, action="dependency-stage", *, categories=()):
    env = environment(tmp_path, policy, action, categories=categories)
    plan, _, port, state, review, consent, broker, clock, executor = env
    registry = DependencyRegistry.load()
    # Explicit fixture identity, not a packaged-registry qualification assertion.
    registry.digest = D
    adapter = FixtureAdapter()
    service = DependencyService(
        registry, dict.fromkeys(ADAPTERS, adapter), state, policy[1], broker, clock, Mock(),
    )
    context = c.InstallContext(c.Context(
        "controller", D, "fixture", D, policy[0], D, D,
    ))
    service.plan(c.InstallScope(("native.stdlib",), (), False, False), context)
    context_digest = c.digest(context)
    root = port.read("facts")
    port.seed("facts", {**dict(root.payload), "context_digest": context_digest})
    if plan.content["verification"] is not None:
        verification = dict(plan.content["verification"])
        verification["context_digest"] = context_digest
        verification["probes"] = tuple(
            c.public_object({**dict(probe), "context_digest": context_digest})
            for probe in verification["probes"]
        )
        port.seed("verification", verification)
        plan = replace(plan, content=c.public_object({
            **dict(plan.content), "verification": verification,
        }))
    changes = {"context_digest": context_digest}
    if type(plan) is lc.InstallPlan:
        changes["scope"] = c.InstallScope(("native.stdlib",), (), False, False)
    plan = replace(plan, **changes)
    plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    return service, plan, context, port, state, review, consent, broker, clock


def test_catalog_preview_is_not_an_executable_install_plan(tmp_path, policy):
    service, _, context, port, *_ = product_service(tmp_path, policy)
    preview = service.plan(c.InstallScope(("native.stdlib",), (), False, False), context)
    before = len(port.writes)
    with pytest.raises(c.ContractError):
        service.provision(preview, lc.InstallConsent(), Cancel())
    assert len(port.writes) == before


def test_restore_metadata_enumeration_is_bounded_before_generation_reads(tmp_path, policy):
    service, _, context, port, *_ = product_service(tmp_path, policy)
    facts = port.read("facts")
    port.seed("facts", {**dict(facts.payload), "generation_refs": ("missing",) * 129})
    before = len(port.writes)
    with pytest.raises(c.ContractError):
        service.plan_restore(str(uuid4()), context)
    assert len(port.writes) == before


def test_restore_metadata_deadline_stops_before_pointer_or_generation_reads(tmp_path, policy):
    service, _, context, port, _, _, _, _, clock = product_service(tmp_path, policy)
    original = port.read
    reads = []

    def expired_read(resource):
        reads.append(resource)
        result = original(resource)
        clock.value = 71.0
        return result

    port.read = expired_read
    with pytest.raises(AuthorizationError):
        service.plan_restore(str(uuid4()), context)
    assert reads == ["facts"]
    assert not port.writes


def test_service_runs_actual_private_consent_stage_once(tmp_path, policy):
    service, plan, _, port, state, _, consent, *_ = product_service(tmp_path, policy)
    receipt = consent.review(plan, 10.0, 20.0)
    result = service.provision(plan, receipt, Cancel())
    assert result.status == c.OutcomeStatus.PARTIAL
    assert result.steps[0].status == c.OutcomeStatus.SUCCEEDED
    assert state.artifact("destination")
    before = len(port.writes)
    replay = service.provision(plan, receipt, Cancel())
    assert replay.status == c.OutcomeStatus.BLOCKED
    assert replay.errors[0].reason == c.ReasonCode.CONSENT_STALE
    assert len(port.writes) == before
    assert result.active_generation_id == "old"
    assert result.readiness.companion == "not-requested"
    assert result.errors[0].reason == c.ReasonCode.DEPENDENCY_NOT_READY
    assert result.pending_actions == ("review-activation-plan",)


@pytest.mark.parametrize("kind", ("provision", "uninstall", "restore"))
def test_wrong_concrete_plan_rejects_before_state_io(tmp_path, policy, kind):
    service, plan, _, port, *_ = product_service(tmp_path, policy)
    before = len(port.writes)
    other = object() if kind == "provision" else plan
    with pytest.raises(c.ContractError):
        if kind == "uninstall":
            service.uninstall(other, lc.InstallConsent())
        else:
            getattr(service, kind)(other, lc.InstallConsent(), Cancel())
    assert len(port.writes) == before


def test_forged_consent_never_enters_a_handler(tmp_path, policy):
    service, plan, _, port, *_ = product_service(tmp_path, policy)
    result = service.provision(plan, lc.InstallConsent(), Cancel())
    assert result.status == c.OutcomeStatus.BLOCKED
    assert not result.uncertain
    assert not port.writes
    assert not service._lifecycle._plans


def test_unknown_selected_capability_does_not_leak_the_service_writer_lock(tmp_path, policy):
    service, plan, _, port, _, _, consent, *_ = product_service(tmp_path, policy)
    invalid = replace(
        plan, plan_id=str(uuid4()),
        scope=c.InstallScope(("unregistered.capability",), (), False, False),
    )
    invalid = replace(invalid, plan_digest=lifecycle_plan_digest(invalid))
    rejected = service.provision(invalid, consent.review(invalid, 10.0, 20.0), Cancel())
    assert rejected.status == c.OutcomeStatus.FAILED
    assert not port.writes
    assert not service._lifecycle._plans
    result = service.provision(plan, consent.review(plan, 10.0, 20.0), Cancel())
    assert result.steps[0].status == c.OutcomeStatus.SUCCEEDED


def test_cancel_before_entry_preserves_active_pointer(tmp_path, policy):
    service, plan, _, port, state, _, consent, *_ = product_service(tmp_path, policy)
    cancel = Cancel()
    cancel.value = True
    result = service.provision(plan, consent.review(plan, 10.0, 20.0), cancel)
    assert result.status == c.OutcomeStatus.CANCELLED
    assert state.pointer().active_generation_id == "old"
    assert not port.writes
    assert not result.uncertain


@pytest.mark.parametrize("category", (
    "elevation", "wsl-change", "vm-change", "reboot", "runtime-install", "security-change",
))
def test_each_consequential_category_remains_a_separate_prompt(tmp_path, policy, category):
    service, plan, _, port, _, review, consent, *_ = product_service(
        tmp_path, policy, categories=(category,),
    )
    review.denied = category
    with pytest.raises(AuthorizationError):
        consent.review(plan, 10.0, 20.0)
    assert review.prompts == [category]
    assert not port.writes
    # Generic assent cannot fill the missing category.
    result = service.provision(plan, lc.InstallConsent(), Cancel())
    assert result.status == c.OutcomeStatus.BLOCKED
    assert not port.writes


def test_state_drift_after_consent_is_not_authority_reuse(tmp_path, policy):
    service, plan, _, port, state, _, consent, *_ = product_service(tmp_path, policy)
    receipt = consent.review(plan, 10.0, 20.0)
    root = port.read("facts")
    pointer = dict(root.payload["pointer"])
    pointer["revision"] += 1
    port.seed("facts", {**dict(root.payload), "pointer": pointer})
    result = service.provision(plan, receipt, Cancel())
    assert result.status == c.OutcomeStatus.BLOCKED
    assert state.pointer().revision == pointer["revision"]
    assert not port.writes


def test_original_error_survives_pointer_read_cleanup_failure(tmp_path, policy):
    service, plan, _, port, _, _, consent, *_ = product_service(tmp_path, policy)
    receipt = consent.review(plan, 10.0, 20.0)
    port.fail_reads = True
    result = service.provision(plan, receipt, Cancel())
    assert result.status == c.OutcomeStatus.FAILED
    assert result.errors
    assert result.cleanup_errors[0].reason == c.ReasonCode.OWNERSHIP_INVALID
    assert result.uncertain
    assert result.status != c.OutcomeStatus.SUCCEEDED


def test_sink_failures_do_not_change_real_stage_outcome(tmp_path, policy, monkeypatch):
    service, plan, _, _, _, _, consent, *_ = product_service(tmp_path, policy)
    service.events.emit.side_effect = RuntimeError("PRIVATE-SENTINEL")
    import netops.dependencies._lifecycle as lifecycle

    monkeypatch.setattr(lifecycle._LOG, "info", Mock(side_effect=RuntimeError("PRIVATE-SENTINEL")))
    result = service.provision(plan, consent.review(plan, 10.0, 20.0), Cancel())
    assert result.status == c.OutcomeStatus.PARTIAL
    assert result.steps[0].status == c.OutcomeStatus.SUCCEEDED
    assert "PRIVATE-SENTINEL" not in repr(result)


def test_resume_cannot_replay_original_review(tmp_path, policy):
    service, plan, _, port, _, _, consent, *_ = product_service(tmp_path, policy)
    receipt = consent.review(plan, 10.0, 20.0)
    service.provision(plan, receipt, Cancel())
    before = len(port.writes)
    with pytest.raises(AuthorizationError):
        service.resume(plan.lifecycle_id, receipt, Cancel())
    assert len(port.writes) == before


def test_restore_id_validation_precedes_host_io(tmp_path, policy):
    service, _, context, port, *_ = product_service(tmp_path, policy)
    port.fail_reads = True
    with pytest.raises(c.ContractError):
        service.plan_restore("../not-a-generation", context)
    assert not port.writes


def test_service_uninstall_tombstones_only_the_reviewed_owned_resource(tmp_path, policy):
    service, plan, _, port, state, _, consent, *_ = product_service(
        tmp_path, policy, "dependency-uninstall",
    )
    unknown = port.seed("user-inventory-vault-and-settings", {"sentinel": "keep"})
    source = port.read("source")
    result = service.uninstall(plan, consent.review(plan, 10.0, 20.0))
    assert result.status == c.OutcomeStatus.SUCCEEDED, (
        result.errors, result.cleanup_errors, result.uncertain,
    )
    assert port.read("user-inventory-vault-and-settings") == unknown
    assert port.read("source") == source
    assert port.read("destination").payload["removed_digest"] == plan.generation.manifest_digest
    assert state.pointer().active_generation_id == "old"
    assert result.remote_state == "not-requested"


def test_unowned_destination_blocks_without_adoption_or_cleanup(tmp_path, policy):
    service, plan, _, port, state, _, consent, *_ = product_service(tmp_path, policy)
    review = consent.review(plan, 10.0, 20.0)
    destination = port.read("destination")
    port.seed("destination", destination.payload, owner="2" * 64)
    result = service.provision(plan, review, Cancel())
    assert result.status == c.OutcomeStatus.FAILED
    assert result.errors[0].reason == c.ReasonCode.OWNERSHIP_INVALID
    assert state.pointer().active_generation_id == "old"
    assert not port.writes


def test_two_public_service_writers_do_not_enter_the_handler_twice(tmp_path, policy, monkeypatch):
    service, plan, _, port, state, _, consent, *_ = product_service(tmp_path, policy)
    entered, finish = Event(), Event()
    original = state.copy_artifact
    calls = []

    def held_copy(*args):
        calls.append(args)
        entered.set()
        assert finish.wait(5.0)
        return original(*args)

    monkeypatch.setattr(state, "copy_artifact", held_copy)
    first_review = consent.review(plan, 10.0, 20.0)
    second_review = consent.review(plan, 10.0, 20.0)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(service.provision, plan, first_review, Cancel())
        try:
            assert entered.wait(5.0)
            second = service.provision(plan, second_review, Cancel())
            assert second.errors[0].reason == c.ReasonCode.RESOURCE_BUSY
            assert second.status == c.OutcomeStatus.BLOCKED
        finally:
            finish.set()
        assert first.result(timeout=5.0).steps[0].status == c.OutcomeStatus.SUCCEEDED
    assert len(calls) == 1
    assert state.pointer().active_generation_id == "old"
    assert any(resource == "destination" for resource, _, _ in port.writes)


def test_install_step_log_and_counter_have_bounded_labels_and_safe_context(tmp_path, policy, caplog):
    service, plan, _, _, _, _, consent, *_ = product_service(tmp_path, policy)
    with caplog.at_level("INFO", logger="netops.dependencies._lifecycle"):
        service.provision(plan, consent.review(plan, 10.0, 20.0), Cancel())
    logs = [record for record in caplog.records if record.msg == "install.step"]
    assert len(logs) == 1
    log = logs[0]
    assert log.metric_name == "netops.install.step.count"
    assert log.metric_value == 1 and log.step_kind == "dependency-stage"
    assert log.operation_id == plan.lifecycle_id
    assert log.context_digest == plan.context_digest
    assert "operation_id" not in log.metric_labels
    assert "context_digest" not in log.metric_labels
    event = service.events.emit.call_args.args[0]
    assert event.operation_id == log.operation_id
    assert event.status.value == log.status
