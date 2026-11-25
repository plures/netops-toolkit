"""Criteria-derived public terminal safety proofs, never platform qualification."""

from dataclasses import replace
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    TrustedConsentAdapter,
    TrustedLifecycleConsentAdapter,
)
from netops.dependencies._composition import ManagedLifecycleState
from netops.dependencies._recovery import RecoverySelection
from netops.dependencies._restore import ManagedQualification
from netops.dependencies.service import ADAPTERS, DependencyService
from tests.test_nov19_independent_controller_execution import Cancel
from tests.test_nov19_independent_dependency_lifecycle import OWNER
from tests.test_nov19_successor_public_installer import (
    GENERATION,
    MEMBER_BYTES,
    managed_environment,
    staged,
)


def activate(env, cancel=None):
    service = env["service"]
    plan = service.plan(env["scope"], env["context"])
    consent = service.review(plan, env["clock"].now, 30.0)
    return service.provision(plan, consent, cancel or Cancel())


def test_normal_public_activation_has_terminal_success_and_canonical_pointer_record():
    env = managed_environment()
    staged(env)
    outcome = activate(env)
    assert outcome.status == c.OutcomeStatus.SUCCEEDED, c.canonical_bytes(outcome).decode()
    assert not outcome.pending_actions and not outcome.errors and not outcome.cleanup_errors
    assert outcome.active_generation_id == GENERATION and outcome.pointer_revision == 1
    assert outcome.readiness == c.ReadinessProjection("ready", "not-requested", "not-requested")
    events = [
        record.payload["event"] for resource, _, record in env["records"].writes
        if resource.startswith("dependency-lifecycle-event-")
    ]
    assert events[-1]["kind"] == "Activated"
    assert [e["kind"] for e in events].count("CandidateVerified") == 1
    assert env["state"].pointer().active_generation_id == GENERATION
    assert len(env["transport"].calls) == 1 and env["files"].calls.count("stage") == 1


def test_post_cas_cancel_reports_actual_active_generation_without_reverse():
    env = managed_environment()
    staged(env)
    cancel = Cancel()
    port = env["records"]
    original = port.compare_replace
    pointer_writes = []

    def replace_record(resource, expected, record):
        before = port.records.get(resource)
        result = original(resource, expected, record)
        if resource == "managed-control" and before.payload["pointer"] != record.payload["pointer"]:
            pointer_writes.append(record.payload["pointer"])
            cancel.value = True
        return result

    port.compare_replace = replace_record
    result = activate(env, cancel)
    assert result.status != c.OutcomeStatus.SUCCEEDED
    assert result.active_generation_id == GENERATION and result.pointer_revision == 1
    assert result.previous_generation_id is None
    assert len(pointer_writes) == 1, "Post-CAS cancellation cannot implicitly reverse selection"
    assert any(error.reason == c.ReasonCode.CANCELLED for error in result.errors)
    assert env["state"].pointer().active_generation_id == GENERATION
    assert env["files"].calls.count("stage") == 1 and len(env["transport"].calls) == 1


@pytest.mark.parametrize("failure", ["expired", "pointer", "candidate-bytes", "setup-disabled"])
def test_fresh_activation_revalidates_authority_and_candidate_before_cas(failure):
    env = managed_environment()
    staged(env)
    plan = env["service"].plan(env["scope"], env["context"])
    consent = env["service"].review(plan, env["clock"].now, 30.0)
    if failure == "expired":
        env["clock"].now += 31.0
    elif failure == "candidate-bytes":
        env["files"].drift = True
    else:
        record = env["records"].read("managed-control")
        payload = dict(record.payload)
        if failure == "pointer":
            payload["pointer"] = c.wire(lc.AbsentPointer("absent", 1))
        else:
            payload["setup_enabled"] = False
        env["records"].records["managed-control"] = replace(
            record, revision=record.revision + 1, payload=c.public_object(payload),
        )
    pointer = env["state"].pointer()
    try:
        result = env["service"].provision(plan, consent, Cancel())
    except (AuthorizationError, c.ContractError):
        pass
    else:
        assert result.status != c.OutcomeStatus.SUCCEEDED
    assert env["state"].pointer() == pointer
    assert env["files"].calls.count("stage") == 1 and len(env["transport"].calls) == 1


def test_busy_execution_never_stages_or_downloads_and_does_not_steal_lock():
    env = managed_environment()
    service = env["service"]
    plan = service.plan(env["scope"], env["context"])
    consent = service.review(plan, env["clock"].now, 30.0)
    assert env["state"]._execution.acquire(blocking=False)
    try:
        result = service.provision(plan, consent, Cancel())
        assert result.status == c.OutcomeStatus.BLOCKED
        assert result.errors[0].reason == c.ReasonCode.RESOURCE_BUSY
        assert not env["transport"].calls and not env["files"].calls
        assert not env["state"]._execution.acquire(blocking=False)
    finally:
        env["state"]._execution.release()


def test_full_selected_closure_cannot_be_silently_reduced_to_one_registered_asset():
    env = managed_environment()
    scope = c.InstallScope((), (), True, True)
    plan = env["service"].plan(scope, env["context"])
    expected = {
        entry.id for entry in env["service"]._entries(env["service"]._selection(scope), scope)
    }
    assert len(expected) > 1
    assert {step.dependency for step in plan.steps} == expected
    assert plan.blocked and plan.lifecycle is None
    with pytest.raises((c.ContractError, AuthorizationError)):
        env["service"].review(plan, env["clock"].now, 30.0)
    assert not env["records"].writes and not env["transport"].calls


class Runs:
    def __init__(self):
        self.calls = []
        self.enabled = True
        self.before = ()
        self.after = ()
        self.drain_ok = True

    def pins(self):
        return self.after if "drain" in self.calls else self.before

    def stop_admission(self):
        self.enabled = False
        self.calls.append("stop")

    def drain(self, cancel, clock, deadline):
        assert deadline > clock.monotonic()
        self.calls.append("drain")
        return self.drain_ok

    def start_admission(self, generation):
        self.enabled = True
        self.calls.append("start")


def retained_environment():
    """Valid synthetic retained tree and exact pinned descriptor, not Q03 proof.

    No actual platform is certified. The external qualification input is modeled
    as owned immutable historical metadata and its claimed bytes are independently
    rechecked through the real restore algorithm's functional file/probe ports.
    """
    env = managed_environment()
    service, manifest = env["service"], env["manifest"]
    generation = lc.GenerationBinding(
        GENERATION, 0, manifest.content_digest, c.digest(manifest),
    )
    report = service.verify(env["scope"], env["context"])
    item = ManagedQualification(
        generation, env["scope"], env["context"], manifest.consuming_contexts,
        c.digest(report), "e" * 64,
    )
    current = replace(
        manifest, generation_id=str(uuid4()),
        context=c.InstallContext(replace(env["context"].context, source_id="broken-current")),
    )
    records = env["records"]
    records.seed("managed-root", {
        "schema": "i02-managed-generations-v1",
        "root_manifest": {
            "control_resource": "managed-control",
            "registered_manifests": tuple(c.wire(value) for value in (manifest, current)),
            "registered_qualifications": (c.wire(item),),
        },
        "generations": tuple({
            "generation_id": value.generation_id, "manifest": c.wire(value), "state": "staged",
            "plan_digest": "b" * 64, "occurrence_id": "historical-owned-stage",
            "staging_directory": "owned-staging", "directory": "owned-tree",
        } for value in (manifest, current)),
    })
    pointer = lc.PresentPointer("present", current.generation_id, "c" * 64, 2)
    records.seed("managed-control", {
        "schema": "i02-managed-control-v1", "pointer": c.wire(pointer),
        "verification": None, "setup_enabled": True, "installation_id": None,
    })
    selection = RecoverySelection(
        str(uuid4()), str(uuid4()), generation, item.scope, item.context,
        item.consuming_contexts, item.report_digest,
    )
    records.seed("dependency-generation-" + c.digest(generation), {
        "schema": "i02-lifecycle-recovery-v1", "selection": c.wire(selection),
    })
    now = env["clock"].now
    records.seed("dependency-verification-" + c.digest(generation), {
        "schema": "i02-retained-verification-v1", "verification": {
            "kind": "candidate", "event_kind": "CandidateVerified", "event_id": str(uuid4()),
            "revision": 0, "generation_id": GENERATION,
            "content_digest": generation.content_digest, "manifest_digest": generation.manifest_digest,
            "context_digest": c.digest(item.context), "registry_digest": service.registry.digest,
            "policy_digest": service._policy_identity.bundle_sha256,
            "qualification_digest": item.qualification_digest,
            "observed_at": now, "expires_at": now + 60.0,
            "probes": ({
                "probe_id": "dependency-readiness", "generation_id": GENERATION,
                "content_digest": generation.content_digest, "context_digest": c.digest(item.context),
                "result_digest": item.report_digest, "status": "succeeded",
            },),
        },
    })
    runs = Runs()
    runs.before = tuple(c.public_object({
        "generation_id": value.generation_id, "manifest_digest": c.digest(value),
        "revision": 0, "holders": (),
    }) for value in (manifest, current))
    runs.after = runs.before
    env["files"].content = ((manifest.members[0], MEMBER_BYTES),)
    host = ManagedLifecycleState(
        records, "managed-root", "managed-control", OWNER, service._policy_identity,
        (manifest, current), env["files"], env["transport"], (item,), runs,
    )
    private = TrustedLifecycleConsentAdapter(env["review"])
    broker = AuthorizationBroker(
        object(), TrustedConsentAdapter(env["review"]), lifecycle_state=host,
        lifecycle_consent=private,
    )
    fresh = DependencyService(
        service.registry, service.adapters, host, service.policy, broker, env["clock"], env["events"],
    )
    env.update(service=fresh, state=host, runs=runs, old_pointer=pointer, generation=generation)
    return env


def test_restore_plan_for_real_managed_generation_is_readonly_and_not_inert_schema():
    env = retained_environment()
    before = list(env["records"].writes), list(env["files"].calls), list(env["transport"].calls)
    # Public managed restore must not be forced through A02 inert-record validators.
    plan = env["service"].plan_restore(GENERATION, env["context"])
    assert type(plan) is lc.RestorePlan
    assert plan.generation.generation_id == GENERATION
    assert before == (
        list(env["records"].writes), list(env["files"].calls), list(env["transport"].calls),
    )


def test_fresh_service_retained_restore_never_redeploys_or_uses_install_history():
    env = retained_environment()
    service = DependencyService(
        env["service"].registry, dict.fromkeys(ADAPTERS, env["probes"]), env["state"],
        env["service"].policy, env["service"].authorization, env["clock"], env["events"],
    )
    before = len(env["transport"].calls), env["files"].calls.count("stage")
    plan = service.plan_restore(GENERATION, env["context"])
    adapter = service.authorization._lifecycle_consent
    consent = adapter.review(plan, env["clock"].now, 30.0)
    result = service.restore(plan, consent, Cancel())
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert result.active_generation_id == GENERATION
    assert result.previous_generation_id == env["old_pointer"].active_generation_id
    assert result.pointer_revision == 3
    assert env["runs"].calls == ["stop", "drain", "start"] and env["runs"].enabled
    assert (len(env["transport"].calls), env["files"].calls.count("stage")) == before
    assert env["files"].calls and all(call == "verify" for call in env["files"].calls)


@pytest.mark.parametrize("failure", ["pre-cancel", "drain", "pins", "post-cancel", "postcheck"])
def test_retained_restore_races_and_failures_never_reverse_or_redeploy(failure):
    env = retained_environment()
    service, records, runs = env["service"], env["records"], env["runs"]
    plan = service.plan_restore(GENERATION, env["context"])
    consent = service.authorization._lifecycle_consent.review(plan, env["clock"].now, 30.0)
    cancel = Cancel()
    original_cas, original_verify = records.compare_replace, env["files"].verify
    changes = []
    if failure == "pre-cancel":
        cancel.value = True
    elif failure == "drain":
        runs.drain_ok = False
    elif failure == "pins":
        runs.after = (
            c.public_object({**dict(runs.before[0]), "manifest_digest": "f" * 64, "revision": 1}),
            runs.before[1],
        )

    def cas(resource, expected, record):
        old = records.records.get(resource)
        result = original_cas(resource, expected, record)
        if resource == "managed-control" and old.payload["pointer"] != record.payload["pointer"]:
            changes.append(record.payload["pointer"])
            if failure == "post-cancel":
                cancel.value = True
        return result

    def verify(*args):
        if failure == "postcheck" and changes:
            raise PermissionError("synthetic functional retained postcheck failure")
        original_verify(*args)

    records.compare_replace, env["files"].verify = cas, verify
    result = service.restore(plan, consent, cancel)
    assert result.status != c.OutcomeStatus.SUCCEEDED
    committed = failure in ("post-cancel", "postcheck")
    assert len(changes) == int(committed)
    assert result.active_generation_id == (
        GENERATION if committed else env["old_pointer"].active_generation_id
    )
    assert result.pointer_revision == (3 if committed else 2)
    if committed:
        assert result.steps[0].status == c.OutcomeStatus.SUCCEEDED
        assert not runs.enabled and env["state"]._control().payload["admission_enabled"] is False
        assert result.pending_actions == ("review-new-exact-restore",)
    assert not env["transport"].calls and "stage" not in env["files"].calls


@pytest.mark.parametrize("corrupt", ["manifest", "qualification", "context", "owner", "expired"])
def test_corrupt_retained_candidate_is_readonly_blocked_not_auto_repaired(corrupt):
    env = retained_environment()
    resource = "dependency-verification-" + c.digest(env["generation"])
    record = env["records"].read(resource)
    data = dict(record.payload["verification"])
    if corrupt == "owner":
        env["records"].records[resource] = replace(record, ownership_token="f" * 64)
    else:
        field = {
            "manifest": "manifest_digest", "qualification": "qualification_digest",
            "context": "context_digest", "expired": "expires_at",
        }[corrupt]
        if corrupt == "expired":
            # Keep the historical receipt structurally valid. Expire it by
            # advancing the host clock, not by corrupting expiry < observed_at.
            env["clock"].now += 61.0
        else:
            data[field] = "f" * 64
        env["records"].records[resource] = replace(
            record, payload=c.public_object({**dict(record.payload), "verification": data}),
        )
    with pytest.raises((AuthorizationError, c.ContractError, ValueError)):
        env["service"].plan_restore(GENERATION, env["context"])
    assert not env["records"].writes and not env["transport"].calls and not env["files"].calls


@pytest.mark.parametrize("generation", ["", "not-a-uuid", str(uuid4())])
def test_invalid_or_unknown_restore_selection_never_acquires_assets(generation):
    env = managed_environment()
    with pytest.raises((c.ContractError, AuthorizationError)):
        env["service"].plan_restore(generation, env["context"])
    assert not env["records"].writes and not env["transport"].calls and not env["files"].calls
