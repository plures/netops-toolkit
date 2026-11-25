"""Independent I02 T02/T03/T04/T23/T28/T32 service proofs using fake effect ports."""

from __future__ import annotations

import hashlib
import sys
import threading
from contextlib import contextmanager
from dataclasses import replace
from importlib import resources
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.artifacts import OwnedRecord
from netops.ansible.lifecycle_execution import OwnedLifecycleState
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    TrustedConsentAdapter,
    TrustedLifecycleConsentAdapter,
    lifecycle_plan_digest,
)
from netops.ansible.policy.engine import LocalReferencePolicyEngine
from netops.ansible.policy.lifecycle_evidence import lifecycle_arguments_digest
from netops.ansible.policy.loader import load_policy
from netops.dependencies._lifecycle import InstallOutcome, InstallStepOutcome
from netops.dependencies.service import (
    ADAPTERS,
    ConsumingContext,
    DependencyRegistry,
    DependencyService,
    ProbeResult,
)
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_nov19_independent_controller_execution import Cancel, Events
from tests.test_nov19_independent_credentials import Clock, policy_identity

OWNER = "1" * 64
DATA = b"independent owned inert asset; not a qualified controller"
GENERATION = "52f739c9-53f6-48f4-9c46-8fa170c2f673"
OLD = "d98e3e1a-50d5-48ed-839b-b00daf1d17ea"
SCHEMA = "a02-owned-inert-v1"


class Records:
    """Fake OwnedStatePort with checked immutable records and deterministic CAS hooks."""

    def __init__(self, identity):
        self.identity = identity
        self.records = {}
        self.writes = []
        self.mutex = threading.RLock()
        self.fail_effect = False
        self.fail_cleanup = False
        self.after_pointer = None

    def seed(self, resource, payload, revision=0, owner=OWNER):
        record = OwnedRecord(
            resource, "checkpoint", revision, 0, owner,
            self.identity.bundle_sha256, self.identity.reducer_version,
            c.public_object(payload), self.identity,
        )
        self.records[resource] = record
        return record

    @contextmanager
    def lock(self, resources, timeout):
        with self.mutex:
            yield

    def read(self, resource):
        return self.records[resource]

    def compare_replace(self, resource, expected, record):
        previous = self.records.get(resource)
        if self.fail_effect and resource == "destination":
            if self.fail_cleanup:
                self.records["facts"] = replace(
                    self.records["facts"], ownership_token="2" * 64,
                )
            raise PermissionError("effect denied")
        if previous is None:
            if expected != 0 or record.revision != 0:
                raise AuthorizationError()
        elif previous.revision != expected or record.revision != expected + 1:
            raise AuthorizationError()
        self.records[resource] = record
        self.writes.append((resource, expected, record))
        if (
            resource == "facts" and previous is not None
            and previous.payload["pointer"] != record.payload["pointer"]
            and self.after_pointer is not None
        ):
            self.after_pointer()
        return record


class Review:
    def __init__(self):
        self.decline = None
        self.categories = []

    def confirm(self, plan, binding, deadline):
        raise AssertionError("lifecycle consent must never use operational review")

    def confirm_lifecycle(self, binding, deadline):
        return True

    def confirm_consequential(self, binding, requirement, deadline):
        self.categories.append(requirement.category)
        return requirement.category != self.decline


class Probes:
    """Fake dependency adapter; no subprocess, downloads or OS capability claims."""

    def __init__(self):
        self.calls = []
        self.status = "available"
        self.contexts = {
            "native": ConsumingContext(
                "native", sys.platform, "test-arch", sys.executable, "", "native",
            ),
        }

    def probe(self, entry, context, deadline):
        self.calls.append((entry.id, context.digest, deadline))
        return ProbeResult(
            entry.id, context.digest, self.status,
            "functional-observed" if self.status == "available" else "dependency-missing",
            "test-version", "a" * 64 if self.status == "available" else None,
        )


def environment(action="dependency-stage", categories=()):
    identity, registry, clock = policy_identity(), DependencyRegistry.load(), Clock()
    root = resources.files("netops.ansible.policy")
    engine = LocalReferencePolicyEngine(load_policy(
        root.joinpath("ansible_molecule.px").read_bytes(),
        root.joinpath("ansible_molecule.contracts.px").read_bytes(),
        root.joinpath("bundle.json").read_bytes(), identity,
    ))
    context = c.InstallContext(c.Context(
        "owned-controller", "a" * 64, "inventory", "b" * 64,
        identity, registry.digest, "d" * 64,
    ))
    scope = c.InstallScope(("native.stdlib",), (), False, False)
    port, review, probes, events = Records(identity), Review(), Probes(), Events()
    manifest = c.public_object({"member": "inert-owned-asset"})
    root_manifest = c.public_object({"owner": "independent-test", "schema": "1.0"})
    content_digest, manifest_digest = hashlib.sha256(DATA).hexdigest(), c.digest(manifest)
    generation = lc.GenerationBinding(GENERATION, 2, content_digest, manifest_digest)
    kind = (
        "restore" if action == "restore-active-pointer"
        else "uninstall" if action == "dependency-uninstall" else "install"
    )
    if kind == "uninstall":
        generation = replace(generation, selected=(generation,))
    port.seed("generation", {
        "generation_id": GENERATION, "ordinal": 2, "content": tuple(DATA), "manifest": manifest,
    })
    port.seed("source", {
        "schema": SCHEMA, "content": tuple(DATA), "content_digest": content_digest,
        "manifest": manifest,
    })
    if action in ("dependency-stage", "dependency-download"):
        port.seed("destination", {"schema": SCHEMA, "reserved": True, "manifest": manifest})
    else:
        port.seed("destination", {
            "schema": SCHEMA, "content": tuple(DATA), "content_digest": content_digest,
            "manifest": manifest,
        })
    step = c.public_object({
        "occurrence_id": "owned-effect-0", "generation_id": GENERATION,
        "source": {
            "source_id": "source", "registry_digest": registry.digest,
            "artifact_digest": content_digest, "descriptor_digest": manifest_digest,
        } if action in ("dependency-stage", "dependency-download") else None,
        "destination": {
            "resource_id": "destination", "root_resource_id": "facts",
            "segments": (GENERATION, "asset"), "manifest_digest": manifest_digest,
        } if action in ("dependency-stage", "dependency-download", "dependency-uninstall") else None,
        "reuse": None, "consequential": categories,
    })
    effect = lc.LifecycleEffectOccurrence(
        "owned-effect-0", 0, "owned-stage", "destination", action,
        lifecycle_arguments_digest(step),
    )
    port.seed("step", step)
    pointer = lc.PresentPointer("present", OLD, "e" * 64, 5)
    verification = None
    if action in ("dependency-activate", "restore-active-pointer"):
        verification = c.public_object({
            "kind": "retained" if kind == "restore" else "candidate",
            "event_kind": "CandidateVerified", "event_id": str(uuid4()), "revision": 0,
            "generation_id": GENERATION, "content_digest": content_digest,
            "manifest_digest": manifest_digest, "context_digest": c.digest(context),
            "registry_digest": registry.digest, "policy_digest": identity.bundle_sha256,
            "qualification_digest": "f" * 64,
            "observed_at": clock.now - 1.0, "expires_at": clock.now + 60.0,
            "probes": ({
                "probe_id": "inert-byte-probe", "generation_id": GENERATION,
                "content_digest": content_digest, "context_digest": c.digest(context),
                "result_digest": content_digest, "status": "succeeded",
            },),
        })
        port.seed("verification", verification)
    pins = ()
    if kind == "uninstall":
        pins = (c.public_object({
            "generation_id": GENERATION, "manifest_digest": manifest_digest,
            "revision": 0, "holders": (),
        }),)
        port.seed("pin", pins[0])
    port.seed("facts", {
        "schema": SCHEMA, "root_manifest": root_manifest, "generation_refs": ("generation",),
        "step_refs": ("step",), "pin_refs": ("pin",) if pins else (),
        "verification_ref": "verification" if verification is not None else None,
        "registry_digest": registry.digest, "qualification_digest": "f" * 64,
        "context_digest": c.digest(context), "setup_enabled": True, "cancelled": False,
        "pointer": c.wire(pointer),
    })
    # Unowned/user state is outside the manifest and must survive every operation.
    for name in ("inventory", "vault", "backups", "settings", "unknown", "active", "previous"):
        port.seed("user-" + name, {"preserve": name}, owner="2" * 64)
    identifier = str(uuid4())
    cls = {"install": lc.InstallPlan, "uninstall": lc.UninstallPlan, "restore": lc.RestorePlan}[kind]
    plan = cls(
        "1.0", identifier, str(uuid4()) if kind == "install" else identifier,
        "0" * 64, c.digest(context),
        lc.OwnedRootBinding("facts", c.digest(root_manifest)), generation, pointer, identity,
        registry.digest, "f" * 64, (effect,),
        tuple(lc.ConsequentialRequirement(category, (effect.occurrence_id,))
              for category in categories),
        c.public_object({
            "schema": "1.0", "steps": (step,), "pins": pins,
            "verification": verification, "cancel_scope": (effect.occurrence_id,),
        }), kind, **({"scope": scope} if kind == "install" else {}),
    )
    plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    state = OwnedLifecycleState(port, "facts", OWNER, identity)
    consent = TrustedLifecycleConsentAdapter(review)
    broker = AuthorizationBroker(
        object(), TrustedConsentAdapter(review), lifecycle_state=state, lifecycle_consent=consent,
    )
    service = DependencyService(
        registry, dict.fromkeys(ADAPTERS, probes), state, engine, broker, clock, events,
    )
    # Public read-only planning remembers the selected context; it grants no effects.
    public_plan = service.plan(scope, context)
    return {
        "plan": plan, "public_plan": public_plan, "state": state, "port": port,
        "review": review, "consent": consent, "broker": broker, "clock": clock,
        "probes": probes, "service": service, "events": events, "context": context,
        "scope": scope, "cancel": Cancel(),
    }


def receipt(env, plan=None):
    return env["consent"].review(plan or env["plan"], env["clock"].now, 30.0)


def user_state(env):
    return {name: record for name, record in env["port"].records.items()
            if name.startswith("user-")}


def test_t02_public_plan_can_be_reviewed_then_provisioned_without_private_reconstruction():
    from tests.test_nov19_successor_public_installer import managed_environment

    env = managed_environment()
    before = env["records"].read("user-inventory")
    service = env["service"]
    plan = service.plan(env["scope"], env["context"])
    assert plan.lifecycle is not None and not plan.blocked
    assert not env["records"].writes and not env["transport"].calls
    consent = service.review(plan, env["clock"].now, 30.0)
    result = service.provision(plan, consent, Cancel())
    assert result.status == c.OutcomeStatus.PARTIAL
    assert all(step.status == c.OutcomeStatus.SUCCEEDED for step in result.steps)
    assert result.pending_actions == ("review-activation-plan",)
    assert env["state"].pointer() == lc.AbsentPointer("absent", 0)
    activation = service.plan(env["scope"], env["context"])
    assert tuple(step.kind for step in activation.lifecycle.effects) == (
        "dependency-probe", "dependency-activate",
    )
    result = service.provision(
        activation, service.review(activation, env["clock"].now, 30.0), Cancel(),
    )
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert env["records"].read("user-inventory") == before
    assert len(env["transport"].calls) == 1


def test_t03_actual_service_stages_owned_bytes_once_and_preserves_user_state():
    env = environment()
    before = user_state(env)
    consent = receipt(env)
    outcome = env["service"].provision(env["plan"], consent, env["cancel"])
    assert outcome.steps[0].status == c.OutcomeStatus.SUCCEEDED
    assert outcome.status != c.OutcomeStatus.SUCCEEDED, (
        "A staged inert asset is not an activated functionally ready selected installation"
    )
    assert env["state"].artifact("destination") == DATA
    assert user_state(env) == before
    count = len(env["port"].writes)
    replay = env["service"].provision(env["plan"], consent, env["cancel"])
    assert replay.status != c.OutcomeStatus.SUCCEEDED
    assert len(env["port"].writes) == count
    assert env["state"].pointer().active_generation_id == OLD


@pytest.mark.parametrize("category", [
    "elevation", "wsl-change", "vm-change", "reboot", "runtime-install", "security-change",
])
def test_t02_each_consequential_category_needs_a_separate_prompt_and_grant(category):
    env = environment(categories=(category,))
    env["review"].decline = category
    with pytest.raises(AuthorizationError):
        receipt(env)
    assert env["review"].categories == [category]
    assert not env["port"].writes
    assert env["state"].pointer().active_generation_id == OLD


@pytest.mark.parametrize("fault", ["forged", "expired", "context-drift", "owner-corrupt"])
def test_t03_invalid_consent_or_drift_has_no_effects(fault):
    env = environment()
    consent = lc.InstallConsent() if fault == "forged" else receipt(env)
    if fault == "expired":
        env["clock"].now += 30.0
    elif fault == "context-drift":
        record = env["port"].read("facts")
        env["port"].records["facts"] = replace(
            record, payload=c.public_object(dict(record.payload, context_digest="0" * 64)),
        )
    elif fault == "owner-corrupt":
        env["port"].records["source"] = replace(
            env["port"].read("source"), ownership_token="2" * 64,
        )
    before = user_state(env)
    outcome = env["service"].provision(env["plan"], consent, env["cancel"])
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert outcome.errors
    assert not env["port"].writes
    assert user_state(env) == before


def test_t03_effect_permission_failure_stays_primary_and_pointer_unchanged():
    env = environment()
    env["port"].fail_effect = True
    outcome = env["service"].provision(env["plan"], receipt(env), env["cancel"])
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert outcome.errors[0].reason == c.ReasonCode.PROVISION_FAILED
    assert env["state"].pointer().active_generation_id == OLD
    assert user_state(env)


def test_t23_actual_uninstall_removes_only_selected_manifest_owned_resource():
    env = environment("dependency-uninstall")
    before = user_state(env)
    result = env["service"].uninstall(env["plan"], receipt(env))
    assert result.steps[0].status == c.OutcomeStatus.SUCCEEDED
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert "removed_digest" in env["port"].read("destination").payload
    assert user_state(env) == before
    assert env["state"].pointer().active_generation_id == OLD


def test_t28_restore_plan_reads_retained_metadata_without_running_current_generation(tmp_path, policy):
    from tests.test_i02_terminal_restore import qualified_case

    service, host, port, effects, _, context, generation, _, pointer = qualified_case(tmp_path, policy)
    sentinel = tmp_path / "user-inventory-sentinel"
    sentinel.write_bytes(b"untouched user inventory")
    before = len(effects.calls), len(port.writes)
    probes = service.adapters["python"]
    probe_count = len(probes.calls)
    plan = service.plan_restore(generation.generation_id, context)
    assert plan.generation.generation_id == generation.generation_id
    assert plan.expected_pointer.active_generation_id == pointer.active_generation_id
    assert tuple(effect.kind for effect in plan.effects) == ("restore-active-pointer",)
    assert before == (len(effects.calls), len(port.writes))
    assert len(probes.calls) == probe_count, "Metadata-only planning must not run current generation"
    assert host.pointer() == pointer
    assert sentinel.read_bytes() == b"untouched user inventory"


def test_t28_restore_after_fresh_bootstrap_uses_retained_scope_not_in_memory_install_history(
    tmp_path, policy,
):
    from netops.dependencies._composition import ManagedLifecycleState
    from tests.test_i02_terminal_restore import qualified_case

    service, host, port, effects, _, context, generation, runs, pointer = qualified_case(
        tmp_path, policy,
    )
    sentinel = tmp_path / "user-vault-sentinel"
    sentinel.write_bytes(b"unchanged user vault")
    identity = service._policy_identity
    fresh_host = ManagedLifecycleState(
        port, "managed-root", "managed-control", OWNER, identity,
        host.manifests, effects, effects, host.qualifications, runs,
    )
    review = Review()
    private = TrustedLifecycleConsentAdapter(review)
    broker = AuthorizationBroker(
        None, TrustedConsentAdapter(review), lifecycle_state=fresh_host, lifecycle_consent=private,
    )
    fresh = DependencyService(
        service.registry, service.adapters, fresh_host, service.policy, broker,
        service.clock, Events(),
    )
    before = len(effects.calls), len(port.writes)
    plan = fresh.plan_restore(generation.generation_id, context)
    assert before == (len(effects.calls), len(port.writes))
    result = fresh.restore(plan, private.review(plan, 10.0, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert fresh_host.pointer().active_generation_id == generation.generation_id
    assert result.previous_generation_id == pointer.active_generation_id
    assert result.selected_scope == fresh_host.qualifications[0].scope
    assert service.adapters["python"].calls
    assert all(call[0] == "verify" and call[1] == generation.generation_id for call in effects.calls)
    assert all(resource not in ("source", "destination") for resource, _, _ in port.writes[before[1]:])
    assert sentinel.read_bytes() == b"unchanged user vault"


def test_t04_cancel_before_restore_pointer_cas_preserves_active_generation(tmp_path, policy):
    from tests.test_i02_terminal_restore import qualified_case

    service, host, port, effects, private, context, generation, runs, pointer = qualified_case(
        tmp_path, policy,
    )
    sentinel = tmp_path / "user-settings-sentinel"
    sentinel.write_bytes(b"unchanged user settings")
    plan = service.plan_restore(generation.generation_id, context)
    consent = private.review(plan, 10.0, 30.0)
    cancel = Cancel()
    cancel.value = True
    before = len(port.writes)
    effect_count = len(effects.calls)
    result = service.restore(plan, consent, cancel)
    assert result.status == c.OutcomeStatus.CANCELLED
    assert host.pointer() == pointer
    assert len(effects.calls) == effect_count and runs.calls == []
    written = [resource for resource, _, _ in port.writes[before:]]
    assert len(written) == 2
    assert sum(resource.startswith("dependency-outcome-event-") for resource in written) == 1
    assert sum(resource.startswith("dependency-outcome-") and
               not resource.startswith("dependency-outcome-event-") for resource in written) == 1
    assert all(resource not in ("managed-root", "managed-control", "source", "destination")
               for resource in written)
    assert sentinel.read_bytes() == b"unchanged user settings"


def test_t03_resume_never_reconstructs_authority_from_completed_checkpoint():
    env = environment()
    consent = receipt(env)
    result = env["service"].provision(env["plan"], consent, env["cancel"])
    assert result.steps[0].status == c.OutcomeStatus.SUCCEEDED
    assert result.status != c.OutcomeStatus.SUCCEEDED
    count = len(env["port"].writes)
    with pytest.raises(AuthorizationError):
        env["service"].resume(env["plan"].lifecycle_id, consent, env["cancel"])
    assert len(env["port"].writes) == count


def test_t32_install_step_pair_and_throwing_sink_do_not_replace_facts(caplog):
    env = environment()
    env["events"].throw = True
    caplog.set_level("INFO")
    outcome = env["service"].provision(env["plan"], receipt(env), env["cancel"])
    assert outcome.steps[0].status == c.OutcomeStatus.SUCCEEDED
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    records = [record for record in caplog.records if record.getMessage() == "install.step"]
    assert records
    assert any(record.metric_name == "netops.install.step.count"
               and record.metric_value == 1 and record.duration >= 0 for record in records)
    assert env["events"].records


def test_t04_actual_activation_cas_reports_active_and_previous_generations():
    env, plan, consent = managed_activation()
    before = env["records"].read("user-inventory")
    result = env["service"].provision(plan, consent, Cancel())
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert result.active_generation_id == GENERATION
    assert result.previous_generation_id == OLD
    assert env["state"].pointer().revision == 6
    assert env["probes"].calls, "Functional consuming-context re-probes must precede activation"
    assert result.readiness.native == "ready"
    assert result.readiness.companion == "not-requested"
    assert result.readiness.enhanced == "not-requested"
    assert env["records"].read("user-inventory") == before


def test_t04_cancel_after_actual_activation_cas_reports_truth_without_reverse_cas():
    env, plan, consent = managed_activation()
    cancel = Cancel()
    records = env["records"]
    original = records.compare_replace
    pointer_writes = []

    def after_cas(resource, expected, record):
        result = original(resource, expected, record)
        if resource == "managed-control" and record.payload["pointer"]["revision"] == 6:
            pointer_writes.append(record.payload["pointer"])
            cancel.value = True
        return result

    records.compare_replace = after_cas
    result = env["service"].provision(plan, consent, cancel)
    assert env["state"].pointer().active_generation_id == GENERATION
    assert env["state"].pointer().revision == 6
    assert result.active_generation_id == GENERATION
    assert result.previous_generation_id == OLD
    assert result.status == c.OutcomeStatus.PARTIAL
    assert any(error.reason == c.ReasonCode.CANCELLED for error in result.errors)
    assert len(pointer_writes) == 1, "Post-CAS cancellation must never reverse the factual pointer"


def managed_activation():
    """Supported managed stage, factual readiness and separately reviewed canonical activation."""
    from tests.test_nov19_successor_public_installer import managed_environment, staged

    env = managed_environment()
    staged(env)
    records = env["records"]
    control = records.read("managed-control")
    records.records["managed-control"] = replace(
        control, payload=c.public_object(dict(
            control.payload, pointer=c.wire(lc.PresentPointer("present", OLD, "e" * 64, 5)),
        )),
    )
    plan = env["service"].plan(env["scope"], env["context"])
    assert plan.lifecycle is not None and not plan.blocked
    assert tuple(step.kind for step in plan.lifecycle.effects) == (
        "dependency-probe", "dependency-activate",
    )
    consent = env["service"].review(plan, env["clock"].now, 30.0)
    return env, plan, consent


@pytest.mark.parametrize("action", ["dependency-activate", "restore-active-pointer"])
def test_inert_positive_predecessor_remains_rejected_without_pointer_mutation(action):
    env = environment(action)
    before = user_state(env), env["state"].pointer(), len(env["port"].writes)
    if action == "restore-active-pointer":
        with pytest.raises(AuthorizationError):
            env["service"].plan_restore(GENERATION, env["context"])
    else:
        result = env["service"].provision(env["plan"], receipt(env), env["cancel"])
        assert result.status == c.OutcomeStatus.BLOCKED
    assert user_state(env) == before[0] and env["state"].pointer() == before[1]


def test_t04_cancel_before_exact_restore_plan_entry_never_changes_pointer():
    env = environment("restore-active-pointer")
    consent = receipt(env)
    env["cancel"].value = True
    result = env["service"].restore(env["plan"], consent, env["cancel"])
    assert result.status == c.OutcomeStatus.CANCELLED
    assert env["state"].pointer().active_generation_id == OLD
    assert not env["port"].writes


def test_t04_pointer_revision_drift_after_consent_blocks_before_effect():
    env = environment("dependency-activate")
    consent = receipt(env)
    record = env["port"].read("facts")
    pointer = lc.PresentPointer("present", OLD, "e" * 64, 6)
    env["port"].records["facts"] = replace(
        record, payload=c.public_object(dict(record.payload, pointer=c.wire(pointer))),
    )
    result = env["service"].provision(env["plan"], consent, env["cancel"])
    assert result.status != c.OutcomeStatus.SUCCEEDED
    assert not env["port"].writes
    assert env["state"].pointer().revision == 6
    assert env["state"].pointer().active_generation_id == OLD


def test_t23_cleanup_ownership_failure_cannot_erase_original_provision_error():
    env = environment()
    env["port"].fail_effect = env["port"].fail_cleanup = True
    result = env["service"].provision(env["plan"], receipt(env), env["cancel"])
    assert result.status == c.OutcomeStatus.FAILED
    assert result.errors[0].reason == c.ReasonCode.PROVISION_FAILED
    assert any(error.reason == c.ReasonCode.OWNERSHIP_INVALID for error in result.cleanup_errors)
    assert user_state(env)


def test_t03_resume_requires_actual_reprobe_and_fresh_exact_consent():
    env = environment()
    first = env["service"].provision(env["plan"], receipt(env), env["cancel"])
    assert first.steps[0].status == c.OutcomeStatus.SUCCEEDED
    prior = env["plan"]
    fresh = replace(prior, plan_id=str(uuid4()))
    fresh = replace(fresh, plan_digest=lifecycle_plan_digest(fresh))
    # This is a new reviewed plan, not a replayed checkpoint/grant.
    consent = receipt(env, fresh)
    env["probes"].status = "missing"
    before = len(env["port"].writes)
    result = env["service"].resume(prior.lifecycle_id, consent, env["cancel"])
    assert env["probes"].calls
    assert result.status != c.OutcomeStatus.SUCCEEDED
    assert not any(
        resource == "destination" or resource.startswith("lifecycle-receipt-")
        for resource, _, _ in env["port"].writes[before:]
    ), (
        "Drift must trigger replanning/reconsent, not dispatch from a stale reviewed plan"
    )


def test_t02_install_outcome_response_exact_serialization_pin():
    outcome = InstallOutcome(
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000002",
        "install", c.OutcomeStatus.SUCCEEDED,
        (InstallStepOutcome("effect-0", "activate", "dependency-activate",
                            c.OutcomeStatus.SUCCEEDED, True),),
        c.ReadinessProjection("ready", "not-requested", "not-requested"),
        "candidate", "candidate", "prior", pointer_revision=6,
        selected_scope=c.InstallScope(("native.stdlib",), (), False, False),
    )
    assert c.canonical_bytes(outcome).decode() == (
        '{"active_generation_id":"candidate","candidate_generation_id":"candidate",'
        '"cleanup_errors":[],"errors":[],"installation_id":"00000000-0000-4000-8000-000000000001",'
        '"kind":"install","original_errors":[],"pending_actions":[],'
        '"plan_id":"00000000-0000-4000-8000-000000000002","pointer_revision":6,'
        '"previous_generation_id":"prior","readiness":{"companion":"not-requested",'
        '"enhanced":"not-requested","errors":[],"native":"ready"},'
        '"remote_state":"not-requested","schema_version":"1.0",'
        '"selected_scope":{"companions":[],"enhanced":false,"full_toolkit":false,'
        '"native_capabilities":["native.stdlib"]},"status":"succeeded",'
        '"steps":[{"changed":true,"error":null,"kind":"dependency-activate",'
        '"occurrence_id":"effect-0","status":"succeeded","step_id":"activate"}],"uncertain":false}'
    )
