"""Inert file-port handler proofs, not native protection or platform qualification."""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.artifacts import OwnedRecord
from netops.ansible.lifecycle_execution import LifecycleExecutor, OwnedLifecycleState
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    TrustedConsentAdapter,
    TrustedLifecycleConsentAdapter,
    bind_lifecycle,
    lifecycle_effects,
    lifecycle_plan_digest,
)
from netops.ansible.policy.engine import LocalReferencePolicyEngine
from netops.ansible.policy.lifecycle_evidence import lifecycle_arguments_digest
from netops.ansible.policy.loader import load_policy
from netops.dependencies import DependencyRegistry, DependencyService
from netops.dependencies.service import ADAPTERS
from tests.test_dependency_probes import FixtureAdapter

D = "a" * 64
OWNER = "1" * 64
SCHEMA = "a02-owned-inert-v1"
DATA = b"owned inert bytes; never executable"
CONTENT = hashlib.sha256(DATA).hexdigest()


class FilePort:
    """Unprivileged actual file host-port fixture; no protected-backend claim."""

    def __init__(self, path, identity):
        self.path = path
        self.identity = identity
        self.mutex = threading.RLock()
        self.writes = []
        self.before_cas = None
        self.after_cas = None
        self.fail_reads = False

    def filename(self, resource):
        return self.path / (hashlib.sha256(resource.encode()).hexdigest() + ".json")

    @contextmanager
    def lock(self, resources, timeout):
        with self.mutex:
            yield self

    def read(self, resource):
        if self.fail_reads:
            raise OSError("fixture read failure")
        return OwnedRecord.from_bytes(self.filename(resource).read_bytes())

    def seed(self, resource, payload, revision=0, owner=OWNER):
        record = OwnedRecord(
            resource, "checkpoint", revision, 0, owner,
            self.identity.bundle_sha256, self.identity.reducer_version,
            c.public_object(payload), self.identity,
        )
        self.filename(resource).write_bytes(record.to_bytes())
        return record

    def compare_replace(self, resource, expected, record):
        with self.mutex:
            if self.before_cas is not None:
                self.before_cas(resource, record)
            path = self.filename(resource)
            if path.exists():
                actual = self.read(resource)
                if actual.revision != expected or record.revision != expected + 1:
                    raise AuthorizationError()
            elif expected != 0 or record.revision != 0:
                raise AuthorizationError()
            pending = path.with_suffix(".pending")
            pending.write_bytes(record.to_bytes())
            pending.replace(path)
            self.writes.append((resource, expected, record.revision))
            if self.after_cas is not None:
                self.after_cas(resource, record)
            return record


class Review:
    def __init__(self):
        self.denied = None
        self.prompts = []

    def confirm(self, plan, binding, deadline):
        raise AssertionError("operational consent is not lifecycle consent")

    def confirm_lifecycle(self, binding, deadline):
        return True

    def confirm_consequential(self, binding, requirement, deadline):
        self.prompts.append(requirement.category)
        return self.denied != requirement.category


class Clock:
    value = 10.0

    def monotonic(self):
        return self.value


@pytest.fixture(scope="module")
def policy():
    root = Path(__file__).resolve().parents[2]
    directory = root / "netops" / "ansible" / "policy"
    source = (directory / "ansible_molecule.px").read_bytes()
    contracts = (directory / "ansible_molecule.contracts.px").read_bytes()
    bundle = (directory / "bundle.json").read_bytes()
    raw = json.loads(bundle)
    identity = lc.PolicyIdentity(
        lc.PIN, hashlib.sha256(source).hexdigest(), hashlib.sha256(contracts).hexdigest(),
        hashlib.sha256(bundle).hexdigest(), tuple(item["id"] for item in raw["manifest"]),
        raw["reducer_version"],
    )
    engine = LocalReferencePolicyEngine(load_policy(source, contracts, bundle, identity))
    corpus = json.loads((root / "tests" / "policy" / "canonical-corpus.json").read_bytes())
    facts = next(case["input"]["facts"] for case in corpus["cases"] if case["case_id"] ==
                 "netops_companion_setup_consent_install_consented_restore_example_3")
    return identity, engine, facts


def decision_for(policy, binding):
    _, engine, raw = policy
    values = copy.deepcopy(raw)
    effect = binding.effects[0]
    values["request"]["operation"] = binding.kind
    values["lifecycle"]["next_effect_kind"] = effect.kind
    activate = effect.kind == "dependency-activate"
    if activate:
        verification = binding.content["verification"]
        event_kind = lc.EventKind.CANDIDATE_VERIFIED
        event_id = verification["event_id"]
        payload = c.public_object({
            "candidate_digest": binding.generation.content_digest,
            "registry_digest": binding.registry_digest, "assets_digest": D,
            "policy_digest": binding.policy.bundle_sha256,
            "qualification_digest": binding.qualification_digest,
            "functional_evidence_ref": verification["probes"][0]["probe_id"],
        })
    else:
        event_kind, event_id = lc.EventKind.INSTALL_CONSENTED, str(uuid4())
        payload = c.public_object({
            "lifecycle_kind": binding.kind, "plan_id": binding.plan_id,
            "lifecycle_binding_digest": c.digest(binding),
            "private_consent_reference": "host-private-symbolic-reference",
        })
    event = lc.DecisionEvent(
        event_id, event_kind, 0, binding.plan_digest, binding.context_digest,
        binding.policy.bundle_sha256, "resource", effect.step_id, payload,
        install_id=binding.lifecycle_id,
    )
    return engine.decide(event, lc.DecisionFacts(
        values, lc.Phase.STAGING if activate else lc.Phase.PLANNED, 0,
    ))


def environment(tmp_path, policy, action="dependency-stage", *, categories=(), virgin=False):
    identity = policy[0]
    port = FilePort(tmp_path, identity)
    manifest = c.public_object({"member": "inert-bytes"})
    manifest_digest = c.digest(manifest)
    root_manifest = c.public_object({"owner": "inert-test", "schema": "1.0"})
    kind = (
        "uninstall" if action == "dependency-uninstall"
        else "restore" if action == "restore-active-pointer" else "install"
    )
    generation = lc.GenerationBinding("generation", 0, CONTENT, manifest_digest)
    if kind == "uninstall":
        generation = replace(generation, selected=(generation,))
    port.seed("generation", {
        "generation_id": "generation", "ordinal": 0, "content": tuple(DATA), "manifest": manifest,
    })
    port.seed("source", {
        "schema": SCHEMA, "content": tuple(DATA), "content_digest": CONTENT, "manifest": manifest,
    })
    if action in ("dependency-download", "dependency-stage"):
        port.seed("destination", {"schema": SCHEMA, "reserved": True, "manifest": manifest})
    else:
        port.seed("destination", {
            "schema": SCHEMA, "content": tuple(DATA), "content_digest": CONTENT, "manifest": manifest,
        })
    effect = lc.LifecycleEffectOccurrence("occurrence", 0, "step", "destination", action, D)
    step = c.public_object({
        "occurrence_id": effect.occurrence_id, "generation_id": "generation",
        "source": c.public_object({
            "source_id": "source", "registry_digest": D, "artifact_digest": CONTENT,
            "descriptor_digest": c.digest(manifest),
        }) if action in ("dependency-download", "dependency-stage") else None,
        "destination": c.public_object({
            "resource_id": "destination", "root_resource_id": "facts",
            "segments": ("generation", "artifact"), "manifest_digest": manifest_digest,
        }) if action in (
            "dependency-download", "dependency-stage", "dependency-verify", "dependency-uninstall",
        ) else None,
        "reuse": None, "consequential": categories,
    })
    effect = replace(effect, arguments_digest=lifecycle_arguments_digest(step))
    port.seed("step", step)
    pointer = lc.AbsentPointer("absent", 0) if virgin else lc.PresentPointer("present", "old", D, 3)
    verification = None
    if action in ("dependency-activate", "restore-active-pointer"):
        verification = c.public_object({
            "kind": "candidate" if kind == "install" else "retained",
            "event_kind": "CandidateVerified", "event_id": str(uuid4()), "revision": 0,
            "generation_id": "generation", "content_digest": CONTENT,
            "manifest_digest": manifest_digest, "context_digest": D, "registry_digest": D,
            "policy_digest": identity.bundle_sha256, "qualification_digest": D,
            "observed_at": 1.0, "expires_at": 100.0,
            "probes": (c.public_object({
                "probe_id": "inert-byte-probe", "generation_id": "generation",
                "content_digest": CONTENT, "context_digest": D,
                "result_digest": CONTENT, "status": "succeeded",
            }),),
        })
        port.seed("verification", verification)
    pins = ()
    if kind == "uninstall":
        pin = c.public_object({
            "generation_id": "generation", "manifest_digest": manifest_digest,
            "revision": 0, "holders": (),
        })
        pins = (pin,)
        port.seed("pin", pin)
    port.seed("facts", {
        "schema": SCHEMA, "root_manifest": root_manifest, "generation_refs": ("generation",),
        "step_refs": ("step",), "pin_refs": ("pin",) if pins else (),
        "verification_ref": "verification" if verification is not None else None,
        "registry_digest": D, "qualification_digest": D, "context_digest": D,
        "setup_enabled": True, "cancelled": False, "pointer": c.wire(pointer),
    })
    cls = {"install": lc.InstallPlan, "uninstall": lc.UninstallPlan, "restore": lc.RestorePlan}[kind]
    plan = cls(
        "1.0", str(uuid4()), str(uuid4()), D, D,
        lc.OwnedRootBinding("facts", c.digest(root_manifest)), generation, pointer, identity,
        D, D, (effect,), tuple(
            lc.ConsequentialRequirement(category, ("occurrence",)) for category in categories
        ), c.public_object({
            "schema": "1.0", "steps": (step,), "pins": pins, "verification": verification,
            "cancel_scope": ("occurrence",),
        }), kind, **({"scope": c.InstallScope((), ("ansible",), False)} if kind == "install" else {}),
    )
    plan = replace(plan, lifecycle_id=plan.lifecycle_id if kind == "install" else plan.plan_id)
    plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    binding = bind_lifecycle(plan)
    state = OwnedLifecycleState(port, "facts", OWNER, identity)
    review = Review()
    adapter = TrustedLifecycleConsentAdapter(review)
    broker = AuthorizationBroker(
        object(), TrustedConsentAdapter(review), lifecycle_state=state, lifecycle_consent=adapter,
    )
    clock = Clock()
    executor = LifecycleExecutor(broker, state, clock)
    return plan, binding, port, state, review, adapter, broker, clock, executor


def issue(env, policy):
    plan, binding, _, _, _, adapter, broker, _, _ = env
    decision = decision_for(policy, binding)
    assert decision.decision == "allow"
    return broker.issue_lifecycle(plan, adapter.review(plan, 10.0, 20.0), decision, 10.0)


def reserve(env, policy):
    _, binding, _, state, _, _, broker, _, _ = env
    grant = issue(env, policy)
    session = broker.consume_lifecycle(grant, binding, 10.0)
    effect = lc.LifecycleEffectBinding(binding, str(uuid4()),
                                     state.snapshot_lifecycle(binding).revision, "occurrence")
    return broker.permit_lifecycle(session, effect, 10.0), effect


def continuation_decision(policy, binding, index=0):
    _, engine, raw = policy
    values = copy.deepcopy(raw)
    values["request"]["operation"] = binding.kind
    values["lifecycle"]["next_effect_kind"] = binding.effects[index].kind
    event = lc.DecisionEvent(
        str(uuid4()), lc.EventKind.STEP_COMPLETED, 0, binding.plan_digest,
        D, policy[0].bundle_sha256, "resource", binding.effects[index].step_id,
        c.public_object({
            "invocation_id": str(uuid4()), "effect_id": "previous-occurrence",
            "target_id": "resource", "step_id": binding.effects[index].step_id,
            "safe_result_digest": CONTENT, "primary": "success",
            "cleanup": "success", "remote_uncertain": False,
        }), install_id=binding.lifecycle_id,
    )
    return engine.decide(event, lc.DecisionFacts(values, lc.Phase.STAGING, 0))


@pytest.mark.parametrize("action", (
    "dependency-stage", "dependency-uninstall", "restore-active-pointer", "dependency-activate",
))
def test_actual_packaged_policy_admits_real_owned_handler(tmp_path, policy, action):
    env = environment(tmp_path, policy, action)
    plan, _, port, state, _, _, _, _, executor = env
    result = executor.execute(plan, issue(env, policy))
    assert result.completed and not result.uncertain and not result.pending
    assert len(result.receipts) == 1
    assert result.receipts[0].kind == action
    if action == "dependency-stage":
        assert state.artifact("destination") == DATA
    elif action == "dependency-uninstall":
        assert port.read("destination").payload["removed_digest"] == plan.generation.manifest_digest
    else:
        assert state.pointer().active_generation_id == "generation"
    before = len(port.writes)
    with pytest.raises(AuthorizationError):
        executor.execute(plan, lc.LifecycleAuthorization())
    assert len(port.writes) == before


@pytest.mark.parametrize("action", ("dependency-probe", "dependency-download", "dependency-verify"))
def test_inert_fixed_symbols_use_actual_broker_not_fake_policy_client(tmp_path, policy, action):
    env = environment(tmp_path, policy, action)
    plan, binding, _, state, _, adapter, broker, _, executor = env
    # Current frozen setup event admits stage, not these initial symbols.
    # Derive the actual policy rule for a completed prior step, then project its
    # exact single effect; no invented rule ID or permissive policy client.
    decision = continuation_decision(policy, binding)
    assert decision.decision == "allow"
    # The closed admission descriptor is the actual evaluator's executable
    # intent projection, not its factual aggregate record_outcome action.
    decision = replace(decision, effects=tuple(
        effect for effect in decision.effects if effect.name == "request_effect"
    ))
    assert decision.effects == lifecycle_effects(binding)
    grant = broker.issue_lifecycle(plan, adapter.review(plan, 10.0, 20.0), decision, 10.0)
    result = executor.execute(plan, grant)
    assert result.completed and result.receipts[0].kind == action
    if action == "dependency-download":
        assert state.artifact("destination") == DATA


def test_entry_without_permit_is_zero_owned_io(tmp_path, policy):
    env = environment(tmp_path, policy)
    _, binding, port, _, _, _, _, _, executor = env
    port.fail_reads = True
    with pytest.raises(AuthorizationError):
        executor.enter(lc.LifecycleEffectPermit(), lc.LifecycleEffectBinding(
            binding, str(uuid4()), 0, "occurrence",
        ))
    assert port.writes == []


@pytest.mark.parametrize("resource,change", (
    ("facts", {"registry_digest": "b" * 64}),
    ("facts", {"qualification_digest": "b" * 64}),
    ("facts", {"context_digest": "b" * 64}),
    ("facts", {"root_manifest": {"owner": "other"}}),
    ("facts", {"pointer": {"kind": "absent", "revision": 1}}),
    ("generation", {"content": tuple(b"changed")}),
    ("generation", {"manifest": {"member": "changed"}}),
    ("source", {"content": tuple(b"changed")}),
    ("step", {"consequential": ("reboot",)}),
))
def test_changed_actual_owned_fact_after_issue_prevents_any_handler(tmp_path, policy, resource, change):
    env = environment(tmp_path, policy)
    plan, _, port, _, _, _, _, _, executor = env
    grant = issue(env, policy)
    current = port.read(resource)
    payload = dict(current.payload.items())
    payload.update(change)
    port.seed(resource, payload)
    before = port.filename("destination").read_bytes()
    with pytest.raises((AuthorizationError, c.ContractError)):
        executor.execute(plan, grant)
    assert port.filename("destination").read_bytes() == before
    assert port.writes == []


@pytest.mark.parametrize("resource", ("facts", "generation", "source", "step", "destination"))
def test_wrong_owner_actual_record_never_adopted(tmp_path, policy, resource):
    env = environment(tmp_path, policy)
    plan, _, port, _, _, _, _, _, executor = env
    original = port.read(resource)
    port.seed(resource, original.payload, owner="2" * 64)
    with pytest.raises((c.ContractError, AuthorizationError)):
        issue(env, policy)
    assert port.writes == []
    assert plan.kind == "install"


@pytest.mark.parametrize("resource", ("verification", "generation", "facts"))
def test_restore_observation_loss_is_not_virgin_or_valid_probe(tmp_path, policy, resource):
    env = environment(tmp_path, policy, "restore-active-pointer")
    grant = issue(env, policy)
    env[2].filename(resource).unlink()
    with pytest.raises((OSError, AuthorizationError, c.ContractError)):
        env[-1].execute(env[0], grant)
    assert env[2].writes == []


@pytest.mark.parametrize("category", (
    "elevation", "wsl-change", "vm-change", "reboot", "runtime-install", "security-change",
))
def test_separate_consequential_receipt_missing_blocks_actual_setup(tmp_path, policy, category):
    env = environment(tmp_path, policy, categories=(category,))
    env[4].denied = category
    with pytest.raises(AuthorizationError):
        issue(env, policy)
    assert env[4].prompts == [category]
    assert env[2].writes == []


def test_exact_separate_consequential_receipts_admit_only_bound_occurrence(tmp_path, policy):
    categories = ("elevation", "wsl-change", "vm-change", "reboot", "runtime-install", "security-change")
    env = environment(tmp_path, policy, categories=categories)
    result = env[-1].execute(env[0], issue(env, policy))
    assert result.completed and tuple(env[4].prompts) == categories


@pytest.mark.parametrize("clock", (float("nan"), float("inf"), -float("inf"), 9.0, 31.0))
def test_bad_entry_clock_irreversibly_retires_authority(tmp_path, policy, clock):
    env = environment(tmp_path, policy)
    permit, binding = reserve(env, policy)
    env[-2].value = clock
    with pytest.raises((c.ContractError, AuthorizationError)):
        env[-1].enter(permit, binding)
    env[-2].value = 12.0
    with pytest.raises(AuthorizationError):
        env[-1].enter(permit, binding)
    assert env[2].read("destination").payload["reserved"] is True


def test_actual_cancel_before_final_cas_keeps_pointer_and_pending_fact(tmp_path, policy):
    env = environment(tmp_path, policy, "restore-active-pointer")
    permit, effect = reserve(env, policy)
    env[-1].cancel(env[0])
    with pytest.raises(AuthorizationError):
        env[-1].enter(permit, effect)
    assert env[3].pointer() == env[1].expected_pointer
    assert env[6].reconcile_lifecycle(permit) == effect


def test_actual_cas_before_cancel_never_reverse_and_late_completion_is_factual(tmp_path, policy):
    env = environment(tmp_path, policy, "restore-active-pointer")
    permit, effect = reserve(env, policy)
    result = env[-1].enter(permit, effect)
    actual = env[3].pointer()
    env[-1].cancel(env[0])
    env[-2].value = 40.0
    assert env[-1].complete(permit) == result
    assert env[3].pointer() == actual
    with pytest.raises(AuthorizationError):
        env[-1].enter(permit, effect)
    with pytest.raises(AuthorizationError):
        env[-1].complete(permit)
    assert env[-1].reconcile(permit) == result


def test_revision_exhaustion_preserves_cancel_and_pending_reconciliation(tmp_path, policy):
    env = environment(tmp_path, policy)
    permit, effect = reserve(env, policy)
    result = env[-1].enter(permit, effect)
    root = env[2].read("facts")
    env[2].seed("facts", root.payload, revision=lc.MAX_SAFE_INT)
    with pytest.raises(AuthorizationError):
        env[-1].complete(permit)
    env[-1].cancel(env[0])
    assert env[-1].reconcile(permit) == result
    assert env[2].read("facts").revision == lc.MAX_SAFE_INT


def test_final_pointer_cas_lost_ack_retains_actual_new_pointer(tmp_path, policy):
    env = environment(tmp_path, policy, "restore-active-pointer")
    permit, effect = reserve(env, policy)

    def lost_ack(resource, record):
        if resource == "facts" and record.payload["pointer"] != c.public_object(
            c.wire(env[1].expected_pointer),
        ):
            raise OSError("lost issued acknowledgement")

    env[2].after_cas = lost_ack
    with pytest.raises(OSError):
        env[-1].enter(permit, effect)
    assert env[3].pointer().active_generation_id == "generation"
    assert env[6].reconcile_lifecycle(permit) == effect
    assert env[-1].reconcile(permit) is None
    with pytest.raises(AuthorizationError):
        env[-1].enter(permit, effect)


def test_wrong_kind_permit_binding_does_not_enter_handler(tmp_path, policy):
    env = environment(tmp_path, policy)
    other_path = tmp_path / "other"
    other_path.mkdir()
    other = environment(other_path, policy, "restore-active-pointer")
    permit, effect = reserve(env, policy)
    with pytest.raises(AuthorizationError):
        env[-1].enter(permit, replace(effect, lifecycle=other[1]))
    assert env[2].read("destination").payload["reserved"] is True


def test_current_source_manifest_is_checked_not_just_artifact_content(tmp_path, policy):
    env = environment(tmp_path, policy)
    record = env[2].read("source")
    payload = dict(record.payload.items())
    payload["manifest"] = c.public_object({"member": "changed-source-identity"})
    env[2].seed("source", payload)
    with pytest.raises((c.ContractError, AuthorizationError)):
        issue(env, policy)
    assert env[2].writes == []


def test_missing_owned_generation_is_not_filled_from_plan(tmp_path, policy):
    env = environment(tmp_path, policy)
    record = env[2].read("facts")
    payload = dict(record.payload.items())
    payload["generation_refs"] = ()
    env[2].seed("facts", payload)
    with pytest.raises((c.ContractError, AuthorizationError)):
        issue(env, policy)
    assert env[2].writes == []


def test_inert_verification_must_measure_actual_current_owned_bytes(tmp_path, policy):
    env = list(environment(tmp_path, policy, "restore-active-pointer"))
    record = env[2].read("verification")
    payload = dict(record.payload.items())
    probe = dict(payload["probes"][0].items())
    probe["result_digest"] = D
    payload["probes"] = (c.public_object(probe),)
    env[2].seed("verification", payload)
    content = dict(env[0].content.items())
    content["verification"] = c.public_object(payload)
    plan = replace(env[0], content=c.public_object(content))
    plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    env[0], env[1] = plan, bind_lifecycle(plan)
    with pytest.raises((c.ContractError, AuthorizationError)):
        issue(env, policy)
    assert env[2].writes == []


def test_actual_pointer_race_never_overwrites_winner(tmp_path, policy):
    env = environment(tmp_path, policy, "restore-active-pointer")
    permit, effect = reserve(env, policy)
    winner = lc.PresentPointer("present", "race-winner", "c" * 64, 4)

    def race(resource, record):
        if resource == "facts":
            env[2].before_cas = None
            current = env[2].read("facts")
            payload = dict(current.payload.items())
            payload["pointer"] = c.wire(winner)
            env[2].seed("facts", payload, revision=current.revision + 1)

    env[2].before_cas = race
    with pytest.raises(AuthorizationError):
        env[-1].enter(permit, effect)
    assert env[3].pointer() == winner
    assert env[6].reconcile_lifecycle(permit) == effect


def test_successful_handler_fact_survives_completion_checkpoint_failure(tmp_path, policy):
    env = environment(tmp_path, policy)
    grant = issue(env, policy)

    def exhausted_after_effect(resource, record):
        if resource == "destination":
            root = env[2].read("facts")
            env[2].seed("facts", root.payload, revision=lc.MAX_SAFE_INT)

    env[2].after_cas = exhausted_after_effect
    result = env[-1].execute(env[0], grant)
    assert not result.completed and not result.uncertain
    assert result.receipts[0].result_digest == CONTENT
    assert result.pending
    assert env[3].artifact("destination") == DATA


def test_owned_factual_receipt_is_not_a_recoverable_grant(tmp_path, policy):
    env = environment(tmp_path, policy)
    permit, effect = reserve(env, policy)
    receipt = env[-1].enter(permit, effect)
    persisted = env[3].inspect_receipt(effect)
    assert persisted["phase"] == "observed"
    assert persisted["result"]["result_digest"] == CONTENT
    recovered = LifecycleExecutor(env[6], env[3], env[-2])
    with pytest.raises(AuthorizationError):
        recovered.enter(permit, effect)
    with pytest.raises(AuthorizationError):
        recovered.execute(env[0], lc.LifecycleAuthorization())
    with pytest.raises(AuthorizationError):
        recovered.complete(permit)
    assert env[-1].complete(permit) == receipt


def test_pending_fact_remains_when_inert_effect_loses_its_ack(tmp_path, policy):
    env = environment(tmp_path, policy)
    permit, effect = reserve(env, policy)

    def lose_ack(resource, record):
        if resource == "destination":
            raise OSError("already wrote actual owned artifact")

    env[2].after_cas = lose_ack
    with pytest.raises(OSError):
        env[-1].enter(permit, effect)
    assert env[3].artifact("destination") == DATA
    assert env[3].inspect_receipt(effect)["phase"] == "pending"
    assert env[-1].reconcile(permit) is None
    with pytest.raises(AuthorizationError):
        env[-1].enter(permit, effect)


def test_original_baseexception_identity_is_not_sanitized_or_replayed(tmp_path, policy):
    env = environment(tmp_path, policy)
    permit, effect = reserve(env, policy)
    sentinel = KeyboardInterrupt("fixture-local cancellation")

    def interrupt(resource, record):
        if resource == "destination":
            raise sentinel

    env[2].after_cas = interrupt
    with pytest.raises(KeyboardInterrupt) as caught:
        env[-1].enter(permit, effect)
    assert caught.value is sentinel
    assert env[3].inspect_receipt(effect)["phase"] == "pending"
    assert env[3].artifact("destination") == DATA
    env[-1].cancel(env[0])
    assert env[6].reconcile_lifecycle(permit) == effect


@pytest.mark.parametrize("pointer", (
    {"kind": "absent", "revision": True},
    {"kind": "absent", "revision": lc.MAX_SAFE_INT + 1},
    {"kind": "absent", "revision": 0, "extra": "not-virgin"},
    {"kind": "missing", "revision": 0},
    None,
))
def test_corrupt_pointer_never_becomes_virgin_absence(tmp_path, policy, pointer):
    env = environment(tmp_path, policy)
    record = env[2].read("facts")
    raw = json.loads(record.to_bytes())
    raw["payload"]["pointer"] = pointer
    env[2].filename("facts").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises((c.ContractError, ValueError, RuntimeError)):
        issue(env, policy)
    assert env[2].writes == []


def test_pointer_revision_exhaustion_cannot_activate_but_cancel_is_independent(tmp_path, policy):
    env = list(environment(tmp_path, policy, "restore-active-pointer"))
    pointer = replace(env[1].expected_pointer, revision=lc.MAX_SAFE_INT)
    record = env[2].read("facts")
    payload = dict(record.payload.items())
    payload["pointer"] = c.wire(pointer)
    env[2].seed("facts", payload)
    plan = replace(env[0], expected_pointer=pointer)
    env[0] = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    env[1] = bind_lifecycle(env[0])
    permit, effect = reserve(env, policy)
    with pytest.raises(AuthorizationError):
        env[-1].enter(permit, effect)
    env[-1].cancel(env[0])
    assert env[3].pointer() == pointer
    assert env[6].reconcile_lifecycle(permit) == effect


def test_current_pin_holder_after_issue_blocks_real_uninstall(tmp_path, policy):
    env = environment(tmp_path, policy, "dependency-uninstall")
    grant = issue(env, policy)
    pin = env[2].read("pin")
    payload = dict(pin.payload.items())
    payload["holders"] = ("new-live-reader",)
    env[2].seed("pin", payload, revision=1)
    with pytest.raises((c.ContractError, AuthorizationError)):
        env[-1].execute(env[0], grant)
    assert env[3].artifact("destination") == DATA
    assert env[2].writes == []


def test_expired_current_probe_blocks_restore_even_with_unused_private_grant(tmp_path, policy):
    env = environment(tmp_path, policy, "restore-active-pointer")
    grant = issue(env, policy)
    env[-2].value = 101.0
    with pytest.raises(AuthorizationError):
        env[-1].execute(env[0], grant)
    env[-2].value = 12.0
    with pytest.raises(AuthorizationError):
        env[-1].execute(env[0], grant)
    assert env[3].pointer() == env[1].expected_pointer


def test_virgin_install_pointer_is_explicit_reviewed_cas(tmp_path, policy):
    env = environment(tmp_path, policy, "dependency-activate", virgin=True)
    result = env[-1].execute(env[0], issue(env, policy))
    assert result.completed
    assert result.receipts[0].pointer == ("generation", 1)
    assert env[3].pointer().revision == 1


def test_observation_drift_after_entry_cannot_erase_late_factual_completion(tmp_path, policy):
    env = environment(tmp_path, policy)
    permit, effect = reserve(env, policy)
    receipt = env[-1].enter(permit, effect)
    env[2].filename("source").unlink()
    env[-1].cancel(env[0])
    assert env[-1].complete(permit) == receipt
    assert env[3].inspect_receipt(effect)["phase"] == "observed"
    assert env[-1].reconcile(permit) == receipt
    with pytest.raises(AuthorizationError):
        env[-1].enter(permit, effect)


def test_concurrent_same_private_authorization_enters_only_once(tmp_path, policy):
    env = environment(tmp_path, policy)
    grant = issue(env, policy)
    barrier = threading.Barrier(2)

    def run():
        barrier.wait()
        try:
            return env[-1].execute(env[0], grant).completed
        except AuthorizationError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert sorted(results) == [False, True]
    assert len([item for item in env[2].writes if item[0] == "destination"]) == 1
    assert env[3].artifact("destination") == DATA


@pytest.mark.parametrize("value", (None, {}, "permit", lc.LifecycleEffectPermit()))
def test_unknown_or_nominal_permit_rejects_before_any_owned_read(tmp_path, policy, value):
    env = environment(tmp_path, policy)
    effect = lc.LifecycleEffectBinding(env[1], str(uuid4()), 0, "occurrence")
    env[2].fail_reads = True
    with pytest.raises((c.ContractError, AuthorizationError)):
        env[-1].enter(value, effect)
    assert env[2].writes == []


@pytest.mark.parametrize("field,value", (
    ("setup_enabled", False), ("cancelled", True),
    ("policy_identity", "not-an-owned-policy"),
))
def test_live_kill_switch_and_policy_drift_never_enable_setup(tmp_path, policy, field, value):
    env = environment(tmp_path, policy)
    record = env[2].read("facts")
    if field == "policy_identity":
        raw = json.loads(record.to_bytes())
        raw["policy_identity"]["source_sha256"] = "b" * 64
        env[2].filename("facts").write_text(json.dumps(raw), encoding="utf-8")
    else:
        payload = dict(record.payload.items())
        payload[field] = value
        env[2].seed("facts", payload)
    with pytest.raises((c.ContractError, AuthorizationError, RuntimeError)):
        issue(env, policy)
    assert env[2].writes == []


def test_repeated_uninstall_cannot_tombstone_an_already_removed_resource(tmp_path, policy):
    env = environment(tmp_path, policy, "dependency-uninstall")
    result = env[-1].execute(env[0], issue(env, policy))
    assert result.completed
    before = len(env[2].writes)
    with pytest.raises(c.ContractError):
        env[3].remove_artifact("destination", env[0].generation.manifest_digest)
    assert len(env[2].writes) == before


def test_executor_rejects_split_broker_and_handler_owned_state(tmp_path, policy):
    env = environment(tmp_path, policy)
    wrong = OwnedLifecycleState(env[2], "facts", OWNER, policy[0])
    with pytest.raises(c.ContractError):
        LifecycleExecutor(env[6], wrong, env[-2])
    assert env[2].writes == []


def repeated_environment(tmp_path, policy):
    env = list(environment(tmp_path, policy))
    plan, _, port = env[:3]
    original = port.read("step").payload
    step = dict(original.items())
    step["occurrence_id"] = "second-occurrence"
    destination = dict(step["destination"].items())
    destination["resource_id"] = "destination-two"
    step["destination"] = c.public_object(destination)
    step = c.public_object(step)
    port.seed("step-two", step)
    port.seed("destination-two", port.read("destination").payload)
    effect = replace(
        plan.effects[0], occurrence_id="second-occurrence", ordinal=1,
        step_id="step-two", resource_id="destination-two",
        arguments_digest=lifecycle_arguments_digest(step),
    )
    content = dict(plan.content.items())
    content["steps"] = (original, step)
    content["cancel_scope"] = ("occurrence", "second-occurrence")
    plan = replace(plan, effects=(*plan.effects, effect), content=c.public_object(content))
    env[0] = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    env[1] = bind_lifecycle(env[0])
    facts = port.read("facts")
    data = dict(facts.payload.items())
    data["step_refs"] = ("step", "step-two")
    port.seed("facts", data)
    first = decision_for(policy, env[1])
    second = continuation_decision(policy, env[1], 1)
    assert first.decision == second.decision == "allow"
    decisions = (first, second)
    narrowed = replace(
        first,
        rule_ids=tuple(sorted({rule for decision in decisions for rule in decision.rule_ids})),
        effects=tuple(
            effect for decision in decisions for effect in decision.effects
            if effect.name == "request_effect"
        ),
    )
    assert narrowed.effects == lifecycle_effects(env[1])
    grant = env[6].issue_lifecycle(
        env[0], env[5].review(env[0], 10.0, 20.0), narrowed, 10.0,
    )
    return env, grant


def test_repeated_action_names_enter_distinct_ordered_real_occurrences(tmp_path, policy):
    env, grant = repeated_environment(tmp_path, policy)
    result = env[-1].execute(env[0], grant)
    assert result.completed
    assert tuple(receipt.binding.occurrence_id for receipt in result.receipts) == (
        "occurrence", "second-occurrence",
    )
    assert env[3].artifact("destination") == env[3].artifact("destination-two") == DATA
    assert len([item for item in env[2].writes if item[0] == "destination"]) == 1
    assert len([item for item in env[2].writes if item[0] == "destination-two"]) == 1


def test_reordered_or_skipped_real_occurrence_cannot_reserve_or_dispatch(tmp_path, policy):
    env, grant = repeated_environment(tmp_path, policy)
    session = env[6].consume_lifecycle(grant, env[1], 10.0)
    before = len(env[2].writes)
    wrong = lc.LifecycleEffectBinding(env[1], str(uuid4()), 0, "second-occurrence")
    with pytest.raises(AuthorizationError):
        env[6].permit_lifecycle(session, wrong, 10.0)
    assert len(env[2].writes) == before
    correct = replace(wrong, occurrence_id="occurrence")
    permit = env[6].permit_lifecycle(session, correct, 10.0)
    env[-1].enter(permit, correct)
    with pytest.raises(AuthorizationError):
        env[6].permit_lifecycle(session, replace(wrong, expected_revision=1), 10.0)
    env[-1].complete(permit)
    second = replace(
        wrong, event_id=str(uuid4()), expected_revision=env[3].snapshot_lifecycle(env[1]).revision,
    )
    next_permit = env[6].permit_lifecycle(session, second, 10.0)
    env[-1].enter(next_permit, second)
    env[-1].complete(next_permit)


def test_replanned_resume_requires_fresh_plan_and_private_receipt(tmp_path, policy):
    env = list(environment(tmp_path, policy))
    result = env[-1].execute(env[0], issue(env, policy))
    assert result.completed
    old_binding = env[1]
    old_lifecycle_id = env[0].lifecycle_id
    step = dict(env[0].content["steps"][0].items())
    step["source"] = None
    step["occurrence_id"] = "resume-verify"
    step = c.public_object(step)
    env[2].seed("step", step, revision=1)
    effect = replace(
        env[0].effects[0], occurrence_id="resume-verify", kind="dependency-verify",
        arguments_digest=lifecycle_arguments_digest(step),
    )
    content = dict(env[0].content.items())
    content["steps"], content["cancel_scope"] = (step,), ("resume-verify",)
    plan = replace(
        env[0], plan_id=str(uuid4()), effects=(effect,), content=c.public_object(content),
    )
    env[0] = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    env[1] = bind_lifecycle(env[0])
    assert env[0].lifecycle_id == old_lifecycle_id and env[1] != old_binding
    with pytest.raises(AuthorizationError):
        env[-1].execute(env[0], lc.LifecycleAuthorization())
    decision = continuation_decision(policy, env[1])
    decision = replace(decision, effects=tuple(
        effect for effect in decision.effects if effect.name == "request_effect"
    ))
    grant = env[6].issue_lifecycle(
        env[0], env[5].review(env[0], 10.0, 20.0), decision, 10.0,
    )
    resumed = env[-1].execute(env[0], grant)
    assert resumed.completed and resumed.receipts[0].kind == "dependency-verify"


def test_cancel_after_reservation_before_entry_is_not_an_uncertain_effect(tmp_path, policy):
    env = environment(tmp_path, policy)
    grant = issue(env, policy)

    class CancelAtEntry:
        calls = 0

        def monotonic(self):
            self.calls += 1
            if self.calls == 3:
                env[6].revoke_lifecycle(env[0].kind, env[0].plan_id)
            return 10.0

    executor = LifecycleExecutor(env[6], env[3], CancelAtEntry())
    result = executor.execute(env[0], grant)
    assert not result.completed and not result.uncertain
    assert not result.receipts and result.pending
    assert env[2].read("destination").payload["reserved"] is True


@pytest.mark.parametrize("action", (
    "dependency-probe", "dependency-download", "dependency-stage", "dependency-verify",
    "dependency-activate", "dependency-uninstall", "restore-active-pointer",
))
def test_original_a02_typed_host_entry_composes_real_admission_and_owned_io(
    tmp_path, policy, monkeypatch, action,
):
    """The documented bootstrap call uses existing typed constructors, not I02."""
    env = environment(tmp_path, policy, action)
    plan, binding, port, state, _, consent, broker, clock, _ = env
    owner = LifecycleExecutor(authorization=broker, state=state, clock=clock)
    calls = []

    def observe(name):
        original = getattr(broker, name)

        def invoke(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append(name)
            return result

        monkeypatch.setattr(broker, name, invoke)

    for name in (
        "consume_lifecycle", "permit_lifecycle", "enter_lifecycle", "complete_lifecycle",
    ):
        observe(name)
    original_begin = state.begin_receipt

    def begin(effect):
        assert calls == ["consume_lifecycle", "permit_lifecycle", "enter_lifecycle"]
        calls.append("owned_pending_before_fixed_handler")
        return original_begin(effect)

    monkeypatch.setattr(state, "begin_receipt", begin)
    actual_decision = (
        continuation_decision(policy, binding)
        if action in ("dependency-probe", "dependency-download", "dependency-verify")
        else decision_for(policy, binding)
    )
    # Only the factual aggregate action is omitted. All decision/identity/rule
    # fields remain the actual packaged evaluator's result, including denial.
    assert all(effect.name in ("request_effect", "record_outcome", "set_phase")
               for effect in actual_decision.effects)
    admitted_intents = replace(actual_decision, effects=tuple(
        effect for effect in actual_decision.effects if effect.name != "record_outcome"
    ))
    assert tuple(effect for effect in admitted_intents.effects
                 if effect.name == "request_effect") == lifecycle_effects(binding)
    assert tuple(effect for effect in admitted_intents.effects if effect.name == "set_phase") == (
        tuple(effect for effect in actual_decision.effects if effect.name == "set_phase")
    )
    receipt = consent.review(plan, clock.monotonic(), 20.0)
    grant = broker.issue_lifecycle(plan, receipt, admitted_intents, clock.monotonic())
    result = owner.execute(plan, grant)
    assert result.completed and not result.pending and not result.uncertain
    assert calls == [
        "consume_lifecycle", "permit_lifecycle", "enter_lifecycle",
        "owned_pending_before_fixed_handler", "complete_lifecycle",
    ]
    observed = result.receipts[0]
    assert observed.kind == action
    assert state.inspect_receipt(observed.binding)["phase"] == "observed"
    if action in ("dependency-activate", "restore-active-pointer"):
        assert observed.pointer == ("generation", plan.expected_pointer.revision + 1)
        assert state.pointer().active_generation_id == "generation"
    elif action in ("dependency-stage", "dependency-download"):
        assert state.artifact("destination") == DATA
    before = tuple(port.writes)
    with pytest.raises(AuthorizationError):
        owner.execute(plan, grant)
    with pytest.raises(AuthorizationError):
        broker.issue_lifecycle(plan, receipt, admitted_intents, clock.monotonic())
    assert tuple(port.writes) == before


def test_catalog_discovers_actual_typed_lifecycle_entry_and_transitive_dependency():
    """Discovery preserves complete public-module validation without exclusions."""
    registry = DependencyRegistry.load()
    registry.validate_public_sources(Path("netops"))
    operation = registry.operation("netops.ansible.lifecycle_execution", "LifecycleExecutor")
    assert operation.capability == "native.core"
    assert operation.dependencies == ("pyyaml",)


def test_host_intent_projection_cannot_replace_actual_policy_denial(tmp_path, policy):
    env = environment(tmp_path, policy)
    plan, binding, port, _, _, consent, broker, clock, _ = env
    identity, engine, source_facts = policy
    denied_facts = copy.deepcopy(source_facts)
    denied_facts["consent"]["present"] = False
    actual_decision = decision_for((identity, engine, denied_facts), binding)
    assert actual_decision.decision == "deny"
    projection = replace(actual_decision, effects=tuple(
        effect for effect in actual_decision.effects if effect.name == "request_effect"
    ))
    receipt = consent.review(plan, clock.monotonic(), 20.0)
    with pytest.raises(AuthorizationError):
        broker.issue_lifecycle(plan, receipt, projection, clock.monotonic())
    assert port.writes == []


def test_frozen_dependency_constructor_plans_lifecycle_entry_without_provisioning(tmp_path, policy):
    env = environment(tmp_path, policy)
    _, _, owned, _, _, _, broker, clock, _ = env
    identity, engine, _ = policy
    registry = DependencyRegistry.load()
    adapter = FixtureAdapter(missing=("pyyaml",))
    emitted = []

    class Events:
        def emit(self, event):
            emitted.append(event)

    service = DependencyService(
        registry, dict.fromkeys(ADAPTERS, adapter), owned, engine, broker, clock, Events(),
    )
    context = c.InstallContext(c.Context(
        "controller", D, "fixture", D, identity, registry.digest, D,
    ))
    scope = c.InstallScope(
        ("netops.ansible.lifecycle_execution:LifecycleExecutor",), (), False,
    )
    planned = service.plan(scope, context)
    assert "pyyaml" in {step.dependency for step in planned.steps}
    assert adapter.calls == []
    assert owned.writes == []
    readiness = service.verify(scope, context)
    assert readiness.readiness.native == "blocked"
    assert "pyyaml" in {dependency for dependency, _, _ in adapter.calls}
    assert emitted and owned.writes == []
