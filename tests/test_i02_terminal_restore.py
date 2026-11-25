"""Managed qualified retained fixtures: fake functional ports, not platform proof."""

import hashlib
import io
import stat
import zipfile
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
from netops.dependencies._assets import AssetResponse, LockedAsset
from netops.dependencies._composition import ManagedLifecycleState
from netops.dependencies._managed import ManagedArchive, ManagedMember
from netops.dependencies._recovery import RecoverySelection
from netops.dependencies._restore import ManagedQualification
from netops.dependencies.service import DependencyService
from tests.policy.test_lifecycle_execution import OWNER, Review
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel
from tests.test_i02_public_flow import DATA, Events, public_case, restarted


class Runs:
    """Fake joined owned-run port; approved recovery survives the drain."""

    def __init__(self):
        self.enabled = True
        self.calls = []
        self.before = ()
        self.after = ()
        self.busy = False
        self.recovery_preserved = True

    def pins(self):
        return self.after if "drain" in self.calls else self.before

    def stop_admission(self):
        self.enabled = False
        self.calls.append("stop")

    def drain(self, cancel, clock, deadline):
        self.calls.append("drain")
        assert self.recovery_preserved
        return not self.busy

    def start_admission(self, generation):
        self.calls.append("start")
        self.enabled = True


def qualified_case(tmp_path, policy):
    service, scope, context, port, host, effects, engine, _ = public_case(tmp_path, policy)
    manifest = host.manifests[0]
    generation = lc.GenerationBinding(manifest.generation_id, 0, manifest.content_digest, c.digest(manifest))
    report = service.verify(scope, context)
    item = ManagedQualification(
        generation, scope, context, manifest.consuming_contexts, c.digest(report), "a" * 64,
    )
    # A separate known managed generation represents the broken current install.
    # Its interpreter/context is never inspected/executed by restore planning.
    current = replace(manifest, generation_id=str(uuid4()), context=c.InstallContext(
        replace(context.context, source_id="broken-current-unit-generation"),
    ))
    verification = c.public_object({
        "kind": "candidate", "event_kind": "CandidateVerified", "event_id": str(uuid4()),
        "revision": 0, "generation_id": generation.generation_id,
        "content_digest": generation.content_digest, "manifest_digest": generation.manifest_digest,
        "context_digest": c.digest(context), "registry_digest": service.registry.digest,
        "policy_digest": service._policy_identity.bundle_sha256,
        "qualification_digest": item.qualification_digest,
        "observed_at": 9.0, "expires_at": 70.0,
        "probes": ({"probe_id": "dependency-readiness", "generation_id": generation.generation_id,
                    "content_digest": generation.content_digest, "context_digest": c.digest(context),
                    "result_digest": c.digest(report), "status": "succeeded"},),
    })
    port.seed("managed-root", {
        "schema": "i02-managed-generations-v1",
        "generations": tuple({
            "generation_id": value.generation_id, "manifest": c.wire(value), "state": "staged",
            "plan_digest": "b" * 64, "occurrence_id": "unit-completed-stage",
            "staging_directory": "unit-not-used", "directory": "unit-owned-tree",
        } for value in (manifest, current)),
        "root_manifest": {
            "control_resource": "managed-control",
            "registered_manifests": tuple(c.wire(value) for value in (manifest, current)),
            "registered_qualifications": (c.wire(item),),
        },
    })
    old_pointer = lc.PresentPointer("present", current.generation_id, "c" * 64, 2)
    port.seed("managed-control", {
        "schema": "i02-managed-control-v1", "pointer": c.wire(old_pointer),
        "verification": None, "setup_enabled": True, "installation_id": None,
    })
    recovery = RecoverySelection(str(uuid4()), str(uuid4()), generation, scope, context,
                                 manifest.consuming_contexts, c.digest(report))
    port.seed("dependency-generation-" + c.digest(generation), {
        "schema": "i02-lifecycle-recovery-v1", "selection": c.wire(recovery),
    })
    port.seed("dependency-verification-" + c.digest(generation), {
        "schema": "i02-retained-verification-v1", "verification": verification,
    })
    effects.tree = tuple((member, DATA) for member in manifest.members)
    runs = Runs()
    runs.before = tuple(c.public_object({
        "generation_id": value.generation_id, "manifest_digest": c.digest(value),
        "revision": 0, "holders": (),
    }) for value in (manifest, current))
    runs.after = runs.before
    state = ManagedLifecycleState(
        port, "managed-root", "managed-control", OWNER, service._policy_identity,
        (manifest, current), effects, effects, (item,), runs,
    )
    review = Review()
    private = TrustedLifecycleConsentAdapter(review)
    broker = AuthorizationBroker(None, TrustedConsentAdapter(review),
                                 lifecycle_state=state, lifecycle_consent=private)
    fresh = DependencyService(service.registry, service.adapters, state, engine,
                              broker, service.clock, Events())
    return fresh, state, port, effects, private, context, generation, runs, old_pointer


def test_actual_fresh_service_retained_plan_and_restore_never_runs_broken_current(tmp_path, policy):
    service, host, port, effects, private, context, generation, runs, pointer = qualified_case(tmp_path, policy)
    before = len(effects.calls), len(port.writes)
    plan = service.plan_restore(generation.generation_id, context)
    assert before == (len(effects.calls), len(port.writes)), "Planning is metadata-only"
    result = service.restore(plan, private.review(plan, 10.0, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    assert result.selected_scope == host.qualifications[0].scope
    assert result.active_generation_id == generation.generation_id
    assert result.previous_generation_id == pointer.active_generation_id
    assert result.pointer_revision == 3
    assert result.readiness.native == "ready"
    assert runs.calls == ["stop", "drain", "start"] and runs.enabled
    assert all(call[0] == "verify" and call[1] == generation.generation_id for call in effects.calls)
    head = port.read("dependency-policy-" + plan.plan_id)
    assert head.payload["state"]["dispositions"][0]["disposition"] == "succeeded"


@pytest.mark.parametrize("when", ["before", "after"])
def test_actual_restore_cancel_preserves_factual_pointer_without_reverse(tmp_path, policy, when):
    service, host, port, _, private, context, generation, runs, pointer = qualified_case(tmp_path, policy)
    plan = service.plan_restore(generation.generation_id, context)
    consent = private.review(plan, 10.0, 30.0)
    cancel = Cancel()
    if when == "before":
        cancel.value = True
    else:
        def after_cas(resource, record):
            if resource == "managed-control" and record.payload["pointer"]["revision"] == 3:
                cancel.value = True
        port.after_cas = after_cas
    result = service.restore(plan, consent, cancel)
    assert host.pointer().revision == (2 if when == "before" else 3)
    assert result.active_generation_id == (pointer.active_generation_id if when == "before" else generation.generation_id)
    assert result.status == (c.OutcomeStatus.CANCELLED if when == "before" else c.OutcomeStatus.PARTIAL)
    if when == "after":
        assert result.steps[0].status == c.OutcomeStatus.SUCCEEDED
        assert not runs.enabled and host._control().payload["admission_enabled"] is False
        head = port.read("dependency-policy-" + plan.plan_id)
        assert head.payload["state"]["dispositions"][0]["disposition"] == "succeeded"


def test_restore_postcheck_failure_stops_admission_and_needs_new_consent(tmp_path, policy):
    service, host, _, effects, private, context, generation, runs, _ = qualified_case(tmp_path, policy)
    plan = service.plan_restore(generation.generation_id, context)
    consent = private.review(plan, 10.0, 30.0)
    original = effects.verify
    def verify(*args):
        if host.pointer().revision == 3:
            raise PermissionError("fake retained postcheck failure")
        original(*args)
    effects.verify = verify
    result = service.restore(plan, consent, Cancel())
    assert result.status == c.OutcomeStatus.PARTIAL and result.active_generation_id == generation.generation_id
    assert not runs.enabled and host._control().payload["admission_enabled"] is False
    assert result.pending_actions == ("review-new-exact-restore",)
    replay = service.restore(plan, consent, Cancel())
    assert replay.status == c.OutcomeStatus.BLOCKED
    assert host.pointer().revision == 3


def test_restore_busy_owned_run_drain_keeps_old_pointer_and_recovery(tmp_path, policy):
    service, host, _, _, private, context, generation, runs, pointer = qualified_case(tmp_path, policy)
    runs.busy = True
    plan = service.plan_restore(generation.generation_id, context)
    result = service.restore(plan, private.review(plan, 10.0, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.BLOCKED
    assert host.pointer() == pointer and not runs.enabled and runs.recovery_preserved


def test_restore_pin_drift_never_enters_pointer_cas(tmp_path, policy):
    service, host, _, _, private, context, generation, runs, pointer = qualified_case(tmp_path, policy)
    runs.before = (c.public_object({"generation_id": generation.generation_id, "manifest_digest": generation.manifest_digest, "revision": 1, "holders": ("owned-run",)}), runs.before[1])
    runs.after = (c.public_object({"generation_id": generation.generation_id, "manifest_digest": "f" * 64, "revision": 2, "holders": ()}), runs.after[1])
    plan = service.plan_restore(generation.generation_id, context)
    result = service.restore(plan, private.review(plan, 10.0, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.BLOCKED and host.pointer() == pointer


def test_missing_qualification_or_corrupt_retained_digest_cannot_plan(tmp_path, policy):
    service, _, port, _, _, context, generation, _, _ = qualified_case(tmp_path, policy)
    record = port.read("dependency-verification-" + c.digest(generation))
    port.seed(record.resource_id, {"schema": "i02-retained-verification-v1", "verification": {
        **dict(record.payload["verification"]), "manifest_digest": "f" * 64,
    }})
    with pytest.raises((AuthorizationError, c.ContractError, ValueError)):
        service.plan_restore(generation.generation_id, context)


def test_multiple_registered_archive_assets_compose_full_selected_native_closure(tmp_path, policy):
    service, _, context, port, host, effects, engine, _ = public_case(tmp_path, policy)
    scope = c.InstallScope(("netops.report.health_dashboard:render_html",), (), False, False)
    primary = host.manifests[0]
    data = b"fake jinja2 package; unit file contribution, no package installation claim"
    path = "lib/jinja2.py"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo(path)
        info.external_attr = (stat.S_IFREG | 0o600) << 16
        archive.writestr(info, data)
    content = buffer.getvalue()
    asset = LockedAsset("unit-jinja2", "jinja2", "https://files.pythonhosted.org/unit.whl",
                        hashlib.sha256(content).hexdigest(), len(content))
    archives = (
        ManagedArchive(primary.asset, primary.archive, primary.members),
        ManagedArchive(asset, "zip", (ManagedMember(path, hashlib.sha256(data).hexdigest(), len(data)),)),
    )
    manifest = replace(primary, scope=scope, archives=archives,
                       members=tuple(member for archive in archives for member in archive.members))
    port.seed("managed-root", {
        "schema": "i02-managed-generations-v1", "generations": (),
        "root_manifest": {"control_resource": "managed-control", "registered_manifests": (c.wire(manifest),)},
    })
    acquired = {primary.asset.url: effects.content, asset.url: content}
    def read(url, timeout, limit):
        effects.calls.append(("download", url))
        return AssetResponse(url, acquired[url])
    def verify(value, clock, cancel, deadline):
        effects.calls.append(("verify", value.generation_id))
        assert effects.tree == ((manifest.members[0], DATA), (manifest.members[1], data))
    effects.read, effects.verify = read, verify
    state = ManagedLifecycleState(port, "managed-root", "managed-control", OWNER,
                                  service._policy_identity, (manifest,), effects, effects)
    review = Review()
    private = TrustedLifecycleConsentAdapter(review)
    broker = AuthorizationBroker(None, TrustedConsentAdapter(review),
                                 lifecycle_state=state, lifecycle_consent=private)
    fresh = DependencyService(service.registry, service.adapters, state, engine,
                              broker, service.clock, Events())
    plan = fresh.plan(scope, context)
    assert not plan.blocked
    assert tuple(step.dependency for step in plan.steps) == ("native-python", "jinja2")
    assert tuple(effect.kind for effect in plan.lifecycle.effects) == (
        "dependency-download", "dependency-download", "dependency-stage", "dependency-verify",
    )
    result = fresh.provision(plan, fresh.review(plan, 10.0, 30.0), Cancel())
    assert all(step.status == c.OutcomeStatus.SUCCEEDED for step in result.steps), result
    assert result.status == c.OutcomeStatus.PARTIAL
    activation = fresh.plan(scope, context)
    result = fresh.provision(activation, fresh.review(activation, 10.0, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert [call[1] for call in effects.calls if call[0] == "download"] == list(acquired)


def test_restore_drains_reviewed_owned_pins_outside_locks_preserving_recovery(tmp_path, policy):
    service, host, _, _, private, context, generation, runs, _ = qualified_case(tmp_path, policy)
    runs.before = tuple(c.public_object({**dict(pin), "holders": ("owned-run",)}) for pin in runs.before)
    runs.after = tuple(c.public_object({**dict(pin), "revision": 1}) for pin in runs.after)
    original = runs.drain
    def drain(*args):
        assert getattr(host._local, "depth", 0) == 0, "Recovery must not be blocked by held root lock"
        return original(*args)
    runs.drain = drain
    plan = service.plan_restore(generation.generation_id, context)
    result = service.restore(plan, private.review(plan, 10.0, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.SUCCEEDED and runs.recovery_preserved


def test_missing_managed_run_pin_records_block_retained_planning(tmp_path, policy):
    service, _, _, _, _, context, generation, runs, _ = qualified_case(tmp_path, policy)
    runs.before = runs.after = ()
    with pytest.raises(AuthorizationError):
        service.plan_restore(generation.generation_id, context)


def test_fresh_resume_skips_finished_stage_and_retains_original_failure_history(tmp_path, policy):
    service, scope, context, _, host, effects, engine, _ = public_case(tmp_path, policy)
    plan = service.plan(scope, context)
    engine.deny = lc.EventKind.DEPENDENCY_OBSERVED
    first = service.provision(plan, service.review(plan, 10.0, 30.0), Cancel())
    assert first.errors and first.status == c.OutcomeStatus.PARTIAL
    engine.deny = None
    fresh, _ = restarted(service, host)
    activation = fresh.plan(scope, context)
    resumed = fresh.resume(first.installation_id, fresh.review(activation, 10.0, 30.0), Cancel())
    assert resumed.status == c.OutcomeStatus.SUCCEEDED
    assert resumed.original_errors == first.errors
    assert [call[0] for call in effects.calls].count("download") == 1
    assert [call[0] for call in effects.calls].count("stage") == 1


def test_restore_log_metric_pair_and_throwing_event_sink_are_non_authoritative(tmp_path, policy, caplog):
    service, _, _, _, private, context, generation, _, _ = qualified_case(tmp_path, policy)
    class ThrowingEvents:
        def emit(self, event):
            raise RuntimeError("unit event sink failure")
    service.events = ThrowingEvents()
    plan = service.plan_restore(generation.generation_id, context)
    with caplog.at_level("INFO"):
        result = service.restore(plan, private.review(plan, 10.0, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.SUCCEEDED
    pairs = [record for record in caplog.records if record.getMessage() == "install.step"]
    assert len(pairs) == 1
    record = pairs[0]
    assert record.metric_name == "netops.install.step.count"
    assert record.kind == "restore" and record.step_kind == "restore-active-pointer"
    assert record.duration >= 0 and record.status == "succeeded"


@pytest.mark.parametrize("when", ["before", "after"])
def test_restore_probe_cancellation_rechecks_before_cas_or_admission(tmp_path, policy, when):
    service, host, _, effects, private, context, generation, runs, pointer = qualified_case(tmp_path, policy)
    plan = service.plan_restore(generation.generation_id, context)
    cancel = Cancel()
    original = effects.verify
    def verify(*args):
        original(*args)
        if host.pointer().revision == (2 if when == "before" else 3):
            cancel.value = True
    effects.verify = verify
    result = service.restore(plan, private.review(plan, 10.0, 30.0), cancel)
    assert result.status == (c.OutcomeStatus.CANCELLED if when == "before" else c.OutcomeStatus.PARTIAL)
    assert result.active_generation_id == (pointer.active_generation_id if when == "before" else generation.generation_id)
    assert not runs.enabled and "start" not in runs.calls


def test_restore_postcheck_expiry_never_reopens_admission(tmp_path, policy):
    service, host, _, effects, private, context, generation, runs, _ = qualified_case(tmp_path, policy)
    class Clock:
        value = 10.0
        def monotonic(self):
            return self.value
    service.clock = Clock()
    plan = service.plan_restore(generation.generation_id, context)
    original = effects.verify
    def verify(*args):
        original(*args)
        if host.pointer().revision == 3:
            service.clock.value = 40.0
    effects.verify = verify
    result = service.restore(plan, private.review(plan, 10.0, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.PARTIAL
    assert result.active_generation_id == generation.generation_id
    assert not runs.enabled and "start" not in runs.calls


def test_restore_changed_expected_pointer_requires_new_review(tmp_path, policy):
    service, host, port, _, private, context, generation, _, pointer = qualified_case(tmp_path, policy)
    plan = service.plan_restore(generation.generation_id, context)
    consent = private.review(plan, 10.0, 30.0)
    control = host._control()
    advanced = replace(pointer, revision=3)
    port.seed(control.resource_id, {**dict(control.payload), "pointer": c.wire(advanced)})
    result = service.restore(plan, consent, Cancel())
    assert result.status == c.OutcomeStatus.BLOCKED and host.pointer() == advanced


def test_restore_unexpected_failure_uses_paired_unhandled_observation(tmp_path, policy, caplog):
    service, _, _, _, private, context, generation, runs, _ = qualified_case(tmp_path, policy)
    plan = service.plan_restore(generation.generation_id, context)
    def drain(*args):
        raise RuntimeError("unit private diagnostic must not be logged")
    runs.drain = drain
    with caplog.at_level("INFO"):
        result = service.restore(plan, private.review(plan, 10.0, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.BLOCKED
    pairs = [record for record in caplog.records if record.getMessage() == "install.step"]
    assert len(pairs) == 1 and pairs[0].stage == "Unhandled"
    assert pairs[0].metric_name == "netops.install.step.count"
    assert "unit private diagnostic" not in caplog.text


@pytest.mark.parametrize("corruption", ["target", "effect", "replayed"])
def test_factual_activation_rejects_corrupt_selected_completion_bindings(tmp_path, policy, corruption):
    service, scope, context, _, _, _, engine, _ = public_case(tmp_path, policy)
    first = service.plan(scope, context)
    service.provision(first, service.review(first, 10.0, 30.0), Cancel())
    original = engine.reduce
    checked = []
    def reduce(state, event, facts):
        if event.kind == lc.EventKind.ACTIVATED:
            pending = state.dispositions[-1]
            if corruption == "target":
                broken = replace(state, dispositions=(*state.dispositions[:-1], replace(pending, target_id="wrong-root")))
            elif corruption == "effect":
                broken = replace(state, dispositions=(*state.dispositions[:-1], replace(pending, effect_id=None)))
            else:
                broken = replace(state, consumed_effect_receipts=(*state.consumed_effect_receipts, pending.effect_id))
            with pytest.raises(lc.PolicyInputError):
                original(broken, event, facts)
            checked.append(corruption)
        return original(state, event, facts)
    engine.reduce = reduce
    activation = service.plan(scope, context)
    outcome = service.provision(activation, service.review(activation, 10.0, 30.0), Cancel())
    assert outcome.status == c.OutcomeStatus.SUCCEEDED and checked == [corruption]
