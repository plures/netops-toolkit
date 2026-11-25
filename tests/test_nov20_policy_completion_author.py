"""Owned causal policy controls; inert ports are not platform qualification."""

import hashlib
import inspect
import json
import os
import subprocess
import sys
import textwrap
from dataclasses import replace
from pathlib import Path
from types import MethodType
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.engine import LocalReferencePolicyEngine, PolicyInputError
from netops.ansible.policy.loader import load_policy
from netops.dependencies._uninstall import ManagedUninstall
from netops.dependencies.runs import OwnedGenerationRuns
from tests.policy.test_lifecycle_execution import OWNER
from tests.policy.test_policy_derivation import cancellation_facts, full_occurrence_case
from tests.policy.test_policy_derivation import canonical_context as canonical_context
from tests.test_i02_author_lifecycle import Cancel
from tests.test_i02_public_flow import public_case
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed
from tests.test_workflow_execution import policy as policy


def _generated(sources):
    base = sources.value.request
    content = json.dumps({"results": [{
        "host": "r1", "device_type": "cisco_ios", "success": True,
        "timestamp": "2026-11-20T06:30:00Z",
        "checks": {"cpu": {"alert": True, "usage_percent": 99}},
    }]}).encode()
    ref = c.InputRef("findings", "owned-findings", hashlib.sha256(content).hexdigest())
    request = replace(
        base, operation="compare.generate", mode=c.Mode.OUTPUT, inputs=(ref,),
        output_intent=c.OutputIntent(("yaml",), "owned"),
    )
    sources.value = replace(sources.value, request=request, sources=(
        c.InputSource(ref, "json", content, "parser-1", "vendor-1", observations=(
            c.Observation(
                "bound-findings-observation", "r1", c.digest(request.context),
                request.context.route_digest, request.context.controller_id, ref, ref.digest,
                "2026-11-20T06:30:00Z", 0.0,
            ),
        )),
    ))
    return request


@pytest.mark.parametrize("mutation", ("no-consent", "input-drift", "root-drift", "replay"))
def test_actual_generate_authority_is_bound_and_one_use(output_composed, mutation):
    service, host, sources, effects, filesystem, _ = output_composed
    request = _generated(sources)
    grant = None if mutation == "no-consent" else host.review(service, request)
    if mutation == "input-drift":
        source = sources.value.sources[0]
        sources.value = replace(sources.value, sources=(replace(
            source, content=source.content + b" ",
        ),))
    elif mutation == "root-drift":
        filesystem.inode += 1
    elif mutation == "replay":
        first = service.execute(request, grant)
        assert first.status == c.OutcomeStatus.SUCCEEDED, first
    before = len(filesystem.bindings)
    result = service.execute(request, grant)
    assert result.status != c.OutcomeStatus.SUCCEEDED
    assert len(filesystem.bindings) == before
    assert effects.calls == []


@pytest.mark.parametrize("mode", (c.Mode.PREVIEW, c.Mode.CHECK))
def test_generate_pure_modes_never_request_output(output_composed, mode):
    service, host, sources, effects, filesystem, _ = output_composed
    request = replace(_generated(sources), mode=mode, output_intent=c.OutputIntent())
    sources.value = replace(sources.value, request=request)
    result = service.execute(request)
    assert result.artifacts == ()
    assert effects.calls == [] and filesystem.bindings == []


def _uninstall(tmp_path, policy, monkeypatch, removal=None):
    service, scope, context, port, state, effects, engine, private = public_case(tmp_path, policy)
    plan = service.plan(scope, context)
    provisioned = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    safe_provisioned = c.canonical_bytes(provisioned).decode("utf-8")
    # This inert fixture stages an inactive generation, not a ready installation.
    assert provisioned.status == c.OutcomeStatus.PARTIAL, safe_provisioned
    assert [step.kind for step in provisioned.steps] == [
        "dependency-download", "dependency-stage", "dependency-verify",
    ], safe_provisioned
    assert all(step.status == c.OutcomeStatus.SUCCEEDED for step in provisioned.steps), safe_provisioned
    assert provisioned.pending_actions == ("review-activation-plan",), safe_provisioned
    assert not provisioned.errors and not provisioned.cleanup_errors, safe_provisioned
    assert state.pointer() == lc.AbsentPointer("absent", 0), safe_provisioned
    manifest = state.manifests[0]
    generation = lc.GenerationBinding(manifest.generation_id, 0, manifest.content_digest, c.digest(manifest))
    state.runs = OwnedGenerationRuns(
        port, "managed-root", "managed-control", OWNER, policy[0], (generation,), generation.generation_id,
    )
    state.runs.initialize()
    uninstall = service.plan_uninstall(generation.generation_id, context)
    consent = private.review(uninstall, 10.0, 20.0)
    monkeypatch.setattr(
        ManagedUninstall, "_remove_selected",
        removal or (lambda self, removed, remaining: removed.append("owned")),
    )
    return service, state, port, engine, uninstall, consent


@pytest.mark.parametrize("mutation", ("remaining", "pointer-change", "new-pin"))
def test_uninstall_incomplete_or_changed_poststate_is_never_terminal(tmp_path, policy, monkeypatch, mutation):
    def removal(self, removed, remaining):
        removed.append("owned")
        if mutation == "remaining":
            remaining.append("owned-unremoved")
        elif mutation == "pointer-change":
            control = self.host._facts_resource
            assert control == "managed-root"
            record = self.host._state.read("managed-control")
            self.host._state.seed("managed-control", {
                **dict(record.payload),
                "pointer": c.wire(lc.PresentPointer("present", str(uuid4()), "a" * 64, 1)),
            })
        else:
            generation = self.host.runs.generations[0]
            resource = self.host.runs._resource(generation)
            record = self.host._state.read(resource)
            self.host._state.seed(resource, {
                **dict(record.payload), "holders": (str(uuid4()),),
            })

    service, state, port, engine, plan, consent = _uninstall(tmp_path, policy, monkeypatch, removal)
    engine.events.clear()
    result = service.uninstall(plan, consent)
    assert result.status != c.OutcomeStatus.SUCCEEDED
    assert not any(event.kind == lc.EventKind.STEP_COMPLETED for event in engine.events)
    receipt = port.read("dependency-uninstall-result-" + plan.plan_id)
    assert receipt.payload["completed"] is False
    if mutation == "remaining":
        assert result.pending_actions == ("owned-unremoved",)
    else:
        assert result.errors
    assert service.uninstall(plan, consent).status != c.OutcomeStatus.SUCCEEDED


@pytest.mark.parametrize("phase", (lc.Phase.ADMITTED, lc.Phase.EXECUTING))
@pytest.mark.parametrize("mutation", (
    "poststate", "ownership", "pointer", "invocation", "effect", "revision", "incomplete",
))
def test_terminal_uninstall_requires_exact_correlated_verified_receipt(
    tmp_path, policy, monkeypatch, phase, mutation,
):
    service, state, port, engine, plan, consent = _uninstall(tmp_path, policy, monkeypatch)
    captured = []
    original = engine.reduce

    def capture(current, event, facts):
        if event.kind == lc.EventKind.STEP_COMPLETED:
            captured.append((current, event, facts))
        return original(current, event, facts)

    monkeypatch.setattr(engine, "reduce", capture)
    outcome = service.uninstall(plan, consent)
    assert outcome.status == c.OutcomeStatus.SUCCEEDED, outcome
    current, event, facts = captured[0]
    current = replace(current, phase=phase)
    facts = replace(facts, state_phase=phase)
    values = dict(facts.values)
    if mutation in ("poststate", "ownership", "pointer"):
        key, field = {
            "poststate": ("change", "poststate_verified"),
            "ownership": ("ownership", "valid"),
            "pointer": ("candidate", "pointer_matches"),
        }[mutation]
        values[key] = {**dict(values[key]), field: False}
    elif mutation in ("invocation", "effect"):
        key = "invocation_id" if mutation == "invocation" else "effect_id"
        event = replace(event, payload=c.public_object({**dict(event.payload), key: "wrong"}))
    elif mutation == "revision":
        event = replace(event, expected_revision=0)
    else:
        values["result"] = {
            **dict(values["result"]), "completed": 0, "unsuccessful": 1, "blocked": 1,
        }
    facts = replace(facts, values=c.public_object(values))
    try:
        refused = engine.engine.reduce(current, event, facts)
    except PolicyInputError:
        return
    assert refused.next_state.phase != lc.Phase.COMPLETED
    assert refused.next_state.consumed_effect_receipts == current.consumed_effect_receipts
    assert refused.effects == ()


def test_terminal_uninstall_replay_does_not_consume_twice(tmp_path, policy, monkeypatch):
    service, state, port, engine, plan, consent = _uninstall(tmp_path, policy, monkeypatch)
    captured = []
    original = engine.reduce

    def capture(current, event, facts):
        transition = original(current, event, facts)
        if event.kind == lc.EventKind.STEP_COMPLETED:
            captured.append((transition, event, facts))
        return transition

    monkeypatch.setattr(engine, "reduce", capture)
    assert service.uninstall(plan, consent).status == c.OutcomeStatus.SUCCEEDED
    transition, event, facts = captured[0]
    with pytest.raises(PolicyInputError):
        engine.engine.reduce(
            transition.next_state, event, replace(
                facts, state_phase=transition.next_state.phase,
                state_revision=transition.next_state.revision,
            ),
        )
    replay = engine.engine.reduce(transition.next_state, event, replace(
        facts, state_phase=transition.next_state.phase,
    ))
    assert replay.next_state == transition.next_state and replay.effects == ()
    assert replay.decision.decision == "deny"


def test_clean_source_setup_reaches_full_registry_without_site_packages(tmp_path):
    root = Path(__file__).resolve().parents[1]
    selected = tmp_path / "not-created"
    code = (
        "import sys;sys.path.insert(0,sys.argv.pop(1));"
        "from netops.setup import main;raise SystemExit(main())"
    )
    result = subprocess.run(
        (sys.executable, "-I", "-S", "-B", "-c", code, str(root), "plan", "--root", str(selected)),
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 3, result.stderr
    assert "Selected registry" in result.stdout
    assert "default selection remains full toolkit" in result.stdout
    assert "ModuleNotFoundError" not in result.stderr
    assert not selected.exists()


def test_terminal_uninstall_phase_correction_is_load_bearing(tmp_path, policy, monkeypatch):
    from netops.ansible.policy import engine as engine_module

    service, state, port, engine, plan, consent = _uninstall(tmp_path, policy, monkeypatch)
    source = textwrap.dedent(inspect.getsource(LocalReferencePolicyEngine.reduce))
    needle = "or terminal_uninstall"
    assert source.count(needle) == 1
    namespace = dict(vars(engine_module))
    exec(compile(source.replace(needle, "or False"), "<author-phase-ablation>", "exec"), namespace)
    monkeypatch.setattr(engine.engine, "reduce", MethodType(namespace["reduce"], engine.engine))
    result = service.uninstall(plan, consent)
    assert result.status != c.OutcomeStatus.SUCCEEDED and result.errors
    assert port.read("dependency-uninstall-result-" + plan.plan_id).payload["completed"] is False


def test_actual_canonical_save_selector_is_load_bearing(tmp_path, output_composed):
    from netops.ansible.execution import _Rejected

    service, host, sources, effects, filesystem, _ = output_composed
    request = _generated(sources)
    root = Path(__file__).resolve().parents[1]
    binary = Path(os.environ["NETOPS_CANONICAL_ADAPTER"]).resolve(strict=True)
    assert root in binary.parents and not binary.is_symlink()
    policy_root = root / "netops" / "ansible" / "policy"
    source = (policy_root / "ansible_molecule.px").read_text(encoding="utf-8")
    contracts = (policy_root / "ansible_molecule.contracts.px").read_text(encoding="utf-8")
    start = source.index("rule netops_companion_compare_operation_requested_save:")
    end = source.index("rule netops_companion_report_", start)
    source = source[:start] + source[end:]
    start = contracts.index("contract netops_companion_compare_operation_requested_save_contract:")
    end = contracts.index("contract netops_companion_report_", start)
    contracts = contracts[:start] + contracts[end:]
    input_path, contract_path = tmp_path / "ablation.px", tmp_path / "ablation.contracts.px"
    input_path.write_bytes(source.encode())
    contract_path.write_bytes(contracts.encode())
    emitted = tmp_path / "emitted"
    emitted.mkdir()
    result = subprocess.run(
        (str(binary), "--source", str(input_path), "--contracts", str(contract_path),
         "--emit-dir", str(emitted)),
        capture_output=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    raw = (emitted / "bundle.json").read_bytes()
    bundle = json.loads(raw)
    identity = lc.PolicyIdentity(
        bundle["canonical_revision"],
        hashlib.sha256(input_path.read_bytes()).hexdigest(),
        hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        hashlib.sha256(raw).hexdigest(),
        tuple(item["id"] for item in bundle["manifest"]), bundle["reducer_version"],
    )
    service._policy = LocalReferencePolicyEngine(load_policy(
        input_path.read_bytes(), contract_path.read_bytes(), raw, identity,
    ))
    request = replace(request, context=replace(request.context, policy_identity=identity))
    sources.value = replace(sources.value, request=request, sources=tuple(
        replace(item, observations=tuple(
            replace(observation, context_digest=c.digest(request.context))
            for observation in item.observations
        )) for item in sources.value.sources
    ))
    with pytest.raises(_Rejected, match="consent-stale"):
        host.review(service, request)
    assert filesystem.bindings == [] and effects.calls == []


@pytest.mark.parametrize("mutation", (
    "none", "input", "vendor", "unsafe", "no-consent", "expired", "binding", "effects",
    "preview", "check", "cancelled",
))
def test_canonical_generate_matches_runtime_without_broad_authority(canonical_context, policy, mutation):
    identity, engine = policy
    facts = cancellation_facts("generate", False, 1000, False)
    facts["request"] = {"area": "compare", "operation": "generate", "mode": "output"}
    mode = "output"
    fires = True
    if mutation in ("input", "vendor"):
        facts["compare"]["inputs_bound" if mutation == "input" else "vendor_supported"] = False
        fires = False
    elif mutation == "unsafe":
        facts["report"]["output_safe"] = False
        fires = False
    elif mutation in ("preview", "check"):
        mode = mutation
        facts["request"]["mode"] = mutation
        fires = False
    elif mutation == "cancelled":
        facts["control"]["cancelled"] = True
    elif mutation != "none":
        key, value = {
            "no-consent": ("present", False), "expired": ("remaining_ms", 0),
            "binding": ("binding_matches", False), "effects": ("effects_match", False),
        }[mutation]
        facts["consent"][key] = value
    payload = {"request_digest": "3" * 64, "loaded_input_digest": "4" * 64,
               "plan_digest": "1" * 64, "mode": mode}
    inputs = {
        "state": {"phase": "Planned", "revision": 1},
        "event": {
            "schema": "1.0", "event_id": "40000000-0000-4000-8000-000000000004",
            "operation_id": "60000000-0000-4000-8000-000000000006",
            "kind": "OperationRequested", "expected_revision": 1,
            "plan_digest": "1" * 64, "context_digest": "2" * 64,
            "policy_digest": "9" * 64, "target_id": "local", "step_id": "owned-save",
            "payload": payload,
        },
        "facts": facts,
    }
    actions = [{"name": "request_effect", "params": {"kind": "save"}}] if fires else []
    canonical = full_occurrence_case(
        canonical_context, "netops_companion_compare_operation_requested_save",
        inputs, actions, fires=fires,
    )["combined"]
    event = lc.DecisionEvent(
        inputs["event"]["event_id"], lc.EventKind.OPERATION_REQUESTED, 1,
        "1" * 64, "2" * 64, identity.bundle_sha256, "local", "owned-save",
        c.public_object(payload), operation_id=inputs["event"]["operation_id"],
    )
    runtime = engine.decide(event, lc.DecisionFacts(facts, lc.Phase.PLANNED, 1))
    assert runtime.decision == canonical["decision"]
    assert [{"name": effect.name, "params": dict(effect.params)} for effect in runtime.effects] == canonical["actions"]
    if mutation == "none":
        assert canonical["actions"] == actions
    else:
        assert not [action for action in canonical["actions"] if action["name"] == "request_effect"]
