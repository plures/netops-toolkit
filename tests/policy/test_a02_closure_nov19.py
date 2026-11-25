"""Original A02 boundary and literal public-wire closure; no platform qualification."""

import os
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.execution import EffectResult
from netops.ansible.lifecycle_execution import LifecycleHandlerReceipt, LifecycleRunResult
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.contracts import PolicyIdentity
from netops.ansible.settings import AnsibleSettings
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import policy as policy

OPERATION = "e9c85d98-b991-4d8c-a92b-a7c3e3437816"

REQUEST_GOLDEN = (
    '{"context":{"assets_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    '"controller_id":"local","mapping_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    '"policy_identity":{"bundle_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    '"canonical_revision":"6d367fe673756dabaa6085bc6b5202debaaabe6f",'
    '"contracts_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    '"numeric_profile":"exact-int53-finite-order-v1","profile":"netops-reference-v1",'
    '"reducer_version":"1","rule_manifest":["r1"],"schema":"1.0",'
    '"source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},'
    '"registry_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    '"route_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_id":"owned"},'
    '"inputs":[],"mode":"observe","operation":"health.gather",'
    '"operation_id":"e9c85d98-b991-4d8c-a92b-a7c3e3437816",'
    '"output_intent":{"git":false,"kinds":[],"overwrite":"reject","retention":false,"root_ref":null},'
    '"plan_digest":null,"schema_version":"1.0","scope":{"exclusions":[],"limit":100,"target_ids":["r1"]}}'
)


def test_operation_request_literal_constructor_and_decoder():
    """Pin constructor output and independent inbound shape to one literal contract."""
    identity = PolicyIdentity(
        "6d367fe673756dabaa6085bc6b5202debaaabe6f", "a" * 64, "a" * 64, "a" * 64,
        ("r1",), "1",
    )
    request = c.OperationRequest(
        OPERATION, "health.gather", c.Mode.OBSERVE, c.Scope(("r1",)),
        c.Context("local", "a" * 64, "owned", "a" * 64, identity, "a" * 64, "a" * 64),
    )
    assert c.canonical_bytes(request).decode() == REQUEST_GOLDEN
    decoded = c.OperationRequest.from_json(REQUEST_GOLDEN.encode())
    assert decoded == request
    assert decoded.scope.target_ids == ("r1",)
    assert decoded.mode is c.Mode.OBSERVE


def test_operation_response_literal_constructor_and_decoder():
    """Pin all response keys, modes, exact disposition and omitted authority."""
    outcome = c.OperationOutcome(
        OPERATION, c.Mode.OBSERVE, c.Mode.OBSERVE, c.ReadinessProjection(),
        (), (), c.OutcomeStatus.SUCCEEDED, False, (), (), (), c.CleanupOutcome(),
        c.public_object({}),
    )
    golden = (
        '{"artifacts":[],"changed":false,"cleanup":{"errors":[],"remaining_refs":[],'
        '"status":"not-requested"},"errors":[],"executed_mode":"observe","findings":[],'
        '"operation_id":"e9c85d98-b991-4d8c-a92b-a7c3e3437816","provenance":{},'
        '"readiness":{"companion":"blocked","enhanced":"not-requested","errors":[],"native":"blocked"},'
        '"requested_mode":"observe","schema_version":"1.0","status":"succeeded","steps":[],"targets":[]}'
    )
    assert c.canonical_bytes(outcome).decode() == golden
    assert c.OperationOutcome.from_json(golden.encode()) == outcome
    assert outcome.exit_code == 0


def test_lifecycle_handler_receipt_literal_response():
    """Pin actual A02 factual receipt, including binding, pointer and no private grant."""
    identity = PolicyIdentity(
        "6d367fe673756dabaa6085bc6b5202debaaabe6f", "a" * 64, "a" * 64, "a" * 64,
        ("r1",), "1",
    )
    plan = lc.RestoreBinding(
        "1.0", OPERATION, OPERATION, "a" * 64, "a" * 64,
        lc.OwnedRootBinding("owned", "a" * 64),
        lc.GenerationBinding("generation", 0, "a" * 64, "a" * 64),
        lc.AbsentPointer("absent", 0), identity, "a" * 64, "a" * 64,
        (), (), lc.FrozenObject(), "restore",
    )
    binding = lc.LifecycleEffectBinding(plan, OPERATION, 0, "one")
    receipt = LifecycleHandlerReceipt(
        binding, "restore-active-pointer", "a" * 64, True, ("generation", 1),
    )
    golden = (
        '{"binding":{"event_id":"e9c85d98-b991-4d8c-a92b-a7c3e3437816",'
        '"expected_revision":0,"lifecycle":{"content":{},'
        '"context_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        '"effects":[],"expected_pointer":{"kind":"absent","revision":0},'
        '"generation":{"content_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        '"generation_id":"generation","manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        '"ordinal":0,"selected":[]},"kind":"restore",'
        '"lifecycle_id":"e9c85d98-b991-4d8c-a92b-a7c3e3437816",'
        '"plan_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        '"plan_id":"e9c85d98-b991-4d8c-a92b-a7c3e3437816",'
        '"policy":{"bundle_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        '"canonical_revision":"6d367fe673756dabaa6085bc6b5202debaaabe6f",'
        '"contracts_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        '"numeric_profile":"exact-int53-finite-order-v1","profile":"netops-reference-v1",'
        '"reducer_version":"1","rule_manifest":["r1"],"schema":"1.0",'
        '"source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},'
        '"qualification_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        '"registry_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        '"required_consequential":[],"root":{"manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        '"resource_id":"owned"},"schema":"1.0"},"occurrence_id":"one"},'
        '"changed":true,"kind":"restore-active-pointer","pointer":["generation",1],'
        '"result_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    )
    assert c.canonical_bytes(receipt).decode() == golden


@pytest.mark.parametrize(("value", "golden"), [
    (c.Scope(("r1", "r2")), '{"exclusions":[],"limit":100,"target_ids":["r1","r2"]}'),
    (c.InputRef("inventory", "owned", "a" * 64),
     '{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kind":"inventory","ref":"owned"}'),
    (c.OutputIntent(("json",), "owned"),
     '{"git":false,"kinds":["json"],"overwrite":"reject","retention":false,"root_ref":"owned"}'),
    (c.CancelReceipt(True, "cancelled", 12.0),
     '{"accepted":true,"reason":"cancelled","received_at":12.0}'),
    (c.ReadinessProjection(),
     '{"companion":"blocked","enhanced":"not-requested","errors":[],"native":"blocked"}'),
    (c.PlannedEffect("one", 0, "gather", "r1", "gather"),
     '{"destination_ref":null,"kind":"gather","occurrence_id":"one","ordinal":0,"step_id":"gather","target_id":"r1"}'),
    (c.CleanupOutcome(), '{"errors":[],"remaining_refs":[],"status":"not-requested"}'),
    (c.StepOutcome("gather", c.OutcomeStatus.SUCCEEDED, True),
     '{"attempted":true,"changed":false,"errors":[],"findings":[],"native_payload":{},"remote_state":"unchanged","selected":true,"status":"succeeded","step_id":"gather","unapplied_effects":[]}'),
    (c.TargetOutcome("r1", c.OutcomeStatus.SUCCEEDED, True),
     '{"attempted":true,"changed":false,"errors":[],"findings":[],"native_payload":{},"remote_state":"unchanged","selected":true,"status":"succeeded","target_id":"r1","unapplied_effects":[]}'),
    (EffectResult(c.StepOutcome("gather", c.OutcomeStatus.SUCCEEDED, True)),
     '{"artifacts":[],"cleanup":{"errors":[],"remaining_refs":[],"status":"not-requested"},"step":{"attempted":true,"changed":false,"errors":[],"findings":[],"native_payload":{},"remote_state":"unchanged","selected":true,"status":"succeeded","step_id":"gather","unapplied_effects":[]}}'),
    (LifecycleRunResult((), (), True, False),
     '{"completed":true,"pending":[],"receipts":[],"uncertain":false}'),
    (AnsibleSettings(), '{"enabled":false,"enhanced":false,"mode":"audit"}'),
], ids=[
    "Scope", "InputRef", "OutputIntent", "CancelReceipt", "ReadinessProjection",
    "PlannedEffect", "CleanupOutcome", "StepOutcome", "TargetOutcome", "EffectResult",
    "LifecycleRunResult", "AnsibleSettings",
])
def test_literal_public_wire(value, golden):
    """Expected bytes are literals, never calculated by the serializer under test."""
    assert c.canonical_bytes(value).decode("utf-8") == golden


def test_cancel_public_method_request_response_literal(composed):
    """Pin actual method request and returned response, not a DTO-only roundtrip."""
    service, host, _, _, _ = composed
    assert c.canonical_bytes(OPERATION) == b'"e9c85d98-b991-4d8c-a92b-a7c3e3437816"'
    assert c.canonical_bytes(service.cancel(OPERATION)) == (
        b'{"accepted":true,"reason":"cancelled","received_at":12.0}'
    )
    assert host.authorization.is_revoked(OPERATION)


def test_original_a02_criterion1_fixed_entry_never_accepts_nominal_permit(composed):
    """Original criterion 1: a fixed entry must stop before any native call."""
    service, host, request, _, effects = composed
    host.review(service, request)
    plan, _ = host._load(service, request)
    # Supply the ordinary backend argument so ablation measures guard removal,
    # not a missing test-fixture dictionary entry.
    host._cancellations[request.operation_id] = object()
    with pytest.raises(RuntimeError):
        host._gather(object(), None, plan, plan.effects[0])
    assert effects.calls == []


def test_original_a02_criterion2_cancel_keeps_revocation(composed):
    """Original criterion 2's cancellation branch is independent from receipt success."""
    service, host, request, _, _ = composed
    receipt = service.cancel(request.operation_id)
    assert receipt.accepted is True
    assert host.authorization.is_revoked(request.operation_id) is True


def test_original_a02_criterion3_restored_counter_overflow_is_rejected(composed):
    """Original criterion 3: MAX cannot allocate a host CAS; malformed hydrate rejects."""
    from netops.ansible.policy.authorization import AuthorizationError

    binding = c.PlanBinding(OPERATION, *("a" * 64 for _ in range(7)), "owned", 0, ())
    maximum = c.EffectBinding(binding, OPERATION, 9007199254740991, "one", "r1", "gather", ())
    assert maximum.expected_revision == 9007199254740991
    with pytest.raises(c.ContractError):
        replace(maximum, expected_revision=9007199254740992)
    _, host, request, _, effects = composed
    calls = []

    class StateSpy:
        def compare_revision(self, operation_id, expected_revision, next_revision):
            calls.append((operation_id, expected_revision, next_revision))
            return True

    host.authorization._state = StateSpy()
    with pytest.raises(AuthorizationError):
        host.authorization._advance(request.operation_id, 9007199254740991)
    assert calls == []
    assert effects.calls == []
    assert host.authorization.is_revoked(request.operation_id)
    # Revocation remains usable without allocating another revision.
    host.authorization.revoke(request.operation_id)


def test_original_a02_criterion4_default_is_disabled_audit_no_output():
    """Original criterion 4: ambient construction is not enabled/apply/output authority."""
    settings = AnsibleSettings()
    assert settings.enabled is False
    assert settings.mode == "audit"
    assert c.OutputIntent() == c.OutputIntent((), None, "reject", False, False)


@pytest.fixture(autouse=True)
def isolated_production_hunk_ablation(monkeypatch):
    """Optional exact production-source hunk deletion, compiled only in this process."""
    import inspect
    import textwrap

    from netops.ansible import execution, settings, workflows
    from netops.ansible.policy import authorization

    selected = os.environ.get("A02_CLOSURE_ABLATION")
    choices = {
        "criterion1": (
            execution.ExecutionHost, "_gather",
            '    self._entry(permit, binding, plan, effect, "gather")\n', "",
        ),
        "criterion2": (
            workflows.WorkflowService, "cancel",
            "self._authorization.revoke(operation_id)", "None",
        ),
        "criterion3": (
            authorization.AuthorizationBroker, "_advance",
            "    if revision == MAX_SAFE_INT:\n        self._revoke(operation_id)\n        raise AuthorizationError(numeric=True)\n", "",
        ),
    }
    if selected == "criterion4":
        original = settings.AnsibleSettings.__init__
        defaults = original.__defaults__
        assert defaults == (False, "audit", False)
        monkeypatch.setattr(original, "__defaults__", (True, "audit", False))
    elif selected:
        owner, name, old, new = choices[selected]
        original = getattr(owner, name)
        source = textwrap.dedent(inspect.getsource(original))
        assert source.count(old) == 1, (name, old)
        namespace = {}
        exec(compile(source.replace(old, new), "<isolated-A02-hunk-ablation>", "exec"),
             original.__globals__, namespace)
        monkeypatch.setattr(owner, name, namespace[name])
