"""Literal pins for consumed A02 error, finding and publication result shapes."""

import inspect

import pytest

from netops.ansible import contracts as c
from netops.ansible.lifecycle_execution import LifecycleExecutor
from netops.ansible.workflows import WorkflowService


@pytest.mark.parametrize(("value", "golden"), [
    (
        c.SafeError(
            c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
            "r1", "gather", False, "Cleanup remains incomplete.", "Inspect owned state.",
        ),
        '{"category":"cleanup","detail":"Cleanup remains incomplete.",'
        '"next_action":"Inspect owned state.","reason":"cleanup-failed","retryable":false,'
        '"stage":"finalize","step_id":"gather","target_id":"r1"}',
    ),
    (
        c.Finding("cpu", "health", "error", "alert", 90, 80, None, "cisco", "native"),
        '{"category":"health","check":"cpu","expected":null,"parser":"native",'
        '"raw_source_ref":null,"reading":90,"result":"alert","severity":"error",'
        '"threshold":80,"vendor":"cisco"}',
    ),
    (
        c.ArtifactDescriptor(
            "owned-result", "a" * 64, 5, "application/json", "public",
            "verified-owned", "not-requested", "owned", "b" * 64,
        ),
        '{"classification":"public",'
        '"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        '"input_binding":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
        '"media_type":"application/json","owning_resource":"owned",'
        '"permissions_proof":"verified-owned","ref":"owned-result",'
        '"retention":"not-requested","size":5}',
    ),
], ids=["SafeError", "Finding", "ArtifactDescriptor"])
def test_consumed_nested_outcome_shape_is_literal(value, golden):
    """Pin exact consumed bytes; no serializer-generated expected value."""
    assert c.canonical_bytes(value).decode("utf-8") == golden


@pytest.mark.parametrize(("method", "parameters"), [
    (WorkflowService.execute, ("self", "request", "authorization")),
    (WorkflowService.cancel, ("self", "operation_id")),
    (LifecycleExecutor.execute, ("self", "plan", "authorization")),
    (LifecycleExecutor.cancel, ("self", "plan")),
    (LifecycleExecutor.enter, ("self", "permit", "binding")),
    (LifecycleExecutor.complete, ("self", "permit")),
    (LifecycleExecutor.reconcile, ("self", "permit")),
])
def test_frozen_python_entry_signature_without_invented_permission_wire(method, parameters):
    """Live opaque authority is Python-only; pin its real call boundary instead."""
    signature = inspect.signature(method)
    assert tuple(signature.parameters) == parameters
    assert all(p.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
               for p in signature.parameters.values())
    if method is WorkflowService.execute:
        assert signature.parameters["authorization"].default is None
    else:
        assert all(p.default is inspect.Parameter.empty for p in signature.parameters.values())
