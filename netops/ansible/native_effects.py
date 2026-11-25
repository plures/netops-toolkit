"""Private fixed backup publication adapter; never an admission authority."""

from __future__ import annotations

from dataclasses import replace

from . import contracts as c
from .artifacts import ArtifactStore


def _publish_backup(
    store: c.ArtifactPort, plan: c.OperationPlan, effect: c.PlannedEffect,
    binding: c.EffectBinding, content: bytes,
) -> tuple[c.ArtifactDescriptor, c.ArtifactBinding]:
    """Keep exact sensitive bytes out of ordinary payloads and policy facts.

    The host must enter the real one-use backup permit first. Retention and
    Git remain separate admitted occurrences: publication only writes content
    and its protected receipt; it never prunes or creates a Git snapshot.
    """
    if (
        type(store) is not ArtifactStore or type(content) is not bytes
        or plan.requested_mode != c.Mode.OUTPUT or plan.operation != "config.backup"
        or effect.kind != "backup" or plan.effects[effect.ordinal] != effect
        or effect.occurrence_id != binding.occurrence_id
        or effect.target_id != binding.target_id
        or binding.plan.plan_digest != plan.plan_digest
        or plan.output_intent.retention is not True
        or plan.output_intent.kinds != ("text",)
    ):
        raise c.ContractError()
    artifact_binding = c.ArtifactBinding(binding, "sensitive")
    descriptor = store.publish(replace(plan.output_intent, git=False), content, artifact_binding)
    return descriptor, artifact_binding
