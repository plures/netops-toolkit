"""Pure minimized coverage projections for versioned companion outcomes.

Rendering and publication are deliberately absent. Native payloads, exception
details and protected configuration are not report facts.
"""

from __future__ import annotations

from dataclasses import replace

from netops.ansible.contracts import (
    CleanupOutcome,
    ContractError,
    ErrorCategory,
    Finding,
    OperationOutcome,
    OutcomeStatus,
    ReasonCode,
    SafeError,
    Stage,
    canonical_bytes,
    public_object,
    wire,
)
from netops.ansible.policy.contracts import FrozenObject, Json

__all__ = ["project_outcome"]


def _errors(errors: tuple[SafeError, ...]) -> tuple[FrozenObject, ...]:
    return tuple(public_object({
        "category": error.category.value, "reason": error.reason.value,
        "stage": error.stage.value, "retryable": error.retryable,
        "target_id": error.target_id, "step_id": error.step_id,
        "next_action": "Inspect the source outcome and replan the selected blocked or failed work.",
    }) for error in errors)


def project_outcome(
    value: Json, selected_target_ids: tuple[str, ...] = (),
) -> FrozenObject:
    """Preserve selected, unattempted, missing and uncertain work without rendering."""
    source = OperationOutcome.from_json(canonical_bytes(value))
    selected = tuple(target for target in source.targets if target.selected)
    if len({target.target_id for target in selected}) != len(selected):
        raise ContractError("input-binding-invalid")
    counts = {status.value: 0 for status in OutcomeStatus}
    coverage: list[FrozenObject] = []
    for target in selected:
        counts[target.status.value] += 1
        coverage.append(public_object({
            "target_id": target.target_id, "status": target.status.value,
            "attempted": target.attempted, "changed": target.changed,
            "remote_state": target.remote_state, "unapplied_effects": target.unapplied_effects,
            "findings": tuple(wire(finding) for finding in target.findings),
            "errors": _errors(target.errors),
        }))
    missing = tuple(target for target in selected_target_ids
                    if target not in {item.target_id for item in selected})
    for missing_target in missing:
        counts["blocked"] += 1
        coverage.append(public_object({
            "target_id": missing_target, "status": "blocked", "attempted": False,
            "changed": False, "remote_state": "unchanged", "missing": True,
        }))
    source_status = source.status
    if missing and source_status == OutcomeStatus.SUCCEEDED:
        source_status = OutcomeStatus.PARTIAL if selected else OutcomeStatus.BLOCKED
    if not selected and not any(step.selected for step in source.steps) and source_status == OutcomeStatus.SUCCEEDED:
        source_status = OutcomeStatus.BLOCKED
    source_exit = replace(source, status=source_status).exit_code
    return public_object({
        "schema_version": "1.0", "source_operation_id": source.operation_id,
        "source_requested_mode": source.requested_mode.value,
        "source_executed_mode": None if source.executed_mode is None else source.executed_mode.value,
        "source_status": source_status.value, "source_exit_code": source_exit,
        "readiness": {
            "native": source.readiness.native, "companion": source.readiness.companion,
            "enhanced": source.readiness.enhanced, "errors": _errors(source.readiness.errors),
        },
        "counts": counts, "selected_count": len(coverage), "missing_count": len(missing),
        "coverage_complete": not missing, "coverage": tuple(coverage), "targets": tuple(coverage),
        "steps": tuple(public_object({
            "step_id": step.step_id, "status": step.status.value, "selected": step.selected,
            "attempted": step.attempted, "changed": step.changed,
            "remote_state": step.remote_state, "unapplied_effects": step.unapplied_effects,
            "errors": _errors(step.errors),
        }) for step in source.steps),
        "findings": tuple(wire(finding) for finding in source.findings),
        "errors": _errors(source.errors),
        "cleanup": {"status": source.cleanup.status,
                    "remaining_count": len(source.cleanup.remaining_refs),
                    "remaining_refs": source.cleanup.remaining_refs,
                    "errors": _errors(source.cleanup.errors)},
        "changed": source.changed,
        "remote_uncertain": any(item.remote_state == "uncertain" for item in selected + source.steps),
        "overall_alert": source_status != OutcomeStatus.SUCCEEDED,
        "execution_performed": False,
    })


def _preserve_source(outcome: OperationOutcome) -> OperationOutcome:
    """Successful rendering never grants success to failed selected source work.

    This is pure postprocessing of facts actually returned by the native
    renderer, not a source read, a second execution, or new admission.
    """
    statuses: list[OutcomeStatus] = []
    errors: list[SafeError] = []
    cleanup_errors: list[SafeError] = []
    remaining: list[str] = []
    source_cleanup_failed = False
    source_findings: list[Finding] = []
    for step in outcome.steps:
        sections = step.native_payload.get("sections", ())
        if not isinstance(sections, tuple):
            continue
        for section in sections:
            if not isinstance(section, FrozenObject):
                continue
            data = section.get("data")
            if not isinstance(data, FrozenObject) or "source_status" not in data:
                continue
            status = data["source_status"]
            if not isinstance(status, str):
                raise ContractError()
            statuses.append(OutcomeStatus(status))
            from netops.ansible.contracts import _finding_from_wire

            raw_findings = data.get("findings", ())
            if not isinstance(raw_findings, tuple):
                raise ContractError()
            source_findings.extend(_finding_from_wire(item) for item in raw_findings)
            errors.extend(_read_errors(data.get("errors", ())))
            cleanup_data = data.get("cleanup")
            if isinstance(cleanup_data, FrozenObject):
                source_cleanup_failed |= cleanup_data["status"] == "failed"
                refs = cleanup_data.get("remaining_refs", ())
                if not isinstance(refs, tuple) or any(not isinstance(ref, str) for ref in refs):
                    raise ContractError()
                remaining.extend(ref for ref in refs if isinstance(ref, str))
                cleanup_errors.extend(_read_errors(cleanup_data.get("errors", ())))
    final_status = outcome.status
    if final_status == OutcomeStatus.SUCCEEDED:
        for status in (
            OutcomeStatus.PARTIAL, OutcomeStatus.FAILED, OutcomeStatus.CANCELLED,
            OutcomeStatus.UNSUPPORTED, OutcomeStatus.BLOCKED,
        ):
            if status in statuses:
                final_status = status
                break
    cleanup = outcome.cleanup
    if source_cleanup_failed or remaining or cleanup_errors:
        cleanup = CleanupOutcome(
            "failed" if source_cleanup_failed or cleanup.status == "failed" or cleanup_errors else cleanup.status,
            tuple(dict.fromkeys(cleanup.remaining_refs + tuple(remaining))),
            tuple(dict.fromkeys(cleanup.errors + tuple(cleanup_errors))),
        )
    return replace(
        outcome, status=final_status, cleanup=cleanup,
        findings=outcome.findings + tuple(source_findings),
        errors=tuple(dict.fromkeys(outcome.errors + tuple(errors))),
    )


def _error(value: Json) -> SafeError:
    if not isinstance(value, FrozenObject):
        raise ContractError()
    from netops.ansible.contracts import text

    target, step = value.get("target_id"), value.get("step_id")
    retryable = value["retryable"]
    if type(retryable) is not bool:
        raise ContractError()
    assert isinstance(retryable, bool)
    return SafeError(
        ErrorCategory(text(value["category"])), ReasonCode(text(value["reason"])),
        Stage(text(value["stage"])), text(target) if target is not None else None,
        text(step) if step is not None else None, retryable=retryable,
        next_action=text(value["next_action"]),
    )


def _read_errors(value: Json) -> tuple[SafeError, ...]:
    if not isinstance(value, tuple):
        raise ContractError()
    return tuple(_error(item) for item in value)
