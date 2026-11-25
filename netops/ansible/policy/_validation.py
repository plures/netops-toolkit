"""Shared closed-schema validation, independent of rule applicability."""

from __future__ import annotations

import math
from collections.abc import Mapping

from .contracts import (
    MAX_NODES,
    MAX_SAFE_INT,
    DecisionEvent,
    EventKind,
    FrozenObject,
    Json,
    Phase,
    PolicyInputError,
)

LIFECYCLE_EFFECTS = (
    "dependency-probe", "dependency-download", "dependency-stage", "dependency-verify",
    "dependency-activate", "dependency-uninstall", "restore-active-pointer",
)
EFFECTS = LIFECYCLE_EFFECTS + (
    "scan", "save", "export", "refresh", "resolve-for-run", "gather", "collect",
    "backup", "apply", "rollback", "render", "retention", "git",
)
STATUSES = ("success", "partial", "failed", "cancelled", "unsupported", "blocked")
MODES = ("preview", "check", "observe", "output", "apply", "rollback")
OPERATIONS = (
    "discover", "inventory-preview", "save", "validate", "export", "refresh", "preflight",
    "resolve-for-run", "collect", "backup", "plan", "apply", "rollback", "gather",
    "evaluate", "compare", "remediation-preview", "generate", "aggregate", "render",
    "install", "uninstall", "restore",
)
BOOL_GROUPS = (
    ("binding", ("input_valid", "plan_current", "policy_current")),
    ("scope", ("exclusions_valid",)),
    ("config", ("enabled",)),
    ("control", ("cancelled",)),
    ("readiness", ("selected_complete",)),
    ("controller", ("qualified",)),
    ("route", ("qualified",)),
    ("credentials", ("channel_qualified",)),
    ("ownership", ("valid",)),
    ("storage", ("sensitive_ready",)),
    ("output", ("retention_requested", "git_requested")),
    ("consent", ("present", "binding_matches", "effects_match", "recovery_matches")),
    ("consequential", ("required", "granted")),
    ("result", ("policy_failed", "cleanup_failed", "remote_uncertain")),
    ("inventory", ("source_valid", "cache_binding_valid", "hostvars_safe")),
    ("discovery", ("scope_valid",)),
    ("change", ("prestate_bound", "vendor_recovery_qualified", "poststate_verified")),
    ("health", ("reading_present", "reading_finite", "check_supported")),
    ("compare", ("inputs_bound", "vendor_supported")),
    ("report", ("coverage_complete", "pdf_ready", "output_safe")),
    ("candidate", ("verified", "pointer_matches", "retained_owned")),
)
COUNTER_PATHS = (
    "state.revision", "event.expected_revision", "scope.selected_count",
    "control.remaining_ms", "consent.remaining_ms", "result.selected", "result.completed",
    "result.unsuccessful", "result.failed", "result.cancelled", "result.unsupported",
    "result.blocked",
)
STRING_DOMAINS = (
    ("event.kind", tuple(e.value for e in EventKind)),
    ("event.payload.lifecycle_kind", ("install", "uninstall", "restore")),
    ("state.phase", tuple(p.value for p in Phase)),
    ("request.area", ("scan", "inventory", "vault", "config", "health", "compare", "report", "setup")),
    ("request.operation", OPERATIONS),
    ("request.mode", MODES),
    ("config.mode", ("audit", "enforce")),
    ("readiness.native", ("ready", "blocked", "unsupported", "not-requested")),
    ("readiness.companion", ("ready", "blocked", "unsupported", "not-requested")),
    ("readiness.enhanced", ("ready", "blocked", "unsupported", "not-requested")),
    ("lifecycle.next_effect_kind", LIFECYCLE_EFFECTS + ("none",)),
    ("operational.next_effect_kind", ("collect", "backup", "retention", "git", "none")),
)


def fail() -> None:
    """Raise a safe input failure without leaking a supplied value."""
    raise PolicyInputError("policy-input-invalid")


def text(value: object, *, safe: bool = False) -> str:
    """Require bounded exact text, optionally a nonempty safe reference."""
    if type(value) is not str:
        fail()
    if not isinstance(value, str):
        fail()
    assert isinstance(value, str)
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        fail()
        raise AssertionError
    if len(encoded) > 4096:
        fail()
    if safe and (value == "" or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        fail()
    return value


def counter(value: object) -> int:
    """Require a nonnegative exact int53, never bool or a coerced float."""
    if type(value) is not int or not isinstance(value, int) or not 0 <= value <= MAX_SAFE_INT:
        fail()
    assert isinstance(value, int)
    return value


def digest(value: object) -> str:
    """Require an exact SHA256 string without numeric conversion."""
    result = text(value)
    if len(result) != 64 or any(c not in "0123456789abcdefABCDEF" for c in result):
        fail()
    return result


def uuid(value: object) -> str:
    """Require the existing canonical UUID wire shape."""
    result = text(value)
    if len(result) != 36 or any(
        (c != "-" if i in (8, 13, 18, 23) else c not in "0123456789abcdefABCDEF")
        for i, c in enumerate(result)
    ):
        fail()
    return result


def keys(value: object, required: tuple[str, ...]) -> FrozenObject:
    """Require a closed immutable object, including all mandatory fields."""
    if type(value) is not FrozenObject or set(value) != set(required):
        fail()
    assert isinstance(value, FrozenObject)
    if len(value) != len(required):
        fail()
    return value


def path_type(path: tuple[str, ...]) -> str:
    """Resolve only the frozen profile's exact typed paths."""
    joined = ".".join(path)
    if joined in COUNTER_PATHS:
        return "int"
    if joined in ("health.reading", "health.threshold"):
        return "float"
    if any(joined == name for name, _ in STRING_DOMAINS):
        return "string"
    if any(path == (root, leaf) for root, leaves in BOOL_GROUPS for leaf in leaves):
        return "bool"
    fail()
    raise AssertionError


def scalar(value: object, kind: str) -> None:
    """Validate all literal types before evaluating any expression branch."""
    if kind == "bool" and type(value) is bool:
        return
    if kind == "int" and type(value) is int and isinstance(value, int):
        if -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
            return
    if kind == "float" and type(value) is float and isinstance(value, float):
        if math.isfinite(value):
            return
    if kind == "string":
        text(value)
        return
    fail()


def leaf(path: tuple[str, ...], value: object) -> None:
    """Validate type and domain even for an unused supplied field."""
    kind = path_type(path)
    scalar(value, kind)
    if kind == "int":
        counter(value)
    for name, domain in STRING_DOMAINS:
        if ".".join(path) == name and value not in domain:
            fail()


def tree(value: FrozenObject, prefix: tuple[str, ...] = ()) -> None:
    """Reject unknown, empty, malformed and irrelevant fact branches."""
    if len(value) == 0:
        fail()
    for name, item in value.items():
        path = prefix + (name,)
        if isinstance(item, FrozenObject):
            tree(item, path)
        else:
            leaf(path, item)


def lookup(values: Mapping[str, Json], path: tuple[str, ...]) -> Json:
    """Resolve mapping keys only, never Python attributes or methods."""
    value: Json = values.get(path[0])
    if path[0] not in values:
        fail()
    for part in path[1:]:
        if not isinstance(value, FrozenObject) or part not in value:
            fail()
        assert isinstance(value, FrozenObject)
        value = value[part]
    return value


PAYLOADS = (
    ("OperationRequested", ("request_digest", "loaded_input_digest", "plan_digest", "mode")),
    ("DependencyObserved", ("dependency_id", "context_digest", "probe_receipt", "probe_digest", "readiness")),
    ("InstallConsented", ("lifecycle_kind", "plan_id", "lifecycle_binding_digest", "private_consent_reference")),
    ("Observed", ("invocation_id", "target_id", "step_id", "observation_ref", "observation_digest", "disposition")),
    ("ApplyConsented", ("plan_digest", "approved_effect_ids", "approved_recovery_ids", "private_consent_reference")),
    ("StepCompleted", ("invocation_id", "effect_id", "target_id", "step_id", "safe_result_digest", "primary", "cleanup", "remote_uncertain")),
    ("CandidateVerified", ("candidate_digest", "registry_digest", "assets_digest", "policy_digest", "qualification_digest", "functional_evidence_ref")),
    ("Activated", ("expected_pointer_digest", "current_pointer_digest", "new_pointer_digest", "cas_receipt")),
    ("Cancelled", ("accepted_host_receipt", "revocation_revision", "safe_reason")),
)


def identifiers(value: object) -> None:
    """Require safe, unique, ordered identifiers without truncation."""
    if type(value) is not tuple or not isinstance(value, tuple) or len(value) > MAX_NODES:
        fail()
    assert isinstance(value, tuple)
    for item in value:
        text(item, safe=True)
    if len(set(value)) != len(value):
        fail()


def event_value(event: DecisionEvent) -> FrozenObject:
    """Validate every full event metadata field and its closed payload."""
    if type(event) is not DecisionEvent or type(event.kind) is not EventKind:
        fail()
    if text(event.schema) != "1.0":
        fail()
    uuid(event.event_id)
    counter(event.expected_revision)
    if (event.operation_id is None) == (event.install_id is None):
        fail()
    uuid(event.operation_id if event.operation_id is not None else event.install_id)
    kind = event.kind.value
    if kind in ("InstallConsented", "CandidateVerified", "Activated") and event.install_id is None:
        fail()
    if kind in ("OperationRequested", "Observed", "ApplyConsented") and event.operation_id is None:
        fail()
    for bound_digest in (event.plan_digest, event.context_digest, event.policy_digest):
        digest(bound_digest)
    text(event.target_id, safe=True)
    text(event.step_id, safe=True)
    required = next(fields for name, fields in PAYLOADS if name == kind)
    payload = keys(event.payload, required)
    for name, value in payload.items():
        if name.endswith("_digest"):
            digest(value)
        elif name == "plan_id":
            uuid(value)
        elif name == "revocation_revision":
            counter(value)
        elif name == "remote_uncertain":
            scalar(value, "bool")
        elif name in ("approved_effect_ids", "approved_recovery_ids"):
            identifiers(value)
        else:
            text(value, safe=True)
    domains = (
        ("mode", MODES), ("readiness", ("ready", "blocked", "unsupported")),
        ("lifecycle_kind", ("install", "uninstall", "restore")),
        ("disposition", STATUSES), ("primary", STATUSES), ("cleanup", STATUSES),
    )
    for name, domain in domains:
        if name in payload and payload[name] not in domain:
            fail()
    for name, expected in (
        ("plan_digest", event.plan_digest), ("context_digest", event.context_digest),
        ("policy_digest", event.policy_digest), ("target_id", event.target_id),
        ("step_id", event.step_id),
    ):
        if name in payload and payload[name] != expected:
            fail()
    if kind == "InstallConsented" and payload["lifecycle_kind"] != "install":
        if payload["plan_id"] != event.install_id:
            fail()
    if kind == "Activated" and payload["expected_pointer_digest"] != payload["current_pointer_digest"]:
        fail()
    entries: tuple[tuple[str, Json], ...] = (
        ("kind", kind), ("expected_revision", event.expected_revision),
    )
    if kind == "InstallConsented":
        entries += (("payload", FrozenObject((("lifecycle_kind", payload["lifecycle_kind"]),))),)
    return FrozenObject(entries)


def result_counters(value: object) -> None:
    """Validate factual counters, allowing selected work still pending."""
    fields = (
        "selected", "completed", "unsuccessful", "failed", "cancelled", "unsupported",
        "blocked", "policy_failed", "cleanup_failed", "remote_uncertain",
    )
    result = keys(value, fields)
    for name, item in result.items():
        leaf(("result", name), item)
    selected = counter(result["selected"])
    completed = counter(result["completed"])
    unsuccessful = counter(result["unsuccessful"])
    counts = tuple(counter(result[name]) for name in fields[:7])
    if any(n > selected for n in counts) or completed + unsuccessful > selected:
        fail()
    if unsuccessful == 0 and any(counter(result[name]) != 0 for name in fields[3:7]):
        fail()


def final_counters(value: object) -> None:
    """Require complete final coverage without inventing a category partition."""
    result_counters(value)
    assert isinstance(value, FrozenObject)
    if counter(value["completed"]) + counter(value["unsuccessful"]) != counter(value["selected"]):
        fail()
