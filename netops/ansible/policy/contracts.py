"""Immutable, credential-free values for the local reference policy boundary."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Literal, Protocol, Union

if TYPE_CHECKING:
    from ..contracts import InstallScope

MAX_SAFE_INT = 9007199254740991
MAX_BYTES = 1048576
MAX_NODES = 32768
MAX_DEPTH = 32
MAX_VISITS = 200000
PIN = "6d367fe673756dabaa6085bc6b5202debaaabe6f"
POLICY_LOAD_INVALID = "policy-load-invalid"
POLICY_INPUT_INVALID = "policy-input-invalid"
POLICY_REJECTED = "policy-rejected"
POLICY_EVALUATION_FAILED = "policy-evaluation-failed"
POLICY_EVENT_CONFLICT = "policy-event-conflict"

Scalar = Union[bool, int, float, str]
Json = Union[None, Scalar, tuple["Json", ...], "FrozenObject"]


class PolicyLoadError(ValueError):
    """Reject an unsupported or integrity-invalid program."""

    reason = POLICY_LOAD_INVALID


class PolicyInputError(ValueError):
    """Reject malformed typed input without producing a decision."""

    reason = POLICY_INPUT_INVALID


class PolicyEvaluationError(ValueError):
    """Reject ambiguous or inconsistent evaluation without partial permission."""

    reason = POLICY_EVALUATION_FAILED


class PolicyBudgetError(PolicyEvaluationError):
    """Reject evaluation that exceeds the fixed visit budget."""


LifecycleKind = Literal["install", "uninstall", "restore"]
LifecycleEffectKind = Literal[
    "dependency-probe", "dependency-download", "dependency-stage", "dependency-verify",
    "dependency-activate", "dependency-uninstall", "restore-active-pointer",
]
ConsequentialCategory = Literal[
    "elevation", "wsl-change", "vm-change", "reboot", "runtime-install", "security-change",
]


@dataclass(frozen=True)
class OwnedRootBinding:
    """Exact owned resource and verified ownership manifest."""

    resource_id: str
    manifest_digest: str


@dataclass(frozen=True)
class GenerationBinding:
    """Exact generation identity, including ordered uninstall selections."""

    generation_id: str
    ordinal: int
    content_digest: str
    manifest_digest: str
    selected: tuple[GenerationBinding, ...] = ()


@dataclass(frozen=True)
class AbsentPointer:
    """Verified virgin state, never a missing or corrupt pointer fallback."""

    kind: Literal["absent"]
    revision: int


@dataclass(frozen=True)
class PresentPointer:
    """Persisted pointer identity at the reviewed revision."""

    kind: Literal["present"]
    active_generation_id: str
    pointer_digest: str
    revision: int


PointerExpectation = Union[AbsentPointer, PresentPointer]


@dataclass(frozen=True)
class LifecycleEffectOccurrence:
    """One exact ordered invocation, not merely an action name."""

    occurrence_id: str
    ordinal: int
    step_id: str
    resource_id: str
    kind: LifecycleEffectKind
    arguments_digest: str


@dataclass(frozen=True)
class ConsequentialRequirement:
    """Separately reviewed category and exact affected occurrences."""

    category: ConsequentialCategory
    occurrence_ids: tuple[str, ...]


@dataclass(frozen=True)
class _LifecycleProjection:
    schema: Literal["1.0"]
    plan_id: str
    lifecycle_id: str
    plan_digest: str
    context_digest: str
    root: OwnedRootBinding
    generation: GenerationBinding
    expected_pointer: PointerExpectation
    policy: PolicyIdentity
    registry_digest: str
    qualification_digest: str
    effects: tuple[LifecycleEffectOccurrence, ...]
    required_consequential: tuple[ConsequentialRequirement, ...]
    content: FrozenObject


@dataclass(frozen=True)
class InstallBinding(_LifecycleProjection):
    """Install projection with a required concrete discriminant."""

    kind: Literal["install"]
    scope: InstallScope


@dataclass(frozen=True)
class UninstallBinding(_LifecycleProjection):
    """Owned removal projection; no fabricated install UUID."""

    kind: Literal["uninstall"]


@dataclass(frozen=True)
class RestoreBinding(_LifecycleProjection):
    """Retained-generation restore projection."""

    kind: Literal["restore"]


@dataclass(frozen=True)
class InstallPlan(InstallBinding):
    """Concrete immutable install plan, distinct from its projection."""


@dataclass(frozen=True)
class UninstallPlan(UninstallBinding):
    """Concrete immutable uninstall plan."""


@dataclass(frozen=True)
class RestorePlan(RestoreBinding):
    """Concrete immutable restore plan."""


LifecyclePlan = Union[InstallPlan, UninstallPlan, RestorePlan]
LifecycleBinding = Union[InstallBinding, UninstallBinding, RestoreBinding]


@dataclass(frozen=True)
class LifecycleEffectBinding:
    """Checkpoint event and occurrence bound to the complete lifecycle."""

    lifecycle: LifecycleBinding
    event_id: str
    expected_revision: int
    occurrence_id: str


class _LifecyclePrivate:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<private>"


class InstallConsent(_LifecyclePrivate):
    """Nominal private lifecycle consent; construction grants nothing."""

    __slots__ = ()


class ConsequentialGrant(_LifecyclePrivate):
    """Nominal separately prompted consequential receipt."""

    __slots__ = ()


class LifecycleAuthorization(_LifecyclePrivate):
    """Nominal lifecycle-only plan grant."""

    __slots__ = ()


class LifecycleAdmissionSession(_LifecyclePrivate):
    """Nominal lifecycle-only admission session."""

    __slots__ = ()


class LifecycleEffectPermit(_LifecyclePrivate):
    """Nominal lifecycle-only invocation permit."""

    __slots__ = ()


@dataclass(frozen=True)
class FrozenObject(Mapping[str, Json]):
    """A recursively immutable JSON object with deterministic iteration."""

    entries: tuple[tuple[str, Json], ...] = ()

    def __post_init__(self) -> None:
        """Defensively normalize entries and reject duplicate or nonstring keys."""
        if type(self.entries) is not tuple or len(self.entries) > MAX_NODES:
            raise PolicyInputError(POLICY_INPUT_INVALID)
        seen: set[str] = set()
        normalized: list[tuple[str, Json]] = []
        for pair in self.entries:
            if type(pair) is not tuple or len(pair) != 2:
                raise PolicyInputError(POLICY_INPUT_INVALID)
            key, value = pair
            if type(key) is not str or key in seen:
                raise PolicyInputError(POLICY_INPUT_INVALID)
            seen.add(key)
            normalized.append((key, freeze(value)))
        object.__setattr__(self, "entries", tuple(normalized))

    def __getitem__(self, key: str) -> Json:
        """Return a value by its exact key."""
        for name, value in self.entries:
            if name == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        """Iterate exact keys in stored order."""
        return (name for name, _ in self.entries)

    def __len__(self) -> int:
        """Return the number of keys."""
        return len(self.entries)


def freeze(value: object, depth: int = 0) -> Json:
    """Detach caller-owned containers; reject non-JSON values and deep inputs."""
    # Projection wrappers are not expression nodes. Expression depth is checked
    # separately by the loader; leave room for bundle/rule/condition containers.
    if depth > MAX_DEPTH + 8:
        raise PolicyInputError(POLICY_INPUT_INVALID)
    if type(value) is FrozenObject:
        return value
    if value is None or type(value) in (bool, int, float, str):
        if isinstance(value, (bool, int, float, str)) or value is None:
            return value
    if isinstance(value, Mapping):
        if len(value) > MAX_NODES or any(type(k) is not str for k in value):
            raise PolicyInputError(POLICY_INPUT_INVALID)
        return FrozenObject(tuple((k, freeze(v, depth + 1)) for k, v in value.items()))
    if type(value) in (list, tuple):
        if not isinstance(value, (list, tuple)) or len(value) > MAX_NODES:
            raise PolicyInputError(POLICY_INPUT_INVALID)
        return tuple(freeze(v, depth + 1) for v in value)
    raise PolicyInputError(POLICY_INPUT_INVALID)


def object_value(value: object) -> FrozenObject:
    """Require and defensively freeze a JSON object."""
    result = freeze(value)
    if not isinstance(result, FrozenObject):
        raise PolicyInputError(POLICY_INPUT_INVALID)
    return result


class EventKind(str, Enum):
    """The nine existing schema-1.0 event kinds."""

    OPERATION_REQUESTED = "OperationRequested"
    DEPENDENCY_OBSERVED = "DependencyObserved"
    INSTALL_CONSENTED = "InstallConsented"
    OBSERVED = "Observed"
    APPLY_CONSENTED = "ApplyConsented"
    STEP_COMPLETED = "StepCompleted"
    CANDIDATE_VERIFIED = "CandidateVerified"
    ACTIVATED = "Activated"
    CANCELLED = "Cancelled"


class Phase(str, Enum):
    """Closed state phases; no effect is implied by a phase value."""

    PLANNED = "Planned"
    STAGING = "Staging"
    VERIFIED = "Verified"
    ACTIVE = "Active"
    OBSERVING = "Observing"
    ADMITTED = "Admitted"
    EXECUTING = "Executing"
    CANCELLING = "Cancelling"
    COMPLETED = "Completed"
    CANCELLED = "Cancelled"
    UNCERTAIN = "Uncertain"


class Disposition(str, Enum):
    """Selected target/step dispositions, distinct from aggregate status."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"
    CANCELLED = "cancelled"
    NOT_REQUESTED = "not-requested"


@dataclass(frozen=True)
class PolicyIdentity:
    """Exact packaged program identity, never an omitted-version wildcard."""

    canonical_revision: str
    source_sha256: str
    contracts_sha256: str
    bundle_sha256: str
    rule_manifest: tuple[str, ...]
    reducer_version: str
    profile: str = "netops-reference-v1"
    numeric_profile: str = "exact-int53-finite-order-v1"
    schema: str = "1.0"


@dataclass(frozen=True)
class EffectDescriptor:
    """A fixed-symbol action intent, not an executable or host permit."""

    name: str
    params: FrozenObject

    def __post_init__(self) -> None:
        """Detach constant parameters from caller-owned objects."""
        object.__setattr__(self, "params", object_value(self.params))


@dataclass(frozen=True)
class Expression:
    """Validated expression with statically resolved type."""

    kind: str
    value_type: str
    value: Scalar | None = None
    path: tuple[str, ...] = ()
    op: str = ""
    children: tuple[Expression, ...] = ()


@dataclass(frozen=True)
class Declaration:
    """Validated rule or invariant in source declaration order."""

    id: str
    source_id: str
    conditions: tuple[Expression, ...]
    actions: tuple[EffectDescriptor, ...] = ()
    required: Expression | None = None
    reason: str = POLICY_REJECTED
    order: int = 0
    required_paths: tuple[tuple[str, ...], ...] = ()


@dataclass(frozen=True)
class PolicyProgram:
    """Immutable validated program returned only after complete load validation."""

    identity: PolicyIdentity
    rules: tuple[Declaration, ...]
    constraints: tuple[Declaration, ...]
    examples: tuple[FrozenObject, ...]
    node_count: int
    content_digest: str
    # Loader-only proof operands: not a public constructor argument, wire field,
    # alternate digest, or authorization credential.
    _load_bytes: tuple[bytes, ...] = field(default=(), init=False, repr=False, compare=False)


@dataclass(frozen=True)
class DecisionEvent:
    """Full event metadata; private references are symbolic, never grants."""

    event_id: str
    kind: EventKind
    expected_revision: int
    plan_digest: str
    context_digest: str
    policy_digest: str
    target_id: str
    step_id: str
    payload: FrozenObject
    operation_id: str | None = None
    install_id: str | None = None
    schema: str = "1.0"

    def __post_init__(self) -> None:
        """Detach payload metadata without obtaining host authority."""
        object.__setattr__(self, "payload", object_value(self.payload))


@dataclass(frozen=True)
class DecisionFacts:
    """Closed typed fact groups, validated in full even when irrelevant."""

    values: FrozenObject
    state_phase: Phase = Phase.PLANNED
    state_revision: int = 0

    def __post_init__(self) -> None:
        """Detach every supplied fact before subsequent validation."""
        object.__setattr__(self, "values", object_value(self.values))


@dataclass(frozen=True)
class StepDisposition:
    """One exact selected target/step and its factual pending/completed receipt."""

    target_id: str
    step_id: str
    disposition: Disposition = Disposition.NOT_REQUESTED
    invocation_id: str | None = None
    effect_id: str | None = None
    result_digest: str | None = None


@dataclass(frozen=True)
class PolicyState:
    """Restorable v1 state; it is not consent, qualification or remote truth."""

    identity: PolicyIdentity
    operation_id: str
    revision: int
    phase: Phase
    plan_digest: str
    context_digest: str
    policy_digest: str
    dispositions: tuple[StepDisposition, ...] = ()
    last_event_id: str | None = None
    last_event_digest: str | None = None
    consumed_effect_receipts: tuple[str, ...] = ()
    primary: str | None = None
    cleanup: str | None = None
    remote_uncertain: bool = False
    schema: str = "1.0"
    namespace: Literal["operation", "install"] = "operation"


@dataclass(frozen=True)
class DecisionResult:
    """Deterministic memory-only admission result."""

    decision: Literal["allow", "deny"]
    rule_ids: tuple[str, ...]
    reason: str
    effects: tuple[EffectDescriptor, ...]
    policy_digest: str


@dataclass(frozen=True)
class PolicyTransition:
    """A pure proposal requiring independent host CAS and effect admission."""

    expected_revision: int
    next_state: PolicyState
    effects: tuple[EffectDescriptor, ...]
    decision: DecisionResult


class LocalPolicyPort(Protocol):
    """The only two reference-engine operations; there is no authorize alias."""

    def decide(self, event: DecisionEvent, facts: DecisionFacts) -> DecisionResult:
        """Evaluate a fully validated event and facts without I/O."""
        ...

    def reduce(
        self, state: PolicyState, event: DecisionEvent, facts: DecisionFacts
    ) -> PolicyTransition:
        """Propose an immutable revision without persisting or dispatching it."""
        ...
