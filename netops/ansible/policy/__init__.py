"""Pure local reference policy API; importing this package performs no bootstrap."""

from .contracts import (
    DecisionEvent,
    DecisionFacts,
    DecisionResult,
    Disposition,
    EffectDescriptor,
    EventKind,
    FrozenObject,
    LocalPolicyPort,
    Phase,
    PolicyBudgetError,
    PolicyEvaluationError,
    PolicyIdentity,
    PolicyInputError,
    PolicyLoadError,
    PolicyProgram,
    PolicyState,
    PolicyTransition,
    StepDisposition,
)
from .engine import LocalReferencePolicyEngine
from .loader import load_policy

__all__ = [
    "DecisionEvent", "DecisionFacts", "DecisionResult", "Disposition", "EffectDescriptor",
    "EventKind", "FrozenObject", "LocalPolicyPort", "LocalReferencePolicyEngine", "Phase",
    "PolicyBudgetError", "PolicyEvaluationError", "PolicyIdentity", "PolicyInputError",
    "PolicyLoadError", "PolicyProgram", "PolicyState", "PolicyTransition", "StepDisposition",
    "load_policy",
]
