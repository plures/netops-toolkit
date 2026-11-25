"""Bounded deterministic evaluation and pure state-transition proposals."""

from __future__ import annotations

import hashlib
import json
from dataclasses import fields, is_dataclass, replace
from enum import Enum

from . import _validation as v
from .contracts import (
    MAX_DEPTH,
    MAX_NODES,
    MAX_SAFE_INT,
    MAX_VISITS,
    POLICY_EVENT_CONFLICT,
    POLICY_REJECTED,
    DecisionEvent,
    DecisionFacts,
    DecisionResult,
    Declaration,
    Disposition,
    EffectDescriptor,
    Expression,
    FrozenObject,
    Phase,
    PolicyBudgetError,
    PolicyEvaluationError,
    PolicyIdentity,
    PolicyInputError,
    PolicyLoadError,
    PolicyProgram,
    PolicyState,
    PolicyTransition,
    Scalar,
    StepDisposition,
)
from .loader import (
    _Builder,
    _example,
    _paths,
    action,
    load_policy,
    validate_example_bindings,
    validate_identity,
)


def _wire(value: object) -> object:
    """Encode only internal immutable values for deterministic event identity."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, FrozenObject):
        return {key: _wire(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_wire(item) for item in value]
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _wire(getattr(value, field.name)) for field in fields(value)}
    if value is None or type(value) in (str, bool, int, float):
        return value
    v.fail()
    raise AssertionError


def _event_digest(event: DecisionEvent) -> str:
    encoded = json.dumps(
        _wire(event), sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _expression_value(expr: Expression, depth: int = 0) -> FrozenObject:
    """Revalidate even caller-constructed programs, including dormant branches."""
    if type(expr) is not Expression or depth > MAX_DEPTH:
        v.fail()
    if type(expr.path) is not tuple or type(expr.children) is not tuple:
        v.fail()
    if expr.kind == "literal":
        if expr.path != () or expr.op != "" or expr.children != ():
            v.fail()
        return FrozenObject((("kind", "literal"), ("type", expr.value_type), ("value", expr.value)))
    if expr.value is not None:
        v.fail()
    if expr.kind == "path":
        if expr.op != "" or expr.children != ():
            v.fail()
        return FrozenObject((("kind", "path"), ("segments", expr.path)))
    if expr.path != ():
        v.fail()
    if expr.kind in ("not", "paren") and len(expr.children) == 1 and expr.op == "":
        return FrozenObject((
            ("kind", expr.kind), ("operand", _expression_value(expr.children[0], depth + 1)),
        ))
    if expr.kind == "binary" and len(expr.children) == 2:
        return FrozenObject((
            ("kind", "binary"), ("op", expr.op),
            ("left", _expression_value(expr.children[0], depth + 1)),
            ("right", _expression_value(expr.children[1], depth + 1)),
        ))
    v.fail()
    raise AssertionError


def _immutable(value: object, depth: int = 0) -> None:
    """Require exact recursive DTOs, not caller-defined equality or subclasses."""
    # DTO/container wrappers are not expression nodes. The semantic expression
    # depth is independently checked by _expression_value and the loader.
    if depth > MAX_DEPTH * 4 + 16:
        v.fail()


    if value is None or type(value) in (str, bool, int, float):
        return
    if type(value) is tuple:
        assert isinstance(value, tuple)
        if len(value) > MAX_NODES:
            v.fail()
        for item in value:
            _immutable(item, depth + 1)
        return
    if type(value) is FrozenObject:
        assert isinstance(value, FrozenObject)
        _immutable(value.entries, depth + 1)
        return
    if (
        type(value) in (PolicyIdentity, Declaration, Expression, EffectDescriptor)
        and is_dataclass(value) and not isinstance(value, type)
    ):
        for field in fields(value):
            _immutable(getattr(value, field.name), depth + 1)
        return
    v.fail()


def _completion_counters(value: object, dispositions: tuple[StepDisposition, ...]) -> FrozenObject:
    """Bind intermediate or final counters to the complete factual index."""
    v.result_counters(value)
    assert isinstance(value, FrozenObject)
    if v.counter(value["selected"]) != len(dispositions):
        v.fail()
    for key, disposition in (
        ("completed", Disposition.SUCCEEDED), ("failed", Disposition.FAILED),
        ("cancelled", Disposition.CANCELLED), ("unsupported", Disposition.UNSUPPORTED),
        ("blocked", Disposition.BLOCKED),
    ):
        if v.counter(value[key]) != sum(
            step.disposition == disposition for step in dispositions
        ):
            v.fail()
    if v.counter(value["unsuccessful"]) != sum(
        step.disposition not in (Disposition.SUCCEEDED, Disposition.NOT_REQUESTED)
        for step in dispositions
    ):
        v.fail()
    return value


class _Evaluation:
    def __init__(self, values: FrozenObject) -> None:
        self.values = values
        self.visits = 0

    def evaluate(self, expr: Expression) -> Scalar:
        self.visits += 1
        if self.visits > MAX_VISITS:
            raise PolicyBudgetError("policy-evaluation-failed")
        if expr.kind == "literal":
            if expr.value is None:
                raise PolicyEvaluationError("policy-evaluation-failed")
            return expr.value
        if expr.kind == "path":
            value = v.lookup(self.values, expr.path)
            v.leaf(expr.path, value)
            if not isinstance(value, (str, bool, int, float)):
                raise PolicyEvaluationError("policy-evaluation-failed")
            return value
        left = self.evaluate(expr.children[0])
        if expr.kind == "paren":
            return left
        if expr.kind == "not":
            if type(left) is not bool:
                raise PolicyEvaluationError("policy-evaluation-failed")
            return left is False
        if expr.op == "And" and left is False:
            return False
        if expr.op == "Or" and left is True:
            return True
        right = self.evaluate(expr.children[1])
        if type(left) is not type(right):
            raise PolicyEvaluationError("policy-evaluation-failed")
        if expr.op in ("And", "Or"):
            if type(left) is not bool or type(right) is not bool:
                raise PolicyEvaluationError("policy-evaluation-failed")
            return (left is True and right is True) if expr.op == "And" else (
                left is True or right is True
            )
        if expr.op in ("Eq", "Neq"):
            if type(left) is float:
                raise PolicyEvaluationError("policy-evaluation-failed")
            return (left == right) if expr.op == "Eq" else (left != right)
        if type(left) not in (int, float):
            raise PolicyEvaluationError("policy-evaluation-failed")
        if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
            raise PolicyEvaluationError("policy-evaluation-failed")
        if expr.op == "Gt":
            return left > right
        if expr.op == "Lt":
            return left < right
        if expr.op == "Gte":
            return left >= right
        if expr.op == "Lte":
            return left <= right
        raise PolicyEvaluationError("policy-evaluation-failed")

    def boolean(self, expr: Expression) -> bool:
        value = self.evaluate(expr)
        if type(value) is not bool:
            raise PolicyEvaluationError("policy-evaluation-failed")
        return value is True


class LocalReferencePolicyEngine:
    """Implement LocalPolicyPort without clocks, callbacks, persistence or dispatch."""

    def __init__(self, program: PolicyProgram) -> None:
        try:
            self._validate_program(program)
        except (PolicyInputError, TypeError, ValueError, KeyError, RecursionError):
            raise PolicyLoadError("policy-load-invalid") from None
        self._program = program

    @staticmethod
    def _validate_program(program: PolicyProgram) -> None:
        if type(program) is not PolicyProgram:
            v.fail()
        for field in fields(program):
            if field.name != "_load_bytes":
                _immutable(getattr(program, field.name))
        validate_identity(program.identity)
        v.digest(program.content_digest)
        if any(type(x) is not tuple for x in (program.rules, program.constraints, program.examples)):
            v.fail()
        declarations = program.rules + program.constraints
        if any(type(declaration) is not Declaration for declaration in declarations):
            v.fail()
        for declaration in declarations:
            v.text(declaration.id, safe=True)
            v.text(declaration.source_id, safe=True)
        ids = tuple(sorted(d.id for d in declarations))
        if ids != program.identity.rule_manifest or len(set(ids)) != len(ids) or len(ids) > 512:
            v.fail()
        builder = _Builder()
        for declaration in declarations:
            if (
                type(declaration.conditions) is not tuple
                or type(declaration.actions) is not tuple
                or type(declaration.required_paths) is not tuple
                or len(declaration.conditions) == 0
            ):
                v.fail()
            v.counter(declaration.order)
            v.text(declaration.reason, safe=True)
            if declaration.source_id != "netops_companion_" + declaration.id.removeprefix("netops.companion."):
                v.fail()
            expressions = declaration.conditions
            if declaration.required is not None:
                expressions += (declaration.required,)
            for expression in expressions:
                checked = builder.boolean(_expression_value(expression))
                if checked != expression:
                    v.fail()
            actual_paths: set[tuple[str, ...]] = set()
            for expression in expressions:
                actual_paths.update(_paths(expression))
            if tuple(sorted(actual_paths)) != declaration.required_paths:
                v.fail()
            for descriptor in declaration.actions:
                if type(descriptor) is not EffectDescriptor:
                    v.fail()
                if action(FrozenObject((("name", descriptor.name), ("params", descriptor.params)))) != descriptor:
                    v.fail()
        if builder.nodes != program.node_count:
            v.fail()
        if type(program.node_count) is not int or not 1 <= program.node_count <= MAX_NODES:
            v.fail()
        orders = tuple(rule.order for rule in program.rules)
        if tuple(sorted(set(orders))) != orders:
            v.fail()
        for constraint in program.constraints:
            if constraint.required is None or constraint.actions != () or len(constraint.conditions) != 1:
                v.fail()
        for rule in program.rules:
            if rule.required is not None or len(rule.actions) == 0:
                v.fail()
        for example in program.examples:
            _example(example, set(ids), {c.id for c in program.constraints})
        validate_example_bindings(program.examples, declarations)
        operands = program._load_bytes
        if type(operands) is not tuple or len(operands) != 3:
            v.fail()
        if any(type(operand) is not bytes for operand in operands):
            v.fail()
        # Re-derive the entire projection from the original hashed bytes. A
        # caller's internally consistent replacement semantics are not proof.
        original = load_policy(operands[0], operands[1], operands[2], program.identity)
        if program != original:
            v.fail()

    def _inputs(self, event: DecisionEvent, facts: DecisionFacts) -> FrozenObject:
        projected = v.event_value(event)
        if type(facts) is not DecisionFacts or type(facts.state_phase) is not Phase:
            v.fail()
        v.counter(facts.state_revision)
        if facts.state_revision != event.expected_revision:
            v.fail()
        if event.policy_digest != self._program.identity.bundle_sha256:
            v.fail()
        v.tree(facts.values)
        if "event" in facts.values or "state" in facts.values:
            v.fail()
        # Intermediate counters include still-pending selected work. Only an
        # actual final aggregate requires a complete partition.
        if "result" in facts.values:
            v.result_counters(facts.values["result"])
        if event.kind.value == "OperationRequested":
            request = facts.values.get("request")
            if isinstance(request, FrozenObject) and "mode" in request:
                if event.payload["mode"] != request["mode"]:
                    v.fail()
        return FrozenObject(facts.values.entries + (
            ("event", projected),
            ("state", FrozenObject((("phase", facts.state_phase.value), ("revision", facts.state_revision)))),
        ))

    def decide(self, event: DecisionEvent, facts: DecisionFacts) -> DecisionResult:
        """Return complete ordered intents or deny; never return partial permission."""
        values = self._inputs(event, facts)
        evaluation = _Evaluation(values)
        violations: list[str] = []
        reasons: list[str] = []
        for constraint in self._program.constraints:
            guard = evaluation.boolean(constraint.conditions[0])
            if guard:
                if constraint.required is None:
                    raise PolicyEvaluationError("policy-evaluation-failed")
                for path in constraint.required_paths:
                    v.leaf(path, v.lookup(values, path))
                if evaluation.boolean(constraint.required) is False:
                    violations.append(constraint.id)
                    reasons.append(constraint.reason)
        digest = self._program.identity.bundle_sha256
        if len(violations) != 0:
            return DecisionResult("deny", (), reasons[0], (), digest)
        matched: list[str] = []
        effects: list[EffectDescriptor] = []
        effect_rules = 0
        for rule in self._program.rules:
            applies = True
            for condition in rule.conditions:
                if evaluation.boolean(condition) is False:
                    applies = False
                    break
            if applies is False:
                continue
            for path in rule.required_paths:
                v.leaf(path, v.lookup(values, path))
            matched.append(rule.id)
            if any(effect.name == "request_effect" for effect in rule.actions):
                effect_rules += 1
            effects.extend(rule.actions)
        if len(set(effects)) != len(effects) or effect_rules > 1:
            raise PolicyEvaluationError("policy-evaluation-failed")
        if any(sum(effect.name == name for effect in effects) > 1 for name in (
            "set_phase", "record_step", "record_outcome",
        )):
            raise PolicyEvaluationError("policy-evaluation-failed")
        if len(matched) == 0:
            return DecisionResult("deny", (), POLICY_REJECTED, (), digest)
        return DecisionResult("allow", tuple(sorted(set(matched))), "policy-admitted", tuple(effects), digest)

    def _state(self, state: PolicyState) -> None:
        if type(state) is not PolicyState:
            v.fail()
        if v.text(state.schema) != "1.0":
            v.fail()
        validate_identity(state.identity)
        if state.identity != self._program.identity or type(state.phase) is not Phase:
            v.fail()
        if v.text(state.namespace) not in ("operation", "install"):
            v.fail()
        v.counter(state.revision)
        v.uuid(state.operation_id)
        for item in (state.plan_digest, state.context_digest, state.policy_digest):
            v.digest(item)
        if state.policy_digest != self._program.identity.bundle_sha256:
            v.fail()
        if (state.last_event_id is None) != (state.last_event_digest is None):
            v.fail()
        if state.last_event_id is not None:
            v.uuid(state.last_event_id)
            v.digest(state.last_event_digest)
        v.scalar(state.remote_uncertain, "bool")
        for summary in (state.primary, state.cleanup):
            if summary is not None:
                if v.text(summary) not in v.STATUSES:
                    v.fail()
        v.identifiers(state.consumed_effect_receipts)
        if type(state.dispositions) is not tuple or len(state.dispositions) > MAX_NODES:
            v.fail()
        seen: set[tuple[str, str]] = set()
        invocations: set[str] = set()
        effect_ids: set[str] = set()
        completed_effects: set[str] = set()
        for step in state.dispositions:
            if type(step) is not StepDisposition or type(step.disposition) is not Disposition:
                v.fail()
            v.text(step.target_id, safe=True)
            v.text(step.step_id, safe=True)
            key = (step.target_id, step.step_id)
            if key in seen:
                v.fail()
            seen.add(key)
            for receipt in (step.invocation_id, step.effect_id):
                if receipt is not None:
                    v.text(receipt, safe=True)
            if step.invocation_id is not None:
                if step.invocation_id in invocations:
                    v.fail()
                invocations.add(step.invocation_id)
            if step.result_digest is not None:
                v.digest(step.result_digest)
            if step.disposition != Disposition.NOT_REQUESTED and step.result_digest is None:
                v.fail()
            if step.disposition == Disposition.NOT_REQUESTED and step.result_digest is not None:
                v.fail()
            if step.effect_id is not None:
                if step.effect_id in effect_ids:
                    v.fail()
                effect_ids.add(step.effect_id)
                if step.result_digest is not None:
                    completed_effects.add(step.effect_id)
        if not set(state.consumed_effect_receipts).issubset(completed_effects):
            v.fail()

    def reduce(
        self, state: PolicyState, event: DecisionEvent, facts: DecisionFacts
    ) -> PolicyTransition:
        """Propose a checked next revision, retaining factual selected dispositions."""
        self._state(state)
        self._inputs(event, facts)
        if (
            state.operation_id != (event.operation_id or event.install_id)
            or state.namespace != ("operation" if event.operation_id is not None else "install")
            or state.plan_digest != event.plan_digest
            or state.context_digest != event.context_digest
            or facts.state_phase != state.phase
        ):
            v.fail()
        event_digest = _event_digest(event)
        if state.last_event_id == event.event_id:
            if state.last_event_digest != event_digest or event.expected_revision + 1 != state.revision:
                raise PolicyInputError(POLICY_EVENT_CONFLICT)
            duplicate = DecisionResult("deny", (), "event-already-recorded", (), state.policy_digest)
            return PolicyTransition(state.revision, state, (), duplicate)
        if state.revision != event.expected_revision:
            raise PolicyInputError(POLICY_EVENT_CONFLICT)
        decision = self.decide(event, facts)
        if decision.decision == "deny":
            return PolicyTransition(state.revision, state, (), decision)
        if any(effect.name == "request_effect" for effect in decision.effects):
            selected = tuple(step for step in state.dispositions if (
                step.target_id == event.target_id and step.step_id == event.step_id
            ))
            if len(selected) != 1 or selected[0].result_digest is not None:
                raise PolicyInputError(POLICY_EVENT_CONFLICT)
        if state.revision == MAX_SAFE_INT:
            v.fail()
        phase = state.phase
        dispositions = state.dispositions
        primary, cleanup, uncertain = state.primary, state.cleanup, state.remote_uncertain
        receipts = state.consumed_effect_receipts
        kind = event.kind.value
        request = facts.values.get("request")
        lifecycle = facts.values.get("lifecycle")
        change = facts.values.get("change")
        ownership = facts.values.get("ownership")
        candidate = facts.values.get("candidate")
        continuation = tuple(
            effect.params["kind"] for effect in decision.effects
            if effect.name == "request_effect"
        )
        uninstall_terminal = (
            kind == "StepCompleted" and isinstance(request, FrozenObject)
            and request.get("area") == "setup" and request.get("operation") == "uninstall"
            and isinstance(lifecycle, FrozenObject) and lifecycle.get("next_effect_kind") == "none"
        )
        terminal_uninstall = (
            uninstall_terminal and continuation == ()
            and isinstance(request, FrozenObject) and request.get("mode") == "apply"
            and isinstance(change, FrozenObject) and change.get("poststate_verified") is True
            and isinstance(ownership, FrozenObject) and ownership.get("valid") is True
            and isinstance(candidate, FrozenObject) and candidate.get("pointer_matches") is True
        )
        # All terminal uninstall paths, including ordinary Executing receipts,
        # need the same factual postcheck. Phase alone is never cleanup proof.
        if uninstall_terminal and not terminal_uninstall:
            raise PolicyInputError(POLICY_EVENT_CONFLICT)
        allowed_phases = {
            "OperationRequested": (Phase.PLANNED,),
            "DependencyObserved": (Phase.PLANNED, Phase.STAGING),
            "InstallConsented": (Phase.PLANNED,),
            "Observed": (Phase.OBSERVING, Phase.EXECUTING),
            "ApplyConsented": (Phase.PLANNED, Phase.UNCERTAIN),
            "StepCompleted": (Phase.EXECUTING, Phase.STAGING, Phase.CANCELLING, Phase.UNCERTAIN),
            "CandidateVerified": (Phase.STAGING, Phase.VERIFIED),
            "Activated": (Phase.VERIFIED,),
        }
        if kind in allowed_phases and phase not in allowed_phases[kind]:
            # Lifecycle receipts retain their factual Admitted phase. A terminal
            # uninstall is not another effect: require its verified poststate,
            # then correlate the pending invocation/one-use receipt below.
            lifecycle_phase = (
                kind == "StepCompleted" and isinstance(request, FrozenObject)
                and request.get("area") == "setup"
                and (
                    (phase == Phase.VERIFIED and request.get("operation") == "install"
                     and continuation == ("dependency-activate",))
                    or (phase == Phase.ADMITTED and request.get("operation") == "uninstall"
                        and (continuation in (("dependency-uninstall",), ("restore-active-pointer",))
                             or terminal_uninstall))
                    or (phase == Phase.ADMITTED and request.get("operation") == "restore"
                        and continuation == ()
                        and isinstance(lifecycle, FrozenObject)
                        and lifecycle["next_effect_kind"] == "none")
                )
            )
            if lifecycle_phase is False:
                raise PolicyInputError(POLICY_EVENT_CONFLICT)
        if kind == "Cancelled" and phase in (Phase.COMPLETED, Phase.CANCELLED, Phase.ACTIVE):
            return PolicyTransition(state.revision, state, (), replace(decision, effects=()))
        if kind == "Activated" and dispositions:
            # This is the correlated receipt of an already performed pointer
            # CAS, not a request for a second activation. Record its selected
            # disposition atomically with the factual Active phase. Existing
            # canonical phase-only states have no selected-work bindings:
            # preserve their phase transition without inventing a receipt or
            # selected completion. Such states never authorize host effects.
            matching = tuple(step for step in dispositions if (
                step.target_id == event.target_id and step.step_id == event.step_id
            ))
            if len(matching) != 1:
                raise PolicyInputError(POLICY_EVENT_CONFLICT)
            pending = matching[0]
            if pending.effect_id is None or pending.result_digest is not None or pending.effect_id in receipts:
                raise PolicyInputError(POLICY_EVENT_CONFLICT)
            dispositions = tuple(
                replace(step, disposition=Disposition.SUCCEEDED, result_digest=event_digest)
                if step == pending else step for step in dispositions
            )
            receipts += (pending.effect_id,)
            result = _completion_counters(facts.values.get("result"), dispositions)
            v.final_counters(result)
            if result["remote_uncertain"] is not uncertain:
                v.fail()
            primary = "success"
        if kind in ("Observed", "StepCompleted"):
            matching = tuple(step for step in dispositions if (
                step.target_id == event.target_id and step.step_id == event.step_id
            ))
            if len(matching) != 1:
                raise PolicyInputError(POLICY_EVENT_CONFLICT)
            pending = matching[0]
            if pending.invocation_id != event.payload["invocation_id"] or pending.result_digest is not None:
                raise PolicyInputError(POLICY_EVENT_CONFLICT)
            if kind == "StepCompleted":
                effect_id = v.text(event.payload["effect_id"], safe=True)
                if pending.effect_id != effect_id or effect_id in receipts:
                    raise PolicyInputError(POLICY_EVENT_CONFLICT)
                receipts += (effect_id,)
                primary = v.text(event.payload["primary"])
                current_cleanup = v.text(event.payload["cleanup"])
                cleanup = (
                    state.cleanup if state.cleanup is not None and state.cleanup != "success"
                    else current_cleanup
                )
                uncertain = state.remote_uncertain or event.payload["remote_uncertain"] is True
                status = primary
                result_digest = v.digest(event.payload["safe_result_digest"])
            else:
                status = v.text(event.payload["disposition"])
                result_digest = v.digest(event.payload["observation_digest"])
            # Aggregate-only "partial" is never a single selected disposition.
            if status == "partial":
                v.fail()
            disposition = Disposition.SUCCEEDED if status == "success" else Disposition(status)
            updated = replace(pending, disposition=disposition, result_digest=result_digest)
            dispositions = tuple(updated if step == pending else step for step in dispositions)
            if kind == "StepCompleted":
                _completion_counters(facts.values.get("result"), dispositions)
        for effect in decision.effects:
            if effect.name == "set_phase":
                phase = Phase(v.text(effect.params["phase"]))
            elif effect.name == "record_step":
                status = v.text(effect.params["disposition"])
                if status == "partial":
                    v.fail()
                selected = tuple(step for step in dispositions if (
                    step.target_id == event.target_id and step.step_id == event.step_id
                ))
                if len(selected) != 1 or selected[0].result_digest is None:
                    v.fail()
                actual = Disposition.SUCCEEDED if status == "success" else Disposition(status)
                dispositions = tuple(
                    replace(step, disposition=actual) if step == selected[0] else step
                    for step in dispositions
                )
            elif effect.name == "record_outcome":
                # Only aggregate StepCompleted is terminal. Dependency observations
                # and qualification outcomes must not overwrite their phase.
                if kind == "Observed":
                    outcome = v.text(effect.params["status"])
                    if outcome == "partial":
                        v.fail()
                    selected_status = (
                        Disposition.SUCCEEDED if outcome == "success" else Disposition(outcome)
                    )
                    # A health finding can fail successful work, never promote
                    # an unsuccessful factual observation to success or erase
                    # its original failure category.
                    dispositions = tuple(
                        replace(step, disposition=selected_status)
                        if step.target_id == event.target_id and step.step_id == event.step_id
                        and step.disposition == Disposition.SUCCEEDED
                        else step for step in dispositions
                    )
                    factual = v.text(event.payload["disposition"])
                    precedence = ("failed", "cancelled", "unsupported", "blocked", "success")
                    primary = next(status for status in precedence if status in (factual, outcome))
                    continue
                if kind == "StepCompleted":
                    result = _completion_counters(facts.values.get("result"), dispositions)
                    lifecycle = facts.values.get("lifecycle")
                    request = facts.values.get("request")
                    remaining = (
                        isinstance(request, FrozenObject) and request.get("area") == "setup"
                        and isinstance(lifecycle, FrozenObject)
                        and lifecycle.get("next_effect_kind") != "none"
                    )
                    if (
                        any(step.disposition == Disposition.NOT_REQUESTED for step in dispositions)
                        or remaining
                        or any(item.name == "request_effect" for item in decision.effects)
                    ):
                        # The correlated receipt is recorded, but later selected
                        # work/occurrences remain. This is not a terminal result.
                        continue
                    v.final_counters(result)
                    if result["remote_uncertain"] is not uncertain:
                        v.fail()
                    if cleanup is not None and cleanup != "success":
                        if result["cleanup_failed"] is not True:
                            v.fail()
                    phase = (
                        Phase.UNCERTAIN if uncertain or phase == Phase.UNCERTAIN
                        else Phase.COMPLETED
                    )
                primary = v.text(effect.params["status"])
        # An operational intent opens the factual pending-invocation phase.
        # It is still only a proposal: the host must persist it and separately
        # consume/enter A01's private permit before invoking any I/O.
        operational_request = facts.values.get("request")
        if (
            state.namespace == "operation"
            and isinstance(operational_request, FrozenObject)
            and (
                (operational_request.get("area"), operational_request.get("operation"))
                in (("health", "gather"), ("config", "collect"))
                or (
                    (operational_request.get("area"), operational_request.get("operation"))
                    in (
                        ("vault", "resolve-for-run"), ("scan", "discover"),
                        ("scan", "save"), ("inventory", "export"), ("report", "render"),
                        ("compare", "generate"),
                        ("inventory", "refresh"), ("config", "backup"),
                        ("config", "apply"), ("config", "rollback"),
                    )
                    and any(
                        step.target_id == event.target_id and step.step_id == event.step_id
                        and step.invocation_id is not None and step.effect_id == event.step_id
                        and step.result_digest is None for step in dispositions
                    )
                )
            )
            and any(effect.name == "request_effect" for effect in decision.effects)
            and phase in (Phase.PLANNED, Phase.ADMITTED, Phase.OBSERVING)
        ):
            phase = Phase.EXECUTING
        next_state = replace(
            state, revision=state.revision + 1, phase=phase, dispositions=dispositions,
            last_event_id=event.event_id, last_event_digest=event_digest,
            consumed_effect_receipts=receipts, primary=primary, cleanup=cleanup,
            remote_uncertain=uncertain,
        )
        self._state(next_state)
        return PolicyTransition(state.revision, next_state, decision.effects, decision)
