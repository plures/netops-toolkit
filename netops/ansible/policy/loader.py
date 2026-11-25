"""Pure strict loading of the canonical-derived reference projection."""

from __future__ import annotations

import hashlib
import json
from typing import cast

from . import _validation as v
from .contracts import (
    MAX_BYTES,
    MAX_DEPTH,
    MAX_NODES,
    MAX_SAFE_INT,
    PIN,
    DecisionEvent,
    Declaration,
    EffectDescriptor,
    EventKind,
    Expression,
    FrozenObject,
    Json,
    PolicyIdentity,
    PolicyInputError,
    PolicyLoadError,
    PolicyProgram,
    Scalar,
    object_value,
)


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyLoadError("policy-load-invalid")
        result[key] = value
    return result


def _constant(value: str) -> object:
    raise PolicyLoadError("policy-load-invalid")


def _string(value: object) -> str:
    return v.text(value, safe=True)


def _sequence(value: Json) -> tuple[Json, ...]:
    if not isinstance(value, tuple):
        v.fail()
    assert isinstance(value, tuple)
    return value


def _path(value: Json) -> tuple[str, ...]:
    return tuple(_string(part) for part in _sequence(value))


def validate_identity(identity: PolicyIdentity) -> None:
    """Validate all identity fields, including exact mandatory reducer identity."""
    if type(identity) is not PolicyIdentity:
        v.fail()
    for item in (
        identity.profile, identity.numeric_profile, identity.schema, identity.canonical_revision,
        identity.reducer_version,
    ):
        _string(item)
    if (
        identity.profile != "netops-reference-v1"
        or identity.numeric_profile != "exact-int53-finite-order-v1"
        or identity.schema != "1.0"
        or identity.canonical_revision != PIN
        or identity.reducer_version != "1"
    ):
        v.fail()
    for item in (identity.source_sha256, identity.contracts_sha256, identity.bundle_sha256):
        v.digest(item)
    if type(identity.rule_manifest) is not tuple or len(identity.rule_manifest) == 0:
        v.fail()
    for item in identity.rule_manifest:
        _string(item)
    if tuple(sorted(set(identity.rule_manifest))) != identity.rule_manifest:
        v.fail()


class _Builder:
    def __init__(self) -> None:
        self.nodes = 0

    def expression(self, value: Json, depth: int = 0) -> Expression:
        self.nodes += 1
        if self.nodes > MAX_NODES or depth > MAX_DEPTH:
            v.fail()
        if not isinstance(value, FrozenObject):
            v.fail()
        assert isinstance(value, FrozenObject)
        kind = _string(value.get("kind"))
        if kind == "literal":
            v.keys(value, ("kind", "type", "value"))
            ty = _string(value["type"])
            v.scalar(value["value"], ty)
            return Expression(kind, ty, cast(Scalar, value["value"]))
        if kind == "path":
            v.keys(value, ("kind", "segments"))
            path = _path(value["segments"])
            return Expression(kind, v.path_type(path), path=path)
        if kind in ("not", "paren"):
            v.keys(value, ("kind", "operand"))
            operand = self.expression(value["operand"], depth + 1)
            if kind == "not" and operand.value_type != "bool":
                v.fail()
            return Expression(kind, operand.value_type, children=(operand,))
        if kind == "binary":
            v.keys(value, ("kind", "op", "left", "right"))
            left = self.expression(value["left"], depth + 1)
            right = self.expression(value["right"], depth + 1)
            op = _string(value["op"])
            if left.value_type != right.value_type:
                v.fail()
            ty = left.value_type
            valid = (
                (op in ("And", "Or") and ty == "bool")
                or (op in ("Eq", "Neq") and ty in ("bool", "int", "string"))
                or (op in ("Gt", "Lt", "Gte", "Lte") and ty in ("int", "float"))
            )
            if not valid:
                v.fail()
            return Expression(kind, "bool", op=op, children=(left, right))
        v.fail()
        raise AssertionError

    def boolean(self, value: Json) -> Expression:
        result = self.expression(value)
        if result.value_type != "bool":
            v.fail()
        return result


def action(value: Json) -> EffectDescriptor:
    """Validate the exact constant-only action schema, even in dead rules."""
    item = v.keys(value, ("name", "params"))
    name = _string(item["name"])
    fields = {
        "set_phase": ("phase", tuple(p.value for p in v.Phase)),
        "record_step": ("disposition", v.STATUSES),
        "record_outcome": ("status", v.STATUSES),
        "revoke_pending": ("scope", ("operation",)),
        "request_effect": ("kind", v.EFFECTS),
    }
    if name not in fields:
        v.fail()
    key, domain = fields[name]
    params = v.keys(item["params"], (key,))
    if params[key] not in domain:
        v.fail()
    return EffectDescriptor(name, params)


def _paths(expression: Expression) -> set[tuple[str, ...]]:
    result = {expression.path} if expression.kind == "path" else set()
    for child in expression.children:
        result.update(_paths(child))
    return result


def _example(value: Json, ids: set[str], constraint_ids: set[str]) -> FrozenObject:
    item = v.keys(value, ("case_id", "rule_id", "input", "expect"))
    _string(item["case_id"])
    if item["rule_id"] not in ids:
        v.fail()
    input_value = v.keys(item["input"], ("state", "event", "facts"))
    for group in ("state", "facts"):
        obj = input_value[group]
        if not isinstance(obj, FrozenObject):
            v.fail()
        assert isinstance(obj, FrozenObject)
        if group == "state":
            v.tree(obj, ("state",))
        elif len(obj) != 0:
            v.tree(obj)
    event = input_value["event"]
    if not isinstance(event, FrozenObject):
        v.fail()
    assert isinstance(event, FrozenObject)
    if any(name not in ("kind", "expected_revision", "payload") for name in event):
        namespace = "operation_id" if "operation_id" in event else "install_id"
        v.keys(event, (
            "schema", "event_id", namespace, "kind", "expected_revision", "plan_digest",
            "context_digest", "policy_digest", "target_id", "step_id", "payload",
        ))
        full = DecisionEvent(
            event_id=_string(event["event_id"]), kind=EventKind(_string(event["kind"])),
            expected_revision=v.counter(event["expected_revision"]),
            plan_digest=_string(event["plan_digest"]), context_digest=_string(event["context_digest"]),
            policy_digest=_string(event["policy_digest"]), target_id=_string(event["target_id"]),
            step_id=_string(event["step_id"]), payload=object_value(event["payload"]),
            operation_id=_string(event["operation_id"]) if namespace == "operation_id" else None,
            install_id=_string(event["install_id"]) if namespace == "install_id" else None,
            schema=_string(event["schema"]),
        )
        v.event_value(full)
    else:
        # Canonical expression-only fixtures intentionally carry minimal metadata.
        # They are not acceptable full runtime events or reconstructed permissions.
        projected = event
        if event.get("kind") == "InstallConsented" and "payload" in event:
            payload = v.keys(event["payload"], ("lifecycle_kind", "plan_id", "lifecycle_binding_digest"))
            v.uuid(payload["plan_id"])
            v.digest(payload["lifecycle_binding_digest"])
            projected = FrozenObject(tuple(
                (name, FrozenObject((("lifecycle_kind", payload["lifecycle_kind"]),)))
                if name == "payload" else (name, entry)
                for name, entry in event.items()
            ))
        v.tree(projected, ("event",))
    expected = v.keys(item["expect"], (
        "decision", "reason", "actions", "next_phase", "aggregate", "constraint_outcomes", "error",
    ))
    if expected["decision"] not in ("allow", "deny", "error"):
        v.fail()
    domains = (
        ("reason", None), ("error", ("policy-load-invalid", "policy-input-invalid",
                                   "policy-evaluation-failed", "policy-event-conflict")),
        ("next_phase", tuple(p.value for p in v.Phase)), ("aggregate", v.STATUSES),
    )
    for name, domain in domains:
        if expected[name] is not None:
            _string(expected[name])
            if domain is not None and expected[name] not in domain:
                v.fail()
    actions = tuple(action(entry) for entry in _sequence(expected["actions"]))
    if len(set(actions)) != len(actions):
        v.fail()
    if any(sum(entry.name == name for entry in actions) > 1 for name in (
        "set_phase", "record_step", "record_outcome",
    )):
        v.fail()
    outcomes = expected["constraint_outcomes"]
    if not isinstance(outcomes, FrozenObject):
        v.fail()
    assert isinstance(outcomes, FrozenObject)
    for name, outcome in outcomes.items():
        if name not in constraint_ids or outcome not in ("satisfied", "violated", "not-applicable"):
            v.fail()
    return item


def _example_budget(value: Json, depth: int = 0) -> int:
    if depth > MAX_DEPTH:
        v.fail()
    count = 1
    children = value.values() if isinstance(value, FrozenObject) else (
        value if isinstance(value, tuple) else ()
    )
    for child in children:
        count += _example_budget(child, depth + 1)
        if count > MAX_NODES:
            v.fail()
    return count


def validate_example_bindings(
    examples: tuple[FrozenObject, ...], declarations: tuple[Declaration, ...]
) -> None:
    """Validate target-required paths and static action association for every case."""
    by_id = {declaration.id: declaration for declaration in declarations}
    for example in examples:
        target = by_id[_string(example["rule_id"])]
        input_value = v.keys(example["input"], ("state", "event", "facts"))
        facts = input_value["facts"]
        if not isinstance(facts, FrozenObject):
            v.fail()
        assert isinstance(facts, FrozenObject)
        if "event" in facts or "state" in facts:
            v.fail()
        variables = FrozenObject(facts.entries + (
            ("event", input_value["event"]), ("state", input_value["state"]),
        ))
        for path in target.required_paths:
            v.leaf(path, v.lookup(variables, path))
        if target.id.startswith("netops.companion.aggregate_"):
            v.final_counters(facts.get("result"))
        expected = example["expect"]
        assert isinstance(expected, FrozenObject)
        expected_actions = tuple(action(value) for value in _sequence(expected["actions"]))
        actual_actions = target.actions if expected["decision"] == "allow" else ()
        if expected_actions != actual_actions:
            v.fail()


def load_policy(
    source: bytes, contracts: bytes, bundle: bytes, expected: PolicyIdentity
) -> PolicyProgram:
    """Validate pure bytes into an immutable program, without fallback or I/O."""
    try:
        return _load(source, contracts, bundle, expected)
    except (PolicyInputError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise PolicyLoadError("policy-load-invalid") from None


def _load(
    source: bytes, contracts: bytes, bundle: bytes, expected: PolicyIdentity
) -> PolicyProgram:
    validate_identity(expected)
    for data, digest in (
        (source, expected.source_sha256), (contracts, expected.contracts_sha256),
        (bundle, expected.bundle_sha256),
    ):
        if type(data) is not bytes or len(data) == 0 or len(data) > MAX_BYTES:
            v.fail()
        data.decode("utf-8")
        if hashlib.sha256(data).hexdigest() != digest:
            v.fail()
    decoded: object = json.loads(bundle, object_pairs_hook=_pairs, parse_constant=_constant)
    root = object_value(decoded)
    v.keys(root, (
        "canonical_revision", "constraints", "content_digest", "contracts", "manifest",
        "max_safe_int", "numeric_profile", "profile", "reducer_version", "rules", "schema",
        "source_digests",
    ))
    for name in ("canonical_revision", "numeric_profile", "profile", "reducer_version", "schema"):
        if root[name] != getattr(expected, name):
            v.fail()
    if type(root["max_safe_int"]) is not int or root["max_safe_int"] != MAX_SAFE_INT:
        v.fail()
    digests = v.keys(root["source_digests"], ("source", "contracts"))
    if digests["source"] != expected.source_sha256 or digests["contracts"] != expected.contracts_sha256:
        v.fail()
    content = v.digest(root["content_digest"])
    # The producer's encoded() is compact sorted UTF-8 JSON followed by LF.
    # Remove only this exact root field from the original encoding, preserving
    # Rust's binary64 spelling rather than round-tripping it through Python.
    member = b',"content_digest":"' + content.encode("ascii") + b'"'
    if bundle.count(member) != 1 or hashlib.sha256(bundle.replace(member, b"", 1)).hexdigest() != content:
        v.fail()
    builder = _Builder()
    manifest: dict[str, tuple[str, tuple[tuple[str, ...], ...]]] = {}
    for row in _sequence(root["manifest"]):
        item = v.keys(row, ("id", "source_id", "required_paths"))
        name, source_id = _string(item["id"]), _string(item["source_id"])
        paths = tuple(_path(p) for p in _sequence(item["required_paths"]))
        if name in manifest or tuple(sorted(set(paths))) != paths:
            v.fail()
        for path in paths:
            v.path_type(path)
        manifest[name] = (source_id, paths)
    if tuple(sorted(manifest)) != expected.rule_manifest:
        v.fail()
    rules: list[Declaration] = []
    constraints_out: list[Declaration] = []
    seen: set[str] = set()
    orders: set[int] = set()
    for family, destination in (("constraints", constraints_out), ("rules", rules)):
        for row in _sequence(root[family]):
            fields = (
                ("guard", "id", "kind", "reason", "require", "severity", "source_id")
                if family == "constraints"
                else ("actions", "conditions", "id", "kind", "order", "source_id")
            )
            item = v.keys(row, fields)
            name, source_id = _string(item["id"]), _string(item["source_id"])
            if (
                name in seen or name not in manifest
                or source_id != "netops_companion_" + name.removeprefix("netops.companion.")
                or not name.startswith("netops.companion.")
                or manifest[name][0] != source_id
            ):
                v.fail()
            seen.add(name)
            conditions: tuple[Expression, ...]
            expressions: tuple[Expression, ...]
            if family == "constraints":
                if item["kind"] != "constraint" or item["severity"] != "error":
                    v.fail()
                conditions = (builder.boolean(item["guard"]),)
                required = builder.boolean(item["require"])
                declaration = Declaration(
                    name, source_id, conditions, required=required,
                    reason=_string(item["reason"]), required_paths=manifest[name][1],
                )
                expressions = conditions + (required,)
            else:
                if item["kind"] != "rule":
                    v.fail()
                order = v.counter(item["order"])
                if order in orders:
                    v.fail()
                orders.add(order)
                conditions = tuple(builder.boolean(x) for x in _sequence(item["conditions"]))
                actions = tuple(action(x) for x in _sequence(item["actions"]))
                if len(conditions) == 0 or len(actions) == 0 or len(set(actions)) != len(actions):
                    v.fail()
                if sum(a.name == "set_phase" for a in actions) > 1:
                    v.fail()
                declaration = Declaration(
                    name, source_id, conditions, actions, order=order,
                    required_paths=manifest[name][1],
                )
                expressions = conditions
            actual_paths: set[tuple[str, ...]] = set()
            for expression in expressions:
                actual_paths.update(_paths(expression))
            if actual_paths != set(manifest[name][1]):
                v.fail()
            destination.append(declaration)
    if len(seen) == 0 or len(seen) > 512 or seen != set(manifest):
        v.fail()
    if tuple(rule.order for rule in rules) != tuple(range(len(constraints_out), len(seen))):
        v.fail()
    example_values = _sequence(root["contracts"])
    for example_value in example_values:
        _example_budget(example_value)
    examples = tuple(_example(x, seen, {c.id for c in constraints_out}) for x in example_values)
    names = tuple(_string(x["case_id"]) for x in examples)
    if len(set(names)) != len(names) or {x["rule_id"] for x in examples} != seen:
        v.fail()
    for name in seen:
        group = tuple(x for x in examples if x["rule_id"] == name)
        prefix = manifest[name][0] + "_example_"
        if {_string(x["case_id"]) for x in group} != {
            prefix + str(index) for index in range(len(group))
        }:
            v.fail()
    validate_example_bindings(examples, tuple(rules + constraints_out))
    program = PolicyProgram(
        expected, tuple(sorted(rules, key=lambda rule: rule.order)), tuple(constraints_out),
        examples, builder.nodes, content,
    )
    object.__setattr__(program, "_load_bytes", (source, contracts, bundle))
    return program
