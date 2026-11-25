"""Explicit hydration and pure seven-area companion planning.

No effectful adapter is automatically bootstrapped here. Explicit execution
requires A02's concrete host and private A01 admission; an uncomposed C01 service
remains blocked. Existing native entry points are untouched.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
from collections.abc import Sequence
from dataclasses import replace
from uuid import NAMESPACE_URL, uuid5

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode

from netops.change.diff import ConfigStyle, diff_configs, format_json

from .contracts import (
    INPUT_BINDING_INVALID,
    MAX_CONTENT_BYTES,
    ArtifactPort,
    Authorization,
    AuthorizationBroker,
    CancelReceipt,
    CapabilityCatalog,
    ClockPort,
    ContractError,
    ControllerPort,
    DependencyPort,
    ErrorCategory,
    EventPort,
    InputSource,
    LoadedInput,
    LoadedInputContext,
    Mode,
    NativeWorkflowPort,
    Observation,
    OperationOutcome,
    OperationPlan,
    OperationRequest,
    OutcomeStatus,
    PlannedEffect,
    ReadinessProjection,
    ReasonCode,
    SafeError,
    Stage,
    StepOutcome,
    TargetOutcome,
    aggregate_outcome,
    canonical_bytes,
    capability,
    counter,
    digest,
    finite,
    nonsecret_text,
    public_object,
    public_value,
    text,
    uuid_text,
    wire,
)
from .policy.contracts import (
    DecisionEvent,
    DecisionFacts,
    DecisionResult,
    EventKind,
    FrozenObject,
    Json,
    LocalPolicyPort,
    PolicyEvaluationError,
    PolicyInputError,
)
from .settings import SettingsSnapshot


class PolicyFailure(RuntimeError):
    """Safe in-memory internal failure, distinct from invalid public input.

    The diagnostic is an allowlisted internal cause, not a new wire reason.
    Surface adapters carry ``error`` into the ordinary failed outcome/exit 5.
    """

    def __init__(self, diagnostic: str) -> None:
        self.diagnostic = (
            diagnostic if diagnostic == "policy-input-invalid" else "policy-evaluation-failed"
        )
        self.error = SafeError(
            ErrorCategory.POLICY, ReasonCode.READING_UNAVAILABLE, Stage.EVALUATE,
            next_action="Repair or reload the qualified local policy evaluator before replanning; do not retry effects.",
        )
        self.exit_code = 5
        super().__init__(ReasonCode.READING_UNAVAILABLE.value)


class _UniqueLoader(yaml.SafeLoader):
    """Safe YAML with duplicates and aliases rejected before object expansion."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[str, object]:
        result: dict[str, object] = {}
        for key_node, value_node in node.value:
            key: object = self.construct_object(key_node, deep=deep)
            if type(key) is not str or not isinstance(key, str) or key in result:
                raise ContractError(INPUT_BINDING_INVALID)
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(INPUT_BINDING_INVALID)
        result[key] = value
    return result


def _json_constant(value: str) -> None:
    raise ContractError(INPUT_BINDING_INVALID)


def _inventory_value(value: Json) -> None:
    """Validate the native nonsecret inventory schema, including dormant records."""
    if not isinstance(value, FrozenObject) or any(key not in ("devices", "defaults") for key in value):
        raise ContractError(INPUT_BINDING_INVALID)
    devices = value.get("devices", FrozenObject())
    defaults = value.get("defaults", FrozenObject())
    if not isinstance(devices, FrozenObject) or not isinstance(defaults, FrozenObject):
        raise ContractError(INPUT_BINDING_INVALID)
    allowed = frozenset({
        "host", "vendor", "transport", "port", "groups", "tags", "site", "role",
        "jump_host", "jump_port",
    })
    for record in (defaults,) + tuple(devices.values()):
        if not isinstance(record, FrozenObject) or any(key not in allowed for key in record):
            raise ContractError(INPUT_BINDING_INVALID)
        for key, item in record.items():
            if key in ("port", "jump_port"):
                if counter(item, positive=True) > 65535:
                    raise ContractError(INPUT_BINDING_INVALID)
            elif key == "groups":
                if type(item) is not tuple or not isinstance(item, tuple):
                    raise ContractError(INPUT_BINDING_INVALID)
                for group in item:
                    text(group)
            elif key == "tags":
                if not isinstance(item, FrozenObject):
                    raise ContractError(INPUT_BINDING_INVALID)
                for tag in item.values():
                    text(tag)
            else:
                text(item)


def _content(item: LoadedInput) -> Json:
    """Revalidate exact nonsecret content in memory on every preview."""
    try:
        if type(item) is not LoadedInput:
            raise ContractError()
        item.__post_init__()
        item.source.__post_init__()
        decoded = item.content.decode("utf-8")
        if item.format == "json":
            value: object = json.loads(
                decoded, object_pairs_hook=_json_pairs, parse_constant=_json_constant,
            )
            result = public_value(value)
        elif item.format == "yaml":
            if any(isinstance(event, AliasEvent) for event in yaml.parse(decoded)):
                raise ContractError()
            result = public_value(yaml.load(decoded, Loader=_UniqueLoader))
        else:
            nonsecret_text(decoded)
            result = decoded
        if item.source.kind in ("inventory", "fragment"):
            _inventory_value(result)
        if hashlib.sha256(item.content).hexdigest() != item.source.digest:
            raise ContractError()
        return result
    except (ValueError, TypeError, UnicodeError, yaml.YAMLError, RecursionError):
        raise ContractError(INPUT_BINDING_INVALID) from None


def request_digest(request: OperationRequest) -> str:
    """Bind all intent except the previous plan's self-referential digest."""
    return digest(replace(request, plan_digest=None))


def plan_digest(plan: OperationPlan) -> str:
    """Bind canonical nonsecret plan content, excluding only its digest field."""
    encoded = wire(plan)
    if not isinstance(encoded, dict):
        raise ContractError()
    return digest(public_object({key: value for key, value in encoded.items() if key != "plan_digest"}))


def _binding(
    request: OperationRequest,
    contents: tuple[LoadedInput, ...],
    observations: tuple[Observation, ...],
    settings: SettingsSnapshot,
) -> str:
    return digest(public_object({
        "schema_version": "1.0", "request_digest": request_digest(request),
        "context_digest": digest(request.context),
        "settings_digest": digest(settings),
        "contents": tuple(public_object({
            "kind": item.source.kind, "ref": item.source.ref,
            "digest": hashlib.sha256(item.content).hexdigest(),
            "format": item.format, "parser_revision": item.parser_revision,
            "vendor_revision": item.vendor_revision,
        }) for item in contents),
        "observations": json.loads(canonical_bytes(observations)),
    }))


def _observations(
    request: OperationRequest,
    contents: tuple[LoadedInput, ...],
    observations: tuple[Observation, ...],
) -> None:
    if type(observations) is not tuple:
        raise ContractError(INPUT_BINDING_INVALID)
    identities: set[str] = set()
    for observation in observations:
        if type(observation) is not Observation:
            raise ContractError(INPUT_BINDING_INVALID)
        observation.__post_init__()
        if (
            observation.observation_id in identities
            or observation.target_id not in request.scope.target_ids
            or observation.context_digest != digest(request.context)
            or observation.route_digest != request.context.route_digest
            or observation.controller_id != request.context.controller_id
            or not any(
                item.source == observation.source
                and hashlib.sha256(item.content).hexdigest() == observation.content_digest
                for item in contents
            )
        ):
            raise ContractError(INPUT_BINDING_INVALID)
        identities.add(observation.observation_id)


def _validate_loaded(request: OperationRequest, loaded: LoadedInputContext) -> tuple[Json, ...]:
    try:
        # Reconstruct the public boundary to detect even deliberately corrupted
        # frozen/nested DTOs without accepting caller equality implementations.
        if type(request) is not OperationRequest:
            raise ContractError()
        validated = OperationRequest.from_json(canonical_bytes(request))
        if validated != request or type(loaded) is not LoadedInputContext:
            raise ContractError()
        if (
            loaded.schema_version != "1.0"
            or loaded.request_digest != request_digest(request)
            or loaded.context_digest != digest(request.context)
            or type(loaded.contents) is not tuple
            or tuple(item.source for item in loaded.contents) != request.inputs
        ):
            raise ContractError()
        values = tuple(_content(item) for item in loaded.contents)
        _required_inputs(request)
        _content_budget(loaded.contents)
        _observations(request, loaded.contents, loaded.observations)
        if type(loaded.settings) is not SettingsSnapshot:
            raise ContractError()
        loaded.settings.__post_init__()
        if loaded.binding_digest != _binding(request, loaded.contents, loaded.observations, loaded.settings):
            raise ContractError()
        return values
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise ContractError(INPUT_BINDING_INVALID) from None


def _required_inputs(request: OperationRequest) -> None:
    required = capability(request.operation).required_inputs
    if any(sum(ref.kind == kind for ref in request.inputs) != 1 for kind in required):
        raise ContractError(INPUT_BINDING_INVALID)


def _content_budget(contents: tuple[LoadedInput, ...]) -> None:
    if sum(len(item.content) for item in contents) > MAX_CONTENT_BYTES * 16:
        raise ContractError(INPUT_BINDING_INVALID)


def hydrate_inputs(
    request: OperationRequest, sources: Sequence[InputSource], clock: ClockPort,
) -> LoadedInputContext:
    """Hydrate only explicitly supplied bytes/checked descriptors outside preview.

    Reading starts at the descriptor's current offset and never seeks/reopens.
    No path, URL, socket, credential resolver or implicit source is supported.
    The caller owns descriptor lifetime. One bounded read detects oversize input.
    """
    try:
        OperationRequest.from_json(canonical_bytes(request))
        _required_inputs(request)
        finite(clock.monotonic())
        if len(sources) != len(request.inputs):
            raise ContractError()
        contents: list[LoadedInput] = []
        observations: list[Observation] = []
        for expected, source in zip(request.inputs, sources):
            if type(source) is not InputSource or source.source != expected:
                raise ContractError()
            if isinstance(source.content, bytes):
                if type(source.content) is not bytes:
                    raise ContractError()
                data = source.content
                assert isinstance(data, bytes)
            else:
                descriptor = source.content
                if (
                    type(descriptor) not in (io.FileIO, io.BufferedReader)
                    or descriptor.closed or not descriptor.readable()
                    or descriptor.writable()
                ):
                    raise ContractError()
                if not stat.S_ISREG(os.fstat(descriptor.fileno()).st_mode):
                    raise ContractError()
                data = descriptor.read(MAX_CONTENT_BYTES + 1)
            if type(data) is not bytes:
                raise ContractError()
            item = LoadedInput(
                source.source, source.format, data, source.parser_revision, source.vendor_revision,
            )
            _content(item)
            contents.append(item)
            _content_budget(tuple(contents))
            if type(source.observations) is not tuple:
                raise ContractError()
            observations.extend(source.observations)
        frozen_contents, frozen_observations = tuple(contents), tuple(observations)
        _observations(request, frozen_contents, frozen_observations)
        settings = SettingsSnapshot()
        return LoadedInputContext(
            request_digest(request), digest(request.context), frozen_contents,
            frozen_observations, _binding(request, frozen_contents, frozen_observations, settings),
            settings=settings,
        )
    except (ValueError, TypeError, OSError, AttributeError, KeyError, RecursionError):
        raise ContractError(INPUT_BINDING_INVALID) from None


def bind_settings(
    request: OperationRequest, loaded: LoadedInputContext, snapshot: SettingsSnapshot,
) -> LoadedInputContext:
    """Explicit bootstrap-only pure binding of validated stored/effective settings.

    Request JSON has no settings/overrides field. Bootstrap reads protected
    settings outside preview and resolves tuning before supplying this value.
    No loaded bytes, targets or original input provenance are replaced.
    """
    _validate_loaded(request, loaded)
    if type(snapshot) is not SettingsSnapshot:
        raise ContractError()
    snapshot.__post_init__()
    return replace(
        loaded, settings=snapshot,
        binding_digest=_binding(request, loaded.contents, loaded.observations, snapshot),
    )


_PRECONDITION_ERRORS = {
    ReasonCode.ROUTE_UNAVAILABLE: (
        ErrorCategory.TRANSPORT, Stage.CONNECT, "Repair the selected approved route and replan.",
    ),
    ReasonCode.DEPENDENCY_NOT_READY: (
        ErrorCategory.DEPENDENCY, Stage.READINESS,
        "Complete qualified dependency and controller setup before execution.",
    ),
    ReasonCode.CONSENT_STALE: (
        ErrorCategory.PRECONDITION, Stage.AUTHORIZE, "Replan and obtain fresh scoped consent.",
    ),
    ReasonCode.OBSERVATION_REQUIRED: (
        ErrorCategory.PRECONDITION, Stage.AUTHORIZE, "Observe the selected target and replan.",
    ),
    ReasonCode.CONSENT_REQUIRED: (
        ErrorCategory.PLATFORM, Stage.PROVISION, "Obtain consent for the exact planned effects.",
    ),
    ReasonCode.OUTPUT_REJECTED: (
        ErrorCategory.RENDERING, Stage.PUBLISH, "Select a valid protected output intent and replan.",
    ),
}


def _precondition(reason: ReasonCode, *, target_id: str | None = None) -> SafeError:
    """Use the frozen error matrix for each C01-produced diagnostic."""
    category, stage, next_action = _PRECONDITION_ERRORS[reason]
    return SafeError(category, reason, stage, target_id=target_id, next_action=next_action)


def _planned_effects(request: OperationRequest) -> tuple[PlannedEffect, ...]:
    item = capability(request.operation)
    targets = request.scope.target_ids if item.network else ("local",)
    effects: list[PlannedEffect] = []
    for target in targets:
        for kind in item.effects:
            # Backup observation is collection only. Publication remains an
            # explicit output occurrence, never an observe-mode side effect.
            if request.operation == "config.backup" and request.mode == Mode.OBSERVE and kind == "backup":
                continue
            ordinal = counter(len(effects))
            effects.append(PlannedEffect(
                occurrence_id=f"{request.operation_id}:{ordinal}",
                ordinal=ordinal, kind=kind, target_id=target, step_id=item.operation,
                destination_ref=request.output_intent.root_ref if kind in (
                    "save", "export", "backup", "render",
                ) else None,
            ))
    for kind, requested in (
        ("retention", request.output_intent.retention), ("git", request.output_intent.git),
    ):
        if requested:
            ordinal = counter(len(effects))
            effects.append(PlannedEffect(
                f"{request.operation_id}:{ordinal}", ordinal, kind, "local", "publish",
                request.output_intent.root_ref,
            ))
    return tuple(effects)


def _comparison(
    request: OperationRequest, loaded: LoadedInputContext, values: tuple[Json, ...],
) -> FrozenObject:
    """Validate selected semantic ownership before calling permissive native parsers."""
    pair = tuple(
        (item, value) for item, value in zip(loaded.contents, values)
        if item.source.kind in ("before", "after")
    )
    if (
        len(pair) != 2 or pair[0][0].source.kind == pair[1][0].source.kind
        or any(item.format != "text" or type(value) is not str for item, value in pair)
    ):
        raise ContractError(INPUT_BINDING_INVALID)
    before_item, before = next((item, value) for item, value in pair if item.source.kind == "before")
    after_item, after = next((item, value) for item, value in pair if item.source.kind == "after")
    assert isinstance(before, str) and isinstance(after, str)
    vendors = {
        "cisco_ios": ConfigStyle.CISCO, "cisco_xe": ConfigStyle.CISCO,
        "cisco_xr": ConfigStyle.CISCO, "cisco_ios_xr": ConfigStyle.CISCO,
        "cisco_nxos": ConfigStyle.CISCO, "arista_eos": ConfigStyle.CISCO,
        "juniper_junos": ConfigStyle.JUNOS, "junos": ConfigStyle.JUNOS,
        "nokia_sros": ConfigStyle.FLAT, "flat": ConfigStyle.FLAT,
    }
    if (
        before_item.parser_revision != after_item.parser_revision
        or before_item.vendor_revision != after_item.vendor_revision
    ):
        raise ContractError(INPUT_BINDING_INVALID)
    # Versioned source provenance is not a parser selector. Bind the full
    # paired revision, then use the same native autodetection as diff_configs.
    provenance = re.fullmatch(
        r"([a-z][a-z0-9]*(?:-[a-z0-9]+)*)-parser-v([1-9][0-9]*)",
        before_item.parser_revision,
    )
    native_provenance = (
        provenance is not None
        and before_item.vendor_revision
        == f"{provenance[1]}-vendor-v{provenance[2]}"
    )
    style: ConfigStyle | None
    if native_provenance:
        style = ConfigStyle.detect(before or after)
    else:
        if (
            before_item.parser_revision not in ("parser-1", "cisco", "junos", "flat")
            or before_item.vendor_revision not in tuple(vendors) + ("vendor-1",)
        ):
            raise ContractError(INPUT_BINDING_INVALID)
        style = (
            ConfigStyle(before_item.parser_revision)
            if before_item.parser_revision != "parser-1"
            else vendors.get(before_item.vendor_revision)
        )
    if (
        style is not None and before_item.vendor_revision in vendors
        and style != vendors[before_item.vendor_revision]
    ):
        raise ContractError(INPUT_BINDING_INVALID)
    style = style or ConfigStyle.detect(before or after)
    for content in (before, after):
        if "\x00" in content or content.lstrip().startswith(("{", "[", "<")):
            raise ContractError(INPUT_BINDING_INVALID)
        lines = tuple(line.strip() for line in content.splitlines()
                      if line.strip() and not line.strip().startswith(("#", "!")))
        if style == ConfigStyle.JUNOS:
            set_format = any(line.startswith("set ") for line in lines)
            if set_format and any(not line.startswith("set ") for line in lines):
                raise ContractError(INPUT_BINDING_INVALID)
            if not set_format:
                depth = 0
                for line in lines:
                    if line == "}":
                        depth -= 1
                    elif line.endswith("{"):
                        if line.count("{") != 1 or "}" in line:
                            raise ContractError(INPUT_BINDING_INVALID)
                        depth += 1
                    elif "{" in line or "}" in line or not line.endswith(";"):
                        raise ContractError(INPUT_BINDING_INVALID)
                    if depth < 0:
                        raise ContractError(INPUT_BINDING_INVALID)
                if depth != 0:
                    raise ContractError(INPUT_BINDING_INVALID)
        elif any(line.startswith("set ") or line.endswith(("{", "}")) for line in lines):
            raise ContractError(INPUT_BINDING_INVALID)
    native = diff_configs(before, after, style=style)
    missing = not before.strip() or not after.strip()
    return public_object({
        "native_payload": json.loads(format_json(native)),
        "comparison": {
            "status": "blocked" if missing else "drift" if native.has_changes else "no-change",
            "style": style.value, "execution_performed": False,
            "counts": {"unmatched": len(native.added), "missing": len(native.removed),
                       "drift": len(native.changed)},
            "input_missing": missing,
        },
    })


def _remediation(
    request: OperationRequest, loaded: LoadedInputContext, values: tuple[Json, ...],
) -> FrozenObject:
    """Use the native guarded owner with deterministic explicit identity and time."""
    from netops.playbooks.generator import _CHECK_KEY_TO_FAILURE, _generate_playbook
    from netops.playbooks.templates.remediation import VENDOR_COMMAND_MODULE

    source = next(value for item, value in zip(request.inputs, values) if item.kind == "findings")
    if not isinstance(source, FrozenObject):
        raise ContractError(INPUT_BINDING_INVALID)
    results = source.get("results", (source,))
    if not isinstance(results, tuple) or any(not isinstance(result, FrozenObject) for result in results):
        raise ContractError(INPUT_BINDING_INVALID)
    hosts: set[str] = set()
    generated: list[FrozenObject] = []
    coverage: list[FrozenObject] = []
    observation_time = loaded.observations[0].observed_at if loaded.observations else ""
    for result in results:
        assert isinstance(result, FrozenObject)
        host = text(result.get("host"))
        # Ansible inventory patterns and Jinja are executable selection syntax.
        # Only one literal selected inventory identity may enter generated plays.
        if (
            re.fullmatch(r"[A-Za-z0-9_.-]+", host) is None or host in hosts
            or host in ("all", "ungrouped")
        ):
            raise ContractError(INPUT_BINDING_INVALID)
        hosts.add(host)
        if request.scope.target_ids and host not in request.scope.target_ids:
            raise ContractError(INPUT_BINDING_INVALID)
        vendor = text(result.get("device_type", "_default"))
        if vendor not in VENDOR_COMMAND_MODULE:
            raise ContractError(INPUT_BINDING_INVALID)
        success = result.get("success")
        checks = result.get("checks")
        if type(success) is not bool or not isinstance(checks, FrozenObject):
            raise ContractError(INPUT_BINDING_INVALID)
        unsupported = False
        for name, check in checks.items():
            if not isinstance(check, FrozenObject) or type(check.get("alert")) is not bool:
                raise ContractError(INPUT_BINDING_INVALID)
            if check["alert"] is True and name not in _CHECK_KEY_TO_FAILURE:
                unsupported = True
        if success is False:
            coverage.append(public_object({"target_id": host, "status": "failed"}))
            continue
        if unsupported:
            coverage.append(public_object({"target_id": host, "status": "unsupported"}))
            continue
        native_result = json.loads(canonical_bytes(result))
        identifier = str(uuid5(NAMESPACE_URL, loaded.binding_digest + ":" + host))
        timestamp = text(result.get("timestamp", observation_time), empty=True)
        playbook = _generate_playbook(native_result, vendor, True, True, identifier, timestamp)
        coverage.append(public_object({
            "target_id": host,
            "status": "failed" if success is False else "unexecuted" if playbook is not None else "no-active-alert",
        }))
        if playbook is not None:
            generated.append(public_object(playbook.to_dict()))
    if request.scope.target_ids and set(request.scope.target_ids) != hosts:
        for target in request.scope.target_ids:
            if target not in hosts:
                coverage.append(public_object({"target_id": target, "status": "missing"}))
    if request.scope.target_ids:
        by_target = {item["target_id"]: item for item in coverage}
        coverage = [by_target[target] for target in request.scope.target_ids]
    plays_list: list[Json] = []
    for item in generated:
        selected_plays = item["plays"]
        if not isinstance(selected_plays, tuple):
            raise ContractError(INPUT_BINDING_INVALID)
        plays_list.extend(selected_plays)
    plays = tuple(plays_list)
    return public_object({
        "generated": tuple(generated), "coverage": tuple(coverage),
        "generated_yaml": (
            yaml.safe_dump(json.loads(canonical_bytes(plays)), sort_keys=False) if plays else None
        ),
        "execution_performed": False, "dry_run": True, "collect_authorized": False,
        "apply_authorized": False,
    })


def _projection(
    request: OperationRequest, loaded: LoadedInputContext, values: tuple[Json, ...],
) -> FrozenObject:
    """Produce inspectable loaded-input projections, never fabricated execution."""
    projection: dict[str, object] = {
        "area": capability(request.operation).area,
        "operation": capability(request.operation).operation,
        "inputs": tuple(public_object({
            "kind": item.kind, "ref": item.ref, "digest": item.digest, "value": value,
        }) for item, value in zip(request.inputs, values)),
        "execution_performed": False,
    }
    if request.operation == "compare.compare":
        projection.update(_comparison(request, loaded, values))
    elif request.operation in ("compare.remediation-preview", "compare.generate"):
        findings = next(value for item, value in zip(request.inputs, values) if item.kind == "findings")
        if findings == FrozenObject():
            projection["input_missing"] = True
            projection["coverage"] = tuple(public_object({
                "target_id": target, "status": "missing",
            }) for target in request.scope.target_ids)
            projection["generated"] = ()
            projection["execution_performed"] = False
        else:
            projection.update(_remediation(request, loaded, values))
    elif request.operation in ("report.aggregate", "report.render"):
        from netops.report.companion import project_outcome

        value = next(value for item, value in zip(request.inputs, values) if item.kind == "outcomes")
        if value == FrozenObject():
            projection["input_missing"] = True
            projection["report"] = public_object({
                "source_status": "blocked", "coverage_complete": False,
                "selected_count": len(request.scope.target_ids),
                "missing_count": len(request.scope.target_ids),
            })
        else:
            projection["report"] = project_outcome(value, request.scope.target_ids)
    return public_object(projection)


def _routes(
    request: OperationRequest, values: tuple[Json, ...],
) -> tuple[tuple[FrozenObject, ...], tuple[SafeError, ...]]:
    """Normalize credential-free native inventory values without reopening sources."""
    inventory = tuple(value for ref, value in zip(request.inputs, values) if ref.kind == "inventory")
    if len(inventory) > 1:
        raise ContractError(INPUT_BINDING_INVALID)
    devices = FrozenObject()
    defaults = FrozenObject()
    if len(inventory) == 1:
        root = inventory[0]
        if type(root) is not FrozenObject or not isinstance(root, FrozenObject):
            raise ContractError(INPUT_BINDING_INVALID)
        raw_devices, raw_defaults = root.get("devices", FrozenObject()), root.get("defaults", FrozenObject())
        if not isinstance(raw_devices, FrozenObject) or not isinstance(raw_defaults, FrozenObject):
            raise ContractError(INPUT_BINDING_INVALID)
        devices, defaults = raw_devices, raw_defaults
    routes: list[FrozenObject] = []
    errors: list[SafeError] = []
    for target in request.scope.target_ids:
        device = devices.get(target)
        if not isinstance(device, FrozenObject):
            routes.append(public_object({"target_id": target, "resolved": False}))
            if capability(request.operation).network and capability(request.operation).area != "scan":
                errors.append(_precondition(ReasonCode.ROUTE_UNAVAILABLE, target_id=target))
            continue
        merged = dict(defaults)
        merged.update(device)
        host = text(merged.get("host", target))
        vendor = text(merged.get("vendor", "autodetect"))
        transport = text(merged.get("transport", "ssh"))
        port = counter(merged.get("port", 23 if transport == "telnet" else 22), positive=True)
        if port > 65535 or "://" in host:
            raise ContractError(INPUT_BINDING_INVALID)
        routes.append(public_object({
            "target_id": target, "resolved": True, "host": host, "port": port,
            "vendor": vendor, "transport": transport,
            "controller_id": request.context.controller_id, "route_digest": request.context.route_digest,
        }))
    return tuple(routes), tuple(errors)


class WorkflowService:
    """Pure companion planning and explicitly composed host-only execution."""

    def __init__(
        self, policy: LocalPolicyPort, authorization: AuthorizationBroker,
        dependencies: DependencyPort, controller: ControllerPort,
        native: NativeWorkflowPort, artifacts: ArtifactPort, clock: ClockPort, events: EventPort,
    ) -> None:
        self._policy = policy
        self._authorization = authorization
        self._dependencies = dependencies
        self._controller = controller
        self._native = native
        self._artifacts = artifacts
        self._clock = clock
        self._events = events

    def catalog(self) -> CapabilityCatalog:
        """Return all seven areas without probes, resources, clocks or registry claims."""
        return CapabilityCatalog()

    def preview(self, request: OperationRequest, loaded: LoadedInputContext) -> OperationPlan:
        """Validate all bound bytes/provenance and plan without any host-port call."""
        values = _validate_loaded(request, loaded)
        settings = loaded.settings
        if (
            len(request.scope.target_ids) > settings.execution.target_limit
            or request.scope.limit > settings.execution.target_limit
            or (settings.controller.id is not None
                and settings.controller.id != request.context.controller_id)
        ):
            raise ContractError(INPUT_BINDING_INVALID)
        routes, route_errors = _routes(request, values)
        item = capability(request.operation)
        projection = _projection(request, loaded, values)
        input_present = projection.get("input_missing") is not True
        identity = request.context.policy_identity
        selected_digest = request_digest(request)
        context_digest = digest(request.context)
        # The policy sees the real operation in a pure planning mode. A requested
        # future effect is not presented as an already-consented admission.
        policy_mode = request.mode if request.mode in (Mode.PREVIEW, Mode.CHECK) else Mode.PREVIEW
        event = DecisionEvent(
            event_id=str(uuid5(NAMESPACE_URL, "netops:preview:" + selected_digest)),
            operation_id=request.operation_id,
            kind=EventKind.OPERATION_REQUESTED, expected_revision=0,
            plan_digest=selected_digest, context_digest=context_digest,
            policy_digest=identity.bundle_sha256,
            target_id="local", step_id="preview",
            payload=public_object({
                "request_digest": selected_digest, "loaded_input_digest": loaded.binding_digest,
                "plan_digest": selected_digest, "mode": policy_mode.value,
            }),
        )
        facts = DecisionFacts(public_object({
            "request": {"area": item.area, "operation": item.operation, "mode": policy_mode.value},
            "binding": {"input_valid": input_present, "plan_current": True, "policy_current": True},
            "control": {"cancelled": False, "remaining_ms": settings.execution.timeout_seconds * 1000},
            "scope": {"exclusions_valid": True, "selected_count": len(request.scope.target_ids)},
            "config": {"enabled": settings.ansible.enabled, "mode": settings.ansible.mode},
            "inventory": {"source_valid": True, "cache_binding_valid": True, "hostvars_safe": True},
        }))
        preconditions: list[SafeError] = list(route_errors)
        if not input_present:
            preconditions.append(SafeError(
                ErrorCategory.INVALID_INPUT, ReasonCode.INPUT_BINDING_INVALID, Stage.VALIDATE,
                next_action="Supply the complete bound versioned outcome or selected findings before replanning.",
            ))
        try:
            decision = self._policy.decide(event, facts)
        except PolicyInputError:
            raise PolicyFailure("policy-input-invalid") from None
        except PolicyEvaluationError:
            raise PolicyFailure("policy-evaluation-failed") from None
        if type(decision) is not DecisionResult or decision.policy_digest != identity.bundle_sha256:
            raise PolicyFailure("policy-evaluation-failed")
        if decision.decision != "allow" and input_present:
            preconditions.append(SafeError(
                ErrorCategory.POLICY, ReasonCode.CONSENT_STALE, Stage.AUTHORIZE,
                next_action="Resolve the local policy denial and obtain fresh scoped consent.",
            ))
        effects = (
            () if item.area in ("compare", "report") and request.mode in (Mode.PREVIEW, Mode.CHECK)
            else _planned_effects(request)
        )
        if item.observation_required or item.area == "compare":
            for target in request.scope.target_ids:
                if not any(observation.target_id == target for observation in loaded.observations):
                    preconditions.append(_precondition(ReasonCode.OBSERVATION_REQUIRED, target_id=target))
        if len(effects) != 0:
            preconditions.extend((
                _precondition(ReasonCode.DEPENDENCY_NOT_READY),
                _precondition(ReasonCode.CONSENT_REQUIRED),
            ))
        if any(effect.kind in ("save", "export", "backup", "render") for effect in effects):
            if request.output_intent.root_ref is None or len(request.output_intent.kinds) == 0:
                preconditions.append(_precondition(ReasonCode.OUTPUT_REJECTED))
        recovery_scope: tuple[str, ...] = ()
        if request.operation in ("config.apply", "config.rollback"):
            intents = tuple(value for ref, value in zip(request.inputs, values) if ref.kind == "intent")
            if len(intents) == 1 and isinstance(intents[0], FrozenObject):
                prestate = intents[0].get("prestate")
                if isinstance(prestate, FrozenObject) and set(prestate) == set(request.scope.target_ids):
                    recovery_scope = tuple(text(prestate[target]) for target in request.scope.target_ids)
        plan = OperationPlan(
            operation_id=request.operation_id, operation=request.operation,
            requested_mode=request.mode, targets=request.scope.target_ids, routes=routes,
            context=request.context,
            request_digest=selected_digest, input_binding_digest=loaded.binding_digest,
            policy_digest=decision.policy_digest, reducer_version=identity.reducer_version,
            effects=effects, observations=loaded.observations, preconditions=tuple(preconditions),
            native_payload=projection, output_intent=request.output_intent,
            concurrency=settings.execution.ssh_concurrency,
            deadline_ms=settings.execution.timeout_seconds * 1000,
            recovery_scope=recovery_scope, plan_digest="0" * 64,
            settings=settings,
        )
        return replace(plan, plan_digest=plan_digest(plan))

    def execute(
        self, request: OperationRequest, authorization: Authorization | None = None,
    ) -> OperationOutcome:
        """Execute only through the explicitly composed host, never caller projections."""
        request = OperationRequest.from_json(canonical_bytes(request))
        # Import here: the host composes this module's pure preview and A01's
        # concrete broker; neither dependency may initialize the other.
        from .execution import ExecutionHost

        if type(self._native) is ExecutionHost:
            from .contracts import CleanupOutcome
            from .controller_backend import _ControllerEffectsBackend

            terminal_cleanup = CleanupOutcome()
            try:
                outcome = self._native.execute(self, request, authorization)
            finally:
                if type(self._native._backend) is _ControllerEffectsBackend:
                    terminal_cleanup = self._native._backend._finish(request.operation_id)
            if request.operation == "report.render":
                from netops.report.companion import _preserve_source

                outcome = _preserve_source(outcome)
            if terminal_cleanup.status == "failed":
                cleanup = CleanupOutcome(
                    "failed", tuple(dict.fromkeys(
                        outcome.cleanup.remaining_refs + terminal_cleanup.remaining_refs,
                    )), outcome.cleanup.errors + terminal_cleanup.errors,
                )
                # Reuse central precedence without duplicating already
                # aggregated errors/findings into the returned public facts.
                status = aggregate_outcome(
                    request, outcome.targets, outcome.steps, errors=outcome.errors,
                    findings=outcome.findings, cleanup=cleanup,
                ).status
                outcome = replace(outcome, status=status, cleanup=cleanup)
            return outcome
        error = _precondition(ReasonCode.DEPENDENCY_NOT_READY)
        targets = tuple(TargetOutcome(
            target_id, OutcomeStatus.BLOCKED, False,
            unapplied_effects=capability(request.operation).effects,
        ) for target_id in request.scope.target_ids)
        steps = (StepOutcome(
            capability(request.operation).operation, OutcomeStatus.BLOCKED, False,
            unapplied_effects=capability(request.operation).effects,
        ),)
        return aggregate_outcome(
            request, targets, steps, errors=(error,),
            readiness=ReadinessProjection(errors=(error,)),
            provenance=public_object({"execution_performed": False, "integration_owner": "A02"}),
        )

    def cancel(self, operation_id: str) -> CancelReceipt:
        """Revoke private admission without allocating a checkpoint revision.

        Revocation precedes reading the receipt clock so a clock failure cannot
        leave an already accepted stop request eligible for a later dispatch.
        Issued-effect reconciliation remains the broker's factual boundary.
        """
        uuid_text(operation_id)
        # The broker uses plan_digest, so keep its concrete host qualification
        # out of this module's pure-planning import cycle.
        from .policy.authorization import AuthorizationBroker as _HostAuthorizationBroker

        if type(self._authorization) is not _HostAuthorizationBroker:
            return CancelReceipt(
                False, ReasonCode.DEPENDENCY_NOT_READY.value, finite(self._clock.monotonic()),
            )
        from .controller import ControllerLauncher

        if type(self._controller) is ControllerLauncher:
            self._controller._cancel(operation_id)
        from .execution import ExecutionHost

        # Wake the authentic host before a stalled native credential reader's
        # admission guard can make broker revocation wait on its lock.
        if type(self._native) is ExecutionHost:
            self._native.notify_cancelled(operation_id)
        self._authorization.revoke(operation_id)
        return CancelReceipt(
            True, ReasonCode.CANCELLED.value, finite(self._clock.monotonic()),
        )
