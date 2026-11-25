"""Read-only prerequisite catalog, deterministic plans and consuming-context evidence."""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import math
import sys
from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import asdict, dataclass, replace
from importlib import resources
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

from netops.ansible.artifacts import OwnedStatePort
from netops.ansible.contracts import (
    AuthorizationBroker,
    CancelPort,
    ClockPort,
    ContractError,
    ErrorCategory,
    EventPort,
    InstallContext,
    InstallScope,
    Mode,
    OutcomeStatus,
    ReadinessProjection,
    ReadinessReport,
    ReasonCode,
    SafeEvent,
)
from netops.ansible.contracts import digest as public_digest
from netops.ansible.lifecycle_execution import OwnedLifecycleState
from netops.ansible.policy import contracts as lifecycle_contracts
from netops.ansible.policy.authorization import AuthorizationBroker as PrivateBroker
from netops.ansible.policy.contracts import (
    DecisionEvent,
    DecisionFacts,
    EventKind,
    FrozenObject,
    LocalPolicyPort,
    PolicyIdentity,
    freeze,
)

from ._composition import ManagedLifecycleState
from ._lifecycle import DependencyLifecycle, InstallOutcome
from ._probe_catalog import PROBE_SYMBOLS

__all__ = [
    "observe_probe", "RegistryError", "DependencyEntry", "PublicOperation",
    "ConsumingContext", "ProbeResult", "DependencyAdapter", "DependencyCatalog",
    "InstallStep", "InstallPlan", "DependencyRegistry", "DependencyService", "OwnedStatePort",
]

ADAPTERS = frozenset(PROBE_SYMBOLS)
STATUSES = frozenset({"available", "missing", "blocked", "unsupported"})
_PROBE_OBSERVATION_DEFERRED: ContextVar[bool] = ContextVar("probe_observation_deferred", default=False)


def observe_probe(result: ProbeResult, role: str, duration: float,
                  logger: logging.Logger) -> None:
    """Pair a safe probe log and counter without exposing telemetry sink failures."""
    if _PROBE_OBSERVATION_DEFERRED.get():
        return
    try:
        logger.info(
            "dependency.probe",
            extra={"metric_name": "netops.dependency.probe.count", "metric_value": 1,
                   "context": role, "status": result.status, "reason": result.reason,
                   "duration": max(0.0, duration),
                   "category": "none" if result.status == "available" else "dependency",
                   "next_action": result.next_action, "dependency": result.dependency},
        )
    except Exception:
        # Observability is not authority and cannot invalidate factual readiness.
        pass


class RegistryError(ValueError):
    """Closed registry validation failure, without supplied input diagnostics."""


class _NeverCancelled:
    """Uninstall has no public cancellation argument; host revocation still applies."""

    def is_cancelled(self) -> bool:
        return False

    def wait(self, timeout: float) -> bool:
        return False


def _packaged_identity() -> PolicyIdentity:
    root = resources.files("netops.ansible.policy")
    source = root.joinpath("ansible_molecule.px").read_bytes()
    contracts = root.joinpath("ansible_molecule.contracts.px").read_bytes()
    bundle = root.joinpath("bundle.json").read_bytes()
    parsed = json.loads(bundle)
    return PolicyIdentity(
        parsed["canonical_revision"], hashlib.sha256(source).hexdigest(),
        hashlib.sha256(contracts).hexdigest(), hashlib.sha256(bundle).hexdigest(),
        tuple(x["id"] for x in parsed["manifest"]), parsed["reducer_version"],
    )


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _object(value: object) -> dict:
    if not isinstance(value, dict):
        raise RegistryError("registry-invalid")
    return value


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(type(x) is not str or not x for x in value):
        raise RegistryError("registry-invalid")
    if len(set(value)) != len(value):
        raise RegistryError("registry-invalid")
    return tuple(value)


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError("duplicate-key")
        result[key] = value
    return result


@dataclass(frozen=True)
class DependencyEntry:
    """One declarative prerequisite; executable commands never come from JSON."""

    id: str
    kind: str
    adapter: str
    probe: str
    context: str
    consumers: tuple[str, ...]
    requires: tuple[str, ...]
    platforms: tuple[str, ...]
    source: str
    version: str
    effects: tuple[str, ...]
    ownership: str
    recovery: str
    digest: str | None = None
    size: int | None = None


@dataclass(frozen=True)
class PublicOperation:
    """Explicit exported symbols and their required and selected-intent capabilities."""

    module: str
    exports: tuple[str, ...]
    capability: str
    tier: str
    dependencies: tuple[str, ...]
    intents: tuple[tuple[str, tuple[str, ...]], ...]
    ui_actions: tuple[str, ...] = ()
    export_dependencies: tuple[tuple[str, tuple[str, ...]], ...] = ()
    variants: tuple[tuple[str, tuple[str, ...]], ...] = ()
    aliases: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ConsumingContext:
    """Actual process selection; a label alone is never platform or route proof."""

    id: str
    platform: str
    architecture: str
    python: str
    path: str
    role: str
    collection_paths: tuple[str, ...] = ()
    driver: str | None = None
    image: str | None = None
    grants: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Reject ambiguous contexts before any process starts."""
        if (
            self.role not in ("native", "controller")
            or any(not isinstance(x, str) or not x for x in
                   (self.id, self.platform, self.architecture, self.python))
            or not Path(self.python).is_absolute()
            or not isinstance(self.path, str)
        ):
            raise RegistryError("context-invalid")

    @property
    def digest(self) -> str:
        """Bind every consuming process, path, runtime and platform input."""
        return _digest(asdict(self))


@dataclass(frozen=True)
class ProbeResult:
    """A functional observation, explicitly not a qualification certificate."""

    dependency: str
    context_digest: str
    status: str
    reason: str
    version: str | None = None
    evidence_digest: str | None = None
    next_action: str = "inspect-prerequisite"

    def __post_init__(self) -> None:
        """Keep untrusted adapter statuses outside successful evidence."""
        if self.status not in STATUSES or len(self.context_digest) != 64:
            raise RegistryError("probe-invalid")
        if self.status == "available" and not self.evidence_digest:
            raise RegistryError("probe-evidence-missing")


class DependencyAdapter(Protocol):
    """Bounded factual I/O only; acquisition is an I02 responsibility."""

    def probe(
        self, entry: DependencyEntry, context: ConsumingContext, deadline: float,
    ) -> ProbeResult:
        """Inspect the exact selected consuming process without network or installation."""
        ...


@dataclass(frozen=True)
class DependencyCatalog:
    """Single package-resource authority for setup, help and documentation."""

    revision: str
    digest: str
    entries: tuple[DependencyEntry, ...]
    operations: tuple[PublicOperation, ...]
    native_baseline: tuple[str, ...]


@dataclass(frozen=True)
class InstallStep:
    """A would-effect description, never an installer invocation or permission."""

    dependency: str
    context: str
    ownership: str
    source: str
    digest: str | None
    size: int | None
    destination: str
    reuse: str
    effects: tuple[str, ...]
    separate_grants: tuple[str, ...]
    recovery: str
    disposition: str = "blocked"
    reason: str = "verified-asset-lock-missing"


@dataclass(frozen=True)
class InstallPlan:
    """Immutable full-scope plan binding registry, consuming contexts and exact policy."""

    id: str
    digest: str
    context: InstallContext
    registry_revision: str
    registry_digest: str
    consuming_contexts: tuple[str, ...]
    policy_identity: PolicyIdentity
    steps: tuple[InstallStep, ...]
    qualification: str
    free_space: int | None = None
    lifecycle: lifecycle_contracts.InstallPlan | None = None
    blocked: tuple[str, ...] = ()


class DependencyRegistry:
    """Validate a complete immutable DAG and public-operation manifest before use."""

    def __init__(
        self, revision: str, entries: tuple[DependencyEntry, ...],
        operations: tuple[PublicOperation, ...], qualification: dict, digest: str,
        native_baseline: tuple[str, ...],
        package_requirements: tuple[tuple[str, tuple[str, ...]], ...] = (),
    ) -> None:
        self.revision = revision
        self.entries = entries
        self.operations = operations
        self._qualification_bytes = json.dumps(qualification, sort_keys=True).encode()
        self.digest = digest
        self.native_baseline = native_baseline
        self.package_requirements = package_requirements

    @property
    def qualification(self) -> dict:
        """Return a detached lock; caller changes cannot certify the registry."""
        return cast(dict, json.loads(self._qualification_bytes))

    @classmethod
    def load(cls) -> DependencyRegistry:
        """Load bounded packaged JSON, including from an installed wheel."""
        values = []
        for name in ("registry.json", "operations.json", "qualification.json"):
            raw = resources.files("netops.dependencies").joinpath(name).read_bytes()
            if len(raw) > 1048576:
                raise RegistryError("registry-limit")
            values.append(json.loads(raw, object_pairs_hook=_pairs))
        return cls.from_data(*values)

    @classmethod
    def from_data(
        cls, data: object, operations: object, qualification: object,
    ) -> DependencyRegistry:
        """Reject unknown adapters, cycles, omitted consumers and fictional lock evidence."""
        try:
            return cls._from_data(data, operations, qualification)
        except RegistryError:
            raise
        except (KeyError, TypeError, ValueError, RecursionError):
            raise RegistryError("registry-invalid") from None

    @classmethod
    def _from_data(
        cls, data: object, operations: object, qualification: object,
    ) -> DependencyRegistry:
        root, manifest, lock = map(_object, (data, operations, qualification))
        if any(x.get("schema_version") != "1.0" for x in (root, manifest, lock)):
            raise RegistryError("schema-invalid")
        revision = root.get("catalog_revision")
        if not isinstance(revision, str) or not revision or manifest.get("catalog_revision") != revision:
            raise RegistryError("revision-invalid")
        entries: list[DependencyEntry] = []
        for raw in root["entries"]:
            value = _object(raw)
            if set(value) != {
                "id", "kind", "adapter", "probe", "context", "consumers", "requires",
                "platforms", "source", "version", "effects", "ownership", "recovery",
            }:
                raise RegistryError("entry-fields-invalid")
            if any(type(value[k]) is not str or not value[k] for k in (
                "id", "kind", "adapter", "probe", "context", "source", "version",
                "ownership", "recovery",
            )):
                raise RegistryError("entry-invalid")
            if value["adapter"] not in ADAPTERS or value["context"] not in ("native", "controller"):
                raise RegistryError("adapter-invalid")
            if value["probe"] not in PROBE_SYMBOLS[value["adapter"]]:
                raise RegistryError("probe-unregistered")
            if (value["adapter"] == "collection") != (value["kind"] == "galaxy"):
                raise RegistryError("collection-not-pip")
            if value["kind"] not in ("pip", "python", "galaxy", "executable", "library", "runtime", "image", "platform"):
                raise RegistryError("kind-invalid")
            if (value["id"].startswith(("ansible.", "cisco.", "arista.", "junipernetworks.", "paloaltonetworks."))
                    and value["kind"] != "galaxy"):
                raise RegistryError("collection-not-pip")
            for key in ("consumers", "requires", "platforms", "effects"):
                value = {**value, key: _strings(value[key])}
            if not value["consumers"]:
                raise RegistryError("consumer-omitted")
            entries.append(DependencyEntry(**value))
        ids = tuple(x.id for x in entries)
        if len(set(ids)) != len(ids) or not ids or len(ids) > 512:
            raise RegistryError("duplicate-or-empty-registry")
        public: list[PublicOperation] = []
        for raw in manifest["operations"]:
            value = _object(raw)
            public.append(PublicOperation(
                value["module"], _strings(value["exports"]), value["capability"], value["tier"],
                _strings(value["dependencies"]),
                tuple((k, _strings(v)) for k, v in _object(value["intents"]).items()),
                _strings(value.get("ui_actions", [])),
                tuple((k, _strings(v)) for k, v in _object(value.get("export_dependencies", {})).items()),
                tuple((k, _strings(v)) for k, v in _object(value.get("variants", {})).items()),
                tuple(_object(value.get("aliases", {})).items()),
            ))
        by_module = {operation.module: operation for operation in public}

        def canonical(module: str, export: str, active: frozenset[tuple[str, str]]) -> tuple[str, ...]:
            key = (module, export)
            operation = by_module.get(module)
            if key in active or operation is None or export not in operation.exports:
                raise RegistryError("public-alias-invalid")
            target = dict(operation.aliases).get(export)
            if target is not None:
                if not isinstance(target, str) or target.count(":") != 1:
                    raise RegistryError("public-alias-invalid")
                target_module, target_export = target.split(":")
                return canonical(target_module, target_export, active | {key})
            return dict(operation.export_dependencies).get(export, operation.dependencies)

        for operation in public:
            if any(
                export not in operation.exports or export in dict(operation.export_dependencies)
                or not isinstance(target, str) or target.count(":") != 1
                for export, target in operation.aliases
            ):
                raise RegistryError("public-alias-invalid")
        public = [
            replace(operation, export_dependencies=tuple(
                (export, canonical(operation.module, export, frozenset()))
                for export in operation.exports
            )) if operation.aliases else operation
            for operation in public
        ]
        capabilities = {x.capability for x in public}
        if len({x.module for x in public}) != len(public):
            raise RegistryError("duplicate-operation")
        for operation in public:
            if not operation.exports or operation.tier not in ("native", "companion", "enhanced"):
                raise RegistryError("operation-invalid")
            needed = set(operation.dependencies)
            if operation.export_dependencies and (
                {name for name, _ in operation.export_dependencies} != set(operation.exports)
            ):
                raise RegistryError("public-manifest-drift")
            variant_names = {name for name, _ in operation.variants}
            if variant_names.intersection(name for name, _ in operation.intents):
                raise RegistryError("operation-intent-ambiguous")
            local_exports = tuple(
                (export, deps) for export, deps in operation.export_dependencies
                if export not in dict(operation.aliases)
            )
            for _, deps in (*operation.intents, *local_exports, *operation.variants):
                needed.update(deps)
            if not needed <= set(ids):
                raise RegistryError("unknown-dependency")
            for dependency in needed:
                if operation.capability not in next(x for x in entries if x.id == dependency).consumers:
                    raise RegistryError("consumer-drift")
        for entry in entries:
            if not set(entry.requires) <= set(ids) or not set(entry.consumers) <= capabilities:
                raise RegistryError("unknown-edge-or-consumer")
        if lock.get("qualified") != []:
            # Q03 owns real evidence admission; arbitrary edited JSON is never proof.
            raise RegistryError("qualification-evidence-not-admitted")
        baseline = _strings(manifest["native_baseline"])
        if not baseline or not set(baseline) <= set(ids):
            raise RegistryError("native-baseline-invalid")
        package_requirements = tuple(
            (group, _strings(dependencies))
            for group, dependencies in _object(root["package_requirements"]).items()
        )
        if "base" not in dict(package_requirements) or any(
            not isinstance(group, str) or not group
            or (group != "base" and not group.startswith("extra:"))
            or any(
                dependency not in ids
                or next(entry for entry in entries if entry.id == dependency).kind != "pip"
                for dependency in dependencies
            )
            for group, dependencies in package_requirements
        ):
            raise RegistryError("package-groups-invalid")
        result = cls(
            revision, tuple(entries), tuple(public), lock, _digest([root, manifest, lock]),
            baseline, package_requirements,
        )
        result.ordered()
        return result

    def entry(self, dependency: str) -> DependencyEntry:
        """Resolve an exact immutable ID."""
        for entry in self.entries:
            if entry.id == dependency:
                return entry
        raise RegistryError("unknown-dependency")

    def operation(self, module: str, export: str) -> PublicOperation:
        """Resolve an exact registered public function/class."""
        for operation in self.operations:
            if operation.module == module and export in operation.exports:
                requirements = dict(operation.export_dependencies)
                target = dict(operation.aliases).get(export)
                if target is not None:
                    source = self.operation(*target.split(":"))
                    return replace(
                        operation, capability=source.capability, tier=source.tier,
                        dependencies=source.dependencies, intents=source.intents,
                    )
                return replace(operation, dependencies=requirements[export]) if requirements else operation
        raise RegistryError("public-manifest-drift")

    def ordered(self, selected: tuple[str, ...] | None = None) -> tuple[DependencyEntry, ...]:
        """Topologically resolve transitive dependencies in stable registry order."""
        done: set[str] = set()
        active: set[str] = set()
        result: list[DependencyEntry] = []

        def visit(name: str) -> None:
            if name in active:
                raise RegistryError("dependency-cycle")
            if name in done:
                return
            active.add(name)
            entry = self.entry(name)
            for edge in entry.requires:
                visit(edge)
            active.remove(name)
            done.add(name)
            result.append(entry)

        for name in selected if selected is not None else tuple(x.id for x in self.entries):
            visit(name)
        return tuple(result)

    def validate_exports(self, exports: Mapping[str, tuple[str, ...]]) -> None:
        """Fail closed when an export or module lacks explicit dependency coverage."""
        for module, names in exports.items():
            for name in names:
                self.operation(module, name)
            registered = next((x.exports for x in self.operations if x.module == module), ())
            if set(names) != set(registered):
                raise RegistryError("public-manifest-drift")

    def validate_public_sources(self, root: Path) -> None:
        """Development drift check using AST, never import optional public modules."""
        exports = {}
        excluded = {"policy"}
        declared = {operation.module for operation in self.operations}
        for path in root.rglob("*.py"):
            relative = path.relative_to(root)
            module = ".".join((root.name, *relative.with_suffix("").parts))
            if excluded.intersection(relative.parts) or path.name in ("contracts.py", "settings.py"):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8-sig"))
            # Dependency implementation modules explicitly declare an empty
            # public surface. Their directory is not a census exemption: a
            # future named export, new public module, or missing declaration
            # must be checked even before it has a manifest registration.
            private_dependency = "dependencies" in relative.parts and path.name.startswith("_")
            private_exports: tuple[str, ...] | None = None
            for node in tree.body:
                if (
                    isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                    and node.target.id == "__all__" and node.value is not None
                ):
                    value = ast.literal_eval(node.value)
                    if type(value) is not tuple:
                        raise RegistryError("public-manifest-drift")
                    private_exports = _strings(list(value))
            if private_dependency and private_exports == () and module not in declared:
                continue
            names = tuple(
                node.name for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and not node.name.startswith("_")
            )
            if private_exports:
                names = tuple(dict.fromkeys((*names, *private_exports)))
            for node in tree.body:
                if (
                    isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets)
                ):
                    exported = ast.literal_eval(node.value)
                    names = tuple(dict.fromkeys((*names, *_strings(exported))))
            if names:
                module = ".".join((root.name, *relative.with_suffix("").parts))
                exports[module] = names
                imported = {}
                for node in tree.body:
                    if not isinstance(node, ast.ImportFrom):
                        continue
                    parts = module.split(".")[:-1]
                    source = ".".join(
                        parts[:len(parts) - node.level + 1]
                        + ([node.module] if node.module else [])
                    ) if node.level else (node.module or "")
                    if source not in {x.module for x in self.operations}:
                        source += ".__init__"
                    for alias in node.names:
                        target = next((x for x in self.operations if x.module == source), None)
                        if target is not None and alias.name in target.exports:
                            imported[alias.asname or alias.name] = source + ":" + alias.name
                expected_aliases = {name: imported[name] for name in names if name in imported}
                operation = next((x for x in self.operations if x.module == module), None)
                if operation is not None and dict(operation.aliases) != expected_aliases:
                    raise RegistryError("public-alias-drift")
                actions = tuple(
                    node.name + "." + child.name for node in tree.body
                    if isinstance(node, ast.ClassDef) for child in node.body
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and child.name.startswith("action_")
                )
                registered = next((x.ui_actions for x in self.operations if x.module == module), ())
                if set(actions) != set(registered):
                    raise RegistryError("public-ui-action-drift")
        modules = {operation.module for operation in self.operations
                   if operation.module.startswith(root.name + ".")}
        if set(exports) != modules:
            raise RegistryError("public-manifest-drift")
        self.validate_exports(exports)

    def is_qualified(self, exact_tuple: Mapping[str, object]) -> bool:
        """Empty evidence means unqualified; version ranges and mocks never certify."""
        return False

    def validate_package_metadata(self, project_text: str) -> None:
        """Parse project TOML/PEP 508, rejecting missing pip and all Galaxy declarations."""
        try:
            from packaging.requirements import InvalidRequirement, Requirement
            from packaging.specifiers import SpecifierSet
            from packaging.utils import canonicalize_name

            if sys.version_info >= (3, 11):
                import tomllib
            else:
                import tomli as tomllib
        except ImportError:
            raise RegistryError("package-metadata-parser-unavailable") from None
        try:
            project = tomllib.loads(project_text)["project"]
            groups = {"base": project["dependencies"]}
            groups.update(
                ("extra:" + name, values)
                for name, values in project["optional-dependencies"].items()
            )
            if any(not isinstance(group, list) for group in groups.values()):
                raise RegistryError("package-metadata-drift")
            declared = []
            by_group: dict[str, list[Requirement]] = {}
            for group_name, group in groups.items():
                by_group[group_name] = []
                for text in group:
                    if not isinstance(text, str):
                        raise RegistryError("package-metadata-drift")
                    requirement = Requirement(text)
                    declared.append(requirement)
                    by_group[group_name].append(requirement)
        except (ValueError, KeyError, TypeError, AttributeError, InvalidRequirement):
            raise RegistryError("package-metadata-drift") from None
        galaxy = {canonicalize_name(entry.id) for entry in self.entries if entry.kind == "galaxy"}
        if any(canonicalize_name(requirement.name) in galaxy for requirement in declared):
            raise RegistryError("package-metadata-drift")
        for group_name, dependencies in self.package_requirements:
            for dependency in dependencies:
                entry = self.entry(dependency)
                name = canonicalize_name(entry.source.removeprefix("pypi:"))
                if not any(
                    canonicalize_name(requirement.name) == name and requirement.marker is None
                    for requirement in by_group.get(group_name, [])
                ):
                    raise RegistryError("package-metadata-drift")
        for entry in self.entries:
            if (
                entry.kind != "pip" or not entry.source.startswith("pypi:")
                or not entry.version.startswith((">=", "<", "=="))
            ):
                continue
            name = canonicalize_name(entry.source.removeprefix("pypi:"))
            matches = [item for item in declared if canonicalize_name(item.name) == name]
            if (
                not any(item.marker is None for item in matches)
                or any(item.url is not None or item.specifier != SpecifierSet(entry.version) for item in matches)
            ):
                raise RegistryError("package-metadata-drift")

    def documentation(self) -> str:
        """Render deterministic help/docs directly from the catalog authority."""
        lines = ["| Dependency | Context | Source | Range | Consumers |",
                 "| --- | --- | --- | --- | --- |"]
        lines.extend(
            f"| {x.id} | {x.context} | {x.source} | {x.version} | {', '.join(x.consumers)} |"
            for x in self.entries
        )
        lines.extend([
            "", f"Registry/manifest digest: `{self.digest}`.", "",
            "Exact export and reduced-mode requirements (native Python baseline also applies):", "",
            "| Selector | Dependencies |",
            "| --- | --- |",
        ])
        for operation in self.operations:
            lines.extend(
                f"| {operation.module}:{export} | {', '.join(deps) or 'stdlib only'} |"
                for export, deps in operation.export_dependencies
            )
            lines.extend(
                f"| {operation.capability}:{variant} | {', '.join(deps) or 'stdlib only'} |"
                for variant, deps in operation.variants
            )
        lines.extend([
            "", "Canonical public aliases (capability, tier and intents are inherited):", "",
            "| Selector | Canonical selector |", "| --- | --- |",
        ])
        lines.extend(
            f"| {operation.module}:{export} | {target} |"
            for operation in self.operations for export, target in operation.aliases
        )
        lines.extend([
            "", "Required pip metadata by consuming package group:", "",
            "| Group | Registry dependencies |",
            "| --- | --- |",
        ])
        lines.extend(
            f"| {group} | {', '.join(dependencies)} |"
            for group, dependencies in self.package_requirements
        )
        return "\n".join(lines)


class DependencyService:
    """Read-only dependency planning plus explicitly consented owned lifecycle entry."""

    def __init__(
        self, registry: DependencyRegistry, adapters: Mapping[str, DependencyAdapter],
        state: OwnedStatePort | OwnedLifecycleState | ManagedLifecycleState, policy: LocalPolicyPort, authorization: AuthorizationBroker,
        clock: ClockPort, events: EventPort,
    ) -> None:
        self.registry = registry
        self.adapters = dict(adapters)
        if not ADAPTERS <= self.adapters.keys():
            raise RegistryError("adapter-missing")
        self.state, self.policy, self.authorization = state, policy, authorization
        self.clock, self.events = clock, events
        self._policy_identity = _packaged_identity()
        self._observed: dict[tuple[str, str, str], ProbeResult] = {}
        self._lifecycle = DependencyLifecycle(self)

    def provision(
        self, plan: InstallPlan,
        consent: lifecycle_contracts.InstallConsent, cancel: CancelPort,
    ) -> InstallOutcome:
        """Admit a concrete lifecycle plan, not a catalog preview or asserted boolean."""
        received: object = plan
        if type(received) is InstallPlan:
            closed = self._executable(received)
            return self._lifecycle.execute(closed, consent, cancel)
        # Retain the previous inert-host compatibility entry, not a way to turn
        # an incomplete public plan into a caller-built executable plan.
        if (
            type(self.state) is not OwnedLifecycleState
            or type(received) is not lifecycle_contracts.InstallPlan
        ):
            raise ContractError()
        return self._lifecycle.execute(received, consent, cancel)

    def _executable(self, plan: InstallPlan) -> lifecycle_contracts.InstallPlan:
        if (
            type(plan) is not InstallPlan or plan.lifecycle is None or plan.blocked
            or type(self.state) is not ManagedLifecycleState
            or plan.registry_digest != self.registry.digest
            or plan.policy_identity != self._policy_identity
        ):
            raise ContractError()
        self.state.validate_public(plan, self)
        return plan.lifecycle

    def review(
        self, plan: InstallPlan, now: float, lifetime: float,
    ) -> lifecycle_contracts.InstallConsent:
        """Review the exact public plan through the host's private one-use adapter.

        This adds no serialized grant and never reconstructs an effect plan.
        Blocked asset dispositions cannot reach the prompt or any handler.
        """
        closed = self._executable(plan)
        broker = self.authorization
        if type(broker) is not PrivateBroker:
            raise ContractError()
        adapter = broker._lifecycle_consent
        if adapter is None:
            raise ContractError()
        return adapter.review(closed, now, lifetime)

    def resume(
        self, install_id: str, consent: lifecycle_contracts.InstallConsent, cancel: CancelPort,
    ) -> InstallOutcome:
        """Resume only through fresh exact consent and current consuming-context probes."""
        if type(self.state) is ManagedLifecycleState:
            return self.state.resume(install_id, consent, cancel, self)
        return self._lifecycle.resume(install_id, consent, cancel)

    def uninstall(
        self, plan: lifecycle_contracts.UninstallPlan, consent: lifecycle_contracts.InstallConsent,
    ) -> InstallOutcome:
        """Remove only selected manifest-owned resources through lifecycle admission."""
        if type(plan) is not lifecycle_contracts.UninstallPlan:
            raise ContractError()
        return self._lifecycle.execute(plan, consent, _NeverCancelled())

    def plan_restore(
        self, generation_id: str, context: InstallContext,
    ) -> lifecycle_contracts.RestorePlan:
        """Build a bounded read-only exact retained-generation pointer plan."""
        return self._lifecycle.plan_restore(generation_id, context)

    def plan_uninstall(
        self, generation_id: str, context: InstallContext,
    ) -> lifecycle_contracts.UninstallPlan:
        """Describe exact inactive owned cleanup; active generations require qualified restore first."""
        if type(self.state) is not ManagedLifecycleState:
            raise ContractError()
        return self.state.plan_uninstall(generation_id, context, self)

    def restore(
        self, plan: lifecycle_contracts.RestorePlan, consent: lifecycle_contracts.InstallConsent,
        cancel: CancelPort,
    ) -> InstallOutcome:
        """Restore the reviewed pointer only, never redeploy or undo devices."""
        if type(plan) is not lifecycle_contracts.RestorePlan:
            raise ContractError()
        return self._lifecycle.execute(plan, consent, cancel)

    def catalog(self) -> DependencyCatalog:
        """Return immutable metadata without probing, unlocking or contacting a service."""
        return DependencyCatalog(
            self.registry.revision, self.registry.digest, self.registry.entries,
            self.registry.operations, self.registry.native_baseline,
        )

    def _selection(self, scope: InstallScope) -> tuple[PublicOperation, ...]:
        names = set(scope.native_capabilities + scope.companions)
        known = {x.capability for x in self.registry.operations}
        known.update(
            x.capability + ":" + intent for x in self.registry.operations for intent, _ in x.intents
        )
        known.update(
            x.capability + ":" + variant for x in self.registry.operations for variant, _ in x.variants
        )
        known.update(
            x.module + ":" + export for x in self.registry.operations for export in x.exports
        )
        if not names <= known:
            raise RegistryError("capability-unknown")
        selected = [
            x for x in self.registry.operations
            if (scope.full_toolkit and x.tier != "enhanced")
            or x.capability in names
            or any(x.capability + ":" + intent in names for intent, _ in x.intents)
            or any(x.capability + ":" + variant in names for variant, _ in x.variants)
            or (scope.enhanced and x.tier == "enhanced")
        ]
        selected_modules = {item.module for item in selected}
        selected.extend(
            replace(self.registry.operation(operation.module, export), exports=(export,))
            for operation in self.registry.operations for export in operation.exports
            if operation.module + ":" + export in names
            and operation.module not in selected_modules
        )
        if not selected:
            raise RegistryError("scope-empty")
        return tuple(selected)

    @staticmethod
    def _requirements(operation: PublicOperation, scope: InstallScope) -> set[str]:
        """Share exact consuming-operation selection between plan and readiness."""
        names = set(scope.native_capabilities + scope.companions)
        needed: set[str] = set()
        if (
            scope.full_toolkit or operation.capability in names
            or (scope.enhanced and operation.tier == "enhanced")
        ):
            needed.update(operation.dependencies)
        if scope.full_toolkit:
            for _, deps in (*operation.export_dependencies, *operation.variants):
                needed.update(deps)
        for intent, deps in operation.intents:
            if scope.full_toolkit or operation.capability + ":" + intent in names:
                needed.update(operation.dependencies)
                needed.update(deps)
        for variant, deps in operation.variants:
            if operation.capability + ":" + variant in names:
                needed.update(deps)
        exports = dict(operation.export_dependencies)
        for export in operation.exports:
            if operation.module + ":" + export in names:
                needed.update(exports.get(export, operation.dependencies))
        return needed

    def _contexts(self) -> Mapping[str, ConsumingContext]:
        contexts: dict[str, ConsumingContext] = {}
        for adapter in self.adapters.values():
            values = getattr(adapter, "contexts", {})
            for name, context in values.items():
                if name in contexts and contexts[name] != context:
                    raise RegistryError("context-conflict")
                contexts[name] = context
        return contexts

    def _entries(self, operations: tuple[PublicOperation, ...], scope: InstallScope) -> tuple[DependencyEntry, ...]:
        needed: set[str] = set()
        if any(x.tier == "native" for x in operations):
            needed.update(self.registry.native_baseline)
        for operation in operations:
            needed.update(self._requirements(operation, scope))
        return self.registry.ordered(tuple(x.id for x in self.registry.entries if x.id in needed))

    def plan(self, scope: InstallScope, context: InstallContext) -> InstallPlan:
        """Describe exact scope and effects without any probe, state write or installer."""
        self._lifecycle.remember_context(context)
        preview = self._catalog_plan(scope, context)
        if type(self.state) is ManagedLifecycleState:
            result = self.state.compose(preview, scope, self._entries(self._selection(scope), scope), self)
            return replace(result, digest=public_digest(replace(result, digest="")))
        return replace(preview, blocked=tuple(step.dependency for step in preview.steps))

    def _catalog_plan(
        self, scope: InstallScope, context: InstallContext, plan_id: str | None = None,
    ) -> InstallPlan:
        """Share the exact I01 descriptive closure with executable-plan validation."""
        operations = self._selection(scope)
        contexts = self._contexts()
        bindings = tuple(sorted(x.digest for x in contexts.values()))
        entries = self._entries(operations, scope)
        binding = _digest(asdict(context))
        steps = tuple(
            InstallStep(
                x.id, x.context, x.ownership, x.source, x.digest, x.size,
                "external:observe-only" if x.ownership == "external-observe-only" else f"owned:{x.context}/{x.id}",
                "verified-reuse" if (
                    x.context in contexts
                    and (x.id, contexts[x.context].digest, binding) in self._observed
                    and self._observed[x.id, contexts[x.context].digest, binding].status == "available"
                    and context.context.registry_digest == self.registry.digest
                    and context.context.policy_identity == self._policy_identity
                ) else "reprobe-required",
                x.effects, tuple(e for e in x.effects if e in (
                    "elevation", "wsl", "vm", "reboot", "runtime", "security",
                )), x.recovery,
            ) for x in entries
        )
        identity = context.context.policy_identity
        plan_id = plan_id or str(uuid4())
        digest = _digest({
            "id": plan_id, "scope": asdict(scope), "context": asdict(context),
            "registry": self.registry.digest, "consuming": bindings,
            "steps": [asdict(step) for step in steps],
        })
        return InstallPlan(
            plan_id, digest, context, self.registry.revision, self.registry.digest,
            bindings, identity, steps, "unqualified",
        )

    def verify(self, scope: InstallScope, context: InstallContext) -> ReadinessReport:
        """Probe selected dependencies and project independent factual readiness tiers."""
        operations = self._selection(scope)
        entries = self._entries(operations, scope)
        contexts = self._contexts()
        operation_id = str(uuid4())
        budget_start = self.clock.monotonic()
        if type(budget_start) is not float or not math.isfinite(budget_start) or budget_start < 0:
            raise RegistryError("clock-invalid")
        overall_deadline = budget_start + 60.0
        if not math.isfinite(overall_deadline) or overall_deadline <= budget_start:
            raise RegistryError("clock-invalid")
        last_observed = budget_start

        def sample() -> float:
            nonlocal last_observed
            observed = self.clock.monotonic()
            if type(observed) is not float or not math.isfinite(observed) or observed < last_observed:
                raise RegistryError("clock-invalid")
            last_observed = observed
            return observed

        results: dict[str, ProbeResult] = {}
        for entry in entries:
            consuming = contexts.get(entry.context)
            start = sample()
            deadline = min(start + 5.0, overall_deadline)
            if start >= overall_deadline:
                result = ProbeResult(entry.id, self.registry.digest, "blocked", "deadline-exceeded")
            elif context.context.policy_identity != self._policy_identity:
                result = ProbeResult(entry.id, self.registry.digest, "blocked", "policy-identity-drift")
            elif context.context.registry_digest != self.registry.digest:
                result = ProbeResult(entry.id, self.registry.digest, "blocked", "registry-drift")
            elif consuming is None:
                result = ProbeResult(entry.id, self.registry.digest, "blocked", "context-missing")
            elif entry.context == "controller" and consuming.id != context.context.controller_id:
                result = ProbeResult(entry.id, consuming.digest, "blocked", "controller-drift")
            else:
                token = _PROBE_OBSERVATION_DEFERRED.set(True)
                try:
                    result = self.adapters[entry.adapter].probe(entry, consuming, deadline)
                finally:
                    _PROBE_OBSERVATION_DEFERRED.reset(token)
                # A late successful adapter return is not timely consuming
                # evidence. Never publish or cache it as reusable readiness.
                if sample() >= deadline:
                    result = ProbeResult(entry.id, consuming.digest, "blocked", "deadline-exceeded")
                if result.dependency != entry.id or result.context_digest != consuming.digest:
                    result = ProbeResult(entry.id, consuming.digest, "blocked", "context-drift")
                self._observed[entry.id, consuming.digest, _digest(asdict(context))] = result
            results[entry.id] = result
            duration = sample() - start
            if result.next_action == "inspect-prerequisite" and result.status == "blocked":
                result = replace(result, next_action="verify-consuming-context")
                results[entry.id] = result
            observe_probe(result, entry.context, duration, logging.getLogger(__name__))
            safe_event = SafeEvent(
                operation_id, "dependency.probe", entry.id,
                consuming.id if consuming else entry.context, Mode.CHECK,
                OutcomeStatus.SUCCEEDED if result.status == "available" else OutcomeStatus.BLOCKED,
                None if result.status == "available" else ErrorCategory.DEPENDENCY,
                None if result.status == "available" else ReasonCode.DEPENDENCY_NOT_READY,
                False, duration,
            )
            try:
                self.events.emit(safe_event)
            except Exception:
                pass
        records: list[FrozenObject] = []
        tiers: dict[str, list[str]] = {"native": [], "companion": [], "enhanced": []}
        for operation in operations:
            needed = self._requirements(operation, scope)
            if operation.tier == "native":
                needed.update(self.registry.native_baseline)
            deps = self.registry.ordered(tuple(x.id for x in entries if x.id in needed))
            unavailable = tuple(x.id for x in deps if results[x.id].status != "available")
            qualification = "unqualified" if operation.tier != "native" else "not-required"
            status = "blocked" if unavailable or operation.tier != "native" else "ready"
            tiers[operation.tier].append(status)
            records.append(cast(FrozenObject, freeze({
                "capability": operation.capability, "tier": operation.tier, "status": status,
                "qualification": qualification, "missing": list(unavailable),
                "probes": [asdict(results[x.id]) for x in deps],
                "next_action": "resolve-prerequisites" if unavailable else (
                    "collect-exact-tuple-evidence" if operation.tier != "native" else "none"
                ),
            })))
        projected = {
            tier: "not-requested" if not values else ("ready" if all(x == "ready" for x in values) else "blocked")
            for tier, values in tiers.items()
        }
        # Derived rules receive real observations; a policy result is never qualification.
        context_digest = _digest(asdict(context))
        receipt_digest = _digest([asdict(x) for x in results.values()])
        event = DecisionEvent(
            str(uuid4()), EventKind.DEPENDENCY_OBSERVED, 0,
            self.registry.digest, context_digest,
            self._policy_identity.bundle_sha256,
            "dependencies", "dependency.probe", cast(FrozenObject, freeze({
                "dependency_id": "selected-scope", "context_digest": context_digest,
                "probe_receipt": receipt_digest, "probe_digest": receipt_digest,
                "readiness": "ready" if all(x in ("ready", "not-requested") for x in projected.values()) else "blocked",
            })),
            operation_id=operation_id,
        )
        remaining = overall_deadline - sample()
        facts = DecisionFacts(cast(FrozenObject, freeze({
            "binding": {
                "input_valid": True,
                "plan_current": context.context.registry_digest == self.registry.digest,
                "policy_current": context.context.policy_identity == self._policy_identity,
            },
            "control": {"cancelled": False, "remaining_ms": max(0, int(remaining * 1000))},
            "request": {"area": "setup", "operation": "preflight", "mode": "check"},
            "readiness": {
                **projected,
                "selected_complete": all(
                    x in ("ready", "not-requested") for x in projected.values()
                ),
            },
        })))
        # An exhausted observation budget is a factual non-success, not a
        # malformed contract or permission to call policy with extra time.
        # Actual adapter/policy defects still escape unchanged.
        decision = self.policy.decide(event, facts) if remaining > 0.0 else None
        expired = remaining <= 0.0 or sample() >= overall_deadline
        if expired:
            projected = {
                tier: "not-requested" if not values else "blocked"
                for tier, values in tiers.items()
            }
            records = [cast(FrozenObject, freeze({
                **dict(record), "status": "blocked",
                "reason": "deadline-exceeded", "next_action": "verify-consuming-context",
            })) for record in records]
            for entry in entries:
                consuming = contexts.get(entry.context)
                if consuming is not None:
                    self._observed.pop((entry.id, consuming.digest, context_digest), None)
        records.append(cast(FrozenObject, freeze({
            "policy_decision": decision.decision if decision is not None else "not-requested",
            "policy_digest": decision.policy_digest if decision is not None else self._policy_identity.bundle_sha256,
            **({"reason": "deadline-exceeded"} if expired else {}),
            "consuming_context_digests": sorted(x.digest for x in contexts.values()),
            "qualification_state": "unqualified",
            "qualification_tuple_digest": _digest({
                "contexts": [asdict(x) for x in contexts.values()],
                "versions": {key: value.version for key, value in results.items()},
                "policy": asdict(context.context.policy_identity),
                "assets": context.context.assets_digest, "route": context.context.route_digest,
            }),
        })))
        return ReadinessReport(
            self.registry.revision, context, tuple(records),
            ReadinessProjection(projected["native"], projected["companion"], projected["enhanced"]),
        )
