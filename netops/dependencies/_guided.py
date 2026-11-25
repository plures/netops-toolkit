"""Read-only first-run discovery and resumable selections, never private grants."""

from __future__ import annotations

import base64
import binascii
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from netops.ansible import contracts as c

from ._context_facts import _host_architecture
from .service import ConsumingContext, DependencyService, InstallPlan, ProbeResult, RegistryError

if TYPE_CHECKING:
    from collections.abc import Callable

__all__: tuple[str, ...] = ()
_SCHEMA = "netops-guided-selection-v1"
_MODES = ("reuse", "install", "decline")
_CATEGORIES = ("os", "wsl", "distribution", "vm", "virtualization", "runtime",
               "service", "security", "elevation", "reboot")
_TOKEN_LIMIT = 32768
_BOOTSTRAP = (
    "import sys; sys.path.insert(0,sys.argv.pop(1)); "
    "from netops.setup import main; raise SystemExit(main())"
)


@dataclass(frozen=True)
class _Component:
    dependency: str
    kind: str
    context: str
    version: str
    platforms: tuple[str, ...]
    source: str
    requires: tuple[str, ...]
    observation: ProbeResult | None
    choices: tuple[str, ...]
    default: str


@dataclass(frozen=True)
class _Diagnosis:
    plan: InstallPlan
    readiness: c.ReadinessReport | None
    components: tuple[_Component, ...]


@dataclass(frozen=True)
class _Selection:
    components: tuple[tuple[str, str], ...] = ()
    categories: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        for values, names, modes in (
            (self.components, None, _MODES),
            (self.categories, _CATEGORIES, ("review", "decline")),
        ):
            if type(values) is not tuple or len(values) > 256:
                raise c.ContractError()
            keys = []
            for value in values:
                if type(value) is not tuple or len(value) != 2:
                    raise c.ContractError()
                name, mode = value
                c.text(name)
                if (names is not None and name not in names) or mode not in modes:
                    raise c.ContractError()
                keys.append(name)
            c.unique(tuple(keys))


@dataclass(frozen=True)
class _Need:
    dependency: str
    kind: str
    version: str
    platforms: tuple[str, ...]
    source: str
    fields: tuple[str, ...]
    reason: str
    choices: tuple[str, ...]


def _existing_python() -> str:
    """Locate a pin candidate without treating a Store launch alias as file bytes."""
    if sys.prefix != sys.base_prefix:
        return sys.executable
    if os.name == "nt":
        return str(Path(sys.base_prefix) / "python.exe")
    return str(Path(sys.executable).resolve())


def _existing_contexts() -> dict[str, ConsumingContext]:
    """Observe only the already selected host; never discover by launching WSL."""
    native = ConsumingContext(
        "source-existing-native", sys.platform, _host_architecture(),
        sys.executable, os.environ.get("PATH", ""), "native",
    )
    contexts = {"native": native}
    if sys.platform in ("linux", "darwin"):
        contexts["controller"] = ConsumingContext(
            "source-guided-setup", native.platform, native.architecture,
            native.python, native.path, "controller",
        )
    return contexts


def _diagnose(
    service: DependencyService, scope: c.InstallScope, context: c.InstallContext,
    *, probe: bool,
) -> _Diagnosis:
    """Use the public resolver and verifier, including all future registered kinds."""
    plan = service.plan(scope, context)
    exhausted = False
    try:
        readiness = service.verify(scope, context) if probe else None
    except RegistryError as error:
        if str(error) != "deadline-exceeded":
            raise
        # A failed aggregate observation is not a partial ready receipt. Keep
        # every selected key actionable without renewing the verifier's budget.
        readiness, exhausted = None, True
    observations: dict[str, ProbeResult] = {}
    if readiness is not None:
        exhausted = any(capability.get("reason") == "deadline-exceeded"
                        for capability in readiness.capabilities)
        for capability in readiness.capabilities:
            if "capability" not in capability:
                continue
            values = capability["probes"]
            if type(values) is not tuple:
                raise c.ContractError()
            for value in values:
                observed = ProbeResult(**cast(dict, dict(c.public_object(value))))
                if observed.dependency in observations and observations[observed.dependency] != observed:
                    raise c.ContractError()
                observations[observed.dependency] = observed
    components = []
    for step in plan.steps:
        entry = service.registry.entry(step.dependency)
        observation = ProbeResult(
            entry.id, service.registry.digest, "blocked", "diagnosis-budget-exhausted",
            next_action="retry-bounded-diagnosis",
        ) if exhausted else observations.get(entry.id)
        if probe and observation is None:
            raise c.ContractError()
        available = observation is not None and observation.status == "available"
        components.append(_Component(
            entry.id, entry.kind, entry.context, entry.version, entry.platforms, entry.source,
            entry.requires, observation, _MODES if available else ("install", "decline"),
            "reuse" if available else "decline",
        ))
    return _Diagnosis(plan, readiness, tuple(components))


def _ask(ask: Callable[[str], str], prompt: str, default: str) -> str:
    try:
        answer = ask(prompt).strip().lower()
    except (EOFError, OSError):
        return default
    return answer or default


def _choose(
    diagnosis: _Diagnosis, previous: _Selection,
    ask: Callable[[str], str], display: Callable[[str], None],
) -> _Selection:
    """Record requests only. Neither 'install' nor 'review' is effect consent."""
    known = {component.dependency for component in diagnosis.components}
    if not {name for name, _ in previous.components} <= known:
        raise c.ContractError()
    saved = dict(previous.components)
    choices = []
    for component in diagnosis.components:
        observed = component.observation
        display(
            f"Discovery {component.dependency}: "
            f"{observed.status if observed else 'not-probed'}/"
            f"{observed.reason if observed else 'pure-plan'}; "
            f"requires {component.version}; source={component.source}; "
            f"safe destination=user-local; Reuse requires compatible consuming evidence."
        )
        default = saved.get(component.dependency, component.default)
        # A saved choice never supplies stale reuse evidence.
        if default not in component.choices:
            default = "decline"
        choice = _ask(
            ask, f"{component.dependency} Reuse/Install/Decline "
            f"(available: {','.join(component.choices)}; default {default}): ", default,
        )
        if choice not in component.choices:
            choice = "decline"
        choices.append((component.dependency, choice))
    categories = []
    if any(mode == "install" for _, mode in choices):
        saved_categories = dict(previous.categories)
        display(
            "Consequential groups below are prospective requests, NOT grants. "
            "No OS, WSL, distro, VM, virtualization, runtime, service, security, "
            "elevation or reboot effect is authorized by this selection."
        )
        for category in _CATEGORIES:
            default = saved_categories.get(category, "decline")
            choice = _ask(
                ask, f"{category}: request separate exact plan review or decline "
                f"[review/decline; default {default}]: ", default,
            )
            categories.append((category, choice if choice == "review" else "decline"))
    return _Selection(tuple(choices), tuple(categories))


def _needs(diagnosis: _Diagnosis, selection: _Selection) -> tuple[_Need, ...]:
    """Describe every unresolved selected component, not a truncated repair hint."""
    choices = dict(selection.components)
    declined = {name for name, mode in selection.components if mode == "decline"}
    blocked = set(declined)
    for component in diagnosis.components:
        if any(edge in blocked for edge in component.requires):
            blocked.add(component.dependency)
    needs = []
    for component in diagnosis.components:
        mode = choices.get(component.dependency)
        observation = component.observation
        fields: tuple[str, ...]
        if mode == "decline":
            reason, fields = "component-declined", ("component-selection",)
        elif component.dependency in blocked:
            reason, fields = "prerequisite-declined", ("prerequisite-selection",)
        elif mode == "reuse" and (observation is None or observation.status != "available"):
            reason, fields = "compatible-reuse-evidence-required", ("consuming-context",)
        elif observation is not None and observation.reason == "diagnosis-budget-exhausted":
            reason, fields = "fresh-consuming-observation-required", ("bounded-retry", "consuming-context")
        elif component.context == "controller" and (
            observation is not None and observation.reason == "context-missing"
        ):
            reason, fields = "controller-context-required", ("platform", "distribution", "interpreter")
        else:
            reason = "verified-metadata-required"
            fields = (
                "compatible-version", "platform", "source-identity", "sha256", "size",
                "exact-members", "transitive-wheel-collection-lock", "provider-handler",
            )
        needs.append(_Need(
            component.dependency, component.kind, component.version, component.platforms,
            component.source, fields, reason, component.choices,
        ))
    return tuple(needs)


def _binding(
    root: Path, scope: c.InstallScope, diagnosis: _Diagnosis,
) -> dict[str, object]:
    return {
        "schema": _SCHEMA, "root": str(root), "scope": c.wire(scope),
        "registry_digest": diagnosis.plan.registry_digest,
        "consuming_contexts": diagnosis.plan.consuming_contexts,
    }


def _checkpoint(
    root: Path, scope: c.InstallScope, diagnosis: _Diagnosis, selection: _Selection,
) -> str:
    content = c.canonical_bytes(c.public_object({
        **_binding(root, scope, diagnosis), "selection": c.wire(selection),
    }))
    token = base64.urlsafe_b64encode(content).decode("ascii").rstrip("=")
    if len(token) > _TOKEN_LIMIT:
        raise c.ContractError()
    return token


def _resume_selection(
    token: str | None, root: Path, scope: c.InstallScope, diagnosis: _Diagnosis,
) -> _Selection:
    """Restore a portable selection, never an owned recovery checkpoint."""
    if token is None:
        return _Selection()
    if type(token) is not str or not 1 <= len(token) <= _TOKEN_LIMIT:
        raise c.ContractError()
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        value = json.loads(raw)
        if type(value) is not dict or set(value) != {*_binding(root, scope, diagnosis), "selection"}:
            raise c.ContractError()
        if {key: value[key] for key in value if key != "selection"} != json.loads(
            c.canonical_bytes(c.public_object(_binding(root, scope, diagnosis))),
        ):
            raise c.ContractError()
        selected = value["selection"]
        if type(selected) is not dict or set(selected) != {"components", "categories"}:
            raise c.ContractError()
        selection = _Selection(
            tuple(tuple(item) for item in selected["components"]),
            tuple(tuple(item) for item in selected["categories"]),
        )
        if _checkpoint(root, scope, diagnosis, selection) != token:
            raise c.ContractError()
        known = {component.dependency for component in diagnosis.components}
        if not {name for name, _ in selection.components} <= known:
            raise c.ContractError()
        return selection
    except (ValueError, KeyError, TypeError, binascii.Error, RecursionError):
        raise c.ContractError() from None


def _report(
    root: Path, scope: c.InstallScope, diagnosis: _Diagnosis, selection: _Selection,
    needs: tuple[_Need, ...], *, preview: bool,
) -> c.FrozenObject:
    checkpoint = _checkpoint(root, scope, diagnosis, selection)
    command = [
        sys.executable, "-I", "-B", "-c", _BOOTSTRAP,
        str(Path(__file__).resolve().parents[2]), "install", "--root", str(root),
    ]
    for capability in scope.native_capabilities:
        command.extend(("--capability", capability))
    for companion in scope.companions:
        command.extend(("--companion", companion))
    if scope.enhanced:
        command.append("--enhanced")
    command.extend(("--checkpoint", checkpoint))
    return c.public_object({
        "schema": _SCHEMA, "status": "Planned" if preview else "NeedsInput",
        "host_platform": sys.platform, "host_architecture": _host_architecture(),
        "scope": c.wire(scope), "registry_digest": diagnosis.plan.registry_digest,
        "closure": tuple(c.wire(component) for component in diagnosis.components),
        "readiness": c.wire(diagnosis.readiness) if diagnosis.readiness is not None else None,
        "selection": c.wire(selection), "needs": tuple(c.wire(need) for need in needs),
        "checkpoint": checkpoint, "next_command": command,
        "effects_performed": (), "consent_issued": False,
    })
