"""Registry-driven full-family metadata projection for the existing guided route."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from netops.ansible import contracts as c

from ._family_lock import (
    _FamilyLock,
    _FamilyResolver,
    _RegisteredSource,
    _Requirement,
    _Target,
)
from ._guided import _Diagnosis, _Need, _needs, _Selection
from .service import DependencyEntry, DependencyRegistry

if TYPE_CHECKING:
    from ._family_source import _FamilyContributions

__all__: tuple[str, ...] = ()
_KINDS = {
    "python": "python", "pip": "wheel", "executable": "executable",
    "galaxy": "collection", "library": "library", "runtime": "runtime",
    "image": "image", "platform": "os-feature", "service": "service",
    "os-feature": "os-feature", "distribution": "distribution",
}


def _requirement(entry: DependencyEntry) -> _Requirement:
    family = _KINDS.get(entry.kind)
    if family is None:
        raise c.ContractError()
    name = entry.id
    source = entry.source
    if entry.source.startswith("pypi:"):
        # Executable launchers produced by a wheel share that exact package
        # lock. They still remain separate selected consumer observations.
        family, name = "wheel", entry.source[len("pypi:"):]
        name = name.lower().replace("_", "-").replace(".", "-")
        source = "pypi:" + name
    elif entry.source.startswith("galaxy:"):
        name = entry.source[len("galaxy:"):]
    version = entry.version
    if version in (
        "qualification-required", "functional-probe", "functional-render",
        "exact-digest-required", "actual-grant-receipt-required",
    ):
        version = ""
    elif not version.startswith(("=", ">", "<", "!", "~")):
        version = "==" + version
    return _Requirement(
        name, family, source, entry.context, version,
        ("python",) if source == "pypi:mkdocstrings" else (),
    )


@dataclass(frozen=True)
class _FamilyPlanning:
    """Trusted metadata ports only, never a descriptor, grant or readiness claim."""

    sources: tuple[_RegisteredSource, ...]
    targets: tuple[_Target, ...]

    def __post_init__(self) -> None:
        _FamilyResolver(self.sources)
        if type(self.targets) is not tuple or not self.targets or len(self.targets) > 2:
            raise c.ContractError()
        for target in self.targets:
            if type(target) is not _Target:
                raise c.ContractError()
            target.__post_init__()
        c.unique(tuple(target.context for target in self.targets))

    def resolve(
        self, diagnosis: _Diagnosis, selection: _Selection, registry: DependencyRegistry,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
        *, additional_roots: tuple[_Requirement, ...] = (),
    ) -> tuple[_FamilyLock | None, tuple[_Need, ...]]:
        """Retain every selected consumer and every discovered transitive requirement."""
        lock, needs, _ = self._resolve(
            diagnosis, selection, registry, clock, cancel, deadline,
            additional_roots=additional_roots,
        )
        return lock, needs

    def _resolve(
        self, diagnosis: _Diagnosis, selection: _Selection, registry: DependencyRegistry,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
        *, additional_roots: tuple[_Requirement, ...] = (),
    ) -> tuple[_FamilyLock | None, tuple[_Need, ...], _FamilyContributions | None]:
        """Retain the real resolver's private issuance alongside its factual lock."""
        self.__post_init__()
        needs = _needs(diagnosis, selection)
        expected = tuple(component.dependency for component in diagnosis.components)
        if set(dict(selection.components)) != set(expected):
            return None, needs, None
        stopped = (
            "component-declined", "prerequisite-declined",
            "compatible-reuse-evidence-required", "fresh-consuming-observation-required",
        )
        if any(need.reason in stopped for need in needs):
            return None, needs, None
        if diagnosis.plan.registry_digest != registry.digest:
            raise c.ContractError()
        roots: list[_Requirement] = []
        aliases: dict[tuple[str, str, str], list[_Need]] = {}
        for component, need in zip(diagnosis.components, needs):
            entry = registry.entry(component.dependency)
            requirement = _requirement(entry)
            if requirement not in roots:
                roots.append(requirement)
            aliases.setdefault(requirement.key, []).append(need)
        if not roots:
            raise c.ContractError()
        if type(additional_roots) is not tuple:
            raise c.ContractError()
        from ._lock_layout import _selected_toolkit_roots, _toolkit_requirement

        selected_toolkit = _selected_toolkit_roots(
            tuple(registry.entry(component.dependency) for component in diagnosis.components),
            registry,
        )
        if additional_roots not in ((), (_toolkit_requirement(),), selected_toolkit):
            raise c.ContractError()
        roots.extend(requirement for requirement in additional_roots if requirement not in roots)
        result = _FamilyResolver(self.sources).resolve(
            tuple(roots), self.targets, registry.digest, clock, cancel, deadline,
        )
        if result.lock is not None:
            return result.lock, (), result.contributions
        missing: list[_Need] = []
        for unresolved in result.needs:
            consumers = aliases.get(unresolved.requirement.key)
            if consumers is not None:
                missing.extend(replace(
                    consumer, reason=unresolved.reason, fields=unresolved.fields,
                ) for consumer in consumers)
            else:
                target = next(
                    (item for item in self.targets if item.context == unresolved.requirement.context),
                    None,
                )
                missing.append(_Need(
                    unresolved.requirement.context + ":" + unresolved.requirement.name,
                    unresolved.requirement.family, unresolved.requirement.version,
                    (target.platform,) if target is not None else (),
                    unresolved.requirement.source, unresolved.fields, unresolved.reason,
                    ("install", "decline"),
                ))
        return None, tuple(missing), None
