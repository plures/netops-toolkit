"""Compatible, immutable full-family locks from trusted publisher observations.

This is a private host port, not a descriptor loader or a new trusted-local source.
Reading metadata never authorizes acquisition, execution or platform qualification.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from netops.ansible import contracts as c

from ._assets import LockedAsset, _origin
from ._managed import ManagedMember

if TYPE_CHECKING:
    from ._family_source import _FamilyContributions, _IssuedContribution

__all__: tuple[str, ...] = ()

_FAMILIES = (
    "python", "wheel", "executable", "collection", "library", "runtime",
    "image", "service", "os-feature", "distribution",
)
_FORMATS = {
    "python": ("zip", "tar.gz", "host-package"),
    "wheel": ("wheel",),
    "executable": ("zip", "tar.gz", "host-package"),
    "collection": ("collection.tar.gz",),
    "library": ("zip", "tar.gz", "host-package"),
    "runtime": ("zip", "tar.gz", "host-package"),
    "image": ("oci-manifest", "oci-archive"),
    "service": ("host-service",),
    "os-feature": ("host-feature",),
    "distribution": ("wsl-rootfs", "vm-image"),
}
_SCOPES = (
    "os", "wsl", "distribution", "vm", "virtualization", "runtime",
    "image", "service", "security", "elevation", "reboot",
)
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,159}\Z")
_MAX_NODES = 256
_MAX_SEARCH = 4096
_LOG = logging.getLogger(__name__)


def _artifact_identity(asset: LockedAsset) -> tuple[str, str, str, int]:
    """Retain one publisher-byte identity across independently locked roles."""
    if type(asset) is not LockedAsset:
        raise c.ContractError()
    asset.__post_init__()
    return asset.source_id, asset.url, asset.sha256, asset.size


def _contributions(releases: tuple[_Release, ...]) -> tuple[_Release, ...]:
    """Deduplicate bytes only when format, family, version and members agree."""
    selected: dict[tuple[str, str, str, int], _Release] = {}
    for release in releases:
        if release.artifact is None:
            continue
        key = _artifact_identity(release.artifact)
        previous = selected.get(key)
        if previous is not None and (
            previous.members != release.members or previous.format != release.format
            or previous.version != release.version
            or previous.requirement.family != release.requirement.family
        ):
            raise c.ContractError()
        selected.setdefault(key, release)
    return tuple(selected.values())


def _trace(stage: str, family: str, status: str) -> None:
    """Keep boundary telemetry non-authoritative and free of publisher/host content."""
    try:
        _LOG.debug(
            "dependency.family.boundary",
            extra={"stage": stage, "step_kind": family, "status": status},
        )
    except BaseException:
        pass


def _name(value: str) -> str:
    if type(value) is not str or _NAME.fullmatch(value) is None:
        raise c.ContractError()
    return value


@dataclass(frozen=True)
class _Target:
    context: str
    platform: str
    architecture: str
    python: str
    abi: str
    wheel_tags: tuple[str, ...]
    context_digest: str

    def __post_init__(self) -> None:
        if self.context not in ("native", "controller"):
            raise c.ContractError()
        for value in (self.platform, self.architecture, self.python, self.abi):
            _name(value)
        c.unique(self.wheel_tags)
        if len(self.wheel_tags) > 1024:
            raise c.ContractError()
        for tag in self.wheel_tags:
            _name(tag)
        c.sha256(self.context_digest)


@dataclass(frozen=True)
class _Requirement:
    name: str
    family: str
    source: str
    context: str
    version: str = ""
    extras: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _name(self.name)
        c.text(self.source)
        if (
            self.family not in _FAMILIES or self.context not in ("native", "controller")
            or type(self.version) is not str or len(self.version) > 256
            or any(ord(char) < 32 for char in self.version)
        ):
            raise c.ContractError()
        if type(self.extras) is not tuple or len(self.extras) > 64:
            raise c.ContractError()
        c.unique(self.extras)
        for extra in self.extras:
            _name(extra)

    @property
    def key(self) -> tuple[str, str, str]:
        return self.context, self.family, self.name


@dataclass(frozen=True)
class _Release:
    """Normalized complete publisher metadata, not caller assertions of origin.

    Sources must normalize active PEP 508 target markers into ``requires`` and
    each declared extra's ``extra_requires``; the independently pinned snapshot
    binds that projection. The resolver, not the source, selects requested extras.
    No credentials, command strings, entry points or environment overrides exist.
    """

    requirement: _Requirement
    version: str
    format: str
    platforms: tuple[str, ...]
    architectures: tuple[str, ...]
    requires: tuple[_Requirement, ...]
    metadata_digest: str
    artifact: LockedAsset | None = None
    python: str = ""
    abis: tuple[str, ...] = ()
    wheel_tags: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    resource: str | None = None
    members: tuple[ManagedMember, ...] = ()
    extra_requires: tuple[tuple[str, tuple[_Requirement, ...]], ...] = ()

    def __post_init__(self) -> None:
        if type(self.requirement) is not _Requirement:
            raise c.ContractError()
        self.requirement.__post_init__()
        _name(self.version)
        c.sha256(self.metadata_digest)
        family = self.requirement.family
        if self.format not in _FORMATS[family]:
            raise c.ContractError()
        for values in (self.platforms, self.architectures, self.abis, self.wheel_tags, self.scopes):
            if type(values) is not tuple or len(values) > 1024:
                raise c.ContractError()
            c.unique(values)
            for value in values:
                _name(value)
        if not self.platforms or not self.architectures or set(self.scopes) - set(_SCOPES):
            raise c.ContractError()
        if type(self.python) is not str or len(self.python) > 256:
            raise c.ContractError()
        if type(self.requires) is not tuple or len(self.requires) > _MAX_NODES:
            raise c.ContractError()
        for requirement in self.requires:
            if type(requirement) is not _Requirement:
                raise c.ContractError()
            requirement.__post_init__()
        c.unique(tuple(c.digest(item) for item in self.requires))
        if type(self.extra_requires) is not tuple or len(self.extra_requires) > 64:
            raise c.ContractError()
        extra_names = []
        for pair in self.extra_requires:
            if type(pair) is not tuple or len(pair) != 2:
                raise c.ContractError()
            name, requirements = pair
            extra_names.append(_name(name))
            if type(requirements) is not tuple or len(requirements) > _MAX_NODES:
                raise c.ContractError()
            for requirement in requirements:
                if type(requirement) is not _Requirement:
                    raise c.ContractError()
                requirement.__post_init__()
        c.unique(tuple(extra_names))
        if self.artifact is not None:
            if type(self.artifact) is not LockedAsset:
                raise c.ContractError()
            self.artifact.__post_init__()
            if self.artifact.dependency != self.requirement.name:
                raise c.ContractError()
        artifact_required = self.format not in ("host-package", "host-service", "host-feature")
        if artifact_required != (self.artifact is not None):
            raise c.ContractError()
        if type(self.members) is not tuple or len(self.members) > 4096:
            raise c.ContractError()
        if self.format in ("zip", "tar.gz", "wheel", "collection.tar.gz", "wsl-rootfs"):
            if not self.members:
                raise c.ContractError()
        elif self.members and self.format not in ("oci-manifest", "oci-archive"):
            raise c.ContractError()
        paths = []
        total = 0
        for member in self.members:
            if type(member) is not ManagedMember:
                raise c.ContractError()
            member.__post_init__()
            paths.append(member.path.casefold())
            total += member.size
        c.unique(tuple(paths))
        if total > 512 * 1024 * 1024:
            raise c.ContractError()
        # An absent official Requires-Python is an unrestricted PEP 440 range.
        # Target wheel tags remain mandatory; no invented Python bound is used.
        if family == "wheel" and not self.wheel_tags:
            raise c.ContractError()
        if family in ("image", "service", "os-feature", "distribution", "runtime"):
            if self.resource is None:
                raise c.ContractError()
            _name(self.resource)
        elif self.resource is not None:
            raise c.ContractError()
        required_scopes = {
            "runtime": {"runtime"}, "image": {"image"}, "service": {"service"},
            "os-feature": {"os"}, "distribution": {"distribution"},
        }.get(family, set())
        if self.format == "host-package":
            required_scopes.add("os")
        if self.format == "wsl-rootfs":
            required_scopes.add("wsl")
        if self.format == "vm-image":
            required_scopes.update(("vm", "virtualization"))
        if not required_scopes <= set(self.scopes):
            raise c.ContractError()
        # A collection's controller/core compatibility is metadata, not an
        # implication of the registry's coarse collection-to-core edge.
        if family == "collection" and not any(
            item.family == "wheel" and item.name == "ansible-core"
            and item.context == self.requirement.context and item.version
            for item in self.requires
        ):
            raise c.ContractError()


@dataclass(frozen=True)
class _PublisherSnapshot:
    """One exact metadata observation made by a registered trusted host source."""

    source: str
    target_digest: str
    releases: tuple[_Release, ...]
    metadata_digest: str
    observed_at: float
    expires_at: float

    def __post_init__(self) -> None:
        c.text(self.source)
        c.sha256(self.target_digest)
        c.sha256(self.metadata_digest)
        if (
            type(self.releases) is not tuple or len(self.releases) > 1024
            or c.finite(self.observed_at) < 0
            or c.finite(self.expires_at) <= self.observed_at
            or self.expires_at - self.observed_at > 300.0
        ):
            raise c.ContractError()
        for release in self.releases:
            if type(release) is not _Release:
                raise c.ContractError()
            release.__post_init__()
            if release.requirement.source != self.source:
                raise c.ContractError()
        c.unique(tuple(c.digest(release) for release in self.releases))


class _MetadataPort(Protocol):
    def observe(
        self, requirement: _Requirement, target: _Target,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _PublisherSnapshot:
        """Return bounded normalized publisher metadata, never acquire artifacts."""
        ...


class _SourceUnavailable(c.ContractError):
    """A closed source could not verify its publisher observation."""


class _CatalogueUnavailable(_SourceUnavailable):
    """No independently retained publisher pins exist; do not contact a source."""

    def __init__(self, fields: tuple[str, ...] = ()) -> None:
        super().__init__()
        if type(fields) is not tuple:
            raise c.ContractError()
        c.unique(fields)
        for name in fields:
            c.text(name)
        self.fields = fields


@dataclass(frozen=True)
class _RegisteredSource:
    """Trusted constructor wiring; neither a URL nor a digest establishes trust.

    ``metadata_digest`` is independently retained by the supplying host, not
    copied from the candidate it is checking. Source implementations must bind
    their normalized release set to that exact publisher observation.
    """

    source: str
    families: tuple[str, ...]
    origins: tuple[str, ...]
    metadata_digest: str
    port: _MetadataPort

    def __post_init__(self) -> None:
        c.text(self.source)
        c.sha256(self.metadata_digest)
        c.unique(self.families)
        c.unique(self.origins)
        if not self.families or set(self.families) - set(_FAMILIES):
            raise c.ContractError()
        for origin in self.origins:
            if _origin("https://" + origin + "/") != origin:
                raise c.ContractError()
        # Preserve the existing publisher-family limits, even for an injected
        # host source. No source registration turns local paths into publishers.
        fixed = (
            ("files.pythonhosted.org",) if self.source.startswith("pypi:")
            else ("galaxy.ansible.com",) if self.source.startswith("galaxy:")
            else ("www.python.org",) if self.source == "python.org" else None
        )
        if fixed is not None and self.origins != fixed:
            raise c.ContractError()
        if not callable(getattr(self.port, "observe", None)):
            raise c.ContractError()


@dataclass(frozen=True)
class _Missing:
    requirement: _Requirement
    reason: str
    fields: tuple[str, ...]


@dataclass(frozen=True)
class _FamilyLock:
    """The entire selected and transitive closure, ordered prerequisites first."""

    roots: tuple[_Requirement, ...]
    targets: tuple[_Target, ...]
    releases: tuple[_Release, ...]
    observations: tuple[_PublisherSnapshot, ...]
    registry_digest: str
    selected_extras: tuple[tuple[tuple[str, str, str], tuple[str, ...]], ...] = ()

    def __post_init__(self) -> None:
        c.sha256(self.registry_digest)
        if (
            type(self.roots) is not tuple or not self.roots
            or type(self.targets) is not tuple or not self.targets
            or type(self.releases) is not tuple or not self.releases
            or len(self.releases) > _MAX_NODES
            or type(self.observations) is not tuple or not self.observations
        ):
            raise c.ContractError()
        targets = {target.context: target for target in self.targets}
        c.unique(tuple(target.context for target in self.targets))
        for selected_target in self.targets:
            if type(selected_target) is not _Target:
                raise c.ContractError()
            selected_target.__post_init__()
        observations = {}
        for selected_observation in self.observations:
            if type(selected_observation) is not _PublisherSnapshot:
                raise c.ContractError()
            selected_observation.__post_init__()
            key = selected_observation.source, selected_observation.target_digest
            if key in observations:
                raise c.ContractError()
            observations[key] = selected_observation
        selected: dict[tuple[str, str, str], _Release] = {}
        if type(self.selected_extras) is not tuple:
            raise c.ContractError()
        extras = dict(self.selected_extras)
        if len(extras) != len(self.selected_extras):
            raise c.ContractError()
        members: dict[tuple[str, str, str], ManagedMember] = {}
        total_size = 0
        for release in self.releases:
            if type(release) is not _Release:
                raise c.ContractError()
            release.__post_init__()
            target = targets.get(release.requirement.context)
            observation = observations.get((
                release.requirement.source, c.digest(target),
            ))
            if (
                target is None or observation is None or release not in observation.releases
                or release.requirement.key in selected or not _compatible(release, target)
            ):
                raise c.ContractError()
            names = extras.get(release.requirement.key, ())
            if type(names) is not tuple:
                raise c.ContractError()
            c.unique(names)
            extra_requires = dict(release.extra_requires)
            if not set(names) <= set(extra_requires):
                raise c.ContractError()
            dependencies = (
                *release.requires, *(edge for name in names for edge in extra_requires[name]),
            )
            for requirement in dependencies:
                dependency = selected.get(requirement.key)
                if (
                    dependency is None or dependency.requirement.source != requirement.source
                    or not _matches(dependency.version, requirement.version)
                    or not set(requirement.extras) <= set(extras.get(requirement.key, ()))
                ):
                    raise c.ContractError()
            if release.artifact is not None:
                total_size += release.artifact.size
            for member in release.members:
                member_key = (
                    release.requirement.context, release.requirement.family, member.path.casefold(),
                )
                previous = members.get(member_key)
                if previous is not None and previous != member:
                    raise c.ContractError()
                members[member_key] = member
            selected[release.requirement.key] = release
        if total_size > 512 * 1024 * 1024 or len(members) > 4096:
            raise c.ContractError()
        reachable: set[tuple[str, str, str]] = set()
        wanted_extras: dict[tuple[str, str, str], set[str]] = {}

        def visit(requirement: _Requirement) -> None:
            if type(requirement) is not _Requirement:
                raise c.ContractError()
            requirement.__post_init__()
            release = selected.get(requirement.key)
            if (
                release is None or release.requirement.source != requirement.source
                or not _matches(release.version, requirement.version)
            ):
                raise c.ContractError()
            wanted_extras.setdefault(requirement.key, set()).update(requirement.extras)
            if requirement.key in reachable:
                return
            reachable.add(requirement.key)
            for edge in release.requires:
                visit(edge)
            for extra in extras.get(requirement.key, ()):
                for edge in dict(release.extra_requires)[extra]:
                    visit(edge)

        for root in self.roots:
            visit(root)
        if reachable != set(selected):
            raise c.ContractError()
        if {key: set(value) for key, value in extras.items()} != {
            key: value for key, value in wanted_extras.items() if value
        }:
            raise c.ContractError()

    @property
    def digest(self) -> str:
        return c.digest(self)


@dataclass(frozen=True)
class _Resolution:
    lock: _FamilyLock | None
    needs: tuple[_Missing, ...]
    contributions: _FamilyContributions | None = field(default=None, repr=False, compare=False)


def _check(clock: c.ClockPort, cancel: c.CancelPort, deadline: float) -> float:
    now = c.finite(clock.monotonic())
    if cancel.is_cancelled():
        raise InterruptedError()
    if now >= c.finite(deadline):
        raise TimeoutError()
    return now


def _matches(version: str, requirement: str) -> bool:
    """Use PEP 440 when available; absence is actionable, never a permissive match."""
    try:
        from packaging.specifiers import InvalidSpecifier, SpecifierSet
        from packaging.version import InvalidVersion, Version
    except ImportError:
        raise _ParserUnavailable() from None
    try:
        return Version(version) in SpecifierSet(requirement)
    except (InvalidVersion, InvalidSpecifier):
        raise c.ContractError() from None


class _ParserUnavailable(Exception):
    pass


def _compatible(release: _Release, target: _Target) -> bool:
    return (
        target.platform in release.platforms
        and target.architecture in release.architectures
        and (not release.python or _matches(target.python, release.python))
        and (not release.abis or target.abi in release.abis)
        and (not release.wheel_tags or bool(set(release.wheel_tags) & set(target.wheel_tags)))
    )


class _FamilyResolver:
    """Bounded backtracking over exact observed versions before any acquisition."""

    def __init__(self, sources: tuple[_RegisteredSource, ...]) -> None:
        if type(sources) is not tuple or len(sources) > _MAX_NODES:
            raise c.ContractError()
        for source in sources:
            if type(source) is not _RegisteredSource:
                raise c.ContractError()
            source.__post_init__()
        c.unique(tuple(source.source for source in sources))
        self._sources = {source.source: source for source in sources}
        self._issued_contributions: _FamilyContributions | None = None
        self._contribution_objects: tuple[_IssuedContribution, ...] = ()

    def resolve(
        self, roots: tuple[_Requirement, ...], targets: tuple[_Target, ...],
        registry_digest: str, clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _Resolution:
        c.sha256(registry_digest)
        if (
            type(roots) is not tuple or not roots or len(roots) > _MAX_NODES
            or type(targets) is not tuple or not targets or len(targets) > 2
        ):
            raise c.ContractError()
        for target in targets:
            if type(target) is not _Target:
                raise c.ContractError()
            target.__post_init__()
        for root in roots:
            if type(root) is not _Requirement:
                raise c.ContractError()
            root.__post_init__()
        c.unique(tuple(target.context for target in targets))
        c.unique(tuple(c.digest(root) for root in roots))
        selected_targets = {target.context: target for target in targets}
        snapshots: dict[tuple[str, str], _PublisherSnapshot] = {}
        failures: dict[tuple[str, str, str], _Missing] = {}
        attempts = 0
        start = _check(clock, cancel, deadline)
        deadline = min(deadline, start + 60.0)
        last = start

        def check() -> float:
            nonlocal last
            now = _check(clock, cancel, deadline)
            if now < last:
                raise c.ContractError()
            last = now
            return now

        def fail(requirement: _Requirement, reason: str, *fields: str) -> tuple[_Release, ...]:
            failures[requirement.key] = _Missing(requirement, reason, tuple(fields))
            return ()

        def candidates(requirement: _Requirement) -> tuple[_Release, ...]:
            now = check()
            source = self._sources.get(requirement.source)
            target = selected_targets.get(requirement.context)
            if target is None:
                return fail(requirement, "consuming-target-required", "platform", "python", "abi")
            if source is None or requirement.family not in source.families:
                return fail(requirement, "registered-metadata-source-required", "publisher-metadata")
            key = requirement.source, c.digest(target)
            snapshot = snapshots.get(key)
            if snapshot is None:
                _trace("family-metadata", requirement.family, "attempt")
                try:
                    snapshot = source.port.observe(requirement, target, clock, cancel, deadline)
                except _CatalogueUnavailable as unavailable:
                    _trace("family-metadata", requirement.family, "unretained")
                    return fail(
                        requirement, "verified-metadata-required",
                        "compatible-version", "source-identity", "sha256", "size",
                        "transitive-wheel-collection-lock", "provider-handler",
                        *(unavailable.fields or ("retained-independent-publisher-catalogue",)),
                    )
                except _SourceUnavailable:
                    _trace("family-metadata", requirement.family, "failed")
                    return fail(
                        requirement, "verified-publisher-metadata-required",
                        "fresh-publisher-json", "retained-independent-metadata-pin",
                    )
                except BaseException:
                    _trace("family-metadata", requirement.family, "failed")
                    raise
                _trace("family-metadata", requirement.family, "returned")
                now = check()
                if type(snapshot) is not _PublisherSnapshot:
                    raise c.ContractError()
                snapshot.__post_init__()
                if (
                    snapshot.source != source.source or snapshot.target_digest != c.digest(target)
                    or snapshot.metadata_digest != source.metadata_digest
                    or snapshot.observed_at > now or snapshot.expires_at <= now
                ):
                    raise c.ContractError()
                for release in snapshot.releases:
                    if release.requirement.family not in source.families:
                        raise c.ContractError()
                    asset = release.artifact
                    if asset is not None and (
                        asset.source_id != source.source or _origin(asset.url) not in source.origins
                    ):
                        raise c.ContractError()
                snapshots[key] = snapshot
            if now >= snapshot.expires_at:
                return fail(requirement, "fresh-publisher-observation-required", "publisher-metadata")
            values = tuple(
                release for release in snapshot.releases
                if release.requirement.key == requirement.key
                and _matches(release.version, requirement.version)
                and _compatible(release, target)
            )
            if not values:
                return fail(
                    requirement, "compatible-publisher-release-required",
                    "version", "platform", "python", "abi", "wheel-tag", "format",
                )
            # Publisher preference order is part of the pinned metadata snapshot.
            return values

        def search(
            pending: tuple[_Requirement, ...],
            selected: dict[tuple[str, str, str], _Release],
            extras: dict[tuple[str, str, str], frozenset[str]],
        ) -> tuple[
            dict[tuple[str, str, str], _Release],
            dict[tuple[str, str, str], frozenset[str]],
        ] | None:
            nonlocal attempts
            check()
            attempts += 1
            if attempts > _MAX_SEARCH or len(selected) + len(pending) > _MAX_NODES * 4:
                raise c.ContractError()
            if not pending:
                return selected, extras
            wanted, *tail = pending
            previous = selected.get(wanted.key)
            if previous is not None:
                if (
                    previous.requirement.source == wanted.source
                    and _matches(previous.version, wanted.version)
                ):
                    extra_requires = dict(previous.extra_requires)
                    added = set(wanted.extras) - extras.get(wanted.key, frozenset())
                    if not added <= set(extra_requires):
                        fail(wanted, "requested-extra-metadata-required", "extra-requirements")
                        return None
                    return search(
                        (*(edge for name in sorted(added) for edge in extra_requires[name]), *tail),
                        selected,
                        {**extras, wanted.key: extras.get(wanted.key, frozenset()) | added},
                    )
                fail(wanted, "transitive-version-conflict", "compatible-transitive-version")
                return None
            for release in candidates(wanted):
                extra_requires = dict(release.extra_requires)
                if not set(wanted.extras) <= set(extra_requires):
                    fail(wanted, "requested-extra-metadata-required", "extra-requirements")
                    continue
                result = search(
                    (
                        *release.requires,
                        *(edge for name in wanted.extras for edge in extra_requires[name]), *tail,
                    ),
                    {**selected, wanted.key: release},
                    {**extras, wanted.key: frozenset(wanted.extras)},
                )
                if result is not None:
                    return result
            return None

        try:
            # Diagnose every selected root even if the first is unavailable.
            # Backtracking may stop at one unsatisfied edge; the public guided
            # result must never make that look like the entire selected closure.
            for root in roots:
                candidates(root)
            solution = search(roots, {}, {})
        except _ParserUnavailable:
            return _Resolution(None, tuple(
                _Missing(root, "metadata-parser-required", ("pep440-parser",)) for root in roots
            ))
        if solution is None:
            return _Resolution(None, tuple(failures.values()) or tuple(
                _Missing(root, "complete-compatible-closure-required", ("transitive-metadata",))
                for root in roots
            ))
        selected, selected_extras = solution
        ordered: list[_Release] = []
        visited: set[tuple[str, str, str]] = set()
        visiting: set[tuple[str, str, str]] = set()

        def visit(key: tuple[str, str, str]) -> None:
            check()
            if key in visiting:
                raise c.ContractError()
            if key in visited:
                return
            visiting.add(key)
            release = selected[key]
            for edge in release.requires:
                visit(edge.key)
            for extra in selected_extras.get(key, ()):
                for edge in dict(release.extra_requires)[extra]:
                    visit(edge.key)
            visiting.remove(key)
            visited.add(key)
            ordered.append(release)

        for root in roots:
            visit(root.key)
        now = check()
        if any(snapshot.expires_at <= now for snapshot in snapshots.values()):
            return _Resolution(None, tuple(
                _Missing(root, "fresh-publisher-observation-required", ("publisher-metadata",))
                for root in roots
            ))
        lock = _FamilyLock(
            roots, targets, tuple(ordered), tuple(snapshots.values()), registry_digest,
            tuple((release.requirement.key, tuple(sorted(selected_extras[release.requirement.key])))
                  for release in ordered if selected_extras.get(release.requirement.key)),
        )
        from ._family_source import _issue

        contributions = _issue(self, lock, clock, cancel, deadline)
        return _Resolution(lock, (), contributions)
