"""Live publisher contribution issuance; normalized locks never recreate authority."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn, cast

from netops.ansible import contracts as c
from netops.ansible.artifacts import _root
from netops.ansible.policy.authorization import AuthorizationError

from ._assets import HttpsAssetTransport, LockedAsset
from ._family_lock import _check, _FamilyLock, _RegisteredSource, _Release

if TYPE_CHECKING:
    from ._bootstrap import _BootstrapContribution
    from ._family_lock import _FamilyResolver
    from ._family_provider import _Operation
    from ._lock_layout import _LockLayout
    from ._managed import ManagedGenerationManifest

__all__: tuple[str, ...] = ()
_NEEDS_CONTRIBUTIONS = "live-selected-family-contributions-required"


def _requires_contributions(scope: c.InstallScope) -> bool:
    """Keep legacy narrow native layouts distinct from compound/full admission."""
    if type(scope) is not c.InstallScope:
        raise c.ContractError()
    scope.__post_init__()
    return scope.full_toolkit or bool(scope.companions) or scope.enhanced


def _client_facts(source: _RegisteredSource) -> str:
    """Accept real closed clients, not a callback or normalized JSON observation."""
    from ._official_profiles import _OfficialMetadata
    from ._publisher_catalog import _SeededPublisherMetadata
    from ._publisher_metadata import _PublisherMetadata
    from ._python_metadata import _PythonOrgMetadata, _SeededPythonMetadata

    port = source.port
    if type(port) not in (
        _PublisherMetadata, _SeededPublisherMetadata, _PythonOrgMetadata,
        _SeededPythonMetadata, _OfficialMetadata,
    ) or type(getattr(port, "transport", None)) is not HttpsAssetTransport:
        raise AuthorizationError()
    client = cast(
        "_PublisherMetadata | _SeededPublisherMetadata | _PythonOrgMetadata | "
        "_SeededPythonMetadata | _OfficialMetadata", port,
    )
    return c.digest((
        source.source, source.families, source.origins, source.metadata_digest,
        type(port).__name__,
        tuple((field.name, getattr(port, field.name))
              for field in fields(client) if field.name != "transport"),
    ))


@dataclass(frozen=True, eq=False, repr=False)
class _IssuedContribution:
    """One issuer-retained exact selected subset, including its transitive edges."""

    source: _RegisteredSource
    release: _Release
    source_facts: str
    target_digest: str
    port: object
    transport: object

    def __repr__(self) -> str:
        return "<private publisher contribution>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("Live publisher contributions cannot be serialized.")


class _FamilyContributions:
    """Issued only by the real resolver after every selected observation validates.

    This is publisher/input provenance, not a new platform qualification or
    consent. The issuer retains each identity-bearing subset; a reconstructed
    lock, equal object or receipt cannot replace any of them.
    """

    def __init__(
        self, issuer: _FamilyResolver, lock: _FamilyLock,
        contributions: tuple[_IssuedContribution, ...],
    ) -> None:
        self._issuer, self._lock, self._contributions = issuer, lock, contributions
        self._bound: _BoundFamilyContributions | None = None
        self._pid, self._thread = os.getpid(), threading.get_ident()
        self._last = max(observation.observed_at for observation in lock.observations)
        self._digest = c.digest((lock, tuple(
            (item.source_facts, item.target_digest, item.release) for item in contributions
        )))

    def __reduce__(self) -> NoReturn:
        raise TypeError("Live publisher contributions cannot be serialized.")

    def __repr__(self) -> str:
        return "<private publisher contributions>"

    def guard(self, clock: c.ClockPort, cancel: c.CancelPort, deadline: float) -> None:
        """Recheck the original issuer, each real client and original expiry."""
        now = _check(clock, cancel, deadline)
        if (
            now < self._last
            or self._pid != os.getpid() or self._thread != threading.get_ident()
            or self._issuer._issued_contributions is not self
            or len(self._contributions) != len(self._lock.releases)
            or self._issuer._contribution_objects != self._contributions
        ):
            raise AuthorizationError()
        self._last = now
        self._lock.__post_init__()
        targets = {target.context: target for target in self._lock.targets}
        for release, item in zip(self._lock.releases, self._contributions):
            source = self._issuer._sources.get(release.requirement.source)
            if (
                type(item) is not _IssuedContribution or item.release is not release
                or source is not item.source or _client_facts(item.source) != item.source_facts
                or source.port is not item.port
                or getattr(source.port, "transport", None) is not item.transport
                or item.target_digest != c.digest(targets[release.requirement.context])
            ):
                raise AuthorizationError()
        if any(now >= observation.expires_at for observation in self._lock.observations):
            raise AuthorizationError()
        if self._digest != c.digest((self._lock, tuple(
            (item.source_facts, item.target_digest, item.release) for item in self._contributions
        ))):
            raise AuthorizationError()
        observed = _check(clock, cancel, deadline)
        if observed < self._last or any(
            observed >= observation.expires_at for observation in self._lock.observations
        ):
            raise AuthorizationError()
        self._last = observed

    def bind(
        self, manifest: ManagedGenerationManifest, cache_paths: tuple[Path, ...],
        bootstrap: _BootstrapContribution, layout: _LockLayout, clock: c.ClockPort,
        cancel: c.CancelPort, deadline: float,
    ) -> _BoundFamilyContributions:
        """Bind actual compiled inputs after closure checks, before any admission."""
        self.guard(clock, cancel, deadline)
        from ._family_integration import _validate_archives
        from ._setup import _contexts, _Review, _service
        from .service import DependencyRegistry

        registry = DependencyRegistry.load()
        spec = manifest.installation
        if spec is None or self._bound is not None:
            raise AuthorizationError()
        contexts = _contexts(
            Path(bootstrap.root.path), manifest.generation_id,
            spec.controller or spec.controller_installation is not None,
            separate_controller=spec.controller_installation is not None,
        )
        service = _service(registry, contexts, _Review(lambda _: "", lambda _: None), None)
        selected = tuple(entry.id for entry in service._entries(
            service._selection(manifest.scope), manifest.scope,
        ))
        _validate_archives(self._lock, manifest, registry, selected)
        return _BoundFamilyContributions._bind(
            self, manifest, cache_paths, bootstrap, layout, clock, cancel, deadline,
        )


def _issue(
    issuer: _FamilyResolver, lock: _FamilyLock,
    clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
) -> _FamilyContributions | None:
    """Issue from actual resolver observations; legacy test ports get no capability."""
    _check(clock, cancel, deadline)
    targets = {target.context: target for target in lock.targets}
    values = []
    try:
        for release in lock.releases:
            source = issuer._sources[release.requirement.source]
            values.append(_IssuedContribution(
                source, release, _client_facts(source),
                c.digest(targets[release.requirement.context]),
                source.port, getattr(source.port, "transport"),
            ))
    except AuthorizationError:
        return None
    contributions = tuple(values)
    result = _FamilyContributions(issuer, lock, contributions)
    issuer._contribution_objects = contributions
    issuer._issued_contributions = result
    result.guard(clock, cancel, deadline)
    return result


@dataclass(frozen=True, eq=False, repr=False)
class _BoundFamilyContributions:
    """Exact source/input/cache/tool/member/root/context binding for one generation."""

    source: _FamilyContributions
    manifest: ManagedGenerationManifest
    cache_paths: tuple[Path, ...]
    cache_present: tuple[bool, ...]
    cache_identities: tuple[tuple[str, str, int, str] | None, ...]
    bootstrap: _BootstrapContribution
    layout: _LockLayout
    digest: str

    def __repr__(self) -> str:
        return "<private bound publisher contributions>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("Bound publisher contributions cannot be serialized.")

    def require_operation(self, operation: _Operation) -> None:
        """Require the issuer's exact subset at the real typed family handler."""
        from ._family_provider import _Operation

        if (
            type(operation) is not _Operation or self.source._bound is not self
            or operation.lock_digest != self.source._lock.digest
            or operation.generation_id != self.manifest.generation_id
            or sum(c.digest(item.release) == operation.release_digest
                   for item in self.source._contributions) != 1
        ):
            raise AuthorizationError()
        operation.__post_init__()

    @classmethod
    def _bind(
        cls, source: _FamilyContributions, manifest: ManagedGenerationManifest,
        paths: tuple[Path, ...], bootstrap: _BootstrapContribution,
        layout: _LockLayout, clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _BoundFamilyContributions:
        from ._bootstrap import _BootstrapContribution
        from ._lock_layout import _LockLayout
        from ._managed import ManagedGenerationManifest

        if (
            type(source) is not _FamilyContributions
            or type(manifest) is not ManagedGenerationManifest
            or type(bootstrap) is not _BootstrapContribution or bootstrap.family is not None
            or type(layout) is not _LockLayout or type(paths) is not tuple
            or any(not isinstance(path, Path) for path in paths)
        ):
            raise AuthorizationError()
        plain = replace(manifest, bootstrap_digest=None)
        if (
            len(paths) != len(manifest.archives)
            or manifest.context.context.registry_digest != source._lock.registry_digest
            or manifest.consuming_contexts != tuple(sorted(
                target.context_digest for target in source._lock.targets
            ))
        ):
            raise AuthorizationError()
        present = tuple(path.exists() or path.is_symlink() for path in paths)
        identities = tuple(
            _cache_identity(path) if exists else None for path, exists in zip(paths, present)
        )
        result = cls(source, plain, paths, present, identities, bootstrap, layout, c.digest((
            source._digest, plain, tuple(str(path) for path in paths),
            present, identities, bootstrap.digest, layout,
        )))
        source._bound = result
        result.guard(Path(bootstrap.root.path), clock, cancel, deadline)
        return result

    def guard(
        self, root: Path, clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> None:
        """Inspect each actual retained input without downloading or extending expiry."""
        from ._installation import _hash
        from ._owned_build import _external, _ToolchainFile
        from ._setup import _context, _contexts, _OfflineAssets
        from .service import DependencyRegistry

        self.source.guard(clock, cancel, deadline)
        registry = DependencyRegistry.load()
        spec = self.manifest.installation
        if (
            spec is None or root != Path(self.bootstrap.root.path)
            or self.source._bound is not self
        ):
            raise AuthorizationError()
        with _root(self.bootstrap.root):
            pass
        contexts = _contexts(
            root, self.manifest.generation_id,
            spec.controller or spec.controller_installation is not None,
            separate_controller=spec.controller_installation is not None,
        )
        if (
            self.manifest.context != _context(root, registry)
            or self.manifest.consuming_contexts != tuple(sorted(
                context.digest for context in contexts.values()
            ))
            or self.digest != c.digest((
                self.source._digest, self.manifest, tuple(str(path) for path in self.cache_paths),
                self.cache_present, self.cache_identities, self.bootstrap.digest, self.layout,
            ))
        ):
            raise AuthorizationError()
        self.layout.__post_init__()
        for pin in self.layout.interpreters:
            _external(_ToolchainFile(pin.path, pin.digest, pin.qualification_ref))
            _check(clock, cancel, deadline)
        for consuming in (spec, *((spec.controller_installation,)
                                 if spec.controller_installation is not None else ())):
            if _hash(Path(consuming.python), clock, cancel, deadline) != consuming.python_digest:
                raise AuthorizationError()
        for archive, path, present, identity in zip(
            self.manifest.archives, self.cache_paths, self.cache_present, self.cache_identities,
        ):
            asset = archive.asset
            if type(asset) is not LockedAsset:
                raise AuthorizationError()
            if (path.exists() or path.is_symlink()) != present:
                raise AuthorizationError()
            if present:
                if _cache_identity(path) != identity:
                    raise AuthorizationError()
                cache = _OfflineAssets(())
                cache.sources[asset.url] = (asset, path)
                cache.read(asset.url, deadline - _check(clock, cancel, deadline),
                           asset.size + 1)
                if _cache_identity(path) != identity:
                    raise AuthorizationError()
        self.source.guard(clock, cancel, deadline)


def _cache_identity(path: Path) -> tuple[str, str, int, str]:
    info = path.lstat()
    return str(info.st_dev), str(info.st_ino), info.st_size, str(info.st_mtime_ns)
