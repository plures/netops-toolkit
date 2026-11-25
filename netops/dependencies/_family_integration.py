"""Registered family locks consumed by the existing managed lifecycle owner."""

from __future__ import annotations

from typing import TYPE_CHECKING

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import AuthorizationError

from ._assets import _origin
from ._family_bridge import _requirement
from ._family_lock import _contributions, _FamilyLock, _matches, _Release
from ._family_provider import _Authority, _HostResult, _Operation, _Resource

if TYPE_CHECKING:
    from ._composition import ManagedLifecycleState
    from ._managed import ManagedGenerationManifest
    from ._platform_host import _PlatformFamilies
    from .service import DependencyEntry, DependencyRegistry

__all__: tuple[str, ...] = ()
_MATERIALIZED = ("python", "wheel", "executable", "collection", "library")


def _validate_archives(
    lock: _FamilyLock, manifest: ManagedGenerationManifest,
    registry: DependencyRegistry, selected: tuple[str, ...],
) -> None:
    """Require the full registry selection and every transitive exact contribution."""
    lock.__post_init__()
    if lock.registry_digest != registry.digest:
        raise AuthorizationError()
    entries = tuple(registry.entry(name) for name in selected)
    from ._lock_layout import _selected_toolkit_roots, _toolkit_requirement

    roots = tuple(dict.fromkeys(_requirement(entry) for entry in entries))
    if lock.roots not in (
        roots, (*roots, _toolkit_requirement()),
        (*roots, *_selected_toolkit_roots(entries, registry)),
    ):
        raise AuthorizationError()
    _validate_entries(lock, manifest, entries)


def _validate_entries(
    lock: _FamilyLock, manifest: ManagedGenerationManifest,
    entries: tuple[DependencyEntry, ...],
) -> None:
    lock.__post_init__()
    if lock.registry_digest != manifest.context.context.registry_digest:
        raise AuthorizationError()
    roots = tuple(dict.fromkeys(_requirement(entry) for entry in entries))
    from ._lock_layout import _toolkit_requirement

    additional = lock.roots[len(roots):]
    extras = additional[0].extras if additional else ()
    if set(extras) - {"tui", "snmp", "report", "report-pdf", "docs"}:
        raise AuthorizationError()
    toolkit = _toolkit_requirement(extras)
    controller_toolkit = _toolkit_requirement(("ansible",), context="controller")
    if lock.roots not in (
        roots, (*roots, toolkit), (*roots, toolkit, controller_toolkit),
    ) or tuple(sorted(
        target.context_digest for target in lock.targets
    )) != tuple(sorted(manifest.consuming_contexts)):
        raise AuthorizationError()
    spec = manifest.installation
    if spec is not None:
        for target in lock.targets:
            try:
                consuming = (
                    spec if spec.controller and spec.controller_installation is None
                    else spec.for_context(target.context)
                )
            except c.ContractError:
                raise AuthorizationError() from None
            if target.platform != consuming.platform or target.python != consuming.python_version:
                raise AuthorizationError()
            if spec.controller_installation is not None or consuming.requested_extras:
                expected_extras = tuple(
                    (name, extras)
                    for (context, family, name), extras in lock.selected_extras
                    if context == target.context and family == "wheel" and extras
                )
                if consuming.requested_extras != expected_extras:
                    raise AuthorizationError()
            if spec.controller_installation is not None:
                from pathlib import Path

                releases = tuple(
                    release for release in lock.releases
                    if release.requirement.context == target.context
                )
                expected_wheels = tuple(sorted(
                    (release.requirement.name, release.version,
                     release.members[0].path, release.members[0].digest)
                    for release in releases if release.requirement.family == "wheel"
                ))
                from ._installation import _normalize

                actual_wheels = tuple(sorted(
                    (_normalize(wheel.distribution), wheel.version, wheel.member, wheel.digest)
                    for wheel in consuming.wheels
                ))
                expected_collections = tuple(sorted(
                    (release.requirement.name, release.version,
                     release.members[0].path, release.members[0].digest)
                    for release in releases if release.requirement.family == "collection"
                ))
                actual_collections = tuple(sorted(
                    (collection.name, collection.version, collection.member, collection.digest)
                    for collection in consuming.collections
                ))
                if (
                    actual_wheels != expected_wheels
                    or actual_collections != expected_collections
                ):
                    raise AuthorizationError()
                interpreters = tuple(
                    release for release in releases if release.requirement.family == "python"
                )
                if not interpreters or any(
                    release.version != consuming.python_version or not any(
                        member.executable and member.digest == consuming.python_digest
                        and member.path.rsplit("/", 1)[-1] == Path(consuming.python).name
                        for member in release.members
                    ) for release in interpreters
                ):
                    raise AuthorizationError()
    archives = manifest.archives
    try:
        archive_releases = _contributions(lock.releases)
    except c.ContractError:
        raise AuthorizationError() from None
    if len(archives) != len(archive_releases):
        raise AuthorizationError()
    for release, archive in zip(archive_releases, archives):
        source = release.requirement.source
        origin = (
            "files.pythonhosted.org" if source.startswith("pypi:")
            else "galaxy.ansible.com" if source.startswith("galaxy:")
            else "www.python.org" if source == "python.org" else None
        )
        if (
            release.artifact != archive.asset or release.members != archive.members
            or archive.archive != {
                "wheel": "file", "collection.tar.gz": "file", "wsl-rootfs": "file",
                "oci-archive": "file",
            }.get(release.format, release.format)
            or release.artifact is None or release.artifact.source_id != source
            or origin is None or _origin(release.artifact.url) != origin
        ):
            raise AuthorizationError()
        if release.requirement.family in ("wheel", "collection"):
            from ._installation import _normalize

            if spec is None:
                raise AuthorizationError()
            consuming = (
                spec if spec.controller and spec.controller_installation is None
                else spec.for_context(release.requirement.context)
            )
            contributions = (
                tuple((item.distribution, item.version, item.member, item.digest)
                      for item in consuming.wheels)
                if release.requirement.family == "wheel" else
                tuple((item.name, item.version, item.member, item.digest)
                      for item in consuming.collections)
            )
            if not any(
                _normalize(name) == _normalize(release.requirement.name)
                and _matches(version, "==" + release.version)
                and any(member.path == path and member.digest == digest for member in release.members)
                for name, version, path, digest in contributions
            ):
                raise AuthorizationError()
    platform = tuple(release for release in lock.releases
                     if release.requirement.family not in _MATERIALIZED)
    if platform:
        from ._platform_host import _required_tools, _supported_release

        if spec is None or any(not _supported_release(item) for item in platform):
            raise AuthorizationError()
        for item in platform:
            consuming = (
                spec if spec.controller and spec.controller_installation is None
                else spec.for_context(item.requirement.context)
            )
            available = {file.destination for file in consuming.native_files if file.executable}
            suffix = ".exe" if consuming.platform == "win32" else ""
            if any("tools/" + name + suffix not in available for name in _required_tools(item)):
                raise AuthorizationError()


def _supported(lock: _FamilyLock) -> bool:
    """Only materialized or fixed typed host operations have a production driver."""
    from ._platform_host import _supported_release

    if not all(
        (release.requirement.family in _MATERIALIZED and not release.scopes)
        or _supported_release(release)
        for release in lock.releases
    ):
        return False
    by_key = {release.requirement.key: release for release in lock.releases}
    for release in lock.releases:
        family = release.requirement.family
        dependencies = tuple(by_key[edge.key] for edge in release.requires)
        if family in ("image", "service") and not any(
            item.requirement.family == "runtime" and item.resource == "podman-rootless"
            for item in dependencies
        ):
            return False
        if family == "image" and not any(
            item.requirement.family == "service" and item.resource == "podman-user-service"
            for item in dependencies
        ):
            return False
    return True


class _MaterializedFamilies:
    """Actual protected-tree postconditions after the admitted managed installer.

    The original stage handler performs acquisition, extraction and offline
    installation. These per-family hooks validate and ledger those real effects;
    they do not claim a second install, own an external daemon or create a grant.
    Final consuming readiness remains the original lifecycle owner's probe.
    """

    def __init__(
        self, owner: ManagedLifecycleState, manifest: ManagedGenerationManifest,
        lock: _FamilyLock,
    ) -> None:
        from ._composition import ManagedLifecycleState
        from ._managed import ProtectedGenerationFiles

        if (
            type(owner) is not ManagedLifecycleState
            or type(owner.files) is not ProtectedGenerationFiles
            or not _supported(lock)
            or manifest not in owner.manifests
            or owner._family_locks.get(manifest.generation_id) != lock
        ):
            raise AuthorizationError()
        owner._facts()
        self._owner, self._manifest, self._lock = owner, manifest, lock

    def _platform(self) -> _PlatformFamilies:
        from ._platform_host import _PlatformFamilies

        return _PlatformFamilies(self._owner, self._manifest, self._lock)

    def reconcile_removal(
        self, release: _Release, operation: _Operation,
        authority: _Authority, existing: _Resource,
    ) -> _HostResult:
        """Use only fresh exact absence queries, not a second removal."""
        if release.requirement.family in (*_MATERIALIZED, "runtime"):
            return self._observe(
                release.requirement.family, release, operation, authority, existing,
            )
        return self._platform().reconcile_removal(release, operation, authority, existing)

    def _observe(
        self, family: str, release: _Release, operation: _Operation,
        authority: _Authority, existing: _Resource | None,
    ) -> _HostResult:
        from ._managed import ProtectedGenerationFiles

        if (
            type(authority) is not _Authority or type(operation) is not _Operation
            or release not in self._lock.releases or release.requirement.family != family
            or operation.action not in ("install", "verify", "remove")
            or operation.generation_id != self._manifest.generation_id
            or type(self._owner.files) is not ProtectedGenerationFiles
        ):
            raise AuthorizationError()
        authority.enter(operation)
        if operation.action == "remove":
            from pathlib import Path

            from ._installation import _OfflineInstallation

            if existing is None:
                raise AuthorizationError()
            targets = (
                Path(self._owner.files._root.path) / self._owner.files._directory(self._manifest),
                _OfflineInstallation(self._owner.files._root).path(self._manifest),
            )
            if any(path.exists() or path.is_symlink() for path in targets):
                raise AuthorizationError()
            identity = c.digest((self._manifest.generation_id, release))
            if existing.identity_digest != identity:
                raise AuthorizationError()
            return _HostResult(identity, False, True, True)
        # Re-read ownership and exact byte membership, including installed
        # output receipts, under the driver's original root lock and budget.
        actual = self._owner.files._verify(
            self._manifest, authority._clock, authority._cancel, authority.deadline,
            functional=False,
        )
        if self._manifest.installation is not None:
            self._owner._installed_receipt(self._manifest, actual)
        identity = c.digest((self._manifest.generation_id, release))
        if existing is not None and existing.identity_digest != identity:
            raise AuthorizationError()
        authority.check()
        return _HostResult(identity, False, True, True)

    def python(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Verify the actual owned interpreter tree, never global interpreter ownership."""
        return self._observe("python", release, operation, authority, existing)

    def wheel(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Verify exact staged wheel and actual protected offline installation."""
        return self._observe("wheel", release, operation, authority, existing)

    def executable(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Verify exact executable members without a PATH or shell fallback."""
        return self._observe("executable", release, operation, authority, existing)

    def collection(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Verify the exact collection contribution and consuming installation."""
        return self._observe("collection", release, operation, authority, existing)

    def library(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Verify exact native-library bytes without granting external package ownership."""
        return self._observe("library", release, operation, authority, existing)

    def runtime(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Check the exact owned rootless runtime binary, not a global daemon."""
        if operation.action == "remove":
            return self._observe("runtime", release, operation, authority, existing)
        return self._platform().runtime(release, operation, authority, existing)

    def image(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Load/inspect/remove only an exact digest on the owned runtime endpoint."""
        return self._platform().image(release, operation, authority, existing)

    def service(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Use a unique owned transient user service and actual invocation identity."""
        return self._platform().service(release, operation, authority, existing)

    def os_feature(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Enable only a separately reviewed fixed feature; never disable or reboot."""
        return self._platform().os_feature(release, operation, authority, existing)

    def distribution(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Import or retire only a byte- and UUID-bound owned WSL2 distribution."""
        return self._platform().distribution(release, operation, authority, existing)
