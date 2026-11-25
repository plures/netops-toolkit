"""Compile a complete retained family lock into the original offline installer.

No path from publisher metadata becomes a host executable. Cache locations are
content addressed under the explicitly selected root's sibling cache, and the
existing interpreter must match an independently locked executable member.
"""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

from netops.ansible import contracts as c

from ._context_facts import _host_architecture
from ._family_lock import (
    _artifact_identity,
    _contributions,
    _FamilyLock,
    _Release,
    _Requirement,
    _Target,
)
from ._installation import (
    _Collection,
    _InstallationSpec,
    _Library,
    _NativeFile,
    _Tool,
    _Wheel,
)
from ._managed import ManagedArchive, _parts

__all__: tuple[str, ...] = ()

if TYPE_CHECKING:
    from ._official_profiles import _PublisherContext
    from .service import DependencyEntry, DependencyRegistry


class _LayoutUnavailable(c.ContractError):
    """A precise missing compiler input, never an installation success."""

    def __init__(
        self, reason: str, fields: tuple[str, ...], *, context: str | None = None,
    ) -> None:
        super().__init__()
        self.reason, self.fields = c.text(reason), fields
        if context not in (None, "native", "controller"):
            raise c.ContractError()
        self.context = context
        c.unique(fields)
        for field in fields:
            c.text(field)


def _toolkit_requirement(
    extras: tuple[str, ...] = (), *, context: str = "native",
) -> _Requirement:
    from netops import __version__

    return _Requirement(
        "netops-toolkit", "wheel", "pypi:netops-toolkit", context, "==" + __version__,
        extras,
    )


def _selected_toolkit_requirement(
    entries: tuple[DependencyEntry, ...], registry: DependencyRegistry,
) -> _Requirement:
    """Retain package extras selected by the registry, not merely wheel versions."""
    from .service import DependencyEntry, DependencyRegistry

    if type(registry) is not DependencyRegistry or any(
        type(entry) is not DependencyEntry for entry in entries
    ):
        raise c.ContractError()
    sources = {
        entry.source[len("pypi:"):].lower().replace("_", "-").replace(".", "-")
        for entry in entries
        if entry.context == "native" and entry.source.startswith("pypi:")
    }
    extras = tuple(sorted(
        name[len("extra:"):] for name, packages in registry.package_requirements
        if name.startswith("extra:") and packages and all(
            registry.entry(package).source[len("pypi:"):].lower().replace(
                "_", "-",
            ).replace(".", "-") in sources
            for package in packages
        ) and name != "extra:ansible"
    ))
    return _toolkit_requirement(extras)


def _selected_toolkit_roots(
    entries: tuple[DependencyEntry, ...], registry: DependencyRegistry,
) -> tuple[_Requirement, ...]:
    roots: tuple[_Requirement, ...] = (_selected_toolkit_requirement(entries, registry),)
    if any(entry.context == "controller" for entry in entries):
        roots += (_toolkit_requirement(("ansible",), context="controller"),)
    return roots


@dataclass(frozen=True)
class _InterpreterPin:
    """Independently retained existing interpreter, not a process qualification."""

    target: _Target
    path: str
    digest: str
    qualification_ref: str

    def __post_init__(self) -> None:
        if type(self.target) is not _Target:
            raise c.ContractError()
        self.target.__post_init__()
        if not Path(self.path).is_absolute() or ".." in Path(self.path).parts:
            raise c.ContractError()
        c.sha256(self.digest)
        c.sha256(self.qualification_ref)


@dataclass(frozen=True)
class _CompiledLayout:
    installation: _InstallationSpec
    archives: tuple[ManagedArchive, ...]
    cache_paths: tuple[Path, ...]


@dataclass(frozen=True)
class _LockLayout:
    """Fixed production compiler; callers cannot supply layout callbacks or argv."""

    interpreters: tuple[_InterpreterPin, ...] = ()
    contexts: tuple[_PublisherContext, ...] = ()

    def __post_init__(self) -> None:
        if type(self.interpreters) is not tuple or len(self.interpreters) > 2:
            raise c.ContractError()
        for pin in self.interpreters:
            if type(pin) is not _InterpreterPin:
                raise c.ContractError()
            pin.__post_init__()
        c.unique(tuple(pin.target.context for pin in self.interpreters))
        from ._official_profiles import _PublisherContext

        if type(self.contexts) is not tuple or len(self.contexts) > 2:
            raise c.ContractError()
        for context in self.contexts:
            if type(context) is not _PublisherContext:
                raise c.ContractError()
            context.__post_init__()
        c.unique(tuple(context.consuming.context for context in self.contexts))

    def preflight(self, targets: tuple[_Target, ...]) -> None:
        """Keep prospective guest profiles separate from an actual host controller."""
        self.__post_init__()
        for target in targets:
            context = next(
                (context for context in self.contexts
                 if context.consuming.context == target.context), None,
            )
            if context is not None:
                from dataclasses import replace

                if (
                    context.host_platform != sys.platform
                    or replace(context.consuming, context_digest=target.context_digest) != target
                ):
                    raise _LayoutUnavailable(
                        "independent-publisher-layout-profile-mismatch",
                        ("host-platform", "selected-role-python-abi-tags", "exact-publisher-context"),
                        context=target.context,
                    )
                if context.layout in ("wsl2-guest", "vm-guest"):
                    raise _LayoutUnavailable(
                        "qualified-guest-consuming-layout-required",
                        ("independently-selected-guest-platform-version",
                         "guest-python-abi-wheel-tags", "guest-framework-and-collections",
                         "guest-native-library-closure", "protected-guest-root",
                         "actual-qualified-route-and-receipts", "separate-exact-category-review"),
                        context=target.context,
                    )
            if target.context == "controller" and target.platform == "win32":
                raise _LayoutUnavailable(
                    "native-windows-controller-prohibited",
                    ("qualified-existing-linux-wsl-controller", "separate-exact-wsl-review"),
                    context=target.context,
                )
            if target.platform != sys.platform:
                raise _LayoutUnavailable(
                    "qualified-controller-consuming-layout-required",
                    ("actual-supported-controller", "independent-guest-platform-python-abi-tags",
                     "protected-controller-root", "separate-exact-category-review"),
                    context=target.context,
                )

    def compile(
        self, lock: _FamilyLock, root: Path,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _CompiledLayout:
        from ._family_lock import _check

        self.__post_init__()
        if type(lock) is not _FamilyLock or not root.is_absolute() or ".." in root.parts:
            raise c.ContractError()
        lock.__post_init__()
        self.preflight(lock.targets)
        _check(clock, cancel, deadline)
        native = next((target for target in lock.targets if target.context == "native"), None)
        if native is None:
            raise _LayoutUnavailable(
                "native-consuming-layout-required", ("separate-native-target",),
            )
        selected = {
            target.context: self._compile_context(lock, root, target, clock, cancel, deadline)
            for target in lock.targets
        }
        native_spec = selected["native"].installation
        controller = selected.get("controller")
        if controller is not None:
            from dataclasses import replace

            native_spec = replace(
                native_spec, controller_installation=controller.installation,
            )
        archives, paths = [], []
        for release in _contributions(lock.releases):
            artifact = release.artifact
            if artifact is None:
                raise c.ContractError()
            archives.append(ManagedArchive(
                artifact, {"wheel": "file", "collection.tar.gz": "file",
                           "oci-archive": "file", "wsl-rootfs": "file"}.get(
                               release.format, release.format,
                           ), release.members,
            ))
            filename = unquote(urlsplit(artifact.url).path.rsplit("/", 1)[-1])
            if len(_parts(filename)) != 1:
                raise c.ContractError()
            paths.append(root.parent / "netops-publisher-cache" / artifact.sha256 / filename)
        _check(clock, cancel, deadline)
        return _CompiledLayout(native_spec, tuple(archives), tuple(paths))

    def _compile_context(
        self, lock: _FamilyLock, root: Path, target: _Target,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _CompiledLayout:
        from ._family_lock import _check, _matches, _trace
        from ._guided import _existing_python
        from ._installation import _hash
        from ._probe_catalog import TOOLS

        if type(lock) is not _FamilyLock or not root.is_absolute() or ".." in root.parts:
            raise c.ContractError()
        lock.__post_init__()
        _check(clock, cancel, deadline)
        releases = tuple(
            release for release in lock.releases if release.requirement.context == target.context
        )
        if target.platform != sys.platform or target.architecture != _host_architecture():
            raise _LayoutUnavailable(
                "separate-compatible-controller-installation-required",
                ("qualified-controller-interpreter", "controller-platform", "controller-layout"),
            )
        pin = next((pin for pin in self.interpreters if pin.target.context == target.context), None)
        if pin is not None:
            from dataclasses import replace

            if replace(pin.target, context_digest=target.context_digest) != target:
                raise _LayoutUnavailable(
                    "selected-interpreter-profile-mismatch",
                    ("independent-role-python-abi-tags-platform",),
                )
            interpreter = Path(pin.path)
        else:
            if target.python != platform.python_version():
                raise _LayoutUnavailable(
                    "independent-consuming-interpreter-required",
                    ("selected-role-interpreter", "actual-python-version", "exact-sha256"),
                )
            interpreter = Path(_existing_python())
        python = tuple(item for item in releases if item.requirement.family == "python")
        _trace("compiler-interpreter-read", "python", "attempt")
        try:
            if pin is None:
                digest = _hash(interpreter, clock, cancel, deadline)
            else:
                from ._owned_build import _external, _ToolchainFile

                _external(_ToolchainFile(pin.path, pin.digest, pin.qualification_ref))
                _check(clock, cancel, deadline)
                digest = pin.digest
        except (OSError, c.ContractError):
            _trace("compiler-interpreter-read", "python", "failed")
            raise _LayoutUnavailable(
                "verified-existing-interpreter-required",
                ("existing-interpreter", "independently-retained-executable-sha256"),
            ) from None
        except BaseException:
            _trace("compiler-interpreter-read", "python", "raised")
            raise
        _trace("compiler-interpreter-read", "python", "returned")
        if not python or any(
            release.version != target.python or not any(
                member.executable and member.path.rsplit("/", 1)[-1] == interpreter.name
                and member.digest == digest
                for member in release.members
            )
            for release in python
        ):
            raise _LayoutUnavailable(
                "independently-locked-existing-interpreter-required",
                ("official-or-qualified-owned-interpreter-member", "exact-sha256",
                 "version-platform-architecture"),
            )
        wheels, collections, native, tools, libraries = [], [], [], [], []
        archives: list[ManagedArchive] = []
        cache_paths: list[Path] = []
        try:
            contributions = _contributions(releases)
        except c.ContractError:
            raise _LayoutUnavailable(
                "conflicting-locked-member-layout", ("identical-archive-member-manifest",),
            ) from None
        seen: dict[str, _Release] = {}
        for release in releases:
            _check(clock, cancel, deadline)
            artifact = release.artifact
            if artifact is not None and release in contributions:
                try:
                    archive = ManagedArchive(
                        artifact, {"wheel": "file", "collection.tar.gz": "file",
                                   "oci-archive": "file", "wsl-rootfs": "file"}.get(
                                       release.format, release.format,
                                   ), release.members,
                    )
                except c.ContractError:
                    raise _LayoutUnavailable(
                        "closed-installable-archive-layout-required",
                        ("supported-archive-format", "exact-member-layout"),
                    ) from None
                archives.append(archive)
                filename = unquote(urlsplit(artifact.url).path.rsplit("/", 1)[-1])
                if len(_parts(filename)) != 1:
                    raise c.ContractError()
                cache_paths.append(
                    root.parent / "netops-publisher-cache" / artifact.sha256 / filename,
                )
            family = release.requirement.family
            if family in ("wheel", "collection"):
                if artifact is None or len(release.members) != 1:
                    raise _LayoutUnavailable(
                        "exact-raw-package-layout-required", ("one-locked-raw-package-member",),
                    )
                member = release.members[0]
                filename = unquote(urlsplit(artifact.url).path.rsplit("/", 1)[-1])
                if member.path.rsplit("/", 1)[-1] != filename:
                    raise _LayoutUnavailable(
                        "publisher-filename-layout-mismatch", ("exact-publisher-filename",),
                    )
                previous = seen.get(release.requirement.name)
                if previous is not None:
                    # One owned venv can serve two roles only for identical bytes,
                    # versions and fully compatible target-specific projections.
                    if (
                        previous.version != release.version or previous.artifact is None
                        or _artifact_identity(previous.artifact) != _artifact_identity(artifact)
                        or previous.members != release.members
                    ):
                        raise _LayoutUnavailable(
                            "separate-context-package-layout-required",
                            ("distinct-native-controller-installation", "compatible-package-pins"),
                        )
                    continue
                seen[release.requirement.name] = release
                if family == "wheel":
                    wheels.append(_Wheel(
                        member.path, release.requirement.name, release.version, artifact.sha256,
                    ))
                else:
                    collections.append(_Collection(
                        member.path, release.requirement.name, release.version, artifact.sha256,
                    ))
            elif family in ("executable", "library", "runtime"):
                if release not in contributions:
                    continue
                for member in release.members:
                    prefix = member.path.split("/", 1)[0]
                    if prefix not in ("tools", "libraries"):
                        raise _LayoutUnavailable(
                            "closed-native-member-layout-required",
                            ("tools-or-libraries-owned-destination",),
                        )
                    native.append(_NativeFile(
                        member.path, member.path, member.digest, member.executable,
                    ))
                    name = member.path.rsplit("/", 1)[-1].removesuffix(".exe")
                    if member.executable and name in TOOLS:
                        tools.append(_Tool(name, member.path))
                    if family == "library" and release.requirement.name in (
                        "pango", "gobject", "fontconfig", "harfbuzz",
                    ):
                        libraries.append(_Library(release.requirement.name, member.path))
        toolkit = seen.get("netops-toolkit")
        required = _toolkit_requirement(context=target.context)
        if toolkit is None or not _matches(toolkit.version, required.version):
            raise _LayoutUnavailable(
                "current-toolkit-independent-publisher-lock-required",
                ("pypi:netops-toolkit", "current-version-wheel", "verified-complete-dependency-lock"),
            )
        controller = target.context == "controller"
        if controller and sys.platform == "win32":
            raise _LayoutUnavailable(
                "qualified-controller-context-required", ("qualified-wsl-or-vm-context",),
            )
        try:
            spec = _InstallationSpec(
                str(interpreter), digest, target.python, target.platform,
                tuple(wheels), controller, tuple(collections),
                tuple(native), tuple(tools), tuple(libraries),
                requested_extras=tuple(
                    (name, extras) for (context, family, name), extras in lock.selected_extras
                    if context == target.context and family == "wheel" and extras
                ),
            )
        except c.ContractError:
            raise _LayoutUnavailable(
                "complete-compatible-installation-layout-required",
                ("unique-locked-contributions", "controller-tools-and-collections"),
            ) from None
        _check(clock, cancel, deadline)
        return _CompiledLayout(spec, tuple(archives), tuple(cache_paths))
