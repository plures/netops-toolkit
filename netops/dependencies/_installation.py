"""Offline installation of pinned wheels into a new manifest-owned generation.

Invoked only by the admitted managed stage handler. Descriptors come from the
owned immutable root, not request JSON. Installation proof is not qualification.
"""

from __future__ import annotations

import hashlib
import io
import json
import ntpath
import os
import re
import stat
import sys
import tarfile
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

from netops.ansible import contracts as c
from netops.ansible.artifacts import ProtectedRoot, _directory, _root

from ._context_program import _CONTEXT_PROGRAM
from ._installation_process import _VENV, _run

if TYPE_CHECKING:
    from ._managed import ManagedGenerationManifest

__all__: tuple[str, ...] = ()
_RECEIPT = "netops-installation.json"
_LIMIT = 1024 * 1024
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+!-]{0,127}\Z")
_CLOSURE = """
import importlib.metadata as m, json, sys
expected = json.loads(sys.argv[1])
actual = {d.metadata['Name'].lower().replace('_', '-').replace('.', '-'): d.version
          for d in m.distributions()}
assert all(actual.get(k) == v for k, v in expected.items())
assert set(actual) <= set(expected) | {'pip', 'setuptools'}
import netops
assert netops.__file__.startswith(sys.prefix)
print(json.dumps({'python': sys.executable, 'prefix': sys.prefix, 'versions': actual}))
"""


def _predictable_path_limit(
    root: str, generation_id: str, spec: _InstallationSpec,
    members: tuple[str, ...] = (),
) -> bool:
    """Admit known Windows launcher/cwd/member paths before staging, not relocate.

    This is a conservative compatibility admission for APIs without a qualified
    extended-path launcher. It is not a diagnosis of a previous native failure
    and says nothing about as-yet-unobserved wheel expansion paths.
    """
    if spec.platform != "win32":
        return False
    c.text(root)
    c.text(generation_id)
    target = ntpath.join(root, "installation-" + c.digest(generation_id))
    staged = ntpath.join(root, "generation-" + c.digest(generation_id))
    known = [
        target, ntpath.join(target, "Scripts", "python.exe"),
        *(ntpath.join(target, "wheelhouse", ntpath.basename(wheel.member))
          for wheel in spec.wheels),
        *(ntpath.join(staged, *member.split("/")) for member in members),
    ]
    return any(len(path.encode("utf-16-le")) // 2 >= 260 for path in known)
_WHEEL_METADATA = _CONTEXT_PROGRAM + "\n" + """
import email.parser, hashlib, io, json, pathlib, stat, sys, tarfile, zipfile
try:
    from packaging import tags as packaging_tags
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name, parse_wheel_filename
    from packaging.version import Version
    from packaging.specifiers import SpecifierSet
except ImportError:
    try:
        import pip
    except ImportError:
        import ensurepip
        bundled = pathlib.Path(ensurepip.__file__).parent / '_bundled'
        wheels = tuple(bundled.glob('pip-*.whl'))
        assert len(wheels) == 1
        sys.path.insert(0, str(wheels[0]))
    from pip._vendor.packaging import tags as packaging_tags
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.utils import canonicalize_name, parse_wheel_filename
    from pip._vendor.packaging.version import Version
    from pip._vendor.packaging.specifiers import SpecifierSet
selected = json.loads(sys.argv[1])
profile = json.loads(sys.argv[2]) if len(sys.argv) > 2 else None
versions = {canonicalize_name(w['distribution']): Version(w['version']) for w in selected}
assert len(versions) == len(selected)
environment, metadata = _marker_environment(), {}
tags = set(_interpreter_tags(packaging_tags)) if profile is None else set()
if profile is not None:
    environment = _target_environment(profile['platform'],
                                      environment['platform_machine'],
                                      profile['python_version'])
source_key, source_bytes, declared_extras = None, None, {}
for wheel in selected:
    path = pathlib.Path(wheel['path'])
    if 'archive' in wheel:
        key = (str(path), wheel['source_digest'], wheel['source_size'])
        if key != source_key:
            assert path.stat().st_size == wheel['source_size'] <= 128 * 1024 * 1024
            source_bytes = path.read_bytes()
            assert hashlib.sha256(source_bytes).hexdigest() == wheel['source_digest']
            source_key = key
        if wheel['archive'] == 'zip':
            with zipfile.ZipFile(io.BytesIO(source_bytes)) as outer:
                info = outer.getinfo(wheel['member'])
                assert info.file_size <= 128 * 1024 * 1024
                content = outer.read(info)
        else:
            with tarfile.open(fileobj=io.BytesIO(source_bytes), mode='r:gz') as outer:
                info = outer.getmember(wheel['member'])
                assert info.isfile() and info.size <= 128 * 1024 * 1024
                stream = outer.extractfile(info)
                assert stream is not None
                content = stream.read()
        filename = pathlib.PurePosixPath(wheel['member']).name
    else:
        content, filename = path.read_bytes(), path.name
    assert hashlib.sha256(content).hexdigest() == wheel['digest']
    name, version, build, wheel_tags = parse_wheel_filename(filename)
    name = canonicalize_name(name)
    assert name in versions and version == versions[name]
    assert profile is not None or wheel_tags & tags
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        members, seen, total = archive.infolist(), set(), 0
        assert 1 <= len(members) <= 4096
        for member in members:
            parts = member.filename.rstrip('/').split('/')
            assert all(p not in ('', '.', '..') for p in parts)
            assert '\\\\' not in member.filename and ':' not in member.filename
            assert member.filename.casefold() not in seen and not member.flag_bits & 1
            seen.add(member.filename.casefold())
            mode = member.external_attr >> 16
            assert stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR)
            total += member.file_size
            assert member.file_size <= 128 * 1024 * 1024 and total <= 512 * 1024 * 1024
        records = [m for m in members if m.filename.count('/') == 1
                   and m.filename.endswith('.dist-info/METADATA')]
        assert len(records) == 1 and records[0].file_size <= 1024 * 1024
        value = email.parser.BytesParser().parsebytes(archive.read(records[0]))
        assert len(value.get_all('Name', [])) == len(value.get_all('Version', [])) == 1
        assert canonicalize_name(value['Name']) == name and Version(value['Version']) == version
        python = value.get_all('Requires-Python', [])
        assert len(python) <= 1
        if python:
            assert Version(environment['python_full_version']) in SpecifierSet(python[0])
        requirements = value.get_all('Requires-Dist', [])
        assert len(requirements) <= 4096
        metadata[name] = tuple(Requirement(text) for text in requirements)
        declared = value.get_all('Provides-Extra', [])
        assert len(declared) <= 64
        declared_extras[name] = {canonicalize_name(extra) for extra in declared}
extras = {canonicalize_name(w['distribution']):
          {canonicalize_name(extra) for extra in w.get('extras', ())} for w in selected}
pending, checked = list(versions), set()
while pending:
    name = pending.pop()
    # One declaration gate for roots and every newly contributed transitive extra.
    assert extras[name] <= declared_extras[name]
    key = (name, tuple(sorted(extras[name])))
    if key in checked:
        continue
    checked.add(key)
    for requirement in metadata[name]:
        assert requirement.url is None
        active = requirement.marker is None or any(
            _evaluate_marker(requirement.marker, environment, extra)
            for extra in ('', *sorted(extras[name])))
        if not active:
            continue
        dependency = canonicalize_name(requirement.name)
        assert dependency in versions and versions[dependency] in requirement.specifier
        added = {canonicalize_name(extra) for extra in requirement.extras} - extras[dependency]
        if added:
            extras[dependency].update(added)
            pending.append(dependency)
print('verified-wheel-metadata-closure')
"""


class _InstallationIOError(c.ContractError):
    """Safe bounded native failure distinct from protected-root ownership."""

    def __init__(self, reason: str) -> None:
        super().__init__()
        self.io_reason = reason
        self.cleanup_errors: tuple[c.SafeError, ...] = ()


@contextmanager
def _installation_io(resource_sha256: str = "0" * 64) -> Iterator[None]:
    from netops.ansible.artifact_cleanup import _storage_io

    try:
        with _storage_io("installation", "install-files", resource_sha256):
            yield
    except OSError as exc:
        supplied = exc.args[0] if exc.args else ""
        reason = supplied if type(supplied) is str and re.fullmatch(
            r"(?:installation|protected-storage)-[a-z-]{1,64}", supplied,
        ) else "installation-io-failed"
        from netops.ansible.artifact_cleanup import _carry_storage_diagnostics, cleanup_errors

        wrapped = _InstallationIOError(reason)
        _carry_storage_diagnostics(exc, wrapped)
        wrapped.cleanup_errors = cleanup_errors(exc)
        raise wrapped from None


@dataclass(frozen=True)
class _Wheel:
    """Exact wheel already present in the reviewed managed archive tree."""

    member: str
    distribution: str
    version: str
    digest: str

    def __post_init__(self) -> None:
        from ._managed import _parts

        _parts(self.member)
        if (
            not self.member.endswith(".whl") or _NAME.fullmatch(self.distribution) is None
            or _VERSION.fullmatch(self.version) is None
        ):
            raise c.ContractError()
        c.sha256(self.digest)


@dataclass(frozen=True)
class _Collection:
    """Pinned collection tarball, consumed by the installed offline Galaxy CLI."""

    member: str
    name: str
    version: str
    digest: str

    def __post_init__(self) -> None:
        from ._managed import _parts
        from ._probe_catalog import PROBE_SYMBOLS

        _parts(self.member)
        if (
            not self.member.endswith(".tar.gz") or self.name not in PROBE_SYMBOLS["collection"]
            or _VERSION.fullmatch(self.version) is None
        ):
            raise c.ContractError()
        c.sha256(self.digest)


@dataclass(frozen=True)
class _NativeFile:
    """One verified binary/library support member copied only into the owned tree."""

    member: str
    destination: str
    digest: str
    executable: bool = False

    def __post_init__(self) -> None:
        from ._managed import _parts

        _parts(self.member)
        _parts(self.destination)
        if self.destination.split("/")[0] not in ("tools", "libraries"):
            raise c.ContractError()
        c.sha256(self.digest)
        if type(self.executable) is not bool:
            raise c.ContractError()


@dataclass(frozen=True)
class _Tool:
    """A fixed consuming executable probe, never request-supplied argv or shell."""

    name: str
    destination: str

    def __post_init__(self) -> None:
        from ._managed import _parts
        from ._probe_catalog import TOOLS

        _parts(self.destination)
        if self.name not in TOOLS or self.destination.split("/")[0] != "tools":
            raise c.ContractError()


@dataclass(frozen=True)
class _Library:
    """Absolute owned native-library loading plus a fixed known symbol check."""

    name: str
    destination: str

    def __post_init__(self) -> None:
        from ._managed import _parts

        _parts(self.destination)
        if self.name not in ("pango", "gobject", "fontconfig", "harfbuzz") or (
            self.destination.split("/")[0] != "libraries"
        ):
            raise c.ContractError()


@dataclass(frozen=True)
class _InstallationSpec(c.FrozenObject):
    """Pinned existing compatible interpreter and complete offline wheel closure."""

    entries: tuple[tuple[str, c.Json], ...] = field(
        default=(), init=False, repr=False, compare=False,
    )
    python: str
    python_digest: str
    python_version: str
    platform: str
    wheels: tuple[_Wheel, ...]
    controller: bool = False
    collections: tuple[_Collection, ...] = ()
    native_files: tuple[_NativeFile, ...] = ()
    tools: tuple[_Tool, ...] = ()
    libraries: tuple[_Library, ...] = ()
    controller_installation: _InstallationSpec | None = None
    requested_extras: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def __post_init__(self) -> None:
        c.text(self.python)
        c.sha256(self.python_digest)
        if (
            not Path(self.python).is_absolute() or self.platform not in ("win32", "linux", "darwin")
            or re.fullmatch(r"\d+\.\d+\.\d+", self.python_version) is None
            or type(self.controller) is not bool or (self.controller and self.platform == "win32")
            or type(self.wheels) is not tuple or not 1 <= len(self.wheels) <= 256
        ):
            raise c.ContractError()
        names = []
        for wheel in self.wheels:
            if type(wheel) is not _Wheel:
                raise c.ContractError()
            wheel.__post_init__()
            names.append(_normalize(wheel.distribution))
        c.unique(tuple(names))
        c.unique(tuple(Path(w.member).name.casefold() for w in self.wheels))
        if (
            type(self.collections) is not tuple or len(self.collections) > 64
            or (self.collections and not self.controller)
        ):
            raise c.ContractError()
        for collection in self.collections:
            if type(collection) is not _Collection:
                raise c.ContractError()
            collection.__post_init__()
        c.unique(tuple(collection.name for collection in self.collections))
        if "netops-toolkit" not in names or (
            self.controller and "ansible-core" not in names
        ):
            raise c.ContractError()
        for values, expected in ((self.native_files, _NativeFile), (self.tools, _Tool),
                                 (self.libraries, _Library)):
            if type(values) is not tuple or len(values) > 256:
                raise c.ContractError()
            for value in values:
                if type(value) is not expected:
                    raise c.ContractError()
                value.__post_init__()
        c.unique(tuple(item.destination.casefold() for item in self.native_files))
        c.unique(tuple(tool.name for tool in self.tools))
        c.unique(tuple(library.name for library in self.libraries))
        destinations = {item.destination: item for item in self.native_files}
        for tool in self.tools:
            if tool.destination not in destinations or not destinations[tool.destination].executable:
                raise c.ContractError()
        for library in self.libraries:
            if library.destination not in destinations:
                raise c.ContractError()
        companion = self.controller_installation
        if companion is not None:
            if (
                type(companion) is not _InstallationSpec or self.controller
                or not companion.controller or companion.controller_installation is not None
                or self.platform not in ("linux", "darwin")
                or companion.platform != self.platform
            ):
                raise c.ContractError()
            companion.__post_init__()
        if type(self.requested_extras) is not tuple or len(self.requested_extras) > 256:
            raise c.ContractError()
        selected_names = []
        for pair in self.requested_extras:
            if type(pair) is not tuple or len(pair) != 2:
                raise c.ContractError()
            name, extras = pair
            if (
                name not in names or type(extras) is not tuple or not extras
                or len(extras) > 64
            ):
                raise c.ContractError()
            c.unique(extras)
            for extra in extras:
                if type(extra) is not str or _NAME.fullmatch(extra) is None:
                    raise c.ContractError()
            selected_names.append(name)
        c.unique(tuple(selected_names))
        encoded = c.public_object({
            item.name: c.wire(getattr(self, item.name)) for item in fields(self)
            if item.name != "entries" and not (
                item.name == "controller_installation" and companion is None
                or item.name == "requested_extras" and not self.requested_extras
            )
        })
        object.__setattr__(self, "entries", encoded.entries)

    def validate_members(self, manifest: ManagedGenerationManifest) -> None:
        """Reject absent/substituted wheels before any interpreter or file effect."""
        members = {member.path: member for member in manifest.members}
        for wheel in self.wheels:
            if wheel.member not in members or members[wheel.member].digest != wheel.digest:
                raise c.ContractError()
        for collection in self.collections:
            if (
                collection.member not in members
                or members[collection.member].digest != collection.digest
            ):
                raise c.ContractError()
        for item in self.native_files:
            if item.member not in members or members[item.member].digest != item.digest:
                raise c.ContractError()
        if self.controller_installation is not None:
            self.controller_installation.validate_members(manifest)

    def for_context(self, role: str) -> _InstallationSpec:
        """Select the separately bound consuming installation without role aliasing."""
        if role == "native" and not self.controller:
            return self
        if role == "controller":
            if self.controller:
                return self
            if self.controller_installation is not None:
                return self.controller_installation
        raise c.ContractError()


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _validate_collection(
    content: bytes, selected: _Collection, spec: _InstallationSpec,
    clock: c.ClockPort | None = None, cancel: c.CancelPort | None = None,
    deadline: float | None = None,
) -> None:
    """Bound tar members and verify the actual declared collection dependency closure."""
    from ._managed import _parts
    from .adapters import _version_matches

    supplied = (clock is not None, cancel is not None, deadline is not None)
    if any(supplied) and not all(supplied):
        raise c.ContractError()

    def check() -> None:
        if clock is not None and cancel is not None and deadline is not None:
            _check(clock, cancel, deadline)

    check()
    if len(content) > 128 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != selected.digest:
        raise c.ContractError()
    total, count = 0, 0
    seen: set[str] = set()
    metadata: dict | None = None
    with tarfile.open(fileobj=io.BytesIO(content), mode="r|gz") as archive:
        for member in archive:
            check()
            count += 1
            _parts(member.name)
            if (
                count > 4096 or member.name.casefold() in seen or member.pax_headers
                or not (member.isdir() or member.isfile()) or member.size > 128 * 1024 * 1024
            ):
                raise c.ContractError()
            seen.add(member.name.casefold())
            total += member.size
            if total > 512 * 1024 * 1024:
                raise c.ContractError()
            if member.name == "MANIFEST.json":
                if member.size > _LIMIT:
                    raise c.ContractError()
                stream = archive.extractfile(member)
                if stream is None:
                    raise c.ContractError()
                with stream:
                    metadata = json.loads(stream.read(_LIMIT + 1))
    check()
    if type(metadata) is not dict or type(metadata.get("collection_info")) is not dict:
        raise c.ContractError()
    info = metadata["collection_info"]
    if (
        info.get("namespace", "") + "." + info.get("name", "") != selected.name
        or info.get("version") != selected.version or type(info.get("dependencies")) is not dict
    ):
        raise c.ContractError()
    closure = {collection.name: collection.version for collection in spec.collections}
    for name, version in info["dependencies"].items():
        if name not in closure or (
            version != "*" and (type(version) is not str or not _version_matches(closure[name], version))
        ):
            raise c.ContractError()


def _check(clock: c.ClockPort, cancel: c.CancelPort, deadline: float) -> None:
    if cancel.is_cancelled():
        raise InterruptedError()
    if c.finite(clock.monotonic()) >= deadline:
        raise TimeoutError()


def _hash(path: Path, clock: c.ClockPort, cancel: c.CancelPort, deadline: float) -> str:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise c.ContractError()
    result = hashlib.sha256()
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise c.ContractError()
        while True:
            _check(clock, cancel, deadline)
            chunk = stream.read(65536)
            if not chunk:
                break
            result.update(chunk)
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
    ):
        raise c.ContractError()
    return result.hexdigest()


def _walk_error(error: OSError) -> NoReturn:
    raise error


def _match_installed_receipt(
    manifest: ManagedGenerationManifest, expected: object, actual: object,
) -> c.FrozenObject:
    """Require the admitted staged receipt, not a newly self-described changed tree."""
    pinned, observed = c.public_object(expected), c.public_object(actual)
    if (
        pinned != observed or observed.get("schema") != "i02-installed-generation-v1"
        or observed.get("generation_id") != manifest.generation_id
        or observed.get("descriptor_digest") != c.digest(manifest)
    ):
        raise c.ContractError()
    return observed


def _installed_parts(path: str) -> tuple[str, ...]:
    """Validate owned installed data, not artifact IDs or archive destinations.

    Setuptools installs ``script (dev).tmpl``. Interior ASCII parentheses and
    spaces are literal data names; separators, streams and platform aliases
    remain forbidden. Actual membership/ownership is independently rehashed.
    """
    if type(path) is not str or len(path) > 1024:
        raise c.ContractError()
    parts = tuple(path.split("/"))
    if len(parts) > 32:
        raise c.ContractError()
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}
    for part in parts:
        if (
            re.fullmatch(r"[A-Za-z0-9_. ()-]{1,160}", part) is None
            or part in (".", "..") or part.strip() != part or part.endswith(".")
            or part.split(".")[0].rstrip(" ").casefold() in reserved
        ):
            raise c.ContractError()
    return parts


def _tree(
    path: Path, clock: c.ClockPort, cancel: c.CancelPort, deadline: float, *, secure: bool = False,
) -> tuple[c.FrozenObject, ...]:
    def inspect(child: Path) -> c.FrozenObject:
        _installed_parts(child.relative_to(path).as_posix())
        _check(clock, cancel, deadline)
        info = child.lstat()
        directory = stat.S_ISDIR(info.st_mode)
        if not directory and not stat.S_ISREG(info.st_mode):
            raise c.ContractError()
        if os.name == "nt":
            from ._installation_files import _private_windows

            _private_windows(child, directory=directory)
        else:
            if info.st_uid != getattr(os, "getuid")():
                raise c.ContractError()
            if secure:
                child.chmod(0o700 if directory or info.st_mode & 0o111 else 0o600)
                info = child.lstat()
            if info.st_mode & 0o077:
                raise c.ContractError()
        size = 0 if directory else info.st_size
        if size > 256 * 1024 * 1024:
            raise c.ContractError()
        return c.public_object({
            "path": child.relative_to(path).as_posix(), "kind": "directory" if directory else "file",
            "digest": None if directory else _hash(child, clock, cancel, deadline),
            "size": size, "executable": bool(info.st_mode & 0o111),
        })

    members: list[c.FrozenObject] = []
    total = 0
    # Windows owner/ACL checks and file reads are independent. Bound both the
    # worker count and submitted batch, join all workers on every failure, and
    # retain the same original deadline and every per-member safety check.
    with ThreadPoolExecutor(max_workers=4 if os.name == "nt" else 1) as workers:
        for parent, directories, files in os.walk(path, followlinks=False, onerror=_walk_error):
            children = [Path(parent) / name for name in sorted((*directories, *files))
                        if (Path(parent) / name).relative_to(path).as_posix() != _RECEIPT]
            for offset in range(0, len(children), 64):
                for member in workers.map(inspect, children[offset:offset + 64]):
                    total += c.counter(member["size"])
                    if len(members) >= 8192 or total > 1024 * 1024 * 1024:
                        raise c.ContractError()
                    members.append(member)
    c.unique(tuple(str(member["path"]).casefold() for member in members))
    return tuple(sorted(members, key=lambda member: str(member["path"])))


class _OfflineInstallation:
    """Create once, verify exactly; never clear, adopt or sweep a partial tree."""

    def __init__(
        self, root: ProtectedRoot, *, controller: bool = False,
        _source_guard: Callable[[], None] | None = None,
    ) -> None:
        if type(controller) is not bool:
            raise c.ContractError()
        self.root, self._controller = root, controller
        self._source_guard = _source_guard

    def _guard(self, clock: c.ClockPort, cancel: c.CancelPort, deadline: float) -> None:
        if self._source_guard is not None:
            self._source_guard()
            _check(clock, cancel, deadline)

    def _run(
        self, command: tuple[str, ...], cwd: Path, clock: c.ClockPort,
        cancel: c.CancelPort, deadline: float, *, accepted: tuple[int, ...] = (0,),
    ) -> bytes:
        if self._source_guard is not None:
            return _run(
                command, cwd, clock, cancel, deadline, accepted=accepted,
                _source_guard=self._source_guard,
            )
        if accepted != (0,):
            return _run(command, cwd, clock, cancel, deadline, accepted=accepted)
        return _run(command, cwd, clock, cancel, deadline)

    def path(self, manifest: ManagedGenerationManifest) -> Path:
        """Stable final location: venv absolute script paths survive activation."""
        target = Path(self.root.path) / ("installation-" + c.digest(manifest.generation_id))
        return target / "controller" if self._controller else target

    def _spec(self, manifest: ManagedGenerationManifest) -> _InstallationSpec:
        spec = manifest.installation
        if spec is None:
            raise c.ContractError()
        if self._controller:
            if spec.controller_installation is None:
                raise c.ContractError()
            return spec.controller_installation
        return spec

    def python(self, manifest: ManagedGenerationManifest) -> Path:
        """Return the fixed owned interpreter, not PATH or the current active alias."""
        return self.path(manifest) / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    def install(
        self, manifest: ManagedGenerationManifest, assets: Path,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> None:
        """Install verified wheels offline under the handler's original stage permit."""
        self._guard(clock, cancel, deadline)
        spec = self._spec(manifest)
        spec.__post_init__()
        spec.validate_members(manifest)
        if spec.platform != sys.platform:
            raise c.ContractError()
        python = Path(spec.python)
        # A symlink-selected or modified base interpreter is not a pinned source.
        if _hash(python, clock, cancel, deadline) != spec.python_digest:
            raise c.ContractError()
        version = self._run(
            (spec.python, "-I", "-B", "-c",
             "import platform; print(platform.python_version())"),
            assets, clock, cancel, deadline,
        ).decode("ascii").strip()
        if version != spec.python_version or tuple(map(int, version.split("."))) < (3, 9, 0):
            raise c.ContractError()
        for wheel in spec.wheels:
            if _hash(assets / wheel.member, clock, cancel, deadline) != wheel.digest:
                raise c.ContractError()
        # Validate actual pinned metadata, compatible wheel tags, Python ranges
        # and recursive active requirements before creating a venv or invoking
        # pip installation. --no-deps below is not a dependency resolver.
        selected = [{
            "path": str(assets / wheel.member), "distribution": wheel.distribution,
            "version": wheel.version, "digest": wheel.digest,
            "extras": dict(spec.requested_extras).get(_normalize(wheel.distribution), ()),
        } for wheel in spec.wheels]
        self._run((spec.python, "-I", "-B", "-c", _WHEEL_METADATA, json.dumps(selected)),
             assets, clock, cancel, deadline)
        for collection in spec.collections:
            source = assets / collection.member
            if _hash(source, clock, cancel, deadline) != collection.digest:
                raise c.ContractError()
            _validate_collection(source.read_bytes(), collection, spec, clock, cancel, deadline)
        target = self.path(manifest)
        with _root(self.root), _installation_io(c.digest((
            self.root.path, self.root.device, self.root.inode, target.name,
        ))):
            _check(clock, cancel, deadline)
            self._guard(clock, cancel, deadline)
            if os.name == "nt":
                from ._installation_files import _create_private_tree

                _create_private_tree(target, _source_guard=self._source_guard)
            else:
                target.mkdir(mode=0o700)  # exclusive; partial and unknown trees block
            self._run((spec.python, "-I", "-B", "-c", _VENV, str(target)),
                 target, clock, cancel, deadline)
            # POSIX venv creates this precise convenience link even with copies.
            link = target / "lib64"
            if link.is_symlink() and os.readlink(link) == "lib":
                self._guard(clock, cancel, deadline)
                link.unlink()
            requirements = target / "wheel-lock.txt"
            self._guard(clock, cancel, deadline)
            requirements.write_text("".join(
                f"{wheel.distribution}"
                + ("[" + ",".join(dict(spec.requested_extras)[_normalize(wheel.distribution)])
                   + "]" if _normalize(wheel.distribution) in dict(spec.requested_extras) else "")
                + f"=={wheel.version} --hash=sha256:{wheel.digest}\n"
                for wheel in spec.wheels
            ), encoding="utf-8")
            wheelhouse = target / "wheelhouse"
            # Windows' mkdir(0700) synthesizes a different DACL. Inherit the
            # newly created owner-only tree instead; never repair an ACL.
            self._guard(clock, cancel, deadline)
            wheelhouse.mkdir(mode=0o777 if os.name == "nt" else 0o700)
            # Copy only locked wheels, never pip's mutable/global cache or links.
            for wheel in spec.wheels:
                source = assets / wheel.member
                data = source.read_bytes()
                if hashlib.sha256(data).hexdigest() != wheel.digest:
                    raise c.ContractError()
                self._guard(clock, cancel, deadline)
                with (wheelhouse / source.name).open("xb") as stream:
                    stream.write(data)
            managed = str(self.python(manifest))
            self._run((managed, "-I", "-B", "-m", "pip", "--isolated",
                  "--disable-pip-version-check", "install", "--no-index", "--no-cache-dir",
                  "--no-deps", "--only-binary=:all:", "--require-hashes",
                  "--find-links", str(wheelhouse), "--requirement", str(requirements)),
                 target, clock, cancel, deadline)
            if spec.collections:
                collections = target / "collections"
                self._guard(clock, cancel, deadline)
                collections.mkdir(mode=0o700)
                for collection in spec.collections:
                    source = assets / collection.member
                    if _hash(source, clock, cancel, deadline) != collection.digest:
                        raise c.ContractError()
                    _validate_collection(source.read_bytes(), collection, spec,
                                         clock, cancel, deadline)
                    self._run((managed, "-I", "-B", "-m", "ansible.cli.galaxy",
                          "collection", "install", str(source), "--offline", "--no-deps",
                          "--collections-path", str(collections)),
                         target, clock, cancel, deadline)
            for item in spec.native_files:
                from ._managed import ProtectedGenerationFiles, _parts

                source = assets / item.member
                data = source.read_bytes()
                if hashlib.sha256(data).hexdigest() != item.digest:
                    raise c.ContractError()
                # Use the same exclusive protected writes as archive staging;
                # no path-based mkdir/open through an injected parent link.
                port = ProtectedGenerationFiles(self.root)
                parts = _parts(item.destination)
                with _directory(str(target)) as installed, port._parents(
                    installed, parts[:-1], True, _source_guard=self._source_guard,
                ) as parent:
                    self._guard(clock, cancel, deadline)
                    port._write(parent, parts[-1], data, item.executable)
            if spec.controller_installation is not None:
                self._guard(clock, cancel, deadline)
                _OfflineInstallation(
                    self.root, controller=True, _source_guard=self._source_guard,
                ).install(
                    manifest, assets, clock, cancel, deadline,
                )
            self.consume(manifest, clock, cancel, deadline)
            members = _tree(target, clock, cancel, deadline, secure=True)
            receipt = c.public_object({
                "schema": "i02-installed-generation-v1", "generation_id": manifest.generation_id,
                "descriptor_digest": c.digest(manifest), "python_member":
                self.python(manifest).relative_to(target).as_posix(),
                "manifest": members, "installation_digest": c.digest(members),
            })
            content = c.canonical_bytes(receipt)
            if len(content) > _LIMIT:
                raise c.ContractError()
            _check(clock, cancel, deadline)
            self._guard(clock, cancel, deadline)
            with (target / _RECEIPT).open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            if os.name != "nt":
                self._guard(clock, cancel, deadline)
                (target / _RECEIPT).chmod(0o600)

    def consume(
        self, manifest: ManagedGenerationManifest, clock: c.ClockPort,
        cancel: c.CancelPort, deadline: float,
    ) -> None:
        """Run actual closure/CLI/action imports in the installed consuming context."""
        spec = self._spec(manifest)
        managed, target = str(self.python(manifest)), self.path(manifest)
        self._run((managed, "-I", "-B", "-m", "pip", "--isolated",
              "--disable-pip-version-check", "check"), target, clock, cancel, deadline)
        expected = {_normalize(w.distribution): w.version for w in spec.wheels}
        raw = self._run((managed, "-I", "-B", "-c", _CLOSURE, json.dumps(expected)),
                   target, clock, cancel, deadline)
        observation = json.loads(raw)
        if (
            os.path.normcase(observation["python"]) != os.path.normcase(managed)
            or os.path.normcase(observation["prefix"]) != os.path.normcase(str(target))
        ):
            raise c.ContractError()
        self._run((managed, "-I", "-B", "-m", "netops", "--help"),
             target, clock, cancel, deadline)
        from ._probe_catalog import TOOLS

        for tool in spec.tools:
            # Validate every consuming path against the same descriptor/file
            # hashes; discovery on PATH alone cannot establish installed proof.
            native = next(item for item in spec.native_files if item.destination == tool.destination)
            path = target / tool.destination
            if _hash(path, clock, cancel, deadline) != native.digest:
                raise c.ContractError()
            output = self._run(
                (str(path), *TOOLS[tool.name][1:]), target, clock, cancel, deadline,
                accepted=(1,) if tool.name == "rm" and sys.platform == "darwin" else (0,),
            )
            if tool.name == "rm" and re.search(rb"\busage:\s+(?:\S*[/\\])?rm", output,
                                              re.IGNORECASE) is None:
                raise c.ContractError()
        symbols = {"pango": "pango_version", "gobject": "g_type_init",
                   "fontconfig": "FcGetVersion", "harfbuzz": "hb_version_string"}
        for library in spec.libraries:
            native = next(item for item in spec.native_files if item.destination == library.destination)
            path = target / library.destination
            if _hash(path, clock, cancel, deadline) != native.digest:
                raise c.ContractError()
            self._run((managed, "-I", "-B", "-c",
                  "import ctypes,sys; lib=ctypes.CDLL(sys.argv[1]); "
                  "fn=getattr(lib,sys.argv[2]); "
                  "fn.restype=ctypes.c_char_p if sys.argv[2]=='hb_version_string' "
                  "else (None if sys.argv[2]=='g_type_init' else ctypes.c_int); "
                  "value=fn(); assert value is None if sys.argv[2]=='g_type_init' else bool(value)",
                  str(path), symbols[library.name]),
                 target, clock, cancel, deadline)
        if spec.controller:
            modules: tuple[str, ...] = (
                "ansible.cli.playbook", "ansible.cli.inventory", "ansible.cli.vault",
            )
            if "molecule" in expected:
                modules = (*modules, "molecule")
            for module in modules:
                self._run((managed, "-I", "-B", "-m", module, "--version"),
                     target, clock, cancel, deadline)
            for collection in spec.collections:
                raw = self._run((managed, "-I", "-B", "-m", "ansible.cli.galaxy",
                                "collection", "list", collection.name, "--format", "json",
                                "--collections-path", str(target / "collections")),
                               target, clock, cancel, deadline)
                entries = json.loads(raw)
                observed = [value[collection.name]["version"] for value in entries.values()
                                if collection.name in value]
                if observed != [collection.version]:
                        raise c.ContractError()
            self._run((managed, "-I", "-B", "-c",
                  "from netops.ansible.action_plugins.netops_workflow import NetopsWorkflowAction;"
                  "from ansible.plugins.action import ActionBase;"
                  "assert issubclass(NetopsWorkflowAction, ActionBase)"),
                 target, clock, cancel, deadline)
        if spec.controller_installation is not None:
            self._guard(clock, cancel, deadline)
            _OfflineInstallation(
                self.root, controller=True, _source_guard=self._source_guard,
            ).consume(
                manifest, clock, cancel, deadline,
            )

    def verify(
        self, manifest: ManagedGenerationManifest, clock: c.ClockPort,
        cancel: c.CancelPort, deadline: float,
    ) -> c.FrozenObject:
        """Rehash exact owned output before consuming it; a receipt alone is insufficient."""
        return self._verify(manifest, clock, cancel, deadline, functional=True)

    def _verify(
        self, manifest: ManagedGenerationManifest, clock: c.ClockPort,
        cancel: c.CancelPort, deadline: float, *, functional: bool,
    ) -> c.FrozenObject:
        """Rehash all output; consume only when establishing functional evidence."""
        target = self.path(manifest)
        with _root(self.root):
            receipt_path = target / _RECEIPT
            if receipt_path.lstat().st_size > _LIMIT:
                raise c.ContractError()
            if not stat.S_ISDIR(target.lstat().st_mode):
                raise c.ContractError()
            # Reject links/aliases before opening the record.
            _hash(receipt_path, clock, cancel, deadline)
            receipt = c.public_object(json.loads(receipt_path.read_bytes()))
            members = _tree(target, clock, cancel, deadline)
            if (
                set(receipt) != {"schema", "generation_id", "descriptor_digest", "python_member",
                                 "manifest", "installation_digest"}
                or receipt["schema"] != "i02-installed-generation-v1"
                or receipt["generation_id"] != manifest.generation_id
                or receipt["descriptor_digest"] != c.digest(manifest)
                or receipt["manifest"] != members
                or receipt["installation_digest"] != c.digest(members)
                or receipt["python_member"] != self.python(manifest).relative_to(target).as_posix()
            ):
                raise c.ContractError()
            if functional:
                self.consume(manifest, clock, cancel, deadline)
                if _tree(target, clock, cancel, deadline) != members:
                    raise c.ContractError()
            if self._spec(manifest).controller_installation is not None:
                _OfflineInstallation(
                    self.root, controller=True, _source_guard=self._source_guard,
                )._verify(
                    manifest, clock, cancel, deadline, functional=False,
                )
            _check(clock, cancel, deadline)
            return receipt
