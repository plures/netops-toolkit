"""Fixed bounded offline wheel/sdist producer for trusted private composition.

This host is not reachable from setup request JSON. Its constructor's sealed
inputs and qualification references are supplied by the owning build host,
not inferred from a cache directory, archive receipt or successful exit code.
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import sys
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from netops.ansible import artifact_platform as storage
from netops.ansible import contracts as c
from netops.ansible.artifact_cleanup import teardown
from netops.ansible.artifacts import ProtectedRoot, _private, _read_file, _root, _write_file
from netops.ansible.policy.authorization import AuthorizationError

from ._assets import _MonotonicClock
from ._installation_process import _run
from ._owned_source import _ProducedBuild

__all__: tuple[str, ...] = ()
_LIMIT = 128 * 1024 * 1024
_LEDGER = "owned-build-ledger.json"
_BUILD_BACKEND = """
import importlib.machinery, json, os, pathlib, re, sys, traceback, zipfile
wheel, source, output = sys.argv[1:]
wheel = pathlib.Path(wheel).as_posix()
sys.path.insert(0, wheel)
os.chdir(source)
try:
    # Wheel ZIPs need not contain directory entries. Python's zip importer
    # cannot discover those implicit namespace directories. Resolve only
    # directories actually present in this exact qualified wheel. Executable
    # child modules still load from its original bytes, not a module stub.
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    directories = {name.rsplit('/', index)[0] for name in names
                   for index in range(1, name.count('/') + 1)}
    class VendoredNamespaces:
        def find_spec(self, fullname, path=None, target=None):
            parents = path if path is not None else (wheel, wheel + '/setuptools/_vendor')
            for parent in parents:
                parent = parent.replace(chr(92), '/')
                if parent != wheel and not parent.startswith(wheel + '/'):
                    continue
                directory = (parent[len(wheel):].strip('/') + '/' +
                             fullname.rsplit('.', 1)[-1]).lstrip('/')
                if directory in directories and directory + '/__init__.py' not in names:
                    spec = importlib.machinery.ModuleSpec(fullname, loader=None, is_package=True)
                    spec.submodule_search_locations = [wheel + '/' + directory]
                    return spec
            return None
    sys.meta_path.append(VendoredNamespaces())
    from setuptools import build_meta
    assert pathlib.Path('pyproject.toml').is_file()
    # Use the actual backend's fixed wheel/sdist commands in the already
    # exclusive inheritable-owner-only output root. PEP517's temporary-dir
    # wrapper requests mode 0700, which Store Python maps to a different
    # package ACL; never repair or adopt those resulting files' ACLs.
    sys.argv = ['setup.py', 'bdist_wheel', '--dist-dir', output,
                'sdist', '--dist-dir', output]
    build_meta._BACKEND.run_setup()
except BaseException as error:
    name = getattr(error, 'name', None)
    report = {
        'type': type(error).__name__, 'errno': getattr(error, 'errno', None),
        'winerror': getattr(error, 'winerror', None),
        'missing_module': name if type(name) is str and
            re.fullmatch(r'[A-Za-z0-9_.]{1,128}', name) else None,
        'frames': [(pathlib.Path(frame.filename).name, frame.lineno, frame.name)
                   for frame in traceback.extract_tb(error.__traceback__)],
    }
    pathlib.Path(output, 'build-failure.json').write_text(json.dumps(report), encoding='utf-8')
    raise SystemExit(1)
"""


def _check(clock: c.ClockPort, cancel: c.CancelPort, deadline: float) -> None:
    if cancel.is_cancelled():
        raise InterruptedError()
    if c.finite(clock.monotonic()) >= deadline:
        raise TimeoutError()


@dataclass(frozen=True)
class _Input:
    """One explicitly known input; qualification is independent of its own hash."""

    path: str
    digest: str
    size: int
    qualification_ref: str

    def __post_init__(self) -> None:
        from ._managed import _parts

        _parts(self.path)
        c.sha256(self.digest)
        c.sha256(self.qualification_ref)
        if c.counter(self.size) > _LIMIT:
            raise c.ContractError()


@dataclass(frozen=True)
class _ToolchainFile:
    """Pinned existing interpreter/toolchain file; never an archive masquerade."""

    path: str
    digest: str
    qualification_ref: str

    def __post_init__(self) -> None:
        if not Path(self.path).is_absolute() or ".." in Path(self.path).parts:
            raise c.ContractError()
        c.sha256(self.digest)
        c.sha256(self.qualification_ref)


@dataclass(frozen=True)
class _BuildSpec:
    """Trusted constructor input, intentionally no public descriptor decoder."""

    source: tuple[_Input, ...]
    cache: tuple[_Input, ...]
    toolchain: tuple[_ToolchainFile, ...]
    python: str
    python_version: str
    platform: str
    context_digest: str
    consuming_contexts: tuple[str, ...]

    def __post_init__(self) -> None:
        c.sha256(self.context_digest)
        c.unique(self.consuming_contexts)
        for value in self.consuming_contexts:
            c.sha256(value)
        for values, expected in ((self.source, _Input), (self.cache, _Input),
                                 (self.toolchain, _ToolchainFile)):
            if type(values) is not tuple or not 1 <= len(values) <= 8192:
                raise c.ContractError()
            c.unique(tuple(item.path for item in values))
            for item in values:
                if type(item) is not expected:
                    raise c.ContractError()
                item.__post_init__()
        if (
            self.python not in (
                sys.executable,
                str(Path(sys.base_prefix) / "python.exe") if os.name == "nt" else sys.executable,
            ) or self.platform != sys.platform
            or self.python_version != ".".join(str(item) for item in sys.version_info[:3])
            or not any(item.path == self.python for item in self.toolchain)
            or any(not item.path.endswith(".whl") for item in self.cache)
            or any(item.path.startswith("netops_toolkit-") for item in self.cache)
            or sum(Path(item.path).name.startswith("setuptools-") for item in self.cache) != 1
            or "pyproject.toml" not in tuple(item.path for item in self.source)
            or "netops/__init__.py" not in tuple(item.path for item in self.source)
        ):
            raise c.ContractError()


@contextmanager
def _parent(root: int, parts: tuple[str, ...], *, create: bool = False) -> Iterator[int]:
    opened: list[int] = []
    current = root
    try:
        for part in parts:
            if create:
                try:
                    storage.mkdir(current, part)
                except FileExistsError:
                    pass
            current = storage.open_directory(current, part)
            opened.append(current)
            _private(storage.info(current), True)
        yield current
    finally:
        for handle in reversed(opened):
            with teardown():
                storage.close(handle)


def _identity(info: os.stat_result) -> tuple[str, str, int]:
    # Native Windows file indexes are uint64, not JSON interoperable int53
    # counters. Preserve every bit rather than truncate or weaken the encoder.
    return str(info.st_dev), str(info.st_ino), info.st_size


def _write_member(parent: int, name: str, content: bytes) -> None:
    """Use managed member grammar, not the unrelated artifact logical-ID grammar."""
    from ._managed import ProtectedGenerationFiles, _parts

    if len(_parts(name)) != 1:
        raise c.ContractError()
    ProtectedGenerationFiles._write(parent, name, content, False)


def _read_member(parent: int, name: str, limit: int) -> bytes:
    from ._managed import _parts

    if len(_parts(name)) != 1:
        raise c.ContractError()
    if os.name == "nt":
        return storage.windows().read(parent, name, limit)
    fd = os.open(name, os.O_RDONLY | int(getattr(os, "O_NOFOLLOW"))
                 | int(getattr(os, "O_NONBLOCK")), dir_fd=parent)
    try:
        before = os.fstat(fd)
        _private(before, False)
        if before.st_size > limit:
            raise AuthorizationError()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            value = stream.read(limit + 1)
        after = os.fstat(fd)
        _private(after, False)
        if (
            _identity(before) != _identity(after) or len(value) != before.st_size
            or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise AuthorizationError()
        return value
    finally:
        os.close(fd)


def _external(item: _ToolchainFile) -> c.FrozenObject:
    """Never follow a substituted interpreter, tool file or reparse ancestor."""
    path = Path(item.path)
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise AuthorizationError()
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _LIMIT:
        raise AuthorizationError()
    # Pin a no-follow file handle where supported and bind its identity to the
    # path before and after the read. No executable supplied by a request runs.
    fd = os.open(path, os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0)))
    try:
        opened = os.fstat(fd)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            value = stream.read(_LIMIT + 1)
        finished = os.fstat(fd)
        after = path.lstat()
        if (
            _identity(before) != _identity(opened) or _identity(after) != _identity(opened)
            or _identity(finished) != _identity(opened)
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or opened.st_mtime_ns != finished.st_mtime_ns
            or opened.st_ctime_ns != finished.st_ctime_ns
            or len(value) != opened.st_size or hashlib.sha256(value).hexdigest() != item.digest
        ):
            raise AuthorizationError()
    finally:
        os.close(fd)
    return c.public_object({**dict(c.public_object(c.wire(item))), "identity": _identity(opened)})


class _OfflineBuildHost:
    """Own build execution and a create-only producer ledger under pinned roots."""

    def __init__(
        self, root: ProtectedRoot, consuming_root: ProtectedRoot, spec: _BuildSpec,
        *, ledger_digest: str | None = None,
    ) -> None:
        if type(root) is not ProtectedRoot or type(consuming_root) is not ProtectedRoot:
            raise c.ContractError()
        spec.__post_init__()
        if root.path == consuming_root.path:
            raise c.ContractError()
        if ledger_digest is not None:
            c.sha256(ledger_digest)
        self.root, self.consuming_root, self.spec = root, consuming_root, spec
        self._ledger_digest = ledger_digest
        self._identity = c.digest((
            "trusted-private-offline-build-host-v1", spec,
            (root.path, str(root.device), str(root.inode)),
            (consuming_root.path, str(consuming_root.device), str(consuming_root.inode)),
        ))

    @property
    def identity(self) -> str:
        """Return a stable exact producer/root/input identity, not a trust boolean."""
        return self._identity

    def _inputs(
        self, directory: str, inputs: tuple[_Input, ...],
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> tuple[tuple[c.FrozenObject, bytes], ...]:
        from ._managed import _parts

        result = []
        expected: dict[tuple[str, ...], set[str]] = {(): set()}
        with _root(self.root) as root, _parent(root, (directory,)) as base:
            for item in inputs:
                _check(clock, cancel, deadline)
                parts = _parts(item.path)
                for index, name in enumerate(parts):
                    expected.setdefault(parts[:index], set()).add(name)
                with _parent(base, parts[:-1]) as parent:
                    value = _read_member(parent, parts[-1], item.size)
                    info = (Path(self.root.path) / directory / item.path).lstat()
                    if len(value) != item.size or hashlib.sha256(value).hexdigest() != item.digest:
                        raise AuthorizationError()
                    result.append((c.public_object({
                        **dict(c.public_object(c.wire(item))), "identity": _identity(info),
                    }), value))
            for parts, names in expected.items():
                _check(clock, cancel, deadline)
                with _parent(base, parts) as parent:
                    if set(storage.names(parent)) != names:
                        raise AuthorizationError()
        return tuple(result)

    def _facts(
        self, clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> dict:
        _check(clock, cancel, deadline)
        with _root(self.root), _root(self.consuming_root):
            pass
        sources = self._inputs("source", self.spec.source, clock, cancel, deadline)
        caches = self._inputs("cache", self.spec.cache, clock, cancel, deadline)
        tools = []
        for item in self.spec.toolchain:
            _check(clock, cancel, deadline)
            tools.append(_external(item))
        executable = next(item for item in tools if item["path"] == self.spec.python)
        return {
            "source_seal": c.digest(tuple(item for item, _ in sources)),
            "build_inputs": tuple(item for item, _ in sources),
            "cache_inputs": tuple(item for item, _ in caches), "toolchain": tuple(tools),
            "interpreter": {
                **dict(executable), "version": self.spec.python_version,
                "platform": self.spec.platform,
            },
            "root": (self.root.path, str(self.root.device), str(self.root.inode)),
            "consuming_root": (self.consuming_root.path, str(self.consuming_root.device),
                               str(self.consuming_root.inode)),
            "context_digest": self.spec.context_digest,
            "consuming_contexts": self.spec.consuming_contexts,
        }

    def produce(
        self, clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> str:
        """Execute a fresh offline build; never adopt a preexisting output or ledger."""
        from ._managed import _parts

        clock = _MonotonicClock(clock)
        deadline = min(c.finite(deadline), c.checked_deadline(clock.monotonic(), 300.0))
        before = self._facts(clock, cancel, deadline)
        sources = self._inputs("source", self.spec.source, clock, cancel, deadline)
        with _root(self.root) as root:
            if set(storage.names(root)) != {"source", "cache"}:
                raise AuthorizationError()
            if os.name == "nt":
                from ._installation_files import _create_private_tree

                # Only NEW objects: child processes need inherited owner-only
                # access for their own build products. Never repair an ACL.
                _create_private_tree(Path(self.root.path) / "work")
                _create_private_tree(Path(self.root.path) / "build-output")
            else:
                storage.mkdir(root, "work")
                storage.mkdir(root, "build-output")
            storage.mkdir(root, "output")
            for item, value in sources:
                _check(clock, cancel, deadline)
                with _parent(root, ("work", *_parts(c.text(item["path"]))[:-1]), create=True) as parent:
                    _write_member(parent, _parts(c.text(item["path"]))[-1], value)
        _run((
            self.spec.python, "-I", "-S", "-B", "-c", _BUILD_BACKEND,
            str(Path(self.root.path) / "cache" / next(
                item.path for item in self.spec.cache
                if Path(item.path).name.startswith("setuptools-")
            )), str(Path(self.root.path) / "work"),
            str(Path(self.root.path) / "build-output"),
        ), Path(self.root.path) / "work", clock, cancel, deadline)
        if before != self._facts(clock, cancel, deadline):
            raise AuthorizationError()
        self._seal_outputs(clock, cancel, deadline)
        outputs, content, members = self._assemble(clock, cancel, deadline)
        receipt = c.public_object({
            "schema": "owned-offline-build-v1", "producer_id": self.identity, **before,
            "operation": "offline-wheel-sdist-and-cache-assembly", "exit_code": 0,
            "outputs": outputs, "members": members,
            "archive_digest": hashlib.sha256(content).hexdigest(), "archive_size": len(content),
        })
        _check(clock, cancel, deadline)
        with _root(self.root) as root:
            _write_file(root, _LEDGER, c.canonical_bytes(receipt))
            storage.sync(root)
        self._ledger_digest = c.digest(receipt)
        return self._ledger_digest

    def _seal_outputs(
        self, clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> None:
        """Copy actual joined-process products into exclusive protected ledger members."""
        with _root(self.root) as root, _parent(root, ("build-output",)) as built, _parent(
            root, ("output",),
        ) as sealed:
            names = sorted(storage.names(built))
            if len(names) != 2:
                raise AuthorizationError()
            for name in names:
                _check(clock, cancel, deadline)
                if (
                    not name.startswith("netops_toolkit-") or "/" in name or "\\" in name
                    or not name.endswith((".whl", ".tar.gz"))
                ):
                    raise AuthorizationError()
                path = Path(self.root.path) / "build-output" / name
                if os.name == "nt":
                    from ._installation_files import _private_windows

                    _private_windows(path, directory=False)
                before = path.lstat()
                if (
                    not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size > _LIMIT
                    or getattr(before, "st_file_attributes", 0) & 0x400
                ):
                    raise AuthorizationError()
                fd = os.open(path, os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0)))
                try:
                    opened = os.fstat(fd)
                    with os.fdopen(fd, "rb", closefd=False) as stream:
                        value = stream.read(_LIMIT + 1)
                    after = path.lstat()
                    if (
                        _identity(before) != _identity(opened) or _identity(after) != _identity(opened)
                        or before.st_mtime_ns != after.st_mtime_ns
                        or before.st_ctime_ns != after.st_ctime_ns or len(value) != opened.st_size
                    ):
                        raise AuthorizationError()
                    if os.name == "nt":
                        _private_windows(path, directory=False)
                    else:
                        _private(opened, False)
                    _write_member(sealed, name, value)
                finally:
                    os.close(fd)
            storage.sync(sealed)

    def _assemble(
        self, clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> tuple[tuple[c.FrozenObject, ...], bytes, tuple[c.FrozenObject, ...]]:
        cache = self._inputs("cache", self.spec.cache, clock, cancel, deadline)
        values: dict[str, bytes] = {c.text(item["path"]): value for item, value in cache}
        outputs = []
        with _root(self.root) as root, _parent(root, ("output",)) as output:
            names = sorted(storage.names(output))
            if len(names) != 2 or sum(name.endswith(".whl") for name in names) != 1 or sum(
                name.endswith(".tar.gz") for name in names
            ) != 1:
                raise AuthorizationError()
            for name in names:
                _check(clock, cancel, deadline)
                if not name.startswith("netops_toolkit-") or "/" in name or "\\" in name:
                    raise AuthorizationError()
                value = _read_member(output, name, _LIMIT)
                info = (Path(self.root.path) / "output" / name).lstat()
                outputs.append(c.public_object({
                    "path": name, "digest": hashlib.sha256(value).hexdigest(), "size": len(value),
                    "identity": _identity(info),
                }))
                if name.endswith(".whl"):
                    if name in values:
                        raise AuthorizationError()
                    expected = {item.path: item for item in self.spec.source
                                if item.path.startswith("netops/")}
                    with zipfile.ZipFile(io.BytesIO(value)) as wheel:
                        names = [entry.filename for entry in wheel.infolist()
                                 if entry.filename.startswith("netops/") and not entry.is_dir()]
                        if len(names) != len(set(names)) or set(names) != set(expected):
                            raise AuthorizationError()
                        for member in names:
                            _check(clock, cancel, deadline)
                            entry = wheel.getinfo(member)
                            pinned = expected[member]
                            if entry.file_size != pinned.size:
                                raise AuthorizationError()
                            if hashlib.sha256(wheel.read(entry)).hexdigest() != pinned.digest:
                                raise AuthorizationError()
                    values[name] = value
        stream = io.BytesIO()
        members = []
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, value in sorted(values.items()):
                _check(clock, cancel, deadline)
                # Stable assembly permits fresh-process validation; identity is
                # the actual host's ledger, not the deterministic archive hash.
                zip_info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                zip_info.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(zip_info, value)
                members.append(c.public_object({
                    "path": name, "digest": hashlib.sha256(value).hexdigest(),
                    "size": len(value), "executable": False,
                }))
        content = stream.getvalue()
        if len(content) > _LIMIT:
            raise AuthorizationError()
        return tuple(outputs), content, tuple(members)

    def inspect(
        self, clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _ProducedBuild:
        """Validate the producer's own exact ledger; a supplied receipt is never enough."""
        if self._ledger_digest is None:
            raise AuthorizationError()
        clock = _MonotonicClock(clock)
        with _root(self.root) as root:
            if set(storage.names(root)) != {
                "source", "cache", "work", "build-output", "output", _LEDGER,
            }:
                raise AuthorizationError()
        facts = self._facts(clock, cancel, deadline)
        outputs, content, members = self._assemble(clock, cancel, deadline)
        expected = c.public_object({
            "schema": "owned-offline-build-v1", "producer_id": self.identity, **facts,
            "operation": "offline-wheel-sdist-and-cache-assembly", "exit_code": 0,
            "outputs": outputs, "members": members,
            "archive_digest": hashlib.sha256(content).hexdigest(), "archive_size": len(content),
        })
        with _root(self.root) as root:
            ledger = _read_file(root, _LEDGER, 16 * 1024 * 1024)
        if c.digest(expected) != self._ledger_digest or ledger != c.canonical_bytes(expected):
            raise AuthorizationError()
        _check(clock, cancel, deadline)
        return _ProducedBuild(expected, content)
