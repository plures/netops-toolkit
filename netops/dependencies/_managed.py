"""Exact managed-generation manifests and admitted protected archive staging.

This is a distinct product-tree format, not A02's inert byte schema. A staged
tree is neither an installed/qualified controller nor an active generation.
No archive member is executed; no package resolver, shell or global install is
used. The trusted composition must still provide a real managed lifecycle state
and exact reviewed asset descriptors; no missing pin is invented here.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import stat
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, fields, replace
from typing import IO, Protocol
from uuid import uuid4

from netops.ansible import artifact_platform as platform
from netops.ansible import contracts as c
from netops.ansible.artifact_cleanup import (
    _carry_storage_diagnostics,
    _storage_detail,
    _storage_diagnostics,
    _storage_io,
    _storage_operation,
    cleanup_errors,
    teardown,
)
from netops.ansible.artifacts import (
    ArtifactError,
    OwnedRecord,
    OwnedStatePort,
    ProtectedRoot,
    _private,
    _read_file,
    _root,
)
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    LifecycleSnapshot,
)
from netops.ansible.policy.lifecycle_evidence import validate_current

from ._assets import LockedAsset, _MonotonicClock
from ._installation import _InstallationSpec, _OfflineInstallation
from ._owned_source import _OwnedBuildAsset

__all__: tuple[str, ...] = ()
_SCHEMA = "i02-managed-generation-v1"
_ROOT_SCHEMA = "i02-managed-generations-v1"
_SENTINEL = "netops-generation.json"
_FILES = 4096
_TOTAL = 512 * 1024 * 1024
_MEMBER = 128 * 1024 * 1024
_COMPONENT = re.compile(r"[A-Za-z0-9_.-]{1,160}\Z")
_LOG = logging.getLogger(__name__)


def _parts(path: str) -> tuple[str, ...]:
    if type(path) is not str or len(path) > 1024:
        raise c.ContractError()
    parts = tuple(path.split("/"))
    for part in parts:
        if (
            _COMPONENT.fullmatch(part) is None or part in (".", "..") or part.endswith(".")
            or part.split(".")[0].casefold() in (
                "con", "prn", "aux", "nul",
                *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10)),
            )
        ):
            raise c.ContractError()
    if len(parts) > 32 or parts[0].casefold() == _SENTINEL:
        raise c.ContractError()
    return parts


@dataclass(frozen=True)
class ManagedMember:
    """One exact regular file and reviewed owner-only execution mode."""

    path: str
    digest: str
    size: int
    executable: bool = False

    def __post_init__(self) -> None:
        """Reject alternate path spellings, unbounded sizes and unreviewed modes."""
        _parts(self.path)
        c.sha256(self.digest)
        c.counter(self.size)
        if self.size > _MEMBER or type(self.executable) is not bool:
            raise c.ContractError()


@dataclass(frozen=True)
class ManagedArchive:
    """One registered locked archive contributing exact files to one generation."""

    asset: LockedAsset | _OwnedBuildAsset
    archive: str
    members: tuple[ManagedMember, ...]

    def __post_init__(self) -> None:
        """Require typed locks and a bounded regular-file contribution."""
        if type(self.asset) not in (LockedAsset, _OwnedBuildAsset) or self.archive not in ("zip", "tar", "tar.gz", "file"):
            raise c.ContractError()
        self.asset.__post_init__()
        if type(self.members) is not tuple or not self.members or len(self.members) > _FILES:
            raise c.ContractError()
        for member in self.members:
            if type(member) is not ManagedMember:
                raise c.ContractError()
            member.__post_init__()
        if self.archive == "file" and (
            type(self.asset) is not LockedAsset or len(self.members) != 1
            or self.members[0].digest != self.asset.sha256
            or self.members[0].size != self.asset.size or self.members[0].executable
        ):
            raise c.ContractError()


@dataclass(frozen=True)
class ManagedGenerationManifest(c.FrozenObject):
    """Exact selected product tree; qualification remains a separate real fact."""

    entries: tuple[tuple[str, c.Json], ...] = field(default=(), init=False, repr=False, compare=False)
    generation_id: str
    asset: LockedAsset | _OwnedBuildAsset
    archive: str
    members: tuple[ManagedMember, ...]
    scope: c.InstallScope
    context: c.InstallContext
    consuming_contexts: tuple[str, ...]
    schema: str = _SCHEMA
    archives: tuple[ManagedArchive, ...] = ()
    installation: _InstallationSpec | None = None
    bootstrap_digest: str | None = None

    def __post_init__(self) -> None:
        """Bind every path, byte and selected context without asserting readiness."""
        c.text(self.generation_id)
        if type(self.asset) not in (LockedAsset, _OwnedBuildAsset):
            raise c.ContractError()
        self.asset.__post_init__()
        if self.schema != _SCHEMA or self.archive not in ("zip", "tar", "tar.gz", "file"):
            raise c.ContractError()
        if type(self.members) is not tuple or not 0 < len(self.members) <= _FILES:
            raise c.ContractError()
        if self.archive == "file" and not self.archives:
            ManagedArchive(self.asset, self.archive, self.members)
        if type(self.archives) is not tuple or len(self.archives) > 128:
            raise c.ContractError()
        if self.archives:
            if type(self.asset) is _OwnedBuildAsset or any(
                type(archive.asset) is _OwnedBuildAsset for archive in self.archives
            ):
                # Private builds are one exact local producer closure, never a
                # member hidden inside a publisher-family archive collection.
                raise c.ContractError()
            for archive in self.archives:
                if type(archive) is not ManagedArchive:
                    raise c.ContractError()
                archive.__post_init__()
            if (
                self.asset != self.archives[0].asset or self.archive != self.archives[0].archive
                or self.members != tuple(member for archive in self.archives for member in archive.members)
            ):
                raise c.ContractError()
            dependencies = tuple(archive.asset.dependency for archive in self.archives)
            if len(set(dependencies)) != len(dependencies):
                spec = self.installation
                if type(spec) is not _InstallationSpec or spec.controller_installation is None:
                    raise c.ContractError()
                spec.__post_init__()
                for dependency in set(dependencies):
                    duplicated = tuple(
                        archive for archive in self.archives
                        if archive.asset.dependency == dependency
                    )
                    if len(duplicated) == 1:
                        continue
                    native = tuple(
                        wheel for wheel in spec.wheels if wheel.distribution == dependency
                    )
                    controller = tuple(
                        wheel for wheel in spec.controller_installation.wheels
                        if wheel.distribution == dependency
                    )
                    if (
                        len(duplicated) != 2 or len(native) != 1 or len(controller) != 1
                        or (native[0].member, native[0].digest)
                        == (controller[0].member, controller[0].digest)
                        or {
                            (archive.members[0].path, archive.asset.sha256)
                            for archive in duplicated
                            if archive.archive == "file" and len(archive.members) == 1
                        } != {
                            (native[0].member, native[0].digest),
                            (controller[0].member, controller[0].digest),
                        }
                    ):
                        raise c.ContractError()
        files: set[str] = set()
        directories: set[str] = set()
        total = 0
        for member in self.members:
            if type(member) is not ManagedMember:
                raise c.ContractError()
            member.__post_init__()
            key = member.path.casefold()
            if key in files:
                raise c.ContractError()
            files.add(key)
            parts = _parts(member.path)
            directories.update("/".join(parts[:index]).casefold() for index in range(1, len(parts)))
            total += member.size
        if files & directories or total > _TOTAL:
            raise c.ContractError()
        if type(self.scope) is not c.InstallScope or type(self.context) is not c.InstallContext:
            raise c.ContractError()
        self.scope.__post_init__()
        self.context.__post_init__()
        if self.bootstrap_digest is not None:
            c.sha256(self.bootstrap_digest)
            if type(self.asset) is _OwnedBuildAsset:
                raise c.ContractError()
        c.unique(self.consuming_contexts)
        for context in self.consuming_contexts:
            c.sha256(context)
        if self.installation is not None:
            if type(self.installation) is not _InstallationSpec:
                raise c.ContractError()
            self.installation.__post_init__()
            self.installation.validate_members(self)
        # Use the contract's supported immutable JSON mapping representation.
        # Omit an absent opt-in installation so legacy descriptors retain their
        # exact canonical bytes/digests, without modifying the shared encoder.
        encoded = c.public_object({
            item.name: c.wire(getattr(self, item.name)) for item in fields(self)
            if item.name != "entries" and not (
                item.name in ("installation", "bootstrap_digest")
                and getattr(self, item.name) is None
            )
        })
        object.__setattr__(self, "entries", encoded.entries)

    @property
    def content_digest(self) -> str:
        """Hash the exact expected tree, including executable-file distinctions."""
        return c.digest(tuple(sorted(self.members, key=lambda member: member.path)))

    @property
    def assets(self) -> tuple[LockedAsset | _OwnedBuildAsset, ...]:
        """Return the complete ordered reviewed acquisition closure."""
        return tuple(archive.asset for archive in self.archives) if self.archives else (self.asset,)


@dataclass(frozen=True)
class _File:
    member: ManagedMember
    content: bytes = field(repr=False)


def _check(clock: c.ClockPort, cancel: c.CancelPort, deadline: float) -> None:
    if cancel.is_cancelled():
        raise InterruptedError()
    if c.finite(clock.monotonic()) >= deadline:
        raise TimeoutError()


def _zip_directory(content: bytes) -> None:
    """Bound and count central metadata before ZipFile allocates entry objects."""
    end = content.rfind(b"PK\x05\x06", max(0, len(content) - 65557))
    if end < 0 or len(content) - end < 22:
        raise c.ContractError()
    _, disk, central_disk, local_count, count, size, offset, comment = struct.unpack_from(
        "<4s4H2IH", content, end,
    )
    if (
        disk != 0 or central_disk != 0 or local_count != count or count > _FILES * 2
        or end + 22 + comment != len(content) or offset + size != end
        or size > _FILES * 2 * 4096
    ):
        raise c.ContractError()
    position = offset
    actual = 0
    while position < end:
        if content[position:position + 4] != b"PK\x01\x02" or position + 46 > end:
            raise c.ContractError()
        name, extra, description = struct.unpack_from("<3H", content, position + 28)
        if name > 1024 or extra > 1024 or description > 1024:
            raise c.ContractError()
        position += 46 + name + extra + description
        actual += 1
        if actual > _FILES * 2:
            raise c.ContractError()
    if position != end or actual != count:
        raise c.ContractError()


def unpack(
    manifest: ManagedGenerationManifest, content: bytes, clock: c.ClockPort,
    cancel: c.CancelPort, deadline: float,
) -> tuple[_File, ...]:
    """Read only exact regular members, never extractall, links, devices or loaders."""
    manifest.__post_init__()
    c.finite(deadline)
    if (
        type(content) is not bytes or len(content) != manifest.asset.size
        or hashlib.sha256(content).hexdigest() != manifest.asset.sha256
    ):
        raise c.ContractError()
    expected = {member.path: member for member in manifest.members}
    directories = {
        "/".join(_parts(path)[:index])
        for path in expected for index in range(1, len(_parts(path)))
    }
    found: dict[str, _File] = {}
    seen: set[str] = set()

    def read_member(path: str, size: int, stream: IO[bytes]) -> None:
        _check(clock, cancel, deadline)
        member = expected.get(path)
        if member is None or size != member.size:
            raise c.ContractError()
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            _check(clock, cancel, deadline)
            chunk = stream.read(min(65536, remaining))
            if not chunk:
                raise c.ContractError()
            chunks.append(chunk)
            remaining -= len(chunk)
        if stream.read(1):
            raise c.ContractError()
        value = b"".join(chunks)
        if hashlib.sha256(value).hexdigest() != member.digest:
            raise c.ContractError()
        found[path] = _File(member, value)

    def name(raw: str, directory: bool) -> str:
        path = raw[:-1] if directory and raw.endswith("/") else raw
        _parts(path)
        key = path.casefold()
        if key in seen or len(seen) >= _FILES * 2:
            raise c.ContractError()
        seen.add(key)
        if directory and path not in directories:
            raise c.ContractError()
        return path

    _check(clock, cancel, deadline)
    if manifest.archive == "file":
        ManagedArchive(manifest.asset, "file", manifest.members)
        read_member(manifest.members[0].path, len(content), io.BytesIO(content))
    elif manifest.archive == "zip":
        _zip_directory(content)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            if len(archive.infolist()) > _FILES * 2:
                raise c.ContractError()
            for entry in archive.infolist():
                _check(clock, cancel, deadline)
                mode = entry.external_attr >> 16
                directory = entry.is_dir()
                kind = stat.S_IFMT(mode)
                if (
                    entry.flag_bits & 1 or kind not in (0, stat.S_IFDIR, stat.S_IFREG)
                    or (kind == stat.S_IFDIR) != directory and kind != 0
                    or mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
                ):
                    raise c.ContractError()
                path = name(entry.filename, directory)
                if directory and entry.file_size != 0:
                    raise c.ContractError()
                if not directory:
                    with archive.open(entry) as stream:
                        read_member(path, entry.file_size, stream)
    else:
        raw = content
        if manifest.archive == "tar.gz":
            # Bound decompression before a tar metadata parser can consume a
            # hostile extension header. Only USTAR regular files/directories
            # are admitted below, never PAX/GNU sparse/link extensions.
            maximum = sum(item.size for item in manifest.members) + (_FILES * 3 + 32) * 512
            blocks: list[bytes] = []
            total = 0
            compressed = zlib.decompressobj(31)
            for offset in range(0, len(content), 65536):
                tail = content[offset:offset + 65536]
                while tail:
                    _check(clock, cancel, deadline)
                    block = compressed.decompress(tail, min(65536, maximum + 1 - total))
                    tail = compressed.unconsumed_tail
                    total += len(block)
                    if total > maximum:
                        raise c.ContractError()
                    blocks.append(block)
                if compressed.unused_data:
                    # No concatenated stream with separately unbounded metadata.
                    raise c.ContractError()
            if not compressed.eof:
                raise c.ContractError()
            raw = b"".join(blocks)
        position = 0
        while position < len(raw):
            _check(clock, cancel, deadline)
            header = raw[position:position + 512]
            if header == b"\0" * 512:
                if raw[position:].strip(b"\0"):
                    raise c.ContractError()
                break
            if len(header) != 512:
                raise c.ContractError()
            tar_entry = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            if (
                not (tar_entry.isfile() or tar_entry.isdir()) or tar_entry.issparse()
                or tar_entry.mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
                or tar_entry.isdir() and tar_entry.size != 0
            ):
                raise c.ContractError()
            path = name(tar_entry.name, tar_entry.isdir())
            position += 512
            if tar_entry.isfile():
                member = expected.get(path)
                if member is None or tar_entry.size != member.size:
                    raise c.ContractError()
                with io.BytesIO(raw[position:position + tar_entry.size]) as stream:
                    read_member(path, tar_entry.size, stream)
            position += ((tar_entry.size + 511) // 512) * 512
            if position > len(raw):
                raise c.ContractError()
    if set(found) != set(expected):
        raise c.ContractError()
    _check(clock, cancel, deadline)
    return tuple(found[path] for path in sorted(found))


class GenerationFilesPort(Protocol):
    """Generation I/O and opt-in consuming verification; never pointer mutation."""

    def stage(
        self, manifest: ManagedGenerationManifest, files: tuple[_File, ...],
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> None:
        """Publish one exact previously absent tree, retaining unknown destinations."""
        ...

    def verify(
        self, manifest: ManagedGenerationManifest, clock: c.ClockPort,
        cancel: c.CancelPort, deadline: float,
    ) -> c.FrozenObject | None:
        """Return installed proof when selected; legacy archive verification returns None."""
        ...


class ProtectedGenerationFiles:
    """Pinned-handle publication in an already protected, explicitly selected root."""

    def __init__(self, root: ProtectedRoot) -> None:
        if type(root) is not ProtectedRoot:
            raise c.ContractError()
        self._root = root

    @staticmethod
    def _directory(manifest: ManagedGenerationManifest) -> str:
        return "generation-" + c.digest(manifest.generation_id)

    @staticmethod
    def _pending_directory(manifest: ManagedGenerationManifest) -> str:
        return "managed-pending-" + c.digest(manifest)

    @contextmanager
    def _parents(
        self, root: int, parts: tuple[str, ...], create: bool,
        *, _source_guard: Callable[[], None] | None = None,
    ) -> Iterator[int]:
        opened: list[int] = []
        parent = root
        try:
            for part in parts:
                if create:
                    if _source_guard is not None:
                        _source_guard()
                    try:
                        platform.mkdir(parent, part)
                    except FileExistsError:
                        pass
                parent = platform.open_directory(parent, part)
                opened.append(parent)
                _private(platform.info(parent), True)
            yield parent
        finally:
            for handle in reversed(opened):
                with teardown():
                    platform.close(handle)

    @staticmethod
    def _write(parent: int, name: str, value: bytes, executable: bool) -> None:
        if os.name == "nt":
            # Windows' lower layer validates the inherited protected DACL. No
            # ACL is changed here, and this is not Windows controller support.
            platform.windows().write(parent, name, value)
            return
        fd = os.open(
            name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | int(getattr(os, "O_NOFOLLOW")),
            0o700 if executable else 0o600, dir_fd=parent,
        )
        try:
            _private(platform.info(fd), False)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(value)
                stream.flush()
                os.fsync(fd)
        finally:
            with teardown():
                os.close(fd)

    def stage(
        self, manifest: ManagedGenerationManifest, files: tuple[_File, ...],
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
        *, _source_guard: Callable[[], None] | None = None,
    ) -> None:
        """Publish exact members atomically; failed private staging is retained, not swept."""
        manifest.__post_init__()
        if tuple(item.member for item in files) != tuple(
            sorted(manifest.members, key=lambda item: item.path)
        ) or any(
            len(item.content) != item.member.size
            or hashlib.sha256(item.content).hexdigest() != item.member.digest for item in files
        ):
            raise c.ContractError()
        pending = self._pending_directory(manifest)
        with _root(self._root) as parent:
            _check(clock, cancel, deadline)
            resource = c.digest((self._root.path, self._root.device, self._root.inode, pending))
            with _storage_io("managed-stage", "create-directory", resource):
                if _source_guard is not None:
                    _source_guard()
                platform.mkdir(parent, pending)
            # No recursive cleanup: an interrupted staging tree remains owned
            # evidence, never authority to sweep unknown or injected resources.
            with self._parents(parent, (pending,), False) as staged:
                for item in files:
                    _check(clock, cancel, deadline)
                    parts = _parts(item.member.path)
                    with self._parents(
                        staged, parts[:-1], True, _source_guard=_source_guard,
                    ) as directory:
                        with _storage_io("managed-stage", "write-member", c.digest((
                            resource, item.member.path,
                        ))):
                            if _source_guard is not None:
                                _source_guard()
                            self._write(directory, parts[-1], item.content, item.member.executable)
                            platform.sync(directory)
                with _storage_io("managed-stage", "write-member", c.digest((resource, _SENTINEL))):
                    if _source_guard is not None:
                        _source_guard()
                    self._write(staged, _SENTINEL, c.canonical_bytes(manifest), False)
                    platform.sync(staged)
            _check(clock, cancel, deadline)
            with _root(self._root), _storage_io("managed-stage", "publish-generation", resource):
                if _source_guard is not None:
                    _source_guard()
                platform.rename(parent, pending, self._directory(manifest), replace=False)
            platform.sync(parent)
        if manifest.installation is not None:
            from pathlib import Path

            if _source_guard is not None:
                _source_guard()
            _OfflineInstallation(self._root, _source_guard=_source_guard).install(
                manifest, Path(self._root.path) / self._directory(manifest),
                clock, cancel, deadline,
            )

    def verify(
        self, manifest: ManagedGenerationManifest, clock: c.ClockPort,
        cancel: c.CancelPort, deadline: float,
    ) -> c.FrozenObject | None:
        """Rehash exact owned tree and reject every extra/missing member or alias."""
        return self._verify(manifest, clock, cancel, deadline, functional=True)

    def _verify(
        self, manifest: ManagedGenerationManifest, clock: c.ClockPort,
        cancel: c.CancelPort, deadline: float, *, functional: bool,
        _source_guard: Callable[[], None] | None = None,
    ) -> c.FrozenObject | None:
        """Rehash full membership; keep functional reuse private to the live host."""
        manifest.__post_init__()
        _check(clock, cancel, deadline)
        with _root(self._root) as parent, self._parents(
            parent, (self._directory(manifest),), False,
        ) as generation:
            if _read_file(generation, _SENTINEL) != c.canonical_bytes(manifest):
                raise c.ContractError()
            expected: dict[tuple[str, ...], set[str]] = {(): {_SENTINEL}}
            for member in manifest.members:
                _check(clock, cancel, deadline)
                parts = _parts(member.path)
                for index, part in enumerate(parts):
                    expected.setdefault(parts[:index], set()).add(part)
                with self._parents(generation, parts[:-1], False) as directory:
                    if os.name == "nt":
                        value = platform.windows().read(directory, parts[-1], member.size)
                    else:
                        fd = os.open(parts[-1], os.O_RDONLY | int(getattr(os, "O_NOFOLLOW"))
                                     | int(getattr(os, "O_NONBLOCK")),
                                     dir_fd=directory)
                        try:
                            info = platform.info(fd)
                            _private(info, False)
                            if info.st_size != member.size or bool(info.st_mode & 0o111) != member.executable:
                                raise c.ContractError()
                            with os.fdopen(fd, "rb", closefd=False) as stream:
                                chunks: list[bytes] = []
                                remaining = member.size
                                while remaining:
                                    _check(clock, cancel, deadline)
                                    chunk = stream.read(min(65536, remaining))
                                    if not chunk:
                                        raise c.ContractError()
                                    chunks.append(chunk)
                                    remaining -= len(chunk)
                                if stream.read(1):
                                    raise c.ContractError()
                                value = b"".join(chunks)
                        finally:
                            with teardown():
                                os.close(fd)
                    if len(value) != member.size or hashlib.sha256(value).hexdigest() != member.digest:
                        raise c.ContractError()
            for parts, names in expected.items():
                _check(clock, cancel, deadline)
                with self._parents(generation, parts, False) as directory:
                    if set(platform.names(directory)) != names:
                        raise c.ContractError()
        if manifest.installation is not None:
            return _OfflineInstallation(self._root, _source_guard=_source_guard)._verify(
                manifest, clock, cancel, deadline, functional=functional,
            )
        return None

    def installation_receipt(
        self, manifest: ManagedGenerationManifest, clock: c.ClockPort,
        cancel: c.CancelPort, deadline: float,
    ) -> c.FrozenObject:
        """Return genuinely consumed installed output, never staged-archive evidence."""
        return _OfflineInstallation(self._root).verify(manifest, clock, cancel, deadline)


@dataclass(frozen=True)
class ManagedStageReceipt:
    """Factual staged manifest, explicitly not readiness or activation."""

    generation_id: str
    manifest_digest: str
    content_digest: str
    cancelled_after_publication: bool


class ManagedGenerationHandler:
    """Stage exact archives through real private broker entry, root lock and CAS.

    The lifecycle state must use the same owned records and managed root schema.
    Inert A02 facts are rejected rather than relabeled as product ownership.
    """

    def __init__(
        self, owned: OwnedStatePort, files: GenerationFilesPort,
        authorization: AuthorizationBroker, clock: c.ClockPort, events: c.EventPort,
    ) -> None:
        if type(authorization) is not AuthorizationBroker:
            raise c.ContractError()
        self._owned: OwnedStatePort = owned
        self._files: GenerationFilesPort = files
        self._authorization = authorization
        self._clock = clock
        self._events = events
        self._pending: dict[lc.LifecycleEffectPermit, tuple[
            lc.LifecycleEffectBinding, ManagedStageReceipt,
        ]] = {}

    def _observe(
        self, effect: lc.LifecycleEffectBinding, status: c.OutcomeStatus, started: float,
    ) -> None:
        reason = None if status == c.OutcomeStatus.SUCCEEDED else (
            c.ReasonCode.CANCELLED if status == c.OutcomeStatus.CANCELLED
            else c.ReasonCode.PROVISION_FAILED
        )
        try:
            duration = max(0.0, c.finite(self._clock.monotonic()) - started)
        except BaseException:
            duration = 0.0
        try:
            _LOG.info("install.step", extra={
                "metric_name": "netops.install.step.count", "metric_value": 1,
                "kind": effect.lifecycle.kind, "step_kind": "dependency-stage",
                "status": status.value, "stage": "managed-stage",
                "reason": reason.value if reason is not None else "none",
                "category": "dependency" if reason is not None else "none",
                "next_action": "review-owned-generation" if reason is not None else "none",
                "duration": duration, "operation_id": effect.lifecycle.lifecycle_id,
                "step_id": effect.occurrence_id, "context_digest": effect.lifecycle.context_digest,
                "metric_labels": ("kind", "step_kind", "status", "stage", "category", "reason"),
            })
        except BaseException:
            pass
        try:
            self._events.emit(c.SafeEvent(
                effect.lifecycle.lifecycle_id, effect.occurrence_id,
                effect.lifecycle.root.resource_id, effect.lifecycle.context_digest,
                c.Mode.APPLY, status, c.ErrorCategory.DEPENDENCY if reason is not None else None,
                reason, False, duration,
            ))
        except BaseException:
            pass

    def _record(self, binding: lc.LifecycleBinding) -> OwnedRecord:
        state = self._authorization._lifecycle_state
        if state is None or getattr(state, "_state", None) is not self._owned:
            raise AuthorizationError()
        root = self._owned.read(binding.root.resource_id)
        if type(root) is not OwnedRecord:
            raise c.ContractError()
        root.__post_init__()
        data = root.payload
        if (
            root.kind != "checkpoint" or root.policy_identity != binding.policy
            or set(data) != {"schema", "root_manifest", "generations"}
            or data["schema"] != _ROOT_SCHEMA
            or c.digest(c.public_object(data["root_manifest"])) != binding.root.manifest_digest
            or type(data["generations"]) is not tuple
        ):
            raise AuthorizationError()
        return root

    def stage(
        self, manifest: ManagedGenerationManifest, content: bytes | tuple[bytes, ...],
        permit: lc.LifecycleEffectPermit, effect: lc.LifecycleEffectBinding,
        cancel: c.CancelPort,
    ) -> ManagedStageReceipt:
        """Publish through actual admission; observations never replace effect facts."""
        if type(effect) is not lc.LifecycleEffectBinding:
            raise c.ContractError()
        clock = _MonotonicClock(self._clock)
        started = 0.0
        try:
            started = clock.monotonic()
            with _storage_operation(c.digest(effect.lifecycle.lifecycle_id)):
                receipt = self._stage(manifest, content, permit, effect, cancel, clock)
        except BaseException as exc:
            with _storage_operation(c.digest(effect.lifecycle.lifecycle_id)), teardown(exc):
                self._authorization.revoke_lifecycle(effect.lifecycle.kind, effect.lifecycle.plan_id)
            self._observe(effect, c.OutcomeStatus.CANCELLED if isinstance(
                exc, (InterruptedError, KeyboardInterrupt),
            ) else c.OutcomeStatus.FAILED, started)
            if isinstance(exc, ArtifactError):
                raise
            if isinstance(exc, OSError) or _storage_diagnostics(exc):
                diagnostics = _storage_diagnostics(exc)
                wrapped = ArtifactError(c.SafeError(
                    c.ErrorCategory.DEPENDENCY, c.ReasonCode.PROVISION_FAILED,
                    c.Stage.PROVISION, detail=_storage_detail(exc),
                    next_action="Inspect the exact retained staging manifest before a new reviewed plan.",
                ), cleanup_errors(exc), native_code=(
                    diagnostics[0].winerror if diagnostics
                    else getattr(exc, "winerror", None)
                ))
                _carry_storage_diagnostics(exc, wrapped)
                raise wrapped from None
            raise
        self._pending[permit] = effect, receipt
        self._observe(effect, c.OutcomeStatus.SUCCEEDED, started)
        return receipt

    def _stage(
        self, manifest: ManagedGenerationManifest, content: bytes | tuple[bytes, ...],
        permit: lc.LifecycleEffectPermit, effect: lc.LifecycleEffectBinding,
        cancel: c.CancelPort, clock: c.ClockPort,
    ) -> ManagedStageReceipt:
        """Enter once, persist staging intent, publish exact tree, then CAS staged facts."""
        manifest.__post_init__()
        binding = effect.lifecycle
        if type(binding) is not lc.InstallBinding:
            raise AuthorizationError()
        actual = self._authorization.reconcile_lifecycle(permit)
        if actual != effect:
            raise AuthorizationError()
        occurrences = tuple(item for item in binding.effects if item.occurrence_id == effect.occurrence_id)
        if len(occurrences) != 1 or occurrences[0].kind != "dependency-stage":
            raise AuthorizationError()
        steps = binding.content["steps"]
        if type(steps) is not tuple:
            raise c.ContractError()
        step = c.public_object(steps[occurrences[0].ordinal])
        source = c.public_object(step["source"])
        destination = c.public_object(step["destination"])
        if (
            manifest.generation_id != binding.generation.generation_id
            or c.digest(manifest) != destination["manifest_digest"]
            or binding.generation.manifest_digest != c.digest(manifest)
            or binding.generation.content_digest != manifest.content_digest
            or manifest.scope != binding.scope or c.digest(manifest.context) != binding.context_digest
            or manifest.context.context.policy_identity != binding.policy
            or manifest.context.context.registry_digest != binding.registry_digest
            or source["artifact_digest"] != manifest.asset.sha256
            or source["descriptor_digest"] != c.digest(manifest.asset)
            or source["source_id"] != manifest.asset.source_id
            or source["registry_digest"] != binding.registry_digest
        ):
            raise AuthorizationError()
        scope = self._authorization._life_scope(permit)
        state = self._authorization._lifecycle_state
        if scope is None or state is None:
            raise AuthorizationError()
        deadline = min(scope.deadline, c.checked_deadline(clock.monotonic(), 300.0))
        if manifest.archives:
            if type(content) is not tuple or len(content) != len(manifest.archives):
                raise c.ContractError()
            files = tuple(
                file for archive, acquired in zip(manifest.archives, content)
                for file in unpack(replace(
                    manifest, asset=archive.asset, archive=archive.archive,
                    members=archive.members, archives=(), installation=None,
                ), acquired, clock, cancel, deadline)
            )
        else:
            if type(content) is not bytes:
                raise c.ContractError()
            files = unpack(manifest, content, clock, cancel, deadline)
        # Never acquire the broker while holding an owned OS root lock.
        # Broker entry takes that root itself; it need not be reentrant.
        self._authorization.enter_lifecycle(permit, effect, clock.monotonic())
        with state.lock_lifecycle(binding):
            root = self._record(binding)
            snapshot = state.snapshot_lifecycle(binding)
            if type(snapshot) is not LifecycleSnapshot:
                raise c.ContractError()
            c.counter(snapshot.revision)
            flags = (snapshot.cancelled, snapshot.setup_enabled, snapshot.owned_valid,
                     snapshot.pins_valid, snapshot.probes_valid)
            if any(type(flag) is not bool for flag in flags):
                raise c.ContractError()
            if (
                snapshot.binding != binding or snapshot.revision != root.revision
                or snapshot.cancelled or not all(flags[1:])
            ):
                raise AuthorizationError()
            validate_current(binding, snapshot.evidence, clock.monotonic())
            from ._composition import ManagedLifecycleState

            source_state: ManagedLifecycleState | None = None
            if (
                type(manifest.asset) is _OwnedBuildAsset
                or manifest.bootstrap_digest is not None
            ):
                # The original broker has already admitted this effect. A
                # serialized asset and exact bytes still cannot supply actor
                # authority: require the trusted host's private capability.
                if (
                    type(state) is not ManagedLifecycleState
                    or type(self._files) is not ProtectedGenerationFiles
                    or self._files is not state.files
                ):
                    raise AuthorizationError()
                source_state = state
                source_state.guard_source(manifest, clock, cancel, deadline)
            source_guard: Callable[[], None] | None = None
            if source_state is not None:
                guard_owner: ManagedLifecycleState = source_state
                # Retain this live host within the admitted lock, never a
                # receipt-created actor or a newly sampled permission budget.
                def guard() -> None:
                    _check(clock, cancel, deadline)
                    guard_owner.guard_source(manifest, clock, cancel, deadline)
                    _check(clock, cancel, deadline)

                source_guard = guard
            existing = root.payload["generations"]
            if type(existing) is not tuple or len(existing) >= 128:
                raise AuthorizationError()
            if any(c.public_object(item)["generation_id"] == manifest.generation_id for item in existing):
                raise AuthorizationError()
            entry = c.public_object({
                "generation_id": manifest.generation_id, "manifest": c.wire(manifest),
                "state": "staging", "plan_digest": binding.plan_digest,
                "occurrence_id": effect.occurrence_id,
                "staging_directory": ProtectedGenerationFiles._pending_directory(manifest),
                "directory": ProtectedGenerationFiles._directory(manifest),
            })
            staged = replace(root, revision=root.revision + 1, payload=c.public_object({
                **dict(root.payload), "generations": (*existing, entry),
            }))
            resource = c.digest((binding.root.resource_id, c.digest(manifest)))
            with _storage_io("managed-stage", "persist-intent", resource):
                if source_state is not None:
                    source_state.guard_source(manifest, clock, cancel, deadline)
                self._owned.compare_replace(root.resource_id, root.revision, staged)
            if source_state is not None:
                source_state.guard_source(manifest, clock, cancel, deadline)
            with _storage_io("managed-stage", "stage-files", resource):
                if source_guard is not None and type(self._files) is ProtectedGenerationFiles:
                    self._files.stage(
                        manifest, files, clock, cancel, deadline, _source_guard=source_guard,
                    )
                else:
                    self._files.stage(manifest, files, clock, cancel, deadline)
            if source_state is not None:
                source_state.guard_source(manifest, clock, cancel, deadline)
            with _storage_io("managed-stage", "verify-files", resource):
                if source_guard is not None and type(self._files) is ProtectedGenerationFiles:
                    installed_receipt = self._files._verify(
                        manifest, clock, cancel, deadline, functional=True,
                        _source_guard=source_guard,
                    )
                else:
                    installed_receipt = self._files.verify(manifest, clock, cancel, deadline)
            if source_state is not None:
                source_state.guard_source(manifest, clock, cancel, deadline)
            # Retain late factual publication/verification even on cancellation;
            # checking clock integrity does not mint another effect permission.
            clock.monotonic()
            installed = {}
            if manifest.installation is not None:
                if type(installed_receipt) is not c.FrozenObject:
                    raise c.ContractError()
                installed["installation_receipt"] = installed_receipt
            published = c.public_object({**dict(entry), **installed, "state": "staged"})
            current = self._record(binding)
            if current != staged:
                raise AuthorizationError()
            if source_state is not None:
                source_state.guard_source(manifest, clock, cancel, deadline)
            self._owned.compare_replace(current.resource_id, current.revision, replace(
                current, revision=current.revision + 1, payload=c.public_object({
                    **dict(current.payload), "generations": (*existing, published),
                }),
            ))
        return ManagedStageReceipt(
            manifest.generation_id, c.digest(manifest), manifest.content_digest, cancel.is_cancelled(),
        )

    def complete(self, permit: lc.LifecycleEffectPermit) -> ManagedStageReceipt:
        """Acknowledge only this live factual stage, even after cancellation/expiry."""
        pending = self._pending.get(permit)
        state = self._authorization._lifecycle_state
        if pending is None or state is None:
            raise AuthorizationError()
        effect, receipt = pending
        with state.lock_lifecycle(effect.lifecycle):
            root = self._record(effect.lifecycle)
        # A concurrent revision change is a safe conflict, not a reason to nest
        # the same process-shared root lock inside broker completion.
        self._authorization.complete_lifecycle(
            permit, str(uuid4()), root.revision, c.finite(self._clock.monotonic()),
        )
        del self._pending[permit]
        return receipt
