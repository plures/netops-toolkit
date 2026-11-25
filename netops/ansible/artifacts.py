"""Explicit protected outputs and v1 owned-file state, without implicit adoption."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import sys
import threading
import time
import uuid
import zlib
from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import IO, Literal, Protocol

from netops.ansible import artifact_platform as storage
from netops.ansible.artifact_cleanup import (
    _carry_storage_diagnostics,
    _storage_detail,
    _storage_io,
    teardown,
)
from netops.ansible.artifact_cleanup import cleanup_errors as _cleanup_errors
from netops.ansible.artifact_git import snapshot_files
from netops.ansible.artifact_observations import ArtifactObservations
from netops.ansible.contracts import (
    MAX_SAFE_INT,
    ArtifactBinding,
    ArtifactDescriptor,
    CleanupOutcome,
    ClockPort,
    ContractError,
    ErrorCategory,
    EventPort,
    FrozenObject,
    Mode,
    OutcomeStatus,
    OutputIntent,
    PlanBinding,
    PolicyIdentity,
    ReasonCode,
    SafeError,
    SafeEvent,
    Stage,
    canonical_bytes,
    counter,
    digest,
    finite,
    nonsecret_text,
    public_object,
    sha256,
    text,
    unique,
    uuid_text,
    wire,
)
from netops.ansible.policy.contracts import (
    DecisionEvent,
    DecisionFacts,
    Disposition,
    EventKind,
    LocalPolicyPort,
    Phase,
    PolicyEvaluationError,
    PolicyInputError,
    PolicyState,
    PolicyTransition,
    StepDisposition,
)
from netops.ansible.policy.loader import validate_identity

_LIMIT = 1024 * 1024
_KINDS = {"json": "application/json", "yaml": "application/yaml", "text": "text/plain",
          "html": "text/html", "pdf": "application/pdf"}
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}\Z")
_PRIVATE_FIELD = re.compile(
    r"""(?im)(?:^|[{\s,])["']?(?:auth[_-]?key|priv[_-]?key|shared[_-]?(?:key|secret)|"""
    r"""authentication[_-]?key|privacy[_-]?key|username|ansible[_-]?user|"""
    r"""password(?:[_-]?hash)?|secret[_-]?hash|credential[_-]?hash|token[_-]?hash)"""
    r"""["']?\s*[:=]"""
)
_TEXT_FIELD = re.compile(r"""(?m)(?:^|[{\s,])["']?([A-Za-z][A-Za-z0-9_-]*)["']?\s*[:=]""")


class ArtifactError(RuntimeError):
    """Expose only a safe structured error, never a path or native exception."""

    def __init__(
        self, error: SafeError, cleanup_errors: tuple[SafeError, ...] = (),
        *, native_code: int | None = None,
    ) -> None:
        self.error = error
        self.cleanup_errors = cleanup_errors
        self.native_code = native_code if type(native_code) is int and 0 <= native_code <= 0xFFFFFFFF else None
        super().__init__(error.reason.value)


def _failure(
    reason: ReasonCode = ReasonCode.OWNERSHIP_INVALID,
    category: ErrorCategory = ErrorCategory.PRECONDITION,
) -> ArtifactError:
    return ArtifactError(SafeError(
        category, reason, Stage.PUBLISH,
        retryable=reason == ReasonCode.RESOURCE_BUSY,
        next_action="Select a verified owned root or resolve the conflicting owned revision.",
    ))


@contextmanager
def _teardown(primary: BaseException | None = None) -> Iterator[None]:
    """Keep cleanup uncertainty separate from the active failure or cancellation."""
    with teardown(primary, ArtifactError):
        yield


def _remove_pending_file(parent: int, name: str) -> None:
    """Remove only the exact pending name, preserving primary and cleanup truth."""
    with _teardown():
        try:
            storage.remove(parent, name)
        except FileNotFoundError:
            pass


def _close_handles(handles: Sequence[int]) -> None:
    """Attempt every acquired sibling handle even when one release fails."""
    primary = sys.exc_info()[1]
    original = primary
    for handle in reversed(handles):
        try:
            with _teardown(primary):
                storage.close(handle)
        except BaseException as exc:
            primary = exc
    if original is None and primary is not None:
        raise primary from None


def _name(value: str) -> str:
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}
    if (
        type(value) is not str or _NAME.fullmatch(value) is None or value in (".", "..")
        or value.endswith(".") or value.split(".")[0].casefold() in reserved
    ):
        raise _failure(ReasonCode.OUTPUT_REJECTED)
    return value


def _public_content(content: bytes, kind: str = "text") -> None:
    if type(content) is not bytes:
        raise _failure(ReasonCode.OUTPUT_REJECTED)
    try:
        if kind == "pdf":
            if not content.startswith(b"%PDF-") or not content.rstrip().endswith(b"%%EOF"):
                raise _failure(ReasonCode.OUTPUT_REJECTED)
            decoded = content.decode("latin-1")
            expanded_size = 0
            for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", content, re.DOTALL):
                block = match.group(1)
                try:
                    decoder = zlib.decompressobj()
                    expanded = decoder.decompress(block, 16 * _LIMIT + 1)
                except zlib.error:
                    expanded = block
                else:
                    if len(expanded) > 16 * _LIMIT or not decoder.eof:
                        raise _failure(ReasonCode.OUTPUT_REJECTED)
                expanded_size += len(expanded)
                if expanded_size > 16 * _LIMIT:
                    raise _failure(ReasonCode.OUTPUT_REJECTED)
                decoded += "\n" + expanded.decode("latin-1")
            decoded = decoded.replace("(", "\n").replace(")", "\n")
        else:
            decoded = content.decode("utf-8")
        nonsecret_text(decoded)
        if not decoded.lstrip().startswith(("{", "[")):
            for key_match in _TEXT_FIELD.finditer(decoded):
                public_object({key_match.group(1): None})
        if _PRIVATE_FIELD.search(decoded) is not None:
            raise _failure(ReasonCode.OUTPUT_REJECTED)
        if decoded.lstrip().startswith(("{", "[")):
            structured = content if decoded.lstrip().startswith("{") else b'{"items":' + content + b"}"
            parsed = public_object(_decode(structured))
            _checkpoint_values(parsed)
    except (ContractError, UnicodeError):
        raise _failure(ReasonCode.OUTPUT_REJECTED) from None


@dataclass(frozen=True)
class ProtectedRoot:
    """Selected root and observed identity; revalidated at every I/O boundary."""

    path: str = field(repr=False)
    device: int
    inode: int
    intent: OutputIntent
    permissions_proof: str


@dataclass(frozen=True)
class OwnedResource:
    """Exact manifest-owned cleanup candidate; sensitive content is not diagnostic."""

    descriptor: ArtifactDescriptor
    root: ProtectedRoot = field(repr=False)
    explicit_cleanup: bool = False

    def __post_init__(self) -> None:
        """Require an exact selection boolean, never a truthy caller value."""
        if (
            type(self.descriptor) is not ArtifactDescriptor or type(self.root) is not ProtectedRoot
            or type(self.explicit_cleanup) is not bool
        ):
            raise _failure()


class ProtectedFilesystemPort(Protocol):
    """Frozen protected output seam; no implicit loaders or generic file writes."""

    def validate(self, intent: OutputIntent) -> ProtectedRoot:
        """Validate the explicitly selected output root."""
        ...

    def publish(
        self, root: ProtectedRoot, content: bytes, binding: ArtifactBinding,
    ) -> ArtifactDescriptor:
        """Return a descriptor only after verified atomic publication."""
        ...

    def read(self, descriptor: ArtifactDescriptor) -> bytes:
        """Read exact bytes from a verified descriptor."""
        ...


def selected_state_root(selected: str | None = None) -> Path:
    """Resolve defaults without reading an override or creating/adopting a root."""
    if selected is not None:
        path = Path(selected)
        if not path.is_absolute():
            raise _failure(ReasonCode.OUTPUT_REJECTED)
        return path
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base is None:
            raise _failure(ReasonCode.OUTPUT_REJECTED)
        return Path(base) / "netops-toolkit"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "netops-toolkit"
    return Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / "netops-toolkit"


def _supported() -> None:
    if os.name == "nt":
        return
    if (
        os.name != "posix" or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd or os.rename not in os.supports_dir_fd
    ):
        raise _failure(ReasonCode.OUTPUT_REJECTED, ErrorCategory.PLATFORM)


def _constant(module: object, name: str) -> int:
    value: object = getattr(module, name, None)
    if type(value) is not int or not isinstance(value, int):
        raise _failure(ReasonCode.OUTPUT_REJECTED, ErrorCategory.PLATFORM)
    return value


def _uid() -> int:
    function: object = getattr(os, "geteuid", None)
    if not callable(function):
        raise _failure(ReasonCode.OUTPUT_REJECTED, ErrorCategory.PLATFORM)
    value: object = function()
    if type(value) is not int or not isinstance(value, int):
        raise _failure()
    return value


def _private(info: os.stat_result, directory: bool) -> None:
    if os.name == "nt":
        # Windows identity snapshots are returned only after handle-based ACL proof.
        return
    if os.name != "posix":
        raise _failure(ReasonCode.OUTPUT_REJECTED, ErrorCategory.PLATFORM)
    expected = 0o700 if directory else 0o600
    correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (
        not correct_type or info.st_uid != _uid()
        or stat.S_IMODE(info.st_mode) != expected
        or (not directory and info.st_nlink != 1)
    ):
        raise _failure()


@contextmanager
def _directory(path: str) -> Iterator[int]:
    """Walk every ancestor without following symlinks, keeping the final handle."""
    _supported()
    if os.name == "nt":
        entered = False
        try:
            selected = storage.windows().directory(path)
            handle = selected.__enter__()
            entered = True
            try:
                yield handle
            finally:
                with _teardown():
                    selected.__exit__(*sys.exc_info())
        except OSError as exc:
            if entered:
                # A missing member inside a proved root is not a missing or
                # unowned root. Preserve body exceptions for the owning caller
                # to classify, including native code and cleanup truth.
                raise
            raise ArtifactError(
                _failure().error, _cleanup_errors(exc), native_code=getattr(exc, "winerror", None),
            ) from None
        return
    value = Path(path)
    if not value.is_absolute() or ".." in value.parts:
        raise _failure(ReasonCode.OUTPUT_REJECTED)
    if os.name != "posix":
        raise _failure(ReasonCode.OUTPUT_REJECTED, ErrorCategory.PLATFORM)
    flags = os.O_RDONLY | _constant(os, "O_DIRECTORY") | _constant(os, "O_NOFOLLOW")
    fd = os.open(value.anchor, flags)
    opened = [fd]
    entered = False
    try:
        for component in value.parts[1:]:
            fd = os.open(component, flags, dir_fd=fd)
            opened.append(fd)
        _private(storage.info(fd), True)
        entered = True
        yield fd
    except OSError as exc:
        if entered:
            raise
        raise ArtifactError(_failure().error, _cleanup_errors(exc)) from None
    finally:
        _close_handles(opened)


@contextmanager
def _root(root: ProtectedRoot) -> Iterator[int]:
    with _directory(root.path) as fd:
        info = storage.info(fd)
        if (info.st_dev, info.st_ino) != (root.device, root.inode):
            raise _failure()
        yield fd


def _read_file(parent: int, name: str, limit: int = _LIMIT) -> bytes:
    if os.name == "nt":
        return storage.windows().read(parent, _name(name), limit)
    if os.name != "posix":
        raise _failure(ReasonCode.OUTPUT_REJECTED, ErrorCategory.PLATFORM)
    fd = os.open(
        _name(name), os.O_RDONLY | _constant(os, "O_NOFOLLOW") | _constant(os, "O_NONBLOCK"),
        dir_fd=parent,
    )
    try:
        before = storage.info(fd)
        _private(before, False)
        if before.st_size > limit:
            raise _failure()
        stream = os.fdopen(fd, "rb", closefd=False)
        try:
            value = stream.read(limit + 1)
        finally:
            with _teardown():
                stream.close()
        after = storage.info(fd)
        if (
            len(value) > limit or len(value) != before.st_size
            or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise _failure()
        _private(after, False)
        return value
    finally:
        with _teardown():
            os.close(fd)


def _write_file(parent: int, name: str, content: bytes) -> None:
    if os.name == "nt":
        storage.windows().write(parent, _name(name), content)
        return
    if os.name != "posix":
        raise _failure(ReasonCode.OUTPUT_REJECTED, ErrorCategory.PLATFORM)
    fd = os.open(
        _name(name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _constant(os, "O_NOFOLLOW"),
        0o600, dir_fd=parent,
    )
    try:
        _private(storage.info(fd), False)
        stream = os.fdopen(fd, "wb", closefd=False)
        try:
            stream.write(content)
            stream.flush()
            os.fsync(fd)
        finally:
            with _teardown():
                stream.close()
    finally:
        with _teardown():
            os.close(fd)


def _decode(content: bytes) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise _failure()
            result[key] = value
        return result

    try:
        value: object = json.loads(content, object_pairs_hook=pairs)
        if not isinstance(value, dict):
            raise _failure()
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise _failure() from None


class OwnedLock:
    """Bounded OS lock acquisition in normalized resource order, never TTL stealing."""

    def __init__(self, root: ProtectedRoot, resource_ids: Sequence[str], timeout: float) -> None:
        if type(timeout) is not float or not math.isfinite(timeout) or timeout < 0:
            raise _failure(ReasonCode.INVALID_REQUEST)
        if isinstance(resource_ids, (str, bytes)) or len(resource_ids) == 0:
            raise _failure(ReasonCode.INVALID_REQUEST)
        self._root = root
        self._names = tuple(sorted(set(
            "lock-" + hashlib.sha256(text(item).encode()).hexdigest() for item in resource_ids
        )))
        self._timeout = timeout
        self._keys: list[tuple[int, int, int, str]] = []
        self._native: object = None

    def __enter__(self) -> OwnedLock:
        """Acquire every normalized lock or release the already acquired set."""
        _supported()
        if os.name == "nt":
            native = ExitStack()
            try:
                parent = native.enter_context(_root(self._root))
                native.enter_context(storage.windows().lock(parent, self._names, self._timeout))
            except BlockingIOError as exc:
                with _teardown():
                    native.close()
                raise ArtifactError(
                    _failure(ReasonCode.RESOURCE_BUSY).error, _cleanup_errors(exc),
                ) from None
            except OSError as exc:
                with _teardown():
                    native.close()
                raise ArtifactError(_failure().error, _cleanup_errors(exc)) from None
            except BaseException:
                with _teardown():
                    native.close()
                raise
            self._native = native
            return self
        if os.name != "posix":
            raise _failure(ReasonCode.OUTPUT_REJECTED, ErrorCategory.PLATFORM)
        import fcntl

        flock: object = getattr(fcntl, "flock", None)
        if not callable(flock):
            raise _failure(ReasonCode.OUTPUT_REJECTED, ErrorCategory.PLATFORM)
        flags = _constant(fcntl, "LOCK_EX") | _constant(fcntl, "LOCK_NB")
        deadline = time.monotonic() + self._timeout
        try:
            with _root(self._root) as parent:
                for name in self._names:
                    key = (os.getpid(), self._root.device, self._root.inode, name)
                    held = _HELD_LOCKS.values.get(key)
                    if held is not None:
                        stream, depth = held
                        _private(storage.info(stream.fileno()), False)
                        _HELD_LOCKS.values[key] = (stream, depth + 1)
                        self._keys.append(key)
                        continue
                    fd = os.open(
                        name, os.O_RDWR | os.O_CREAT | _constant(os, "O_NOFOLLOW"),
                        0o600, dir_fd=parent,
                    )
                    try:
                        stream = os.fdopen(fd, "r+b")
                    except BaseException:
                        with _teardown():
                            os.close(fd)
                        raise
                    _HELD_LOCKS.values[key] = (stream, 1)
                    self._keys.append(key)
                    _private(storage.info(fd), False)
                    while True:
                        try:
                            flock(fd, flags)
                            break
                        except BlockingIOError:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise _failure(ReasonCode.RESOURCE_BUSY)
                            # The OS lock is authority; this is bounded lock backoff, not orchestration.
                            time.sleep(min(remaining, 0.01))
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        """Close handles to release OS locks without deleting their files."""
        primary = exc if isinstance(exc, BaseException) else sys.exc_info()[1]
        try:
            native = self._native
            if native is not None:
                self._native = None
                with _teardown(primary):
                    getattr(native, "__exit__")(exc_type, exc, traceback)
        finally:
            self._release_keys(primary)

    def _release_keys(self, primary: BaseException | None) -> None:
        original = primary
        while self._keys:
            key = self._keys.pop()
            try:
                stream, depth = _HELD_LOCKS.values[key]
                if depth == 1:
                    del _HELD_LOCKS.values[key]
                    with _teardown(primary):
                        stream.close()
                else:
                    _HELD_LOCKS.values[key] = (stream, depth - 1)
            except BaseException as failure:
                primary = failure
        if original is None and primary is not None:
            raise primary from None


class _HeldLocks(threading.local):
    def __init__(self) -> None:
        self.values: dict[tuple[int, int, int, str], tuple[IO[bytes], int]] = {}


_HELD_LOCKS = _HeldLocks()


class LocalProtectedFilesystem:
    """Protected handle storage; backend presence is not native qualification."""

    def __init__(self) -> None:
        self._roots: dict[str, ProtectedRoot] = {}

    def validate(self, intent: OutputIntent) -> ProtectedRoot:
        """Select an existing private root, without implicit creation or chmod."""
        if type(intent) is not OutputIntent or intent.root_ref is None or len(intent.kinds) != 1:
            raise _failure(ReasonCode.OUTPUT_REJECTED)
        intent.__post_init__()
        try:
            with _directory(intent.root_ref) as fd:
                info = storage.info(fd)
                root = ProtectedRoot(
                    intent.root_ref, info.st_dev, info.st_ino, intent,
                    "windows-owner-protected-dacl" if os.name == "nt" else
                    "macos-owner-mode-no-extended-acl" if sys.platform == "darwin" else
                    "posix-owner-0700-0600",
                )
                self._roots[intent.root_ref] = root
                return root
        except OSError as exc:
            raise ArtifactError(_failure().error, _cleanup_errors(exc)) from None

    def publish(
        self, root: ProtectedRoot, content: bytes, binding: ArtifactBinding,
    ) -> ArtifactDescriptor:
        """Stage content and manifest together and atomically rename their directory."""
        _supported()
        binding.__post_init__()
        binding.effect.__post_init__()
        if (
            self._roots.get(root.path) != root
            or type(content) is not bytes or root.intent.root_ref != binding.effect.plan.root_ref
            or (binding.classification == "sensitive" and not root.intent.retention)
        ):
            raise _failure(ReasonCode.OUTPUT_REJECTED)
        if binding.classification == "public":
            _public_content(content, root.intent.kinds[0])
        key = digest(binding)
        name = "artifact-" + key + "-" + uuid.uuid4().hex
        pointer = "publication-" + key + ".json"
        pending = "pending-" + uuid.uuid4().hex
        descriptor = ArtifactDescriptor(
            str(Path(root.path) / name / "content"), hashlib.sha256(content).hexdigest(),
            len(content), _KINDS[root.intent.kinds[0]], binding.classification,
            root.permissions_proof, "explicit" if root.intent.retention else "diagnostic-7d",
            name, key,
        )
        try:
            with OwnedLock(root, ("output-root",), 0.0), _root(root) as parent:
                self._replacement(parent, pointer, root, binding)
                storage.mkdir(parent, pending)
                staged = -1
                committed = False
                try:
                    staged = storage.open_directory(parent, pending)
                    _private(storage.info(staged), True)
                    _write_file(staged, "content", content)
                    _write_file(staged, "receipt.json", canonical_bytes(descriptor))
                    if root.intent.git:
                        self._write_git(staged, content, canonical_bytes(descriptor))
                    storage.sync(staged)
                    closing = staged
                    staged = -1
                    with _teardown():
                        storage.close(closing)
                    with _root(root):
                        storage.rename(parent, pending, name)
                    committed = True
                    publication = "pending-" + uuid.uuid4().hex
                    try:
                        _write_file(parent, publication, canonical_bytes(descriptor))
                        with _root(root):
                            storage.rename(
                                parent, publication, pointer,
                                replace=root.intent.overwrite == "replace",
                            )
                        storage.sync(parent)
                        if _read_file(parent, pointer) != canonical_bytes(descriptor):
                            raise _failure()
                    finally:
                        _remove_pending_file(parent, publication)
                finally:
                    try:
                        if staged != -1:
                            with _teardown():
                                storage.close(staged)
                    finally:
                        if not committed:
                            with _teardown():
                                self._remove_pending(parent, pending)
            # Reopen, verify manifest and bytes before returning any descriptor.
            if self.read(descriptor) != content:
                raise _failure()
            if root.intent.git:
                with self._artifact(descriptor) as published:
                    self._check_git(published, snapshot_files(content, canonical_bytes(descriptor)))
            return descriptor
        except OSError as exc:
            raise ArtifactError(
                _failure(ReasonCode.OUTPUT_REJECTED).error, _cleanup_errors(exc),
            ) from None

    def _replacement(
        self, parent: int, pointer: str, root: ProtectedRoot, binding: ArtifactBinding,
    ) -> None:
        """Replace only a valid prior publication of this exact binding."""
        try:
            prior = _read_file(parent, pointer)
        except FileNotFoundError:
            return
        if root.intent.overwrite != "replace":
            raise _failure(ReasonCode.OUTPUT_REJECTED)
        try:
            value = _decode(prior)
            descriptor = ArtifactDescriptor(
                text(value["ref"]), sha256(value["digest"]), counter(value["size"]),
                text(value["media_type"]), text(value["classification"]),
                text(value["permissions_proof"]), text(value["retention"]),
                text(value["owning_resource"]), sha256(value["input_binding"]),
            )
        except (KeyError, TypeError, ContractError):
            raise _failure() from None
        if descriptor.input_binding != digest(binding) or canonical_bytes(descriptor) != prior:
            raise _failure()
        self.read(descriptor)

    @staticmethod
    def _write_git(parent: int, content: bytes, receipt: bytes) -> None:
        """Write a new private bare snapshot, never touch an existing Git repository."""
        files = snapshot_files(content, receipt)
        storage.mkdir(parent, "git")
        git = storage.open_directory(parent, "git")
        try:
            for path, value in files.items():
                parts = path.split("/")
                opened: list[int] = []
                current = git
                try:
                    for part in parts[:-1]:
                        try:
                            storage.mkdir(current, part)
                        except FileExistsError:
                            pass
                        current = storage.open_directory(current, part)
                        opened.append(current)
                        _private(storage.info(current), True)
                    _write_file(current, parts[-1], value)
                    storage.sync(current)
                finally:
                    _close_handles(opened)
            storage.sync(git)
        finally:
            with _teardown():
                storage.close(git)
        LocalProtectedFilesystem._check_git(parent, files)

    @staticmethod
    def _remove_pending(parent: int, pending: str) -> None:
        fd = storage.open_directory(parent, pending)
        try:
            _private(storage.info(fd), True)
            if not set(storage.names(fd)).issubset({"content", "receipt.json", "git"}):
                raise _failure()
            if "git" in storage.names(fd):
                receipt = _read_file(fd, "receipt.json")
                size = counter(_decode(receipt).get("size"))
                content = _read_file(fd, "content", size)
                LocalProtectedFilesystem._check_git(
                    fd, snapshot_files(content, receipt), remove=True, complete=False,
                )
            for name in ("content", "receipt.json"):
                try:
                    storage.remove(fd, name)
                except FileNotFoundError:
                    pass
        finally:
            with _teardown():
                storage.close(fd)
        storage.remove(parent, pending, True)

    @staticmethod
    def _check_git(
        parent: int, files: dict[str, bytes], *, remove: bool = False, complete: bool = True,
    ) -> None:
        """Validate all exact generated Git members before deleting any of them."""
        expected: dict[str, object] = {}
        for path, value in files.items():
            node = expected
            parts = path.split("/")
            for part in parts[:-1]:
                child = node.setdefault(part, {})
                if not isinstance(child, dict):
                    raise _failure()
                node = child
            node[parts[-1]] = value

        def walk(handle: int, tree: dict[str, object], deleting: bool) -> None:
            _private(storage.info(handle), True)
            present = set(storage.names(handle))
            if (complete and present != set(tree)) or not present.issubset(tree):
                raise _failure()
            for name in sorted(present):
                value = tree[name]
                if isinstance(value, dict):
                    child = storage.open_directory(handle, name)
                    try:
                        walk(child, value, deleting)
                    finally:
                        with _teardown():
                            storage.close(child)
                    if deleting:
                        storage.remove(handle, name, True)
                elif isinstance(value, bytes):
                    if _read_file(handle, name, len(value)) != value:
                        raise _failure()
                    if deleting:
                        storage.remove(handle, name)
                else:
                    raise _failure()

        git = storage.open_directory(parent, "git")
        try:
            walk(git, expected, False)
            if remove:
                walk(git, expected, True)
        finally:
            with _teardown():
                storage.close(git)
        if remove:
            storage.remove(parent, "git", True)

    @contextmanager
    def _artifact(self, descriptor: ArtifactDescriptor) -> Iterator[int]:
        descriptor.__post_init__()
        candidate = Path(descriptor.ref)
        root = self._roots.get(str(candidate.parent.parent))
        if (
            root is None or candidate.name != "content"
            or candidate.parent.name != descriptor.owning_resource
            or re.fullmatch(
                "artifact-" + descriptor.input_binding + r"-[0-9a-f]{32}",
                descriptor.owning_resource,
            ) is None
        ):
            raise _failure()
        with _root(root) as parent:
            fd = storage.open_directory(parent, _name(descriptor.owning_resource))
            try:
                _private(storage.info(fd), True)
                receipt = _read_file(fd, "receipt.json")
                if receipt != canonical_bytes(descriptor):
                    raise _failure()
                yield fd
            finally:
                with _teardown():
                    storage.close(fd)

    def read(self, descriptor: ArtifactDescriptor) -> bytes:
        """Check manifest, ownership, permissions and exact bytes on every read."""
        try:
            with self._artifact(descriptor) as fd:
                content = _read_file(fd, "content", descriptor.size)
                if len(content) != descriptor.size or hashlib.sha256(content).hexdigest() != descriptor.digest:
                    raise _failure()
                return content
        except OSError as exc:
            raise ArtifactError(_failure().error, _cleanup_errors(exc)) from None


class ArtifactStore:
    """Application wrapper over the frozen protected-filesystem port."""

    def __init__(
        self, filesystem: ProtectedFilesystemPort, clock: ClockPort, events: EventPort,
    ) -> None:
        self._filesystem = filesystem
        self._clock = clock
        self._events = events
        self.observations = ArtifactObservations()
        self._execution_roots: dict[str, tuple[int, int]] = {}
        self._execution_root_lock = threading.RLock()

    def _execution_root(self, root: ProtectedRoot) -> None:
        ref = root.intent.root_ref
        if (
            ref is None or type(root.device) is not int or type(root.inode) is not int
            or root.device < 0 or root.inode < 0
        ):
            raise _failure(ReasonCode.OUTPUT_REJECTED)
        identity = (root.device, root.inode)
        with self._execution_root_lock:
            if self._execution_roots.setdefault(ref, identity) != identity:
                raise _failure(ReasonCode.OUTPUT_REJECTED)

    def _preflight_public(self, intent: OutputIntent, projection: bytes) -> ProtectedRoot:
        """Read-only execution preflight; publication must validate again."""
        if type(intent) is not OutputIntent or len(intent.kinds) != 1:
            raise _failure(ReasonCode.OUTPUT_REJECTED)
        intent.__post_init__()
        _public_content(projection, "json")
        root = self._filesystem.validate(intent)
        if type(root) is not ProtectedRoot or root.intent != intent:
            raise _failure(ReasonCode.OUTPUT_REJECTED)
        self._execution_root(root)
        return root

    def _emit(
        self, binding: ArtifactBinding, status: OutcomeStatus, started: float,
        intent: OutputIntent, size: int, error: SafeError | None = None,
    ) -> None:
        effect = binding.effect
        try:
            duration = finite(self._clock.monotonic() - started)
        except Exception:
            failure = _failure(ReasonCode.OUTPUT_REJECTED, ErrorCategory.EXECUTION)
            self.observations.record(
                "artifact.publish", "failed", kind=intent.kinds[0] if intent.kinds else "none",
                classification=binding.classification, binding=binding, error=error or failure.error,
            )
            if status == OutcomeStatus.SUCCEEDED:
                raise failure from None
            return
        try:
            self._events.emit(SafeEvent(
                effect.plan.operation_id, effect.step_id, effect.target_id, effect.plan.context_digest,
                Mode.OUTPUT, status,
                error.category if error is not None else None,
                error.reason if error is not None else None,
                error.retryable if error is not None else False, duration,
            ))
        except Exception:
            self.observations.record(
                "artifact.publish", "failed", kind=intent.kinds[0] if intent.kinds else "none",
                classification=binding.classification, binding=binding, duration=duration,
                error=error or _failure(
                    ReasonCode.OUTPUT_REJECTED, ErrorCategory.EXECUTION,
                ).error,
            )
            if status == OutcomeStatus.SUCCEEDED:
                raise _failure(ReasonCode.OUTPUT_REJECTED, ErrorCategory.EXECUTION) from None
            return
        self.observations.record(
            "artifact.publish", status.value, kind=intent.kinds[0] if intent.kinds else "none",
            classification=binding.classification, binding=binding, size=size, duration=duration,
            error=error,
        )

    def publish(
        self, intent: OutputIntent, content: bytes, binding: ArtifactBinding,
    ) -> ArtifactDescriptor:
        """Publish only an exact selected output, never a caller assertion of authority."""
        if type(binding) is not ArtifactBinding or type(intent) is not OutputIntent:
            raise _failure(ReasonCode.OUTPUT_REJECTED)
        try:
            binding.__post_init__()
            binding.effect.__post_init__()
            intent.__post_init__()
            started = finite(self._clock.monotonic())
        except Exception:
            raise _failure(ReasonCode.OUTPUT_REJECTED) from None
        try:
            binding.__post_init__()
            binding.effect.__post_init__()
            if (
                type(content) is not bytes or len(intent.kinds) != 1
                or intent.root_ref != binding.effect.plan.root_ref
            ):
                raise _failure(ReasonCode.OUTPUT_REJECTED)
            if binding.classification == "public":
                _public_content(content, intent.kinds[0] if intent.kinds else "text")
            if binding.classification == "sensitive" and not intent.retention:
                raise _failure(ReasonCode.OUTPUT_REJECTED)
            root = self._filesystem.validate(intent)
            if intent.root_ref in self._execution_roots:
                self._execution_root(root)
            result = self._filesystem.publish(root, content, binding)
            self._check(result, binding)
            if (
                result.size != len(content) or result.digest != hashlib.sha256(content).hexdigest()
                or result.media_type != _KINDS[intent.kinds[0]]
                or (binding.classification == "sensitive" and result.retention != "explicit")
            ):
                raise _failure()
        except ArtifactError as exc:
            self._emit(binding, OutcomeStatus.FAILED, started, intent, 0, exc.error)
            raise
        except (OSError, ContractError) as exc:
            failure = _failure(ReasonCode.OUTPUT_REJECTED)
            failure.cleanup_errors = _cleanup_errors(exc)
            self._emit(binding, OutcomeStatus.FAILED, started, intent, 0, failure.error)
            raise failure from None
        except Exception as exc:
            failure = _failure(ReasonCode.OUTPUT_REJECTED, ErrorCategory.EXECUTION)
            failure.cleanup_errors = _cleanup_errors(exc)
            self._emit(binding, OutcomeStatus.FAILED, started, intent, 0, failure.error)
            raise failure from None
        self._emit(binding, OutcomeStatus.SUCCEEDED, started, intent, len(content))
        return result

    @staticmethod
    def _check(descriptor: ArtifactDescriptor, binding: ArtifactBinding) -> None:
        if (
            type(descriptor) is not ArtifactDescriptor
            or descriptor.input_binding != digest(binding)
            or descriptor.classification != binding.classification
        ):
            raise _failure(ReasonCode.INPUT_BINDING_INVALID)
        descriptor.__post_init__()

    def read(self, descriptor: ArtifactDescriptor, binding: ArtifactBinding) -> bytes:
        """Reject swapped bindings before opening and recheck exact content afterward."""
        try:
            if type(binding) is not ArtifactBinding:
                raise _failure()
            binding.__post_init__()
            binding.effect.__post_init__()
            self._check(descriptor, binding)
            content = self._filesystem.read(descriptor)
            if (
                type(content) is not bytes or len(content) != descriptor.size
                or hashlib.sha256(content).hexdigest() != descriptor.digest
            ):
                raise _failure()
            return content
        except ArtifactError:
            raise
        except Exception as exc:
            raise ArtifactError(_failure().error, _cleanup_errors(exc)) from None

    def cleanup(self, resources: Sequence[OwnedResource]) -> CleanupOutcome:
        """Delete only explicitly selected exact ordinary manifests; never recurse."""
        remaining: list[str] = []
        errors: list[SafeError] = []
        seen: set[str] = set()
        bindings: set[str] = set()
        for resource in resources:
            if type(resource) is not OwnedResource:
                raise _failure(ReasonCode.CLEANUP_FAILED, ErrorCategory.CLEANUP)
            resource.__post_init__()
            descriptor = resource.descriptor
            descriptor.__post_init__()
            bindings.add(descriptor.input_binding)
            if descriptor.owning_resource in seen:
                continue
            seen.add(descriptor.owning_resource)
            if resource.explicit_cleanup is not True or descriptor.classification == "sensitive":
                continue
            try:
                if not isinstance(self._filesystem, LocalProtectedFilesystem):
                    raise _failure()
                root = resource.root
                with OwnedLock(root, ("output-root",), 0.0), _root(root) as parent:
                    self._filesystem.read(descriptor)
                    if Path(descriptor.ref).parent.parent != Path(root.path):
                        raise _failure()
                    self._filesystem._remove_pending(parent, _name(descriptor.owning_resource))
                    pointer = "publication-" + descriptor.input_binding + ".json"
                    try:
                        if _read_file(parent, pointer) == canonical_bytes(descriptor):
                            storage.remove(parent, pointer)
                    except FileNotFoundError:
                        pass
                    storage.sync(parent)
            except Exception as exc:
                remaining.append(descriptor.owning_resource)
                errors.extend(_cleanup_errors(exc))
                errors.append(SafeError(
                    ErrorCategory.CLEANUP, ReasonCode.CLEANUP_FAILED, Stage.FINALIZE,
                    next_action="Retain the primary failure and inspect the exact owned manifest.",
                ))
        outcome = CleanupOutcome(
            "failed" if len(errors) != 0 else "succeeded", tuple(remaining), tuple(errors),
        )
        self.observations.record(
            "cleanup.result", outcome.status,
            error=errors[0] if errors else None,
            input_binding=hashlib.sha256("".join(sorted(bindings)).encode("ascii")).hexdigest()
            if bindings else None,
        )
        return outcome


def _checkpoint_values(value: object) -> None:
    if isinstance(value, FrozenObject):
        for key, item in value.items():
            normalized = key.casefold().replace("_", "").replace("-", "")
            if normalized in {
                "permit", "effectpermit", "grant", "authorization", "session",
                "admissionsession", "consentreceipt", "dispatchpermit",
            } or normalized.endswith((
                "passwordhash", "secrethash", "tokenhash", "credentialhash", "communityhash",
            )):
                raise _failure()
            if normalized in {
                "revision", "expectedrevision", "generation", "sequence", "ordinal", "stepordinal",
            }:
                counter(item)
            _checkpoint_values(item)
    elif isinstance(value, tuple):
        for item in value:
            _checkpoint_values(item)


def validate_member_path(value: str) -> tuple[str, ...]:
    """Reject archive/manifest absolute paths, streams, links and traversal spellings."""
    if (
        type(value) is not str or "\\" in value or ":" in value or "\x00" in value
        or value.startswith("/") or len(value) > 4096
    ):
        raise _failure(ReasonCode.OUTPUT_REJECTED)
    parts = tuple(value.split("/"))
    if len(parts) == 0:
        raise _failure(ReasonCode.OUTPUT_REJECTED)
    for component in parts:
        _name(component)
    return parts


def _record_payload(kind: str, payload: FrozenObject, revision: int) -> None:
    if kind == "active":
        if set(payload) != {"environment_id", "content_digest", "prior_id", "state_revision"}:
            raise _failure()
        _name(text(payload["environment_id"]))
        sha256(payload["content_digest"])
        if payload["prior_id"] is not None:
            _name(text(payload["prior_id"]))
        if counter(payload["state_revision"]) != revision:
            raise _failure()
    if kind == "operation":
        required = {
            "request", "plan", "outcome", "provenance", "artifacts",
            "primary_errors", "cleanup_errors", "chunks", "diagnostic_ttl_days",
        }
        if set(payload) != required:
            raise _failure()
        ttl = counter(payload["diagnostic_ttl_days"], positive=True)
        if ttl > 365:
            raise _failure()
        chunks = payload["chunks"]
        if not isinstance(chunks, tuple):
            raise _failure()
        for chunk in chunks:
            if not isinstance(chunk, FrozenObject) or set(chunk) != {"ref", "digest", "size"}:
                raise _failure()
            validate_member_path(text(chunk["ref"]))
            sha256(chunk["digest"])
            counter(chunk["size"])
    if kind == "install":
        required = {
            "manifest", "plan_digest", "controller_digest", "registry_digest",
            "steps", "original_errors", "pending_actions", "previous_id",
        }
        if set(payload) != required:
            raise _failure()
        for key in ("plan_digest", "controller_digest", "registry_digest"):
            sha256(payload[key])
        manifest = payload["manifest"]
        if not isinstance(manifest, tuple):
            raise _failure()
        paths: set[tuple[str, ...]] = set()
        for member in manifest:
            if (
                not isinstance(member, FrozenObject) or set(member) != {"path", "kind", "digest"}
                or member["kind"] not in ("file", "directory")
            ):
                raise _failure()
            path = validate_member_path(text(member["path"]))
            if path in paths:
                raise _failure()
            paths.add(path)
            sha256(member["digest"])


@dataclass(frozen=True)
class OwnedRecord:
    """V1 nonsecret checkpoint; it cannot encode permits or remote truth."""

    resource_id: str
    kind: str
    revision: int
    generation: int
    ownership_token: str = field(repr=False)
    policy_digest: str
    reducer_version: str
    payload: FrozenObject
    policy_identity: PolicyIdentity
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        """Validate all restored counters and identities before hydration or CAS."""
        text(self.resource_id)
        if self.schema_version != "1.0" or self.kind not in (
            "operation", "install", "active", "checkpoint",
        ):
            raise _failure()
        counter(self.revision)
        counter(self.generation)
        if re.fullmatch(r"[0-9a-f]{64}", self.ownership_token) is None:
            raise _failure()
        sha256(self.policy_digest)
        text(self.reducer_version)
        validate_identity(self.policy_identity)
        if (
            self.policy_digest != self.policy_identity.bundle_sha256
            or self.reducer_version != self.policy_identity.reducer_version
        ):
            raise _failure(ReasonCode.INPUT_BINDING_INVALID)
        payload = public_object(self.payload)
        _checkpoint_values(payload)
        _record_payload(self.kind, payload, self.revision)
        object.__setattr__(self, "payload", payload)
        if len(self.to_bytes()) > _LIMIT:
            raise _failure()

    def to_bytes(self) -> bytes:
        """Serialize owned metadata, never through an authority-object encoder."""
        value = {
            "schema_version": self.schema_version, "resource_id": self.resource_id,
            "kind": self.kind, "revision": self.revision, "generation": self.generation,
            "ownership_token": self.ownership_token, "policy_digest": self.policy_digest,
            "reducer_version": self.reducer_version, "payload": wire(self.payload),
            "policy_identity": wire(self.policy_identity),
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

    @classmethod
    def from_bytes(cls, content: bytes) -> OwnedRecord:
        """Reject unknown fields, duplicates, versions and corrupt ownership before writes."""
        if len(content) > _LIMIT:
            raise _failure()
        value = _decode(content)
        fields = {
            "schema_version", "resource_id", "kind", "revision", "generation",
            "ownership_token", "policy_digest", "reducer_version", "payload",
            "policy_identity",
        }
        if set(value) != fields:
            raise _failure()
        try:
            identity = public_object(value["policy_identity"])
            identity_fields = {
                "profile", "numeric_profile", "schema", "canonical_revision",
                "source_sha256", "contracts_sha256", "bundle_sha256", "rule_manifest",
                "reducer_version",
            }
            if set(identity) != identity_fields:
                raise _failure()
            policy_identity = PolicyIdentity(
                profile=text(identity["profile"]), numeric_profile=text(identity["numeric_profile"]),
                schema=text(identity["schema"]), canonical_revision=text(identity["canonical_revision"]),
                source_sha256=sha256(identity["source_sha256"]),
                contracts_sha256=sha256(identity["contracts_sha256"]),
                bundle_sha256=sha256(identity["bundle_sha256"]),
                rule_manifest=unique(identity["rule_manifest"]),
                reducer_version=text(identity["reducer_version"]),
            )
            return cls(
                text(value["resource_id"]), text(value["kind"]), counter(value["revision"]),
                counter(value["generation"]), text(value["ownership_token"]),
                sha256(value["policy_digest"]), text(value["reducer_version"]),
                public_object(value["payload"]), policy_identity, text(value["schema_version"]),
            )
        except (ContractError, TypeError, ValueError):
            raise _failure() from None


class OwnedStatePort(Protocol):
    """Frozen state persistence seam; no migration or implicit adoption."""

    def read(self, resource_id: str) -> OwnedRecord:
        """Read a validated owned v1 record."""
        ...

    def compare_replace(
        self, resource_id: str, expected_revision: int, record: OwnedRecord,
    ) -> OwnedRecord:
        """Replace only the exact expected owned revision."""
        ...

    def lock(self, resource_ids: Sequence[str], timeout: float) -> OwnedLock:
        """Acquire resource locks in normalized order."""
        ...


class OwnedState:
    """Real atomic v1 state with immutable retained revisions and checked CAS."""

    def __init__(self, root: ProtectedRoot, ownership_token: str) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", ownership_token) is None:
            raise _failure()
        self._root = root
        self._owner = ownership_token
        self._decoded: dict[str, tuple[str, OwnedRecord]] = {}
        self._decoded_lock = threading.RLock()

    @staticmethod
    def _filename(resource_id: str) -> str:
        if resource_id == "active":
            return "active.json"
        parts = validate_member_path(resource_id)
        if len(parts) == 2 and parts[0] in ("operations", "installs"):
            if parts[0] == "operations":
                try:
                    if str(uuid.UUID(parts[1])) != parts[1]:
                        raise _failure()
                except ValueError:
                    raise _failure() from None
            return "outcome.json" if parts[0] == "operations" else "state.json"
        return "state-" + hashlib.sha256(text(resource_id).encode()).hexdigest() + ".json"

    @contextmanager
    def _parent(self, resource_id: str, create: bool = False) -> Iterator[int]:
        parts = validate_member_path(resource_id)
        subdirs = parts if len(parts) == 2 and parts[0] in ("operations", "installs") else ()
        with _root(self._root) as root_fd:
            parent = root_fd
            opened: list[int] = []
            try:
                for component in subdirs:
                    if create:
                        try:
                            storage.mkdir(parent, component)
                            storage.sync(parent)
                        except FileExistsError:
                            pass
                    fd = storage.open_directory(parent, component)
                    opened.append(fd)
                    _private(storage.info(fd), True)
                    parent = fd
                yield parent
            finally:
                _close_handles(opened)

    def lock(self, resource_ids: Sequence[str], timeout: float) -> OwnedLock:
        """Take OS locks; diagnostic records are never lock authority."""
        return OwnedLock(self._root, resource_ids, timeout)

    def _validate(self, record: OwnedRecord, resource_id: str) -> OwnedRecord:
        record.__post_init__()
        if record.resource_id != resource_id or record.ownership_token != self._owner:
            raise _failure()
        expected_kind = (
            "active" if resource_id == "active" else
            "operation" if resource_id.startswith("operations/") else
            "install" if resource_id.startswith("installs/") else "checkpoint"
        )
        if record.kind != expected_kind:
            raise _failure()
        return record

    def read(self, resource_id: str) -> OwnedRecord:
        """Read only this store's exact owned schema; never adopt old state."""
        try:
            with self._parent(resource_id) as parent:
                content = _read_file(parent, self._filename(resource_id))
            content_digest = hashlib.sha256(content).hexdigest()
            with self._decoded_lock:
                cached = self._decoded.get(resource_id)
                if cached is not None and cached[0] == content_digest:
                    # Exact protected bytes were just reread, with the same
                    # live ACL/path/root proofs. Only immutable decoding is
                    # reused; this is not a TTL or metadata-authority cache.
                    return cached[1]
                record = self._validate(OwnedRecord.from_bytes(content), resource_id)
                if len(self._decoded) >= 64:
                    self._decoded.pop(next(iter(self._decoded)))
                self._decoded[resource_id] = (content_digest, record)
                return record
        except FileNotFoundError:
            # Root acquisition/protection failures are already ArtifactError.
            # Only absent metadata under the verified root reaches this case.
            raise FileNotFoundError("protected-storage-missing") from None
        except OSError as exc:
            raise ArtifactError(
                _failure().error, _cleanup_errors(exc), native_code=getattr(exc, "winerror", None),
            ) from None

    def compare_replace(
        self, resource_id: str, expected_revision: int, record: OwnedRecord,
    ) -> OwnedRecord:
        """Create revision zero or atomically advance one revision, retaining the old bytes."""
        counter(expected_revision)
        self._validate(record, resource_id)
        name = self._filename(resource_id)
        try:
            with self.lock((resource_id,), 0.0), self._parent(resource_id, create=True) as parent:
                try:
                    previous = _read_file(parent, name)
                except FileNotFoundError:
                    previous = None
                if previous is None:
                    if expected_revision != 0 or record.revision != 0:
                        raise _failure(ReasonCode.CONSENT_STALE)
                else:
                    current = self._validate(OwnedRecord.from_bytes(previous), resource_id)
                    if (
                        current.revision != expected_revision or expected_revision == MAX_SAFE_INT
                        or record.revision != expected_revision + 1 or current.kind != record.kind
                    ):
                        raise _failure(ReasonCode.CONSENT_STALE)
                    if (
                        record.kind == "active"
                        and record.payload["prior_id"] != current.payload["environment_id"]
                    ):
                        raise _failure(ReasonCode.RESTORE_CANDIDATE_INVALID)
                    retained = name + ".r" + str(current.revision)
                    try:
                        _write_file(parent, retained, previous)
                    except FileExistsError:
                        if _read_file(parent, retained) != previous:
                            raise _failure() from None
                pending = "pending-" + uuid.uuid4().hex
                try:
                    with _storage_io("owned-state", "replace-record", digest((
                        self._root.path, self._root.device, self._root.inode, resource_id,
                    ))):
                        _write_file(parent, pending, record.to_bytes())
                        with _root(self._root):
                            storage.rename(parent, pending, name, replace=True)
                        storage.sync(parent)
                finally:
                    _remove_pending_file(parent, pending)
                return record
        except OSError as exc:
            wrapped = ArtifactError(
                replace(_failure().error, detail=_storage_detail(exc)),
                _cleanup_errors(exc), native_code=getattr(exc, "winerror", None),
            )
            _carry_storage_diagnostics(exc, wrapped)
            raise wrapped from None

    def retained(self, resource_id: str, revision: int) -> OwnedRecord:
        """Load an exact retained revision for an explicitly planned restore."""
        counter(revision)
        try:
            with self._parent(resource_id) as parent:
                value = _read_file(parent, self._filename(resource_id) + ".r" + str(revision))
            record = self._validate(OwnedRecord.from_bytes(value), resource_id)
            if record.revision != revision:
                raise _failure()
            return record
        except OSError as exc:
            raise ArtifactError(_failure().error, _cleanup_errors(exc)) from None


def _journal_state(value: object, identity: PolicyIdentity) -> PolicyState:
    """Decode only the complete version-one state, never a private host value."""
    data = public_object(value)
    if set(data) != set(PolicyState.__dataclass_fields__) or data["identity"] != public_object(wire(identity)):
        raise _failure()
    dispositions = data["dispositions"]
    if not isinstance(dispositions, tuple):
        raise _failure()
    steps: list[StepDisposition] = []
    for raw in dispositions:
        if not isinstance(raw, FrozenObject) or set(raw) != set(StepDisposition.__dataclass_fields__):
            raise _failure()
        steps.append(StepDisposition(
            text(raw["target_id"]), text(raw["step_id"]),
            Disposition(text(raw["disposition"])),
            None if raw["invocation_id"] is None else text(raw["invocation_id"]),
            None if raw["effect_id"] is None else text(raw["effect_id"]),
            None if raw["result_digest"] is None else sha256(raw["result_digest"]),
        ))
    if type(data["remote_uncertain"]) is not bool or data["namespace"] not in ("operation", "install"):
        raise _failure()
    namespace: Literal["operation", "install"] = (
        "operation" if data["namespace"] == "operation" else "install"
    )
    return PolicyState(
        identity, text(data["operation_id"]), counter(data["revision"]),
        Phase(text(data["phase"])), sha256(data["plan_digest"]),
        sha256(data["context_digest"]), sha256(data["policy_digest"]), tuple(steps),
        None if data["last_event_id"] is None else text(data["last_event_id"]),
        None if data["last_event_digest"] is None else sha256(data["last_event_digest"]),
        unique(data["consumed_effect_receipts"]),
        None if data["primary"] is None else text(data["primary"]),
        None if data["cleanup"] is None else text(data["cleanup"]),
        data["remote_uncertain"], text(data["schema"]), namespace,
    )


def _journal_event(value: object) -> DecisionEvent:
    data = public_object(value)
    if set(data) != set(DecisionEvent.__dataclass_fields__):
        raise _failure()
    return DecisionEvent(
        text(data["event_id"]), EventKind(text(data["kind"])),
        counter(data["expected_revision"]), sha256(data["plan_digest"]),
        sha256(data["context_digest"]), sha256(data["policy_digest"]),
        text(data["target_id"]), text(data["step_id"]), public_object(data["payload"]),
        None if data["operation_id"] is None else text(data["operation_id"]),
        None if data["install_id"] is None else text(data["install_id"]), text(data["schema"]),
    )


def _journal_facts(value: object) -> DecisionFacts:
    data = public_object(value)
    if set(data) != set(DecisionFacts.__dataclass_fields__):
        raise _failure()
    values = data["values"]
    # Operational facts contain the nonsecret credentials.channel_qualified
    # flag. Encode policy path names as pairs, not public credential objects.
    # Only the reducer's closed typed tree may validate the reconstructed facts.
    if isinstance(values, tuple):
        groups: dict[str, object] = {}
        for pair in values:
            if not isinstance(pair, tuple) or len(pair) != 2 or not isinstance(pair[1], tuple):
                raise _failure()
            name = text(pair[0])
            if name in groups:
                raise _failure()
            leaves: dict[str, object] = {}
            for leaf in pair[1]:
                if not isinstance(leaf, tuple) or len(leaf) != 2:
                    raise _failure()
                key = text(leaf[0])
                if key in leaves:
                    raise _failure()
                leaves[key] = leaf[1]
            groups[name] = leaves
        from .policy.contracts import object_value

        values = object_value(groups)
    if not isinstance(values, FrozenObject):
        raise _failure()
    return DecisionFacts(
        values, Phase(text(data["state_phase"])),
        counter(data["state_revision"]),
    )


def _encoded_journal_facts(facts: DecisionFacts) -> FrozenObject:
    if "credentials" not in facts.values:
        return public_object(wire(facts))
    values: list[object] = []
    for group, leaves in facts.values.items():
        if not isinstance(leaves, FrozenObject):
            raise _failure()
        values.append((group, tuple(leaves.items())))
    return public_object({
        "values": tuple(values), "state_phase": facts.state_phase.value,
        "state_revision": facts.state_revision,
    })


@dataclass(frozen=True)
class PolicyJournalReceipt:
    """Persisted factual event acknowledgement, never permission to dispatch."""

    checkpoint_revision: int
    event_id: str
    event_digest: str
    state: PolicyState
    duplicate: bool = False

    def __post_init__(self) -> None:
        """Validate factual receipt fields without creating private authority."""
        counter(self.checkpoint_revision)
        uuid_text(self.event_id)
        sha256(self.event_digest)
        if type(self.state) is not PolicyState or type(self.duplicate) is not bool:
            raise _failure()


class OwnedPolicyJournal:
    """Explicit protected event CAS with complete replay and no authority recovery.

    The host supplies its current independently verified binding. This journal
    proves only owned event history; it does not collect source facts, construct
    consent, reserve broker effects or replay any external handler.
    """

    def __init__(
        self, state: OwnedStatePort, policy: LocalPolicyPort, binding: PlanBinding,
        identity: PolicyIdentity, ownership_token: str,
        *, occurrence_id: str | None = None,
    ) -> None:
        binding.__post_init__()
        validate_identity(identity)
        if binding.policy_digest != identity.bundle_sha256:
            raise _failure(ReasonCode.INPUT_BINDING_INVALID)
        sha256(ownership_token)
        self._state = state
        self._policy = policy
        self._binding = replace(binding)
        self._identity = identity
        self._owner = ownership_token
        self._resource = "policy/" + binding.operation_id
        self._occurrence_id = occurrence_id
        if occurrence_id is not None:
            self._resource += "/step-" + digest(text(occurrence_id))

    def _bound(self, state: PolicyState) -> None:
        if (
            type(state) is not PolicyState
            or state.identity != self._identity or state.namespace != "operation"
            or state.operation_id != self._binding.operation_id
            or state.plan_digest != self._binding.plan_digest
            or state.context_digest != self._binding.context_digest
            or state.policy_digest != self._binding.policy_digest
        ):
            raise _failure(ReasonCode.CONSENT_STALE)
        if self._occurrence_id is not None and (
            len(state.dispositions) != 1
            or state.dispositions[0].effect_id != self._occurrence_id
        ):
            raise _failure(ReasonCode.CONSENT_STALE)

    def _entry(
        self, state: PolicyState, event: DecisionEvent, facts: DecisionFacts,
        checkpoint_revision: int,
    ) -> tuple[FrozenObject, PolicyJournalReceipt]:
        self._bound(state)
        if type(event) is not DecisionEvent or type(facts) is not DecisionFacts:
            raise _failure()
        transition = self._policy.reduce(state, event, facts)
        if type(transition) is not PolicyTransition:
            raise _failure()
        self._bound(transition.next_state)
        if transition.expected_revision != state.revision or transition.next_state.revision != state.revision + 1:
            raise _failure(ReasonCode.CONSENT_STALE)
        entry = public_object({
            "event": wire(event), "facts": _encoded_journal_facts(facts),
            "state_digest": digest(transition.next_state),
            "checkpoint_revision": checkpoint_revision,
        })
        receipt = PolicyJournalReceipt(
            checkpoint_revision, event.event_id, digest(event), transition.next_state,
        )
        return entry, receipt

    def create(
        self, initial: PolicyState, event: DecisionEvent, facts: DecisionFacts,
    ) -> PolicyJournalReceipt:
        """Create explicitly from a real validated first transition; never adopt."""
        try:
            self._bound(initial)
            if initial.revision != 0 or initial.phase != Phase.PLANNED:
                raise _failure()
            entry, receipt = self._entry(initial, event, facts, 0)
            record = OwnedRecord(
                self._resource, "checkpoint", 0, self._binding.generation, self._owner,
                self._identity.bundle_sha256, self._identity.reducer_version,
                public_object({
                    "schema": "1.0", "binding": wire(self._binding),
                    "initial": wire(initial), "events": (entry,),
                }), self._identity,
            )
            with self._state.lock((self._resource,), 0.0):
                self._state.compare_replace(self._resource, 0, record)
            return receipt
        except (ContractError, PolicyInputError, PolicyEvaluationError, TypeError, ValueError):
            raise _failure() from None

    def _load(self) -> tuple[OwnedRecord, tuple[PolicyJournalReceipt, ...]]:
        record = self._state.read(self._resource)
        record.__post_init__()
        payload = record.payload
        if (
            record.resource_id != self._resource or record.kind != "checkpoint"
            or record.ownership_token != self._owner or record.policy_identity != self._identity
            or record.generation != self._binding.generation
            or set(payload) != {"schema", "binding", "initial", "events"}
            or payload["schema"] != "1.0"
        ):
            raise _failure()
        if payload["binding"] != public_object(wire(self._binding)):
            raise _failure(ReasonCode.CONSENT_STALE)
        state = _journal_state(payload["initial"], self._identity)
        if state.revision != 0 or state.phase != Phase.PLANNED:
            raise _failure()
        events = payload["events"]
        if not isinstance(events, tuple) or len(events) == 0:
            raise _failure()
        receipts: list[PolicyJournalReceipt] = []
        seen: set[str] = set()
        for index, value in enumerate(events):
            if not isinstance(value, FrozenObject) or set(value) != {
                "event", "facts", "state_digest", "checkpoint_revision",
            } or counter(value["checkpoint_revision"]) != index:
                raise _failure()
            event = _journal_event(value["event"])
            if event.event_id in seen:
                raise _failure(ReasonCode.CONSENT_STALE)
            seen.add(event.event_id)
            _, receipt = self._entry(state, event, _journal_facts(value["facts"]), index)
            if digest(receipt.state) != value["state_digest"]:
                raise _failure()
            state = receipt.state
            receipts.append(receipt)
        if record.revision != len(receipts) - 1:
            raise _failure()
        return record, tuple(receipts)

    def recover(self) -> PolicyState:
        """Replay owned facts only; pending invocations recover as uncertain."""
        try:
            with self._state.lock((self._resource,), 0.0):
                _, receipts = self._load()
            state = receipts[-1].state
            if state.remote_uncertain or any(
                step.invocation_id is not None and step.result_digest is None
                for step in state.dispositions
            ):
                return replace(state, phase=Phase.UNCERTAIN, remote_uncertain=True)
            return state
        except (ContractError, PolicyInputError, PolicyEvaluationError, TypeError, ValueError, KeyError):
            raise _failure() from None

    def append(
        self, expected_revision: int, event: DecisionEvent, facts: DecisionFacts,
    ) -> PolicyJournalReceipt:
        """Accept exact duplicates without CAS; reject conflicts and stale writers."""
        try:
            counter(expected_revision)
            if type(event) is not DecisionEvent or type(facts) is not DecisionFacts:
                raise _failure()
            with self._state.lock((self._resource,), 0.0):
                record, receipts = self._load()
                for receipt in receipts:
                    if receipt.event_id == event.event_id:
                        if receipt.event_digest != digest(event):
                            raise _failure(ReasonCode.CONSENT_STALE)
                        # Replayed events cannot silently replace their source facts.
                        entries = record.payload["events"]
                        assert isinstance(entries, tuple)
                        original = entries[receipt.checkpoint_revision]
                        assert isinstance(original, FrozenObject)
                        if original["facts"] != _encoded_journal_facts(facts):
                            raise _failure(ReasonCode.CONSENT_STALE)
                        return replace(receipt, duplicate=True)
                if expected_revision != record.revision or record.revision == MAX_SAFE_INT:
                    raise _failure(ReasonCode.CONSENT_STALE)
                entry, receipt = self._entry(
                    receipts[-1].state, event, facts, record.revision + 1,
                )
                entries = record.payload["events"]
                assert isinstance(entries, tuple)
                replacement = replace(record, revision=record.revision + 1, payload=public_object({
                    **dict(record.payload), "events": entries + (entry,),
                }))
                self._state.compare_replace(self._resource, expected_revision, replacement)
                return receipt
        except (ContractError, PolicyInputError, PolicyEvaluationError, TypeError, ValueError, KeyError):
            raise _failure() from None
