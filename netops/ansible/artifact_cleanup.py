"""Sanitized teardown framing shared by protected storage and its native backend."""

from __future__ import annotations

import errno
import logging
import sys
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from netops.ansible.contracts import (
    ContractError,
    ErrorCategory,
    ReasonCode,
    SafeError,
    Stage,
    digest,
    sha256,
)

_NATIVE_LOG = logging.getLogger(__name__)
_OPERATION: ContextVar[str] = ContextVar("owned_native_operation", default="0" * 64)
_STAGES = frozenset(("managed-stage", "installation", "owned-state", "owned-cleanup"))
_OPERATIONS = frozenset((
    "stage-files", "verify-files", "write-member", "publish-generation", "open-directory",
    "create-directory", "sync-directory", "persist-intent", "persist-staged", "revoke-lifecycle",
    "close-handle", "replace-record", "read-record", "spawn-process", "install-files",
    "release-owned", "verify-tree", "create-environment",
))
_CAUSES = frozenset((
    "native-access-denied", "native-sharing-violation", "native-invalid-directory",
    "native-io", "posix-permission-denied", "storage-full", "unknown-io", "timeout",
    "interrupted", "native-path-too-long", "child-process-exit",
))


@dataclass(frozen=True)
class _StorageDiagnostic:
    """Private bounded facts; no native message, path, command or payload."""

    stage: str
    operation: str
    resource_sha256: str
    operation_sha256: str
    cause_class: str
    winerror: int | None
    errno: int | None
    origin: str = "host"
    child_exit_code: int | None = None
    child_exception_class: str = "none"

    def __post_init__(self) -> None:
        if (
            self.stage not in _STAGES or self.operation not in _OPERATIONS
            or self.cause_class not in _CAUSES
            or self.origin not in ("host", "child", "child-report")
            or self.child_exception_class not in (
                "none", "OSError", "PermissionError", "FileNotFoundError", "NotADirectoryError",
                "FileExistsError", "CalledProcessError", "RuntimeError", "ValueError",
                "ModuleNotFoundError", "ImportError", "LookupError", "TypeError",
            )
        ):
            raise ContractError()
        sha256(self.resource_sha256)
        sha256(self.operation_sha256)
        for value in (self.winerror, self.errno, self.child_exit_code):
            if value is not None and (type(value) is not int or not 0 <= value <= 0xFFFFFFFF):
                raise ContractError()

    @property
    def reference(self) -> str:
        return digest((
            self.stage, self.operation, self.resource_sha256, self.operation_sha256,
            self.cause_class, self.winerror, self.errno, self.origin, self.child_exit_code,
            self.child_exception_class,
        ))


def _storage_diagnostics(
    exc: BaseException, *, cleanup: bool = False,
) -> tuple[_StorageDiagnostic, ...]:
    try:
        values = getattr(
            exc, "_storage_cleanup_diagnostics" if cleanup else "_storage_diagnostics", (),
        )
    except BaseException:
        return ()
    if type(values) is not tuple:
        return ()
    result = []
    for value in values[:8]:
        if type(value) is _StorageDiagnostic:
            try:
                value.__post_init__()
                result.append(value)
            except BaseException:
                pass
    return tuple(result)


def _carry_storage_diagnostics(source: BaseException, target: BaseException) -> None:
    """Carry validated private references when an existing public wrapper sanitizes."""
    for cleanup, name in (
        (False, "_storage_diagnostics"), (True, "_storage_cleanup_diagnostics"),
    ):
        try:
            values = _storage_diagnostics(source, cleanup=cleanup)
            if values:
                setattr(target, name, values)
        except BaseException:
            pass
    owners = getattr(source, "_owned_cleanup_owners", ())
    if type(owners) is tuple:
        for owner in owners:
            _retain_cleanup_owner(target, owner)


def _retain_cleanup_owner(exc: BaseException, owner: object) -> None:
    """Keep exact failed-release rights reachable, without creating new authority."""
    owners = getattr(exc, "_owned_cleanup_owners", ())
    if type(owners) is not tuple:
        owners = ()
    if not any(value is owner for value in owners):
        setattr(exc, "_owned_cleanup_owners", (*owners, owner))


def _capture_storage_failure(
    exc: BaseException, stage: str, operation: str, resource_sha256: str,
) -> None:
    try:
        if _storage_diagnostics(exc):
            return
        # An implicit exception context may be an unrelated active primary.
        # Sanitizing wrappers explicitly carry diagnostics instead of guessing.
        if not isinstance(exc, OSError):
            return
        cause = exc
        native, code = getattr(cause, "winerror", None), cause.errno
        exit_code = getattr(cause, "child_exit_code", None)
        exit_code = exit_code if type(exit_code) is int and 0 <= exit_code <= 0xFFFFFFFF else None
        native = native if type(native) is int and 0 <= native <= 0xFFFFFFFF else None
        code = code if type(code) is int and 0 <= code <= 0xFFFFFFFF else None
        classification = (
            "native-access-denied" if native == 5 else
            "native-sharing-violation" if native in (32, 33) else
            "native-invalid-directory" if native == 267 else
            "native-path-too-long" if native == 206 else
            "native-io" if native is not None else
            "timeout" if isinstance(cause, TimeoutError) else
            "interrupted" if isinstance(cause, InterruptedError) else
            "posix-permission-denied" if code in (errno.EACCES, errno.EPERM) else
            "storage-full" if code == errno.ENOSPC else
            "child-process-exit" if exit_code is not None else "unknown-io"
        )
        origin = "host"
        supplied = getattr(cause, "_storage_origin", None)
        if type(supplied) is str and supplied in ("child", "child-report"):
            origin = supplied
        diagnostic = _StorageDiagnostic(
            stage, operation, resource_sha256, _OPERATION.get(), classification, native, code,
            origin, exit_code, getattr(cause, "child_exception_class", "none"),
        )
        setattr(exc, "_storage_diagnostics", (diagnostic,))
        _NATIVE_LOG.info("install.native.failure", extra={
            "metric_name": "netops.install.native_failure.count", "metric_value": 1,
            "metric_labels": ("stage", "operation", "cause_class"),
            "stage": stage, "operation": operation, "cause_class": classification,
            "diagnostic_ref": diagnostic.reference, "resource_sha256": resource_sha256,
            "operation_sha256": diagnostic.operation_sha256,
            "native_code": native, "errno": code,
            "diagnostic_origin": diagnostic.origin,
            "child_exit_code": exit_code,
            "child_exception_class": diagnostic.child_exception_class,
        })
    except BaseException:
        # A diagnostic sink, hostile exception or clock cannot replace the primary.
        return


@contextmanager
def _storage_operation(operation_sha256: str) -> Iterator[None]:
    token = _OPERATION.set(operation_sha256)
    try:
        yield
    finally:
        _OPERATION.reset(token)


@contextmanager
def _storage_io(stage: str, operation: str, resource_sha256: str) -> Iterator[None]:
    try:
        yield
    except BaseException as exc:
        _capture_storage_failure(exc, stage, operation, resource_sha256)
        raise


def _storage_detail(exc: BaseException) -> str:
    values = _storage_diagnostics(exc)
    return "storage-diagnostic:" + values[0].reference if values else ""


def cleanup_errors(exc: BaseException) -> tuple[SafeError, ...]:
    """Carry only validated structured secondary errors across public wrappers."""
    errors = getattr(exc, "cleanup_errors", ())
    if type(errors) is not tuple:
        return ()
    result = []
    for error in errors:
        if type(error) is SafeError and error.category == ErrorCategory.CLEANUP:
            try:
                error.__post_init__()
            except ContractError:
                continue
            result.append(error)
    return tuple(result)


class StorageCleanupError(OSError):
    """Transport only safe cleanup uncertainty to the public storage boundary."""

    def __init__(self, error: SafeError, errors: tuple[SafeError, ...]) -> None:
        self.cleanup_errors = (*errors, error)
        super().__init__("protected-storage-cleanup")


@contextmanager
def teardown(
    primary: BaseException | None = None,
    failure: Callable[[SafeError, tuple[SafeError, ...]], Exception] = StorageCleanupError,
) -> Iterator[None]:
    """Preserve the exact active primary, containing all secondary BaseExceptions."""
    if primary is None:
        primary = sys.exc_info()[1]
    try:
        yield
    except BaseException as secondary:
        _capture_storage_failure(secondary, "owned-cleanup", "release-owned", "0" * 64)
        error = SafeError(
            ErrorCategory.CLEANUP, ReasonCode.CLEANUP_FAILED, Stage.FINALIZE,
            detail=_storage_detail(secondary),
            next_action="Preserve the primary failure and inspect owned staging.",
        )
        errors = (*cleanup_errors(secondary), error)
        if primary is not None:
            owners = getattr(secondary, "_owned_cleanup_owners", ())
            if type(owners) is tuple:
                for owner in owners:
                    _retain_cleanup_owner(primary, owner)
            setattr(primary, "cleanup_errors", (*cleanup_errors(primary), *errors))
            setattr(primary, "_storage_cleanup_diagnostics", (
                *_storage_diagnostics(primary, cleanup=True), *_storage_diagnostics(secondary),
                *_storage_diagnostics(secondary, cleanup=True),
            )[:8])
        elif isinstance(secondary, Exception):
            wrapped = failure(error, cleanup_errors(secondary))
            _carry_storage_diagnostics(secondary, wrapped)
            raise wrapped from None
        else:
            setattr(secondary, "cleanup_errors", errors)
            raise


def release_all(actions: Iterable[Callable[[], object]]) -> None:
    """Attempt each owned release once, even after another release fails."""
    primary = original = sys.exc_info()[1]
    for action in actions:
        try:
            with teardown(primary):
                action()
        except BaseException as exc:
            primary = exc
    if original is None and primary is not None:
        raise primary from None
