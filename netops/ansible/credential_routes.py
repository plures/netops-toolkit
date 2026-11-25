"""Controller-origin checks of approved route files, without reading key bytes.

Construct this adapter in the selected controller origin. Remote-origin
transport and its authenticated private observation channel belong to S02;
instantiating it on a workstation is not a WSL/controller observation.
"""

from __future__ import annotations

import os
import stat
import sys
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from netops.ansible.contracts import ControllerContext, ReasonCode, digest, text
from netops.ansible.credentials import (
    CredentialError,
    CredentialScope,
    CredentialTelemetry,
    RouteBinding,
)


def _reject(reason: ReasonCode = ReasonCode.ROUTE_UNAVAILABLE) -> NoReturn:
    raise CredentialError(reason) from None


def _stamp(value: os.stat_result) -> tuple[int, ...]:
    # Windows 3.12 lstat's deprecated ctime is creation time while fstat's
    # ctime can be change time. Compare birth time when available, never these
    # two incompatible values. POSIX ctime remains useful drift evidence.
    change_time = (
        getattr(value, "st_birthtime_ns", 0) if os.name == "nt" else value.st_ctime_ns
    )
    return (
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
        change_time, value.st_mode, value.st_uid,
    )


def _inspect(path: Path, purpose: str) -> tuple[int, ...]:
    """Check readable regular-file metadata; never read or hash file content."""
    try:
        if (
            not path.is_absolute() or ".." in path.parts
            or str(path).startswith(("\\\\", "//"))
            or any(":" in part for part in path.parts[1:])
            or purpose not in ("private-key", "known-hosts")
        ):
            _reject()
        # Reject reparse points as well as symlinks, including parent aliases.
        for component in (*reversed(path.parents), path):
            value = component.lstat()
            if (
                stat.S_ISLNK(value.st_mode)
                or getattr(value, "st_file_attributes", 0) & 0x400
            ):
                _reject()
            if sys.platform != "win32" and component != path and (
                not stat.S_ISDIR(value.st_mode)
                or value.st_uid not in (0, os.getuid()) or value.st_mode & 0o022
            ):
                _reject()
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size <= 0:
            _reject()
        if sys.platform != "win32" and (
            before.st_uid != os.getuid()
            or before.st_mode & (0o077 if purpose == "private-key" else 0o022)
        ):
            _reject()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            after = path.lstat()
            if not stat.S_ISREG(opened.st_mode) or not (
                _stamp(before) == _stamp(opened) == _stamp(after)
            ):
                _reject()
            return _stamp(opened)
        finally:
            os.close(descriptor)
    except CredentialError:
        raise
    except Exception:
        _reject()


@dataclass(frozen=True)
class ApprovedRouteFile:
    """Nonsecret metadata captured by trusted setup after separate approval.

    This is drift evidence, not consent or qualification. Private key bytes and
    their hashes are never retained. Windows ACL and origin/fork proof remain
    the qualification owner's responsibility.
    """

    ref: str
    path: Path
    purpose: str
    stamp: tuple[int, ...]

    def __post_init__(self) -> None:
        """Validate metadata-only shape without observing or enrolling a file."""
        text(self.ref)
        if (
            type(self.path) is not type(Path()) or not self.path.is_absolute()
            or self.purpose not in ("private-key", "known-hosts")
            or type(self.stamp) is not tuple or len(self.stamp) != 7
            or any(type(value) is not int or value < 0 for value in self.stamp)
        ):
            _reject()

    @classmethod
    def observe(cls, ref: str, path: Path, purpose: str) -> ApprovedRouteFile:
        """Capture metadata explicitly; never enroll trust during validation."""
        text(ref)
        if type(path) is not type(Path()):
            _reject()
        return cls(ref, path, purpose, _inspect(path, purpose))


class ControllerOriginRoutePolicy:
    """Revalidate only the exact approved controller-origin route and files.

    Trusted setup/qualification supplies the approved binding; the adapter
    cannot mint qualification, enroll host keys, discover keys or fall back.
    """

    def __init__(
        self, origin: ControllerContext, approved: RouteBinding,
        files: tuple[ApprovedRouteFile, ...],
        *, telemetry: CredentialTelemetry | None = None,
    ) -> None:
        if (
            type(origin) is not ControllerContext or type(approved) is not RouteBinding
            or type(files) is not tuple
            or any(type(item) is not ApprovedRouteFile for item in files)
            or len({item.ref for item in files}) != len(files)
        ):
            _reject()
        for item in files:
            item.__post_init__()
        self._telemetry = telemetry if telemetry is not None else CredentialTelemetry()
        self._origin = deepcopy(origin)
        self._approved = deepcopy(approved)
        self._files = deepcopy(files)

    def validate(self, context: ControllerContext, scope: CredentialScope) -> RouteBinding:
        """Observe local approved-file metadata only, never network or key bytes."""
        try:
            route = self._approved
            route.__post_init__()
            scope.__post_init__()
            if (
                context != self._origin or context != scope.context
                or route.controller_digest != digest(self._origin.context.controller_id)
                or route.controller_digest != scope.controller_digest
                or route.route_digest != scope.route_digest
                or scope.route_digest != self._origin.context.route_digest
                or route.targets != scope.targets
                or route.controller_local is not True
                or route.private_channel_qualified is not True
                or route.keys_accessible is not True
            ):
                _reject()
            if route.host_key_policy != "reject":
                _reject(ReasonCode.HOST_KEY_INVALID)
            selected = (*scope.targets, *((route.jump,) if route.jump is not None else ()))
            if any(target.transport not in ("ssh", "ssh2") for target in selected):
                _reject()
            if route.jump is not None and (
                route.jump.transport != "ssh" or route.jump.task_id != "route"
                or route.jump.target_id in {target.target_id for target in scope.targets}
            ):
                _reject()
            required: set[tuple[str, str]] = set()
            for target in selected:
                target.__post_init__()
                if target.known_hosts_ref is None:
                    _reject(ReasonCode.HOST_KEY_INVALID)
                required.add((target.known_hosts_ref, "known-hosts"))
                if target.key_ref is not None:
                    required.add((target.key_ref, "private-key"))
            if {(item.ref, item.purpose) for item in self._files} != required:
                _reject()
            for item in self._files:
                if _inspect(item.path, item.purpose) != item.stamp:
                    _reject(
                        ReasonCode.HOST_KEY_INVALID if item.purpose == "known-hosts"
                        else ReasonCode.ROUTE_UNAVAILABLE,
                    )
            return route
        except CredentialError as error:
            self._telemetry.rejected("credential-route", error.error.reason)
            raise
        except Exception:
            self._telemetry.rejected("credential-route", ReasonCode.ROUTE_UNAVAILABLE)
            _reject()
