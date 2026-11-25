"""Fixed prospective platform operations behind the original family authority.

Only the process/OS boundary is injectable. No public request supplies argv,
service names, executables, environment, callbacks or a serialized authority.
These drivers do not establish platform qualification.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import AuthorizationError

from ._family_lock import _Release, _trace
from ._family_provider import _Authority, _HostResult, _Operation, _Resource

if TYPE_CHECKING:
    from ._composition import ManagedLifecycleState
    from ._family_lock import _FamilyLock
    from ._managed import ManagedGenerationManifest

__all__: tuple[str, ...] = ()
_FEATURES = {
    "Microsoft-Windows-Subsystem-Linux": ("os", "wsl", "elevation"),
    "VirtualMachinePlatform": ("os", "vm", "virtualization", "elevation"),
}
_COMMANDS = {
    "runtime-version": "podman",
    "image-list": "podman", "image-load": "podman", "image-remove": "podman",
    "service-query": "systemctl", "service-start": "systemd-run", "service-stop": "systemctl",
    "feature-query": "dism", "feature-enable": "dism",
    "distribution-import": "wsl", "distribution-remove": "wsl",
}


@contextmanager
def _boundary(stage: str) -> Iterator[None]:
    _trace(stage, "platform", "attempt")
    try:
        yield
    except BaseException:
        _trace(stage, "platform", "raised")
        raise
    else:
        _trace(stage, "platform", "returned")


@dataclass(frozen=True)
class _Command:
    """Closed operation model; it is not an executable command-line interface."""

    kind: str
    tool: str
    tool_digest: str
    root: str
    resource_id: str
    payload: str | None = None
    payload_digest: str | None = None
    runtime: str | None = None
    image_digest: str | None = None
    feature: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in _COMMANDS:
            raise c.ContractError()
        if (
            not Path(self.tool).is_absolute() or not Path(self.root).is_absolute()
            or Path(self.tool).name not in (
                _COMMANDS[self.kind], _COMMANDS[self.kind] + ".exe",
            )
            or re.fullmatch(r"family-[0-9a-f]{40}", self.resource_id) is None
        ):
            raise c.ContractError()
        c.sha256(self.tool_digest)
        if self.kind in ("image-load", "distribution-import"):
            if self.payload is None or not Path(self.payload).is_absolute():
                raise c.ContractError()
            c.sha256(self.payload_digest)
        elif self.payload is not None or self.payload_digest is not None:
            raise c.ContractError()
        if self.kind == "image-remove":
            c.sha256(self.image_digest)
        elif self.image_digest is not None:
            raise c.ContractError()
        if self.kind == "service-start":
            if self.runtime is None or not Path(self.runtime).is_absolute() or (
                Path(self.runtime).name != "podman"
            ):
                raise c.ContractError()
        elif self.runtime is not None:
            raise c.ContractError()
        if self.kind.startswith("feature-"):
            if self.feature not in _FEATURES:
                raise c.ContractError()
        elif self.feature is not None:
            raise c.ContractError()

    @property
    def unit(self) -> str:
        return "netops-" + self.resource_id + ".service"

    @property
    def distro(self) -> str:
        return "NetOps-" + self.resource_id


def _arguments(call: _Command) -> tuple[str, ...]:
    """Compile only fixed allowlisted operations; no shell or global-runtime fallback."""
    call.__post_init__()
    root = Path(call.root)
    endpoint = "unix://" + str(root / "podman.sock")
    remote = (call.tool, "--remote", "--url", endpoint)
    if call.kind == "runtime-version":
        return call.tool, "--version"
    if call.kind == "image-list":
        return (*remote, "image", "list", "--all", "--no-trunc", "--format=json")
    if call.kind == "image-load":
        return (*remote, "image", "load", "--input", c.text(call.payload))
    if call.kind == "image-remove":
        return (*remote, "image", "rm", "sha256:" + c.sha256(call.image_digest))
    if call.kind == "service-query":
        return (
            call.tool, "--user", "show", call.unit, "--no-pager",
            "--property=LoadState,ActiveState,InvocationID",
        )
    if call.kind == "service-start":
        return (
            call.tool, "--user", "--collect", "--unit=" + call.unit,
            "--property=NoNewPrivileges=yes", "--property=UMask=0077",
            "--", c.text(call.runtime), "--root", str(root / "store"),
            "--runroot", str(root / "run"), "--storage-driver=vfs",
            "system", "service", "--time=0", endpoint,
        )
    if call.kind == "service-stop":
        return call.tool, "--user", "stop", "--", call.unit
    if call.kind == "feature-query":
        return (
            call.tool, "/English", "/Online", "/Get-FeatureInfo",
            "/FeatureName:" + c.text(call.feature),
        )
    if call.kind == "feature-enable":
        return (
            call.tool, "/English", "/Online", "/Enable-Feature",
            "/FeatureName:" + c.text(call.feature), "/NoRestart",
        )
    if call.kind == "distribution-import":
        return (
            call.tool, "--import", call.distro, str(root / call.resource_id),
            c.text(call.payload), "--version", "2",
        )
    return call.tool, "--unregister", call.distro


@dataclass(frozen=True)
class _Distribution:
    """Actual WSL registry UUID, exact location, version and protected disk bytes."""

    identifier: str
    location: str
    version: int
    content_digest: str

    def __post_init__(self) -> None:
        c.uuid_text(self.identifier)
        if not Path(self.location).is_absolute() or type(self.version) is not int:
            raise c.ContractError()
        c.sha256(self.content_digest)


class _NativePlatformIO:
    """Actual bounded subprocess/registry boundary; tests replace only these I/O methods."""

    def run(self, call: _Command, authority: _Authority) -> bytes:
        from ._installation import _hash
        from ._installation_process import _run

        call.__post_init__()
        authority.check()
        if _hash(
            Path(call.tool), authority._clock, authority._cancel, authority.deadline,
        ) != call.tool_digest:
            raise AuthorizationError()
        if call.payload is not None and _hash(
            Path(call.payload), authority._clock, authority._cancel, authority.deadline,
        ) != call.payload_digest:
            raise AuthorizationError()
        if call.runtime is not None:
            # The host independently checks the exact runtime's installation
            # receipt before constructing this call.
            if not Path(call.runtime).is_file() or Path(call.runtime).is_symlink():
                raise AuthorizationError()
        with _boundary("platform-" + call.kind):
            return _run(
                _arguments(call), Path(call.root), authority._clock, authority._cancel,
                authority.deadline, accepted=(0, 4) if call.kind == "service-query" else (0,),
            )

    def distribution(
        self, call: _Command, authority: _Authority,
    ) -> _Distribution | None:
        """Read only the fixed current-user WSL namespace; never write the registry."""
        call.__post_init__()
        if os.name != "nt" or call.kind != "distribution-remove":
            raise AuthorizationError()
        with _boundary("platform-distribution-query"):
            return self._distribution(call, authority)

    def _distribution(
        self, call: _Command, authority: _Authority,
    ) -> _Distribution | None:
        import winreg

        from ._installation import _tree

        name = call.distro
        authority.check()
        try:
            parent = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Lxss",
                0, winreg.KEY_READ,
            )
        except FileNotFoundError:
            return None
        found = []
        with parent:
            count, _, _ = winreg.QueryInfoKey(parent)
            if count > 256:
                raise c.ContractError()
            for index in range(count):
                authority.check()
                identifier = winreg.EnumKey(parent, index)
                with winreg.OpenKey(parent, identifier, 0, winreg.KEY_READ) as item:
                    if winreg.QueryValueEx(item, "DistributionName")[0] != name:
                        continue
                    location = winreg.QueryValueEx(item, "BasePath")[0]
                    version = winreg.QueryValueEx(item, "Version")[0]
                    if type(location) is not str or type(version) is not int:
                        raise c.ContractError()
                    if Path(location) != Path(call.root) / call.resource_id or version != 2:
                        raise AuthorizationError()
                    # This is deliberately strict: an altered or live disk is
                    # not a reason to unregister a user's changed distribution.
                    manifest = _tree(
                        Path(location), authority._clock, authority._cancel, authority.deadline,
                    )
                    found.append(_Distribution(
                        identifier.strip("{}"), location, version, c.digest(manifest),
                    ))
        if len(found) > 1:
            raise AuthorizationError()
        return found[0] if found else None


def _scopes(release: _Release) -> tuple[str, ...] | None:
    family = release.requirement.family
    if family == "runtime" and release.resource == "podman-rootless":
        return ("runtime",)
    if family == "image" and release.format == "oci-archive" and re.fullmatch(
        r"sha256-[0-9a-f]{64}", release.resource or "",
    ):
        return ("image", "runtime", "service", "security")
    if family == "service" and release.resource == "podman-user-service":
        return ("service", "runtime", "security")
    if family == "os-feature":
        return _FEATURES.get(release.resource or "")
    if family == "distribution" and release.format == "wsl-rootfs":
        return ("distribution", "wsl", "vm", "virtualization")
    return None


def _supported_release(release: _Release) -> bool:
    scopes = _scopes(release)
    return scopes is not None and set(scopes) <= set(release.scopes) and (
        set(release.platforms) == {"win32"} if release.requirement.family in (
            "os-feature", "distribution",
        ) else set(release.platforms) == {"linux"}
    ) and (
        len(release.members) == 1 and release.artifact is not None
        and release.members[0].digest == release.artifact.sha256
        and release.members[0].size == release.artifact.size
        if release.requirement.family in ("image", "distribution") else True
    )


def _required_tools(release: _Release) -> tuple[str, ...]:
    return {
        "runtime": ("podman",), "image": ("podman",),
        "service": ("podman", "systemctl", "systemd-run"),
        "os-feature": ("dism",), "distribution": ("wsl",),
    }.get(release.requirement.family, ())


def _platform_binding(
    manifest: ManagedGenerationManifest, payload: c.FrozenObject,
) -> tuple[str, str]:
    """Share the exact retained-directory predicate between dispatch and cleanup."""
    identity = payload.get("identity")
    if (
        set(payload) != {"schema", "generation_id", "manifest_digest", "identity"}
        or payload["schema"] != "netops-platform-root-v1"
        or payload["generation_id"] != manifest.generation_id
        or payload["manifest_digest"] != c.digest(manifest)
        or type(identity) is not tuple or len(identity) != 2
    ):
        raise AuthorizationError()
    return c.text(identity[0]), c.text(identity[1])


class _PlatformFamilies:
    """Concrete exact-identity drivers, called only by the original managed owner."""

    def __init__(
        self, owner: ManagedLifecycleState, manifest: ManagedGenerationManifest,
        lock: _FamilyLock,
    ) -> None:
        from ._composition import ManagedLifecycleState
        from ._managed import ProtectedGenerationFiles

        if (
            type(owner) is not ManagedLifecycleState
            or type(owner.files) is not ProtectedGenerationFiles
            or manifest not in owner.manifests
            or owner._family_locks.get(manifest.generation_id) != lock
            or manifest.installation is None
        ):
            raise AuthorizationError()
        self._owner, self._manifest, self._lock = owner, manifest, lock
        self._files = owner.files
        self._io = _NativePlatformIO()

    def _platform_root(self, operation: _Operation, authority: _Authority) -> str:
        from netops.ansible import artifact_platform as storage
        from netops.ansible.artifacts import _root

        root = self._files._root
        directory = "platform-" + c.digest(self._manifest.generation_id)
        resource = "platform-root-" + c.digest(self._manifest.generation_id)
        authority.check()
        try:
            retained = self._owner._read(resource)
        except FileNotFoundError:
            if operation.action != "install":
                raise AuthorizationError() from None
            with _root(root) as parent:
                # mkdir is exclusive: an unknown existing path is never adopted.
                authority.check()
                storage.mkdir(parent, directory)
                child = storage.open_directory(parent, directory)
                try:
                    info = storage.info(child)
                    if storage.names(child):
                        raise AuthorizationError()
                    identity = (str(info.st_dev), str(info.st_ino))
                finally:
                    storage.close(child)
            template = self._owner._facts()
            retained = self._owner._write(resource, 0, replace(
                template, resource_id=resource, revision=0,
                payload=c.public_object({
                    "schema": "netops-platform-root-v1",
                    "generation_id": self._manifest.generation_id,
                    "manifest_digest": c.digest(self._manifest), "identity": identity,
                }),
            ))
        identity = _platform_binding(self._manifest, retained.payload)
        with _root(root) as parent:
            child = storage.open_directory(parent, directory)
            try:
                info = storage.info(child)
                if identity != (str(info.st_dev), str(info.st_ino)):
                    raise AuthorizationError()
            finally:
                storage.close(child)
        return str(Path(root.path) / directory)

    def _tool(
        self, name: str, authority: _Authority, context: str = "native",
    ) -> tuple[str, str]:
        from ._installation import _hash, _OfflineInstallation

        spec = self._manifest.installation
        if spec is None:
            raise AuthorizationError()
        separate = spec.controller_installation is not None and context == "controller"
        if separate:
            spec = spec.for_context(context)
        destination = "tools/" + name + (".exe" if spec.platform == "win32" else "")
        supplied = tuple(
            item for item in spec.native_files
            if item.destination == destination and item.executable
        )
        if len(supplied) != 1:
            raise AuthorizationError()
        path = _OfflineInstallation(
            self._files._root, controller=separate,
        ).path(self._manifest) / destination
        if _hash(path, authority._clock, authority._cancel, authority.deadline) != supplied[0].digest:
            raise AuthorizationError()
        return str(path), supplied[0].digest

    def _call(
        self, kind: str, operation: _Operation, authority: _Authority,
        release: _Release, *, payload: bool = False,
    ) -> _Command:
        from ._installation import _OfflineInstallation

        context = release.requirement.context
        tool, digest = self._tool(_COMMANDS[kind], authority, context)
        spec = self._manifest.installation
        separate = spec is not None and spec.controller_installation is not None and context == "controller"
        root = (
            _OfflineInstallation(self._files._root, controller=separate).path(self._manifest)
            if kind == "runtime-version" else Path(self._platform_root(operation, authority))
        )
        member = None
        if payload:
            if len(release.members) != 1 or release.artifact is None:
                raise AuthorizationError()
            member = release.members[0]
            if member.digest != release.artifact.sha256 or member.size != release.artifact.size:
                raise AuthorizationError()
        runtime = self._tool("podman", authority, context)[0] if kind == "service-start" else None
        return _Command(
            kind, tool, digest, str(root), operation.resource_id,
            str(Path(self._files._root.path) / self._files._directory(
                self._manifest,
            ) / member.path) if member is not None else None,
            member.digest if member is not None else None, runtime,
            release.resource[len("sha256-"):] if kind == "image-remove" and release.resource else None,
            release.resource if kind.startswith("feature-") else None,
        )

    def _enter(
        self, release: _Release, operation: _Operation, authority: _Authority, family: str,
    ) -> None:
        if (
            type(authority) is not _Authority or type(operation) is not _Operation
            or release not in self._lock.releases or release.requirement.family != family
            or not _supported_release(release) or operation.release_digest != c.digest(release)
            or operation.generation_id != self._manifest.generation_id
        ):
            raise AuthorizationError()
        authority.enter(operation)
        actual = self._files._verify(
            self._manifest, authority._clock, authority._cancel, authority.deadline,
            functional=False,
        )
        self._owner._installed_receipt(self._manifest, actual)

    def _retained_result(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _Resource | None:
        """Recover facts only from our prior exact post-I/O receipt, never existence."""
        if existing is not None or operation.action != "verify":
            return existing
        from ._family_provider import _operation

        issued = _operation(self._lock, release, "install", operation.generation_id)
        authority.check()
        try:
            record = self._owner._read("platform-result-" + c.digest(issued))
        except FileNotFoundError:
            raise AuthorizationError() from None
        payload = record.payload
        if (
            set(payload) != {"schema", "operation", "manifest_digest", "result"}
            or payload["schema"] != "netops-platform-result-v1"
            or payload["operation"] != c.public_object(c.wire(issued))
            or payload["manifest_digest"] != c.digest(self._manifest)
        ):
            raise AuthorizationError()
        raw = c.public_object(payload["result"])
        if set(raw) != set(_HostResult.__dataclass_fields__):
            raise AuthorizationError()
        values: dict = dict(raw)
        result = _HostResult(**values)
        result.__post_init__()
        if not result.owned or not result.verified:
            raise AuthorizationError()
        return _Resource(
            operation.resource_id, operation.generation_id, operation.lock_digest,
            operation.release_digest, result.identity_digest, True, False, (),
        )

    def _finish(
        self, operation: _Operation, authority: _Authority, result: _HostResult,
    ) -> _HostResult:
        """Persist observed identity before the separate family-ledger acknowledgement."""
        result.__post_init__()
        if operation.action == "verify":
            return result
        authority.check()
        resource = "platform-result-" + c.digest(operation)
        payload = c.public_object({
            "schema": "netops-platform-result-v1", "operation": c.wire(operation),
            "manifest_digest": c.digest(self._manifest), "result": c.wire(result),
        })
        try:
            previous = self._owner._read(resource)
        except FileNotFoundError:
            previous = None
        if previous is not None:
            if previous.payload != payload:
                raise AuthorizationError()
            return result
        template = self._owner._facts()
        self._owner._write(resource, 0, replace(
            template, resource_id=resource, revision=0, payload=payload,
        ))
        return result

    def reconcile_removal(
        self, release: _Release, operation: _Operation,
        authority: _Authority, existing: _Resource,
    ) -> _HostResult:
        """Read-only recovery; an uncertain removal is never dispatched again."""
        if operation.action != "remove" or not existing.owned:
            raise AuthorizationError()
        family = release.requirement.family
        self._enter(release, operation, authority, family)
        record = self._owner._read("platform-result-" + c.digest(operation))
        raw = record.payload
        if (
            set(raw) != {"schema", "operation", "manifest_digest", "result"}
            or raw["schema"] != "netops-platform-result-v1"
            or raw["operation"] != c.public_object(c.wire(operation))
            or raw["manifest_digest"] != c.digest(self._manifest)
        ):
            raise AuthorizationError()
        values: dict = dict(c.public_object(raw["result"]))
        if set(values) != set(_HostResult.__dataclass_fields__):
            raise AuthorizationError()
        prior = _HostResult(**values)
        prior.__post_init__()
        if (
            prior.identity_digest != existing.identity_digest
            or not prior.owned or not prior.verified
        ):
            raise AuthorizationError()
        if family == "runtime":
            content = self._io.run(
                self._call("runtime-version", operation, authority, release), authority,
            )
            if content.strip() != ("podman version " + release.version).encode("ascii"):
                raise AuthorizationError()
        elif family == "os-feature":
            content = self._io.run(
                self._call("feature-query", operation, authority, release), authority,
            )
            if re.findall(rb"(?m)^State\s*:\s*(Enabled|Disabled)\s*\r?$", content) != [b"Enabled"]:
                raise AuthorizationError()
        elif family == "image":
            self._service_identity(authority)
            content = self._io.run(
                self._call("image-list", operation, authority, release), authority,
            )
            images = json.loads(content)
            if type(images) is not list or len(images) > 4096 or any(
                type(item) is not dict or type(item.get("Id")) is not str
                for item in images
            ) or any(
                item["Id"] == "sha256:" + c.text(release.resource)[len("sha256-"):]
                for item in images
            ):
                raise AuthorizationError()
        elif family == "service":
            content = self._io.run(
                self._call("service-query", operation, authority, release), authority,
            )
            service_values: dict[str, str] = {}
            for line in content.decode("ascii").splitlines():
                key, separator, value = line.partition("=")
                if not separator or key in service_values:
                    raise AuthorizationError()
                service_values[key] = value
            if (
                set(service_values) != {"LoadState", "ActiveState", "InvocationID"}
                or service_values["LoadState"] != "not-found" or service_values["InvocationID"]
            ):
                raise AuthorizationError()
        elif family == "distribution":
            call = self._call("distribution-remove", operation, authority, release)
            if self._io.distribution(call, authority) is not None:
                raise AuthorizationError()
            location = Path(call.root) / operation.resource_id
            if location.exists() or location.is_symlink():
                raise AuthorizationError()
        else:
            raise AuthorizationError()
        authority.check()
        return _HostResult(existing.identity_digest, False, True, True)

    def runtime(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        self._enter(release, operation, authority, "runtime")
        existing = self._retained_result(release, operation, authority, existing)
        observed = self._io.run(self._call("runtime-version", operation, authority, release), authority)
        if observed.strip() != ("podman version " + release.version).encode("ascii"):
            raise AuthorizationError()
        # This receipts only the exact binary already materialized by the
        # original installer. It cannot certify a daemon or image readiness.
        identity = c.digest((self._manifest.generation_id, release))
        if existing is not None and existing.identity_digest != identity:
            raise AuthorizationError()
        return self._finish(operation, authority, _HostResult(identity, False, True, True))

    def image(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        self._enter(release, operation, authority, "image")
        existing = self._retained_result(release, operation, authority, existing)
        self._service_identity(authority)
        expected = "sha256:" + c.text(release.resource)[len("sha256-"):]

        def present() -> bool:
            content = self._io.run(self._call("image-list", operation, authority, release), authority)
            values = json.loads(content)
            if type(values) is not list or len(values) > 4096:
                raise c.ContractError()
            if any(type(item) is not dict or type(item.get("Id")) is not str for item in values):
                raise c.ContractError()
            return any(item["Id"] == expected for item in values)

        identity = c.digest((self._manifest.generation_id, release.requirement.key, expected))
        before = present()
        if existing is not None and existing.identity_digest != identity:
            raise AuthorizationError()
        if operation.action == "install":
            if before and existing is None:
                raise AuthorizationError()
            if not before:
                self._io.run(self._call(
                    "image-load", operation, authority, release, payload=True,
                ), authority)
        elif operation.action == "remove" and before:
            if existing is None or not existing.owned:
                raise AuthorizationError()
            self._io.run(self._call("image-remove", operation, authority, release), authority)
        after = present()
        if after != (operation.action != "remove"):
            raise AuthorizationError()
        return self._finish(operation, authority, _HostResult(identity, before != after, True, True))

    def _service_identity(self, authority: _Authority) -> None:
        from ._family_ledger import _resource
        from ._family_provider import _operation

        services = tuple(item for item in self._lock.releases
                         if item.requirement.family == "service"
                         and item.resource == "podman-user-service")
        if len(services) != 1:
            raise AuthorizationError()
        release = services[0]
        operation = _operation(self._lock, release, "verify", self._manifest.generation_id)
        ledger = self._owner._read("family-ledger-" + c.digest(self._manifest.generation_id))
        resources = ledger.payload.get("resources")
        if type(resources) is not tuple:
            raise AuthorizationError()
        owned = tuple(_resource(item) for item in resources
                      if c.public_object(item).get("resource_id") == operation.resource_id)
        if len(owned) != 1 or (
            not owned[0].owned or owned[0].release_digest != c.digest(release)
            or owned[0].lock_digest != self._lock.digest
        ):
            raise AuthorizationError()
        call = self._call("service-query", operation, authority, release)
        content = self._io.run(call, authority).decode("ascii").splitlines()
        values = {}
        for line in content:
            key, separator, value = line.partition("=")
            if not separator or key in values:
                raise AuthorizationError()
            values[key] = value
        if (
            set(values) != {"LoadState", "ActiveState", "InvocationID"}
            or values["LoadState"] != "loaded" or values["ActiveState"] != "active"
            or re.fullmatch(r"[0-9a-f]{32}", values["InvocationID"]) is None
            or c.digest((operation.resource_id, values["InvocationID"])) != owned[0].identity_digest
        ):
            raise AuthorizationError()

    def service(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        self._enter(release, operation, authority, "service")
        existing = self._retained_result(release, operation, authority, existing)

        def observe() -> tuple[bool, str]:
            content = self._io.run(self._call("service-query", operation, authority, release), authority)
            values = {}
            for line in content.decode("ascii").splitlines():
                key, separator, value = line.partition("=")
                if not separator or key in values:
                    raise c.ContractError()
                values[key] = value
            if set(values) != {"LoadState", "ActiveState", "InvocationID"}:
                raise c.ContractError()
            if values["LoadState"] == "not-found":
                return False, ""
            if values["ActiveState"] == "active" and re.fullmatch(
                r"[0-9a-f]{32}", values["InvocationID"],
            ):
                return True, values["InvocationID"]
            raise AuthorizationError()

        before, identifier = observe()
        if before and (
            existing is None or existing.identity_digest != c.digest((operation.resource_id, identifier))
        ):
            raise AuthorizationError()
        if operation.action == "install" and not before:
            self._io.run(self._call("service-start", operation, authority, release), authority)
        elif operation.action == "remove" and before:
            self._io.run(self._call("service-stop", operation, authority, release), authority)
        after, following = observe()
        if after != (operation.action != "remove") or (
            before and after and following != identifier
        ):
            raise AuthorizationError()
        identity = c.digest((operation.resource_id, following if after else identifier))
        if not before and operation.action != "install":
            raise AuthorizationError()
        return self._finish(operation, authority, _HostResult(identity, before != after, True, True))

    def os_feature(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        self._enter(release, operation, authority, "os-feature")
        existing = self._retained_result(release, operation, authority, existing)

        def enabled() -> bool:
            content = self._io.run(self._call("feature-query", operation, authority, release), authority)
            states = re.findall(rb"(?m)^State\s*:\s*(Enabled|Disabled)\s*\r?$", content)
            if len(states) != 1:
                raise AuthorizationError()
            return bool(states[0] == b"Enabled")

        identity = c.digest((self._manifest.generation_id, release.resource, release.metadata_digest))
        before = enabled()
        if existing is not None and existing.identity_digest != identity:
            raise AuthorizationError()
        if operation.action == "install" and not before:
            self._io.run(self._call("feature-enable", operation, authority, release), authority)
        elif operation.action == "install" and existing is None:
            # Already enabled facilities are external observations, not ours.
            raise AuthorizationError()
        # OS features are shared facilities: uninstall retires only the owned
        # declaration and NEVER disables a feature or reboots the host.
        if not enabled():
            raise AuthorizationError()
        return self._finish(operation, authority, _HostResult(identity, not before, True, True))

    def distribution(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        self._enter(release, operation, authority, "distribution")
        existing = self._retained_result(release, operation, authority, existing)
        query = self._call("distribution-remove", operation, authority, release)

        def observe() -> _Distribution | None:
            item = self._io.distribution(query, authority)
            if item is not None:
                if type(item) is not _Distribution:
                    raise c.ContractError()
                item.__post_init__()
                if Path(item.location) != Path(query.root) / operation.resource_id or item.version != 2:
                    raise AuthorizationError()
            return item

        before = observe()
        if before is not None and (
            existing is None or existing.identity_digest != c.digest(before)
        ):
            raise AuthorizationError()
        if operation.action == "install" and before is None:
            location = Path(query.root) / operation.resource_id
            if location.exists() or location.is_symlink():
                raise AuthorizationError()
            self._io.run(self._call(
                "distribution-import", operation, authority, release, payload=True,
            ), authority)
        elif operation.action == "remove" and before is not None:
            self._io.run(query, authority)
        after = observe()
        if (after is not None) != (operation.action != "remove"):
            raise AuthorizationError()
        if before is not None and after is not None and before != after:
            raise AuthorizationError()
        if before is None and operation.action != "install":
            raise AuthorizationError()
        return self._finish(operation, authority, _HostResult(
            c.digest(after if after is not None else before), before != after, True, True,
        ))
