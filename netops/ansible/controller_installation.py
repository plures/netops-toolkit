"""Consume owned installed bytes and packaged exact qualification, never adopt."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from . import contracts as c
from .artifacts import OwnedStatePort, validate_member_path
from .controller import ControllerInstallation
from .controller_protocol import ProtocolError

_RUNTIME_MEMBERS = (
    "netops/ansible/worker.py", "netops/ansible/controller_runner.py",
    "netops/ansible/action_runtime.py", "netops/ansible/_action_mutation.py",
    "netops/ansible/_action_health.py", "netops/ansible/_windows_job.py",
    "netops/ansible/action_plugins/netops_workflow.py", "ansible/plugins/action/__init__.py",
)


def _require_runtime_members(
    required: object, python_member: str, files: set[str], *, prefix: str = "",
) -> None:
    if (
        type(required) is not list or not required
        or any(type(name) is not str for name in required)
        or python_member not in required or not set(required) <= files
        or any(not name.startswith(prefix) for name in required)
    ):
        raise ProtocolError()
    for source in _RUNTIME_MEMBERS:
        if not any(name == source or name.endswith("/" + source) for name in required):
            raise ProtocolError()


class _OwnedInstallationVerifier:
    """Read-only verifier over existing active/install receipts and file pins.

    Resource IDs, root and owner are private bootstrap selections. No request
    boolean, inert lifecycle record, version range or directory scan can
    qualify an installation. Only Q03's packaged exact lock can do that.
    """

    def __init__(
        self, root: Path, active_resource: str, install_resource: str,
        ownership_token: str,
    ) -> None:
        if not root.is_absolute():
            raise c.ContractError()
        c.sha256(ownership_token)
        c.text(active_resource)
        c.text(install_resource)
        self._root, self._active, self._install, self._owner = (
            root, active_resource, install_resource, ownership_token,
        )

    @staticmethod
    def _stamp(info: os.stat_result) -> tuple[int, ...]:
        # Access time legitimately changes while hashing; identity, ownership,
        # content size and modification/change times must not.
        return (
            info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        )

    @staticmethod
    def _qualification_lock() -> dict:
        from importlib.resources import files

        value = json.loads(files("netops.dependencies").joinpath("qualification.json").read_bytes())
        if type(value) is not dict:
            raise ProtocolError()
        return value

    @staticmethod
    def _private(path: Path, *, directory: bool) -> os.stat_result:
        info = path.lstat()
        getuid = getattr(os, "getuid", None)
        if (
            getuid is None or info.st_uid != getuid() or stat.S_ISLNK(info.st_mode)
            or info.st_mode & 0o077
            or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)
        ):
            raise ProtocolError()
        return info

    def _selection(
        self, context: c.ControllerContext, state: OwnedStatePort,
    ) -> tuple[tuple, str]:
        active, installed = state.read(self._active), state.read(self._install)
        for record in (active, installed):
            record.__post_init__()
            if (
                record.ownership_token != self._owner
                or record.policy_identity != context.context.policy_identity
            ):
                raise ProtocolError()
        if (
            active.kind != "active" or installed.kind != "install"
            or active.payload["environment_id"] != self._install
            or installed.payload["controller_digest"] != c.digest(context.context.controller_id)
        ):
            raise ProtocolError()
        manifest = installed.payload["manifest"]
        if not isinstance(manifest, tuple):
            raise ProtocolError()
        installation_digest = c.digest(manifest)
        if active.payload["content_digest"] != installation_digest:
            raise ProtocolError()
        return manifest, installation_digest

    def _resources(self) -> tuple[str, ...]:
        return self._active, self._install

    def _runtime_selection(self) -> tuple[str | None, str]:
        """Retain legacy qualification selection unless a managed layout pins it."""
        return None, ""

    @staticmethod
    def _member_parts(relative: str) -> tuple[str, ...]:
        return validate_member_path(relative)

    def verify(
        self, context: c.ControllerContext, state: OwnedStatePort,
    ) -> ControllerInstallation | None:
        """Check exact lock before touching any installed executable or assets."""
        try:
            lock = self._qualification_lock()
            # Empty/current unqualified lock blocks before reading/adopting paths.
            if lock.get("state") != "qualified" or not lock.get("qualified"):
                return None
            with state.lock(self._resources(), 0.0):
                manifest, installation_digest = self._selection(context, state)
                entries = [
                    entry for entry in lock["qualified"] if type(entry) is dict
                    and entry.get("installation_digest") == installation_digest
                    and entry.get("context_digest") == c.digest(context)
                ]
                if len(entries) != 1:
                    raise ProtocolError()
                evidence = entries[0]
                if (
                    set(evidence.get("tuple", {})) != set(lock["required_tuple"])
                    or evidence.get("state") != "qualified"
                    or evidence.get("platform") not in ("linux", "macos")
                    or evidence.get("evidence_digest") in (None, "0" * 64)
                ):
                    raise ProtocolError()
                c.sha256(evidence["evidence_digest"])
                root_before = self._private(self._root, directory=True)
                paths: set[str] = set()
                files: set[str] = set()
                directories: set[str] = set()
                total = 0
                for member in manifest:
                    if not isinstance(member, c.FrozenObject):
                        raise ProtocolError()
                    relative = c.text(member["path"])
                    parts = self._member_parts(relative)
                    if relative in paths:
                        raise ProtocolError()
                    paths.add(relative)
                    if len(paths) > 32768:
                        raise ProtocolError()
                    for index in range(1, len(parts)):
                        self._private(self._root.joinpath(*parts[:index]), directory=True)
                        directories.add("/".join(parts[:index]))
                    path = self._root.joinpath(*parts)
                    directory = member["kind"] == "directory"
                    before = self._private(path, directory=directory)
                    if directory:
                        directories.add(relative)
                    else:
                        files.add(relative)
                        total += before.st_size
                        if before.st_size > 256 * 1024 * 1024 or total > 1024 * 1024 * 1024:
                            raise ProtocolError()
                        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                        with os.fdopen(descriptor, "rb") as stream:
                            if self._stamp(os.fstat(stream.fileno())) != self._stamp(before):
                                raise ProtocolError()
                            hasher = hashlib.sha256()
                            while True:
                                chunk = stream.read(1024 * 1024)
                                if not chunk:
                                    break
                                hasher.update(chunk)
                            digest = hasher.hexdigest()
                            if self._stamp(os.fstat(stream.fileno())) != self._stamp(before):
                                raise ProtocolError()
                        if digest != member["digest"] or self._stamp(path.lstat()) != self._stamp(before):
                            raise ProtocolError()
                observed_files: set[str] = set()
                observed_directories: set[str] = set()
                for parent, child_directories, child_files in os.walk(self._root, followlinks=False):
                    for child in (*child_directories, *child_files):
                        path = Path(parent) / child
                        relative = path.relative_to(self._root).as_posix()
                        if child in child_directories:
                            self._private(path, directory=True)
                            observed_directories.add(relative)
                        else:
                            self._private(path, directory=False)
                            observed_files.add(relative)
                    if len(observed_files) + len(observed_directories) > 65536:
                        raise ProtocolError()
                if (
                    observed_files != files or observed_directories != directories
                    or self._stamp(self._root.lstat()) != self._stamp(root_before)
                ):
                    raise ProtocolError()
                python_member = c.text(evidence["python_member"])
                selected_python, prefix = self._runtime_selection()
                if selected_python is not None and python_member != selected_python:
                    raise ProtocolError()
                required = evidence.get("required_members")
                _require_runtime_members(required, python_member, files, prefix=prefix)
                python_path = self._root.joinpath(*self._member_parts(python_member))
                if not python_path.stat().st_mode & stat.S_IXUSR:
                    raise ProtocolError()
                return ControllerInstallation(
                    context, evidence["platform"], str(python_path),
                    installation_digest, evidence["evidence_digest"],
                )
        except Exception:
            return None


class _ManagedInstallationVerifier(_OwnedInstallationVerifier):
    """Consume genuine I02 managed pointer and generated installed-file receipt.

    The exact packaged Q03 lock remains mandatory. Installed native Windows
    packages or a host-created qualification boolean never enable a controller.
    """

    def __init__(
        self, root: Path, root_resource: str, control_resource: str,
        ownership_token: str, manifest: object,
    ) -> None:
        from netops.dependencies._managed import ManagedGenerationManifest

        if (
            type(manifest) is not ManagedGenerationManifest or manifest.installation is None
        ):
            raise c.ContractError()
        manifest.__post_init__()
        self._controller_spec = manifest.installation.for_context("controller")
        self._controller_child = not manifest.installation.controller
        self._descriptor = manifest
        self._root_resource = c.text(root_resource)
        from .policy import contracts as lc

        generation = lc.GenerationBinding(
            manifest.generation_id, 0, manifest.content_digest, c.digest(manifest),
        )
        self._generation = generation
        resource = "dependency-installation-" + c.digest(generation)
        super().__init__(root, control_resource, resource, ownership_token)

    def _resources(self) -> tuple[str, ...]:
        return self._root_resource, self._active, self._install

    def _runtime_selection(self) -> tuple[str | None, str]:
        """Select the child interpreter without changing the parent receipt identity."""
        prefix = "controller/" if self._controller_child else ""
        return prefix + "bin/python", prefix

    @staticmethod
    def _member_parts(relative: str) -> tuple[str, ...]:
        from netops.dependencies._installation import _installed_parts

        return _installed_parts(relative)

    def _selection(
        self, context: c.ControllerContext, state: OwnedStatePort,
    ) -> tuple[tuple, str]:
        from .lifecycle_execution import _pointer
        from .policy import contracts as lc

        root = state.read(self._root_resource)
        active, installed = state.read(self._active), state.read(self._install)
        for record in (root, active, installed):
            record.__post_init__()
            if (
                record.kind != "checkpoint" or record.ownership_token != self._owner
                or record.policy_identity != context.context.policy_identity
            ):
                raise ProtocolError()
        root_data = root.payload
        root_manifest = c.public_object(root_data["root_manifest"])
        registered = root_manifest["registered_manifests"]
        generations = root_data["generations"]
        if type(registered) is not tuple or type(generations) is not tuple:
            raise ProtocolError()
        retained = tuple(c.public_object(item) for item in generations
                         if c.public_object(item).get("generation_id") == self._generation.generation_id)
        if (
            len(retained) != 1 or retained[0].get("state") != "staged"
            or retained[0].get("manifest") != c.public_object(c.wire(self._descriptor))
        ):
            raise ProtocolError()
        verification = c.public_object(active.payload["verification"])
        if (
            verification.get("generation_id") != self._generation.generation_id
            or verification.get("content_digest") != self._generation.content_digest
            or verification.get("manifest_digest") != self._generation.manifest_digest
            or verification.get("context_digest") != c.digest(self._descriptor.context)
            or verification.get("registry_digest") != context.context.registry_digest
            or verification.get("policy_digest") != context.context.policy_identity.bundle_sha256
        ):
            raise ProtocolError()
        qualifications = root_manifest.get("registered_qualifications")
        if type(qualifications) is not tuple:
            raise ProtocolError()
        qualified = tuple(c.public_object(item) for item in qualifications if (
            c.public_object(item).get("generation_binding") == c.public_object(c.wire(self._generation))
            and c.public_object(item).get("context") == c.public_object(c.wire(self._descriptor.context))
            and c.public_object(item).get("scope") == c.public_object(c.wire(self._descriptor.scope))
            and c.public_object(item).get("consuming_contexts") == self._descriptor.consuming_contexts
            and c.public_object(item).get("qualification_digest") == verification.get("qualification_digest")
        ))
        if len(qualified) != 1:
            raise ProtocolError()
        if (
            root_data.get("schema") != "i02-managed-generations-v1"
            or root_manifest["control_resource"] != self._active
            or c.public_object(c.wire(self._descriptor)) not in registered
            or active.payload.get("schema") != "i02-managed-control-v1"
            or active.payload.get("admission_enabled", True) is not True
            or self._descriptor.context.context != context.context
        ):
            raise ProtocolError()
        pointer = _pointer(active.payload["pointer"])
        if type(pointer) is not lc.PresentPointer:
            raise ProtocolError()
        data = installed.payload
        if (
            pointer.active_generation_id != self._generation.generation_id
            or pointer.pointer_digest != c.digest((self._generation, pointer.revision))
            or pointer.revision < 1 or data.get("schema") != "i02-installation-receipt-v1"
            or data["generation_binding"] != c.public_object(c.wire(self._generation))
            or data["context_digest"] != c.digest(self._descriptor.context)
            or data["registry_digest"] != context.context.registry_digest
            or data["consuming_contexts"] != self._descriptor.consuming_contexts
        ):
            raise ProtocolError()
        receipt = c.public_object(data["receipt"])
        from netops.dependencies._installation import _match_installed_receipt

        try:
            _match_installed_receipt(self._descriptor, retained[0].get("installation_receipt"), receipt)
        except c.ContractError:
            raise ProtocolError() from None
        if (
            receipt["schema"] != "i02-installed-generation-v1"
            or receipt["generation_id"] != self._generation.generation_id
            or receipt["descriptor_digest"] != c.digest(self._descriptor)
            or type(receipt["manifest"]) is not tuple
            or receipt["installation_digest"] != c.digest(receipt["manifest"])
            or receipt.get("python_member") != "bin/python"
            or self._root.name != "installation-" + c.digest(self._generation.generation_id)
        ):
            raise ProtocolError()
        python_member, _ = self._runtime_selection()
        selected = tuple(
            c.public_object(member) for member in receipt["manifest"]
            if c.public_object(member).get("path") == python_member
        )
        if (
            len(selected) != 1 or selected[0].get("kind") != "file"
            or selected[0].get("executable") is not True
        ):
            raise ProtocolError()
        if self._controller_child:
            child_receipts = tuple(
                c.public_object(member) for member in receipt["manifest"]
                if c.public_object(member).get("path") == "controller/netops-installation.json"
            )
            if len(child_receipts) != 1 or child_receipts[0].get("kind") != "file":
                raise ProtocolError()
        # Include the receipt's bytes in the independently checked file tree;
        # it is excluded from its own digest to avoid a recursive hash.
        extra = c.public_object({
            "path": "netops-installation.json", "kind": "file",
            "digest": hashlib.sha256(c.canonical_bytes(receipt)).hexdigest(),
        })
        return (*receipt["manifest"], extra), c.sha256(receipt["installation_digest"])
