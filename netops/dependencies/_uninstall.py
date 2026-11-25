"""Explicit inactive-generation uninstall; no TTL purge or directory adoption."""

from __future__ import annotations

import ctypes
import hashlib
import os
import stat
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from netops.ansible import artifact_platform as storage
from netops.ansible import contracts as c
from netops.ansible.artifact_cleanup import cleanup_errors, teardown
from netops.ansible.artifacts import ArtifactError, _root
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    bind_lifecycle,
    lifecycle_effects,
    lifecycle_plan_digest,
)
from netops.ansible.policy.lifecycle_evidence import lifecycle_arguments_digest

from ._installation import _check, _hash, _installed_parts, _tree
from ._lifecycle import InstallOutcome, InstallStepOutcome, _error, _observe
from ._managed import ProtectedGenerationFiles, _parts

if TYPE_CHECKING:
    from ._composition import ManagedLifecycleState
    from .service import DependencyService

__all__: tuple[str, ...] = ()


def _pins(host: ManagedLifecycleState, identifiers: tuple[str, ...]) -> tuple[lc.FrozenObject, ...]:
    if host.runs is None:
        raise AuthorizationError()
    pins = tuple(pin for pin in host.runs.pins() if pin["generation_id"] in identifiers)
    if tuple(pin["generation_id"] for pin in pins) != identifiers or any(
        pin["holders"] != () for pin in pins
    ):
        raise AuthorizationError()
    return pins


def plan_uninstall(
    host: ManagedLifecycleState, generation_id: str, context: c.InstallContext,
    service: DependencyService,
) -> lc.UninstallPlan:
    c.uuid_text(generation_id)
    with host._mutex, host._state.lock((host._facts_resource,), 0.0):
        root = host._facts()
        manifest = next((item for item in host.manifests if item.generation_id == generation_id), None)
        if manifest is None or manifest.context != context:
            raise AuthorizationError()
        pointer = host._pointer_locked()
        # Removing a selected active generation needs the original retained
        # pointer-restore contract, not an invented absent-pointer transition.
        if type(pointer) is lc.PresentPointer and pointer.active_generation_id == generation_id:
            raise AuthorizationError()
        if host._control().payload.get("prior_healthy_generation_id") == generation_id:
            raise AuthorizationError()
        generation = lc.GenerationBinding(generation_id, 0, manifest.content_digest, c.digest(manifest))
        generations = root.payload["generations"]
        if type(generations) is not tuple:
            raise AuthorizationError()
        if not any(c.public_object(item).get("generation_id") == generation_id
                   and c.public_object(item).get("state") == "staged" for item in generations):
            raise AuthorizationError()
        pins = _pins(host, (generation_id,))
        root_binding = lc.OwnedRootBinding(root.resource_id, c.digest(root.payload["root_manifest"]))
        steps = host._steps(manifest, root_binding, ("dependency-uninstall",))
        family_lock = host._family_locks.get(generation_id)
        if family_lock is not None:
            from ._family_integration import _MATERIALIZED
            from ._family_ledger import _OwnedFamilyLedger
            from ._family_provider import _descriptor, _operation

            platform: list[c.FrozenObject] = []
            materialized: list[c.FrozenObject] = []
            ledger = _OwnedFamilyLedger(
                host._state, root_binding, "family-ledger-" + c.digest(generation_id),
                host._owner, host._identity, family_lock, host, service.clock,
            )
            for index in reversed(range(len(family_lock.releases))):
                release = family_lock.releases[index]
                operation = _operation(family_lock, release, "remove", generation_id)
                _, resource, pending = ledger.read(root_binding, operation.resource_id)
                if pending is not None and pending != operation:
                    raise AuthorizationError()
                if resource is None:
                    # Durable explicit absence is not an invitation to repeat
                    # a prior removal or infer ownership from a host name.
                    continue
                if not resource.owned or resource.active or resource.pins or resource.healthy_previous:
                    raise AuthorizationError()
                descriptor = _descriptor(
                    family_lock, release, operation,
                    root_binding, f"family-remove-{index}",
                    generation_manifest_digest=c.digest(manifest),
                )
                (materialized if release.requirement.family in (*_MATERIALIZED, "runtime")
                 else platform).append(
                    descriptor,
                )
            steps = (*platform, *steps, *materialized)
        effects = tuple(lc.LifecycleEffectOccurrence(
            c.text(step["occurrence_id"]), index, c.text(step["occurrence_id"]),
            c.text(c.public_object(step["destination"])["resource_id"]),
            "dependency-uninstall", lifecycle_arguments_digest(step),
        ) for index, step in enumerate(steps))
        from ._composition import _consequential

        identifier = str(uuid4())
        plan = lc.UninstallPlan(
            "1.0", identifier, identifier, "0" * 64, c.digest(context), root_binding,
            replace(generation, selected=(generation,)), pointer, service._policy_identity,
            service.registry.digest, c.digest(("owned-inactive-uninstall", generation)), effects,
            _consequential(steps),
            c.public_object({"schema": "1.0", "steps": steps, "verification": None, "pins": pins,
                             "cancel_scope": tuple(effect.occurrence_id for effect in effects)}), "uninstall",
        )
        plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
        bind_lifecycle(plan)
        return plan


def _remove(
    files: ProtectedGenerationFiles, directory: str, member: c.FrozenObject,
    clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
) -> None:
    """Delete a verified exact handle under pinned parents, including inherited install ACLs."""
    path = c.text(member["path"])
    # A verified wheel legitimately creates data such as "Lorem ipsum.txt".
    # Installed receipt grammar preserves all alias/stream/traversal guards;
    # archive acquisition still uses its separate stricter member grammar.
    parts = _installed_parts(path)
    with _root(files._root) as parent:
        handles = []
        try:
            if os.name == "nt":
                from ._installation_files import _private_windows

                native = storage.windows()
                current = Path(files._root.path)
                for component in (directory, *parts[:-1]):
                    current /= component
                    handle = native._open(current, True, prove=False)
                    handles.append(handle)
                    _private_windows(current, directory=True)
                target = current / parts[-1]
                is_directory = member["kind"] == "directory"
                handle = native.kernel.CreateFileW(
                    str(target), 0x80000000 | 0x10000 | 0x20000 | 0x80, 1, None, 3,
                    0x02000000 | 0x00200000, None,
                )
                if handle in (None, ctypes.c_void_p(-1).value):
                    raise native._error()
                try:
                    _private_windows(target, directory=is_directory)
                    if not is_directory:
                        info = storage._FileInfo()
                        if not native.kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
                            raise native._error()
                        size = info.size_high << 32 | info.size_low
                        if info.links != 1 or size != member["size"]:
                            raise c.ContractError()
                        result = hashlib.sha256()
                        buffer, count = ctypes.create_string_buffer(65536), ctypes.c_uint32()
                        while True:
                            _check(clock, cancel, deadline)
                            if not native.kernel.ReadFile(handle, buffer, 65536, ctypes.byref(count), None):
                                raise native._error()
                            if count.value == 0:
                                break
                            result.update(buffer.raw[:count.value])
                        if result.hexdigest() != member["digest"]:
                            raise c.ContractError()
                    if is_directory and os.listdir(target):
                        raise c.ContractError()
                    disposition = ctypes.c_ubyte(1)
                    if not native.kernel.SetFileInformationByHandle(
                        handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition),
                    ):
                        raise native._error()
                finally:
                    with teardown():
                        native.close(int(handle))
            else:
                with files._parents(parent, (directory, *parts[:-1]), False) as held:
                    target = Path(files._root.path) / directory / c.text(member["path"])
                    if member["kind"] != "directory" and _hash(target, clock, cancel, deadline) != member["digest"]:
                        raise c.ContractError()
                    storage.remove(held, parts[-1], directory=member["kind"] == "directory")
        finally:
            for handle in reversed(handles):
                with teardown():
                    storage.close(handle)


class ManagedUninstall:
    """One-use admitted removal of exact owned inactive resources, with remaining-reference truth."""

    def __init__(
        self, host: ManagedLifecycleState, service: DependencyService, plan: lc.UninstallPlan,
        consent: lc.InstallConsent, cancel: c.CancelPort,
    ) -> None:
        self.host, self.service, self.plan, self.consent, self.cancel = host, service, plan, consent, cancel
        self.binding = bind_lifecycle(plan)
        if type(service.authorization) is not AuthorizationBroker:
            raise AuthorizationError()
        self.broker: AuthorizationBroker = service.authorization
        self.scope = self.broker._life_scope(consent)

    def execute(self) -> InstallOutcome:
        host, binding, broker = self.host, self.binding, self.broker
        effect = binding.effects[0]
        started = c.finite(self.service.clock.monotonic())
        errors: list[c.SafeError] = []
        cleanup: list[c.SafeError] = []
        remaining: list[str] = []
        removed: list[str] = []
        results: list[InstallStepOutcome] = []
        completed = False
        try:
            if self.scope is None or self.scope.binding != binding or broker._lifecycle_state is not host:
                raise AuthorizationError()
            _check(self.service.clock, self.cancel, self.scope.deadline)
            family_lock = host._family_locks.get(binding.generation.generation_id)
            scope_review = None
            if family_lock is not None and any(item.scopes for item in family_lock.releases):
                if host._family_reviews is None:
                    raise AuthorizationError()
                scope_review = host._family_reviews.review(
                    family_lock, binding, self.service.clock, self.cancel, self.scope.deadline,
                )
            now = c.finite(self.service.clock.monotonic())
            milliseconds = max(0, int((self.scope.deadline - now) * 1000))
            event = lc.DecisionEvent(
                str(uuid4()), lc.EventKind.INSTALL_CONSENTED, 0, binding.plan_digest,
                binding.context_digest, binding.policy.bundle_sha256, binding.root.resource_id,
                effect.step_id, c.public_object({
                    "lifecycle_kind": "uninstall", "plan_id": binding.plan_id,
                    "lifecycle_binding_digest": c.digest(binding),
                    "private_consent_reference": "host-private-lifecycle",
                }), install_id=binding.lifecycle_id,
            )
            from ._composition import _category_facts

            facts = lc.DecisionFacts(c.public_object({
                "binding": {"input_valid": True, "plan_current": True, "policy_current": True},
                "request": {"area": "setup", "operation": "uninstall", "mode": "apply"},
                "control": {"cancelled": False, "remaining_ms": milliseconds},
                "consent": {"present": True, "binding_matches": True, "effects_match": True,
                            "recovery_matches": True, "remaining_ms": milliseconds},
                "consequential": _category_facts(broker, binding, self.consent, now),
                "ownership": {"valid": True},
                "candidate": {"verified": True, "retained_owned": True, "pointer_matches": True},
                "lifecycle": {"next_effect_kind": "dependency-uninstall"},
            }), lc.Phase.PLANNED, 0)
            policy_state = lc.PolicyState(
                binding.policy, binding.lifecycle_id, 0, lc.Phase.PLANNED, binding.plan_digest,
                binding.context_digest, binding.policy.bundle_sha256,
                tuple(lc.StepDisposition(
                    binding.root.resource_id, selected.step_id,
                    invocation_id=str(uuid4()), effect_id=selected.occurrence_id,
                ) for selected in binding.effects),
                namespace="install",
            )
            transition = self.service.policy.reduce(policy_state, event, facts)
            from ._composition import _ManagedRun

            _ManagedRun.requested(transition.decision, effect.kind)
            # Match the original install owner's reviewed-closure grant.
            # Every dispatch below still requires its own real reducer intent.
            aggregate = replace(transition.decision, effects=lifecycle_effects(binding))
            grant = broker.issue_lifecycle(self.plan, self.consent, aggregate, now)
            session = broker.consume_lifecycle(grant, binding, now)
            checkpoint = host._checkpoint(binding, transition.next_state, event, None)
            for index, effect in enumerate(binding.effects):
                _ManagedRun.requested(transition.decision, effect.kind)
                current = host.snapshot_lifecycle(binding)
                if self.scope is None:
                    raise AuthorizationError()
                manifest = host._manifest(binding)
                if manifest.bootstrap_digest is not None:
                    host.guard_source(
                        manifest, self.service.clock, self.cancel, self.scope.deadline,
                    )
                occurrence = lc.LifecycleEffectBinding(
                    binding, str(uuid4()), current.revision, effect.occurrence_id,
                )
                permit = broker.permit_lifecycle(
                    session, occurrence, c.finite(self.service.clock.monotonic()),
                )
                family = effect.occurrence_id.startswith("family-")
                if family:
                    host._dispatch_family(
                        host._manifest(binding), binding, broker, permit, occurrence,
                        self.service.clock, self.cancel, scope_review=scope_review,
                    )
                else:
                    broker.enter_lifecycle(permit, occurrence, c.finite(self.service.clock.monotonic()))
                with broker._lock, host.lock_lifecycle(binding):
                    if host.pointer() != binding.expected_pointer or _pins(
                        host, (binding.generation.generation_id,),
                    ) != binding.content["pins"]:
                        raise AuthorizationError()
                    before = len(removed)
                    if not family:
                        self._remove_selected(removed, remaining)
                    # Completion requires the actual postcondition, not an
                    # empty projected work list or merely an entered permit.
                    _check(self.service.clock, self.cancel, self.scope.deadline)
                    if remaining or host.pointer() != binding.expected_pointer or _pins(
                        host, (binding.generation.generation_id,),
                    ) != binding.content["pins"]:
                        raise AuthorizationError()
                    snapshot = host.snapshot_lifecycle(binding)
                    broker.complete_lifecycle(
                        permit, str(uuid4()), snapshot.revision, c.finite(self.service.clock.monotonic()),
                    )
                    following = lc.DecisionEvent(
                        str(uuid4()), lc.EventKind.STEP_COMPLETED, transition.next_state.revision,
                        binding.plan_digest, binding.context_digest, binding.policy.bundle_sha256,
                        binding.root.resource_id, effect.step_id, c.public_object({
                            "invocation_id": transition.next_state.dispositions[index].invocation_id,
                            "effect_id": effect.occurrence_id, "target_id": binding.root.resource_id,
                            "step_id": effect.step_id, "safe_result_digest": c.digest(tuple(removed)),
                            "primary": "success", "cleanup": "success", "remote_uncertain": False,
                        }), install_id=binding.lifecycle_id,
                    )
                    actual = self.service.policy.reduce(transition.next_state, following, replace(
                        facts, values=c.public_object({
                            **dict(facts.values), "lifecycle": {
                                "next_effect_kind": binding.effects[index + 1].kind
                                if index + 1 < len(binding.effects) else "none",
                            },
                            "result": {
                                "selected": len(binding.effects), "completed": index + 1, "unsuccessful": 0,
                                "failed": 0, "cancelled": 0, "unsupported": 0, "blocked": 0,
                                "policy_failed": False, "cleanup_failed": False, "remote_uncertain": False,
                            },
                            "change": {"poststate_verified": True},
                        }), state_phase=transition.next_state.phase,
                        state_revision=transition.next_state.revision,
                    ))
                    if actual.decision.decision != "allow":
                        raise AuthorizationError()
                    checkpoint = host._checkpoint(binding, actual.next_state, following, checkpoint)
                    transition = actual
                    results.append(InstallStepOutcome(
                        effect.occurrence_id, effect.step_id, effect.kind,
                        c.OutcomeStatus.SUCCEEDED, len(removed) != before or family,
                    ))
            completed = len(results) == len(binding.effects)
        except (Exception, KeyboardInterrupt) as exc:
            try:
                broker.revoke_lifecycle("uninstall", binding.plan_id)
            except Exception:
                cleanup.append(_error(
                    c.ReasonCode.CLEANUP_FAILED, c.ErrorCategory.CLEANUP, c.Stage.FINALIZE,
                    "Preserve the primary error; lifecycle revocation also failed.",
                ))
            reason = c.ReasonCode.CANCELLED if isinstance(exc, (InterruptedError, KeyboardInterrupt)) else (
                c.ReasonCode.CONSENT_STALE if isinstance(exc, AuthorizationError) else c.ReasonCode.PROVISION_FAILED
            )
            errors.append(exc.error if isinstance(exc, ArtifactError) else _error(
                reason, c.ErrorCategory.CLEANUP, c.Stage.FINALIZE,
                "Preserve remaining references and review a fresh exact inactive-generation uninstall.",
            ))
            cleanup.extend(item for item in cleanup_errors(exc) if isinstance(item, c.SafeError))
            if len(results) < len(binding.effects):
                results.append(InstallStepOutcome(
                    effect.occurrence_id, effect.step_id, effect.kind,
                    c.OutcomeStatus.BLOCKED, False,
                ))
        try:
            with host.lock_lifecycle(binding):
                root = host._facts()
                resource = "dependency-uninstall-result-" + binding.plan_id
                host._write(resource, 0, replace(
                    root, resource_id=resource, revision=0, payload=c.public_object({
                        "schema": "i02-owned-uninstall-v1", "manifest_digest": binding.generation.manifest_digest,
                        "removed": tuple(removed), "remaining": tuple(remaining), "completed": completed,
                        "primary_errors": tuple(c.wire(error) for error in errors),
                    }),
                ))
        except Exception:
            cleanup.append(_error(
                c.ReasonCode.CLEANUP_FAILED, c.ErrorCategory.CLEANUP, c.Stage.FINALIZE,
                "Preserve remaining references; durable uninstall receipt persistence failed.",
            ))
        pointer = binding.expected_pointer
        try:
            pointer = host.pointer()
        except Exception:
            cleanup.append(_error(
                c.ReasonCode.CLEANUP_FAILED, c.ErrorCategory.CLEANUP, c.Stage.FINALIZE,
                "Active pointer postcheck is uncertain; preserve the reviewed pointer reference.",
            ))
        status = c.OutcomeStatus.SUCCEEDED if completed and not errors and not cleanup else (
            c.OutcomeStatus.PARTIAL if removed else c.OutcomeStatus.BLOCKED
        )
        try:
            elapsed = max(0.0, c.finite(self.service.clock.monotonic()) - started)
        except Exception:
            elapsed = 0.0
        _observe(binding, effect, status, elapsed,
                 errors[0] if errors else None, self.service.events)
        return InstallOutcome(
            binding.lifecycle_id, binding.plan_id, "uninstall", status,
            tuple(results),
            c.ReadinessProjection(), binding.generation.generation_id,
            pointer.active_generation_id if type(pointer) is lc.PresentPointer else None, None,
            tuple(errors), tuple(cleanup), tuple(remaining), bool(cleanup or errors and removed), pointer.revision,
        )

    def _remove_selected(self, removed: list[str], remaining: list[str]) -> None:
        host = self.host
        if type(host.files) is not ProtectedGenerationFiles or self.scope is None:
            raise AuthorizationError()
        files = host.files
        manifest = host._manifest(self.binding)
        generations = host._facts().payload["generations"]
        if type(generations) is not tuple:
            raise AuthorizationError()
        records = tuple(c.public_object(item) for item in generations
                        if c.public_object(item)["generation_id"] == manifest.generation_id)
        if len(records) != 1:
            raise AuthorizationError()
        platform_directory = "platform-" + c.digest(manifest.generation_id)
        platform_identity = None
        with _root(files._root) as parent:
            if platform_directory in storage.names(parent):
                from ._platform_host import _platform_binding

                retained = host._read("platform-root-" + c.digest(manifest.generation_id))
                platform_identity = _platform_binding(manifest, retained.payload)
                child = storage.open_directory(parent, platform_directory)
                try:
                    info = storage.info(child)
                    if (
                        platform_identity != (str(info.st_dev), str(info.st_ino))
                        or storage.names(child)
                    ):
                        remaining.append(platform_directory)
                        raise AuthorizationError()
                finally:
                    storage.close(child)
        trees: list[tuple[str, tuple[c.FrozenObject, ...]]] = []
        archive_members: dict[str, c.FrozenObject] = {}
        for item in manifest.members:
            parts = _parts(item.path)
            archive_members[item.path] = c.public_object({
                "path": item.path, "kind": "file", "digest": item.digest,
                "size": item.size, "executable": item.executable,
            })
            for index in range(1, len(parts)):
                path = "/".join(parts[:index])
                archive_members[path] = c.public_object({"path": path, "kind": "directory",
                                                         "digest": None, "size": 0, "executable": True})
        archive_members["netops-generation.json"] = c.public_object({
            "path": "netops-generation.json", "kind": "file",
            "digest": hashlib.sha256(c.canonical_bytes(manifest)).hexdigest(),
            "size": len(c.canonical_bytes(manifest)), "executable": False,
        })
        trees.append((files._directory(manifest), tuple(archive_members.values())))
        if manifest.installation is not None:
            from ._installation import _OfflineInstallation

            receipt = c.public_object(records[0]["installation_receipt"])
            expected = receipt["manifest"]
            if type(expected) is not tuple or receipt["descriptor_digest"] != c.digest(manifest):
                raise AuthorizationError()
            record_bytes = c.canonical_bytes(receipt)
            expected_members = tuple(c.public_object(item) for item in expected)
            expected_members += (c.public_object({
                "path": "netops-installation.json", "kind": "file",
                "digest": hashlib.sha256(record_bytes).hexdigest(), "size": len(record_bytes),
                "executable": False,
            }),)
            trees.append((_OfflineInstallation(files._root).path(manifest).name, expected_members))
        # Validate ALL selected trees before the first deletion. Extra members,
        # changed digests, aliases and permissions are not swept or adopted.
        for directory, expected in trees:
            remaining.extend(directory + "/" + c.text(item["path"]) for item in expected)
            remaining.append(directory)
        missing: set[str] = set()
        for directory, expected in trees:
            target = Path(files._root.path) / directory
            try:
                info = target.lstat()
            except FileNotFoundError:
                missing.add(directory)
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise AuthorizationError()
            if os.name == "nt":
                from ._installation_files import _private_windows

                _private_windows(target, directory=True)
            actual = _tree(target, self.service.clock, self.cancel, self.scope.deadline)
            if any(not any(
                all(member[key] == known[key] for key in member
                    if key != "executable" or os.name != "nt") for known in expected
            ) for member in actual):
                raise AuthorizationError()
            # _tree excludes the installation receipt; validate it explicitly.
            receipt_path = target / "netops-installation.json"
            if receipt_path.exists():
                known = next(item for item in expected if item["path"] == receipt_path.name)
                if _hash(receipt_path, self.service.clock, self.cancel, self.scope.deadline) != known["digest"]:
                    raise AuthorizationError()
        if platform_identity is not None:
            with _root(files._root) as parent:
                child = storage.open_directory(parent, platform_directory)
                try:
                    info = storage.info(child)
                    if platform_identity != (str(info.st_dev), str(info.st_ino)) or storage.names(child):
                        remaining.append(platform_directory)
                        raise AuthorizationError()
                finally:
                    storage.close(child)
                # All selected trees were validated before this first deletion.
                # Only this exact known EMPTY root is retired; stores and live
                # disks are never swept.
                storage.remove(parent, platform_directory, directory=True)
                removed.append(platform_directory)
        for directory, expected in trees:
            if directory in missing:
                if (Path(files._root.path) / directory).exists():
                    raise AuthorizationError()
                remaining[:] = [reference for reference in remaining
                                if reference != directory and not reference.startswith(directory + "/")]
                continue
            ordered = sorted(expected, key=lambda item: (
                c.text(item["path"]).count("/"), item["kind"] != "directory",
            ), reverse=True)
            for member in ordered:
                _check(self.service.clock, self.cancel, self.scope.deadline)
                reference = directory + "/" + c.text(member["path"])
                try:
                    _remove(files, directory, member, self.service.clock, self.cancel, self.scope.deadline)
                except FileNotFoundError:
                    pass
                else:
                    removed.append(reference)
                remaining.remove(reference)
            with _root(files._root) as parent:
                try:
                    storage.remove(parent, directory, directory=True)
                except FileNotFoundError:
                    pass
                else:
                    removed.append(directory)
            remaining.remove(directory)
        # Recheck every selected root after deletion while the original broker
        # and root locks are held. Missing files alone do not prove an empty
        # tree; a remaining directory or injected resource prevents completion.
        for directory, _ in trees:
            _check(self.service.clock, self.cancel, self.scope.deadline)
            try:
                (Path(files._root.path) / directory).lstat()
            except FileNotFoundError:
                continue
            remaining.append(directory)
            raise AuthorizationError()
