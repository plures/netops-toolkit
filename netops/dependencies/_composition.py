"""Public dependency-plan composition over actual managed trees and A01 admission.

Registered metadata is supplied by the trusted local host and pinned in an
already owned root. It is not downloaded metadata, consent, or qualification.
Registered archive contributions compose one exact complete selected tree.
Absent locks and unqualified consuming tiers remain blocked, never truncated.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from netops.ansible import contracts as c
from netops.ansible.artifact_cleanup import _storage_detail, cleanup_errors, teardown
from netops.ansible.artifacts import ArtifactError, OwnedRecord, OwnedState, OwnedStatePort
from netops.ansible.lifecycle_execution import _pointer
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    LifecycleSnapshot,
    bind_lifecycle,
    lifecycle_effects,
    lifecycle_plan_digest,
)
from netops.ansible.policy.lifecycle_evidence import LifecycleEvidence, lifecycle_arguments_digest
from netops.ansible.settings import ObservationSettings

from ._assets import (
    AssetTransport,
    LockedAsset,
    VerifiedAssetAcquisition,
    _approved,
    _MonotonicClock,
)
from ._lifecycle import InstallOutcome, InstallStepOutcome, _error, _observe
from ._managed import (
    GenerationFilesPort,
    ManagedGenerationHandler,
    ManagedGenerationManifest,
    ProtectedGenerationFiles,
)
from ._owned_source import _OwnedBuildAsset, _OwnedSource
from ._recovery import OutcomeStore, RecoverySelection, RecoveryStore
from ._restore import GenerationRunsPort, ManagedQualification, ManagedRestore
from ._uninstall import ManagedUninstall, plan_uninstall

if TYPE_CHECKING:
    from ._bootstrap import _BootstrapContribution
    from ._family_consent import _ScopeReceipt, _ScopeReviews
    from ._family_lock import _FamilyLock
    from ._family_provider import _Resource
    from .service import DependencyEntry, DependencyRegistry, DependencyService, InstallPlan

__all__: tuple[str, ...] = ()
_SCHEMA = "i02-managed-generations-v1"
_CONTROL = "i02-managed-control-v1"
_NATIVE_LOG = logging.getLogger(__name__)
_CAS_PHASES = (
    "cas-source-before", "cas-owned-tree", "cas-installed-receipt", "cas-source-after",
)


def _consequential(steps: tuple[c.FrozenObject, ...]) -> tuple[lc.ConsequentialRequirement, ...]:
    grouped: dict[lc.ConsequentialCategory, list[str]] = {}
    for step in steps:
        categories = step["consequential"]
        if type(categories) is not tuple:
            raise c.ContractError()
        for value in categories:
            if value not in (
                "elevation", "wsl-change", "vm-change", "runtime-install", "reboot", "security-change",
            ):
                raise c.ContractError()
            grouped.setdefault(cast(lc.ConsequentialCategory, value), []).append(
                c.text(step["occurrence_id"]),
            )
    return tuple(lc.ConsequentialRequirement(category, tuple(ids))
                 for category, ids in grouped.items())


@contextmanager
def _native_phase(
    stage: str, clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
) -> Iterator[None]:
    """Observe four coarse CAS boundaries without affecting the primary outcome."""
    started = None
    try:
        started = c.finite(time.monotonic())
    except BaseException:
        pass
    status = "returned"
    try:
        yield
    except BaseException as exc:
        status = (
            "cancelled" if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "deadline" if isinstance(exc, TimeoutError) else "raised"
        )
        raise
    finally:
        fields: dict[str, object] = {
            "stage": stage if stage in _CAS_PHASES else "unknown", "status": status,
        }
        try:
            if started is not None:
                finished = c.finite(time.monotonic())
                if finished >= started:
                    fields["duration"] = finished - started
        except BaseException:
            pass
        try:
            now = c.finite(clock.monotonic())
            fields.update(
                remaining_seconds=max(0.0, deadline - now), deadline_elapsed=now >= deadline,
            )
        except BaseException:
            pass
        try:
            fields["cancelled"] = cancel.is_cancelled()
        except BaseException:
            pass
        try:
            _NATIVE_LOG.debug("dependency.native.boundary", extra=fields)
        except BaseException:
            pass


def _category_facts(
    broker: AuthorizationBroker, binding: lc.LifecycleBinding,
    consent: lc.InstallConsent, now: float,
) -> c.FrozenObject:
    """Project only the broker's live separately reviewed category receipts."""
    required = bool(binding.required_consequential)
    granted = False
    scope = broker._life_scope(consent)
    if required and scope is not None and scope.binding == binding:
        adapter = broker._lifecycle_consent
        if adapter is None:
            raise AuthorizationError()
        adapter.validate(scope, now)
        granted = True
    return c.public_object({"required": required, "granted": granted})


class ManagedLifecycleState:
    """Concrete managed host state, distinct from A02's inert byte schema.

    Both records must already be protected and owned. The immutable root
    manifest pins all supplied descriptors, while the separate control record
    holds actual pointer/probe observations. No constructor creates or adopts a
    directory, downloads an asset, or manufactures a verification receipt.
    """

    def __init__(
        self, state: OwnedStatePort, root_resource: str, control_resource: str,
        owner: str, identity: lc.PolicyIdentity,
        manifests: tuple[ManagedGenerationManifest, ...],
        files: GenerationFilesPort, transport: AssetTransport,
        qualifications: tuple[ManagedQualification, ...] = (),
        runs: GenerationRunsPort | None = None,
        *, owned_source: _OwnedSource | None = None,
        observation: ObservationSettings | None = None,
        family_locks: tuple[tuple[str, _FamilyLock], ...] = (),
        family_reviews: _ScopeReviews | None = None,
        bootstrap: _BootstrapContribution | None = None,
        bootstrap_registry: DependencyRegistry | None = None,
    ) -> None:
        self._state, self._facts_resource = state, c.text(root_resource)
        self._control_resource = c.text(control_resource)
        self._owner, self._identity = c.sha256(owner), identity
        self.manifests, self.files, self.transport = manifests, files, transport
        self.qualifications, self.runs = qualifications, runs
        if owned_source is not None and type(owned_source) is not _OwnedSource:
            raise c.ContractError()
        self._owned_source = owned_source
        from ._bootstrap import _BootstrapContribution
        from .service import DependencyRegistry

        if bootstrap is not None:
            if (
                type(bootstrap) is not _BootstrapContribution
                or type(bootstrap_registry) is not DependencyRegistry
                or owned_source is not None
                or type(files) is not ProtectedGenerationFiles
                or bootstrap.root != files._root
            ):
                raise c.ContractError()
            bootstrap.__post_init__()
        elif bootstrap_registry is not None:
            raise c.ContractError()
        self._bootstrap, self._bootstrap_registry = bootstrap, bootstrap_registry
        from ._family_integration import _supported
        from ._family_lock import _FamilyLock

        if type(family_locks) is not tuple or len(family_locks) > 256:
            raise c.ContractError()
        self._family_locks = dict(family_locks)
        from ._family_consent import _ScopeReviews

        if family_reviews is not None and type(family_reviews) is not _ScopeReviews:
            raise c.ContractError()
        self._family_reviews = family_reviews
        if len(self._family_locks) != len(family_locks):
            raise c.ContractError()
        for generation_id, lock in family_locks:
            c.text(generation_id)
            if (
                type(lock) is not _FamilyLock or not _supported(lock)
                or not any(item.generation_id == generation_id for item in manifests)
                or owned_source is not None
            ):
                raise c.ContractError()
            lock.__post_init__()
        if observation is not None and type(observation) is not ObservationSettings:
            raise c.ContractError()
        if observation is not None:
            observation.__post_init__()
        self._observation = observation
        self._mutex = threading.RLock()
        self._execution = threading.Lock()
        self._run: _ManagedRun | ManagedRestore | ManagedUninstall | None = None
        self._local = threading.local()
        self._cancelled: set[tuple[str, str]] = set()
        # Ephemeral actual functional observations, never consent or durable
        # readiness reconstruction. One current proof per registered generation.
        self._live_probes: dict[
            str, tuple[c.FrozenObject, c.ReadinessReport, c.FrozenObject | None]
        ] = {}
        for manifest in manifests:
            manifest.__post_init__()
            if manifest.bootstrap_digest is not None and (
                bootstrap is None or manifest.bootstrap_digest != bootstrap.digest
            ):
                raise AuthorizationError()
        c.unique(tuple(manifest.generation_id for manifest in manifests))
        for item in qualifications:
            if type(item) is not ManagedQualification:
                raise c.ContractError()
            item.__post_init__()
        c.unique(tuple(item.generation.generation_id for item in qualifications))
        # A host-supplied descriptor is usable only if the owned immutable root
        # already pins it. Missing/corrupt records are never treated as virgin.
        self._facts()
        self._control()

    def guard_source(
        self, manifest: ManagedGenerationManifest, clock: c.ClockPort,
        cancel: c.CancelPort, deadline: float,
    ) -> None:
        """Validate local producer authority separately from registered HTTPS locks."""
        if manifest.bootstrap_digest is not None:
            from pathlib import Path

            if (
                self._bootstrap is None or self._bootstrap_registry is None
                or manifest.bootstrap_digest != self._bootstrap.digest
            ):
                raise AuthorizationError()
            if self._bootstrap.family is not None:
                from dataclasses import replace

                if self._bootstrap.family.manifest != replace(manifest, bootstrap_digest=None):
                    raise AuthorizationError()
            self._bootstrap.guard(
                Path(self._bootstrap.root.path), self._bootstrap_registry,
                clock, cancel, deadline,
            )
        if type(manifest.asset) is not _OwnedBuildAsset:
            return
        source = self._owned_source
        if type(source) is not _OwnedSource or type(self.files) is not ProtectedGenerationFiles:
            raise AuthorizationError()
        source.guard(manifest, clock, cancel, deadline)
        root = self.files._root
        if source._issued._result.receipt["consuming_root"] != (
            root.path, str(root.device), str(root.inode),
        ):
            raise AuthorizationError()

    def _approve_sources(
        self, manifest: ManagedGenerationManifest, entries: tuple[DependencyEntry, ...],
    ) -> bool:
        """Keep interpreter reuse distinct from toolkit bundle provenance."""
        family = self._family_locks.get(manifest.generation_id)
        if family is not None:
            from ._family_integration import _validate_entries
            from ._family_source import _requires_contributions

            if _requires_contributions(manifest.scope) and (
                self._bootstrap is None or self._bootstrap.family is None
                or manifest.bootstrap_digest != self._bootstrap.digest
            ):
                return False
            _validate_entries(family, manifest, entries)
            return True
        if type(manifest.asset) is _OwnedBuildAsset:
            source = self._owned_source
            # This private increment supports one truthful existing-native
            # interpreter scope only. It never qualifies Ansible/WSL/full
            # selected handlers by relabeling this bundle as native-python.
            return (
                type(source) is _OwnedSource and source.asset == manifest.asset
                and tuple(entry.id for entry in entries) == ("native-python",)
                and manifest.installation is not None and not manifest.installation.controller
                and manifest.scope == c.InstallScope(
                    native_capabilities=("native.stdlib",), companions=(), full_toolkit=False,
                    enhanced=False,
                )
            )
        if tuple(entry.id for entry in entries) != tuple(asset.dependency for asset in manifest.assets):
            return False
        for entry, asset in zip(entries, manifest.assets):
            if type(asset) is not LockedAsset:
                raise AuthorizationError()
            _approved(entry, asset)
        return True

    def _read(self, resource: str) -> OwnedRecord:
        record = self._state.read(resource)
        if type(record) is not OwnedRecord:
            raise c.ContractError()
        if type(self._state) is not OwnedState:
            record.__post_init__()
        if (
            record.resource_id != resource or record.kind != "checkpoint"
            or record.ownership_token != self._owner or record.policy_identity != self._identity
        ):
            raise AuthorizationError()
        return record

    def _write(self, resource: str, expected: int, record: OwnedRecord) -> OwnedRecord:
        return self._state.compare_replace(resource, expected, record)

    def _write_immutable(self, record: OwnedRecord) -> OwnedRecord:
        """Create once; retain only an exactly equal revision-zero receipt on retry."""
        if record.revision != 0:
            raise AuthorizationError()
        try:
            return self._write(record.resource_id, 0, record)
        except ArtifactError as exc:
            # Never reinterpret missing/corrupt/unowned bytes or failed cleanup
            # as a virgin resource. Only an explicit CAS conflict permits read.
            if exc.error.reason != c.ReasonCode.CONSENT_STALE or exc.cleanup_errors:
                raise
            current = self._read(record.resource_id)
            if current != record:
                raise AuthorizationError() from None
            return current

    def _installed_receipt(
        self, manifest: ManagedGenerationManifest, actual: object,
    ) -> c.FrozenObject:
        from ._installation import _match_installed_receipt

        generations = self._generations(self._facts())
        retained = tuple(item for item in generations
                         if item.get("generation_id") == manifest.generation_id)
        if (
            len(retained) != 1 or retained[0].get("state") != "staged"
            or retained[0].get("manifest") != c.public_object(c.wire(manifest))
        ):
            raise AuthorizationError()
        return _match_installed_receipt(manifest, retained[0].get("installation_receipt"), actual)

    @staticmethod
    def _generations(root: OwnedRecord) -> tuple[c.FrozenObject, ...]:
        """Reuse immutable decoding only after re-reading the protected owned root bytes."""
        values = root.payload["generations"]
        if type(values) is not tuple:
            raise c.ContractError()
        result = []
        for value in values:
            if type(value) is not c.FrozenObject or not isinstance(value, c.FrozenObject):
                raise c.ContractError()
            # _read already validated OwnedRecord's complete credential-free
            # payload. Rebuilding each installed inventory at every snapshot
            # is not another file/provenance check, and consumes freshness.
            result.append(value)
        return tuple(result)

    def _facts(self) -> OwnedRecord:
        record = self._read(self._facts_resource)
        data = record.payload
        expected_manifest: dict[str, object] = {
            "control_resource": self._control_resource,
            "registered_manifests": tuple(c.wire(item) for item in self.manifests),
        }
        if self._observation is not None:
            expected_manifest["observation_max_age_seconds"] = self._observation.max_age_seconds
        if self._family_locks:
            expected_manifest["family_locks"] = tuple(
                (generation_id, c.wire(lock)) for generation_id, lock in self._family_locks.items()
            )
        if self.qualifications:
            expected_manifest["registered_qualifications"] = tuple(c.wire(item) for item in self.qualifications)
        if (
            set(data) != {"schema", "root_manifest", "generations"}
            or data["schema"] != _SCHEMA or type(data["generations"]) is not tuple
            or data["root_manifest"] != c.public_object(expected_manifest)
        ):
            raise AuthorizationError()
        return record

    def _control(self) -> OwnedRecord:
        record = self._read(self._control_resource)
        data = record.payload
        if set(data) - {"admission_enabled", "prior_healthy_generation_id"} != {
            "schema", "pointer", "verification", "setup_enabled", "installation_id",
        }:
            raise c.ContractError()
        if "admission_enabled" in data and type(data["admission_enabled"]) is not bool:
            raise c.ContractError()
        if data["schema"] != _CONTROL or type(data["setup_enabled"]) is not bool:
            raise c.ContractError()
        _pointer(data["pointer"])
        if data.get("prior_healthy_generation_id") is not None:
            c.uuid_text(data["prior_healthy_generation_id"])
        if data["installation_id"] is not None:
            c.uuid_text(data["installation_id"])
        if data["verification"] is not None:
            c.public_object(data["verification"])
        return record

    @contextmanager
    def lock_lifecycle(self, binding: lc.LifecycleBinding) -> Iterator[object]:
        """Nest in this thread only; acquire the actual root OS lock exactly once."""
        with self._mutex:
            depth = getattr(self._local, "depth", 0)
            self._local.depth = depth + 1
            try:
                if depth:
                    yield None
                else:
                    with self._state.lock((self._facts_resource,), 0.0) as held:
                        yield held
            finally:
                self._local.depth = depth

    def pointer(self) -> lc.PointerExpectation:
        """Return factual current selection without running the active interpreter."""
        with self._mutex:
            if getattr(self._local, "depth", 0):
                return self._pointer_locked()
            with self._state.lock((self._facts_resource,), 0.0):
                return self._pointer_locked()

    def _pointer_locked(self) -> lc.PointerExpectation:
        return _pointer(self._control().payload["pointer"])

    def _family_resource_facts(self, resource: _Resource) -> _Resource:
        """Overlay live pointer and run-pin facts, never cached serialized flags."""
        control = self._control()
        pointer = _pointer(control.payload["pointer"])
        pins = resource.pins
        if self.runs is not None:
            observations = tuple(
                item for item in self.runs.pins()
                if item["generation_id"] == resource.generation_id
            )
            if len(observations) != 1 or type(observations[0]["holders"]) is not tuple:
                raise AuthorizationError()
            pins = tuple(c.uuid_text(value) for value in observations[0]["holders"])
        return replace(
            resource, pins=pins,
            active=type(pointer) is lc.PresentPointer
            and pointer.active_generation_id == resource.generation_id,
            healthy_previous=control.payload.get("prior_healthy_generation_id") == resource.generation_id,
        )

    def _set_admission(self, enabled: bool) -> None:
        record = self._control()
        self._write(record.resource_id, record.revision, replace(
            record, revision=record.revision + 1,
            payload=c.public_object({**dict(record.payload), "admission_enabled": enabled}),
        ))

    @staticmethod
    def _validate_drained_pins(
        before: tuple[lc.FrozenObject, ...], after: tuple[lc.FrozenObject, ...],
    ) -> None:
        if type(before) is not tuple or type(after) is not tuple or len(before) != len(after):
            raise AuthorizationError()
        for old, new in zip(before, after):
            for pin in (old, new):
                if type(pin) is not lc.FrozenObject or set(pin) != {"generation_id", "manifest_digest", "revision", "holders"}:
                    raise c.ContractError()
                c.uuid_text(pin["generation_id"])
                c.sha256(pin["manifest_digest"])
                c.counter(pin["revision"])
                if type(pin["holders"]) is not tuple:
                    raise c.ContractError()
                for holder in pin["holders"]:
                    c.text(holder)
            if (
                old["generation_id"] != new["generation_id"]
                or old["manifest_digest"] != new["manifest_digest"]
                or c.counter(new["revision"]) < c.counter(old["revision"]) or new["holders"] != ()
            ):
                raise AuthorizationError()

    def _retained_verification(self, generation: lc.GenerationBinding) -> lc.FrozenObject:
        record = self._read("dependency-verification-" + c.digest(generation))
        data = c.public_object(record.payload)
        if set(data) != {"schema", "verification"} or data["schema"] != "i02-retained-verification-v1":
            raise AuthorizationError()
        return c.public_object({**dict(c.public_object(data["verification"])), "kind": "retained"})

    def _live_probe(
        self, manifest: ManagedGenerationManifest, verification: object,
    ) -> tuple[c.ReadinessReport, c.FrozenObject | None] | None:
        """Select only this host's actual completed proof of the exact installed candidate."""
        if manifest.installation is None or type(self.files) is not ProtectedGenerationFiles:
            return None
        proof = self._live_probes.get(manifest.generation_id)
        if proof is None or proof[0] != verification:
            return None
        return proof[1], proof[2]

    def _manifest(self, binding: lc.LifecycleBinding) -> ManagedGenerationManifest:
        matches = tuple(item for item in self.manifests
                        if item.generation_id == binding.generation.generation_id)
        if len(matches) != 1:
            raise AuthorizationError()
        manifest = matches[0]
        if (
            type(binding) not in (lc.InstallBinding, lc.RestoreBinding, lc.UninstallBinding)
            or (type(binding) is lc.InstallBinding and manifest.scope != binding.scope)
            or c.digest(manifest.context) != binding.context_digest
            or manifest.context.context.registry_digest != binding.registry_digest
            or manifest.context.context.policy_identity != binding.policy
            or replace(binding.generation, selected=()) != lc.GenerationBinding(
                manifest.generation_id, 0, manifest.content_digest, c.digest(manifest),
            )
        ):
            raise AuthorizationError()
        return manifest

    @staticmethod
    def _steps(
        manifest: ManagedGenerationManifest, root: lc.OwnedRootBinding,
        kinds: tuple[lc.LifecycleEffectKind, ...],
    ) -> tuple[lc.FrozenObject, ...]:
        result = []
        asset_index = 0
        for index, kind in enumerate(kinds):
            if kind == "dependency-download" and asset_index >= len(manifest.assets):
                raise AuthorizationError()
            asset = manifest.assets[asset_index] if kind == "dependency-download" else manifest.asset
            if kind == "dependency-download":
                asset_index += 1
            destination = None if kind in ("dependency-probe", "dependency-activate", "restore-active-pointer") else {
                "resource_id": root.resource_id, "root_resource_id": root.resource_id,
                "segments": ("generations", manifest.generation_id),
                "manifest_digest": c.digest(manifest),
            }
            source = None if kind not in ("dependency-download", "dependency-stage") else {
                "source_id": asset.source_id,
                "registry_digest": manifest.context.context.registry_digest,
                "artifact_digest": asset.sha256,
                "descriptor_digest": c.digest(asset),
            }
            result.append(c.public_object({
                "occurrence_id": "restore-active-pointer" if kind == "restore-active-pointer" else f"{index}-{kind}",
                "generation_id": manifest.generation_id,
                "source": source, "destination": destination, "reuse": None,
                "consequential": (),
            }))
        return tuple(result)

    def snapshot_lifecycle(self, binding: lc.LifecycleBinding) -> LifecycleSnapshot:
        """Re-read root, descriptors, staged records, verification and pointer."""
        with self.lock_lifecycle(binding):
            root = self._facts()
            control = self._control()
            valid = True
            evidence = None
            try:
                manifest = self._manifest(binding)
                expected_root = lc.OwnedRootBinding(
                    root.resource_id, c.digest(c.public_object(root.payload["root_manifest"])),
                )
                ordinary = tuple(effect for effect in binding.effects
                                 if not effect.occurrence_id.startswith("family-"))
                base = iter(self._steps(
                    manifest, expected_root, tuple(effect.kind for effect in ordinary),
                ))
                steps = tuple(
                    self._family_step(manifest, expected_root, effect)
                    if effect.occurrence_id.startswith("family-") else next(base)
                    for effect in binding.effects
                )
                staged = self._generations(root)
                selected = tuple(item for item in staged
                                 if item["generation_id"] == manifest.generation_id)
                if len(selected) > 1:
                    raise AuthorizationError()
                if selected and (
                    selected[0]["manifest"] != c.public_object(c.wire(manifest))
                    or selected[0]["state"] not in ("staging", "staged")
                ):
                    raise AuthorizationError()
                verification = (
                    self._retained_verification(binding.generation) if binding.kind == "restore"
                    else (control.payload["verification"] if binding.content["verification"] is not None else None)
                )
                pins = self.runs.pins() if binding.kind in ("restore", "uninstall") and self.runs is not None else ()
                if binding.kind == "uninstall":
                    pins = tuple(pin for pin in pins if c.text(pin["generation_id"]) in (
                        item.generation_id for item in binding.generation.selected
                    ))
                evidence = LifecycleEvidence(
                    expected_root,
                    (replace(binding.generation, selected=()),) if selected and selected[0]["state"] == "staged" else (),
                    steps, pins,
                    None if verification is None else c.public_object(verification),
                )
                valid = (
                    binding.root == expected_root and steps == binding.content["steps"]
                    and _pointer(control.payload["pointer"]) == binding.expected_pointer
                    and (binding.kind in ("restore", "uninstall") or control.payload["installation_id"] in (None, binding.lifecycle_id))
                )
            except (c.ContractError, AuthorizationError, KeyError):
                valid = False
            return LifecycleSnapshot(
                binding, root.revision, (binding.kind, binding.plan_id) in self._cancelled,
                (binding.kind in ("restore", "uninstall") or (
                    control.payload["setup_enabled"] is True
                    and control.payload.get("admission_enabled", True) is True
                )), valid, valid, valid, evidence,
            )

    def compare_lifecycle_revision(
        self, binding: lc.LifecycleBinding, expected: int, following: int,
    ) -> bool:
        """Advance only this protected root's exact numeric checkpoint revision."""
        c.counter(expected)
        c.counter(following)
        record = self._facts()
        if record.revision != expected or following != expected + 1:
            return False
        self._write(record.resource_id, expected, replace(record, revision=following))
        return True

    def compare_replace_lifecycle(
        self, binding: lc.LifecycleBinding, expected: lc.PointerExpectation,
        following_revision: int,
    ) -> bool:
        """CAS only the exact verified native generation; no reverse CAS."""
        record = self._control()
        c.counter(following_revision)
        if _pointer(record.payload["pointer"]) != expected or following_revision != expected.revision + 1:
            return False
        verification = (
            self._retained_verification(binding.generation) if binding.kind == "restore"
            else record.payload["verification"]
        )
        if verification != binding.content["verification"]:
            return False
        run = self._run
        if run is None or isinstance(run, ManagedUninstall) or run.binding != binding:
            return False
        # The admitted probe established actual functional evidence. At CAS,
        # guard every byte/owner/member again under this same root lock without
        # consuming that interpreter twice inside the original evidence window.
        # Restore has its own separately qualified functional guard.
        if type(run) is _ManagedRun:
            run.guard_probe()
        else:
            run.probe(retained=True)
            if run.scope is None:
                raise AuthorizationError()
            self.guard_source(
                self._manifest(binding), run.clock, run.cancel, run.scope.deadline,
            )
        if (
            run.cancel.is_cancelled() or run.scope is None
            or c.finite(run.clock.monotonic()) >= run.scope.deadline
            or c.finite(run.clock.monotonic()) >= c.finite(
                c.public_object(binding.content["verification"])["expires_at"],
            )
        ):
            raise AuthorizationError()
        pointer = lc.PresentPointer(
            "present", binding.generation.generation_id,
            c.digest((binding.generation, following_revision)), following_revision,
        )
        self._write(record.resource_id, record.revision, replace(
            record, revision=record.revision + 1,
            payload=c.public_object({
                **dict(record.payload), "pointer": c.wire(pointer),
                "prior_healthy_generation_id": expected.active_generation_id
                if type(expected) is lc.PresentPointer
                and expected.active_generation_id != binding.generation.generation_id
                else record.payload.get("prior_healthy_generation_id"),
            }),
        ))
        return True

    def compose(
        self, preview: InstallPlan, scope: c.InstallScope,
        entries: tuple[DependencyEntry, ...], service: DependencyService,
    ) -> InstallPlan:
        """Read-only: bind every selected dependency or return explicit blockers."""
        self._facts()
        control = self._control()
        if not control.payload["setup_enabled"] or control.payload.get("admission_enabled", True) is not True:
            return replace(preview, steps=tuple(
                replace(step, disposition="blocked", reason="managed-setup-disabled")
                for step in preview.steps
            ), blocked=tuple(step.dependency for step in preview.steps))
        contexts = tuple(sorted(item.digest for item in service._contexts().values()))
        candidates = tuple(item for item in self.manifests if (
            item.scope == scope and item.context == preview.context
            and item.consuming_contexts == contexts
        ))
        by_dependency = {
            dependency: item for item in candidates
            for dependency in (
                tuple(entry.id for entry in entries) if item.generation_id in self._family_locks
                and self._approve_sources(item, entries)
                else ("native-python",) if type(item.asset) is _OwnedBuildAsset
                and self._approve_sources(item, entries)
                else tuple(asset.dependency for asset in item.assets)
            )
        }
        steps = tuple(replace(
            step, disposition="planned" if step.dependency in by_dependency else "blocked",
            reason="review-required" if step.dependency in by_dependency else "verified-asset-lock-missing",
        ) for step in preview.steps)
        blocked = tuple(step.dependency for step in steps if step.disposition == "blocked")
        # Do not silently install only one member of a larger selected closure.
        if len(candidates) != 1:
            blocked = tuple(dict.fromkeys((*blocked, *(
                step.dependency for step in steps if step.disposition != "blocked"
            ))))
        if blocked:
            return replace(preview, steps=tuple(
                replace(step, disposition="blocked", reason=(
                    step.reason if step.dependency not in by_dependency else "ambiguous-generation-descriptor"
                )) for step in steps
            ), blocked=blocked)
        manifest = candidates[0]
        if not self._approve_sources(manifest, entries):
            return replace(preview, steps=tuple(
                replace(step, disposition="blocked", reason="selected-asset-closure-mismatch")
                for step in steps
            ), blocked=tuple(step.dependency for step in steps))
        pointer = self.pointer()
        verification = control.payload["verification"]
        if verification is not None:
            observed = c.public_object(verification)
            if (
                c.finite(service.clock.monotonic()) >= c.finite(observed["expires_at"])
                or (manifest.installation is not None and (
                    type(self.files) is ProtectedGenerationFiles
                    and self._live_probe(manifest, observed) is None
                ))
            ):
                # Expiry cannot be extended by reusing metadata or an old
                # grant, or reconstructing a live proof in a fresh process.
                # Plan separately consented actual verification of the retained
                # staged tree, with no download/reinstallation.
                verification = None
        lifecycle_id = preview.id if control.payload["installation_id"] is None else c.uuid_text(
            control.payload["installation_id"],
        )
        generations = self._generations(self._facts())
        staged = any(
            item["generation_id"] == manifest.generation_id
            and item["state"] == "staged" for item in generations
        )
        if any(
            item["generation_id"] == manifest.generation_id
            and item["state"] == "staging" for item in generations
        ):
            return replace(preview, steps=tuple(
                replace(step, disposition="blocked", reason="owned-staging-reconciliation-required")
                for step in steps
            ), blocked=tuple(step.dependency for step in steps))
        download_kind: lc.LifecycleEffectKind = "dependency-download"
        downloads = tuple(download_kind for _ in manifest.assets)
        staging: tuple[lc.LifecycleEffectKind, ...] = ("dependency-stage", "dependency-verify")
        kinds: tuple[lc.LifecycleEffectKind, ...]
        if verification is not None:
            kinds = ("dependency-probe", "dependency-activate")
        elif staged:
            kinds = ("dependency-verify",)
        else:
            kinds = downloads + staging
        root = self._facts()
        root_binding = lc.OwnedRootBinding(
            root.resource_id, c.digest(c.public_object(root.payload["root_manifest"])),
        )
        descriptors = self._steps(manifest, root_binding, kinds)
        family_lock = self._family_locks.get(manifest.generation_id)
        if family_lock is not None and verification is None:
            from ._family_provider import _descriptor, _operation

            actions = ("verify",) if staged else ("install", "verify")
            family_steps = tuple(
                _descriptor(
                    family_lock, release,
                    _operation(family_lock, release, action, manifest.generation_id),
                    root_binding, f"family-{action}-{index}",
                )
                for action in actions
                for index, release in enumerate(family_lock.releases)
            )
            # The original installer owns the first stage. Family receipts
            # describe its actual materialized contributions, before the
            # original final whole-selection consuming probe.
            descriptors = (*descriptors[:-1], *family_steps, descriptors[-1])
            family_install: lc.LifecycleEffectKind = "dependency-stage"
            family_verify: lc.LifecycleEffectKind = "dependency-verify"
            kinds = (
                *kinds[:-1],
                *(family_install if action == "install" else family_verify
                  for action in actions for _ in family_lock.releases),
                kinds[-1],
            )
        effects = tuple(lc.LifecycleEffectOccurrence(
            c.text(step["occurrence_id"]), index, c.text(step["occurrence_id"]),
            c.text(c.public_object(step["destination"])["resource_id"])
            if c.text(step["occurrence_id"]).startswith("family-") else root.resource_id,
            kind, lifecycle_arguments_digest(step),
        ) for index, (step, kind) in enumerate(zip(descriptors, kinds)))
        plan = lc.InstallPlan(
            "1.0", preview.id, lifecycle_id, "0" * 64, c.digest(preview.context),
            root_binding, lc.GenerationBinding(
                manifest.generation_id, 0, manifest.content_digest, c.digest(manifest),
            ), pointer, preview.policy_identity, preview.registry_digest,
            next((item.qualification_digest for item in self.qualifications
                  if item.generation == lc.GenerationBinding(
                      manifest.generation_id, 0, manifest.content_digest, c.digest(manifest),
                  ) and item.scope == scope and item.context == preview.context),
                 c.digest(("unqualified-native-managed-tree", manifest))), effects,
            _consequential(descriptors),
            c.public_object({
                "schema": "1.0", "steps": descriptors, "verification": verification,
                "pins": (), "cancel_scope": tuple(effect.occurrence_id for effect in effects),
            }), "install", scope,
        )
        plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
        bind_lifecycle(plan)
        return replace(preview, steps=steps, lifecycle=plan, blocked=())

    def _family_step(
        self, manifest: ManagedGenerationManifest, root: lc.OwnedRootBinding,
        effect: lc.LifecycleEffectOccurrence,
    ) -> c.FrozenObject:
        from ._family_provider import _descriptor, _operation

        lock = self._family_locks.get(manifest.generation_id)
        if lock is None:
            raise AuthorizationError()
        for action in ("install", "verify", "remove"):
            for index, release in enumerate(lock.releases):
                if effect.occurrence_id == f"family-{action}-{index}":
                    expected_kind = {
                        "install": "dependency-stage", "verify": "dependency-verify",
                        "remove": "dependency-uninstall",
                    }[action]
                    if effect.kind != expected_kind:
                        raise AuthorizationError()
                    operation = _operation(lock, release, action, manifest.generation_id)
                    return _descriptor(
                        lock, release, operation, root, effect.occurrence_id,
                        generation_manifest_digest=c.digest(manifest),
                    )
        raise AuthorizationError()

    def _dispatch_family(
        self, manifest: ManagedGenerationManifest, binding: lc.LifecycleBinding,
        broker: AuthorizationBroker, permit: lc.LifecycleEffectPermit,
        effect: lc.LifecycleEffectBinding, clock: c.ClockPort, cancel: c.CancelPort,
        *, scope_review: _ScopeReceipt | None = None,
    ) -> None:
        from ._family_integration import _MaterializedFamilies
        from ._family_ledger import _OwnedFamilyLedger
        from ._family_provider import _FamilyDriver, _FamilyHost, _operation

        lock = self._family_locks.get(manifest.generation_id)
        if lock is None:
            raise AuthorizationError()
        occurrence = next(item for item in binding.effects
                          if item.occurrence_id == effect.occurrence_id)
        descriptor = self._family_step(manifest, binding.root, occurrence)
        for action in ("install", "verify", "remove"):
            for index, release in enumerate(lock.releases):
                if effect.occurrence_id != f"family-{action}-{index}":
                    continue
                steps = binding.content["steps"]
                if type(steps) is not tuple or descriptor not in steps:
                    raise AuthorizationError()
                ledger = _OwnedFamilyLedger(
                    self._state, binding.root, "family-ledger-" + c.digest(manifest.generation_id),
                    self._owner, self._identity, lock, self, clock,
                )
                host = _MaterializedFamilies(self, manifest, lock)
                _FamilyDriver(
                    cast(_FamilyHost, host), ledger, clock, self._family_reviews, scope_review,
                    generation_manifest_digest=c.digest(manifest),
                ).execute(
                    lock, release, _operation(lock, release, action, manifest.generation_id),
                    broker, permit, effect, cancel,
                )
                return
        raise AuthorizationError()

    def validate_public(self, preview: InstallPlan, service: DependencyService) -> None:
        """Reject caller edits and context/registry drift before prompt or admission."""
        closed = preview.lifecycle
        if closed is None:
            raise AuthorizationError()
        entries = service._entries(service._selection(closed.scope), closed.scope)
        # Recomposition is read-only and validates the exact selected closure;
        # preserve reviewed IDs, but never substitute a newly composed plan.
        baseline = service._catalog_plan(closed.scope, preview.context, preview.id)
        expected = self.compose(baseline, closed.scope, entries, service)
        expected = replace(expected, digest=c.digest(replace(expected, digest="")))
        if expected != preview:
            raise AuthorizationError()
        snapshot = self.snapshot_lifecycle(bind_lifecycle(closed))
        if not snapshot.owned_valid:
            raise AuthorizationError()

    def _checkpoint(
        self, binding: lc.LifecycleBinding, state: lc.PolicyState,
        event: lc.DecisionEvent, previous: OwnedRecord | None,
    ) -> OwnedRecord:
        """Persist only reducer output and factual event metadata, never permits."""
        with self.lock_lifecycle(binding):
            root = self._facts()
            resource = "dependency-policy-" + binding.plan_id
            payload = c.public_object({
                "schema": "i02-managed-policy-v1", "state": c.wire(state),
                "event": c.wire(event),
                "previous_event_digest": c.digest(previous.payload) if previous is not None else None,
            })
            # Immutable history and mutable policy heads are distinct streams:
            # a head observer must not count every reducer event twice.
            event_resource = "dependency-lifecycle-event-" + binding.plan_id + "-" + str(state.revision)
            self._write(event_resource, 0, replace(
                root, resource_id=event_resource, revision=0, payload=payload,
            ))
            if previous is None:
                record = replace(root, resource_id=resource, revision=0, payload=payload)
                return self._write(resource, 0, record)
            actual = self._read(resource)
            if actual != previous:
                raise AuthorizationError()
            return self._write(resource, previous.revision, replace(
                previous, revision=previous.revision + 1, payload=payload,
            ))

    def execute(
        self, plan: lc.InstallPlan | lc.RestorePlan | lc.UninstallPlan, consent: lc.InstallConsent, cancel: c.CancelPort,
        service: DependencyService,
    ) -> InstallOutcome:
        """Drive actual reducer events, broker permits and managed I/O in order."""
        runner: _ManagedRun | ManagedRestore | ManagedUninstall
        if isinstance(plan, lc.RestorePlan):
            runner = ManagedRestore(self, service, plan, consent, cancel)
        elif isinstance(plan, lc.UninstallPlan):
            runner = ManagedUninstall(self, service, plan, consent, cancel)
        else:
            runner = _ManagedRun(self, service, plan, consent, cancel)
        if not self._execution.acquire(blocking=False):
            return service._lifecycle._blocked(runner.binding, c.ReasonCode.RESOURCE_BUSY)
        try:
            self._run = runner
            history = OutcomeStore(self)
            original = history.previous_errors(runner.binding.lifecycle_id)
            outcome = replace(runner.execute(), original_errors=original)
            try:
                history.save(runner.binding, outcome)
            except Exception:
                outcome = replace(
                    outcome, status=c.OutcomeStatus.PARTIAL if any(
                        step.status == c.OutcomeStatus.SUCCEEDED for step in outcome.steps
                    ) else c.OutcomeStatus.FAILED,
                    cleanup_errors=(*outcome.cleanup_errors, _error(
                        c.ReasonCode.OWNERSHIP_INVALID, c.ErrorCategory.CLEANUP, c.Stage.FINALIZE,
                        "Inspect immutable outcome publication; retain original failures and pointer facts.",
                    )),
                )
            return outcome
        finally:
            self._run = None
            self._execution.release()

    def plan_uninstall(
        self, generation_id: str, context: c.InstallContext, service: DependencyService,
    ) -> lc.UninstallPlan:
        """Plan an explicit owned inactive-generation cleanup, never an active TTL purge."""
        return plan_uninstall(self, generation_id, context, service)

    def resume(
        self, installation_id: str, consent: lc.InstallConsent, cancel: c.CancelPort,
        service: DependencyService,
    ) -> InstallOutcome:
        """Use only the newly reviewed binding; saved checkpoints are never grants."""
        c.uuid_text(installation_id)
        broker = service.authorization
        if type(broker) is not AuthorizationBroker:
            raise AuthorizationError()
        scope = broker._life_scope(consent)
        previous = RecoveryStore(self).read(installation_id)
        if scope is None or type(scope.binding) is not lc.InstallBinding:
            raise AuthorizationError()
        binding = scope.binding
        if (
            binding.lifecycle_id != installation_id or binding.plan_id == previous.plan_id
            or binding.scope != previous.scope or c.digest(previous.context) != binding.context_digest
        ):
            raise AuthorizationError()
        report = service.verify(binding.scope, previous.context)
        if (
            c.digest(report) != previous.observation_digest
            or tuple(sorted(item.digest for item in service._contexts().values())) != previous.consuming_contexts
        ):
            broker.revoke_lifecycle("install", binding.plan_id)
            return service._lifecycle._blocked(binding, c.ReasonCode.CONSENT_STALE)
        # This is the exact plan projection registered by the NEW live private
        # prompt, not grant/session/permit reconstruction from persistent data.
        plan = lc.InstallPlan(**{
            name: getattr(binding, name) for name in lc.InstallBinding.__dataclass_fields__
        })
        return self.execute(plan, consent, cancel, service)


class _ManagedRun:
    """One live composition; neither persisted facts nor phases restore a grant."""

    def __init__(
        self, state: ManagedLifecycleState, service: DependencyService,
        plan: lc.InstallPlan, consent: lc.InstallConsent, cancel: c.CancelPort,
    ) -> None:
        self.host, self.service, self.plan = state, service, plan
        binding = bind_lifecycle(plan)
        if type(binding) is not lc.InstallBinding:
            raise c.ContractError()
        self.binding: lc.InstallBinding = binding
        self.consent, self.cancel = consent, cancel
        broker = service.authorization
        if type(broker) is not AuthorizationBroker:
            raise AuthorizationError()
        self.broker: AuthorizationBroker = broker
        self.clock = _MonotonicClock(service.clock)
        self.manifest = state._manifest(self.binding)
        self.policy_state = lc.PolicyState(
            self.binding.policy, self.binding.lifecycle_id, 0, lc.Phase.PLANNED,
            self.binding.plan_digest, self.binding.context_digest,
            self.binding.policy.bundle_sha256,
            tuple(lc.StepDisposition(
                self.binding.root.resource_id, effect.step_id,
                invocation_id=str(uuid4()), effect_id=effect.occurrence_id,
            ) for effect in self.binding.effects), namespace="install",
        )
        self.checkpoint: OwnedRecord | None = None
        self.scope = self.broker._life_scope(consent)
        self.report: c.ReadinessReport | None = None
        self.installed_receipt: c.FrozenObject | None = None
        self.family_scope_review = None
        lock = self.host._family_locks.get(self.manifest.generation_id)
        if lock is not None and any(release.scopes for release in lock.releases):
            if self.host._family_reviews is None or self.scope is None:
                raise AuthorizationError()
            self.family_scope_review = self.host._family_reviews.review(
                lock, self.binding, self.clock, cancel, self.scope.deadline,
            )

    def now(self) -> float:
        return c.finite(self.clock.monotonic())

    def duration(self, started: float) -> float:
        """Preserve the original safe failure when the observation clock fails."""
        try:
            return max(0.0, self.now() - started)
        except Exception:
            return 0.0

    def facts(
        self, next_kind: str, *, completed: int = 0, verified: bool = False,
        committed: bool = False,
    ) -> lc.DecisionFacts:
        binding = self.binding
        now = self.now()
        scope = self.scope
        snapshot = self.host.snapshot_lifecycle(binding)
        current_valid = snapshot.owned_valid
        if committed:
            pointer = self.host.pointer()
            self.host._facts()
            current_valid = (
                type(pointer) is lc.PresentPointer
                and pointer.active_generation_id == binding.generation.generation_id
                and pointer.revision == binding.expected_pointer.revision + 1
            )
        matches = scope is not None and scope.binding == binding
        remaining = max(0, int((scope.deadline - now) * 1000)) if scope is not None else 0
        return lc.DecisionFacts(c.public_object({
            "binding": {
                "input_valid": True, "plan_current": current_valid,
                "policy_current": binding.policy == self.service._policy_identity,
            },
            "request": {"area": "setup", "operation": "install", "mode": "apply"},
            "control": {"cancelled": self.cancel.is_cancelled(), "remaining_ms": remaining},
            "consent": {
                "present": scope is not None, "binding_matches": matches,
                "effects_match": matches, "recovery_matches": matches, "remaining_ms": remaining,
            },
            "consequential": _category_facts(self.broker, binding, self.consent, now),
            "ownership": {"valid": current_valid},
            "candidate": {
                "verified": verified, "pointer_matches": current_valid,
                "retained_owned": current_valid,
            },
            "readiness": {
                "native": self.report.readiness.native if verified and self.report is not None else "blocked",
                "companion": self.report.readiness.companion if verified and self.report is not None else "blocked",
                "enhanced": self.report.readiness.enhanced if verified and self.report is not None else "blocked",
                "selected_complete": verified,
            },
            "lifecycle": {"next_effect_kind": next_kind},
            "result": {
                "selected": len(binding.effects), "completed": completed,
                "unsuccessful": 0, "failed": 0, "cancelled": 0, "unsupported": 0,
                "blocked": 0, "policy_failed": False, "cleanup_failed": False,
                "remote_uncertain": False,
            },
            "change": {"poststate_verified": False},
        }), self.policy_state.phase, self.policy_state.revision)

    def transition(
        self, kind: lc.EventKind, index: int, payload: dict,
        next_kind: str, *, completed: int = 0, verified: bool = False,
    ) -> lc.DecisionResult:
        effect = self.binding.effects[index]
        event = lc.DecisionEvent(
            str(uuid4()), kind, self.policy_state.revision, self.binding.plan_digest,
            self.binding.context_digest, self.binding.policy.bundle_sha256,
            self.binding.root.resource_id, effect.step_id, c.public_object(payload),
            install_id=self.binding.lifecycle_id,
        )
        transition = self.service.policy.reduce(
            self.policy_state, event,
            self.facts(next_kind, completed=completed, verified=verified,
                       committed=kind == lc.EventKind.ACTIVATED),
        )
        if transition.decision.decision != "allow" or transition.next_state.revision != self.policy_state.revision + 1:
            raise AuthorizationError()
        self.checkpoint = self.host._checkpoint(
            self.binding, transition.next_state, event, self.checkpoint,
        )
        self.policy_state = transition.next_state
        return transition.decision

    @staticmethod
    def requested(decision: lc.DecisionResult, kind: str) -> None:
        intents = tuple(effect for effect in decision.effects if effect.name == "request_effect")
        if intents != (lc.EffectDescriptor("request_effect", c.public_object({"kind": kind})),):
            raise AuthorizationError()

    def probe(self, *, retained: bool) -> c.ReadinessReport:
        """Probe the exact consuming interpreter/context, not the active pointer."""
        manifest = self.manifest
        if tuple(sorted(item.digest for item in self.service._contexts().values())) != manifest.consuming_contexts:
            raise AuthorizationError()
        deadline = min(self.scope.deadline if self.scope is not None else self.now(), self.now() + 60.0)
        self.host.guard_source(manifest, self.clock, self.cancel, deadline)
        if retained:
            proof = self.host._live_probe(manifest, self.binding.content["verification"])
            if proof is not None:
                self.report, self.installed_receipt = proof
                # Still verify every protected byte/owner/member before the
                # probe effect completes. CAS repeats that guard under its lock.
                with self.host.lock_lifecycle(self.binding):
                    self.guard_probe()
                return self.report
        if manifest.installation is not None:
            from ._installation import _OfflineInstallation

            if type(self.host.files) is not ProtectedGenerationFiles:
                raise AuthorizationError()
            installation = _OfflineInstallation(self.host.files._root)
            role = "controller" if manifest.installation.controller else "native"
            context = self.service._contexts().get(role)
            if context is None or context.python != str(installation.python(manifest)):
                raise AuthorizationError()
            if manifest.installation.controller_installation is not None:
                companion = _OfflineInstallation(self.host.files._root, controller=True)
                context = self.service._contexts().get("controller")
                if context is None or context.python != str(companion.python(manifest)):
                    raise AuthorizationError()
        installed_receipt = self.host.files.verify(
            manifest, self.clock, self.cancel,
            deadline,
        )
        self.host.guard_source(manifest, self.clock, self.cancel, deadline)
        if manifest.installation is not None:
            self.installed_receipt = self.host._installed_receipt(manifest, installed_receipt)
        report = self.service.verify(manifest.scope, manifest.context)
        if report.readiness.native != "ready" or any(
            value == "blocked" for value in (report.readiness.companion, report.readiness.enhanced)
        ):
            raise AuthorizationError()
        if retained:
            verification = c.public_object(self.binding.content["verification"])
            probes = verification["probes"]
            if type(probes) is not tuple or len(probes) != 1:
                raise AuthorizationError()
            if c.public_object(probes[0])["result_digest"] != c.digest(report):
                raise AuthorizationError()
        self.report = report
        return report

    def guard_probe(self) -> None:
        """Guard fresh live functional proof with exact full-tree bytes at pointer CAS."""
        if self.report is None or self.scope is None:
            raise AuthorizationError()
        verification = c.public_object(self.binding.content["verification"])
        probes = verification["probes"]
        deadline = min(self.scope.deadline, c.finite(verification["expires_at"]))
        if (
            self.now() >= deadline or self.cancel.is_cancelled()
            or type(probes) is not tuple or len(probes) != 1
            or c.public_object(probes[0])["result_digest"] != c.digest(self.report)
            or tuple(sorted(item.digest for item in self.service._contexts().values()))
            != self.manifest.consuming_contexts
        ):
            raise AuthorizationError()
        if type(self.host.files) is not ProtectedGenerationFiles:
            # Nonproduction effect ports retain the original full probe path;
            # no supplied fake receipt becomes reusable native proof.
            self.probe(retained=True)
            return
        with _native_phase("cas-source-before", self.clock, self.cancel, deadline):
            self.host.guard_source(self.manifest, self.clock, self.cancel, deadline)
        with _native_phase("cas-owned-tree", self.clock, self.cancel, deadline):
            actual = self.host.files._verify(
                self.manifest, self.clock, self.cancel, deadline, functional=False,
            )
        if self.manifest.installation is not None:
            if self.installed_receipt is None:
                raise AuthorizationError()
            with _native_phase("cas-installed-receipt", self.clock, self.cancel, deadline):
                receipt = self.host._installed_receipt(self.manifest, actual)
                if receipt != self.installed_receipt:
                    raise AuthorizationError()
        if self.now() >= deadline or self.cancel.is_cancelled():
            raise AuthorizationError()
        with _native_phase("cas-source-after", self.clock, self.cancel, deadline):
            self.host.guard_source(self.manifest, self.clock, self.cancel, deadline)

    def verification(self, report: c.ReadinessReport) -> None:
        """Persist real file and functional probe facts; no qualification claim."""
        binding = self.binding
        now = self.now()
        qualifications = tuple(item for item in self.host.qualifications if (
            item.generation == binding.generation and item.scope == binding.scope
            and item.context == self.manifest.context
            and item.consuming_contexts == self.manifest.consuming_contexts
            and item.report_digest == c.digest(report)
        ))
        qualification_digest = qualifications[0].qualification_digest if len(qualifications) == 1 else binding.qualification_digest
        verification = c.public_object({
            "kind": "candidate", "event_kind": "CandidateVerified", "event_id": str(uuid4()),
            "revision": self.policy_state.revision,
            "generation_id": binding.generation.generation_id,
            "content_digest": binding.generation.content_digest,
            "manifest_digest": binding.generation.manifest_digest,
            "context_digest": binding.context_digest, "registry_digest": binding.registry_digest,
            "policy_digest": binding.policy.bundle_sha256,
            "qualification_digest": qualification_digest,
            "observed_at": now, "expires_at": c.checked_deadline(
                now, float(self.host._observation.max_age_seconds)
                if self.host._observation is not None else 60.0,
            ),
            "probes": ({
                "probe_id": "dependency-readiness", "generation_id": binding.generation.generation_id,
                "content_digest": binding.generation.content_digest,
                "context_digest": binding.context_digest,
                "result_digest": c.digest(report), "status": "succeeded",
            },),
        })
        with self.host.lock_lifecycle(binding):
            if self.manifest.installation is not None:
                if type(self.host.files) is not ProtectedGenerationFiles:
                    raise AuthorizationError()
                # The just-completed consuming probe already rehashed and
                # validated this exact receipt. Repeating that full operation
                # here consumed the entire evidence window before publication
                # on native Windows. Final pointer CAS independently re-probes
                # actual files/context under the original lock and deadline.
                if self.installed_receipt is None:
                    raise AuthorizationError()
                receipt = self.host._installed_receipt(self.manifest, self.installed_receipt)
                root = self.host._facts()
                resource = "dependency-installation-" + c.digest(binding.generation)
                self.host._write_immutable(replace(
                    root, resource_id=resource, revision=0, payload=c.public_object({
                        "schema": "i02-installation-receipt-v1", "receipt": receipt,
                        "generation_binding": c.wire(binding.generation),
                        "context_digest": binding.context_digest,
                        "registry_digest": binding.registry_digest,
                        "consuming_contexts": self.manifest.consuming_contexts,
                    }),
                ))
            record = self.host._control()
            self.host._write(record.resource_id, record.revision, replace(
                record, revision=record.revision + 1,
                payload=c.public_object({**dict(record.payload), "verification": verification}),
            ))
            if self.manifest.installation is not None:
                self.host._live_probes[self.manifest.generation_id] = (
                    verification, report, self.installed_receipt,
                )
            if qualifications:
                root = self.host._facts()
                resource = "dependency-verification-" + c.digest(binding.generation)
                self.host._write(resource, 0, replace(
                    root, resource_id=resource, revision=0, payload=c.public_object({
                        "schema": "i02-retained-verification-v1", "verification": verification,
                    }),
                ))

    def execute(self) -> InstallOutcome:
        binding = self.binding
        results: list[InstallStepOutcome] = []
        errors: list[c.SafeError] = []
        cleanup: list[c.SafeError] = []
        pending: tuple[str, ...] = ()
        selected = binding.effects[0]
        started = self.now()
        uncertain = False
        entered = False
        factual = False
        permit: lc.LifecycleEffectPermit | None = None
        try:
            if (
                self.broker._lifecycle_state is not self.host
                or binding.registry_digest != self.service.registry.digest
                or binding.policy != self.service._policy_identity
                or self.scope is None or self.scope.binding != binding
            ):
                raise AuthorizationError()
            if self.cancel.is_cancelled():
                raise InterruptedError()
            # Validate the full actual registry closure before even persisting
            # InstallConsented; direct closed-plan callers cannot skip selection.
            entries = self.service._entries(
                self.service._selection(binding.scope), binding.scope,
            )
            if not self.host._approve_sources(self.manifest, entries):
                raise AuthorizationError()
            first = self.transition(lc.EventKind.INSTALL_CONSENTED, 0, {
                "lifecycle_kind": "install", "plan_id": binding.plan_id,
                "lifecycle_binding_digest": c.digest(binding),
                "private_consent_reference": "host-private-lifecycle",
            }, selected.kind)
            self.requested(first, selected.kind)
            # A01's plan grant covers the reviewed ordered closure, not dispatch.
            # Every occurrence below STILL needs its actual preceding reducer
            # intent and a private one-use permit. No simulated completions or
            # repeated InstallConsented decisions are used to invent intentions.
            aggregate = replace(first, effects=lifecycle_effects(binding))
            grant = self.broker.issue_lifecycle(self.plan, self.consent, aggregate, self.now())
            session = self.broker.consume_lifecycle(grant, binding, self.now())
            initial_report = self.service.verify(binding.scope, self.manifest.context)
            recovery = RecoveryStore(self.host)
            selected_id = self.host._control().payload["installation_id"]
            previous = recovery.read(c.uuid_text(selected_id)) if selected_id is not None else None
            retained = recovery.retained(binding.generation) if previous is not None else None
            if previous is not None and (
                previous.installation_id != binding.lifecycle_id
                or previous.scope != binding.scope or previous.context != self.manifest.context
                or previous.consuming_contexts != self.manifest.consuming_contexts
            ):
                raise AuthorizationError()
            recovery.save(binding, RecoverySelection(
                binding.lifecycle_id, binding.plan_id, binding.generation, binding.scope,
                self.manifest.context, self.manifest.consuming_contexts, c.digest(initial_report),
            ), previous, retained=retained)
            with self.host.lock_lifecycle(binding):
                record = self.host._control()
                if record.payload["installation_id"] not in (None, binding.lifecycle_id):
                    raise AuthorizationError()
                self.host._write(record.resource_id, record.revision, replace(
                    record, revision=record.revision + 1,
                    payload=c.public_object({**dict(record.payload), "installation_id": binding.lifecycle_id}),
                ))
            acquisition = VerifiedAssetAcquisition(
                self.broker, self.host.transport, self.clock, self.service.events,
            )
            handler = ManagedGenerationHandler(
                self.host._state, self.host.files, self.broker, self.clock, self.service.events,
            )
            contents: list[bytes] = []
            decision = first
            for index, selected in enumerate(binding.effects):
                entered = False
                factual = False
                permit = None
                self.requested(decision, selected.kind)
                if self.cancel.is_cancelled():
                    raise InterruptedError()
                started = self.now()
                snapshot = self.host.snapshot_lifecycle(binding)
                effect = lc.LifecycleEffectBinding(
                    binding, str(uuid4()), snapshot.revision, selected.occurrence_id,
                )
                permit = self.broker.permit_lifecycle(session, effect, self.now())
                entered = True
                self.host.guard_source(
                    self.manifest, self.clock, self.cancel, self.scope.deadline,
                )
                if selected.occurrence_id.startswith("family-"):
                    self.host._dispatch_family(
                        self.manifest, binding, self.broker, permit, effect, self.clock, self.cancel,
                        scope_review=self.family_scope_review,
                    )
                    factual = True
                elif selected.kind == "dependency-download":
                    asset = self.manifest.assets[len(contents)]
                    if type(asset) is _OwnedBuildAsset:
                        source = self.host._owned_source
                        if type(source) is not _OwnedSource:
                            raise AuthorizationError()
                        receipt = source.acquire(
                            self.manifest, self.broker, permit, effect, self.clock, self.cancel,
                        )
                    else:
                        if type(asset) is not LockedAsset:
                            raise AuthorizationError()
                        entry = entries[len(contents)] if self.manifest.generation_id not in (
                            self.host._family_locks
                        ) else replace(
                            entries[0], id=asset.dependency, source=asset.source_id,
                            ownership="toolkit-owned-only", digest=asset.sha256, size=asset.size,
                        )
                        receipt = acquisition.download(entry, asset, permit, effect, self.cancel)
                    contents.append(receipt.content)
                    factual = True
                elif selected.kind == "dependency-stage":
                    if len(contents) != len(self.manifest.assets):
                        raise AuthorizationError()
                    handler.stage(self.manifest, tuple(contents) if self.manifest.archives else contents[0],
                                  permit, effect, self.cancel)
                    factual = True
                    handler.complete(permit)
                else:
                    self.broker.enter_lifecycle(permit, effect, self.now())
                    if selected.kind in ("dependency-verify", "dependency-probe"):
                        report = self.probe(retained=selected.kind == "dependency-probe")
                        if selected.kind == "dependency-verify":
                            self.verification(report)
                        self.transition(lc.EventKind.DEPENDENCY_OBSERVED, index, {
                            "dependency_id": "selected-scope",
                            "context_digest": binding.context_digest,
                            "probe_receipt": "actual-selected-probe",
                            "probe_digest": c.digest(report), "readiness": "ready",
                        }, "none", completed=index, verified=True)
                        factual = True
                    elif selected.kind == "dependency-activate":
                        if self.report is None:
                            raise AuthorizationError()
                        # The declared probe occurrence already established
                        # CandidateVerified. The pointer host independently
                        # reprobes under its root lock immediately before CAS.
                        self.broker.replace_lifecycle_pointer(permit, self.now())
                        factual = True
                    else:
                        raise AuthorizationError()
                if selected.kind != "dependency-stage" or selected.occurrence_id.startswith("family-"):
                    current = self.host.snapshot_lifecycle(binding)
                    self.broker.complete_lifecycle(permit, str(uuid4()), current.revision, self.now())
                entered = False
                changed = (
                    selected.kind in ("dependency-download", "dependency-stage", "dependency-activate")
                    and not selected.occurrence_id.startswith("family-")
                )
                results.append(InstallStepOutcome(
                    selected.occurrence_id, selected.step_id, selected.kind,
                    c.OutcomeStatus.SUCCEEDED, changed,
                ))
                _observe(binding, selected, c.OutcomeStatus.SUCCEEDED,
                         self.duration(started), None, self.service.events)
                following = binding.effects[index + 1].kind if index + 1 < len(binding.effects) else "none"
                if selected.kind == "dependency-activate":
                    # The CAS is already factual. Activated is not a request,
                    # and must record the real pointer even after cancellation.
                    pointer = self.host.pointer()
                    if self.broker.reconcile_lifecycle_pointer(permit) != (
                        binding.generation.generation_id, pointer.revision,
                    ):
                        raise AuthorizationError()
                    self.transition(lc.EventKind.ACTIVATED, index, {
                        "expected_pointer_digest": c.digest(binding.expected_pointer),
                        "current_pointer_digest": c.digest(binding.expected_pointer),
                        "new_pointer_digest": c.digest(pointer),
                        "cas_receipt": "owned-pointer-cas",
                    }, "none", completed=index + 1, verified=True)
                    pending = ()
                    if self.cancel.is_cancelled():
                        raise InterruptedError()
                    break
                if following == "dependency-activate":
                    if self.report is None:
                        raise AuthorizationError()
                    self.transition(lc.EventKind.CANDIDATE_VERIFIED, index, {
                        "candidate_digest": binding.generation.content_digest,
                        "registry_digest": binding.registry_digest,
                        "assets_digest": self.manifest.context.context.assets_digest,
                        "policy_digest": binding.policy.bundle_sha256,
                        "qualification_digest": binding.qualification_digest,
                        "functional_evidence_ref": self.host._control_resource,
                    }, following, completed=index, verified=True)
                disposition = self.policy_state.dispositions[index]
                decision = self.transition(lc.EventKind.STEP_COMPLETED, index, {
                    "invocation_id": disposition.invocation_id,
                    "effect_id": selected.occurrence_id,
                    "target_id": binding.root.resource_id, "step_id": selected.step_id,
                    "safe_result_digest": c.digest((selected, self.report)),
                    "primary": "success", "cleanup": "success", "remote_uncertain": False,
                }, following, completed=index + 1, verified=self.report is not None)
            if selected.kind != "dependency-activate":
                if selected.kind == "dependency-verify":
                    if self.report is None:
                        raise AuthorizationError()
                    # The pre-effect observation describes an interpreter
                    # which may not exist yet. Only after actual verification
                    # and its admitted completion checkpoint the resulting
                    # observation for recovery. Never promote a denied or
                    # interrupted probe, nor change the original consent.
                    previous = recovery.read(binding.lifecycle_id)
                    recovery.save(binding, replace(
                        previous, observation_digest=c.digest(self.report),
                    ), previous)
                pending = ("review-activation-plan",)
        except (Exception, KeyboardInterrupt) as exc:
            with teardown(exc):
                self.broker.revoke_lifecycle("install", binding.plan_id)
            uncertain = entered and permit is not None and permit in self.broker._life_entered
            reason = c.ReasonCode.CANCELLED if isinstance(exc, (InterruptedError, KeyboardInterrupt)) else (
                c.ReasonCode.CONSENT_STALE if isinstance(exc, AuthorizationError) else c.ReasonCode.PROVISION_FAILED
            )
            error = exc.error if isinstance(exc, ArtifactError) else _error(
                reason, c.ErrorCategory.PRECONDITION if reason == c.ReasonCode.CONSENT_STALE else c.ErrorCategory.DEPENDENCY,
                c.Stage.PROVISION, "Inspect owned checkpoints; replan and obtain fresh exact consent.",
                selected.step_id,
            )
            cleanup.extend(cleanup_errors(exc))
            if not error.detail and _storage_detail(exc):
                error = replace(error, detail=_storage_detail(exc))
            errors.append(error)
            if not any(item.occurrence_id == selected.occurrence_id for item in results):
                results.append(InstallStepOutcome(
                    selected.occurrence_id, selected.step_id, selected.kind,
                    c.OutcomeStatus.SUCCEEDED if factual else (
                        c.OutcomeStatus.CANCELLED if reason == c.ReasonCode.CANCELLED else (
                            c.OutcomeStatus.BLOCKED if isinstance(exc, AuthorizationError) else c.OutcomeStatus.FAILED
                        )
                    ), changed=factual and selected.kind in (
                        "dependency-download", "dependency-stage", "dependency-activate",
                    ), error=None if factual else error,
                ))
            _observe(binding, selected, results[-1].status, self.duration(started),
                     error, self.service.events, stage=None if isinstance(exc, (
                         AuthorizationError, ArtifactError, c.ContractError, OSError,
                         InterruptedError, KeyboardInterrupt,
                     )) else "Unhandled")
        done = {item.occurrence_id for item in results}
        results.extend(InstallStepOutcome(
            item.occurrence_id, item.step_id, item.kind, c.OutcomeStatus.BLOCKED,
        ) for item in binding.effects if item.occurrence_id not in done)
        active = None
        pointer_revision = None
        try:
            pointer = self.host.pointer()
            pointer_revision = pointer.revision
            active = pointer.active_generation_id if type(pointer) is lc.PresentPointer else None
        except Exception:
            uncertain = True
            cleanup.append(_error(
                c.ReasonCode.OWNERSHIP_INVALID, c.ErrorCategory.CLEANUP, c.Stage.FINALIZE,
                "Inspect the exact protected pointer; never adopt or implicitly reverse it.",
            ))
        status = c.OutcomeStatus.SUCCEEDED if not errors and not pending and not cleanup and not uncertain else (
            c.OutcomeStatus.PARTIAL if any(item.status == c.OutcomeStatus.SUCCEEDED for item in results)
            else (c.OutcomeStatus.FAILED if cleanup or uncertain or any(
                item.status == c.OutcomeStatus.FAILED for item in results
            ) else (c.OutcomeStatus.CANCELLED if any(
                item.status == c.OutcomeStatus.CANCELLED for item in results
            ) else c.OutcomeStatus.BLOCKED))
        )
        readiness = self.report.readiness if self.report is not None and active == binding.generation.generation_id and not (pending or errors or cleanup or uncertain) else self.service._lifecycle._unobserved_readiness(binding)
        return InstallOutcome(
            binding.lifecycle_id, binding.plan_id, "install", status, tuple(results),
            readiness, binding.generation.generation_id, active,
            binding.expected_pointer.active_generation_id if type(binding.expected_pointer) is lc.PresentPointer else None,
            tuple(errors), tuple(cleanup), pending_actions=pending + tuple(
                item.occurrence_id for item in results if item.status != c.OutcomeStatus.SUCCEEDED
            ), uncertain=uncertain, pointer_revision=pointer_revision,
            selected_scope=binding.scope,
        )

