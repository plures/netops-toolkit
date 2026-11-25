"""Constructor-supplied pinned metadata compiled into the existing setup host."""

from __future__ import annotations

import sys
from dataclasses import dataclass, replace
from pathlib import Path
from uuid import uuid4

from netops.ansible import contracts as c
from netops.ansible.artifacts import ProtectedRoot
from netops.ansible.policy.authorization import AuthorizationError
from netops.ansible.settings import ObservationSettings

from ._assets import LockedAsset, _approved
from ._bootstrap import _BootstrapContribution
from ._family_bridge import _FamilyPlanning
from ._family_lock import _FamilyLock
from ._guided import _Diagnosis, _existing_python, _Need, _needs, _Selection
from ._installation import _hash, _InstallationSpec
from ._lock_layout import _LayoutUnavailable, _LockLayout, _selected_toolkit_roots
from ._managed import ManagedArchive
from ._owned_source import _OwnedSource
from ._publisher_acquisition import _PublisherAcquisition
from .adapters import _version_matches
from .service import DependencyRegistry

__all__: tuple[str, ...] = ()


@dataclass(frozen=True)
class _CachedArchive:
    archive: ManagedArchive
    cache_path: Path

    def __post_init__(self) -> None:
        if type(self.archive) is not ManagedArchive or not self.cache_path.is_absolute():
            raise c.ContractError()
        self.archive.__post_init__()
        if type(self.archive.asset) is not LockedAsset:
            raise c.ContractError()


@dataclass(frozen=True)
class _Candidate:
    document: dict
    owned_source: _OwnedSource | None = None
    family_lock: _FamilyLock | None = None
    acquisition: _PublisherAcquisition | None = None
    bootstrap: _BootstrapContribution | None = None


@dataclass(frozen=True)
class _Metadata:
    """Trusted composition only; no CLI flag, JSON loader or URL confers this role.

    Empty packaged pins are a factual absence, not permission to resolve online.
    A host may supply typed existing publisher locks/cache or the already accepted
    private producer. Neither path adds a source family or broadens that producer.
    """

    installation: _InstallationSpec | None = None
    archives: tuple[_CachedArchive, ...] = ()
    owned_source: _OwnedSource | None = None
    generation_id: str | None = None
    consuming_root: ProtectedRoot | None = None
    family_planning: _FamilyPlanning | None = None
    observation: ObservationSettings | None = None
    layout: _LockLayout | None = None
    bootstrap: _BootstrapContribution | None = None

    def __post_init__(self) -> None:
        if self.bootstrap is not None:
            if (
                type(self.bootstrap) is not _BootstrapContribution
                or self.owned_source is not None or self.family_planning is None
                or self.layout is None or self.generation_id == self.bootstrap.generation_id
            ):
                raise c.ContractError()
            self.bootstrap.__post_init__()
        if self.layout is not None and (
            type(self.layout) is not _LockLayout or self.family_planning is None
            or self.installation is not None or self.archives or self.owned_source is not None
        ):
            raise c.ContractError()
        if self.layout is not None:
            self.layout.__post_init__()
        if self.observation is not None:
            if type(self.observation) is not ObservationSettings:
                raise c.ContractError()
            self.observation.__post_init__()
        if self.family_planning is not None:
            if type(self.family_planning) is not _FamilyPlanning or self.owned_source is not None:
                raise c.ContractError()
            self.family_planning.__post_init__()
        if self.installation is not None:
            if type(self.installation) is not _InstallationSpec:
                raise c.ContractError()
            self.installation.__post_init__()
        if type(self.archives) is not tuple or len(self.archives) > 128:
            raise c.ContractError()
        for item in self.archives:
            if type(item) is not _CachedArchive:
                raise c.ContractError()
            item.__post_init__()
        if self.installation is None or self.installation.controller_installation is None:
            c.unique(tuple(item.archive.asset.dependency for item in self.archives))
        else:
            c.unique(tuple(c.digest(item.archive.asset) for item in self.archives))
        if self.owned_source is not None and (
            type(self.owned_source) is not _OwnedSource or self.archives
            or self.generation_id is None
        ):
            raise c.ContractError()
        if self.generation_id is not None:
            c.uuid_text(self.generation_id)
        if self.consuming_root is not None and (
            type(self.consuming_root) is not ProtectedRoot or self.owned_source is None
            or self.owned_source._issued._result.receipt["consuming_root"] != (
                self.consuming_root.path, str(self.consuming_root.device),
                str(self.consuming_root.inode),
            )
        ):
            raise c.ContractError()

    def resolve(
        self, diagnosis: _Diagnosis, selection: _Selection, scope: c.InstallScope,
        root: Path, registry: DependencyRegistry,
    ) -> tuple[_Candidate | None, tuple[_Need, ...]]:
        from . import _setup

        self.__post_init__()
        needs = _needs(diagnosis, selection)
        from ._family_source import _NEEDS_CONTRIBUTIONS, _requires_contributions

        generation = self.generation_id or str(uuid4())
        archives = self.archives
        spec = self.installation
        family_lock = None
        family_source = None
        source_deadline = _setup.time.monotonic() + 60.0
        if self.bootstrap is not None:
            self.bootstrap.guard(
                root, registry, _setup._Clock(), _setup._Cancel(), source_deadline,
            )
        if self.family_planning is not None:
            planning = self.family_planning
            additional: tuple = ()
            if self.layout is not None:
                controller = any(
                    component.context == "controller" for component in diagnosis.components
                )
                contexts = _setup._contexts(
                    root, generation, controller, separate_controller=controller,
                )
                planning = replace(planning, targets=tuple(
                    replace(target, context_digest=contexts[target.context].digest)
                    if target.context in contexts else target for target in planning.targets
                    if target.context in {
                        component.context for component in diagnosis.components
                    } or target.context == "native"
                ))
                try:
                    self.layout.preflight(planning.targets)
                except _LayoutUnavailable as failure:
                    selected_targets = {target.context: target for target in planning.targets}
                    return None, tuple(
                        replace(
                            need, reason=failure.reason, fields=failure.fields,
                            platforms=(selected_targets[component.context].platform,),
                        ) if component.context == failure.context
                        and component.context in selected_targets else need
                        for component, need in zip(diagnosis.components, needs)
                    )
                additional = _selected_toolkit_roots(
                    tuple(registry.entry(component.dependency)
                          for component in diagnosis.components), registry,
                )
            family_lock, family_needs, family_source = planning._resolve(
                diagnosis, selection, registry, _setup._Clock(), _setup._Cancel(),
                source_deadline, additional_roots=additional,
            )
            if family_lock is None:
                return None, family_needs
            if _requires_contributions(scope) and self.bootstrap is None:
                return None, tuple(replace(
                    need, reason=_NEEDS_CONTRIBUTIONS,
                    fields=("original-qualified-native-producer", "each-selected-subset-issuer"),
                ) for need in needs)
            if self.bootstrap is not None and family_source is None:
                return None, tuple(replace(
                    need, reason=_NEEDS_CONTRIBUTIONS,
                    fields=("actual-closed-publisher-clients", "each-selected-subset-issuer"),
                ) for need in needs)
            from ._family_integration import _supported

            if not _supported(family_lock):
                return None, tuple(replace(
                    need, reason="concrete-platform-provider-required",
                    fields=("typed-platform-operation", "separate-current-category-consent"),
                ) for need in needs)
        expected = tuple(component.dependency for component in diagnosis.components)
        supplied = tuple(item.archive.asset.dependency for item in archives)
        # Reject unknown, excess, substituted and wrong-family assets even when
        # another component is declined. No provider dispatch precedes this.
        for item in archives:
            if family_lock is not None:
                continue
            asset = item.archive.asset
            if type(asset) is not LockedAsset:
                raise c.ContractError()
            entry = registry.entry(asset.dependency)
            if entry.id not in expected:
                raise c.ContractError()
            _approved(entry, asset)
        choices = dict(selection.components)
        if set(choices) != set(expected) or any(
            need.reason in ("component-declined", "prerequisite-declined",
                            "compatible-reuse-evidence-required", "controller-context-required",
                            "fresh-consuming-observation-required")
            for need in needs
        ):
            return None, needs
        if self.layout is not None and family_lock is not None:
            try:
                compiled = self.layout.compile(
                    family_lock, root, _setup._Clock(), _setup._Cancel(),
                    source_deadline,
                )
            except _LayoutUnavailable as failure:
                return None, tuple(replace(
                    need, reason=failure.reason, fields=failure.fields,
                ) for need in needs)
            spec = compiled.installation
            archives = tuple(
                _CachedArchive(archive, path)
                for archive, path in zip(compiled.archives, compiled.cache_paths)
            )
        if spec is None:
            return None, needs
        from ._installation import _predictable_path_limit

        if _predictable_path_limit(
            str(root), generation, spec,
            tuple(member.path for item in archives for member in item.archive.members),
        ):
            return None, tuple(replace(
                need, reason="shorter-user-owned-root-required",
                fields=("explicit-shorter-root-choice", "fresh-plan-and-consent"),
            ) for need in needs)
        native = next(
            (component.observation for component in diagnosis.components
             if component.dependency == "native-python"), None,
        )
        if (
            spec.python not in (sys.executable, _existing_python())
            or spec.platform != sys.platform
            or native is None or native.status != "available" or native.version is None
            or not _version_matches(native.version, "==" + spec.python_version)
        ):
            return None, tuple(replace(
                need, reason="compatible-existing-interpreter-required",
                fields=("interpreter", "version", "platform", "sha256"),
            ) for need in needs)
        try:
            interpreter_digest = _hash(
                Path(spec.python), _setup._Clock(), _setup._Cancel(), _setup.time.monotonic() + 5.0,
            )
        except (OSError, c.ContractError, TimeoutError):
            interpreter_digest = None
        if interpreter_digest != spec.python_digest:
            return None, tuple(replace(
                need, reason="existing-interpreter-pin-mismatch",
                fields=("existing-interpreter-sha256",),
            ) for need in needs)
        if self.owned_source is not None:
            document = _setup._owned_document(self.owned_source, spec, generation)
            if _setup._scope(document["scope"]) != scope:
                return None, tuple(replace(
                    need, reason="producer-selected-scope-unsupported",
                    fields=("qualified-full-scope-provider",),
                ) for need in needs)
            manifest, _ = _setup._manifest(document, root, registry, self.owned_source)
            self.owned_source.guard(
                manifest, _setup._Clock(), _setup._Cancel(), _setup.time.monotonic() + 60.0,
            )
            return _Candidate(document, self.owned_source), ()
        if family_lock is None and supplied != expected:
            provided = set(supplied)
            return None, tuple(
                replace(need, reason="ordered-selected-closure-required")
                for need in needs if need.dependency not in provided
            ) or tuple(replace(need, reason="ordered-selected-closure-required") for need in needs)
        from ._family_lock import _contributions

        try:
            contributions = () if family_lock is None else _contributions(family_lock.releases)
        except c.ContractError:
            return None, tuple(replace(
                need, reason="conflicting-locked-member-layout",
                fields=("identical-archive-member-manifest",),
            ) for need in needs)
        if family_lock is not None and tuple(
            item.archive.asset for item in archives
        ) != tuple(release.artifact for release in contributions):
            return None, tuple(replace(
                need, reason="complete-locked-acquisition-layout-required",
                fields=("all-locked-contributions", "owned-consuming-installation-layout"),
            ) for need in needs)
        document = {
            "schema": "netops-local-setup-v1", "generation_id": generation,
            "scope": c.wire(scope), "installation": c.wire(spec),
            "archives": [{
                "asset": c.wire(item.archive.asset), "archive": item.archive.archive,
                "members": c.wire(item.archive.members), "cache_path": str(item.cache_path),
            } for item in archives],
        }
        if self.bootstrap is not None:
            document["bootstrap_digest"] = self.bootstrap.digest
        if family_lock is not None:
            document["family_lock"] = c.wire(family_lock)
        manifest, _ = _setup._manifest(document, root, registry)
        if family_lock is not None:
            from ._family_integration import _validate_archives

            try:
                _validate_archives(family_lock, manifest, registry, expected)
            except AuthorizationError:
                return None, tuple(replace(
                    need, reason="compatible-locked-installation-layout-required",
                    fields=("actual-consuming-context-binding", "all-locked-contributions",
                            "owned-consuming-installation-layout"),
                ) for need in needs)
        # Same actual archive/PEP508/tag/collection checks as the admitted path,
        # using the trusted review interpreter, not descriptor-provided argv.
        missing_cache = False
        try:
            _setup._cached_closure(manifest, document)
        except FileNotFoundError:
            if self.layout is None:
                return None, tuple(replace(
                    need, reason="verified-offline-cache-required", fields=("verified-cache-member",),
                ) for need in needs)
            missing_cache = True
        except (OSError, c.ContractError):
            return None, tuple(replace(
                need, reason="verified-offline-cache-required", fields=("verified-cache-member",),
            ) for need in needs)
        bootstrap = self.bootstrap
        if bootstrap is not None:
            if family_source is None or bootstrap.family is not None or self.layout is None:
                raise AuthorizationError()
            contribution = family_source.bind(
                manifest, tuple(item.cache_path for item in archives), bootstrap, self.layout,
                _setup._Clock(), _setup._Cancel(), source_deadline,
            )
            bootstrap = replace(bootstrap, family=contribution)
            document["bootstrap_digest"] = bootstrap.digest
            manifest, _ = _setup._manifest(document, root, registry)
            bootstrap.guard(root, registry, _setup._Clock(), _setup._Cancel(), source_deadline)
        acquisition = None
        if self.layout is not None and missing_cache:
            if family_lock is None:
                raise c.ContractError()
            assets: list[LockedAsset] = []
            for item in archives:
                asset = item.archive.asset
                if type(asset) is not LockedAsset:
                    raise c.ContractError()
                assets.append(asset)
            acquisition = _PublisherAcquisition(
                tuple(assets), tuple(item.cache_path for item in archives),
                c.digest(c.public_object(document)),
                min(item.expires_at for item in family_lock.observations),
            )
        return _Candidate(
            document, family_lock=family_lock, acquisition=acquisition,
            bootstrap=bootstrap,
        ), ()
