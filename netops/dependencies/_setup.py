"""Trusted local source bootstrap; private receipts never come from request JSON.

Local descriptors supply pinned assets, not grants or qualification. No missing
production pin is synthesized. The same service/reducer/broker owns provision.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import stat
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import cast
from uuid import uuid4

from netops.ansible import artifact_platform as storage
from netops.ansible import contracts as c
from netops.ansible.artifacts import (
    ArtifactError,
    LocalProtectedFilesystem,
    OwnedRecord,
    OwnedState,
    ProtectedRoot,
    _read_file,
    _root,
)
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AdmissionStatePort,
    AuthorizationBroker,
    AuthorizationError,
    TrustedConsentAdapter,
    TrustedLifecycleConsentAdapter,
)
from netops.ansible.policy.engine import LocalReferencePolicyEngine
from netops.ansible.policy.loader import load_policy
from netops.ansible.settings import ObservationSettings

from ._assets import AssetResponse, LockedAsset
from ._bootstrap import _BootstrapContribution
from ._composition import ManagedLifecycleState
from ._context_facts import _host_architecture
from ._guided import (
    _choose,
    _diagnose,
    _existing_contexts,
    _needs,
    _report,
    _resume_selection,
)
from ._guided_metadata import _Candidate, _Metadata
from ._installation import (
    _Collection,
    _InstallationSpec,
    _Library,
    _NativeFile,
    _Tool,
    _Wheel,
)
from ._managed import (
    ManagedArchive,
    ManagedGenerationManifest,
    ManagedMember,
    ProtectedGenerationFiles,
)
from ._owned_source import _OwnedBuildAsset, _OwnedSource
from ._publisher_acquisition import _PublisherAcquisition
from .adapters import LocalDependencyAdapter
from .runs import OwnedGenerationRuns
from .service import (
    ADAPTERS,
    ConsumingContext,
    DependencyRegistry,
    DependencyService,
    RegistryError,
    _packaged_identity,
)

__all__: tuple[str, ...] = ()
_CONFIG = "setup-host"
_ROOT = "setup-generations"
_CONTROL = "setup-control"
_LIMIT = 1024 * 1024


class _UnsupportedMigration(c.ContractError):
    """A protected known setup record has no frozen predecessor transform."""


class _Clock:
    def monotonic(self) -> float:
        return time.monotonic()

    def utc_now(self) -> datetime:
        return datetime.now(timezone.utc)


class _Cancel:
    def __init__(self) -> None:
        self.event = threading.Event()

    def is_cancelled(self) -> bool:
        return self.event.is_set()

    def wait(self, timeout: float) -> bool:
        return self.event.wait(timeout)


class _Events:
    def emit(self, event: c.SafeEvent) -> None:
        # Lifecycle helpers already own paired safe structured observations.
        pass


class _Review:
    def __init__(
        self, ask: Callable[[str], str], display: Callable[[str], None],
        *, observation: ObservationSettings | None = None,
    ) -> None:
        self.ask, self.display = ask, display
        if observation is not None and type(observation) is not ObservationSettings:
            raise c.ContractError()
        self.observation = observation or ObservationSettings()
        self.observation.__post_init__()

    def confirm_lifecycle(self, binding: lc.LifecycleBinding, deadline: float) -> bool:
        self.display(
            f"{binding.kind}: root={binding.root.resource_id}; "
            f"candidate={binding.generation.generation_id}; "
            f"expected pointer={binding.expected_pointer}; "
            f"deadline remaining={max(0, int(deadline - time.monotonic()))}s"
        )
        budget = f"observation max-age={self.observation.max_age_seconds}s"
        self.display(
            f"Resource budget: {budget}; functional source/tree probe window=60s; "
            "retained CAS guards expire with this observation or the original lifecycle "
            "grant, whichever is earlier."
        )
        steps = binding.content["steps"]
        if type(steps) is not tuple:
            raise c.ContractError()
        for effect, descriptor in zip(binding.effects, steps):
            self.display(f"  {effect.kind}: {c.canonical_bytes(descriptor).decode('utf-8')}")
        self.display("Inventory, vault, backups, settings and unknown files are not selected.")
        return self.ask(
            f"{budget}. Type '{binding.kind} {binding.plan_digest}' to consent: ",
        ).strip() == (
            binding.kind + " " + binding.plan_digest
        ) and time.monotonic() < deadline

    def confirm(
        self, plan: c.OperationPlan, binding: c.PlanBinding, deadline: float,
    ) -> bool:
        # This source setup adapter cannot consent to device operations.
        return False

    def confirm_consequential(
        self, binding: lc.LifecycleBinding, requirement: lc.ConsequentialRequirement,
        deadline: float,
    ) -> bool:
        self.display(f"Separate {requirement.category} grant: {requirement.occurrence_ids}")
        return self.ask(f"Type 'grant {requirement.category}' or decline: ").strip() == (
            "grant " + requirement.category
        ) and time.monotonic() < deadline

    def confirm_scope(
        self, binding: lc.LifecycleBinding, scope: str,
        occurrence_ids: tuple[str, ...], deadline: float,
    ) -> bool:
        self.display(
            f"Separate exact {scope} review: plan={binding.plan_digest}; "
            f"occurrences={occurrence_ids}. This cannot replace the broker's category grant."
        )
        return self.ask(f"Type 'review {scope} {binding.plan_digest}' or decline: ").strip() == (
            f"review {scope} {binding.plan_digest}"
        ) and time.monotonic() < deadline


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for name, value in pairs:
        if name in result:
            raise c.ContractError()
        result[name] = value
    return result


def _document(path: Path) -> dict:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > _LIMIT:
        raise c.ContractError()
    value = json.loads(path.read_bytes(), object_pairs_hook=_pairs)
    if type(value) is not dict:
        raise c.ContractError()
    return value


def _scope(value: dict) -> c.InstallScope:
    if set(value) != {"native_capabilities", "companions", "full_toolkit", "enhanced"}:
        raise c.ContractError()
    return c.InstallScope(
        native_capabilities=tuple(value["native_capabilities"]), companions=tuple(value["companions"]),
        full_toolkit=value["full_toolkit"], enhanced=value["enhanced"],
    )


def _installation(value: dict) -> _InstallationSpec:
    if set(value) - {
        "native_files", "tools", "libraries", "controller_installation", "requested_extras",
    } != {
        "python", "python_digest", "python_version", "platform", "wheels", "controller", "collections",
    }:
        raise c.ContractError()
    companion = value.get("controller_installation")
    if companion is not None and (
        type(companion) is not dict or "controller_installation" in companion
    ):
        raise c.ContractError()
    extras = value.get("requested_extras", ())
    if type(extras) not in (list, tuple) or any(
        type(pair) not in (list, tuple) or len(pair) != 2
        or type(pair[1]) not in (list, tuple) for pair in extras
    ):
        raise c.ContractError()
    return _InstallationSpec(
        value["python"], value["python_digest"], value["python_version"], value["platform"],
        tuple(_Wheel(**item) for item in value["wheels"]), value["controller"],
        tuple(_Collection(**item) for item in value["collections"]),
        tuple(_NativeFile(**item) for item in value.get("native_files", ())),
        tuple(_Tool(**item) for item in value.get("tools", ())),
        tuple(_Library(**item) for item in value.get("libraries", ())),
        controller_installation=(
            _installation(value["controller_installation"])
            if companion is not None else None
        ),
        requested_extras=tuple(
            (name, tuple(selected)) for name, selected in extras
        ),
    )


def _contexts(
    root: Path, generation_id: str, controller: bool, *, separate_controller: bool = False,
) -> dict[str, ConsumingContext]:
    target = root / ("installation-" + c.digest(generation_id))
    executable = target / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    paths = os.pathsep.join((str(executable.parent), str(target / "tools")))
    native = ConsumingContext("source-owned-native", sys.platform, _host_architecture(),
                              str(executable), paths, "native")
    result = {"native": native}
    if controller and sys.platform != "win32":
        controller_target = target / "controller" if separate_controller else target
        controller_python = controller_target / "bin/python"
        result["controller"] = replace(
            native, id="source-guided-setup", role="controller",
            python=str(controller_python),
            path=os.pathsep.join((str(controller_python.parent), str(controller_target / "tools"))),
            collection_paths=(str(controller_target / "collections"),),
        )
    return result


def _context(root: Path, registry: DependencyRegistry) -> c.InstallContext:
    return c.InstallContext(c.Context(
        "source-guided-setup", c.digest(str(root)), "owned-local-source",
        c.digest(("no-device-route", str(root))), _packaged_identity(), registry.digest,
        c.digest(("source-setup-v1", str(root))),
    ))


def _manifest(
    value: dict, root: Path, registry: DependencyRegistry,
    owned_source: _OwnedSource | None = None,
) -> tuple[ManagedGenerationManifest, dict[str, ConsumingContext]]:
    if value.get("schema") == "netops-owned-build-v1":
        return _owned_manifest(value, root, registry, owned_source)
    if set(value) - {"family_lock", "bootstrap_digest"} != {"schema", "generation_id", "scope", "installation", "archives"} or (
        value["schema"] != "netops-local-setup-v1"
    ):
        raise c.ContractError()
    c.uuid_text(value["generation_id"])
    installation = _installation(value["installation"])
    if installation.platform != sys.platform:
        raise c.ContractError()
    if installation.controller_installation is not None and "family_lock" not in value:
        raise c.ContractError()
    archives = []
    for item in value["archives"]:
        if set(item) != {"asset", "archive", "members", "cache_path"}:
            raise c.ContractError()
        asset = LockedAsset(**item["asset"])
        archives.append(ManagedArchive(asset, item["archive"], tuple(
            ManagedMember(**member) for member in item["members"]
        )))
        if not Path(item["cache_path"]).is_absolute():
            raise c.ContractError()
    if not archives:
        raise c.ContractError()
    contexts = _contexts(
        root, value["generation_id"],
        installation.controller or installation.controller_installation is not None,
        separate_controller=installation.controller_installation is not None,
    )
    manifest = ManagedGenerationManifest(
        value["generation_id"], archives[0].asset, archives[0].archive,
        tuple(member for archive in archives for member in archive.members),
        _scope(value["scope"]), _context(root, registry),
        tuple(sorted(context.digest for context in contexts.values())),
        archives=tuple(archives), installation=installation,
        bootstrap_digest=value.get("bootstrap_digest"),
    )
    if "family_lock" in value:
        from ._family_codec import _decode_lock
        from ._family_integration import _supported, _validate_archives

        lock = _decode_lock(value["family_lock"])
        selector = _service(
            registry, contexts, _Review(lambda _: "", lambda _: None), None,
        )
        selected = tuple(item.id for item in selector._entries(
            selector._selection(manifest.scope), manifest.scope,
        ))
        _validate_archives(lock, manifest, registry, selected)
        if not _supported(lock):
            raise c.ContractError()
    return manifest, contexts


def _owned_manifest(
    value: dict, root: Path, registry: DependencyRegistry, source: _OwnedSource | None,
) -> tuple[ManagedGenerationManifest, dict[str, ConsumingContext]]:
    """Decode facts only when trusted composition already supplies the producer."""
    if type(source) is not _OwnedSource or set(value) != {
        "schema", "generation_id", "scope", "installation", "asset", "members",
    }:
        raise c.ContractError()
    c.uuid_text(value["generation_id"])
    asset = _OwnedBuildAsset(**value["asset"])
    if asset != source.asset:
        raise AuthorizationError()
    installation = _installation(value["installation"])
    contexts = _contexts(root, value["generation_id"], installation.controller)
    manifest = ManagedGenerationManifest(
        value["generation_id"], asset, "zip",
        tuple(ManagedMember(**member) for member in value["members"]),
        _scope(value["scope"]), _context(root, registry),
        tuple(sorted(context.digest for context in contexts.values())),
        installation=installation,
    )
    return manifest, contexts


def _owned_document(
    source: _OwnedSource, installation: _InstallationSpec, generation_id: str,
) -> dict:
    """Create the private host's durable factual descriptor, never a public trust switch."""
    if type(source) is not _OwnedSource or type(installation) is not _InstallationSpec:
        raise c.ContractError()
    return cast(dict, json.loads(c.canonical_bytes(c.public_object({
        "schema": "netops-owned-build-v1", "generation_id": generation_id,
        "scope": c.wire(c.InstallScope(
            native_capabilities=("native.stdlib",), companions=(), full_toolkit=False,
            enhanced=False,
        )),
        "installation": c.wire(installation), "asset": c.wire(source.asset),
        "members": source._issued._result.receipt["members"],
    }))))


class _OfflineAssets:
    def __init__(self, documents: tuple[dict, ...]) -> None:
        self.sources: dict[str, tuple[LockedAsset, Path]] = {}
        for document in documents:
            for item in document["archives"]:
                asset = LockedAsset(**item["asset"])
                source = (asset, Path(item["cache_path"]))
                if asset.url in self.sources and self.sources[asset.url] != source:
                    raise c.ContractError()
                self.sources[asset.url] = source

    def read(self, url: str, timeout: float, limit: int) -> AssetResponse:
        from ._family_lock import _trace

        _trace("compiler-cache-read", "asset", "attempt")
        try:
            response = self._read(url, timeout, limit)
        except BaseException:
            _trace("compiler-cache-read", "asset", "raised")
            raise
        _trace("compiler-cache-read", "asset", "returned")
        return response

    def _read(self, url: str, timeout: float, limit: int) -> AssetResponse:
        # The original admitted download path rechecks live consent, descriptor
        # family, exact digest and byte count. This transport never uses network.
        if url not in self.sources or timeout <= 0:
            raise c.ContractError()
        asset, path = self.sources[url]
        for parent in path.parents:
            parent_info = parent.lstat()
            if (
                not stat.S_ISDIR(parent_info.st_mode) or parent.is_symlink()
                or getattr(parent_info, "st_file_attributes", 0) & 0x400
            ):
                raise c.ContractError()
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_size != asset.size or info.st_size > limit
        ):
            raise c.ContractError()
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != asset.sha256:
            raise c.ContractError()
        return AssetResponse(url, content)


def _cached_closure(manifest: ManagedGenerationManifest, document: dict) -> None:
    """Read verified local metadata before consent/acquisition, never launch a descriptor program."""
    from ._installation import _WHEEL_METADATA, _normalize, _validate_collection
    from ._installation_process import _run
    from ._managed import unpack

    spec = manifest.installation
    if spec is None:
        raise c.ContractError()
    clock, cancel = _Clock(), _Cancel()
    deadline = c.checked_deadline(clock.monotonic(), 60.0)
    transport = _OfflineAssets((document,))
    sources: dict[str, dict] = {}
    specifications = (
        (spec, spec.controller_installation)
        if spec.controller_installation is not None else (spec,)
    )
    collections = {
        collection.member: (collection, consuming)
        for consuming in specifications if consuming is not None
        for collection in consuming.collections
    }
    for archive, raw in zip(manifest.archives, document["archives"]):
        if type(archive.asset) is not LockedAsset:
            raise c.ContractError()
        response = transport.read(archive.asset.url, deadline - clock.monotonic(),
                                  archive.asset.size + 1)
        files = unpack(replace(
            manifest, asset=archive.asset, archive=archive.archive, members=archive.members,
            archives=(), installation=None,
        ), response.content, clock, cancel, deadline)
        for file in files:
            if file.member.path in collections:
                collection, consuming = collections[file.member.path]
                _validate_collection(file.content, collection, consuming,
                                     clock, cancel, deadline)
            sources[file.member.path] = (
                {"path": raw["cache_path"]} if archive.archive == "file" else {
                    "path": raw["cache_path"], "archive": archive.archive,
                    "source_digest": archive.asset.sha256, "source_size": archive.asset.size,
                }
            )
    # Use the already running trusted review host, NOT the supplied spec.python.
    # The profile is descriptive only; admitted installation later repeats
    # metadata/tag checks with the genuinely selected pinned interpreter.
    for consuming in specifications:
        if consuming is None:
            raise c.ContractError()
        wheels = [{
            **sources[wheel.member], "member": wheel.member, "distribution": wheel.distribution,
            "version": wheel.version, "digest": wheel.digest,
            "extras": dict(consuming.requested_extras).get(_normalize(wheel.distribution), ()),
        } for wheel in consuming.wheels]
        _run((sys.executable, "-I", "-B", "-c", _WHEEL_METADATA, json.dumps(wheels),
              json.dumps({
                  "python_version": consuming.python_version, "platform": consuming.platform,
              })), Path(document["archives"][0]["cache_path"]).parent, clock, cancel, deadline)


def _display_plan(plan: object, display: Callable[[str], None]) -> None:
    from .service import InstallPlan

    if type(plan) is not InstallPlan:
        raise c.ContractError()
    display(f"Selected registry {plan.registry_revision}/{plan.registry_digest}:")
    for step in plan.steps:
        display(
            f"  {step.dependency} ({step.context}): {step.disposition}/{step.reason}; "
            f"source={step.source}; destination={step.destination}; "
            f"effects={','.join(step.effects)}; separate grants={','.join(step.separate_grants)}"
        )
    display("A full catalog is not a grant or a platform qualification.")


def _service(
    registry: DependencyRegistry, contexts: dict[str, ConsumingContext],
    review: _Review, state: ManagedLifecycleState | None,
) -> DependencyService:
    from importlib import resources

    packaged = resources.files("netops.ansible.policy")
    policy = LocalReferencePolicyEngine(load_policy(
        packaged.joinpath("ansible_molecule.px").read_bytes(),
        packaged.joinpath("ansible_molecule.contracts.px").read_bytes(),
        packaged.joinpath("bundle.json").read_bytes(), _packaged_identity(),
    ))
    broker = AuthorizationBroker(
        cast(AdmissionStatePort, None), TrustedConsentAdapter(review), lifecycle_state=state,
        lifecycle_consent=TrustedLifecycleConsentAdapter(review),
    )
    adapter = LocalDependencyAdapter(contexts)
    return DependencyService(
        registry, dict.fromkeys(ADAPTERS, adapter),
        cast(ManagedLifecycleState, state), policy, broker, _Clock(), _Events(),
    )


def _owned(root_path: Path, create: bool) -> ProtectedRoot:
    if (
        not root_path.is_absolute() or ".." in root_path.parts
        or root_path == Path(root_path.anchor) or root_path == Path.home()
    ):
        raise c.ContractError()
    if create:
        if os.name == "nt":
            native = storage.windows()
            with native._security() as security:
                if not native.kernel.CreateDirectoryW(str(root_path), ctypes.byref(security)):
                    raise native._error()
        else:
            root_path.mkdir(mode=0o700)
    return LocalProtectedFilesystem().validate(c.OutputIntent(("json",), str(root_path)))


def _load_host(root: ProtectedRoot) -> tuple[OwnedState, tuple[dict, ...]]:
    # A previously protected root still is not adopted. Its exact owned setup
    # record must already exist and validate before any write or process launch.
    with _root(root) as parent:
        record = OwnedRecord.from_bytes(_read_file(parent, OwnedState._filename(_CONFIG)))
    if (
        record.resource_id == _CONFIG and record.kind == "checkpoint"
        and record.payload.get("schema") != "netops-source-host-v1"
    ):
        raise _UnsupportedMigration()
    if record.resource_id != _CONFIG or record.kind != "checkpoint" or (
        record.policy_identity != _packaged_identity()
        or set(record.payload) - {"registration_pending"} != {"schema", "documents"}
        or record.payload["schema"] != "netops-source-host-v1"
    ):
        raise c.ContractError()
    state = OwnedState(root, record.ownership_token)
    state.read(_CONFIG)
    documents = json.loads(c.canonical_bytes(record.payload["documents"]))
    if (
        type(documents) is not list or not 1 <= len(documents) <= 256
        or any(type(document) is not dict for document in documents)
    ):
        raise c.ContractError()
    return state, tuple(documents)


def _registered_selection(
    root: ProtectedRoot, state: OwnedState, documents: tuple[dict, ...], generation_id: str | None,
    action: str, registry: DependencyRegistry, owned_source: _OwnedSource | None = None,
) -> dict:
    """Select only an exact durable owned descriptor, not an external reconstruction."""
    manifests = tuple(_manifest(document, Path(root.path), registry, owned_source)[0]
                      for document in documents)
    c.unique(tuple(manifest.generation_id for manifest in manifests))
    if generation_id is not None:
        c.uuid_text(generation_id)
    elif action == "restore":
        # Restore never guesses a previous generation or reverses a CAS.
        raise c.ContractError()
    elif action == "verify":
        pointer = c.public_object(state.read(_CONTROL).payload["pointer"])
        selected_id = pointer.get("active_generation_id")
        if type(selected_id) is not str:
            raise c.ContractError()
        generation_id = selected_id
        c.uuid_text(generation_id)
    else:
        # The last explicitly registered candidate is the staging/resume/
        # uninstall selection. An active candidate remains protected by the
        # original uninstall planner and its pin/pointer checks.
        generation_id = manifests[-1].generation_id
    selected = tuple(document for document in documents
                     if document["generation_id"] == generation_id)
    if len(selected) != 1:
        raise c.ContractError()
    return selected[0]


def _register(
    root: ProtectedRoot, state: OwnedState, documents: tuple[dict, ...], selected: dict,
    registry: DependencyRegistry, review: _Review, owned_source: _OwnedSource | None = None,
) -> tuple[dict, ...]:
    """Review descriptor registration separately; never replace the active pointer."""
    config, facts, control = (state.read(resource) for resource in (_CONFIG, _ROOT, _CONTROL))
    manifest, _ = _manifest(selected, Path(root.path), registry, owned_source)
    selected_digest = c.digest(manifest)
    pending = config.payload.get("registration_pending")
    if pending not in (None, selected_digest):
        raise c.ContractError()
    new_documents = documents if selected in documents else (*documents, selected)
    if any(doc["generation_id"] == selected["generation_id"] and doc != selected for doc in documents):
        raise c.ContractError()
    manifests = tuple(c.wire(_manifest(doc, Path(root.path), registry, owned_source)[0])
                      for doc in new_documents)
    retained_manifest = c.public_object(facts.payload["root_manifest"])
    expected_data: dict[str, object] = {
        **dict(retained_manifest), "registered_manifests": manifests,
    }
    new_family_locks = tuple(
        (doc["generation_id"], doc["family_lock"])
        for doc in new_documents if "family_lock" in doc
    )
    if new_family_locks:
        expected_data["family_locks"] = new_family_locks
    expected = c.public_object(expected_data)
    old_manifests = tuple(c.wire(_manifest(doc, Path(root.path), registry, owned_source)[0])
                          for doc in new_documents if doc != selected)
    previous_data = {**expected_data, "registered_manifests": old_manifests}
    old_family_locks = tuple(
        (doc["generation_id"], doc["family_lock"])
        for doc in new_documents if doc != selected and "family_lock" in doc
    )
    if old_family_locks:
        previous_data["family_locks"] = old_family_locks
    else:
        previous_data.pop("family_locks", None)
    previous = c.public_object(previous_data)
    if facts.payload["root_manifest"] not in (previous, expected):
        raise c.ContractError()
    binding = c.digest((selected_digest, config.revision, facts.revision, control.revision,
                        control.payload["pointer"], c.digest(config.payload)))
    review.display(
        f"Register exact candidate {manifest.generation_id}/{selected_digest}. "
        f"Preserve active pointer {control.payload['pointer']}; retain every prior generation. "
        "Registration updates owned metadata only; install and activation each require later private consent."
    )
    if review.ask(f"Type 'register {binding}' to consent: ").strip() != "register " + binding:
        raise AuthorizationError()
    with state.lock((_ROOT,), 0.0):
        if tuple(state.read(resource) for resource in (_CONFIG, _ROOT, _CONTROL)) != (config, facts, control):
            raise AuthorizationError()
        if pending is None:
            config = state.compare_replace(_CONFIG, config.revision, replace(
                config, revision=config.revision + 1, payload=c.public_object({
                    "schema": "netops-source-host-v1", "documents": new_documents,
                    "registration_pending": selected_digest,
                }),
            ))
        if facts.payload["root_manifest"] != expected:
            state.compare_replace(_ROOT, facts.revision, replace(
                facts, revision=facts.revision + 1, payload=c.public_object({
                    **dict(facts.payload), "root_manifest": expected,
                }),
            ))
        _register_family_ledgers(
            state, new_documents, previous, expected, selected["generation_id"],
        )
        runs = OwnedGenerationRuns(
            state, _ROOT, _CONTROL, state._owner, _packaged_identity(),
            tuple(lc.GenerationBinding(
                item.generation_id, 0, item.content_digest, c.digest(item),
            ) for item in (_manifest(doc, Path(root.path), registry, owned_source)[0]
                           for doc in new_documents)),
            selected["generation_id"],
        )
        runs.initialize()
        # A fresh candidate cannot inherit the old candidate's verification
        # or installation identity. Its actual active pointer is unchanged.
        state.compare_replace(_CONTROL, control.revision, replace(
            control, revision=control.revision + 1, payload=c.public_object({
                **dict(control.payload), "verification": None, "installation_id": None,
            }),
        ))
        state.compare_replace(_CONFIG, config.revision, replace(
            config, revision=config.revision + 1, payload=c.public_object({
                "schema": "netops-source-host-v1", "documents": new_documents,
                "registration_pending": None,
            }),
        ))
    return new_documents


def _register_family_ledgers(
    state: OwnedState, documents: tuple[dict, ...],
    previous: c.FrozenObject, following: c.FrozenObject, selected_id: str,
) -> None:
    """Rebind current owned heads under registration consent; history is untouched."""
    from ._family_codec import _decode_lock

    identity = _packaged_identity()
    before = lc.OwnedRootBinding(_ROOT, c.digest(previous))
    after = lc.OwnedRootBinding(_ROOT, c.digest(following))
    for document in documents:
        if "family_lock" not in document:
            continue
        generation_id = c.text(document["generation_id"])
        lock = _decode_lock(document["family_lock"])
        resource = "family-ledger-" + c.digest(generation_id)
        initial = OwnedRecord(
            resource, "checkpoint", 0, 0, state._owner,
            identity.bundle_sha256, identity.reducer_version, c.public_object({
                "schema": "netops-family-resources-v1", "root": c.wire(after),
                "lock_digest": lock.digest, "resources": (), "pending": (),
            }), identity,
        )
        if generation_id == selected_id:
            try:
                state.compare_replace(resource, 0, initial)
                continue
            except ArtifactError as exc:
                if exc.error.reason != c.ReasonCode.CONSENT_STALE or exc.cleanup_errors:
                    raise
        record = state.read(resource)
        payload = record.payload
        if (
            record.kind != "checkpoint" or record.ownership_token != state._owner
            or record.policy_identity != identity
            or set(payload) != {"schema", "root", "lock_digest", "resources", "pending"}
            or payload["schema"] != "netops-family-resources-v1"
            or payload["lock_digest"] != lock.digest
            or payload["root"] not in (c.public_object(c.wire(before)),
                                       c.public_object(c.wire(after)))
            or type(payload["resources"]) is not tuple or payload["pending"] != ()
        ):
            raise AuthorizationError()
        if payload["root"] != initial.payload["root"]:
            state.compare_replace(resource, record.revision, replace(
                record, revision=record.revision + 1,
                payload=c.public_object({**dict(payload), "root": c.wire(after)}),
            ))


def _seed(
    root: ProtectedRoot, documents: tuple[dict, ...], registry: DependencyRegistry,
    *, owned_source: _OwnedSource | None = None,
    observation: ObservationSettings | None = None,
) -> OwnedState:
    if observation is not None and type(observation) is not ObservationSettings:
        raise c.ContractError()
    if observation is not None:
        observation.__post_init__()
    state = OwnedState(root, hashlib.sha256(os.urandom(32)).hexdigest())
    identity = _packaged_identity()
    root_manifest: dict[str, object] = {
        "control_resource": _CONTROL,
        "registered_manifests": tuple(c.wire(_manifest(doc, Path(root.path), registry, owned_source)[0])
                                      for doc in documents),
    }
    if observation is not None:
        root_manifest["observation_max_age_seconds"] = observation.max_age_seconds
    family_locks = tuple(
        (doc["generation_id"], doc["family_lock"]) for doc in documents if "family_lock" in doc
    )
    if family_locks:
        root_manifest["family_locks"] = family_locks
    root_binding = lc.OwnedRootBinding(_ROOT, c.digest(c.public_object(root_manifest)))
    payloads = {
        _CONFIG: {"schema": "netops-source-host-v1", "documents": documents},
        _ROOT: {
            "schema": "i02-managed-generations-v1", "generations": (),
            "root_manifest": root_manifest,
        },
        _CONTROL: {
            "schema": "i02-managed-control-v1", "pointer": c.wire(lc.AbsentPointer("absent", 0)),
            "verification": None, "setup_enabled": True, "installation_id": None,
        },
    }
    with state.lock((_ROOT,), 0.0):
        for resource, payload in payloads.items():
            state.compare_replace(resource, 0, OwnedRecord(
                resource, "checkpoint", 0, 0, state._owner,
                identity.bundle_sha256, identity.reducer_version, c.public_object(payload),
                identity,
            ))
        from ._family_codec import _decode_lock

        for generation_id, encoded in family_locks:
            lock = _decode_lock(encoded)
            resource = "family-ledger-" + c.digest(generation_id)
            state.compare_replace(resource, 0, OwnedRecord(
                resource, "checkpoint", 0, 0, state._owner,
                identity.bundle_sha256, identity.reducer_version, c.public_object({
                    "schema": "netops-family-resources-v1", "root": c.wire(root_binding),
                    "lock_digest": lock.digest, "resources": (), "pending": (),
                }), identity,
            ))
        manifests = tuple(_manifest(doc, Path(root.path), registry, owned_source)[0] for doc in documents)
        OwnedGenerationRuns(
            state, _ROOT, _CONTROL, state._owner, identity, tuple(lc.GenerationBinding(
                item.generation_id, 0, item.content_digest, c.digest(item),
            ) for item in manifests), manifests[0].generation_id,
        ).initialize()
    return state


def _host(
    root: ProtectedRoot, state: OwnedState, documents: tuple[dict, ...],
    selected: dict, registry: DependencyRegistry, review: _Review,
    *, owned_source: _OwnedSource | None = None,
    acquisition: _PublisherAcquisition | None = None,
    bootstrap: _BootstrapContribution | None = None,
) -> DependencyService:
    from ._family_codec import _decode_lock
    from ._family_consent import _ScopeReviews
    from ._family_source import _requires_contributions

    if "family_lock" in selected and _requires_contributions(_scope(selected["scope"])) and (
        bootstrap is None or bootstrap.family is None
        or selected.get("bootstrap_digest") != bootstrap.digest
    ):
        raise AuthorizationError()
    manifests = tuple(_manifest(doc, Path(root.path), registry, owned_source)[0] for doc in documents)
    _, contexts = _manifest(selected, Path(root.path), registry, owned_source)
    if acquisition is not None and (
        type(acquisition) is not _PublisherAcquisition or owned_source is not None
        or "family_lock" not in selected
        or acquisition.document_digest != c.digest(c.public_object(selected))
        or acquisition.assets != tuple(
            LockedAsset(**item["asset"]) for item in selected["archives"]
        )
        or acquisition.cache_paths != tuple(
            Path(item["cache_path"]) for item in selected["archives"]
        )
        or acquisition.source_deadline != min(
            item.expires_at for item in _decode_lock(selected["family_lock"]).observations
        )
    ):
        raise AuthorizationError()
    root_manifest = c.public_object(state.read(_ROOT).payload["root_manifest"])
    observation = (
        ObservationSettings(c.counter(root_manifest["observation_max_age_seconds"]))
        if "observation_max_age_seconds" in root_manifest else None
    )
    managed = ManagedLifecycleState(
        state, _ROOT, _CONTROL, state._owner, _packaged_identity(), manifests,
        ProtectedGenerationFiles(root), acquisition if acquisition is not None else _OfflineAssets(tuple(
            doc for doc in documents if doc["schema"] != "netops-owned-build-v1"
        )),
        runs=OwnedGenerationRuns(
            state, _ROOT, _CONTROL, state._owner, _packaged_identity(),
            tuple(lc.GenerationBinding(
                item.generation_id, 0, item.content_digest, c.digest(item),
            ) for item in manifests), selected["generation_id"],
        ),
        owned_source=owned_source,
        observation=observation,
        family_locks=tuple(
            (doc["generation_id"], _decode_lock(doc["family_lock"]))
            for doc in documents if "family_lock" in doc
        ),
        family_reviews=_ScopeReviews(review),
        bootstrap=bootstrap, bootstrap_registry=registry if bootstrap is not None else None,
    )
    return _service(
        registry, contexts, _Review(review.ask, review.display, observation=observation), managed,
    )


def _main(argv: list[str] | None = None, *, _metadata: _Metadata | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review protected user-local toolkit setup.")
    parser.add_argument("action", nargs="?", choices=("plan", "install", "update", "resume",
                                                    "verify", "restore", "uninstall"),
                        default="install")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--plan-file", type=Path)
    parser.add_argument("--capability", action="append", default=[])
    parser.add_argument("--companion", action="append", default=[])
    parser.add_argument("--checkpoint", help="Opaque guided selection returned by this host; never consent.")
    parser.add_argument("--enhanced", action="store_true")
    parser.add_argument("--generation-id")
    parser.add_argument("--installation-id")
    args = parser.parse_args(argv)
    try:
        return _execute(args, _Review(input, print), _metadata)
    except _UnsupportedMigration:
        print(c.canonical_bytes(c.public_object({
            "status": "NeedsInput", "reason": "unsupported-known-root-migration",
            "effects_performed": (), "consent_issued": False,
            "choices": ("preserve-existing-root", "choose-new-empty-user-owned-root-and-replan",
                        "cancel"),
            "migration": "no-supported-predecessor-transform",
        })).decode("utf-8"))
        return 3
    except (c.ContractError, ArtifactError, AuthorizationError, RegistryError, OSError,
            ValueError, KeyError, TypeError, EOFError):
        print(
            "Setup did not complete. Preserve this root and prior generations. "
            "Review exact local pins, platform and owned metadata, then replan with fresh consent."
        )
        return 3
    except KeyboardInterrupt:
        print("Setup cancelled; owned partial state is retained for explicit recovery.")
        return 130


def _first_run(
    args: argparse.Namespace, review: _Review, registry: DependencyRegistry,
    scope: c.InstallScope, context: c.InstallContext, service: DependencyService,
    metadata: _Metadata,
    *, default_metadata: bool = False,
) -> _Candidate | None:
    preview = _diagnose(service, scope, context, probe=False)
    previous = _resume_selection(args.checkpoint, args.root, scope, preview)
    interactive = args.action in ("install", "update")
    diagnosis = _diagnose(service, scope, context, probe=True) if interactive else preview
    selection = _choose(diagnosis, previous, review.ask, review.display) if interactive else previous
    candidate, needs = None, _needs(diagnosis, selection)
    failure = None
    if interactive:
        try:
            if default_metadata:
                from ._default_family import _default_metadata

                metadata = _default_metadata(registry)
            candidate, needs = metadata.resolve(
                diagnosis, selection, scope, args.root, registry,
            )
        except (OSError, ArtifactError, AuthorizationError, c.ContractError) as error:
            from netops.ansible.artifact_cleanup import _storage_detail

            category = (
                "deadline" if isinstance(error, TimeoutError)
                else "cancelled" if isinstance(error, InterruptedError)
                else "authorization" if isinstance(error, AuthorizationError)
                else "io" if isinstance(error, (OSError, ArtifactError)) else "contract"
            )
            # This boundary precedes root reservation, registration and grants.
            # Keep the actual selection resumable, without converting a source
            # failure into a native-only candidate or a new trust assertion.
            failure = c.public_object({
                "stage": "source-precomposition", "category": category,
                "diagnostic": _storage_detail(error),
            })
            needs = tuple(replace(
                need, reason="source-precomposition-" + category,
                fields=("preserve-current-root-and-producer", "inspect-source-diagnostic",
                        "fresh-source-observation-and-plan"),
            ) for need in needs)
    if candidate is None:
        report = _report(args.root, scope, diagnosis, selection, needs, preview=args.action == "plan")
        if metadata.bootstrap is not None:
            report = c.public_object({
                **dict(report),
                "bootstrap": {
                    "digest": metadata.bootstrap.digest,
                    "generation_id": metadata.bootstrap.generation_id,
                    "qualified_scope": c.wire(c.InstallScope(
                        native_capabilities=("native.stdlib",), companions=(),
                        full_toolkit=False, enhanced=False,
                    )),
                    "future_scope_qualified": False,
                    "publisher_acquisition_authorized": False,
                },
            })
        if failure is not None:
            report = c.public_object({**dict(report), "planning_failure": failure})
        review.display(c.canonical_bytes(report).decode("utf-8"))
        review.display(
            "Continue with next_command/checkpoint; it restores selections and rechecks evidence, "
            "not private consent. --plan-file remains optional legacy pinned metadata, "
            "not a first-run prerequisite. No selected component was omitted; "
            "default selection remains full toolkit."
        )
    return candidate


def _initialize_source_root(
    root: ProtectedRoot, selected: dict, registry: DependencyRegistry,
    source: _OwnedSource | None, review: _Review,
    *, observation: ObservationSettings | None = None,
    bootstrap: _BootstrapContribution | None = None,
) -> OwnedState:
    manifest, _ = _manifest(selected, Path(root.path), registry, source)
    binding = c.digest((root.path, str(root.device), str(root.inode), manifest))
    if observation is not None:
        observation.__post_init__()
        binding = c.digest((binding, observation))
    review.display(
        "Initialize only this producer-bound EMPTY protected root with the displayed "
        "candidate's owned setup records. No unknown files or native user data are adopted. "
        "Installation and activation require separate later private reviews."
    )
    review.display(
        "Creation-bound observation max-age="
        f"{(observation or ObservationSettings()).max_age_seconds}s; "
        "functional probe=60s; lifecycle grant=300s. No existing observation or grant is extended."
    )
    deadline = time.monotonic() + 60.0
    if review.ask(f"Type 'initialize {binding}' to consent: ").strip() != "initialize " + binding:
        raise AuthorizationError()
    if bootstrap is not None:
        if manifest.bootstrap_digest != bootstrap.digest or bootstrap.root != root:
            raise AuthorizationError()
        bootstrap.guard(Path(root.path), registry, _Clock(), _Cancel(), deadline)
    elif source is not None:
        source.guard(manifest, _Clock(), _Cancel(), deadline)
    else:
        raise AuthorizationError()
    with _root(root) as parent:
        if storage.names(parent) or time.monotonic() >= deadline:
            raise AuthorizationError()
    return _seed(root, (selected,), registry, owned_source=source, observation=observation)


def _retained_review(
    state: OwnedState, requested: ObservationSettings | None, review: _Review,
) -> _Review | None:
    """Use only the creation-bound setting; never extend retained evidence."""
    manifest = c.public_object(state.read(_ROOT).payload["root_manifest"])
    retained = ObservationSettings(c.counter(manifest.get("observation_max_age_seconds", 60)))
    if requested is not None and requested != retained:
        review.display(c.canonical_bytes(c.public_object({
            "status": "NeedsInput", "reason": "existing-root-observation-setting-retained",
            "current_max_age_seconds": retained.max_age_seconds,
            "effects_performed": (), "consent_issued": False,
            "choices": ("retain-current-setting", "choose-new-empty-root-and-replan", "cancel"),
        })).decode("utf-8"))
        return None
    return _Review(review.ask, review.display, observation=retained)


def _execute(args: argparse.Namespace, review: _Review, metadata: _Metadata | None = None) -> int:
    if (
        not args.root.is_absolute() or ".." in args.root.parts
        or args.root == Path(args.root.anchor) or args.root == Path.home()
    ):
        raise c.ContractError()
    if metadata is not None and type(metadata) is not _Metadata:
        raise c.ContractError()
    default_metadata = metadata is None
    metadata = metadata or _Metadata()
    metadata.__post_init__()
    if metadata.observation is not None:
        review = _Review(review.ask, review.display, observation=metadata.observation)
    initial_root = (
        metadata.bootstrap.root if metadata.bootstrap is not None else metadata.consuming_root
    )
    if initial_root is not None:
        if Path(initial_root.path) != args.root:
            raise c.ContractError()
        with _root(initial_root) as parent:
            if storage.names(parent):
                initial_root = None
    registry = DependencyRegistry.load()
    scope = c.InstallScope(native_capabilities=tuple(args.capability), companions=tuple(args.companion),
                           full_toolkit=not (args.capability or args.companion), enhanced=args.enhanced)
    from ._family_source import _NEEDS_CONTRIBUTIONS, _requires_contributions

    if (
        metadata.family_planning is not None and _requires_contributions(scope)
        and metadata.bootstrap is None and args.action != "plan"
    ):
        review.display(c.canonical_bytes(c.public_object({
            "status": "NeedsInput", "reason": _NEEDS_CONTRIBUTIONS,
            "effects_performed": (), "consent_issued": False,
            "fields": ("original-qualified-native-producer", "each-selected-subset-issuer"),
            "choices": ("compose-current-source-and-replan", "cancel"),
        })).decode("utf-8"))
        return 3
    context = _context(args.root, registry)
    owned_source = metadata.owned_source
    bootstrap = metadata.bootstrap
    if bootstrap is not None:
        bootstrap.guard(
            args.root, registry, _Clock(), _Cancel(), time.monotonic() + 60.0,
        )
    acquisition = None
    selected = _document(args.plan_file) if args.plan_file else None
    if args.checkpoint and args.plan_file:
        raise c.ContractError()
    retained: tuple[ProtectedRoot, OwnedState, tuple[dict, ...]] | None = None
    if selected is None and initial_root is None and (args.root.exists() or args.root.is_symlink()):
        # Read and validate protected durable metadata before choosing a scope,
        # probing a process, asking for consent, or modifying the root.
        root = _owned(args.root, False)
        state, documents = _load_host(root)
        retained_review = _retained_review(state, metadata.observation, review)
        if retained_review is None:
            return 3
        review = retained_review
        if state.read(_CONFIG).payload.get("registration_pending") is not None:
            review.display("Interrupted registration requires update with its exact reviewed descriptor.")
            return 3
        selected = _registered_selection(
            root, state, documents, args.generation_id, args.action, registry, owned_source,
        )
        stored_scope = _scope(selected["scope"])
        if args.action in ("plan", "install", "update") and scope != stored_scope:
            # A previously narrow installation must not silently turn a
            # default FULL request into another narrow request. Describe the
            # requested full closure and require its new exact descriptor.
            selected = None
        else:
            if ((args.capability or args.companion) and scope != stored_scope) or (
                args.enhanced and not stored_scope.enhanced
            ):
                raise c.ContractError()
            scope = stored_scope
            retained = root, state, documents
    if selected is not None and _scope(selected["scope"]) != scope:
        raise c.ContractError()
    generation = selected["generation_id"] if selected else str(uuid4())
    contexts = _contexts(args.root, generation, bool(
        selected and (selected["installation"]["controller"]
                      or selected["installation"].get("controller_installation") is not None)
    ), separate_controller=bool(
        selected and selected["installation"].get("controller_installation") is not None,
    )) if selected is not None else _existing_contexts()
    discovery = _service(registry, contexts, review, None)
    preview = discovery.plan(scope, context)
    _display_plan(preview, review.display)
    review.display(
        "No OS/elevation/WSL/distribution/VM/virtualization/service/reboot/security/trust "
        "change is implicit. Native Windows is not an Ansible controller. "
        "Unavailable selected pins require verified metadata; no selected dependency is skipped."
    )
    if selected is None:
        candidate = _first_run(
            args, review, registry, scope, context, discovery, metadata,
            default_metadata=default_metadata,
        )
        if candidate is None:
            return 3
        selected, owned_source = candidate.document, candidate.owned_source
        bootstrap = candidate.bootstrap
        acquisition = candidate.acquisition
        generation = selected["generation_id"]
    elif args.checkpoint:
        # A first-run selection token never selects or modifies an owned candidate.
        raise c.ContractError()
    # Check complete closure before reserving a root or asking for effects.
    manifest, _ = _manifest(selected, args.root, registry, owned_source)
    if manifest.bootstrap_digest is not None:
        if bootstrap is None or bootstrap.digest != manifest.bootstrap_digest:
            review.display(c.canonical_bytes(c.public_object({
                "status": "NeedsInput", "reason": "qualified-bootstrap-producer-required",
                "bootstrap_digest": manifest.bootstrap_digest,
                "effects_performed": (), "consent_issued": False,
                "fields": ("same-independently-configured-producer", "protected-original-ledger",
                           "exact-native-scope-root-context-input-cache-tool-output-members"),
                "choices": ("supply-current-qualified-producer-and-replan", "cancel"),
            })).decode("utf-8"))
            return 3
        bootstrap.guard(args.root, registry, _Clock(), _Cancel(), time.monotonic() + 60.0)
    from ._installation import _predictable_path_limit

    if manifest.installation is not None and _predictable_path_limit(
        str(args.root), manifest.generation_id, manifest.installation,
        tuple(member.path for member in manifest.members),
    ):
        review.display(c.canonical_bytes(c.public_object({
            "status": "NeedsInput", "reason": "shorter-user-owned-root-required",
            "scope": c.wire(scope), "effects_performed": (),
            "choices": ("choose-shorter-user-owned-root-and-replan", "cancel"),
            "consent_issued": False, "original_native_cause": "not-determined-by-admission",
        })).decode("utf-8"))
        return 3
    entries = preview.steps
    family = selected.get("family_lock")
    if owned_source is None and family is None and (
        tuple(item.dependency for item in entries) != tuple(asset.dependency for asset in manifest.assets)
    ):
        review.display("Selected asset closure is incomplete or out of order; nothing was installed.")
        return 3
    from ._assets import _approved

    if owned_source is not None:
        owned_source.guard(manifest, _Clock(), _Cancel(), time.monotonic() + 60.0)
    elif family is None:
        for step, asset in zip(entries, manifest.assets):
            if type(asset) is not LockedAsset:
                raise c.ContractError()
            entry = next(item for item in registry.entries if item.id == step.dependency)
            _approved(entry, asset)
    if (
        owned_source is None and acquisition is None and retained is None
        and args.action in ("plan", "install", "update")
    ):
        _cached_closure(manifest, selected)
    review.display("Pinned candidate (not readiness or consent): " + c.canonical_bytes(c.public_object({
        "generation_id": manifest.generation_id, "manifest_digest": c.digest(manifest),
        "scope": c.wire(manifest.scope), "assets": tuple(c.wire(asset) for asset in manifest.assets),
        "installation": c.wire(manifest.installation),
        "owned_root": str(args.root), "root_effects": ("create-owner-only-root", "owned-host-records"),
        "observation_max_age_seconds": review.observation.max_age_seconds,
        "acquisition": "exact-reviewed-publisher-downloads" if acquisition is not None
        else "verified-offline-inputs",
    })).decode("utf-8"))
    if manifest.bootstrap_digest is not None:
        review.display(
            "Separate native.stdlib bootstrap contribution=" + manifest.bootstrap_digest
            + "; future family assets retain their independent publisher origins, "
            "complete selected closure and separate exact effect reviews."
        )
    if args.action == "plan":
        review.display("Pinned selected closure validated. No root, consent or installation was created.")
        return 0
    existing = args.root.exists() or args.root.is_symlink()
    if retained is not None:
        root, state, documents = retained
    elif initial_root is not None:
        if args.action != "install" or (owned_source is None and bootstrap is None):
            raise c.ContractError()
        root, documents = initial_root, (selected,)
        state = _initialize_source_root(
            root, selected, registry, owned_source, review, observation=metadata.observation,
            bootstrap=bootstrap,
        )
    elif not existing:
        if args.action != "install":
            raise c.ContractError()
        prompt = (
            f"Create NEW owner-only root {args.root} and durable setup records for "
            f"selected generation {generation}, observation max-age="
            f"{review.observation.max_age_seconds}s? Type 'create {c.digest(str(args.root))}': "
        )
        if review.ask(prompt).strip() != "create " + c.digest(str(args.root)):
            review.display("Creation declined; nothing changed.")
            return 3
        root = _owned(args.root, True)
        documents = (selected,)
        state = _seed(
            root, documents, registry, owned_source=owned_source, observation=metadata.observation,
        )
    else:
        root = _owned(args.root, False)
        state, documents = _load_host(root)
        retained_review = _retained_review(state, metadata.observation, review)
        if retained_review is None:
            return 3
        review = retained_review
        if selected not in documents or state.read(_CONFIG).payload.get("registration_pending") is not None:
            if args.action != "update":
                review.display("Use update to review exact new or interrupted candidate registration.")
                return 3
            documents = _register(root, state, documents, selected, registry, review, owned_source)
    service = _host(
        root, state, documents, selected, registry, review,
        owned_source=owned_source, acquisition=acquisition, bootstrap=bootstrap,
    )
    installation_id = args.installation_id
    if args.action == "resume":
        stored_id = state.read(_CONTROL).payload["installation_id"]
        if installation_id is None:
            if type(stored_id) is not str:
                raise c.ContractError()
            installation_id = stored_id
        c.uuid_text(installation_id)
        if installation_id != stored_id:
            raise c.ContractError()
    if args.action == "verify":
        report = service.verify(scope, context)
        review.display(c.canonical_bytes(report).decode("utf-8"))
        selected_tiers = {operation.tier for operation in service._selection(scope)}
        return 0 if all(getattr(report.readiness, tier) == "ready" for tier in selected_tiers) else 3
    if args.action == "restore":
        restore_plan = service.plan_restore(args.generation_id or selected["generation_id"], context)
        broker = service.authorization
        if type(broker) is not AuthorizationBroker or broker._lifecycle_consent is None:
            raise c.ContractError()
        consent = broker._lifecycle_consent.review(restore_plan, time.monotonic(), 300.0)
        result = service.restore(restore_plan, consent, _Cancel())
    elif args.action == "uninstall":
        uninstall_plan = service.plan_uninstall(args.generation_id or selected["generation_id"], context)
        broker = service.authorization
        if type(broker) is not AuthorizationBroker or broker._lifecycle_consent is None:
            raise c.ContractError()
        consent = broker._lifecycle_consent.review(uninstall_plan, time.monotonic(), 300.0)
        result = service.uninstall(uninstall_plan, consent)
    else:
        # Replan staging and activation separately. Never reuse the first grant
        # for the pointer effect or silently reinstall a already selected tree.
        plan = service.plan(scope, context)
        _display_plan(plan, review.display)
        if plan.blocked:
            return 3
        consent = service.review(plan, time.monotonic(), 300.0)
        result = service.resume(installation_id, consent, _Cancel()) if args.action == "resume" else (
            service.provision(plan, consent, _Cancel())
        )
        review.display(c.canonical_bytes(result).decode("utf-8"))
        if result.pending_actions == ("review-activation-plan",):
            plan = service.plan(scope, context)
            _display_plan(plan, review.display)
            consent = service.review(plan, time.monotonic(), 300.0)
            result = service.provision(plan, consent, _Cancel())
    review.display(c.canonical_bytes(result).decode("utf-8"))
    return 0 if result.status == c.OutcomeStatus.SUCCEEDED else 3
