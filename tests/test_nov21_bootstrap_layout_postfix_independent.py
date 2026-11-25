"""Original SC-02/05/11 source-bound controls; not platform qualification."""

import hashlib
import sys
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from netops import setup
from netops.ansible import artifact_platform as storage
from netops.ansible import contracts as c
from netops.ansible.controller_backend import _compose_owned_controller_service
from netops.ansible.controller_generation import _PinnedControllerProcesses
from netops.ansible.controller_installation import _ManagedInstallationVerifier
from netops.ansible.controller_protocol import ProtocolError
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import AuthorizationError
from netops.dependencies import _installation_process, _owned_build, _setup
from netops.dependencies._family_lock import _Target
from netops.dependencies._installation import _InstallationSpec, _Wheel
from netops.dependencies._managed import (
    ManagedGenerationManifest,
    ManagedMember,
    ProtectedGenerationFiles,
)
from netops.dependencies._owned_source import _OwnedSource
from netops.dependencies.service import DependencyRegistry
from tests.policy.test_lifecycle_execution import OWNER
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel
from tests.test_owned_source_author import Clock, build_case
from tests.test_s02_managed_installation_binding import binding_case


def producer(tmp_path, monkeypatch):
    """Real protected host/ledger; only external backend execution is synthetic."""
    host, calls = build_case(tmp_path, monkeypatch)
    registry = DependencyRegistry.load()
    generation = str(uuid4())
    root = Path(host.consuming_root.path)
    context = _setup._context(root, registry)
    contexts = tuple(sorted(item.digest for item in _setup._contexts(root, generation, False).values()))
    spec = replace(host.spec, context_digest=c.digest(context), consuming_contexts=contexts)
    host = _owned_build._OfflineBuildHost(host.root, host.consuming_root, spec)
    host.produce(Clock(), Cancel(), 100.0)
    source = _OwnedSource(host, Clock(), Cancel(), 100.0)
    members = tuple(ManagedMember(
        item["path"], item["digest"], item["size"], item["executable"],
    ) for item in source._issued._result.receipt["members"])
    installation = _InstallationSpec(
        spec.python, spec.toolchain[0].digest, spec.python_version, spec.platform,
        tuple(_Wheel(item.path, Path(item.path).name.split("-")[0].replace("_", "-"),
                     Path(item.path).name.split("-")[1], item.digest) for item in members),
    )
    manifest = ManagedGenerationManifest(
        generation, source.asset, "zip", members, c.InstallScope(("native.stdlib",), (), False, False),
        context, contexts, installation=installation,
    )
    source.guard(manifest, Clock(), Cancel(), 100.0)
    return host, source, manifest, calls


def drift(host, area):
    """Mutate actual owned inputs, not a serialized receipt substitute."""
    relative = {
        "source": "source/pyproject.toml", "cache": "cache/setuptools-84.whl",
        "output": "output/netops_toolkit-1.0-py3-none-any.whl",
        "member": "output/netops_toolkit-1.0.tar.gz",
    }
    if area in relative:
        with (Path(host.root.path) / relative[area]).open("ab") as stream:
            stream.write(b"drift")
    elif area == "root":
        (Path(host.root.path) / "unreviewed-member").write_bytes(b"drift")
    elif area == "tool":
        host.spec = replace(host.spec, toolchain=(
            replace(host.spec.toolchain[0], digest="f" * 64),
        ))
    elif area == "input":
        host.spec = replace(host.spec, source=(replace(host.spec.source[0], digest="f" * 64),
                                               *host.spec.source[1:]))
    else:
        host.spec = replace(host.spec, context_digest="f" * 64)


@pytest.mark.parametrize("area", ("source", "cache", "input", "tool", "output", "member", "root", "context"))
@pytest.mark.parametrize("boundary", ("after-review", "after-publication"))
def test_original_producer_drift_stops_real_stage_before_installer(tmp_path, monkeypatch, area, boundary):
    host, source, manifest, build_calls = producer(tmp_path, monkeypatch)
    original = storage.rename
    installed = []
    effects = []

    def publish(*args, **kwargs):
        original(*args, **kwargs)
        effects.append("published")
        drift(host, area)

    monkeypatch.setattr("netops.dependencies._installation._OfflineInstallation.install",
                        lambda *args, **kwargs: installed.append("installation-entered"))
    if boundary == "after-publication":
        monkeypatch.setattr(storage, "rename", publish)
    else:
        drift(host, area)
    files = source._issued._result
    from netops.dependencies._managed import unpack

    expanded = unpack(manifest, files.content, Clock(), Cancel(), 100.0)
    def guard():
        source.guard(manifest, Clock(), Cancel(), 100.0)
    with pytest.raises((AuthorizationError, OSError, c.ContractError)) as rejection:
        ProtectedGenerationFiles(host.consuming_root).stage(
            manifest, expanded, Clock(), Cancel(), 100.0, _source_guard=guard,
        )
    assert installed == []
    assert len(build_calls) == 1
    if effects != (["published"] if boundary == "after-publication" else []):
        try:
            from tests._nov22_exact_failure_capture import capture

            capture(rejection.value, "test_original_producer_drift_stops_real_stage_before_installer",
                    "before-original-effects-assertion",
                    (host.root.path, host.consuming_root.path))
        except BaseException:
            # Preserve the original assertion even if diagnostic initialization fails.
            pass
    assert effects == (["published"] if boundary == "after-publication" else []), repr(rejection.value)
    members = tuple(Path(host.consuming_root.path).iterdir())
    assert bool(members) is (boundary == "after-publication")


@pytest.mark.parametrize("area", ("source", "cache", "input", "tool", "output", "member", "root", "context"))
def test_live_original_producer_blocks_actual_process_boundary(tmp_path, monkeypatch, area):
    from netops.dependencies import _installation_windows as native

    host, source, manifest, _ = producer(tmp_path, monkeypatch)
    spawned = []
    monkeypatch.setattr(native, "_InstallationChild",
                        lambda *args, **kwargs: spawned.append(args))
    drift(host, area)
    with pytest.raises((AuthorizationError, OSError, c.ContractError)):
        _installation_process._run(
            (sys.executable, "-B", "-c", "raise AssertionError()"), tmp_path,
            Clock(), Cancel(), 100.0,
            _source_guard=lambda: source.guard(manifest, Clock(), Cancel(), 100.0),
        )
    assert spawned == []


def test_public_compose_retains_actual_producer_not_serialized_actor(tmp_path, monkeypatch):
    host, source, manifest, _ = producer(tmp_path, monkeypatch)
    native = setup.SetupMetadata(source, manifest.installation, host.consuming_root,
                                 manifest.generation_id)
    family = setup.SetupMetadata.publishers(None, (), (), (
        _Target("native", sys.platform, "x86_64", host.spec.python_version,
                "cp312", ("py3-none-any",), c.digest(manifest.context)),
    ))
    composed = setup.SetupMetadata.compose(native, family)
    contribution = composed._metadata().bootstrap
    assert contribution.source is source and source._host is host
    contribution.guard(Path(host.consuming_root.path), DependencyRegistry.load(),
                       Clock(), Cancel(), 100.0)
    with pytest.raises(TypeError):
        setup.SetupMetadata.compose(c.wire(source.asset), family)
    drift(host, "source")
    with pytest.raises((AuthorizationError, OSError, c.ContractError)):
        contribution.guard(Path(host.consuming_root.path), DependencyRegistry.load(),
                           Clock(), Cancel(), 100.0)


def child_case(tmp_path, policy):
    """Retain original record pins while constructing a distinct child receipt."""
    baseline, context, state, old_resource = binding_case(tmp_path, policy)
    parent = baseline._descriptor
    child = parent.installation
    native = replace(child, controller=False,
                     controller_installation=child)
    manifest = replace(parent, installation=native)
    generation = lc.GenerationBinding(manifest.generation_id, 0,
                                      manifest.content_digest, c.digest(manifest))
    receipt = c.wire(state.read(old_resource).payload)["receipt"]
    receipt["descriptor_digest"] = c.digest(manifest)
    receipt["manifest"] = [
        {"path": "bin/python", "kind": "file", "digest": "a" * 64, "executable": True},
        {"path": "controller/bin/python", "kind": "file", "digest": "c" * 64, "executable": True},
        {"path": "controller/netops-installation.json", "kind": "file", "digest": "b" * 64},
    ]
    receipt["installation_digest"] = c.digest(c.public_value(receipt["manifest"]))
    root = c.wire(state.read("managed-root").payload)
    root["generations"][0].update(manifest=c.wire(manifest), installation_receipt=receipt)
    root["root_manifest"]["registered_manifests"] = [c.wire(manifest)]
    root["root_manifest"]["registered_qualifications"][0]["generation_binding"] = c.wire(generation)
    state.seed("managed-root", root)
    control = c.wire(state.read("managed-control").payload)
    control["pointer"] = c.wire(lc.PresentPointer("present", generation.generation_id,
                                                c.digest((generation, 1)), 1))
    control["verification"]["manifest_digest"] = c.digest(manifest)
    state.seed("managed-control", control)
    data = c.wire(state.read(old_resource).payload)
    data.update(generation_binding=c.wire(generation), receipt=receipt)
    resource = "dependency-installation-" + c.digest(generation)
    state.seed(resource, data)
    verifier = _ManagedInstallationVerifier(baseline._root, "managed-root", "managed-control",
                                            OWNER, manifest)
    return verifier, context, state, resource


@pytest.mark.parametrize("fault", (None, "native-member", "child-member", "child-receipt",
                                  "parent-receipt", "pointer", "generation", "child-root"))
def test_production_parent_child_receipt_pointer_consumption(tmp_path, policy, fault):
    verifier, context, state, resource = child_case(tmp_path, policy)
    members, digest = verifier._selection(context, state)
    assert verifier._runtime_selection() == ("controller/bin/python", "controller/")
    assert members[-1]["path"] == "netops-installation.json"
    assert members[-1]["digest"] == hashlib.sha256(
        c.canonical_bytes(state.read(resource).payload["receipt"]),
    ).hexdigest()
    assert digest == state.read(resource).payload["receipt"]["installation_digest"]
    assert verifier.verify(context, state) is None
    if fault is None:
        return
    if fault == "child-root":
        verifier._root = verifier._root / "controller"
    elif fault == "pointer":
        data = c.wire(state.read("managed-control").payload)
        data["pointer"]["pointer_digest"] = "f" * 64
        state.seed("managed-control", data)
    else:
        data = c.wire(state.read(resource).payload)
        if fault == "generation":
            data["generation_binding"]["manifest_digest"] = "f" * 64
        elif fault == "parent-receipt":
            data["receipt"]["descriptor_digest"] = "f" * 64
        else:
            selected = {"native-member": "bin/python", "child-member": "controller/bin/python",
                        "child-receipt": "controller/netops-installation.json"}[fault]
            data["receipt"]["manifest"] = [
                item for item in data["receipt"]["manifest"] if item["path"] != selected
            ]
        state.seed(resource, data)
    with pytest.raises(ProtocolError):
        verifier._selection(context, state)
    assert verifier.verify(context, state) is None


def test_actual_factory_retains_parent_child_verifier_and_generation_pins(tmp_path, policy):
    verifier, context, state, _ = child_case(tmp_path, policy)
    generation = verifier._generation
    resource = "dependency-run-pin-" + c.digest(generation)
    state.seed(resource, {
        "generation_id": generation.generation_id, "manifest_digest": generation.manifest_digest,
        "revision": 0, "holders": (),
    })
    _, host = _compose_owned_controller_service(
        object(), state, object(), object(), object(), verifier._root,
        "managed-control", "unused-legacy-install", tmp_path / "private",
        object(), None, None, Clock(), object(), OWNER,
        managed_manifest=verifier._descriptor, managed_root_resource="managed-root",
    )
    processes = host._backend._launcher._processes
    assert type(processes) is _PinnedControllerProcesses
    assert type(processes._verifier) is _ManagedInstallationVerifier
    assert processes._verifier._runtime_selection() == ("controller/bin/python", "controller/")
    assert processes._verifier._root == verifier._root
    assert processes.verify(context, state) is None
    assert state.read(resource).payload["holders"] == ()
    data = c.wire(state.read("managed-control").payload)
    data["pointer"]["pointer_digest"] = "f" * 64
    state.seed("managed-control", data)
    with pytest.raises(ProtocolError):
        processes.verify(context, state)
    assert state.read(resource).payload["holders"] == ()
