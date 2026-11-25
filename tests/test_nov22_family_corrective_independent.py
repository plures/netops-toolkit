"""Original AC-001/003/011 source boundaries; HTTPS alone is substituted.

Synthetic official-URL fixtures are not publisher or platform qualification.
The actual original broker consumes matching local source facts and one-use
permits. No network, producer capability, install or next-stage effect is used.
"""

import builtins
import hashlib
import io
import json
import platform
import re
import sys
import time
import zipfile
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from netops import __version__, setup
from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import bind_lifecycle, lifecycle_plan_digest
from netops.ansible.policy.lifecycle_evidence import lifecycle_arguments_digest
from netops.dependencies._assets import (
    AssetResponse,
    HttpsAssetTransport,
    LockedAsset,
    VerifiedAssetAcquisition,
)
from netops.dependencies._family_lock import _FamilyResolver, _Release, _Requirement
from netops.dependencies._managed import ManagedMember
from netops.dependencies._publisher_acquisition import _PublisherAcquisition
from netops.dependencies._publisher_catalog import _PublisherSeed
from netops.dependencies._publisher_metadata import _PublisherMetadata, _registered_publishers
from netops.dependencies._python_metadata import _PythonFile, _PythonOrgMetadata, _PythonSeed
from netops.dependencies.service import DependencyRegistry
from tests.policy.test_lifecycle_execution import (
    CONTENT,
    DATA,
    decision_for,
    environment,
)
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_default_provider_completion_author import native_metadata_case, retained_resource
from tests.test_nov21_publisher_consumption_independent import TARGET, Cancel, Clock, fixture


class Events:
    def __init__(self):
        self.values = []

    def emit(self, value):
        self.values.append(value)


def admitted_download(path, policy, expires_after):
    plan, _, port, state, _, consent, broker, clock, _ = environment(
        path, policy, "dependency-download",
    )
    asset = LockedAsset(
        "pypi:paramiko", "paramiko",
        "https://files.pythonhosted.org/packages/SOURCE-ONLY/fixture.whl",
        CONTENT, len(DATA),
    )
    record = port.read("source")
    payload = {**dict(record.payload), "manifest": c.wire(asset)}
    port.seed("source", payload)
    port.seed(asset.source_id, payload)
    step = dict(plan.content["steps"][0])
    step["source"] = {
        **dict(step["source"]), "source_id": asset.source_id,
        "descriptor_digest": c.digest(asset),
    }
    step = c.public_object(step)
    port.seed("step", step)
    effect = replace(plan.effects[0], arguments_digest=lifecycle_arguments_digest(step))
    plan = replace(
        plan, effects=(effect,),
        content=c.public_object({**dict(plan.content), "steps": (step,)}),
    )
    plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    binding = bind_lifecycle(plan)
    grant = broker.issue_lifecycle(
        plan, consent.review(plan, 10.0, 20.0), decision_for(policy, binding), 10.0,
    )
    session = broker.consume_lifecycle(grant, binding, 10.0)
    invocation = lc.LifecycleEffectBinding(
        binding, str(uuid4()), state.snapshot_lifecycle(binding).revision, effect.occurrence_id,
    )
    permit = broker.permit_lifecycle(session, invocation, 10.0)
    live = _PublisherAcquisition(
        (asset,), (path / "never-created-cache",), "a" * 64,
        time.monotonic() + expires_after,
    )
    events = Events()
    acquisition = VerifiedAssetAcquisition(broker, live, clock, events)
    return acquisition, asset, permit, invocation, port, live, events


@pytest.mark.parametrize("io_outcome", ["returns", "interrupts"])
def test_ac011_original_cancel_reaches_http_and_preserves_factual_io_outcome(
    tmp_path, monkeypatch, policy, io_outcome,
):
    acquisition, asset, permit, binding, port, live, events = admitted_download(
        tmp_path, policy, 60.0,
    )
    original_writes = tuple(port.writes)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir() if path.is_file()}
    original = Cancel()
    scope = acquisition._authorization._life_scope(permit)
    remaining = scope.deadline - acquisition._clock.monotonic()
    observed = []
    primary = InterruptedError("external owned HTTPS child observed caller cancellation")

    def external(self, url, timeout, limit, clock, cancel):
        original.value = True
        observed.append((cancel is original, cancel.is_cancelled(), timeout, limit))
        if io_outcome == "interrupts" and cancel.is_cancelled():
            raise primary
        return AssetResponse(url, DATA)

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", external)
    if io_outcome == "interrupts":
        with pytest.raises(InterruptedError) as error:
            acquisition.download(
                DependencyRegistry.load().entry("paramiko"), asset, permit, binding, original,
            )
        assert error.value is primary
        assert events.values[-1].status == c.OutcomeStatus.CANCELLED
    else:
        result = acquisition.download(
            DependencyRegistry.load().entry("paramiko"), asset, permit, binding, original,
        )
        assert result.content == DATA and result.digest == CONTENT
        assert result.cancelled_after_acquisition is True
    assert len(observed) == 1
    same_object, actual_cancelled, timeout, limit = observed[0]
    assert same_object and actual_cancelled
    assert timeout == remaining and limit == len(DATA) + 1
    assert tuple(port.writes) == original_writes
    assert not live.cache_paths[0].exists()
    assert before == {path.name: path.read_bytes() for path in tmp_path.iterdir()
                      if path.is_file()}


@pytest.mark.parametrize("expiry", ["before", "during"])
def test_ac011_original_publisher_expiry_blocks_acquisition_without_cache_or_next_effect(
    tmp_path, monkeypatch, policy, expiry,
):
    acquisition, asset, permit, binding, port, live, _ = admitted_download(
        tmp_path, policy, 2.0 if expiry == "during" else -1.0,
    )
    deadline = live.source_deadline
    original = Cancel()
    original_writes = tuple(port.writes)
    observed = []

    def external(self, url, timeout, limit, clock, cancel):
        observed.append((cancel is original, timeout))
        time.sleep(max(0.0, deadline - time.monotonic()) + 0.02)
        return AssetResponse(url, DATA)

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", external)
    with pytest.raises((c.ContractError, TimeoutError)):
        acquisition.download(
            DependencyRegistry.load().entry("paramiko"), asset, permit, binding, original,
        )
    assert not observed if expiry == "before" else (
        len(observed) == 1 and observed[0][0] and 0 < observed[0][1] <= 2.0
    )
    assert not live.cache_paths[0].exists() and tuple(port.writes) == original_writes


@pytest.mark.parametrize("route", ["registered", "public", "retained-v1-default"])
def test_ac001_retained_v1_optional_parser_absence_is_typed_before_http(monkeypatch, route):
    from netops.dependencies import _default_family

    release, transport, _ = fixture()
    calls = []

    def external(self, url, timeout, limit, clock, cancel):
        calls.append(url)
        return AssetResponse(url, transport.content)

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", external)
    if route == "public":
        metadata = setup.SetupMetadata.publishers(None, (), (release,), (TARGET,))
        sources = metadata._metadata().family_planning.sources
    elif route == "registered":
        sources = _registered_publishers((release,), HttpsAssetTransport())
    else:
        retained_resource(monkeypatch, json.dumps({
            "schema": "netops-publisher-catalogue-v1",
            "releases": [c.wire(release)], "python_files": [],
        }).encode())
        sources = _default_family._default_metadata(DependencyRegistry.load()).family_planning.sources
        # The fixed installed-v1 resource is loaded by the actual default owner.
        # This source is not a seeded-v2 port or a normalized metadata callback.
        source = next(item for item in sources if item.source == release.requirement.source)
        assert type(source.port) is _PublisherMetadata and source.port.releases == (release,)
    real_import = builtins.__import__

    def missing(name, *args, **kwargs):
        if name == "packaging.requirements":
            raise ImportError("optional parser unavailable; no permissive substitute")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)
    result = _FamilyResolver(sources).resolve(
        (release.requirement,), (TARGET,), "b" * 64, Clock(), Cancel(), 40.0,
    )
    assert result.lock is None and len(result.needs) == 1
    assert result.needs[0].requirement == release.requirement
    assert result.needs[0].reason == "metadata-parser-required"
    assert result.needs[0].fields == ("pep440-parser",)
    assert calls == []


def test_ac001_public_auto_compiler_accepts_closed_retained_official_interpreter(monkeypatch):
    release, _, _ = native_metadata_case()
    def forbidden(*args, **kwargs):
        pytest.fail("Public registration must not perform any publisher HTTP.")

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", forbidden)
    metadata = setup.SetupMetadata.publishers(
        None, (), (), (TARGET,), python_files=(_PythonFile(release, 123),),
    )
    source, = metadata._metadata().family_planning.sources
    assert source.source == "python.org"
    assert source.families == ("python",) and source.origins == ("www.python.org",)
    assert type(source.port) is _PythonOrgMetadata
    assert source.port.files == (_PythonFile(release, 123),)
    assert source.metadata_digest == c.digest((_PythonFile(release, 123),))
    assert metadata._metadata().layout is not None


def test_ac003_public_bare_interpreter_release_does_not_invent_official_file_identity():
    release, _, _ = native_metadata_case()
    with pytest.raises(c.ContractError):
        setup.SetupMetadata.publishers(None, (), (release,), (TARGET,))


def public_compiler_fixture(root, monkeypatch, pin_kind="file"):
    """Real public compiler input; only bounded official HTTP responses are fake."""
    from netops.dependencies import _default_family, _guided, _setup

    registry = DependencyRegistry.load()
    scope = c.InstallScope(("native.stdlib",), (), False, False)
    context = _setup._context(root, registry)
    service = _setup._service(
        registry, _guided._existing_contexts(), _setup._Review(lambda _: "", lambda _: None), None,
    )
    diagnosis = _guided._diagnose(service, scope, context, probe=True)
    selection = _guided._Selection((("native-python", "install"),), ())
    target = next(target for target in _default_family._default_metadata(
        registry,
    ).family_planning.targets if target.context == "native")
    executable = Path(_guided._existing_python())
    interpreter = executable.read_bytes()
    executable_digest = hashlib.sha256(interpreter).hexdigest()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(executable.name, interpreter)
    archive_bytes = buffer.getvalue()
    native_asset = LockedAsset(
        "python.org", "native-python",
        "https://www.python.org/ftp/python/" + platform.python_version() + "/source-only.zip",
        hashlib.sha256(archive_bytes).hexdigest(), len(archive_bytes),
    )
    native_json = json.dumps({
        "id": 7654321, "url": native_asset.url, "filesize": native_asset.size,
    }).encode()
    member = ManagedMember(executable.name, executable_digest, len(interpreter), True)
    native = _Release(
        _Requirement("native-python", "python", "python.org", "native", ">=3.9"),
        platform.python_version(), "zip", (sys.platform,), (platform.machine(),), (),
        hashlib.sha256(native_json).hexdigest(), native_asset, members=(member,),
    )
    responses = {
        "https://www.python.org/api/v2/downloads/release_file/7654321/": native_json,
    }
    assets = {native_asset.url: archive_bytes}
    seeds = []
    for name, version, edges in (
        ("netops-toolkit", __version__, ["source-only-helper==1.0"]),
        ("source-only-helper", "1.0", []),
    ):
        normalized = name.replace("-", "_")
        filename = normalized + "-" + version + "-py3-none-any.whl"
        prefix = normalized + "-" + version + ".dist-info/"
        payload = io.BytesIO()
        metadata = (
            "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n"
            + "".join("Requires-Dist: " + edge + "\n" for edge in edges)
        ).encode()
        files = {
            normalized + "/__init__.py": b'"""SOURCE fixture, not a qualified release."""\n',
            prefix + "METADATA": metadata,
            prefix + "WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        }
        files[prefix + "RECORD"] = (
            "\n".join(path + ",," for path in (*files, prefix + "RECORD")) + "\n"
        ).encode()
        with zipfile.ZipFile(payload, "w") as archive:
            for path, content in files.items():
                archive.writestr(path, content)
        content = payload.getvalue()
        url = "https://files.pythonhosted.org/packages/SOURCE-ONLY/" + filename
        document = json.dumps({
            "info": {"name": name, "version": version, "requires_python": ">=3.9",
                     "requires_dist": edges, "provides_extra": []},
            "urls": [{"filename": filename, "url": url, "size": len(content),
                      "packagetype": "bdist_wheel", "yanked": False,
                      "digests": {"sha256": hashlib.sha256(content).hexdigest()}}],
        }).encode()
        seed = _PublisherSeed(
            "pypi:" + name, name, version, filename, hashlib.sha256(document).hexdigest(),
        )
        seeds.append(seed)
        responses[seed.url] = document
        assets[url] = content
    calls = []

    def external(self, url, timeout, limit, clock, cancel):
        calls.append((url, clock, cancel))
        assert url in responses, "Only exact registered official metadata may be requested."
        return AssetResponse(url, responses[url])

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", external)
    kwargs = (
        {"python_files": (_PythonFile(native, 7654321),)}
        if pin_kind == "file" else
        {"python_records": (_PythonSeed(
            7654321, native.version, native.metadata_digest, native_asset.sha256,
            "zip", native.platforms, native.architectures, native.members,
        ),)}
    )
    public = setup.SetupMetadata.publishers(
        None, (), (), (target,), publisher_records=tuple(seeds), **kwargs,
    )
    return registry, scope, diagnosis, selection, public, native, responses, assets, calls


@pytest.mark.parametrize("pin_kind", ["file", "record"])
def test_ac001_actual_public_compiler_preserves_interpreter_toolkit_transitive_and_root_context(
    tmp_path, monkeypatch, pin_kind,
):
    from netops.dependencies import _setup

    root = tmp_path / "exact-public-root"
    registry, scope, diagnosis, selection, public, native, _, _, calls = public_compiler_fixture(
        root, monkeypatch, pin_kind,
    )
    candidate, needs = public._metadata().resolve(diagnosis, selection, scope, root, registry)
    assert candidate is not None and not needs
    assert candidate.acquisition is not None
    manifest, contexts = _setup._manifest(candidate.document, root, registry)
    assert manifest.installation.python_digest == native.members[0].digest
    assert manifest.installation.python_version == platform.python_version()
    assert manifest.consuming_contexts == (contexts["native"].digest,)
    assert candidate.family_lock.targets[0].context_digest == contexts["native"].digest
    assert Path(contexts["native"].python).is_relative_to(root)
    assert contexts["native"].digest != _setup._contexts(
        root.parent / "substituted-root", manifest.generation_id, False,
    )["native"].digest
    assert {(item.name, item.source, item.context, item.version)
            for item in candidate.family_lock.roots} == {
        ("native-python", "python.org", "native", ">=3.9"),
        ("netops-toolkit", "pypi:netops-toolkit", "native", "==" + __version__),
    }
    assert {(item.distribution, item.version) for item in manifest.installation.wheels} == {
        ("netops-toolkit", __version__), ("source-only-helper", "1.0"),
    }
    assert {item.artifact.source_id for item in candidate.family_lock.releases} == {
        "python.org", "pypi:netops-toolkit", "pypi:source-only-helper",
    }
    assert len(calls) == 3
    assert not root.exists() and not (root.parent / "netops-publisher-cache").exists()
    assert candidate.acquisition.document_digest == c.digest(c.public_object(candidate.document))
    assert "acquisition" not in candidate.document
    assert "permit" not in candidate.document and "consent" not in candidate.document


@pytest.mark.parametrize("damage", ["member", "file-id", "origin", "raw-pin", "mixed", "dict"])
def test_ac003_public_interpreter_contribution_cannot_substitute_source_or_qualification(
    tmp_path, monkeypatch, damage,
):
    root = tmp_path / "not-created"
    registry, scope, diagnosis, selection, public, native, responses, _, calls = public_compiler_fixture(
        root, monkeypatch,
    )
    seed_sources = public._metadata().family_planning.sources
    seeds = tuple(
        seed for source in seed_sources if source.source.startswith("pypi:")
        for seed in source.port.seeds
    )
    file = _PythonFile(native, 7654321)
    if damage == "member":
        native = replace(native, members=(replace(native.members[0], digest="d" * 64),))
        file = _PythonFile(native, 7654321)
    elif damage == "file-id":
        document = json.loads(responses["https://www.python.org/api/v2/downloads/release_file/7654321/"])
        document["id"] = 7654322
        responses["https://www.python.org/api/v2/downloads/release_file/7654321/"] = json.dumps(document).encode()
    elif damage == "raw-pin":
        responses["https://www.python.org/api/v2/downloads/release_file/7654321/"] += b" "
    if damage in ("origin", "mixed", "dict"):
        with pytest.raises(c.ContractError):
            if damage == "origin":
                _PythonFile(replace(native, artifact=replace(
                    native.artifact, url="https://files.pythonhosted.org/not-official.zip",
                )), 7654321)
            elif damage == "dict":
                setup.SetupMetadata.publishers(None, (), (), (
                    public._metadata().family_planning.targets[0],
                ), python_files=(c.wire(file),), publisher_records=seeds)
            else:
                setup.SetupMetadata.publishers(
                    None, (), (), public._metadata().family_planning.targets,
                    python_files=(file,), python_records=(_PythonSeed(
                        7654321, native.version, native.metadata_digest, native.artifact.sha256,
                        native.format, native.platforms, native.architectures, native.members,
                    ),), publisher_records=seeds,
                )
        assert not calls and not root.exists()
        return
    replacement = setup.SetupMetadata.publishers(
        None, (), (), public._metadata().family_planning.targets,
        python_files=(file,), publisher_records=seeds,
    )
    candidate, needs = replacement._metadata().resolve(diagnosis, selection, scope, root, registry)
    assert candidate is None and needs
    assert all(need.reason != "component-declined" for need in needs)
    assert not root.exists() and not (root.parent / "netops-publisher-cache").exists()


def test_ac011_public_compiler_original_broker_reaches_exact_download_then_no_stage(
    tmp_path, monkeypatch, capsys,
):
    from netops.dependencies import _setup

    root = tmp_path / "public-broker-root"
    sentinel = tmp_path / "unrelated-user-inventory"
    sentinel.write_bytes(b"original independent user bytes\n")
    _, _, _, _, public, _, responses, assets, _ = public_compiler_fixture(root, monkeypatch)
    entered = []
    reviewed = []
    primary = InterruptedError("actual external HTTPS child interrupted before response")

    def external(self, url, timeout, limit, clock, cancel):
        if url in responses:
            return AssetResponse(url, responses[url])
        assert url in assets, "Original owner must dispatch only compiled asset identity."
        entered.append((url, timeout, cancel))
        raise primary

    def review(prompt):
        if "Reuse/Install/Decline" in prompt:
            return "install"
        match = re.search(r"Type '((?:create|install) [0-9a-f]{64})'", prompt)
        if match:
            reviewed.append(match.group(1))
            return match.group(1)
        return ""

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", external)
    monkeypatch.setattr("builtins.input", review)
    assert setup.main(
        ["install", "--root", str(root), "--capability", "native.stdlib"], metadata=public,
    ) == 3
    output = capsys.readouterr().out
    assert len(entered) == 1 and entered[0][0] in assets, output
    assert type(entered[0][2]) is _setup._Cancel
    assert 0 < entered[0][1] <= 60.0
    assert any(item.startswith("create ") for item in reviewed)
    assert any(item.startswith("install ") for item in reviewed)
    assert "exact-reviewed-publisher-downloads" in output
    assert root.exists()
    protected = _setup._owned(root, False)
    state, _ = _setup._load_host(protected)
    assert not state.read(_setup._ROOT).payload["generations"]
    assert state.read(_setup._CONTROL).payload["pointer"] == c.public_object(
        c.wire(lc.AbsentPointer("absent", 0)),
    )
    assert not any(path.name.startswith(("installation-", "generation-"))
                   for path in root.iterdir())
    assert not (root.parent / "netops-publisher-cache").exists()
    assert sentinel.read_bytes() == b"original independent user bytes\n"
