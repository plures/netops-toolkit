"""SOURCE controls of the consumed compiler; external HTTP is synthetic only."""

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

import pytest

from netops import __version__, setup
from netops.ansible import contracts as c
from netops.dependencies import _default_family, _guided, _setup
from netops.dependencies._assets import AssetResponse, HttpsAssetTransport, LockedAsset
from netops.dependencies._family_lock import _contributions, _FamilyResolver, _Release, _Requirement
from netops.dependencies._installation import _InstallationSpec, _Wheel
from netops.dependencies._lock_layout import _LayoutUnavailable, _LockLayout, _toolkit_requirement
from netops.dependencies._managed import ManagedMember
from netops.dependencies._publisher_acquisition import _PublisherAcquisition
from netops.dependencies._publisher_catalog import (
    _PublisherSeed,
    _seeded_publishers,
    _SeededPublisherMetadata,
)
from netops.dependencies._python_metadata import _PythonSeed, _SeededPythonMetadata
from tests.test_default_provider_completion_author import retained_resource
from tests.test_family_provider_author import TARGET, Cancel, Clock, D
from tests.test_guided_first_run_author import service_case
from tests.test_public_family_integration_author import publisher_case, transport_for


@pytest.mark.parametrize("collection", [False, True])
def test_seed_populates_artifact_and_edges_from_actual_pinned_json(monkeypatch, collection):
    retained, document, content, _ = publisher_case(collection=collection)
    artifact = retained.artifact
    seed = _PublisherSeed(
        retained.requirement.source, retained.requirement.name, retained.version,
        artifact.url.rsplit("/", 1)[-1], hashlib.sha256(content).hexdigest(),
    )
    transport, calls = transport_for(monkeypatch, content)
    port = _SeededPublisherMetadata((seed,), transport)
    snapshot = port.observe(retained.requirement, TARGET, Clock(), Cancel(), 50.0)
    release, = snapshot.releases
    assert release.artifact == artifact
    assert release.requires == retained.requires
    assert release.members == retained.members
    assert snapshot.metadata_digest == c.digest((seed,))
    assert [call[0] for call in calls] == [seed.url]
    assert document and seed.url != artifact.url


@pytest.mark.parametrize("damage", ["digest", "origin", "filename", "size", "python", "duplicate"])
def test_populated_catalog_cannot_substitute_publisher_fields(monkeypatch, damage):
    item, document, content, _ = publisher_case()
    seed = _PublisherSeed(item.requirement.source, item.requirement.name, item.version,
                          item.artifact.url.rsplit("/", 1)[-1], item.metadata_digest)
    artifact = document["urls"][0]
    if damage == "digest":
        artifact["digests"]["sha256"] = None
    elif damage == "origin":
        artifact["url"] = "https://unapproved.invalid/" + seed.filename
    elif damage == "filename":
        artifact["filename"] = "different-1.0-py3-none-any.whl"
    elif damage == "size":
        artifact["size"] = True
    elif damage == "python":
        artifact["requires_python"] = ">=999"
    else:
        document["urls"].append(dict(artifact))
    content = json.dumps(document).encode()
    seed = replace(seed, metadata_digest=hashlib.sha256(content).hexdigest())
    transport, _ = transport_for(monkeypatch, content)
    with pytest.raises(c.ContractError):
        _SeededPublisherMetadata((seed,), transport).observe(
            item.requirement, TARGET, Clock(), Cancel(), 50.0,
        )


def test_absent_official_python_range_is_not_fabricated(monkeypatch):
    item, document, _, _ = publisher_case()
    document["info"]["requires_python"] = None
    content = json.dumps(document).encode()
    seed = _PublisherSeed(item.requirement.source, item.requirement.name, item.version,
                          item.artifact.url.rsplit("/", 1)[-1],
                          hashlib.sha256(content).hexdigest())
    transport, _ = transport_for(monkeypatch, content)
    snapshot = _SeededPublisherMetadata((seed,), transport).observe(
        item.requirement, TARGET, Clock(), Cancel(), 50.0,
    )
    assert snapshot.releases[0].python == ""


@pytest.mark.parametrize("damage", [None, "md5-only", "outside-release", "raw-pin", "redirect"])
def test_python_catalog_population_requires_separate_exact_sha256_members(monkeypatch, damage):
    body = b"source-only archive, not an official downloadable interpreter"
    digest = hashlib.sha256(body).hexdigest()
    document = {
        "id": 321, "url": "https://www.python.org/ftp/python/3.12.10/source.zip",
        "filesize": len(body), "md5_sum": "legacy-md5-is-not-a-sha256-pin",
    }
    if damage == "outside-release":
        document["url"] = "https://www.python.org/ftp/python/3.13.0/source.zip"
    content = json.dumps(document).encode()
    seed = _PythonSeed(
        321, "3.12.10", hashlib.sha256(content).hexdigest(), digest,
        "zip", ("linux",), ("x86_64",), (ManagedMember("python", digest, len(body), True),),
    )
    if damage == "md5-only":
        with pytest.raises(c.ContractError):
            replace(seed, artifact_digest=document["md5_sum"])
        return
    if damage == "raw-pin":
        content += b" "
    transport, _ = transport_for(
        monkeypatch, content,
        transform=(lambda response: AssetResponse(
            "https://unapproved.invalid/file", response.content,
        )) if damage == "redirect" else None,
    )
    port = _SeededPythonMetadata((seed,), transport)
    requirement = _default_family._requirement(
        _default_family.DependencyRegistry.load().entry("native-python"),
    )
    if damage is not None:
        with pytest.raises(c.ContractError):
            port.observe(requirement, TARGET, Clock(), Cancel(), 50.0)
        return
    snapshot = port.observe(requirement, TARGET, Clock(), Cancel(), 50.0)
    release, = snapshot.releases
    assert release.artifact.url == document["url"] and release.artifact.sha256 == digest
    assert release.artifact.size == len(body) and release.members == seed.members
    assert snapshot.metadata_digest == c.digest((seed,))


@pytest.mark.parametrize("damage", [
    "source", "filename", "missing-pin", "extra-field", "duplicate", "non-list",
    "too-many", "unknown-schema", "python-record", "legacy-conflict",
])
def test_actual_packaged_catalog_rejects_unreviewed_or_ambiguous_records(monkeypatch, damage):
    item, _, _, _ = publisher_case()
    record = c.wire(_PublisherSeed(
        item.requirement.source, item.requirement.name, item.version,
        item.artifact.url.rsplit("/", 1)[-1], item.metadata_digest,
    ))
    document = {
        "schema": "netops-publisher-catalogue-v2", "releases": [], "python_files": [],
        "publisher_records": [record], "python_records": [],
    }
    if damage == "source":
        record["source"] = "pypi:substitute"
    elif damage == "filename":
        record["filename"] = "../escape.whl"
    elif damage == "missing-pin":
        record.pop("metadata_digest")
    elif damage == "extra-field":
        record["trusted"] = True
    elif damage == "duplicate":
        document["publisher_records"].append(dict(record))
    elif damage == "non-list":
        document["publisher_records"] = {}
    elif damage == "too-many":
        document["publisher_records"] *= 1025
    elif damage == "unknown-schema":
        document["schema"] = "unreviewed"
    elif damage == "python-record":
        document["python_records"] = [{"trusted": True, "md5": "not-sha256"}]
    else:
        document["releases"] = [c.wire(item)]
    retained_resource(monkeypatch, json.dumps(document).encode())
    with pytest.raises(c.ContractError):
        _default_family._RetainedCatalogue.load()


@pytest.mark.parametrize("damage", ["duplicate-json", "redirect", "late", "cancel", "oversize"])
def test_new_catalog_client_retains_real_transport_and_original_deadline(monkeypatch, damage):
    item, _, content, _ = publisher_case()
    clock, cancel = Clock(), Cancel()
    if damage == "duplicate-json":
        content = b'{"info":{},"info":{},"urls":[]}'
    elif damage == "oversize":
        content = b" " * (1024 * 1024 + 1)
    seed = _PublisherSeed(item.requirement.source, item.requirement.name, item.version,
                          item.artifact.url.rsplit("/", 1)[-1],
                          hashlib.sha256(content).hexdigest())

    def transform(response):
        if damage == "redirect":
            return AssetResponse("https://unapproved.invalid/json", response.content)
        if damage == "late":
            clock.value = 50.0
        if damage == "cancel":
            cancel.value = True
        return response

    transport, calls = transport_for(monkeypatch, content, transform=transform)
    with pytest.raises((c.ContractError, TimeoutError, InterruptedError)):
        _SeededPublisherMetadata((seed,), transport).observe(
            item.requirement, TARGET, clock, cancel, 50.0,
        )
    assert len(calls) == 1 and calls[0][0] == seed.url


def test_missing_optional_parser_blocks_before_metadata_http_not_native_import(monkeypatch):
    item, _, content, _ = publisher_case()
    seed = _PublisherSeed(item.requirement.source, item.requirement.name, item.version,
                          item.artifact.url.rsplit("/", 1)[-1], item.metadata_digest)
    transport, calls = transport_for(monkeypatch, content)
    original = builtins.__import__

    def importing(name, *args, **kwargs):
        if name in ("packaging.requirements", "packaging.utils"):
            raise ImportError("Source boundary: optional resolver parser is absent")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", importing)
    sources = _seeded_publishers((seed,), transport)
    result = _FamilyResolver(sources).resolve(
        (item.requirement,), (TARGET,), D, Clock(), Cancel(), 50.0,
    )
    assert result.lock is None and result.needs[0].reason == "metadata-parser-required"
    assert calls == []


@pytest.mark.parametrize("damage", ["none", "members", "format", "version", "family"])
def test_role_aliases_share_archive_only_with_identical_complete_contributions(damage):
    release = _Release(
        _Requirement("native-python", "python", "python.org", "native"), "3.12.1",
        "zip", (sys.platform,), (platform.machine(),), (), D,
        LockedAsset("python.org", "native-python",
                    "https://www.python.org/ftp/python/3.12.1/python.zip", D, 1),
        members=(ManagedMember("python.exe", D, 1, True),),
    )
    alias = replace(
        release, requirement=replace(release.requirement, name="controller-python",
                                     context="controller"),
        artifact=replace(release.artifact, dependency="controller-python"),
    )
    if damage == "members":
        alias = replace(alias, members=(replace(alias.members[0], path="wheels/other.whl"),))
    elif damage == "format":
        alias = replace(alias, format="tar.gz")
    elif damage == "version":
        alias = replace(alias, version="9.0")
    elif damage == "family":
        alias = replace(alias, requirement=replace(alias.requirement, family="executable"))
    if damage == "none":
        assert _contributions((release, alias)) == (release,)
    else:
        with pytest.raises(c.ContractError):
            _contributions((release, alias))


def test_selected_ansible_controller_does_not_force_unselected_molecule():
    spec = _InstallationSpec(
        str(Path(_guided._existing_python())), D, platform.python_version(), "linux",
        (_Wheel("wheels/netops.whl", "netops-toolkit", __version__, D),
         _Wheel("wheels/ansible.whl", "ansible-core", "2.18.0", D)),
        controller=True,
    )
    assert {wheel.distribution for wheel in spec.wheels} == {"netops-toolkit", "ansible-core"}


@pytest.mark.parametrize("expired", [True, False])
def test_live_download_never_extends_original_source_expiry(tmp_path, monkeypatch, expired):
    asset = LockedAsset("python.org", "native-python",
                        "https://www.python.org/ftp/python/3.12.1/python.zip", D, 1)
    deadline = time.monotonic() - 1 if expired else time.monotonic() + 0.3
    acquisition = _PublisherAcquisition((asset,), (tmp_path / "missing",), D, deadline)
    calls = []

    def read(self, url, timeout, limit):
        calls.append(timeout)
        time.sleep(0.4)
        return AssetResponse(url, b"x")

    monkeypatch.setattr(HttpsAssetTransport, "read", read)
    with pytest.raises(c.ContractError):
        acquisition.read(asset.url, 30.0, 2)
    assert not calls if expired else len(calls) == 1 and 0 < calls[0] <= 0.3
    assert not tuple(tmp_path.iterdir())


def compiler_case(root, monkeypatch):
    registry, scope, context, service, _ = service_case(root, monkeypatch)
    diagnosis = _guided._diagnose(service, scope, context, probe=True)
    selected = _guided._Selection((("native-python", "install"),), ())
    native = diagnosis.components[0]
    native_requirement = _default_family._requirement(
        registry.entry(native.dependency),
    )
    interpreter = Path(_guided._existing_python()).read_bytes()
    digest = hashlib.sha256(interpreter).hexdigest()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(Path(_guided._existing_python()).name, interpreter)
    native_bytes = buffer.getvalue()
    asset = LockedAsset("python.org", "native-python",
                        "https://www.python.org/ftp/python/" + platform.python_version() + "/native.zip",
                        hashlib.sha256(native_bytes).hexdigest(), len(native_bytes))
    record = {"id": 321, "url": asset.url, "filesize": asset.size}
    native_json = json.dumps(record).encode()
    native_release = _Release(
        native_requirement, platform.python_version(), "zip", (sys.platform,),
        (platform.machine(),), (), hashlib.sha256(native_json).hexdigest(), asset,
        members=(ManagedMember(Path(_guided._existing_python()).name, digest,
                               len(interpreter), True),),
    )
    filename = "netops_toolkit-" + __version__ + "-py3-none-any.whl"
    wheel_buffer = io.BytesIO()
    with zipfile.ZipFile(wheel_buffer, "w") as archive:
        prefix = "netops_toolkit-" + __version__ + ".dist-info/"
        files = {
            "netops/__init__.py": b'"""Synthetic publisher SOURCE transport fixture."""\n',
            "netops/__main__.py": b'"""SOURCE boundary stand-in, not product qualification."""\n',
            prefix + "METADATA": (
                "Metadata-Version: 2.1\nName: netops-toolkit\nVersion: " + __version__ + "\n"
            ).encode(),
            prefix + "WHEEL":
                b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        }
        files[prefix + "RECORD"] = (
            "\n".join(path + ",," for path in (*files, prefix + "RECORD")) + "\n"
        ).encode()
        for name, content in files.items():
            archive.writestr(name, content)
    wheel = wheel_buffer.getvalue()
    wheel_digest = hashlib.sha256(wheel).hexdigest()
    document = {
        "info": {"name": "netops-toolkit", "version": __version__, "requires_python": ">=3.9",
                 "requires_dist": [], "provides_extra": []},
        "urls": [{"filename": filename, "url": "https://files.pythonhosted.org/packages/" + filename,
                  "size": len(wheel), "packagetype": "bdist_wheel", "yanked": False,
                  "digests": {"sha256": wheel_digest}}],
    }
    wheel_json = json.dumps(document).encode()
    seed = _PublisherSeed("pypi:netops-toolkit", "netops-toolkit", __version__, filename,
                          hashlib.sha256(wheel_json).hexdigest())
    retained_resource(monkeypatch, json.dumps({
        "schema": "netops-publisher-catalogue-v2", "releases": [],
        "python_files": [{"release": c.wire(native_release), "file_id": 321}],
        "publisher_records": [c.wire(seed)],
        "python_records": [],
    }).encode())
    responses = {
        seed.url: wheel_json,
        "https://www.python.org/api/v2/downloads/release_file/321/": native_json,
    }
    calls = []

    def read(self, url, timeout, limit, clock, cancel):
        calls.append(url)
        return AssetResponse(url, responses[url])

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", read)
    cache = root.parent / "netops-publisher-cache"
    cache.mkdir()
    (cache / asset.sha256).mkdir()
    (cache / wheel_digest).mkdir()
    (cache / asset.sha256 / "native.zip").write_bytes(native_bytes)
    (cache / wheel_digest / filename).write_bytes(wheel)
    return registry, scope, diagnosis, selected, native_release, calls


def test_actual_default_compiler_consumes_catalog_cache_and_future_context(tmp_path, monkeypatch):
    root = tmp_path / "new-root"
    registry, scope, diagnosis, selected, native, calls = compiler_case(root, monkeypatch)
    metadata = _default_family._default_metadata(registry)
    assert metadata.installation is None and not metadata.archives
    candidate, needs = metadata.resolve(diagnosis, selected, scope, root, registry)
    assert candidate is not None and not needs
    manifest, contexts = _setup._manifest(candidate.document, root, registry)
    assert manifest.installation.wheels[0].distribution == "netops-toolkit"
    assert manifest.installation.python_digest == native.members[0].digest
    assert manifest.consuming_contexts == (contexts["native"].digest,)
    assert candidate.family_lock.roots[-1] == _toolkit_requirement()
    assert len(calls) == 2 and not root.exists()
    assert {Path(item["cache_path"]).parent.parent for item in candidate.document["archives"]} == {
        root.parent / "netops-publisher-cache",
    }


def test_missing_cache_only_compiles_prospective_exact_downloads_without_effects(tmp_path, monkeypatch):
    root = tmp_path / "missing-cache"
    registry, scope, diagnosis, selected, native, _ = compiler_case(root, monkeypatch)
    (root.parent / "netops-publisher-cache" / native.artifact.sha256 / "native.zip").unlink()
    candidate, needs = _default_family._default_metadata(registry).resolve(
        diagnosis, selected, scope, root, registry,
    )
    assert candidate is not None and not needs and candidate.acquisition is not None
    assert candidate.acquisition.assets[0] == native.artifact
    assert "acquisition" not in candidate.document
    assert selected.components == (("native-python", "install"),) and not root.exists()


def test_public_default_exact_downloads_still_reject_wrong_bytes_before_staging(
    tmp_path, monkeypatch, capsys,
):
    root = tmp_path / "download"
    registry, scope, diagnosis, selected, native, _ = compiler_case(root, monkeypatch)
    native_path = root.parent / "netops-publisher-cache" / native.artifact.sha256 / "native.zip"
    expected = native_path.read_bytes()
    native_path.unlink()
    acquired = []
    metadata_read = HttpsAssetTransport.read_bounded

    def read(self, url, timeout, limit, clock, cancel):
        if url != native.artifact.url and not url.startswith("https://files.pythonhosted.org/"):
            return metadata_read(self, url, timeout, limit, clock, cancel)
        acquired.append(url)
        if url == native.artifact.url:
            return AssetResponse(url, expected)
        return AssetResponse(url, b"substituted publisher bytes must be rejected")

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", read)

    def ask(prompt):
        if "Reuse/Install/Decline" in prompt:
            return "install"
        match = re.search(r"Type '((?:create|install) [0-9a-f]{64})'", prompt)
        return match.group(1) if match else ""

    monkeypatch.setattr("builtins.input", ask)
    # The second cached wheel must be absent to exercise actual approved
    # transport, not a fallback replacing a present corrupt cache.
    for path in (root.parent / "netops-publisher-cache").glob("*/*.whl"):
        path.unlink()
    assert setup.main(["install", "--root", str(root), "--capability", "native.stdlib"]) == 3
    output = capsys.readouterr().out
    assert "exact-reviewed-publisher-downloads" in output and acquired
    assert all(url.startswith(("https://www.python.org/", "https://files.pythonhosted.org/"))
               for url in acquired)
    assert root.exists() and not any(
        path.name.startswith(("installation-", "generation-")) for path in root.iterdir()
    )
    protected = _setup._owned(root, False)
    state, _ = _setup._load_host(protected)
    assert not state.read(_setup._ROOT).payload["generations"]
    assert registry.digest and not native_path.exists()


def test_public_default_download_owner_stages_verifies_then_declines_activation(
    tmp_path, monkeypatch, capsys,
):
    root = tmp_path / "acquired"
    registry, scope, diagnosis, selected, native, _ = compiler_case(root, monkeypatch)
    cache = root.parent / "netops-publisher-cache"
    bytes_by_url = {}
    metadata = _default_family._default_metadata(registry)
    # Reuse the actual public diagnosis; the synthetic publisher package is
    # never evidence of the current toolkit source or platform qualification.
    candidate, needs = metadata.resolve(diagnosis, selected, scope, root, registry)
    assert candidate is not None and not needs
    for archive in candidate.document["archives"]:
        path = Path(archive["cache_path"])
        bytes_by_url[archive["asset"]["url"]] = path.read_bytes()
        path.unlink()
    acquired = []
    metadata_read = HttpsAssetTransport.read_bounded

    def read(self, url, timeout, limit, clock, cancel):
        if url not in bytes_by_url:
            return metadata_read(self, url, timeout, limit, clock, cancel)
        acquired.append(url)
        return AssetResponse(url, bytes_by_url[url])

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", read)

    install_grants = []

    def ask(prompt):
        if "Reuse/Install/Decline" in prompt:
            return "install"
        match = re.search(r"Type '((?:create|install) [0-9a-f]{64})'", prompt)
        if match and match.group(1).startswith("install "):
            if install_grants:
                return ""
            install_grants.append(match.group(1))
        return match.group(1) if match else ""

    monkeypatch.setattr("builtins.input", ask)
    assert setup.main(["install", "--root", str(root), "--capability", "native.stdlib"]) == 3
    output = capsys.readouterr().out
    (tmp_path / "public-output.txt").write_text(output, encoding="utf-8")
    assert "review-activation-plan" in output and acquired == list(bytes_by_url)
    protected = _setup._owned(root, False)
    state, _ = _setup._load_host(protected)
    from netops.ansible.policy import contracts as lc

    assert state.read(_setup._CONTROL).payload["pointer"] == c.public_object(
        c.wire(lc.AbsentPointer("absent", 0)),
    )
    assert state.read(_setup._ROOT).payload["generations"]
    assert not tuple(cache.glob("*/*")) and not native.artifact.url.startswith("file:")


def test_layout_requires_independent_interpreter_pin_not_current_hash_alone(tmp_path, monkeypatch):
    root = tmp_path / "bad-pin"
    registry, scope, diagnosis, selected, _, _ = compiler_case(root, monkeypatch)
    metadata = _default_family._default_metadata(registry)
    candidate, needs = metadata.resolve(diagnosis, selected, scope, root, registry)
    assert candidate is not None and not needs
    lock = candidate.family_lock
    native = lock.releases[0]
    damaged = replace(native, members=(replace(native.members[0], digest=D),))
    observations = tuple(replace(
        observation, releases=tuple(damaged if release == native else release
                                   for release in observation.releases),
    ) for observation in lock.observations)
    changed = replace(lock, releases=(damaged, *lock.releases[1:]), observations=observations)
    with pytest.raises(_LayoutUnavailable) as error:
        _LockLayout().compile(changed, root, Clock(), Cancel(), 50.0)
    assert error.value.reason == "independently-locked-existing-interpreter-required"


@pytest.mark.parametrize("create", [False, True])
def test_public_default_first_run_uses_real_compiler_without_private_descriptor(
    tmp_path, monkeypatch, capsys, create,
):
    root = tmp_path / "public"
    compiler_case(root, monkeypatch)
    prompts = []

    def ask(prompt):
        prompts.append(prompt)
        if "Reuse/Install/Decline" in prompt:
            return "install"
        match = re.search(r"Type '(create [0-9a-f]{64})'", prompt)
        if match and create:
            return match.group(1)
        return ""

    monkeypatch.setattr("builtins.input", ask)
    assert setup.main(["install", "--root", str(root), "--capability", "native.stdlib"]) == 3
    output = capsys.readouterr().out
    assert "Pinned candidate (not readiness or consent)" in output
    assert any("Type 'create " in prompt for prompt in prompts)
    assert root.exists() is create
    if create:
        assert any("Type 'install " in prompt for prompt in prompts)
        protected = _setup._owned(root, False)
        state, documents = _setup._load_host(protected)
        assert len(documents) == 1 and documents[0]["family_lock"]
        assert "installation-" not in " ".join(path.name for path in root.iterdir())
        assert state.read(_setup._ROOT).payload["generations"] == ()
    else:
        assert "Creation declined; nothing changed." in output
