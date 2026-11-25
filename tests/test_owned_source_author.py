"""Author private producer controls; synthetic ports are never source qualification."""

import hashlib
import io
import os
import sys
import threading
import zipfile
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from uuid import uuid4

import pytest

from netops.ansible import artifact_platform as storage
from netops.ansible import contracts as c
from netops.ansible.artifacts import _root, _write_file
from netops.ansible.policy.authorization import AuthorizationError
from netops.dependencies import _owned_build as build
from netops.dependencies import _setup
from netops.dependencies._installation import _InstallationSpec, _Wheel
from netops.dependencies._managed import ManagedGenerationManifest, ManagedMember
from netops.dependencies._owned_source import _OwnedBuildAsset, _OwnedSource, _ProducedBuild
from netops.dependencies.service import DependencyRegistry
from tests.test_i02_author_lifecycle import Cancel

QUALIFIED = "1" * 64


class Clock:
    def monotonic(self):
        return 10.0

    def utc_now(self):
        raise AssertionError("not a source authority")


def source_case(tmp_path):
    registry = DependencyRegistry.load()
    generation = str(uuid4())
    context = _setup._context(tmp_path, registry)
    contexts = _setup._contexts(tmp_path, generation, False)
    name = "netops_toolkit-1.0-py3-none-any.whl"
    value = b"explicit synthetic wheel; no executed installation"
    member = ManagedMember(name, hashlib.sha256(value).hexdigest(), len(value))
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(name, value)
    content = stream.getvalue()
    spec = _InstallationSpec(sys.executable, "2" * 64, "3.12.10", sys.platform,
                             (_Wheel(name, "netops-toolkit", "1.0", member.digest),))
    receipt = c.public_object({
        "schema": "owned-offline-build-v1", "producer_id": QUALIFIED,
        "source_seal": "3" * 64, "build_inputs": ({"source": "synthetic"},),
        "toolchain": ({"tool": "synthetic"},), "cache_inputs": ({"cache": "synthetic"},),
        "interpreter": {"path": spec.python, "digest": spec.python_digest,
                        "version": spec.python_version, "platform": spec.platform},
        "operation": "offline-wheel-sdist-and-cache-assembly", "exit_code": 0,
        "outputs": ({"output": "synthetic"},), "members": (c.wire(member),),
        "root": ("synthetic", 1, 2), "consuming_root": (str(tmp_path), 3, 4),
        "context_digest": c.digest(context),
        "consuming_contexts": tuple(sorted(item.digest for item in contexts.values())),
        "archive_digest": hashlib.sha256(content).hexdigest(), "archive_size": len(content),
    })

    class Host:
        identity = QUALIFIED
        result = _ProducedBuild(receipt, content)

        def inspect(self, clock, cancel, deadline):
            return self.result

    host = Host()
    source = _OwnedSource(host, Clock(), Cancel(), 100.0)
    manifest = ManagedGenerationManifest(
        generation, source.asset, "zip", (member,),
        c.InstallScope(("native.stdlib",), (), False, False), context,
        tuple(sorted(item.digest for item in contexts.values())), installation=spec,
    )
    return source, host, manifest


def test_serialized_facts_never_reconstruct_private_source(tmp_path):
    source, host, manifest = source_case(tmp_path)
    document = _setup._owned_document(source, manifest.installation, manifest.generation_id)
    registry = DependencyRegistry.load()
    with pytest.raises(c.ContractError):
        _setup._manifest(document, tmp_path, registry)
    selected, _ = _setup._manifest(document, tmp_path, registry, source)
    assert selected == manifest
    assert "url" not in c.wire(source.asset)
    assert source.asset.dependency == "toolkit-wheel-bundle"
    assert source.asset.source_id == "owned-local-build"
    with pytest.raises(FrozenInstanceError):
        source._issued._result = host.result


@pytest.mark.parametrize("field", (
    "producer_id", "source_seal", "build_inputs", "cache_inputs", "toolchain",
    "interpreter", "outputs", "members", "root", "consuming_root",
    "context_digest", "consuming_contexts", "operation", "exit_code",
    "archive_digest", "archive_size",
))
def test_receipt_or_input_substitution_rejects_consuming_guard(tmp_path, field):
    source, host, manifest = source_case(tmp_path)
    source.guard(manifest, Clock(), Cancel(), 100.0)
    original = dict(host.result.receipt)
    changed = "4" * 64 if type(original[field]) is str else 99
    host.result = replace(host.result, receipt=c.public_object({**original, field: changed}))
    with pytest.raises((AuthorizationError, c.ContractError)):
        source.guard(manifest, Clock(), Cancel(), 100.0)


def test_content_context_and_thread_replay_fail_closed(tmp_path):
    source, host, manifest = source_case(tmp_path)
    host.result = replace(host.result, content=host.result.content + b"substitution")
    with pytest.raises(AuthorizationError):
        source.guard(manifest, Clock(), Cancel(), 100.0)
    source, host, manifest = source_case(tmp_path)
    with pytest.raises(AuthorizationError):
        source.guard(replace(manifest, consuming_contexts=("5" * 64,)), Clock(), Cancel(), 100.0)
    errors = []

    def replay():
        try:
            source.guard(manifest, Clock(), Cancel(), 100.0)
        except AuthorizationError:
            errors.append("rejected")

    thread = threading.Thread(target=replay)
    thread.start()
    thread.join()
    assert errors == ["rejected"]


def test_original_deadline_cancel_and_asset_substitution_reject(tmp_path):
    source, host, manifest = source_case(tmp_path)
    with pytest.raises(TimeoutError):
        source.guard(manifest, Clock(), Cancel(), 10.0)
    cancel = Cancel()
    cancel.cancelled = True
    # The existing fixture uses a boolean flag; do not renew a deadline to
    # turn a denied source operation into an inert successful observation.
    cancel.is_cancelled = lambda: True
    with pytest.raises(InterruptedError):
        source.guard(manifest, Clock(), cancel, 100.0)
    other = replace(source.asset, receipt_digest="6" * 64)
    with pytest.raises(AuthorizationError):
        source.guard(replace(manifest, asset=other), Clock(), Cancel(), 100.0)
    with pytest.raises(c.ContractError):
        _OwnedBuildAsset("python.org", "native-python", other.sha256, other.size,
                         other.producer_id, other.receipt_digest)


def build_case(tmp_path, monkeypatch):
    root = _setup._owned(tmp_path / "producer", True)
    consuming = _setup._owned(tmp_path / "consumer", True)
    with _root(root) as parent:
        for directory in ("source", "cache"):
            storage.mkdir(parent, directory)
            handle = storage.open_directory(parent, directory)
            try:
                _write_file(handle, "pyproject.toml" if directory == "source" else "setuptools-84.whl",
                            b"source" if directory == "source" else b"known")
                if directory == "source":
                    storage.mkdir(handle, "netops")
                    package = storage.open_directory(handle, "netops")
                    try:
                        build._write_member(package, "__init__.py", b"module")
                    finally:
                        storage.close(package)
            finally:
                storage.close(handle)
    python = Path(sys.base_prefix) / "python.exe" if os.name == "nt" else Path(sys.executable)
    spec = build._BuildSpec(
        (build._Input("pyproject.toml", hashlib.sha256(b"source").hexdigest(), 6, QUALIFIED),
         build._Input("netops/__init__.py", hashlib.sha256(b"module").hexdigest(), 6, QUALIFIED)),
        (build._Input("setuptools-84.whl", hashlib.sha256(b"known").hexdigest(), 5, QUALIFIED),),
        (build._ToolchainFile(str(python), hashlib.sha256(python.read_bytes()).hexdigest(),
                              QUALIFIED),), str(python),
        ".".join(str(item) for item in sys.version_info[:3]), sys.platform,
        "7" * 64, ("8" * 64,),
    )
    calls = []

    def run(command, cwd, clock, cancel, deadline):
        calls.append(command)
        with _root(root) as parent:
            output = storage.open_directory(parent, "build-output")
            try:
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, "w") as archive:
                    archive.writestr("netops/__init__.py", b"module")
                _write_file(output, "netops_toolkit-1.0-py3-none-any.whl", stream.getvalue())
                _write_file(output, "netops_toolkit-1.0.tar.gz", b"built-sdist")
            finally:
                storage.close(output)
        return b"synthetic build port"

    monkeypatch.setattr(build, "_run", run)
    return build._OfflineBuildHost(root, consuming, spec), calls


def test_producer_ledger_requires_trusted_constructor_and_exact_known_cache(tmp_path, monkeypatch):
    host, calls = build_case(tmp_path, monkeypatch)
    with pytest.raises(AuthorizationError):
        host.inspect(Clock(), Cancel(), 100.0)
    digest = host.produce(Clock(), Cancel(), 100.0)
    result = host.inspect(Clock(), Cancel(), 100.0)
    assert len(calls) == 1 and "-S" in calls[0] and build._BUILD_BACKEND in calls[0]
    assert result.receipt["exit_code"] == 0
    sibling = build._OfflineBuildHost(host.root, host.consuming_root, host.spec,
                                      ledger_digest=digest)
    assert sibling.inspect(Clock(), Cancel(), 100.0) == result
    with _root(host.root) as parent:
        cache = storage.open_directory(parent, "cache")
        try:
            _write_file(cache, "unknown.whl", b"not qualified")
        finally:
            storage.close(cache)
    with pytest.raises(AuthorizationError):
        sibling.inspect(Clock(), Cancel(), 100.0)
    assert len(calls) == 1


@pytest.mark.parametrize("area", ("source", "cache", "output", "ledger"))
def test_own_ledger_does_not_authorize_mutated_files(tmp_path, monkeypatch, area):
    host, _ = build_case(tmp_path, monkeypatch)
    host.produce(Clock(), Cancel(), 100.0)
    relative = {
        "source": "source/pyproject.toml", "cache": "cache/setuptools-84.whl",
        "output": "output/netops_toolkit-1.0-py3-none-any.whl",
        "ledger": "owned-build-ledger.json",
    }[area]
    path = Path(host.root.path) / relative
    with path.open("ab") as stream:
        stream.write(b"changed")
    with pytest.raises((AuthorizationError, OSError, c.ContractError)):
        host.inspect(Clock(), Cancel(), 100.0)


def test_private_module_census_is_closed_not_directory_exclusion():
    registry = DependencyRegistry.load()
    registry.validate_public_sources(Path(__file__).resolve().parents[1] / "netops")
    assert _OwnedSource.__module__ == "netops.dependencies._owned_source"
