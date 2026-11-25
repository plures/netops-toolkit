"""Criteria-derived original permit and actual producer output-denial controls."""

import hashlib
import os
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import AuthorizationError
from netops.dependencies import _owned_build as build
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel
from tests.test_nov21_owned_producer_guards_author import admitted_owned
from tests.test_owned_source_author import Clock, build_case


@pytest.mark.parametrize("drift", [
    "reconciled-effect", "missing-scope", "occurrence", "step-shape", "source",
])
def test_ac003_original_acquisition_denials_precede_broker_entry(tmp_path, policy, drift):
    source, manifest, broker, permit, effect, clock = admitted_owned(tmp_path, policy)
    original_effect = effect
    binding = effect.lifecycle
    if drift == "reconciled-effect":
        effect = replace(effect, occurrence_id="unregistered-occurrence")
    elif drift == "occurrence":
        selected = replace(binding.effects[0], kind="dependency-stage")
        effect = replace(effect, lifecycle=replace(binding, effects=(selected,)))
    elif drift == "step-shape":
        effect = replace(effect, lifecycle=replace(
            binding, content=c.public_object({**dict(binding.content), "steps": {}}),
        ))
    elif drift == "source":
        step = dict(binding.content["steps"][0])
        step["source"] = {**dict(step["source"]), "artifact_digest": "9" * 64}
        effect = replace(effect, lifecycle=replace(
            binding, content=c.public_object({**dict(binding.content), "steps": (step,)}),
        ))
    entered = []

    class ObservedBroker:
        """Real admitted broker with one deliberately corrupted observation."""

        def reconcile_lifecycle(self, value):
            assert value is permit
            actual = broker.reconcile_lifecycle(value)
            assert actual == original_effect
            return actual if drift == "reconciled-effect" else effect

        def _life_scope(self, value):
            actual = broker._life_scope(value)
            assert actual is not None
            return None if drift == "missing-scope" else actual

        def enter_lifecycle(self, *args):
            entered.append(args)
            return broker.enter_lifecycle(*args)

    with pytest.raises(AuthorizationError):
        source.acquire(manifest, ObservedBroker(), permit, effect, clock, Cancel())
    # A later real-broker rejection must not mask omission of this boundary.
    assert entered == []


def test_ac001_extra_producer_root_prevents_even_build_dispatch(tmp_path, monkeypatch):
    host, calls = build_case(tmp_path, monkeypatch)
    (Path(host.root.path) / "unexpected-member").write_bytes(b"not in reviewed plan")
    with pytest.raises(AuthorizationError):
        host.produce(Clock(), Cancel(), 100.0)
    assert calls == []
    assert not (Path(host.root.path) / "owned-build-ledger.json").exists()


def test_ac001_source_change_during_build_cannot_publish_ledger(tmp_path, monkeypatch):
    host, calls = build_case(tmp_path, monkeypatch)
    original = build._run

    def changed_after_build(*args):
        value = original(*args)
        (Path(host.root.path) / "source/netops/__init__.py").write_bytes(b"edited")
        return value

    monkeypatch.setattr(build, "_run", changed_after_build)
    with pytest.raises(AuthorizationError):
        host.produce(Clock(), Cancel(), 100.0)
    assert len(calls) == 1
    assert not (Path(host.root.path) / "owned-build-ledger.json").exists()


def test_ac001_same_byte_source_identity_replacement_cannot_publish_ledger(tmp_path, monkeypatch):
    from netops.ansible.artifacts import _root

    host, calls = build_case(tmp_path, monkeypatch)
    original = build._run

    def replaced_after_build(*args):
        value = original(*args)
        source = Path(host.root.path) / "source/netops/__init__.py"
        replacement = source.with_suffix(".replacement")
        with _root(host.root) as root, build._parent(root, ("source", "netops")) as parent:
            build._write_member(parent, replacement.name, source.read_bytes())
        replacement.replace(source)
        return value

    monkeypatch.setattr(build, "_run", replaced_after_build)
    with pytest.raises(AuthorizationError):
        host.produce(Clock(), Cancel(), 100.0)
    assert len(calls) == 1
    assert not (Path(host.root.path) / "owned-build-ledger.json").exists()


@pytest.mark.parametrize("drift", ["extra-output", "unsafe-name"])
def test_ac001_invalid_actual_build_outputs_cannot_publish_ledger(tmp_path, monkeypatch, drift):
    host, calls = build_case(tmp_path, monkeypatch)
    original = build._run

    def changed_after_build(*args):
        value = original(*args)
        output = Path(host.root.path) / "build-output"
        if drift == "extra-output":
            (output / "unexpected-member").write_bytes(b"not built from reviewed source")
        else:
            (output / "netops_toolkit-1.0.tar.gz").rename(output / "untrusted.tar.gz")
        return value

    monkeypatch.setattr(build, "_run", changed_after_build)
    with pytest.raises(AuthorizationError):
        host.produce(Clock(), Cancel(), 100.0)
    assert len(calls) == 1
    assert not (Path(host.root.path) / "owned-build-ledger.json").exists()
    sealed = Path(host.root.path) / "output"
    if drift == "extra-output":
        assert list(sealed.iterdir()) == []
    else:
        assert not (sealed / "untrusted.tar.gz").exists()


@pytest.mark.parametrize("value", [object(), {"receipt": {}, "content": b""}])
def test_ac001_untyped_host_observation_cannot_issue_private_capability(value):
    from netops.dependencies._owned_source import _OwnedSource

    class Host:
        identity = "1" * 64

        def inspect(self, clock, cancel, deadline):
            return value

    with pytest.raises(AuthorizationError):
        _OwnedSource(Host(), Clock(), Cancel(), 100.0)


def test_ac001_structurally_similar_input_is_not_trusted_input_record(tmp_path, monkeypatch):
    host, _ = build_case(tmp_path, monkeypatch)

    class SimilarInput(build._Input):
        pass

    item = host.spec.source[0]
    with pytest.raises(c.ContractError):
        replace(host.spec, source=(
            SimilarInput(item.path, item.digest, item.size, item.qualification_ref),
            *host.spec.source[1:],
        ))


def test_ac001_assembly_bound_is_checked_after_complete_actual_zip(tmp_path, monkeypatch):
    host, _ = build_case(tmp_path, monkeypatch)
    host.produce(Clock(), Cancel(), 100.0)
    largest = max(path.stat().st_size for path in (Path(host.root.path) / "output").iterdir())
    # Existing small members remain individually legal; only aggregate ZIP is
    # over the selected resource ceiling. No large allocation or weakened check.
    monkeypatch.setattr(build, "_LIMIT", largest + 1)
    with pytest.raises(AuthorizationError):
        host._assemble(Clock(), Cancel(), 100.0)


def test_ac001_unsafe_sealed_output_name_rejects_reinspection(tmp_path, monkeypatch):
    host, _ = build_case(tmp_path, monkeypatch)
    host.produce(Clock(), Cancel(), 100.0)
    output = Path(host.root.path) / "output"
    (output / "netops_toolkit-1.0.tar.gz").rename(output / "untrusted.tar.gz")
    original = build._read_member
    reads = []

    def observed_read(parent, name, limit):
        reads.append(name)
        return original(parent, name, limit)

    monkeypatch.setattr(build, "_read_member", observed_read)
    with pytest.raises(AuthorizationError):
        host.inspect(Clock(), Cancel(), 100.0)
    assert "untrusted.tar.gz" not in reads


def test_ac001_hardlinked_build_output_cannot_be_sealed(tmp_path, monkeypatch):
    host, _ = build_case(tmp_path, monkeypatch)
    original = build._run

    def link_after_build(*args):
        value = original(*args)
        output = Path(host.root.path) / "build-output/netops_toolkit-1.0.tar.gz"
        os.link(output, tmp_path / "owned-hardlink")
        return value

    monkeypatch.setattr(build, "_run", link_after_build)
    with pytest.raises(AuthorizationError):
        host.produce(Clock(), Cancel(), 100.0)
    assert not (Path(host.root.path) / "output/netops_toolkit-1.0.tar.gz").exists()
    assert not (Path(host.root.path) / "owned-build-ledger.json").exists()


def test_ac001_output_metadata_drift_during_read_cannot_be_sealed(tmp_path, monkeypatch):
    host, _ = build_case(tmp_path, monkeypatch)
    original_fdopen = os.fdopen
    target = Path(host.root.path) / "build-output/netops_toolkit-1.0.tar.gz"
    drifted = []

    @contextmanager
    def observed_read(fd, *args, **kwargs):
        stream = original_fdopen(fd, *args, **kwargs)

        class ReadThenDrift:
            def read(self, *read_args):
                value = stream.read(*read_args)
                if target.exists() and os.fstat(fd).st_ino == target.stat().st_ino:
                    info = target.stat()
                    os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns + 100_000_000))
                    drifted.append(True)
                return value

        try:
            yield ReadThenDrift()
        finally:
            stream.close()

    monkeypatch.setattr(os, "fdopen", observed_read)
    with pytest.raises(AuthorizationError):
        host.produce(Clock(), Cancel(), 100.0)
    assert drifted == [True]
    assert not (Path(host.root.path) / "output/netops_toolkit-1.0.tar.gz").exists()
    assert not (Path(host.root.path) / "owned-build-ledger.json").exists()


def test_ac001_observed_reparse_tool_is_denied_before_open(tmp_path, monkeypatch):
    tool = tmp_path / "owned-tool"
    tool.write_bytes(b"tool")
    pinned = build._ToolchainFile(str(tool), hashlib.sha256(b"tool").hexdigest(), "1" * 64)
    original = Path.lstat

    def reparse(path, *args, **kwargs):
        actual = original(path, *args, **kwargs)
        if path == tool:
            return SimpleNamespace(
                st_mode=actual.st_mode, st_file_attributes=0x400,
                st_nlink=actual.st_nlink, st_size=actual.st_size,
                st_dev=actual.st_dev, st_ino=actual.st_ino,
                st_mtime_ns=actual.st_mtime_ns, st_ctime_ns=actual.st_ctime_ns,
            )
        return actual

    monkeypatch.setattr(Path, "lstat", reparse)
    with pytest.raises(AuthorizationError):
        build._external(pinned)


def test_ac001_cache_output_name_collision_cannot_assemble(tmp_path, monkeypatch):
    from netops.ansible import artifact_platform as storage
    from netops.ansible.artifacts import _root

    host, _ = build_case(tmp_path, monkeypatch)
    host.produce(Clock(), Cancel(), 100.0)
    name = "netops_toolkit-1.0-py3-none-any.whl"
    value = (Path(host.root.path) / "output" / name).read_bytes()
    with _root(host.root) as root:
        cache = storage.open_directory(root, "cache")
        try:
            build._write_member(cache, name, value)
        finally:
            storage.close(cache)
    # Post-construction descriptor corruption must not bypass the independent
    # consuming assembly collision guard. This is not a trusted new BuildSpec.
    object.__setattr__(host.spec, "cache", (
        *host.spec.cache, build._Input(name, hashlib.sha256(value).hexdigest(), len(value), "1" * 64),
    ))
    with pytest.raises(AuthorizationError):
        host._assemble(Clock(), Cancel(), 100.0)
