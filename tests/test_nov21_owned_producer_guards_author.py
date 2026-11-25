"""Author guards over private producer I/O; no publisher or platform qualification."""

import hashlib
import io
import os
import zipfile
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.artifacts import _root
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationError,
    bind_lifecycle,
    lifecycle_plan_digest,
)
from netops.ansible.policy.lifecycle_evidence import lifecycle_arguments_digest
from netops.dependencies import _owned_build as build
from netops.dependencies._owned_source import _OwnedBuildAsset
from tests.policy.test_lifecycle_execution import decision_for, environment
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel
from tests.test_owned_source_author import Clock, build_case, source_case


@pytest.mark.parametrize("change", [
    {"source": ()}, {"cache": ()}, {"toolchain": ()},
    {"source": []}, {"source": (object(),)},
    {"python": "unknown"}, {"platform": "foreign"}, {"python_version": "0.0.0"},
    {"consuming_contexts": ("bad",)}, {"context_digest": "bad"},
])
def test_invalid_build_spec_cannot_issue_host(tmp_path, monkeypatch, change):
    host, _ = build_case(tmp_path, monkeypatch)
    with pytest.raises((c.ContractError, AttributeError)):
        replace(host.spec, **change)


def test_spec_and_root_input_contracts(tmp_path, monkeypatch):
    host, _ = build_case(tmp_path, monkeypatch)
    with pytest.raises(c.ContractError):
        build._Input("valid", "1" * 64, build._LIMIT + 1, "2" * 64)
    with pytest.raises(c.ContractError):
        build._ToolchainFile("relative", "1" * 64, "2" * 64)
    with pytest.raises(c.ContractError):
        build._OfflineBuildHost(object(), host.consuming_root, host.spec)
    with pytest.raises(c.ContractError):
        build._OfflineBuildHost(host.root, host.root, host.spec)
    with pytest.raises(c.ContractError):
        _OwnedBuildAsset("owned-local-build", "toolkit-wheel-bundle", "1" * 64,
                         build._LIMIT + 1, "2" * 64, "3" * 64)
    with _root(host.root) as root:
        with pytest.raises(c.ContractError):
            build._read_member(root, "nested/member", 1)
        with pytest.raises(c.ContractError):
            build._write_member(root, "nested/member", b"")


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_producer_clock_rejects(tmp_path, monkeypatch, value):
    host, calls = build_case(tmp_path, monkeypatch)
    clock = Clock()
    clock.monotonic = lambda: value
    with pytest.raises(c.ContractError):
        host.produce(clock, Cancel(), 100.0)
    assert not calls


@pytest.mark.parametrize("cancelled", [True, False])
def test_cancel_and_deadline_precede_build(tmp_path, monkeypatch, cancelled):
    host, calls = build_case(tmp_path, monkeypatch)
    cancel = Cancel()
    cancel.value = cancelled
    with pytest.raises(InterruptedError if cancelled else TimeoutError):
        host.produce(Clock(), cancel, 10.0)
    assert not calls


@pytest.mark.parametrize("area", ["root", "source", "cache", "output"])
def test_missing_expected_and_extra_members_reject(tmp_path, monkeypatch, area):
    host, _ = build_case(tmp_path, monkeypatch)
    host.produce(Clock(), Cancel(), 100.0)
    base = Path(host.root.path)
    if area == "root":
        (base / "extra").write_bytes(b"unknown")
    elif area == "source":
        (base / "source/netops/__init__.py").unlink()
    elif area == "cache":
        (base / "cache/setuptools-84.whl").write_bytes(b"known-size-changed")
    else:
        (base / "output/netops_toolkit-1.0.tar.gz").unlink()
    with pytest.raises((AuthorizationError, OSError)):
        host.inspect(Clock(), Cancel(), 100.0)


def test_external_tool_digest_and_regular_file_guards(tmp_path, monkeypatch):
    host, _ = build_case(tmp_path, monkeypatch)
    tool = tmp_path / "owned-tool"
    tool.write_bytes(b"tool")
    pinned = build._ToolchainFile(str(tool), hashlib.sha256(b"tool").hexdigest(), "1" * 64)
    assert build._external(pinned)["digest"] == pinned.digest
    tool.write_bytes(b"edit")
    with pytest.raises(AuthorizationError):
        build._external(pinned)
    with pytest.raises(AuthorizationError):
        build._external(replace(pinned, path=str(tmp_path)))


@pytest.mark.parametrize("change", ["missing", "extra", "size", "digest"])
def test_built_wheel_exact_source_member_census_rejects(tmp_path, monkeypatch, change):
    host, _ = build_case(tmp_path, monkeypatch)
    host.produce(Clock(), Cancel(), 100.0)
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        if change != "missing":
            archive.writestr(
                "netops/__init__.py",
                b"module-extra" if change == "size" else b"edited" if change == "digest" else b"module",
            )
        if change == "extra":
            archive.writestr("netops/extra.py", b"unknown")
    (Path(host.root.path) / "output/netops_toolkit-1.0-py3-none-any.whl").write_bytes(
        content.getvalue(),
    )
    with pytest.raises(AuthorizationError):
        host.inspect(Clock(), Cancel(), 100.0)


@pytest.mark.parametrize("change", [
    {"archive": "tar"}, {"installation": None}, {"scope": c.InstallScope((), (), False, True)},
    {"consuming_contexts": ()},
])
def test_consuming_manifest_drift_rejects(tmp_path, change):
    source, _, manifest = source_case(tmp_path)
    with pytest.raises((AuthorizationError, c.ContractError)):
        source.guard(replace(manifest, **change), Clock(), Cancel(), 100.0)


def test_issued_process_binding_and_post_inspection_cancel_deadline(tmp_path, monkeypatch):
    source, host, manifest = source_case(tmp_path)
    monkeypatch.setattr(source, "_issued", replace(source._issued, _pid=os.getpid() + 1))
    with pytest.raises(AuthorizationError):
        source.guard(manifest, Clock(), Cancel(), 100.0)
    source, host, manifest = source_case(tmp_path)
    cancel = Cancel()
    original = host.inspect

    def cancelled_after(*args):
        result = original(*args)
        cancel.value = True
        return result

    monkeypatch.setattr(host, "inspect", cancelled_after)
    with pytest.raises(InterruptedError):
        source.guard(manifest, Clock(), cancel, 100.0)
    cancel.value = False
    monkeypatch.setattr(host, "inspect", original)
    clock = Clock()
    samples = iter((10.0, 100.0))
    clock.monotonic = lambda: next(samples)
    with pytest.raises(TimeoutError):
        source.guard(manifest, clock, cancel, 100.0)


def admitted_owned(tmp_path, policy):
    source, _, manifest = source_case(tmp_path)
    plan, _, port, state, _, consent, broker, clock, _ = environment(
        tmp_path, policy, "dependency-download",
    )
    result = source._issued._result
    port.seed(source.asset.source_id, {
        "schema": port.read("source").payload["schema"], "content": tuple(result.content),
        "content_digest": source.asset.sha256, "manifest": c.wire(source.asset),
    })
    step = c.public_object({
        **dict(plan.content["steps"][0]), "source": {
            "source_id": source.asset.source_id, "artifact_digest": source.asset.sha256,
            "registry_digest": plan.registry_digest, "descriptor_digest": c.digest(source.asset),
        },
    })
    port.seed("step", step)
    occurrence = replace(plan.effects[0], arguments_digest=lifecycle_arguments_digest(step))
    plan = replace(plan, effects=(occurrence,), content=c.public_object({
        **dict(plan.content), "steps": (step,),
    }))
    plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    binding = bind_lifecycle(plan)
    grant = broker.issue_lifecycle(
        plan, consent.review(plan, 10.0, 20.0), decision_for(policy, binding), 10.0,
    )
    session = broker.consume_lifecycle(grant, binding, 10.0)
    effect = lc.LifecycleEffectBinding(
        binding, str(uuid4()), state.snapshot_lifecycle(binding).revision, occurrence.occurrence_id,
    )
    return source, manifest, broker, broker.permit_lifecycle(session, effect, 10.0), effect, clock


def test_private_acquisition_spends_real_broker_permit_once(tmp_path, policy):
    source, manifest, broker, permit, effect, clock = admitted_owned(tmp_path, policy)
    receipt = source.acquire(manifest, broker, permit, effect, clock, Cancel())
    assert receipt.content == source._issued._result.content
    assert receipt.digest == source.asset.sha256
    with pytest.raises(AuthorizationError):
        source.acquire(manifest, broker, permit, effect, clock, Cancel())


def test_entered_source_failure_revokes_original_plan(tmp_path, policy, monkeypatch):
    source, manifest, broker, permit, effect, clock = admitted_owned(tmp_path, policy)
    original = source._current
    calls = []

    def fail_after_entry(*args):
        calls.append(True)
        if len(calls) == 2:
            raise OSError("synthetic own-source read failure")
        return original(*args)

    monkeypatch.setattr(source, "_current", fail_after_entry)
    with pytest.raises(OSError):
        source.acquire(manifest, broker, permit, effect, clock, Cancel())
    assert (effect.lifecycle.kind, effect.lifecycle.plan_id) in broker._life_revoked
