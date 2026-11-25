"""Independent consuming managed-root source proofs, never platform qualification."""

from __future__ import annotations

import threading
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.controller import ControllerInstallation, FixedLaunch, ProcessResult
from netops.ansible.controller_control import _Stop
from netops.ansible.controller_generation import _PinnedControllerProcesses
from netops.ansible.controller_protocol import ProtocolError
from netops.dependencies.runs import OwnedGenerationRuns
from tests.policy.test_lifecycle_execution import OWNER
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_nov19_independent_controller_execution import Cancel, actual_host, bridge
from tests.test_s02_managed_installation_binding import binding_case


def source_case(tmp_path, policy):
    """Real typed managed verifier/records, with explicitly fake effect ports."""
    verifier, context, state, _ = binding_case(tmp_path, policy)
    runs = OwnedGenerationRuns(
        state, verifier._root_resource, verifier._active, OWNER,
        context.context.policy_identity, (verifier._generation,), verifier._generation.generation_id,
    )
    runs.initialize()
    _, installed_digest = verifier._selection(context, state)
    installation = ControllerInstallation(
        context, "linux", "/source-unit/bin/python", installed_digest, "b" * 64,
    )

    class Processes:
        def __init__(self):
            self.calls = []
            self.cleanup = c.CleanupOutcome("succeeded")
            self.error = None
            self.inspect = None

        def verify(self, current, owned):
            assert current == context and owned is state and runs.pins()[0]["holders"]
            self.calls.append("pinned-verify")
            return installation

        def run(self, launch, private, cancel):
            assert runs.pins()[0]["holders"]
            assert private == b"independent-source-only-private-frame"
            self.calls.append("pinned-run")
            if self.inspect is not None:
                self.inspect()
            return ProcessResult((), 0, self.cleanup, self.error)

    processes = Processes()
    adapter = _PinnedControllerProcesses(processes, verifier, state, runs)
    return verifier, context, state, runs, installation, processes, adapter


def launch_for(context, installation):
    # Authentic source-unit host entry; its effect ports are fake and no
    # ProcessPort below spawns an OS process or certifies this installation.
    env = actual_host()
    request = replace(env[0], context=context.context)
    plan = replace(env[1], context=context.context)
    return FixedLaunch(
        installation, c.ControllerRequest(request, plan), bridge(env), 40.0, 310.0,
    )


def test_t30_consuming_bridge_acquires_before_actual_adapter_and_releases_after_join(
    tmp_path, policy,
):
    _, context, state, runs, installed, process, adapter = source_case(tmp_path, policy)
    assert adapter.verify(context, state) == installed
    assert runs.pins()[0]["holders"] == ()
    result = adapter.run(
        launch_for(context, installed), b"independent-source-only-private-frame", _Stop(Cancel()),
    )
    assert result.cleanup == c.CleanupOutcome("succeeded") and result.error is None
    assert process.calls == ["pinned-verify", "pinned-verify", "pinned-run"]
    assert runs.pins()[0]["holders"] == ()
    assert runs.pins()[0]["revision"] == 4


@pytest.mark.parametrize("fault", [
    "pointer-digest", "root-owner", "control-owner", "registry",
    "root-schema", "control-schema", "setup-disabled", "admission-disabled",
    "pointer-generation", "registry-control", "registry-added",
])
def test_t30_current_root_pointer_and_registration_drift_block_before_adapter(
    tmp_path, policy, fault,
):
    verifier, context, state, runs, _, process, adapter = source_case(tmp_path, policy)
    assert adapter.verify(context, state) is not None
    process.calls.clear()
    pin_resource = "dependency-run-pin-" + c.digest(verifier._generation)
    pin_before = state.read(pin_resource)
    if fault == "pointer-digest":
        data = c.wire(state.read(verifier._active).payload)
        data["pointer"]["pointer_digest"] = "f" * 64
        state.seed(verifier._active, data)
    elif fault in ("root-owner", "control-owner"):
        resource = verifier._root_resource if fault == "root-owner" else verifier._active
        state.seed(resource, c.wire(state.read(resource).payload), owner="f" * 64)
    elif fault == "registry":
        data = c.wire(state.read(verifier._root_resource).payload)
        data["root_manifest"]["registered_manifests"] = []
        state.seed(verifier._root_resource, data)
    elif fault in ("root-schema", "registry-control", "registry-added"):
        data = c.wire(state.read(verifier._root_resource).payload)
        if fault == "root-schema":
            data["schema"] = "not-an-i02-owned-root"
        elif fault == "registry-control":
            data["root_manifest"]["control_resource"] = "different-control"
        else:
            extra = c.wire(verifier._descriptor)
            extra["generation_id"] = "ae7dc3ea-d6c9-4f63-b2bc-0d73cae74691"
            data["root_manifest"]["registered_manifests"].append(extra)
        state.seed(verifier._root_resource, data)
    else:
        data = c.wire(state.read(verifier._active).payload)
        if fault == "control-schema":
            data["schema"] = "not-an-i02-owned-control"
        elif fault == "pointer-generation":
            data["pointer"]["active_generation_id"] = "ae7dc3ea-d6c9-4f63-b2bc-0d73cae74691"
        else:
            data["setup_enabled" if fault == "setup-disabled" else "admission_enabled"] = False
        state.seed(verifier._active, data)
    with pytest.raises((ProtocolError, c.ContractError)):
        adapter.verify(context, state)
    assert not process.calls
    # Corrupt root/control observations cannot be used to read a clean
    # pins projection; inspect the exact previously owned record directly.
    record = state.read(pin_resource)
    assert record.payload["holders"] == ()
    assert record == pin_before, "Invalid current ownership/identity must block before any pin CAS"
    assert runs._live == {}


@pytest.mark.parametrize("cleanup", [
    c.CleanupOutcome(),
    c.CleanupOutcome("failed", ("actual-owned-worker",)),
    c.CleanupOutcome("failed", errors=(c.SafeError(
        c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
    ),)),
])
def test_t04_nonjoined_dispatch_preserves_primary_and_all_owned_refs_with_live_pin(
    tmp_path, policy, cleanup,
):
    _, context, state, runs, installed, process, adapter = source_case(tmp_path, policy)
    primary = c.SafeError(
        c.ErrorCategory.EXECUTION, c.ReasonCode.CONTROL_LOST, c.Stage.CONTROLLER,
    )
    process.cleanup, process.error = cleanup, primary
    result = adapter.run(
        launch_for(context, installed), b"independent-source-only-private-frame", _Stop(Cancel()),
    )
    assert result.error is primary
    assert result.cleanup.status == "failed"
    assert result.cleanup.remaining_refs == (*cleanup.remaining_refs, "owned-generation-run-pin")
    assert result.cleanup.errors[:-1] == cleanup.errors
    assert runs.pins()[0]["holders"]
    fresh = _PinnedControllerProcesses(process, adapter._verifier, state)
    assert fresh.runs.pins() == runs.pins()
    assert fresh.runs.drain(Cancel(), type("Clock", (), {"monotonic": lambda self: 10.0})(), 20.0) is False


def test_t04_actual_thread_join_not_pid_or_elapsed_time_owns_pin_lifetime(tmp_path, policy):
    _, context, _, runs, installed, process, adapter = source_case(tmp_path, policy)
    entered, finish = threading.Event(), threading.Event()
    result = []
    stop = _Stop(Cancel())

    def inspect():
        entered.set()
        assert finish.wait(2.0)

    process.inspect = inspect
    thread = threading.Thread(target=lambda: result.append(adapter.run(
        launch_for(context, installed), b"independent-source-only-private-frame", stop,
    )))
    thread.start()
    try:
        assert entered.wait(2.0)
        callbacks = tuple(runs._live.values())
        assert len(callbacks) == 1
        cancel, join = callbacks[0]
        assert join(0.01) is False and runs.pins()[0]["holders"]
        cancel()
        assert stop.is_cancelled() and runs.pins()[0]["holders"]
    finally:
        finish.set()
        thread.join(3.0)
    assert not thread.is_alive() and result
    assert runs.pins()[0]["holders"] == ()
    assert join(0.01) is True


@pytest.mark.parametrize("fault", ["state", "context"])
def test_t30_public_verifier_call_rejects_foreign_selection_before_any_read(
    tmp_path, policy, fault,
):
    _, context, state, runs, _, process, adapter = source_case(tmp_path, policy)
    received = object() if fault == "state" else state
    selected = context if fault == "state" else c.ControllerContext(
        replace(context.context, controller_id="foreign"),
    )
    with pytest.raises(ProtocolError):
        adapter.verify(selected, received)
    assert not process.calls and runs.pins()[0]["holders"] == ()


def test_t13_nonprivate_stop_cannot_dispatch_or_consume_run_pin(tmp_path, policy):
    _, context, _, runs, installed, process, adapter = source_case(tmp_path, policy)
    with pytest.raises(ProtocolError):
        adapter.run(launch_for(context, installed), b"not-authority", Cancel())
    assert not process.calls and runs.pins()[0]["holders"] == ()


@pytest.mark.parametrize("field,value", [
    ("root_resource", "different-root"), ("control_resource", "different-control"),
    ("owner", "f" * 64), ("selected_id", "ae7dc3ea-d6c9-4f63-b2bc-0d73cae74690"),
    ("generations", ()), ("state", object()), ("identity", None),
])
def test_t30_bootstrap_rejects_a_distinct_root_control_owner_or_generation_store(
    tmp_path, policy, field, value,
):
    verifier, _, state, runs, _, process, _ = source_case(tmp_path, policy)
    setattr(runs, field, value)
    with pytest.raises(c.ContractError):
        _PinnedControllerProcesses(process, verifier, state, runs)
    assert not process.calls


def test_t30_foreign_installed_digest_is_rejected_and_observation_pin_released(
    tmp_path, policy, monkeypatch,
):
    _, context, state, runs, installed, process, adapter = source_case(tmp_path, policy)
    monkeypatch.setattr(process, "verify", lambda *_: replace(installed, installation_digest="f" * 64))
    with pytest.raises(ProtocolError) as error:
        adapter.verify(context, state)
    assert error.value.reason == c.ReasonCode.DEPENDENCY_NOT_READY
    assert runs.pins()[0]["holders"] == ()
    result = adapter.run(
        launch_for(context, installed), b"independent-source-only-private-frame", _Stop(Cancel()),
    )
    assert result.error.reason == c.ReasonCode.DEPENDENCY_NOT_READY
    assert result.cleanup.status == "succeeded" and runs.pins()[0]["holders"] == ()
    assert not process.calls


def test_t04_pin_release_failure_preserves_primary_and_remains_durable(
    tmp_path, policy, monkeypatch,
):
    _, context, _, runs, installed, process, adapter = source_case(tmp_path, policy)
    primary = c.SafeError(
        c.ErrorCategory.EXECUTION, c.ReasonCode.CONTROL_LOST, c.Stage.CONTROLLER,
    )
    process.error = primary

    def cannot_release(pin):
        raise OSError("source-unit ownership/CAS failure")

    monkeypatch.setattr(runs, "release", cannot_release)
    result = adapter.run(
        launch_for(context, installed), b"independent-source-only-private-frame", _Stop(Cancel()),
    )
    assert result.error is primary
    assert result.cleanup.remaining_refs == ("owned-generation-run-pin",)
    assert result.cleanup.status == "failed" and runs.pins()[0]["holders"]


def test_t30_cancel_during_consuming_observation_cannot_return_readiness(
    tmp_path, policy, monkeypatch,
):
    _, context, state, runs, installed, process, adapter = source_case(tmp_path, policy)

    def observed_but_cancelled(*_):
        assert len(runs._live) == 1
        cancel, join = next(iter(runs._live.values()))
        assert not join(0.001)
        cancel()
        return installed

    monkeypatch.setattr(process, "verify", observed_but_cancelled)
    with pytest.raises(ProtocolError) as failure:
        adapter.verify(context, state)
    assert failure.value.reason == c.ReasonCode.CANCELLED
    assert runs.pins()[0]["holders"] == ()


@pytest.mark.parametrize("response,expected_reason", [
    ("none", c.ReasonCode.HANDOFF_INVALID),
    ("exception", c.ReasonCode.CONTROL_LOST),
    ("untyped", c.ReasonCode.HANDOFF_INVALID),
])
def test_t04_adapter_failure_keeps_unjoined_pin_without_reconstructing_success(
    tmp_path, policy, monkeypatch, response, expected_reason,
):
    _, context, _, runs, installed, process, adapter = source_case(tmp_path, policy)

    def broken_dispatch(*_):
        assert runs.pins()[0]["holders"]
        if response == "exception":
            raise OSError("source-only owned adapter failure")
        return None if response == "none" else object()

    monkeypatch.setattr(process, "run", broken_dispatch)
    result = adapter.run(
        launch_for(context, installed), b"independent-source-only-private-frame", _Stop(Cancel()),
    )
    # Malformed handoff and lost execution are distinct declared error
    # categories. Keep one exact reason per input, never an allowed-set assert.
    assert result.error.reason == expected_reason
    assert result.cleanup.status == "failed"
    assert result.cleanup.remaining_refs == ("owned-generation-run-pin",)
    assert runs.pins()[0]["holders"]


def test_t30_unavailable_readiness_releases_only_the_observation_pin(tmp_path, policy, monkeypatch):
    _, context, state, runs, installed, process, adapter = source_case(tmp_path, policy)
    monkeypatch.setattr(process, "verify", lambda *_: None)
    assert adapter.verify(context, state) is None
    assert runs.pins()[0]["holders"] == ()
    result = adapter.run(
        launch_for(context, installed), b"independent-source-only-private-frame", _Stop(Cancel()),
    )
    assert result.error.reason == c.ReasonCode.DEPENDENCY_NOT_READY
    assert result.cleanup.status == "succeeded" and runs.pins()[0]["holders"] == ()
