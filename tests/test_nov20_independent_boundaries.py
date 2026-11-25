"""Independent I02/S02 safety probes; fake OS effects are not qualification."""

from __future__ import annotations

import logging
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from netops.ansible import _worker_group as group
from netops.ansible import contracts as c
from netops.ansible.controller_observations import _ControllerIo
from netops.ansible.controller_protocol import ProtocolError
from netops.dependencies.adapters import LocalDependencyAdapter
from netops.dependencies.service import ConsumingContext, DependencyRegistry


class GroupEffects:
    def __init__(self, *, identity=True, exists=False, wait_fails=False):
        self.valid = identity
        self.leftover = exists
        self.wait_fails = wait_fails
        self.actions = []

    def identity(self, process):
        self.actions.append("identity")
        return self.valid

    def signal(self, process, selected):
        self.actions.append(("signal", selected))

    def pause(self, seconds):
        self.actions.append(("pause", seconds))

    def exists(self, process):
        self.actions.append("exists-after-wait")
        return self.leftover

    def finished(self, process):
        return False

    def wait(self, timeout):
        self.actions.append(("wait", timeout))
        if self.wait_fails:
            raise TimeoutError("NOV20_EXTERNAL_SECRET")


def owned_group(monkeypatch, effects):
    # This replaces only the external platform symbol port; no real Linux proof is claimed.
    monkeypatch.setattr(group, "signal", SimpleNamespace(SIGTERM=15, SIGKILL=9))
    manager = group._OwnedLinuxGroup(effects)
    process = SimpleNamespace(wait=effects.wait)
    return manager, process


@pytest.mark.parametrize("fault", ["leftover", "wait", "none"])
def test_s02_group_absence_and_reap_order_are_not_launcher_exit(monkeypatch, fault):
    effects = GroupEffects(exists=fault == "leftover", wait_fails=fault == "wait")
    manager, process = owned_group(monkeypatch, effects)
    manager.attach(process, "local-test-operation")
    outcome = manager.close()
    assert outcome.status == ("succeeded" if fault == "none" else "failed")
    if fault != "none":
        assert outcome.remaining_refs == ("owned-linux-runner-group",)
        assert outcome.errors[0].category == c.ErrorCategory.CLEANUP
        assert outcome.errors[0].next_action != ""
    wait_position = next(i for i, item in enumerate(effects.actions)
                         if isinstance(item, tuple) and item[0] == "wait")
    assert not any(isinstance(item, tuple) and item[0] == "signal"
                   for item in effects.actions[wait_position + 1:])
    assert "NOV20_EXTERNAL_SECRET" not in c.canonical_bytes(outcome).decode()
    first_actions = list(effects.actions)
    assert manager.close() == outcome
    assert effects.actions == first_actions, "Cleanup must not signal/replay twice"


def test_s02_unowned_group_never_signalled_and_cleanup_truthful(monkeypatch):
    effects = GroupEffects(identity=False)
    manager, process = owned_group(monkeypatch, effects)
    with pytest.raises(ProtocolError):
        manager.attach(process, "operation")
    outcome = manager.close()
    assert outcome.status == "failed"
    assert not any(isinstance(item, tuple) and item[0] == "signal" for item in effects.actions)


def test_s02_cancel_before_factory_never_creates_work(monkeypatch):
    effects = GroupEffects()
    manager, _ = owned_group(monkeypatch, effects)
    assert manager.close().status == "succeeded"
    factory = Mock(side_effect=AssertionError("cancelled factory invoked"))
    with pytest.raises(ProtocolError) as caught:
        manager.launch(factory, "operation")
    assert caught.value.reason == c.ReasonCode.CANCELLED
    factory.assert_not_called()


@pytest.mark.parametrize("sink_fails", [False, True])
def test_t32_cleanup_return_failure_paired_and_sink_cannot_replace_primary(caplog, sink_fails):
    observation = _ControllerIo()
    primary = c.SafeError(c.ErrorCategory.EXECUTION, c.ReasonCode.APPLY_FAILED, c.Stage.APPLY)
    cleanup = c.CleanupOutcome("failed", ("owned-leftover",), (primary,))
    if sink_fails:
        observation._logger = SimpleNamespace(info=Mock(side_effect=RuntimeError("sink secret")))
    with caplog.at_level(logging.INFO):
        result = observation.cleanup("worker.cleanup", "NONPUBLIC_OPERATION_ID", lambda: cleanup)
    assert result is cleanup
    assert sum(observation.counts.values()) == 2
    assert any(key[1] == "failed" for key in observation.counts)
    assert not any(key[1] == "succeeded" for key in observation.counts)
    if sink_fails:
        assert observation.sink_failures == 2
    else:
        rows = [r for r in caplog.records if r.getMessage() == "controller.io"]
        assert [r.outcome for r in rows] == ["started", "failed"]
        assert rows[-1].category == "cleanup" and rows[-1].next_action != "none"
        assert rows[-1].metric == "netops.controller.io.count"
        assert rows[-1].duration_metric == "netops.controller.io.duration_seconds"
        assert all(r.duration >= 0 for r in rows)
        assert all("NONPUBLIC_OPERATION_ID" not in str(r.__dict__) for r in rows)
        assert all("operation_ref" not in r.metric_dimensions for r in rows)


def test_t32_span_sink_failure_preserves_exact_primary_exception():
    observation = _ControllerIo()
    observation._logger = SimpleNamespace(info=Mock(side_effect=RuntimeError("sink secret")))
    primary = ProtocolError(c.ReasonCode.CONTROL_LOST)
    with pytest.raises(ProtocolError) as caught:
        with observation.span("process.control", "private-operation"):
            raise primary
    assert caught.value is primary
    assert observation.sink_failures == 2
    assert any(key[3] == "control-lost" for key in observation.counts)


@pytest.mark.parametrize("deadline", [True, 1, float("nan"), float("inf"), -1.0])
def test_i02_bad_probe_budget_never_launches_external_process(monkeypatch, deadline):
    registry = DependencyRegistry.load()
    entry = next(item for item in registry.entries if item.adapter == "python")
    context = ConsumingContext("fixture", "win32", "AMD64", r"C:\owned\python.exe", "", entry.context)
    launch = Mock(side_effect=AssertionError("invalid deadline spawned process"))
    monkeypatch.setattr("netops.dependencies.adapters.subprocess.Popen", launch)
    result = LocalDependencyAdapter({context.id: context}).probe(entry, context, deadline)
    assert result.status != "available"
    assert result.evidence_digest is None
    assert result.next_action != "none"
    launch.assert_not_called()


def test_i02_context_role_mismatch_cannot_reuse_ready_dependency(monkeypatch):
    registry = DependencyRegistry.load()
    entry = next(item for item in registry.entries if item.adapter == "python")
    context = ConsumingContext(
        "fixture", "win32", "AMD64", r"C:\owned\python.exe", "", entry.context,
    )
    wrong = replace(context, role="controller" if entry.context == "native" else "native")
    launch = Mock(side_effect=AssertionError("wrong context launched process"))
    monkeypatch.setattr("netops.dependencies.adapters.subprocess.Popen", launch)
    result = LocalDependencyAdapter({wrong.id: wrong}).probe(entry, wrong, 10**10 * 1.0)
    assert result.status == "blocked" and result.reason == "context-unavailable"
    assert result.evidence_digest is None
    launch.assert_not_called()


def test_i02_packaged_qualification_is_not_mutable_or_inferred():
    registry = DependencyRegistry.load()
    external = registry.qualification
    assert external["qualified"] == []
    external["qualified"].append({"fabricated": True})
    assert registry.qualification["qualified"] == []
    assert registry.is_qualified({"platform": "win32"}) is False
