"""Author protected-byte CAS controls with fake functional observations, not Q03."""

from pathlib import Path

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.dependencies._composition import _ManagedRun
from netops.dependencies._managed import ProtectedGenerationFiles
from netops.dependencies._setup import _owned
from tests.test_nov19_independent_controller_execution import Cancel
from tests.test_nov19_successor_public_installer import managed_environment


def protected_case(tmp_path):
    """Use real protected byte publication, explicitly fake HTTP/functional ports."""
    env = managed_environment()
    root = _owned(tmp_path / "owned-native-guard", True)
    files = ProtectedGenerationFiles(root)
    env["state"].files = files
    service = env["service"]
    plan = service.plan(env["scope"], env["context"])
    result = service.provision(
        plan, service.review(plan, env["clock"].now, 30.0), Cancel(),
    )
    assert all(step.status == c.OutcomeStatus.SUCCEEDED for step in result.steps), result
    assert result.pending_actions == ("review-activation-plan",)
    assert env["state"].pointer() == lc.AbsentPointer("absent", 0)
    env["root"] = Path(root.path)
    env["actual_files"] = files
    return env


def test_public_cas_rehashes_actual_protected_bytes_without_duplicate_functional_probe(
    tmp_path, monkeypatch,
):
    """A live probe and exact full-tree guard admit one factual public pointer CAS."""
    env = protected_case(tmp_path)
    calls = []
    original_probe, original_guard = _ManagedRun.probe, _ManagedRun.guard_probe

    def probe(self, *, retained):
        calls.append("functional")
        return original_probe(self, retained=retained)

    def guard(self):
        calls.append("full-tree-guard")
        return original_guard(self)

    monkeypatch.setattr(_ManagedRun, "probe", probe)
    monkeypatch.setattr(_ManagedRun, "guard_probe", guard)
    service = env["service"]
    plan = service.plan(env["scope"], env["context"])
    result = service.provision(plan, service.review(plan, env["clock"].now, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    assert calls == ["functional", "full-tree-guard"]
    pointer = env["state"].pointer()
    assert pointer.pointer_digest == c.digest((plan.lifecycle.generation, 1))
    assert pointer.revision == 1


@pytest.mark.parametrize("fault", ["member", "extra", "sentinel", "deadline", "cancel"])
def test_public_cas_full_protected_guard_rejects_drift_or_stale_live_proof(
    tmp_path, monkeypatch, fault,
):
    """Post-probe drift rejects before CAS without changing original deadlines."""
    env = protected_case(tmp_path)
    original_guard = _ManagedRun.guard_probe
    called = []
    cancel = Cancel()

    def guard(self):
        called.append(True)
        tree = env["root"] / ("generation-" + c.digest(env["manifest"].generation_id))
        if fault == "member":
            target = tree / env["manifest"].members[0].path
            value = target.read_bytes()
            target.write_bytes(bytes([value[0] ^ 1]) + value[1:])
        elif fault == "extra":
            (tree / "owned-author-extra.txt").write_bytes(b"owned drift control")
        elif fault == "sentinel":
            (tree / "netops-generation.json").write_bytes(b"{}")
        elif fault == "deadline":
            # Deterministic source-unit clock only, never the actual native proof.
            env["clock"].now = self.scope.deadline
        else:
            cancel.value = True
        return original_guard(self)

    monkeypatch.setattr(_ManagedRun, "guard_probe", guard)
    service = env["service"]
    plan = service.plan(env["scope"], env["context"])
    result = service.provision(plan, service.review(plan, env["clock"].now, 30.0), cancel)
    assert called == [True]
    assert result.status != c.OutcomeStatus.SUCCEEDED and result.errors
    assert result.steps[0].status == c.OutcomeStatus.SUCCEEDED
    assert env["state"].pointer() == lc.AbsentPointer("absent", 0)
    assert result.active_generation_id is None
