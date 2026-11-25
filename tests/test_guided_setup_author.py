"""Author-owned guarded setup controls; fake effects are not qualification."""

from contextlib import nullcontext
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.artifacts import ArtifactError, OwnedState, ProtectedRoot
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import AuthorizationError
from netops.dependencies import _setup
from netops.dependencies._installation import _installed_parts
from netops.dependencies._uninstall import ManagedUninstall
from netops.dependencies.runs import OwnedGenerationRuns
from tests.policy.test_lifecycle_execution import OWNER, Clock, FilePort
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel
from tests.test_i02_public_flow import public_case


@pytest.mark.parametrize("enhanced", (False, True))
def test_default_catalog_is_full_and_does_not_create_root(tmp_path, capsys, enhanced):
    root = tmp_path / "not-created"
    args = ["plan", "--root", str(root)] + (["--enhanced"] if enhanced else [])
    assert _setup._main(args) == 3
    output = capsys.readouterr().out
    assert "ansible" in output
    assert ("molecule" in output) is enhanced
    assert "default selection remains full toolkit" in output
    assert not root.exists()


def test_exact_owned_bytes_cache_keeps_live_read_and_owner_proofs(tmp_path, policy, monkeypatch):
    identity = policy[0]
    port = FilePort(tmp_path, identity)
    first = port.seed("sample", {"value": 1})
    root = ProtectedRoot(str(tmp_path), 0, 0, c.OutputIntent(("text",), str(tmp_path)), "unit-fake")
    state = OwnedState(root, OWNER)
    monkeypatch.setattr(state, "_parent", lambda _: nullcontext(None))
    import netops.ansible.artifacts as artifacts

    content = [first.to_bytes()]
    monkeypatch.setattr(artifacts, "_read_file", lambda *_: content[0])
    assert state.read("sample") is state.read("sample")
    content[0] = replace(first, revision=1, payload=c.public_object({"value": 2})).to_bytes()
    assert state.read("sample").payload["value"] == 2
    content[0] = replace(first, ownership_token="f" * 64).to_bytes()
    with pytest.raises(ArtifactError) as wrong_owner:
        state.read("sample")
    content[0] = first.to_bytes()
    state.read("sample")

    def deny(*_):
        raise ArtifactError(wrong_owner.value.error)

    monkeypatch.setattr(artifacts, "_read_file", deny)
    with pytest.raises(ArtifactError):
        state.read("sample")


def pins_case(tmp_path, policy):
    service, scope, context, port, state, effects, engine, private = public_case(tmp_path, policy)
    # Use the real staged-then-activation producer. These external effects are
    # explicitly fake source fixtures, never installed-source qualification.
    stage = service.plan(scope, context)
    service.provision(stage, service.review(stage, 10.0, 20.0), Cancel())
    activation = service.plan(scope, context)
    service.provision(activation, service.review(activation, 10.0, 20.0), Cancel())
    manifest = state.manifests[0]
    generation = lc.GenerationBinding(
        manifest.generation_id, 0, manifest.content_digest, c.digest(manifest),
    )
    runs = OwnedGenerationRuns(
        port, "managed-root", "managed-control", OWNER, policy[0], (generation,), generation.generation_id,
    )
    runs.initialize()
    return runs, generation, port


def test_durable_pin_blocks_sibling_and_does_not_expire(tmp_path, policy):
    runs, generation, port = pins_case(tmp_path, policy)
    pin = runs.acquire(generation, lambda: None, lambda _: True)
    sibling = OwnedGenerationRuns(
        port, "managed-root", "managed-control", OWNER, policy[0], (generation,), generation.generation_id,
    )
    assert sibling.pins()[0]["holders"]
    assert not sibling.drain(Cancel(), Clock(), 10000.0)
    with pytest.raises(c.ContractError):
        sibling.release(pin)
    runs.release(pin)
    assert sibling.pins()[0]["holders"] == ()


def test_stop_admission_and_join_use_same_owned_state(tmp_path, policy):
    runs, generation, port = pins_case(tmp_path, policy)
    calls = []
    runs.acquire(generation, lambda: calls.append("cancel"), lambda remaining: remaining > 0)
    runs.stop_admission()
    with pytest.raises(c.ContractError):
        runs.acquire(generation, lambda: None, lambda _: True)
    assert runs.drain(Cancel(), Clock(), 20.0)
    assert calls == ["cancel"]
    runs.start_admission(generation)
    assert port.read("managed-control").payload["admission_enabled"] is True


def test_public_uninstall_is_one_use_admitted_and_records_actual_failure(tmp_path, policy, monkeypatch):
    service, scope, context, port, state, effects, engine, private = public_case(tmp_path, policy)
    plan = service.plan(scope, context)
    service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    manifest = state.manifests[0]
    generation = lc.GenerationBinding(manifest.generation_id, 0, manifest.content_digest, c.digest(manifest))
    state.runs = OwnedGenerationRuns(
        port, "managed-root", "managed-control", OWNER, policy[0], (generation,), generation.generation_id,
    )
    state.runs.initialize()
    uninstall = service.plan_uninstall(state.manifests[0].generation_id, context)
    consent = private.review(uninstall, 10.0, 20.0)
    calls = []

    def fail(self, removed, remaining):
        calls.append("actual-handler")
        remaining.extend(("owned-first", "owned-untouched-second"))
        removed.append("owned-removed")
        raise OSError("unit-only primary failure")

    monkeypatch.setattr(ManagedUninstall, "_remove_selected", fail)
    result = service.uninstall(uninstall, consent)
    assert calls == ["actual-handler"]
    assert result.status == c.OutcomeStatus.PARTIAL and result.errors
    assert result.pending_actions == ("owned-first", "owned-untouched-second")
    assert state.pointer() == lc.AbsentPointer("absent", 0)
    receipt = port.read("dependency-uninstall-result-" + uninstall.plan_id)
    assert receipt.payload["remaining"] == result.pending_actions
    assert receipt.payload["primary_errors"]
    retried = service.uninstall(uninstall, consent)
    assert retried.status == c.OutcomeStatus.BLOCKED and retried.errors
    assert calls == ["actual-handler"]


def test_public_uninstall_records_factual_terminal_completion(tmp_path, policy, monkeypatch):
    service, scope, context, port, state, effects, engine, private = public_case(tmp_path, policy)
    plan = service.plan(scope, context)
    service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    manifest = state.manifests[0]
    generation = lc.GenerationBinding(manifest.generation_id, 0, manifest.content_digest, c.digest(manifest))
    state.runs = OwnedGenerationRuns(
        port, "managed-root", "managed-control", OWNER, policy[0], (generation,), generation.generation_id,
    )
    state.runs.initialize()
    uninstall = service.plan_uninstall(generation.generation_id, context)
    consent = private.review(uninstall, 10.0, 20.0)
    monkeypatch.setattr(ManagedUninstall, "_remove_selected", lambda self, removed, remaining: removed.append("owned"))
    result = service.uninstall(uninstall, consent)
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    assert result.pending_actions == () and not result.errors
    assert engine.events[-1].kind == lc.EventKind.STEP_COMPLETED
    assert state.pointer() == lc.AbsentPointer("absent", 0)


def test_active_generation_uninstall_is_blocked_before_handler(tmp_path, policy):
    service, scope, context, port, state, effects, engine, private = public_case(tmp_path, policy)
    identifier = state.manifests[0].generation_id
    control = port.read("managed-control")
    port.seed("managed-control", {
        **dict(control.payload), "pointer": c.wire(lc.PresentPointer("present", identifier, "a" * 64, 1)),
    })
    with pytest.raises(AuthorizationError):
        service.plan_uninstall(identifier, context)


def test_installed_data_grammar_preserves_literal_safe_spaces():
    assert _installed_parts("Lib/site-packages/jaraco/text/Lorem ipsum.txt")[-1] == "Lorem ipsum.txt"


@pytest.mark.parametrize("path", (
    "NUL .txt", "a ", " a", "../a", "a:stream", "a//b", "C:\\absolute", "/absolute", "a.",
))
def test_installed_data_grammar_rejects_aliases_streams_and_traversal(path):
    with pytest.raises(c.ContractError):
        _installed_parts(path)
