"""Actual A02/S01 composition with fake process/route I/O, not tuple proof."""

import hashlib
import pickle
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.controller import ControllerInstallation, ProcessResult
from netops.ansible.controller_backend import (
    _compose_controller_service,
    _ControllerCredentialSource,
    _ControllerEffectsBackend,
    _VerifiedControllerSources,
)
from netops.ansible.controller_content import (
    _decode_content,
    _encode_content,
    _NativeRead,
)
from netops.ansible.controller_installation import _OwnedInstallationVerifier
from netops.ansible.controller_protocol import DispatchBinding, ProtocolError, _decode_frame
from netops.ansible.credential_routes import ApprovedRouteFile
from netops.ansible.credentials import CredentialTarget, RouteBinding
from netops.core.vault import CredentialVault
from tests.test_guarded_mutation_execution import mutation as mutation
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed
from tests.test_workflow_execution import policy as policy
from tests.test_workflow_policy_alignment import backup_composed as backup_composed

SECRET = "SYNTHETIC-INTEGRATION-ONLY"
CONFIG = b"hostname selected\nsnmp-server community SYNTHETIC-PRIVATE-CONFIG\n"


@pytest.fixture
def integrated(composed, monkeypatch):
    service, previous, request, sources, native = composed
    content = c.canonical_bytes(c.public_object({
        "devices": {
            "r1": {"host": "192.0.2.1", "vendor": "cisco_ios"},
            "r2": {"host": "192.0.2.2", "vendor": "cisco_ios"},
        },
    }))
    reference = c.InputRef("inventory", "owned-inventory", hashlib.sha256(content).hexdigest())
    request = replace(request, operation="config.collect", inputs=(reference,))
    sources.value = replace(
        sources.value, request=request,
        sources=(c.InputSource(reference, "json", content, "parser-1", "vendor-1"),),
    )
    targets = tuple(CredentialTarget(
        name, "config.collect", name, host, "cisco_ios", "ssh", 22, (),
        ("username", "password"), known_hosts_ref="/owned/known-hosts",
    ) for name, host in (("r1", "192.0.2.1"), ("r2", "192.0.2.2")))
    route = RouteBinding(
        c.digest(request.context.controller_id), request.context.route_digest,
        targets, "e" * 64, True, True, "reject", True,
    )
    # Fake only the external approved-file metadata port. The production route
    # policy, native vault resolver, unlock and delivery guards remain real.
    stamp = (1, 2, 3, 4, 5, 6, 7)
    monkeypatch.setattr("netops.ansible.credential_routes._inspect", lambda *args: stamp)
    files = (ApprovedRouteFile(
        "/owned/known-hosts", Path("/owned/known-hosts").absolute(), "known-hosts", stamp,
    ),)
    root = Path(__file__).resolve().parents[1] / ".sdlc" / "controller-integration-tests" / uuid4().hex
    vault = CredentialVault(root / "synthetic.yaml")
    vault.init("SYNTHETIC-MASTER")
    vault.set_default("synthetic-user", SECRET)
    vault.save("SYNTHETIC-MASTER")
    credentials = _ControllerCredentialSource(
        vault, c.ControllerContext(request.context), route, files,
        SimpleNamespace(password=lambda scope: "SYNTHETIC-MASTER"), previous._clock,
    )

    class Process:
        def __init__(self):
            self.runs = []
            self.verified = 0
            self.available = True
            self.before_dispatch = None
            self.deliver_content = True
            self.failures = []

        def verify(self, context, state):
            self.verified += 1
            if not self.available:
                return None
            # This value is an injected fake process port observation, never
            # supplied to the production installed verifier or packaged lock.
            return ControllerInstallation(context, "linux", "/owned/bin/python", "a" * 64, "b" * 64)

        def run(self, launch, private, cancel):
            self.runs.append(launch)
            frame = _decode_frame(private)
            assert frame["credentials"]["targets"][0]["fields"]["password"] == SECRET
            assert SECRET not in repr(launch)
            binding = DispatchBinding._parse(frame["intents"][0]["binding"])
            launch.control.ready("c" * 64)
            launch.control.request_dispatch(binding, cancel)
            if self.before_dispatch is not None:
                self.before_dispatch()
            task = replace(binding, phase="task", sequence=1)
            launch.control.request_dispatch(task, cancel)
            if self.deliver_content:
                launch.control._accept_content(task, _encode_content(CONFIG))
            return ProcessResult((c.TargetOutcome(
                binding.target_id, c.OutcomeStatus.SUCCEEDED, True,
                native_payload=c.public_object({"line_count": 2}),
            ),), 0, c.CleanupOutcome("succeeded"))

    process = Process()
    events = SimpleNamespace(emit=lambda event: None)
    selected, host = _compose_controller_service(
        sources, previous._owned, previous._consent._reviewer, native, credentials, process,
        service._policy, None, None, previous._clock, events, previous._owner,
    )
    read = host._backend.collect

    def recorded_read(*args):
        try:
            return read(*args)
        except BaseException as failure:
            process.failures.append(failure)
            raise

    host._backend.collect = recorded_read
    return selected, host, request, sources, process, credentials, vault


def test_public_execute_reaches_actual_entered_host_bridge_and_real_s01(integrated):
    service, host, request, sources, process, credentials, vault = integrated
    grant = host.review(service, request)
    assert process.runs == []
    outcome = service.execute(request, grant)
    assert not process.failures, process.failures
    assert outcome.status == c.OutcomeStatus.SUCCEEDED, outcome
    assert len(process.runs) == 1
    assert process.verified >= 2
    assert sources.calls >= 5
    assert SECRET not in repr(outcome) and CONFIG.decode() not in repr(outcome)
    assert credentials._resolvers == {}
    assert host._backend._contents == {}
    # A02 closes the whole grant after the operation, whereas the controller
    # must only close this invocation before the next selected effect.
    assert host.authorization.is_revoked(request.operation_id) is True
    assert process.runs[0].control._closed and not process.runs[0].control._revoked
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(process.runs) == 1


def test_success_does_not_revoke_later_selected_target(integrated):
    service, host, request, sources, process, _, _ = integrated
    request = replace(request, scope=c.Scope(("r1", "r2")))
    sources.value = replace(sources.value, request=request)
    outcome = service.execute(request, host.review(service, request))
    assert outcome.status == c.OutcomeStatus.SUCCEEDED, outcome
    assert len(process.runs) == 2
    assert all(target.status == c.OutcomeStatus.SUCCEEDED for target in outcome.targets)
    assert host._backend._contents == {}


def test_actual_a02_parent_signal_observation_never_takes_its_broker_lock(integrated, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    from netops.ansible.controller_control import _Stop

    service, host, request, _, process, _, _ = integrated
    run = process.run
    checked = []

    def stalled_broker(launch, private, stop):
        actual = host._cancellations[request.operation_id]
        assert stop._parent is actual
        probe = _Stop(actual)
        with ThreadPoolExecutor(max_workers=1) as pool:
            with host.authorization._lock:
                actual._signal.set()
                # Another thread cannot enter this held broker RLock. It must
                # sample only the authentic host's already-owned stop signal.
                assert pool.submit(probe._observe_parent).result(timeout=0.5)
        checked.append(True)
        return run(launch, private, stop)

    monkeypatch.setattr(process, "run", stalled_broker)
    result = service.execute(request, host.review(service, request))
    assert checked == [True] and result.status != c.OutcomeStatus.SUCCEEDED


def test_backend_cannot_reconstruct_authority_from_plan_or_readiness(integrated):
    service, host, request, _, process, credentials, _ = integrated
    host.review(service, request)
    plan, _ = host._load(service, request)
    with pytest.raises(ProtocolError):
        host._backend.collect(plan, plan.effects[0], SimpleNamespace(is_cancelled=lambda: False))
    assert process.runs == [] and credentials._resolvers == {}


def test_unqualified_installation_blocks_before_vault_or_process(integrated, monkeypatch):
    service, host, request, _, process, _, vault = integrated
    process.available = False

    def forbidden(*args):
        pytest.fail("unqualified tuple reached credential resolution")

    monkeypatch.setattr(vault, "private_session", forbidden)
    with pytest.raises(Exception):
        host.review(service, request)
    assert process.runs == []


def test_cancel_after_private_credential_before_task_stops_dispatch(integrated):
    service, host, request, _, process, credentials, _ = integrated
    grant = host.review(service, request)
    process.before_dispatch = lambda: service.cancel(request.operation_id)
    outcome = service.execute(request, grant)
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert host.authorization.is_revoked(request.operation_id)
    assert process.runs[0].control._next[next(iter(process.runs[0].control._next))] == 1
    assert credentials._resolvers == {}
    assert SECRET not in repr(outcome)


def test_missing_protected_content_cannot_be_substituted_by_callback_success(integrated):
    service, host, request, _, process, _, _ = integrated
    process.deliver_content = False
    outcome = service.execute(request, host.review(service, request))
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert host._backend._contents == {}


@pytest.mark.parametrize(
    "value", ["not-base64", "YQ=", "YQ==\n", "YQ===", True, None, "A" * 699053],
    ids=("invalid", "truncated", "newline", "padding", "boolean", "null", "oversize"),
)
def test_protected_content_is_strict_bounded_and_nonserializable(value):
    with pytest.raises(ProtocolError):
        _decode_content(value)
    private = _NativeRead({"status": "succeeded"}, CONFIG)
    assert repr(private) == "<private>"
    with pytest.raises(TypeError):
        pickle.dumps(private)


def test_packaged_unqualified_lock_cannot_adopt_owned_inert_or_directory(integrated):
    _, host, request, _, _, _, _ = integrated
    verifier = _OwnedInstallationVerifier(Path("/not-adopted").absolute(), "active", "inert", "1" * 64)
    before = host._owned.content
    assert verifier.verify(c.ControllerContext(request.context), host._owned) is None
    assert host._owned.content == before


def _replace_backend(service, host, credentials, process):
    from netops.ansible.controller import ControllerLauncher

    launcher = ControllerLauncher(
        process, credentials, host._owned, host._clock, SimpleNamespace(emit=lambda event: None),
    )
    backend = _ControllerEffectsBackend(launcher, credentials, host._backend, host._clock)
    host._backend = backend
    backend._bind(host)
    host._sources = _VerifiedControllerSources(host._sources, launcher)
    service._controller = launcher
    return backend


def test_real_a02_backup_publishes_only_protected_worker_content(
    integrated, backup_composed, monkeypatch,
):
    _, _, selected, selected_sources, process, credentials, _ = integrated
    service, host, request, sources, native, filesystem = backup_composed
    request = replace(
        request, inputs=selected.inputs, output_intent=replace(request.output_intent, git=False),
    )
    sources.value = replace(
        sources.value, request=request, sources=selected_sources.value.sources,
    )
    backend = _replace_backend(service, host, credentials, process)
    consume = backend.backup_content
    guarded = []

    def checked_content(plan, effect, cancel):
        before = dict(backend._contents)
        for altered in (
            replace(effect, target_id="r2" if effect.target_id == "r1" else "r1"),
            replace(effect, step_id="wrong-step"),
            replace(effect, ordinal=(effect.ordinal + 1) % len(plan.effects)),
        ):
            with pytest.raises(ProtocolError):
                consume(plan, altered, cancel)
            assert backend._contents == before
        with pytest.raises(ProtocolError):
            consume(plan, effect, SimpleNamespace(is_cancelled=lambda: False))
        assert backend._contents == before
        guarded.append(effect.occurrence_id)
        return consume(plan, effect, cancel)

    monkeypatch.setattr(backend, "backup_content", checked_content)
    result = service.execute(request, host.review(service, request))
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    assert filesystem.published_bytes == [CONFIG, CONFIG]
    assert len(result.artifacts) == 2 and len(native.retained) == 2
    assert all(artifact["classification"] == "sensitive" for artifact in result.artifacts)
    assert CONFIG.decode() not in repr(result) and SECRET not in repr(result)
    assert len(process.runs) == 2
    assert len(guarded) == 2
    assert all(launch.control._contents == {} for launch in process.runs)
    assert backend._contents == {} and credentials._resolvers == {}


def test_non_successful_target_discards_already_received_private_content(integrated, monkeypatch):
    service, host, request, _, process, credentials, _ = integrated
    run = process.run

    def failed_target(*args):
        completed = run(*args)
        assert args[0].control._contents
        return replace(completed, targets=(
            replace(completed.targets[0], status=c.OutcomeStatus.FAILED),
        ))

    monkeypatch.setattr(process, "run", failed_target)
    result = service.execute(request, host.review(service, request))
    assert result.status == c.OutcomeStatus.FAILED
    assert all(launch.control._contents == {} for launch in process.runs)
    assert host._backend._contents == {} and credentials._resolvers == {}


@pytest.mark.parametrize("failure", [
    "none", "wrong-poststate", "cancel-issued", "prestate-drift", "completion-lost",
])
def test_actual_native_mutation_owner_uses_real_s01_and_specific_recovery(
    integrated, mutation, monkeypatch, failure,
):
    _, _, _, _, process, credentials, _ = integrated
    service, host, apply, rollback, _, device, _, after_write, filesystem = mutation
    opened = []
    from tests.test_fixed_action_mutation import _use_action_process

    _use_action_process(process, device, monkeypatch, opened)
    backend = _replace_backend(service, host, credentials, process)
    recovery = host.review(service, rollback)
    grant = host.review(service, apply, recovery=(recovery,))
    if failure == "wrong-poststate":
        after_write.append(lambda: setattr(device, "config", "hostname unexpected\n"))
    elif failure == "cancel-issued":
        after_write.append(lambda: service.cancel(apply.operation_id))
    elif failure == "prestate-drift":
        device.config = "hostname changed-externally\n"
    elif failure == "completion-lost":
        process.drop_completion = True
    result = service.execute(apply, grant)
    if failure == "none":
        assert result.status == c.OutcomeStatus.SUCCEEDED, result
        assert result.targets[0].remote_state == "confirmed"
        restored = service.execute(rollback, recovery)
        assert restored.status == c.OutcomeStatus.SUCCEEDED, restored
        assert restored.targets[0].remote_state == "rolled-back"
    elif failure == "prestate-drift":
        assert result.status == c.OutcomeStatus.FAILED
        assert device.writes == [] and opened == ["apply"]
        assert result.targets[0].remote_state == "unchanged"
    else:
        assert result.status == c.OutcomeStatus.FAILED, result
        assert result.targets[0].remote_state == "rolled-back", result
        assert result.steps[0].native_payload["recovery_status"] == "succeeded", result
    if failure != "prestate-drift":
        assert device.writes == [("hostname after",), ("hostname before",)]
        assert device.config == "hostname before\n"
        assert opened == ["apply", "rollback"]
    assert filesystem.content == b"hostname before\n"
    assert SECRET not in repr(result) and "hostname before" not in repr(result)
    assert backend._contents == {} and credentials._resolvers == {}


def test_paired_io_metrics_use_bounded_labels_and_do_not_replace_primary_or_cleanup(caplog, monkeypatch):
    from netops.ansible.controller_observations import _ControllerIo

    observed = _ControllerIo()
    with caplog.at_level("INFO"):
        with observed.span("process.teardown", SECRET, CONFIG.decode()):
            actual_cleanup = c.CleanupOutcome("failed", errors=(c.SafeError(
                c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
            ),))
    record = next(record for record in caplog.records if record.msg == "controller.io")
    assert record.metric == "netops.controller.io.count"
    assert set(record.metric_dimensions) == {"boundary", "outcome", "stage", "reason"}
    assert record.operation_ref.startswith("sha256:") and record.context_ref.startswith("sha256:")
    assert SECRET not in repr(record.__dict__) and CONFIG.decode() not in repr(record.__dict__)
    assert actual_cleanup.status == "failed"

    def throwing(*args, **kwargs):
        raise RuntimeError(SECRET)

    monkeypatch.setattr(observed._logger, "info", throwing)
    primary = ProtocolError(c.ReasonCode.CONTROL_LOST)
    with pytest.raises(ProtocolError) as caught:
        with observed.span("process.control", SECRET):
            raise primary
    assert caught.value is primary and observed.sink_failures == 2
    assert any(key[:2] == ("process.control", "failed") for key in observed.counts)


def test_content_guard_negative_and_deliberate_unguarded_leak_control(integrated):
    """Prove the test can see a secret leak, then exercise the actual guard."""
    service, host, request, _, process, _, _ = integrated
    grant = host.review(service, request)
    real = process.run
    seen = []

    def run(launch, private, cancel):
        control = launch.control
        accept = control._accept_content

        def guarded(binding, value):
            for field, altered in (
                ("target_id", "unselected"), ("invocation_id", str(uuid4())),
                ("phase", "credential"), ("sequence", 0), ("plan_digest", "f" * 64),
            ):
                with pytest.raises(ProtocolError):
                    accept(replace(binding, **{field: altered}), value)
                assert control._contents == {}
            # Deliberately unguarded sink proves this fake can detect a leak;
            # the real guard below admits only the exact pending occurrence.
            def unguarded(content):
                seen.append(_decode_content(content))
            unguarded(value)
            assert seen == [CONFIG]
            accept(binding, value)
            with pytest.raises(ProtocolError):
                accept(binding, value)

        control._accept_content = guarded
        return real(launch, private, cancel)

    process.run = run
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    assert CONFIG.decode() not in repr(result)
