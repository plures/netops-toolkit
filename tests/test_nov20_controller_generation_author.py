"""Author-only source controls; fake effects never qualify installed controllers."""

import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from netops.ansible import contracts as c
from netops.ansible.controller import ControllerInstallation, FixedLaunch, ProcessResult
from netops.ansible.controller_backend import (
    _compose_managed_processes,
    _compose_owned_controller_service,
    _compose_owned_wsl_controller_service,
)
from netops.ansible.controller_control import _Stop
from netops.ansible.controller_generation import _PinLifetime, _PinnedControllerProcesses
from netops.ansible.controller_installation import _ManagedInstallationVerifier
from netops.ansible.controller_protocol import ProtocolError
from netops.ansible.policy import contracts as lc
from netops.dependencies._installation import _InstallationSpec, _Wheel
from netops.dependencies._managed import ManagedMember
from netops.dependencies.runs import OwnedGenerationRuns
from tests.test_controller_backend_integration import (
    composed as composed,
)
from tests.test_controller_backend_integration import (
    integrated as integrated,
)
from tests.test_controller_backend_integration import (
    policy as policy,
)
from tests.test_nov19_independent_controller_execution import actual_host, bridge
from tests.test_nov19_successor_public_installer import managed_environment


@pytest.fixture
def generation_case():
    env = managed_environment()
    state, manifest = env["records"], env["manifest"]
    generation = lc.GenerationBinding(
        manifest.generation_id, 0, manifest.content_digest, c.digest(manifest),
    )
    control = state.read("managed-control")
    pointer = lc.PresentPointer(
        "present", generation.generation_id, c.digest((generation, 1)), 1,
    )
    state.seed("managed-control", {
        **dict(control.payload), "pointer": c.wire(pointer),
    })
    runs = OwnedGenerationRuns(
        state, "managed-root", "managed-control", control.ownership_token,
        control.policy_identity, (generation,), generation.generation_id,
    )
    state.seed("dependency-run-pin-" + c.digest(generation), {
        "generation_id": generation.generation_id, "manifest_digest": generation.manifest_digest,
        "revision": 0, "holders": (),
    })
    # A source-only fake verifier selection, NOT production qualification.
    verifier = SimpleNamespace(
        _root_resource="managed-root", _active="managed-control",
        _owner=control.ownership_token, _descriptor=manifest, _generation=generation,
        _selection=lambda *_: ((), "a" * 64),
    )
    context = c.ControllerContext(manifest.context.context)
    installation = ControllerInstallation(context, "linux", "/owned/bin/python", "a" * 64, "b" * 64)
    observed = []

    class Process:
        def verify(self, current, owned):
            assert owned is state and current == context
            assert runs.pins()[0]["holders"]
            observed.append("verify-with-pin")
            return installation

        def run(self, launch, private, cancel):
            assert runs.pins()[0]["holders"]
            observed.append("dispatch-with-pin")
            return ProcessResult((), 0, c.CleanupOutcome("succeeded"))

    process = Process()
    adapter = _PinnedControllerProcesses(process, verifier, state, runs)
    return SimpleNamespace(
        env=env, state=state, runs=runs, verifier=verifier, context=context,
        installation=installation, process=process, adapter=adapter, observed=observed,
    )


def launch_for(case):
    env = actual_host()
    request = replace(env[0], context=case.context.context)
    plan = replace(env[1], context=case.context.context)
    return FixedLaunch(case.installation, c.ControllerRequest(request, plan), bridge(env), 40.0, 310.0)


def test_pin_precedes_consuming_byte_proof_and_dispatch_and_releases_after_join(generation_case):
    case = generation_case
    assert case.adapter.verify(case.context, case.state) == case.installation
    assert case.runs.pins()[0]["holders"] == ()
    result = case.adapter.run(launch_for(case), b"source-only-private-frame", _Stop(SimpleNamespace(is_cancelled=lambda: False)))
    assert result.cleanup.status == "succeeded"
    assert case.observed == ["verify-with-pin", "verify-with-pin", "dispatch-with-pin"]
    assert case.runs.pins()[0]["holders"] == ()


@pytest.mark.parametrize("cleanup", (
    c.CleanupOutcome(),
    c.CleanupOutcome("failed", ("actual-owned-group",)),
    c.CleanupOutcome("failed", errors=(c.SafeError(
        c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
    ),)),
))
def test_unproved_teardown_retains_exact_holder_and_original_refs(generation_case, monkeypatch, cleanup):
    case = generation_case
    monkeypatch.setattr(case.process, "run", lambda *_: ProcessResult((), 1, cleanup))
    result = case.adapter.run(launch_for(case), b"source-only", _Stop(SimpleNamespace(is_cancelled=lambda: False)))
    assert result.cleanup.status == "failed"
    assert result.cleanup.remaining_refs == (*cleanup.remaining_refs, "owned-generation-run-pin")
    assert case.runs.pins()[0]["holders"]
    fresh = _PinnedControllerProcesses(case.process, case.verifier, case.state)
    assert fresh.runs.pins()[0]["holders"] == case.runs.pins()[0]["holders"]
    assert not fresh.runs.drain(SimpleNamespace(is_cancelled=lambda: False), case.env["clock"], 10000.0)


def test_release_failure_retains_pin_and_preserves_native_primary(generation_case, monkeypatch):
    case = generation_case
    primary = c.SafeError(c.ErrorCategory.EXECUTION, c.ReasonCode.CONTROL_LOST, c.Stage.CONTROLLER)
    monkeypatch.setattr(case.process, "run", lambda *_: ProcessResult((), 1, c.CleanupOutcome("succeeded"), primary))

    def fail(_):
        raise OSError("synthetic pin CAS failure")

    monkeypatch.setattr(case.runs, "release", fail)
    result = case.adapter.run(launch_for(case), b"source-only", _Stop(SimpleNamespace(is_cancelled=lambda: False)))
    assert result.error is primary
    assert result.cleanup.status == "failed" and case.runs.pins()[0]["holders"]


@pytest.mark.parametrize("field,value", (
    ("setup_enabled", False), ("setup_enabled", 1), ("admission_enabled", False),
    ("admission_enabled", 1), ("schema", "other"),
))
def test_current_control_grammar_rejects_before_proof_or_dispatch(generation_case, field, value):
    case = generation_case
    control = case.state.read("managed-control")
    case.state.seed("managed-control", {**dict(control.payload), field: value})
    with pytest.raises((ProtocolError, c.ContractError)):
        case.adapter.verify(case.context, case.state)
    assert case.observed == [] and case.runs.pins()[0]["holders"] == ()


@pytest.mark.parametrize("field,value", (
    ("root_resource", "different-root"), ("control_resource", "different-control"),
    ("owner", "f" * 64), ("selected_id", "d98e3e1a-50d5-48ed-839b-b00daf1d17ea"),
    ("generations", ()), ("state", object()), ("identity", None),
))
def test_run_owner_cannot_be_a_sibling_root_control_policy_or_registry(generation_case, field, value):
    case = generation_case
    setattr(case.runs, field, value)
    with pytest.raises(c.ContractError):
        _PinnedControllerProcesses(case.process, case.verifier, case.state, case.runs)
    assert case.observed == []


def test_registration_change_and_wrong_pointer_cannot_reuse_installed_selection(generation_case):
    case = generation_case
    control = case.state.read("managed-control")
    case.state.seed("managed-control", {
        **dict(control.payload), "pointer": c.wire(lc.PresentPointer(
            "present", case.verifier._generation.generation_id, "f" * 64, 1,
        )),
    })
    with pytest.raises(ProtocolError):
        case.adapter.verify(case.context, case.state)
    assert not case.observed
    root = case.state.read("managed-root")
    case.state.seed("managed-root", {
        **dict(root.payload), "root_manifest": {
            "control_resource": "managed-control", "registered_manifests": (),
        },
    })
    with pytest.raises(ProtocolError):
        _PinnedControllerProcesses(case.process, case.verifier, case.state)


def test_verification_cancellation_cannot_return_readiness_or_self_extend(generation_case, monkeypatch):
    case = generation_case

    def cancel_verification(*_):
        pin = next(iter(case.runs._live))
        request_cancel, _ = case.runs._live[pin]
        request_cancel()
        return case.installation

    monkeypatch.setattr(case.process, "verify", cancel_verification)
    with pytest.raises(ProtocolError) as failure:
        case.adapter.verify(case.context, case.state)
    assert failure.value.reason == c.ReasonCode.CANCELLED
    assert case.runs.pins()[0]["holders"] == ()


def test_join_callback_tracks_actual_running_owner_not_pid_or_clock(generation_case, monkeypatch):
    case = generation_case
    entered, complete = threading.Event(), threading.Event()
    results = []
    stop = _Stop(SimpleNamespace(is_cancelled=lambda: False))

    def run(*_):
        entered.set()
        assert complete.wait(2.0)
        return ProcessResult((), 0, c.CleanupOutcome("succeeded"))

    monkeypatch.setattr(case.process, "run", run)
    thread = threading.Thread(target=lambda: results.append(case.adapter.run(launch_for(case), b"source-only", stop)))
    thread.start()
    try:
        assert entered.wait(2.0)
        pin = next(iter(case.runs._live))
        cancel, join = case.runs._live[pin]
        assert not join(0.01)
        cancel()
        assert stop.is_cancelled()
        assert case.runs.pins()[0]["holders"]
    finally:
        complete.set()
        thread.join(2.0)
    assert not thread.is_alive()
    assert results and case.runs.pins()[0]["holders"] == ()
    assert join(0.01)


def test_wrong_context_or_owned_state_never_reads_installed_bytes(generation_case):
    case = generation_case
    for context, state in (
        (case.context, object()),
        (c.ControllerContext(replace(case.context.context, controller_id="other-controller")), case.state),
    ):
        with pytest.raises(ProtocolError):
            case.adapter.verify(context, state)
    assert case.observed == []


def test_private_pin_lifetime_requires_actual_completion():
    lifetime = _PinLifetime()
    assert not lifetime.join(0.001)
    lifetime.cancel()
    with pytest.raises(ProtocolError):
        lifetime.check()
    lifetime._finished.set()
    assert not lifetime.join(0.001)
    lifetime._joined = True
    assert lifetime.join(0.001)
    assert not lifetime.join(0.0)
    with pytest.raises(c.ContractError):
        lifetime.join(-1.0)


@pytest.mark.parametrize("result", (None, "wrong-result", ProtocolError(c.ReasonCode.CONTROL_LOST)))
def test_unknown_adapter_completion_preserves_durable_holder(generation_case, monkeypatch, result):
    case = generation_case

    def run(*_):
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(case.process, "run", run)
    outcome = case.adapter.run(launch_for(case), b"source-only", _Stop(SimpleNamespace(is_cancelled=lambda: False)))
    assert outcome.error is not None
    assert outcome.cleanup.remaining_refs == ("owned-generation-run-pin",)
    assert case.runs.pins()[0]["holders"]


@pytest.mark.parametrize("installation", (None, "different-digest"))
def test_current_installed_selection_cannot_be_substituted_after_pin(generation_case, monkeypatch, installation):
    case = generation_case
    value = None if installation is None else replace(case.installation, installation_digest="f" * 64)
    monkeypatch.setattr(case.process, "verify", lambda *_: value)
    if value is None:
        assert case.adapter.verify(case.context, case.state) is None
    else:
        with pytest.raises(ProtocolError):
            case.adapter.verify(case.context, case.state)
    result = case.adapter.run(launch_for(case), b"source-only", _Stop(SimpleNamespace(is_cancelled=lambda: False)))
    assert result.error.reason == c.ReasonCode.DEPENDENCY_NOT_READY
    assert result.cleanup.status == "succeeded"
    assert not case.observed and case.runs.pins()[0]["holders"] == ()


def test_metadata_verification_failure_releases_without_creating_process(generation_case, monkeypatch):
    case = generation_case

    def fail(*_):
        raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)

    case.verifier._selection = fail
    with pytest.raises(ProtocolError):
        case.adapter.verify(case.context, case.state)
    result = case.adapter.run(launch_for(case), b"source-only", _Stop(SimpleNamespace(is_cancelled=lambda: False)))
    assert result.error.reason == c.ReasonCode.DEPENDENCY_NOT_READY
    assert not case.observed and case.runs.pins()[0]["holders"] == ()


@pytest.mark.parametrize("change", ("owner", "schema", "control", "empty", "duplicate", "members", "manifest"))
def test_corrupt_or_substituted_registration_fails_before_qualification(generation_case, change):
    case = generation_case
    record = case.state.read("managed-root")
    payload = dict(record.payload)
    root = dict(c.public_object(payload["root_manifest"]))
    manifest = c.public_object(c.wire(case.verifier._descriptor))
    if change == "owner":
        case.state.seed("managed-root", payload, owner="f" * 64)
    else:
        if change == "schema":
            payload["schema"] = "other"
        elif change == "control":
            root["control_resource"] = "different-control"
        elif change == "empty":
            root["registered_manifests"] = ()
        elif change == "duplicate":
            root["registered_manifests"] = (manifest, manifest)
        elif change == "members":
            # Retain selected valid manifest plus a corrupt sibling descriptor.
            root["registered_manifests"] = (manifest, c.public_object({
                **dict(manifest), "generation_id": "d98e3e1a-50d5-48ed-839b-b00daf1d17ea", "members": (),
            }))
        else:
            root["registered_manifests"] = (c.public_object({
                **dict(manifest), "archive": "tar",
            }),)
        payload["root_manifest"] = root
        case.state.seed("managed-root", payload)
    with pytest.raises((ProtocolError, c.ContractError)):
        _PinnedControllerProcesses(case.process, case.verifier, case.state)
    assert not case.observed


def test_registration_changed_after_composition_invalidates_new_pin(generation_case):
    case = generation_case
    record = case.state.read("managed-root")
    manifest = case.verifier._descriptor
    sibling = replace(manifest, generation_id="d98e3e1a-50d5-48ed-839b-b00daf1d17ea")
    case.state.seed("managed-root", {
        **dict(record.payload), "root_manifest": {
            "control_resource": "managed-control", "registered_manifests": (c.wire(manifest), c.wire(sibling)),
        },
    })
    with pytest.raises(ProtocolError) as failure:
        case.adapter.verify(case.context, case.state)
    assert failure.value.reason == c.ReasonCode.CONSENT_STALE and not case.observed


def test_verification_pin_release_failure_never_returns_readiness(generation_case, monkeypatch):
    case = generation_case

    def fail(_):
        raise OSError("synthetic release failure")

    monkeypatch.setattr(case.runs, "release", fail)
    with pytest.raises(OSError):
        case.adapter.verify(case.context, case.state)
    assert case.runs.pins()[0]["holders"]


def test_private_run_shape_and_generation_binding_cannot_be_reconstructed(generation_case):
    case = generation_case
    for launch, cancel in (
        (object(), _Stop(SimpleNamespace(is_cancelled=lambda: False))),
        (launch_for(case), SimpleNamespace(is_cancelled=lambda: False)),
    ):
        with pytest.raises(ProtocolError):
            case.adapter.run(launch, b"source-only", cancel)
    case.verifier._generation = replace(case.verifier._generation, manifest_digest="f" * 64)
    with pytest.raises(ProtocolError):
        _PinnedControllerProcesses(case.process, case.verifier, case.state)
    assert not case.observed


def test_actual_lifecycle_and_controller_composition_share_live_callback_owner(generation_case):
    case = generation_case
    lifecycle = case.env["state"]
    lifecycle.runs = case.runs
    pinned = _compose_managed_processes(case.process, case.verifier, case.state, case.env["service"], None)
    assert pinned.runs is lifecycle.runs is case.runs
    lifecycle.runs = None
    constructed = _compose_managed_processes(case.process, case.verifier, case.state, case.env["service"], None)
    assert constructed.runs is lifecycle.runs
    assert constructed.runs is not case.runs
    assert case.runs.pins()[0]["holders"] == ()


@pytest.mark.parametrize("field,value", (
    ("_state", object()), ("_facts_resource", "other-root"),
    ("_control_resource", "other-control"), ("_owner", "f" * 64),
    ("_identity", None), ("runs", object()), ("manifests", ()),
))
def test_lifecycle_binding_cannot_supply_unrelated_run_authority(generation_case, field, value):
    case = generation_case
    setattr(case.env["state"], field, value)
    with pytest.raises(c.ContractError):
        _compose_managed_processes(case.process, case.verifier, case.state, case.env["service"], None)


def test_two_live_registries_or_inert_state_cannot_be_adopted_by_composition(generation_case):
    case = generation_case
    case.env["state"].runs = case.runs
    other = _PinnedControllerProcesses(case.process, case.verifier, case.state).runs
    with pytest.raises(c.ContractError):
        _compose_managed_processes(case.process, case.verifier, case.state, case.env["service"], other)
    case.env["service"].state = object()
    with pytest.raises(c.ContractError):
        _compose_managed_processes(case.process, case.verifier, case.state, case.env["service"], None)


def test_actual_managed_factory_public_execute_consumes_same_root_pin_and_s01(
    generation_case, integrated, monkeypatch, tmp_path,
):
    """Fake physical verifier only; real factory, host, broker, vault and pins."""
    case = generation_case
    service, previous, request, sources, process, credentials, _ = integrated
    wheels = tuple(_Wheel("wheels/" + name + ".whl", name, "1.0", "a" * 64)
                   for name in ("netops-toolkit", "ansible-core", "molecule"))
    manifest = replace(
        case.verifier._descriptor, context=c.InstallContext(request.context),
        members=tuple(ManagedMember(wheel.member, wheel.digest, 1, False) for wheel in wheels),
        installation=_InstallationSpec(str(tmp_path / "python"), "b" * 64, "3.12.0", "linux", wheels, True),
    )
    generation = lc.GenerationBinding(manifest.generation_id, 0, manifest.content_digest, c.digest(manifest))
    state = case.state
    state.seed("managed-root", {
        "schema": "i02-managed-generations-v1", "generations": (),
        "root_manifest": {"control_resource": "managed-control", "registered_manifests": (c.wire(manifest),)},
    })
    state.seed("managed-control", {
        "schema": "i02-managed-control-v1", "setup_enabled": True,
        "pointer": c.wire(lc.PresentPointer("present", generation.generation_id, c.digest((generation, 1)), 1)),
    })
    state.seed("dependency-run-pin-" + c.digest(generation), {
        "generation_id": generation.generation_id, "manifest_digest": generation.manifest_digest,
        "revision": 0, "holders": (),
    })
    runs = OwnedGenerationRuns(state, "managed-root", "managed-control", previous._owner,
                               request.context.policy_identity, (generation,), generation.generation_id)
    read = state.read

    def read_existing(resource):
        try:
            return read(resource)
        except KeyError:
            raise FileNotFoundError() from None

    monkeypatch.setattr(state, "read", read_existing)
    verify, run = process.verify, process.run
    observations = []

    def check_verify(context, owned):
        assert owned is state and runs.pins()[0]["holders"]
        observations.append("verify")
        return verify(context, owned)

    def check_run(*args):
        assert runs.pins()[0]["holders"]
        observations.append("dispatch")
        return run(*args)

    monkeypatch.setattr(process, "verify", check_verify)
    monkeypatch.setattr(process, "run", check_run)
    monkeypatch.setattr("netops.ansible.controller_backend.OwnedPosixProcesses", lambda *_: process)
    # This fake metadata proof is explicitly source-only. It does NOT make
    # these fake wheels an installed/qualified platform generation.
    monkeypatch.setattr("netops.ansible.controller_installation._ManagedInstallationVerifier._selection", lambda *_: ((), "a" * 64))
    selected, host = _compose_owned_controller_service(
        sources, state, previous._consent._reviewer, previous._backend._native, credentials,
        tmp_path / ("installation-" + c.digest(generation.generation_id)),
        "managed-control", "unused-legacy-install", tmp_path / "private",
        service._policy, None, None, previous._clock, SimpleNamespace(emit=lambda _: None), previous._owner,
        managed_manifest=manifest, managed_root_resource="managed-root", managed_runs=runs,
    )
    assert host._backend._launcher._processes.runs is runs
    result = selected.execute(request, host.review(selected, request))
    assert result.status == c.OutcomeStatus.SUCCEEDED, result
    assert observations.count("dispatch") == 1
    assert runs.pins()[0]["holders"] == ()
    assert selected.execute(request, None).status == c.OutcomeStatus.BLOCKED
    assert observations.count("dispatch") == 1


@pytest.mark.parametrize("selection", ("legacy", "root-without-manifest", "manifest-without-root", "runs-without-manifest", "invalid-manifest"))
def test_owned_factory_selectors_are_private_exact_and_closed(generation_case, monkeypatch, tmp_path, selection):
    case = generation_case
    monkeypatch.setattr("netops.ansible.controller_backend.OwnedPosixProcesses", lambda *_: case.process)
    monkeypatch.setattr("netops.ansible.controller_backend._compose_controller_service", lambda *args: ("source-only", args[5]))
    kwargs = {}
    if selection == "root-without-manifest":
        kwargs["managed_root_resource"] = "managed-root"
    elif selection == "manifest-without-root":
        kwargs["managed_manifest"] = case.verifier._descriptor
    elif selection == "runs-without-manifest":
        kwargs["managed_runs"] = case.runs
    elif selection == "invalid-manifest":
        kwargs.update(managed_manifest=True, managed_root_resource="managed-root")

    def compose():
        return _compose_owned_controller_service(
            object(), case.state, object(), object(), object(), tmp_path / "legacy",
            "active", "install", tmp_path / "private", object(), None, None,
            case.env["clock"], object(), case.verifier._owner, **kwargs,
        )

    if selection == "legacy":
        assert compose() == ("source-only", case.process)
    else:
        with pytest.raises(c.ContractError):
            compose()


@pytest.mark.parametrize("selection", ("existing", "managed", "invalid-verifier", "runs-without-verifier"))
def test_wsl_factory_consumes_exact_managed_registry_without_platform_claim(
    generation_case, monkeypatch, tmp_path, selection,
):
    case = generation_case
    monkeypatch.setattr("netops.ansible._controller_wsl._OwnedWslProcesses", lambda *_: case.process)
    monkeypatch.setattr("netops.ansible.controller_backend._compose_controller_service", lambda *args: ("source-only", args[5]))
    kwargs = {}
    if selection == "invalid-verifier":
        kwargs["managed_verifier"] = object()
    elif selection == "runs-without-verifier":
        kwargs["managed_runs"] = case.runs
    elif selection == "managed":
        wheels = tuple(_Wheel("wheels/" + name + ".whl", name, "1.0", "a" * 64)
                       for name in ("netops-toolkit", "ansible-core", "molecule"))
        manifest = replace(
            case.verifier._descriptor,
            members=tuple(ManagedMember(w.member, w.digest, 1, False) for w in wheels),
            installation=_InstallationSpec(str(tmp_path / "python"), "b" * 64, "3.12.0", "linux", wheels, True),
        )
        verifier = _ManagedInstallationVerifier(
            tmp_path / ("installation-" + c.digest(manifest.generation_id)),
            "managed-root", "managed-control", case.verifier._owner, manifest,
        )
        root = case.state.read("managed-root")
        case.state.seed("managed-root", {
            **dict(root.payload), "root_manifest": {
                "control_resource": "managed-control", "registered_manifests": (c.wire(manifest),),
            },
        })
        case.env["state"].manifests = (manifest,)
        kwargs["managed_verifier"] = verifier

    def compose():
        return _compose_owned_wsl_controller_service(
            object(), case.state, object(), object(), object(), object(), "/owned/private",
            object(), case.env["service"], None, case.env["clock"], object(), case.verifier._owner,
            **kwargs,
        )

    if selection in ("invalid-verifier", "runs-without-verifier"):
        with pytest.raises(c.ContractError):
            compose()
    else:
        _, process = compose()
        if selection == "managed":
            assert type(process) is _PinnedControllerProcesses
            assert process.runs is case.env["state"].runs
        else:
            assert process is case.process
