"""Production A02/S01 composition; external ports are private bootstrap inputs."""

from __future__ import annotations

import threading
from contextlib import AbstractContextManager
from dataclasses import replace
from pathlib import Path
from typing import Protocol, cast

from netops.core.connection import DeviceConnection
from netops.core.vault import CredentialVault
from netops.dependencies.runs import OwnedGenerationRuns

from . import contracts as c
from ._action_mutation import _MutationSpec
from .artifacts import OwnedStatePort
from .controller import ControllerLauncher, ProcessPort, _WatchdogRevocations
from .controller_control import HostControllerCredentials, HostDispatchControl, _HostInvocation
from .controller_credentials import _ControllerCredentialAdmission
from .controller_installation import _ManagedInstallationVerifier, _OwnedInstallationVerifier
from .controller_observations import _ControllerIo
from .controller_process import InstallationVerifier, OwnedPosixProcesses
from .controller_protocol import ProtocolError
from .credential_routes import ApprovedRouteFile, ControllerOriginRoutePolicy
from .credentials import CredentialScope, RouteBinding, ScopedCredentialResolver, UnlockSession
from .execution import (
    EffectResult,
    EffectsBackend,
    ExecutionHost,
    ExecutionInputs,
    ExecutionSourcePort,
)
from .policy import LocalPolicyPort
from .policy.authorization import ConsentReviewPort, bind_plan
from .workflows import WorkflowService


class _UnlockPort(Protocol):
    def password(self, scope: CredentialScope) -> str | None: ...


class _ControllerCredentialSource:
    """S01 native vault resolution with exact immutable approved route selection."""

    def __init__(
        self, vault: CredentialVault, origin: c.ControllerContext, approved: RouteBinding,
        files: tuple[ApprovedRouteFile, ...], unlock: _UnlockPort, clock: c.ClockPort,
    ) -> None:
        self._vault, self._origin, self._approved = vault, origin, approved
        self._files, self._unlock, self._clock = files, unlock, clock
        self._lock = threading.RLock()
        self._resolvers: dict[str, list[ScopedCredentialResolver]] = {}
        self._revoked: set[str] = set()

    def prepare(
        self, control: HostDispatchControl, effect: c.PlannedEffect,
    ) -> HostControllerCredentials:
        plan = control._plan
        with self._lock:
            if plan.operation_id in self._revoked or self._origin.context != plan.context:
                raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        selected = tuple(
            replace(target, task_id=effect.step_id)
            for target in self._approved.targets if target.target_id == effect.target_id
        )
        if len(selected) != 1:
            raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        scope = CredentialScope(
            plan.operation_id, self._origin, c.digest(plan.context.controller_id),
            plan.context.route_digest, selected,
            min(control._deadline, control._authorization_deadline),
        )
        route = replace(self._approved, targets=selected)
        selected_refs = {
            ref for target in (*selected, *((route.jump,) if route.jump is not None else ()))
            for ref in (target.key_ref, target.known_hosts_ref) if ref is not None
        }
        policy = ControllerOriginRoutePolicy(
            self._origin, route, tuple(item for item in self._files if item.ref in selected_refs),
        )
        resolver = ScopedCredentialResolver(self._vault, policy, self._clock)
        admission = _ControllerCredentialAdmission(control, scope)
        with control._broker._lock:
            admission._check(scope)
        session = UnlockSession(scope, self._unlock.password(scope), admission)
        try:
            resolved = resolver.resolve(scope, session)
            with self._lock:
                if plan.operation_id in self._revoked:
                    resolver.revoke(plan.operation_id)
                    raise ProtocolError(c.ReasonCode.CANCELLED)
                self._resolvers.setdefault(plan.operation_id, []).append(resolver)
            return HostControllerCredentials(resolved, scope, control)
        finally:
            session.close()

    def revoke(self, operation_id: str) -> None:
        """Revoke all current scopes; never hold this lock while taking host locks."""
        with self._lock:
            self._revoked.add(operation_id)
            resolvers = self._resolvers.pop(operation_id, [])
        for resolver in resolvers:
            resolver.revoke(operation_id)

    def _discard(self, operation_id: str) -> None:
        with self._lock:
            resolvers = self._resolvers.pop(operation_id, [])
        for resolver in resolvers:
            resolver.revoke(operation_id)


class _ControllerEffectsBackend:
    """Find the authentic host entry; never call permit/enter or reconstruct one."""

    def __init__(
        self, launcher: ControllerLauncher, credentials: _ControllerCredentialSource,
        native: EffectsBackend, clock: c.ClockPort,
    ) -> None:
        self._launcher, self._credentials, self._native, self._clock = (
            launcher, credentials, native, clock,
        )
        self._host: ExecutionHost | None = None
        self._contents: dict[tuple[str, str], bytes] = {}
        self._lock = threading.RLock()
        self._io = _ControllerIo()

    def _bind(self, host: ExecutionHost) -> None:
        if self._host is not None or type(host) is not ExecutionHost or host._backend is not self:
            raise ProtocolError()
        self._host = host

    def _invocation(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, cancel: c.CancelPort,
    ) -> tuple[_HostInvocation, float]:
        host = self._host
        if (
            host is None or host._backend is not self
            or effect.ordinal >= len(plan.effects) or plan.effects[effect.ordinal] != effect
        ):
            raise ProtocolError(c.ReasonCode.CONSENT_REQUIRED)
        with host.authorization._lock:
            matches = [
                _HostInvocation(permit, binding, invocation, effect.kind)
                for permit, (binding, invocation) in host._pending.items()
                if permit in host._entered
                and binding.plan.operation_id == plan.operation_id
                and binding.occurrence_id == effect.occurrence_id
                and binding.target_id == effect.target_id and binding.step_id == effect.step_id
                and bind_plan(plan, binding.plan.root_ref, binding.plan.generation) == binding.plan
                and host.authorization.reconcile(permit) == binding
            ]
            if len(matches) != 1 or host._cancellations.get(plan.operation_id) is not cancel:
                raise ProtocolError(c.ReasonCode.CONSENT_STALE)
            # Use the actual broker's original host-local origin. A02's
            # deadline is consent-TTL-clamped, not execution-timeout minus now.
            # Reconstructing an origin from those unlike durations can be
            # negative and, worse, would renew after a delayed invocation.
            pending = next(
                item for permit, item in host.authorization._pending.items()
                if permit is matches[0].permit
            )
            return matches[0], pending.scope.issued_at

    def _control(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, cancel: c.CancelPort,
    ) -> HostDispatchControl:
        entry, accepted = self._invocation(plan, effect, cancel)
        host = self._host
        assert host is not None
        with host.authorization._lock:
            return HostDispatchControl(
                host.authorization, (entry,), plan, self._clock, cancel, accepted,
            )

    def _read(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, cancel: c.CancelPort,
        mutation: _MutationSpec | None = None,
    ) -> EffectResult:
        control = self._control(plan, effect, cancel)
        finalizers = _WatchdogRevocations()
        try:
            if effect.kind == "gather":
                from ._action_health import _HealthSelection

                control._health[effect.occurrence_id] = _HealthSelection(
                    cpu_threshold=plan.settings.health.cpu_threshold,
                    memory_threshold=plan.settings.health.memory_threshold,
                ).wire()
            if mutation is not None:
                if effect.kind not in ("apply", "rollback"):
                    raise ProtocolError()
                control._mutations[effect.occurrence_id] = mutation._wire()
            readiness = self._launcher.verify(c.ControllerContext(plan.context))
            if readiness.readiness.companion != "ready":
                raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
            credentials = self._credentials.prepare(control, effect)
            assert self._host is not None
            request = self._host._requests[plan.operation_id][1]
            outcome = self._launcher._run_host_entry(
                c.ControllerRequest(request, plan), credentials, cancel, self._host,
            )
            selected = next(target for target in outcome.targets if target.target_id == effect.target_id)
            if (
                selected.status == c.OutcomeStatus.SUCCEEDED
                and control._next.get(effect.occurrence_id) != (
                    3 if mutation is not None else 2
                )
            ):
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
            errors = selected.errors + outcome.errors
            status = selected.status if not outcome.errors else c.OutcomeStatus.FAILED
            payload = dict(selected.native_payload)
            remote_state, changed = selected.remote_state, selected.changed
            cleanup = outcome.cleanup
            if effect.kind == "gather":
                health = payload.get("health")
                if isinstance(health, c.FrozenObject) and health.get("connection_cleanup_failed") is True:
                    cleanup = c.CleanupOutcome(
                        "failed", cleanup.remaining_refs, cleanup.errors + (c.SafeError(
                            c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
                            target_id=effect.target_id, step_id=effect.occurrence_id,
                            next_action="Inspect exact health connection teardown; no replay.",
                        ),),
                    )
            if mutation is not None:
                if "issued" not in payload and control._next.get(effect.occurrence_id, 0) >= 3:
                    # Permit response/completion loss cannot prove whether the
                    # fixed action issued its one command. Never auto-replay.
                    payload.update(issued=True, poststate_verified=False, confirmed=False)
                    remote_state, changed = "uncertain", True
                payload.update(
                    prestate_ref=mutation.prestate_ref,
                    recovery_status="not-needed" if status == c.OutcomeStatus.SUCCEEDED
                    else "not-attempted",
                )
                if payload.get("cleanup_failed") is True:
                    cleanup = c.CleanupOutcome(
                        "failed", cleanup.remaining_refs, cleanup.errors + (c.SafeError(
                            c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED,
                            c.Stage.FINALIZE, target_id=effect.target_id,
                            step_id=effect.occurrence_id,
                            next_action="Inspect connection teardown; do not replay mutation.",
                        ),),
                    )
            if (
                effect.kind == "collect" and status == c.OutcomeStatus.SUCCEEDED
                and cleanup.status != "failed"
            ):
                content = control._take_content(effect.occurrence_id)
                if plan.operation == "config.backup":
                    with self._lock:
                        self._contents[(plan.operation_id, effect.target_id)] = content
            result = EffectResult(c.StepOutcome(
                effect.occurrence_id, status, True,
                native_payload=c.public_object(payload), changed=changed,
                remote_state=remote_state, errors=errors, findings=selected.findings,
            ), cleanup)
        except Exception as error:
            issued = mutation is not None and control._next.get(effect.occurrence_id, 0) >= 3
            result = EffectResult(c.StepOutcome(
                effect.occurrence_id, c.OutcomeStatus.FAILED, True,
                native_payload=c.public_object({"issued": issued}),
                changed=issued, remote_state="uncertain" if issued else "unchanged",
                errors=(c.SafeError(
                    c.ErrorCategory.EXECUTION,
                    error.reason if type(error) is ProtocolError else c.ReasonCode.HANDOFF_INVALID,
                    c.Stage.CONTROLLER, target_id=effect.target_id, step_id=effect.occurrence_id,
                    next_action="Inspect actual state and protected evidence; do not replay.",
                ),),
            ))
        finally:
            finalizers.start((
                ("backend-private-control", control._close),
                ("backend-private-content", control._discard_content),
                ("backend-private-credentials", lambda: self._credentials._discard(plan.operation_id)),
            ))
        return replace(result, cleanup=self._io.cleanup(
            "backend.cleanup", plan.operation_id, lambda: finalizers.collect(result.cleanup),
        ))

    def collect(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, cancel: c.CancelPort,
    ) -> EffectResult:
        return self._read(plan, effect, cancel)

    def gather(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, cancel: c.CancelPort,
    ) -> EffectResult:
        return self._read(plan, effect, cancel)

    def backup_content(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, cancel: c.CancelPort,
    ) -> bytes:
        host = self._host
        if host is None or effect.kind != "backup" or cancel.is_cancelled():
            raise ProtocolError(c.ReasonCode.CANCELLED)
        with host.authorization._lock:
            self._invocation(plan, effect, cancel)
            with self._lock:
                return self._contents.pop((plan.operation_id, effect.target_id))

    def _finish(self, operation_id: str) -> c.CleanupOutcome:
        """Drop unused collected bytes on every public exit, including failure."""
        with self._lock:
            for key in tuple(self._contents):
                if key[0] == operation_id:
                    del self._contents[key]
        try:
            self._credentials._discard(operation_id)
        except BaseException:
            self._io._record(
                "backend.cleanup", "failed", 0.0, operation_id, "none",
                c.ReasonCode.CLEANUP_FAILED,
            )
            return c.CleanupOutcome("failed", errors=(c.SafeError(
                c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
                next_action="Inspect final private credential discard; do not replay issued work.",
            ),))
        return c.CleanupOutcome()

    def mutation_connection(
        self, plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> AbstractContextManager[DeviceConnection]:
        """Never open a host-native bypass of the selected fixed action."""
        raise ProtocolError(c.ReasonCode.CONTROL_LOST)

    def _mutate_action(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, permit: c.EffectPermit,
        content: bytes, prestate_ref: str, expected_digest: str,
    ) -> EffectResult:
        """Run A02's entered exact mutation through the inherited private client."""
        host = self._host
        if host is None or effect.kind not in ("apply", "rollback"):
            raise ProtocolError()
        host._check_mutation(plan, effect, permit)
        intent = host._mutation_intent(plan)
        return self._read(
            plan, effect, host._cancellations[plan.operation_id],
            _MutationSpec(
                tuple(intent["commands"]) if effect.kind == "apply" else (),
                content, expected_digest, prestate_ref,
            ),
        )

    def scan(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, cancel: c.CancelPort,
    ) -> EffectResult:
        return self._native.scan(plan, effect, cancel)

    def resolve_for_run(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, cancel: c.CancelPort,
    ) -> EffectResult:
        return self._native.resolve_for_run(plan, effect, cancel)

    def retention(
        self, plan: c.OperationPlan, effect: c.PlannedEffect,
        publications: tuple[tuple[c.ArtifactDescriptor, c.ArtifactBinding], ...],
        cancel: c.CancelPort,
    ) -> EffectResult:
        return self._native.retention(plan, effect, publications, cancel)

    def git(
        self, plan: c.OperationPlan, effect: c.PlannedEffect,
        publications: tuple[tuple[c.ArtifactDescriptor, c.ArtifactBinding], ...],
        cancel: c.CancelPort,
    ) -> EffectResult:
        return self._native.git(plan, effect, publications, cancel)


class _VerifiedControllerSources:
    """Replace source readiness claims with current installed-controller proof."""

    def __init__(
        self, sources: ExecutionSourcePort, launcher: ControllerLauncher,
    ) -> None:
        self._sources, self._launcher = sources, launcher

    def reload(self, operation_id: str) -> ExecutionInputs:
        inputs = self._sources.reload(operation_id)
        if type(inputs) is not ExecutionInputs:
            raise ProtocolError()
        readiness = self._launcher.verify(c.ControllerContext(inputs.request.context))
        return replace(
            inputs, controller_qualified=readiness.readiness.companion == "ready",
            readiness=replace(
                inputs.readiness, companion=readiness.readiness.companion,
                errors=inputs.readiness.errors + readiness.readiness.errors,
            ),
        )


def _compose_controller_service(
    sources: ExecutionSourcePort, state: OwnedStatePort, reviewer: ConsentReviewPort,
    native: EffectsBackend, credentials: _ControllerCredentialSource, processes: ProcessPort,
    policy: LocalPolicyPort, dependencies: c.DependencyPort, artifacts: c.ArtifactPort,
    clock: c.ClockPort, events: c.EventPort, ownership_token: str,
) -> tuple[WorkflowService, ExecutionHost]:
    """Private bootstrap composition, not a second public authorization endpoint."""
    launcher = ControllerLauncher(processes, credentials, state, clock, events)
    backend = _ControllerEffectsBackend(launcher, credentials, native, clock)
    host = ExecutionHost(
        _VerifiedControllerSources(sources, launcher), state, reviewer,
        cast(EffectsBackend, backend), clock, ownership_token,
    )
    backend._bind(host)
    service = WorkflowService(
        policy, host.authorization, dependencies, launcher, host, artifacts, clock, events,
    )
    return service, host


def _compose_managed_processes(
    processes: ProcessPort, verifier: _ManagedInstallationVerifier,
    state: OwnedStatePort, dependencies: c.DependencyPort,
    runs: OwnedGenerationRuns | None,
) -> ProcessPort:
    """Share the actual lifecycle callback owner, never infer it from a request."""
    from netops.dependencies._composition import ManagedLifecycleState
    from netops.dependencies.service import DependencyService

    from .controller_generation import _PinnedControllerProcesses

    lifecycle: ManagedLifecycleState | None = None
    if type(dependencies) is DependencyService:
        if type(dependencies.state) is not ManagedLifecycleState:
            raise c.ContractError()
        lifecycle = dependencies.state
        if (
            lifecycle._state is not state or lifecycle._facts_resource != verifier._root_resource
            or lifecycle._control_resource != verifier._active
            or lifecycle._owner != verifier._owner
            or lifecycle._identity != verifier._descriptor.context.context.policy_identity
        ):
            raise c.ContractError()
        if lifecycle.runs is not None:
            if type(lifecycle.runs) is not OwnedGenerationRuns or (
                runs is not None and runs is not lifecycle.runs
            ):
                raise c.ContractError()
            runs = lifecycle.runs
    pinned = _PinnedControllerProcesses(processes, verifier, state, runs)
    if lifecycle is not None:
        from .policy import contracts as lc

        if tuple(lc.GenerationBinding(
            manifest.generation_id, 0, manifest.content_digest, c.digest(manifest),
        ) for manifest in lifecycle.manifests) != pinned.runs.generations:
            raise c.ContractError()
        # Private bootstrap attachment only: no file, pointer, pin, permission
        # or qualification is created here. Both consumers retain this exact
        # live callback registry and the same cross-process protected records.
        lifecycle.runs = pinned.runs
    return pinned


def _compose_owned_controller_service(
    sources: ExecutionSourcePort, state: OwnedStatePort, reviewer: ConsentReviewPort,
    native: EffectsBackend, credentials: _ControllerCredentialSource,
    installed_root: Path, active_resource: str, install_resource: str, private_root: Path,
    policy: LocalPolicyPort, dependencies: c.DependencyPort, artifacts: c.ArtifactPort,
    clock: c.ClockPort, events: c.EventPort, ownership_token: str,
    *, managed_manifest: object | None = None, managed_root_resource: str | None = None,
    managed_runs: OwnedGenerationRuns | None = None,
) -> tuple[WorkflowService, ExecutionHost]:
    """Compose the shipped consuming verifier and owned local process adapter.

    All selections are from trusted bootstrap, not request JSON. This factory
    reads no credentials, creates no directories and installs nothing. Current
    unqualified/absent product records block the later review/execute path.
    """
    verifier: InstallationVerifier
    if managed_manifest is not None:
        if managed_root_resource is None:
            raise c.ContractError()
        verifier = _ManagedInstallationVerifier(
            installed_root, managed_root_resource, active_resource, ownership_token,
            managed_manifest,
        )
    else:
        if managed_root_resource is not None:
            raise c.ContractError()
        verifier = _OwnedInstallationVerifier(
            installed_root, active_resource, install_resource, ownership_token,
        )
    processes: ProcessPort = OwnedPosixProcesses(verifier, clock, str(private_root))
    if type(verifier) is _ManagedInstallationVerifier:
        processes = _compose_managed_processes(
            processes, verifier, state, dependencies, managed_runs,
        )
    elif managed_runs is not None:
        raise c.ContractError()
    return _compose_controller_service(
        sources, state, reviewer, native, credentials, processes, policy, dependencies,
        artifacts, clock, events, ownership_token,
    )


def _compose_owned_wsl_controller_service(
    sources: ExecutionSourcePort, state: OwnedStatePort, reviewer: ConsentReviewPort,
    native: EffectsBackend, credentials: _ControllerCredentialSource,
    verifier: InstallationVerifier, private_root: str,
    policy: LocalPolicyPort, dependencies: c.DependencyPort, artifacts: c.ArtifactPort,
    clock: c.ClockPort, events: c.EventPort, ownership_token: str,
    *, managed_verifier: _ManagedInstallationVerifier | None = None,
    managed_runs: OwnedGenerationRuns | None = None,
) -> tuple[WorkflowService, ExecutionHost]:
    """Compose real fixed WSL transport with an existing qualified owner verifier.

    No distribution is adopted, installed or activated here. The verifier must
    consume genuine installed ownership and consuming tuple proof. The adapter
    additionally verifies current Windows bytes and the Linux worker verifies
    its current private runtime pins before readiness; absent Q03 blocks.
    """
    from ._controller_wsl import _OwnedWslProcesses

    processes: ProcessPort = _OwnedWslProcesses(verifier, clock, private_root)
    if managed_verifier is not None:
        if type(managed_verifier) is not _ManagedInstallationVerifier:
            raise c.ContractError()
        processes = _compose_managed_processes(
            processes, managed_verifier, state, dependencies, managed_runs,
        )
    elif managed_runs is not None:
        raise c.ContractError()
    return _compose_controller_service(
        sources, state, reviewer, native, credentials, processes, policy, dependencies,
        artifacts, clock, events, ownership_token,
    )
