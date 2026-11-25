"""Author configuration controls; inert ports do not qualify actual activation."""

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    TrustedConsentAdapter,
    TrustedLifecycleConsentAdapter,
)
from netops.ansible.settings import ObservationSettings
from netops.dependencies._composition import ManagedLifecycleState
from netops.dependencies._setup import _host, _owned, _owned_document, _Review, _seed
from netops.dependencies.service import DependencyRegistry, DependencyService
from tests.policy.test_lifecycle_execution import OWNER, Review
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel
from tests.test_i02_public_flow import public_case
from tests.test_owned_source_author import source_case


def configured_case(tmp_path, policy, seconds):
    service, scope, context, port, old, effects, engine, _ = public_case(tmp_path, policy)
    root = port.read("managed-root")
    port.seed("managed-root", {
        **dict(root.payload), "root_manifest": {
            **dict(root.payload["root_manifest"]), "observation_max_age_seconds": seconds,
        },
    })
    state = ManagedLifecycleState(
        port, "managed-root", "managed-control", OWNER, policy[0], old.manifests,
        effects, effects, observation=ObservationSettings(seconds),
    )
    review = Review()
    broker = AuthorizationBroker(
        None, TrustedConsentAdapter(review), lifecycle_state=state,
        lifecycle_consent=TrustedLifecycleConsentAdapter(review),
    )
    configured = DependencyService(
        service.registry, service.adapters, state, engine, broker, service.clock, service.events,
    )
    return configured, scope, context, port, state


@pytest.mark.parametrize("seconds", [1, 120, 300])
def test_new_observation_window_is_owned_root_bound_before_plan(tmp_path, policy, seconds, monkeypatch):
    from netops.dependencies import _composition
    original_teardown = _composition.teardown

    def failure_teardown(primary=None):
        if primary is not None:
            try:
                from tests._nov22_exact_failure_capture import capture

                capture(primary, "test_new_observation_window_is_owned_root_bound_before_plan",
                        "service-primary-before-cleanup", (tmp_path,))
            except BaseException:
                # Import/initialization or diagnostic interrupts cannot skip cleanup.
                pass
        return original_teardown(primary)

    monkeypatch.setattr(_composition, "teardown", failure_teardown)
    service, scope, context, port, state = configured_case(tmp_path, policy, seconds)
    plan = service.plan(scope, context)
    root = port.read("managed-root")
    assert plan.lifecycle.root.manifest_digest == c.digest(root.payload["root_manifest"])
    result = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    assert result.status == c.OutcomeStatus.PARTIAL
    assert not result.errors
    verification = state._control().payload["verification"]
    assert verification["observed_at"] == 10.0
    assert verification["expires_at"] == 10.0 + seconds
    assert state.pointer().revision == 0


def test_changed_configuration_cannot_reuse_an_old_plan_or_extend_old_evidence(tmp_path, policy):
    service, scope, context, port, state = configured_case(tmp_path, policy, 120)
    plan = service.plan(scope, context)
    result = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    assert not result.errors
    before = state._control().payload["verification"]
    state._observation = ObservationSettings(300)
    with pytest.raises(AuthorizationError):
        state._facts()
    assert port.read("managed-control").payload["verification"] == before
    assert before["expires_at"] == 130.0


def test_configured_root_rejects_default_or_different_host_budget(tmp_path, policy):
    _, _, _, port, state = configured_case(tmp_path, policy, 120)
    for selected in (None, ObservationSettings(60), ObservationSettings(300)):
        with pytest.raises(AuthorizationError):
            ManagedLifecycleState(
                port, "managed-root", "managed-control", OWNER, policy[0], state.manifests,
                state.files, state.transport, observation=selected,
            )


def test_default_observation_window_remains_sixty_seconds(tmp_path, policy):
    service, scope, context, _, state, _, _, _ = public_case(tmp_path, policy)
    plan = service.plan(scope, context)
    result = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    assert not result.errors
    assert state._control().payload["verification"]["expires_at"] == 70.0


def test_review_shows_actual_selected_budget_before_exact_consent(tmp_path, policy):
    service, scope, context, _, _ = configured_case(tmp_path, policy, 120)
    binding = service.plan(scope, context).lifecycle
    shown, asked = [], []

    def ask(prompt):
        asked.append(prompt)
        return "decline"

    review = _Review(ask, shown.append, observation=ObservationSettings(120))
    assert not review.confirm_lifecycle(binding, 0.0)
    assert any("observation max-age=120s" in line for line in shown)
    assert "observation max-age=120s" in asked[0]
    assert binding.plan_digest in asked[0]


def test_non_settings_budget_is_not_a_trusted_host_override(tmp_path, policy):
    _, _, _, port, state = configured_case(tmp_path, policy, 120)
    with pytest.raises(c.ContractError):
        ManagedLifecycleState(
            port, "managed-root", "managed-control", OWNER, policy[0], state.manifests,
            state.files, state.transport, observation={"max_age_seconds": 120},
        )


@pytest.mark.parametrize("seconds", [None, 180])
def test_real_owned_setup_roundtrips_explicit_setting_without_serializing_authority(tmp_path, seconds):
    root = _owned(tmp_path / "consumer", True)
    source, _, manifest = source_case(tmp_path / "consumer")
    document = _owned_document(source, manifest.installation, manifest.generation_id)
    registry = DependencyRegistry.load()
    selected = None if seconds is None else ObservationSettings(seconds)
    state = _seed(root, (document,), registry, owned_source=source, observation=selected)
    review = _Review(lambda _: "decline", lambda _: None)
    service = _host(root, state, (document,), document, registry, review, owned_source=source)
    assert service.state._observation == selected
    expected = state.read("setup-generations").payload["root_manifest"]
    assert ("observation_max_age_seconds" in expected) == (seconds is not None)
    if seconds is not None:
        assert expected["observation_max_age_seconds"] == seconds
