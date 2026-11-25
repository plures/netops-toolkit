"""Original configurable observation bounds never renew an issued authority."""

import time
from dataclasses import replace

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
from netops.dependencies._setup import _Review
from netops.dependencies.service import DependencyService
from tests.test_nov19_independent_controller_execution import Cancel
from tests.test_nov19_successor_public_installer import managed_environment


def configured():
    """Choose180 for an unadmitted fixture root, before any plan or prompt."""
    env = managed_environment()
    old = env["service"]
    record = env["records"].read("managed-root")
    root = dict(record.payload["root_manifest"])
    root["observation_max_age_seconds"] = 180
    env["records"].records["managed-root"] = replace(record, payload=c.public_object({
        **dict(record.payload), "root_manifest": root,
    }))
    observation = ObservationSettings(180)
    state = ManagedLifecycleState(
        env["records"], "managed-root", "managed-control", record.ownership_token,
        record.policy_identity, (env["manifest"],), env["files"], env["transport"],
        observation=observation,
    )
    prompts, displayed = [], []

    def exact(prompt):
        prompts.append(prompt)
        return prompt.split("Type '", 1)[1].split("'", 1)[0]

    adapter = _Review(exact, displayed.append, observation=observation)
    broker = AuthorizationBroker(
        object(), TrustedConsentAdapter(env["review"]), lifecycle_state=state,
        lifecycle_consent=TrustedLifecycleConsentAdapter(adapter),
    )
    # Initialize the existing fake fixture's time, not the system clock. The
    # trusted source review adapter checks real time against its issued deadline.
    env["clock"].now = time.monotonic()
    service = DependencyService(
        old.registry, old.adapters, state, old.policy, broker, env["clock"], old.events,
    )
    env.update(service=service, state=state, prompts=prompts, displayed=displayed)
    return env


@pytest.mark.parametrize("seconds", [1, 60, 180, 300])
def test_ac003_original_observation_range_and_unchanged_default(seconds):
    assert ObservationSettings().max_age_seconds == 60
    assert ObservationSettings(seconds).max_age_seconds == seconds


@pytest.mark.parametrize("seconds", [0, 301, True, float("nan"), float("inf")])
def test_ac003_outside_original_observation_range_never_creates_setting(seconds):
    with pytest.raises((c.ContractError, ValueError, TypeError)):
        ObservationSettings(seconds)


def test_ac003_new_budget_is_root_bound_before_exact_public_review():
    env = configured()
    service = env["service"]
    before_writes = list(env["records"].writes)
    plan = service.plan(env["scope"], env["context"])
    root = env["records"].read("managed-root").payload["root_manifest"]
    assert root["observation_max_age_seconds"] == 180
    assert plan.lifecycle.root.manifest_digest == c.digest(root)
    assert env["records"].writes == before_writes
    service.review(plan, env["clock"].now, 300.0)
    assert len(env["prompts"]) == 1
    assert env["prompts"][0] == (
        f"observation max-age=180s. Type 'install {plan.lifecycle.plan_digest}' to consent: "
    )
    assert any("source/tree probe window=60s" in row for row in env["displayed"])
    assert env["files"].calls == [] and env["transport"].calls == []


@pytest.mark.parametrize("drift", ["host-setting", "owned-manifest"])
def test_ac003_changed_budget_after_review_cannot_reuse_plan_or_consent(drift):
    env = configured()
    service = env["service"]
    plan = service.plan(env["scope"], env["context"])
    consent = service.review(plan, env["clock"].now, 300.0)
    if drift == "host-setting":
        service.state._observation = ObservationSettings(300)
    else:
        record = env["records"].read("managed-root")
        root = dict(record.payload["root_manifest"])
        root["observation_max_age_seconds"] = 300
        env["records"].records["managed-root"] = replace(record, payload=c.public_object({
            **dict(record.payload), "root_manifest": root,
        }))
    with pytest.raises((AuthorizationError, c.ContractError)):
        service.provision(plan, consent, Cancel())
    assert env["files"].calls == [] and env["transport"].calls == []


def test_ac003_larger_new_observation_setting_never_renews_expired_consent():
    env = configured()
    service = env["service"]
    plan = service.plan(env["scope"], env["context"])
    consent = service.review(plan, env["clock"].now, 1.0)
    pointer = c.wire(service.state.pointer())
    env["clock"].now += 1.0
    # Public lifecycle denial is a typed InstallOutcome, not necessarily an
    # exception. The original new-test version and exact zero-effect diagnostic
    # are retained in nov21apt-expiry-diagnostic-EVIDENCE.json.
    result = service.provision(plan, consent, Cancel())
    assert result.status == c.OutcomeStatus.BLOCKED
    assert result.errors and all(error.reason == c.ReasonCode.CONSENT_STALE for error in result.errors)
    assert result.steps and all(
        step.status == c.OutcomeStatus.BLOCKED and not step.changed for step in result.steps
    )
    assert c.wire(service.state.pointer()) == pointer
    assert env["files"].calls == [] and env["transport"].calls == []
