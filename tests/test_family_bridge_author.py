"""SOURCE-only full-family planning/review controls; no real platform effects."""

from dataclasses import replace

import pytest

from netops import setup
from netops.ansible import contracts as c
from netops.ansible.policy.authorization import AuthorizationError
from netops.dependencies import _guided as g
from netops.dependencies._family_bridge import _FamilyPlanning, _requirement
from netops.dependencies._family_consent import _ScopeReviews
from netops.dependencies._family_lock import _RegisteredSource
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_family_provider_author import (
    METADATA,
    TARGET,
    Cancel,
    Clock,
    ScopeReview,
    Source,
    admitted,
    release,
    requirement,
    resolve,
)
from tests.test_guided_first_run_author import report_from, service_case


def test_extras_added_by_a_later_consumer_expand_only_the_requested_graph():
    shared = requirement("shared")
    optional = requirement("optional")
    root = requirement("root")
    item = release(shared, extra_requires=(("security", (optional,)), ("container", ())))
    parent = release(root, requires=(replace(shared, extras=("security",)),))
    result, _ = resolve(
        (item, parent, release(optional)), roots=(shared, root),
    )
    assert result.lock is not None
    assert {row.requirement.name for row in result.lock.releases} == {"shared", "root", "optional"}
    assert result.lock.selected_extras == ((shared.key, ("security",)),)
    assert not result.needs
    with pytest.raises(c.ContractError):
        replace(result.lock, selected_extras=())


def test_unknown_extra_metadata_is_needs_input_not_ignored():
    requested = replace(requirement(), extras=("unknown",))
    result, _ = resolve((release(requested),))
    assert result.lock is None
    assert result.needs[0].reason == "requested-extra-metadata-required"


def test_unrequested_container_extra_does_not_enter_default_closure():
    root, container = requirement(), requirement("container", "runtime")
    item = release(root, extra_requires=(("container", (container,)),))
    result, _ = resolve((item, release(container)))
    assert result.lock.releases == (item,)
    assert result.lock.selected_extras == ()
    with pytest.raises(c.ContractError):
        replace(result.lock, selected_extras=((root.key, ("container",)),))


def test_declined_complete_scope_does_not_invoke_metadata_ports(tmp_path, monkeypatch):
    registry, scope, context, service, _ = service_case(tmp_path, monkeypatch)
    diagnosis = g._diagnose(service, scope, context, probe=True)
    source = Source(())
    planner = _FamilyPlanning((_RegisteredSource(
        "source", ("python",), ("publisher.invalid",), METADATA, source,
    ),), (TARGET,))
    result, needs = planner.resolve(
        diagnosis, g._Selection((("native-python", "decline"),)), registry,
        Clock(), Cancel(), 60.0,
    )
    assert result is None and needs[0].reason == "component-declined"
    assert not source.calls


def test_full_guided_census_projects_every_alias_and_future_registered_consumer(
    tmp_path, monkeypatch,
):
    registry, _, context, service, _ = service_case(tmp_path, monkeypatch)
    scope = c.InstallScope((), (), full_toolkit=True, enhanced=True)
    diagnosis = g._diagnose(service, scope, context, probe=True)
    choices = g._Selection(tuple((item.dependency, "install") for item in diagnosis.components))
    planner = _FamilyPlanning((), (TARGET, replace(TARGET, context="controller")))
    lock, needs = planner.resolve(diagnosis, choices, registry, Clock(), Cancel(), 60.0)
    assert lock is None
    assert {item.dependency for item in needs} == {item.dependency for item in diagnosis.components}
    assert all(item.reason == "registered-metadata-source-required" for item in needs)
    assert _requirement(registry.entry("ansible-playbook")).key == (
        _requirement(registry.entry("ansible-core")).key
    )
    assert _requirement(registry.entry("molecule-cli")).key == (
        _requirement(registry.entry("molecule")).key
    )


def test_guided_resolver_consumes_trusted_typed_metadata_without_descriptor_json(
    tmp_path, monkeypatch,
):
    registry, scope, context, service, _ = service_case(tmp_path, monkeypatch)
    registry.entries = tuple(
        replace(entry, source="source") if entry.id == "native-python" else entry
        for entry in registry.entries
    )
    diagnosis = g._diagnose(service, scope, context, probe=True)
    wanted = _requirement(registry.entry("native-python"))
    item = release(wanted, "3.12.2")
    source = Source((item,))
    planner = _FamilyPlanning((_RegisteredSource(
        "source", ("python",), ("publisher.invalid",), METADATA, source,
    ),), (TARGET,))
    lock, needs = planner.resolve(
        diagnosis, g._Selection((("native-python", "install"),)), registry,
        Clock(), Cancel(), 60.0,
    )
    assert lock is not None and not needs and lock.roots == (wanted,)
    assert source.calls and lock.registry_digest == registry.digest


@pytest.mark.parametrize("scope", ("service", "runtime", "image", "os", "wsl", "distribution"))
def test_distinct_semantic_scopes_require_actual_separate_review(tmp_path, policy, scope):
    family = {
        "service": "service", "runtime": "runtime", "image": "image",
        "os": "os-feature", "wsl": "distribution", "distribution": "distribution",
    }[scope]
    _, lock, _, _, _, _, effect, cancel, _, _, clock = admitted(tmp_path, policy, family)
    review = ScopeReview()
    review.denied = scope
    reviews = _ScopeReviews(review)
    with pytest.raises(AuthorizationError):
        reviews.review(lock, effect.lifecycle, clock, cancel, 20.0)
    assert scope in tuple(name for name, _ in review.prompts)


@pytest.mark.parametrize("damage", ("missing", "foreign", "expired", "replayed"))
def test_semantic_review_is_not_serialized_selection_or_generic_category_assent(
    tmp_path, policy, damage,
):
    driver, lock, item, operation, broker, permit, effect, cancel, host, _, clock = admitted(
        tmp_path, policy, "service",
    )
    if damage == "missing":
        driver._scope_review = None
    elif damage == "foreign":
        driver._scope_reviews = _ScopeReviews(ScopeReview())
    elif damage == "expired":
        driver._scope_reviews = _ScopeReviews(ScopeReview())
        driver._scope_review = driver._scope_reviews.review(
            lock, effect.lifecycle, clock, cancel, 11.0,
        )
        clock.value = 11.0
    else:
        driver._scope_reviews.consume(
            driver._scope_review, lock, effect.lifecycle, "occurrence", ("service",), 10.0,
        )
    with pytest.raises(AuthorizationError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert not host.calls


@pytest.mark.parametrize("case", ("cancel", "expiry", "backward"))
def test_scope_review_rechecks_original_control_after_trusted_prompt(tmp_path, policy, case):
    _, lock, _, _, _, _, effect, cancel, _, _, clock = admitted(tmp_path, policy, "service")
    review = ScopeReview()

    def changes_control(*args):
        if case == "cancel":
            cancel.value = True
        elif case == "expiry":
            clock.value = 20.0
        else:
            clock.value = 9.0
        return True

    review.confirm_scope = changes_control
    with pytest.raises(AuthorizationError):
        _ScopeReviews(review).review(lock, effect.lifecycle, clock, cancel, 20.0)


def test_transitive_family_needs_retain_source_and_context(tmp_path, monkeypatch):
    registry, scope, context, service, _ = service_case(tmp_path, monkeypatch)
    registry.entries = tuple(
        replace(entry, source="source") if entry.id == "native-python" else entry
        for entry in registry.entries
    )
    diagnosis = g._diagnose(service, scope, context, probe=True)
    wanted = _requirement(registry.entry("native-python"))
    missing = requirement("transitive", "library")
    item = release(wanted, "3.12.2", requires=(missing,))
    planner = _FamilyPlanning((_RegisteredSource(
        "source", ("python", "library"), ("publisher.invalid",), METADATA, Source((item,)),
    ),), (TARGET,))
    lock, needs = planner.resolve(
        diagnosis, g._Selection((("native-python", "install"),)), registry,
        Clock(), Cancel(), 60.0,
    )
    assert lock is None
    assert needs[0].dependency == "native:transitive" and needs[0].source == "source"
    assert needs[0].kind == "library"


def test_public_checkpoint_retains_each_prospective_scope_without_issuing_grants(
    tmp_path, monkeypatch, capsys,
):
    root = tmp_path / "new-guided-root"
    service_case(root, monkeypatch, status="missing")

    def choose_install_and_scope_review(prompt):
        return "install" if "Reuse/Install/Decline" in prompt else "review"

    monkeypatch.setattr("builtins.input", choose_install_and_scope_review)
    assert setup.main(["install", "--root", str(root), "--enhanced"]) == 3
    before = report_from(capsys.readouterr().out)
    monkeypatch.setattr("builtins.input", lambda _: "")
    assert setup.main([
        "install", "--root", str(root), "--enhanced", "--checkpoint", before["checkpoint"],
    ]) == 3
    after = report_from(capsys.readouterr().out)
    assert after["selection"] == before["selection"]
    assert all(value == "review" for _, value in after["selection"]["categories"])
    assert after["consent_issued"] is False and after["effects_performed"] == []
    assert not root.exists()


@pytest.mark.parametrize("when", ("before-review", "expired", "cancelled", "over-budget"))
def test_detailed_review_cannot_be_renewed_or_consumed_before_its_observation(
    tmp_path, policy, when,
):
    driver, lock, _, _, _, _, effect, cancel, _, _, clock = admitted(
        tmp_path, policy, "service",
    )
    reviews = _ScopeReviews(ScopeReview())
    if when == "cancelled":
        cancel.value = True
    if when in ("expired", "cancelled", "over-budget"):
        with pytest.raises(AuthorizationError):
            reviews.review(
                lock, effect.lifecycle, clock, cancel,
                311.0 if when == "over-budget" else 20.0 if when == "cancelled" else 10.0,
            )
    else:
        with pytest.raises(AuthorizationError):
            driver._scope_reviews.consume(
                driver._scope_review, lock, effect.lifecycle, "occurrence", ("service",), 9.0,
            )


def test_vm_distribution_uses_vm_authority_and_separate_distribution_review_not_wsl(
    tmp_path, policy,
):
    driver, lock, item, operation, broker, permit, effect, cancel, host, _, _ = admitted(
        tmp_path, policy, "distribution", release_changes={
            "format": "vm-image", "members": (),
            "scopes": ("distribution", "vm", "virtualization"),
        },
    )
    assert tuple(
        item.category for item in effect.lifecycle.required_consequential
    ) == ("vm-change",)
    review = driver._scope_reviews._review
    assert {scope for scope, _ in review.prompts} == {"distribution", "vm", "virtualization"}
    assert driver.execute(lock, item, operation, broker, permit, effect, cancel).result.verified
    assert len(host.calls) == 1 and host.calls[0][:2] == (item, operation)


def test_future_registry_exact_version_is_not_weakened_to_any_publisher_release(
    tmp_path, monkeypatch,
):
    registry, _, _, _, _ = service_case(tmp_path, monkeypatch)
    wanted = _requirement(replace(
        registry.entry("native-python"), source="source", version="3.13.1",
    ))
    result, _ = resolve((release(wanted, "3.13.2"),), roots=(wanted,))
    assert result.lock is None and result.needs[0].reason == "compatible-publisher-release-required"
