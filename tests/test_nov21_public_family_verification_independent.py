"""Original full-family safety obligations; fake boundaries are SOURCE only."""

from dataclasses import replace

import pytest

from netops import setup
from netops.ansible import contracts as c
from netops.ansible.policy.authorization import AuthorizationBroker, AuthorizationError
from netops.dependencies._assets import HttpsAssetTransport
from netops.dependencies._family_consent import _ScopeReceipt, _ScopeReviews
from netops.dependencies._family_ledger import _OwnedFamilyLedger
from netops.dependencies._family_lock import _FamilyResolver
from netops.dependencies._family_provider import _Authority, _FamilyDriver, _Resource
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_family_provider_author import SHA, admitted
from tests.test_nov21_guided_entrypoint_independent import first_run as first_run
from tests.test_nov21_guided_entrypoint_independent import public_report, selected_closure
from tests.test_nov21_provider_stage_independent import (
    TARGET,
    release,
    requirement,
    resolve,
    resolver,
)


@pytest.fixture(autouse=True)
def source_only_transport_boundary(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("A SOURCE public-family control attempted an unconfigured real HTTP read.")

    monkeypatch.setattr(HttpsAssetTransport, "read", forbidden)
    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", forbidden)


def test_ac003_public_saved_review_choices_cannot_issue_any_actual_grant(
    first_run, monkeypatch, capsys,
):
    root, sentinel, _, _ = first_run
    before = sentinel.read_bytes()

    def forbidden(*args, **kwargs):
        pytest.fail("A prospective component/scope choice issued actual lifecycle authority.")

    for name in ("issue_lifecycle", "consume_lifecycle", "permit_lifecycle"):
        monkeypatch.setattr(AuthorizationBroker, name, forbidden)
    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: "install" if "Reuse/Install/Decline" in prompt else "review",
    )
    assert setup.main(["install", "--root", str(root), "--enhanced"]) != 0
    initial = public_report(capsys.readouterr().out)
    monkeypatch.setattr("builtins.input", lambda prompt: "")
    assert setup.main(initial["next_command"][6:]) != 0
    resumed = public_report(capsys.readouterr().out)
    assert resumed["selection"] == initial["selection"]
    assert all(value == "review" for _, value in resumed["selection"]["categories"])
    assert resumed["consent_issued"] is False and resumed["effects_performed"] == []
    assert not root.exists() and sentinel.read_bytes() == before


def test_ac001_descriptor_free_full_selection_consumes_the_production_family_resolver(
    first_run, monkeypatch, capsys,
):
    """Missing integration must fail, not qualify an unused private Protocol."""
    root, sentinel, _, _ = first_run
    observed = []
    original = _FamilyResolver.resolve

    def unconfigured_external_boundary(*args, **kwargs):
        pytest.fail("Public family composition needs a SOURCE transport fixture, not real HTTP.")

    monkeypatch.setattr(HttpsAssetTransport, "read", unconfigured_external_boundary)
    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", unconfigured_external_boundary)

    def observing(self, roots, targets, registry_digest, clock, cancel, deadline):
        observed.append((roots, targets, registry_digest, tuple(self._sources.values())))
        return original(self, roots, targets, registry_digest, clock, cancel, deadline)

    monkeypatch.setattr(_FamilyResolver, "resolve", observing)
    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: "install" if "Reuse/Install/Decline" in prompt else "review",
    )
    assert setup.main(["install", "--root", str(root), "--enhanced"]) != 0
    report = public_report(capsys.readouterr().out)
    assert report["status"] == "NeedsInput"
    _, required = selected_closure(True)
    assert {item["dependency"] for item in report["closure"]} == required
    assert not root.exists() and sentinel.read_bytes() == b"native-user-data: retained\n"
    assert observed, (
        "The actual descriptor-free public full selection never consumed the production "
        "family resolver: complete family metadata/host provisioning is still unintegrated."
    )
    assert observed[0][3], "No actual registered publisher metadata clients were composed."


def test_ac001_requested_wheel_extra_adds_its_unknown_transitive_before_any_effect():
    helper = release("unknown-extra-helper")
    root = replace(
        release("extra-parent"),
        extra_requires=(("render", (helper.requirement,)), ("unused", (requirement("absent"),))),
    )
    engine, source = resolver((root, helper))
    result = resolve(engine, (replace(root.requirement, extras=("render",)),))
    assert result.lock is not None and not result.needs
    assert [item.requirement.name for item in result.lock.releases] == [
        "unknown-extra-helper", "extra-parent",
    ]
    assert result.lock.selected_extras == ((root.requirement.key, ("render",)),)
    assert len(source.calls) == 1
    assert source.calls[0][1] == TARGET
    with pytest.raises(c.ContractError):
        replace(result.lock, selected_extras=())


@pytest.mark.parametrize("damage", ["remove", "append-unselected", "reorder"])
def test_ac001_locked_exact_closure_rejects_omitted_extra_or_unselected_members(damage):
    helper = release("closure-helper")
    parent = release("closure-parent", requires=(helper.requirement,))
    extra = release("unselected-member")
    engine, _ = resolver((helper, parent, extra))
    result = resolve(engine, (parent.requirement,))
    lock = result.lock
    assert lock is not None and not result.needs
    changed = {
        "remove": (parent,),
        "append-unselected": (*lock.releases, extra),
        "reorder": tuple(reversed(lock.releases)),
    }[damage]
    with pytest.raises(c.ContractError):
        replace(lock, releases=changed)


@pytest.mark.parametrize("scope", ["os", "elevation", "security", "reboot"])
def test_ac003_every_semantic_scope_is_conjunctive_not_a_generic_install_yes(
    tmp_path, policy, scope,
):
    values = admitted(
        tmp_path, policy, "os-feature",
        release_changes={"scopes": ("os", "elevation", "security", "reboot")},
    )
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, clock = values

    class DenyOne:
        calls = []

        def confirm_scope(self, binding, selected, occurrences, deadline):
            self.calls.append((selected, occurrences, deadline))
            return selected != scope

    prompt = DenyOne()
    reviews = _ScopeReviews(prompt)
    with pytest.raises(AuthorizationError):
        reviews.review(lock, effect.lifecycle, clock, cancel, 20.0)
    assert any(selected == scope for selected, _, _ in prompt.calls)
    no_receipt_driver = _FamilyDriver(host, ledger, clock, reviews)
    with pytest.raises(AuthorizationError):
        no_receipt_driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert host.calls == [] and ledger.writes == []
    assert ledger.pending is None
    assert driver is not no_receipt_driver


@pytest.mark.parametrize("damage", ["constructed", "foreign", "expired", "backward", "binding"])
def test_ac003_live_detailed_review_cannot_be_forged_retargeted_or_renewed(
    tmp_path, policy, damage,
):
    values = admitted(tmp_path, policy, "service")
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, clock = values
    receipt = driver._scope_review
    if damage == "constructed":
        receipt = _ScopeReceipt()
    elif damage == "foreign":
        class Yes:
            def confirm_scope(self, *args):
                return True

        receipt = _ScopeReviews(Yes()).review(lock, effect.lifecycle, clock, cancel, 20.0)
    elif damage == "expired":
        clock.value = 20.0
    elif damage == "backward":
        clock.value = 9.0
    else:
        with pytest.raises(AuthorizationError):
            driver._scope_reviews.consume(
                receipt, lock, replace(effect.lifecycle, context_digest="f" * 64),
                effect.occurrence_id, operation.scopes, clock.value,
            )
        return
    with pytest.raises(AuthorizationError):
        driver.execute(
            lock, item, operation, broker, permit, effect, cancel, scope_review=receipt,
        )
    assert host.calls == [] and ledger.writes == [] and ledger.pending is None


@pytest.mark.parametrize("flag", [
    "setup_enabled", "owned_valid", "pins_valid", "probes_valid",
])
def test_ac011_owned_root_facts_rechecked_inside_actual_lock_after_admission(
    tmp_path, policy, monkeypatch, flag,
):
    values = admitted(tmp_path, policy, owned_ledger=True)
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = values
    original_admit = _Authority._admit
    original_snapshot = ledger._lifecycle.snapshot_lifecycle

    def drift_after_admit(authority):
        original_admit(authority)

        def changed(binding):
            return replace(original_snapshot(binding), **{flag: False})

        monkeypatch.setattr(ledger._lifecycle, "snapshot_lifecycle", changed)

    before = ledger._state.read("family-ledger")
    monkeypatch.setattr(_Authority, "_admit", drift_after_admit)
    with pytest.raises(AuthorizationError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert host.calls == []
    assert ledger._state.read("family-ledger") == before
    assert ledger.read(effect.lifecycle.root, operation.resource_id) == (0, None, None)


def test_ac011_remove_preserves_other_generation_pins_and_native_user_data(tmp_path, policy):
    values = admitted(tmp_path, policy, action="remove", owned_ledger=True)
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = values
    sentinel = tmp_path / "existing-native-backup.cfg"
    sentinel.write_bytes(b"native-user-data-must-remain")
    retained = tuple(
        c.public_object(c.wire(_Resource(
            "retained-" + kind, "previous-" + kind, lock.digest,
            c.digest(item), SHA, True, kind == "active",
            ("existing-reader",) if kind == "pinned" else (),
            kind == "healthy",
        ))) for kind in ("active", "pinned", "healthy")
    )
    old = ledger._state.read("family-ledger")
    ledger._state.seed(
        "family-ledger",
        {**dict(old.payload), "resources": (*old.payload["resources"], *retained)},
        revision=old.revision,
    )
    receipt = driver.execute(lock, item, operation, broker, permit, effect, cancel)
    after = ledger._state.read("family-ledger")
    assert after.payload["resources"] == retained
    assert after.payload["pending"] == ()
    assert receipt.ledger_revision == after.revision == 2
    assert sentinel.read_bytes() == b"native-user-data-must-remain"


def test_ac011_interrupted_owned_effect_survives_fresh_ledger_without_replay(
    tmp_path, policy,
):
    values = admitted(tmp_path, policy, owned_ledger=True)
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, clock = values
    host.fail = True
    with pytest.raises(OSError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    reconstructed = _OwnedFamilyLedger(
        ledger._state, effect.lifecycle.root, ledger._resource_id, ledger._owner,
        ledger._policy, lock, ledger._lifecycle, clock,
    )
    assert reconstructed.read(effect.lifecycle.root, operation.resource_id) == (1, None, operation)
    before = ledger._state.read("family-ledger")
    with pytest.raises(AuthorizationError):
        reconstructed.begin(effect.lifecycle.root, operation, 1)
    assert ledger._state.read("family-ledger") == before
    assert len(host.calls) == 1
