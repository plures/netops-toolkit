"""SOURCE-only fake publisher/host controls; no real publisher/platform qualification."""

from __future__ import annotations

import hashlib
import pickle
from contextlib import contextmanager
from dataclasses import replace
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationError,
    bind_lifecycle,
    lifecycle_plan_digest,
)
from netops.ansible.policy.lifecycle_evidence import lifecycle_arguments_digest
from netops.dependencies._assets import LockedAsset
from netops.dependencies._family_consent import _ScopeReviews
from netops.dependencies._family_ledger import _OwnedFamilyLedger
from netops.dependencies._family_lock import (
    _FAMILIES,
    _FamilyResolver,
    _PublisherSnapshot,
    _RegisteredSource,
    _Release,
    _Requirement,
    _Target,
)
from netops.dependencies._family_provider import (
    _descriptor,
    _FamilyDriver,
    _HostResult,
    _operation,
    _Resource,
)
from netops.dependencies._managed import ManagedMember
from tests.policy.test_lifecycle_execution import DATA, OWNER, D, decision_for, environment
from tests.policy.test_lifecycle_execution import policy as policy

SHA = hashlib.sha256(DATA).hexdigest()
METADATA_BYTES = b"SOURCE-only publisher metadata fixture"
METADATA = hashlib.sha256(METADATA_BYTES).hexdigest()


class Clock:
    value = 10.0

    def monotonic(self):
        return self.value


class Cancel:
    value = False

    def is_cancelled(self):
        return self.value


TARGET = _Target("native", "linux", "x86_64", "3.12.2", "cp312", ("cp312-cp312-linux",), D)


def requirement(name="tool", family="executable", version=">=1", context="native"):
    return _Requirement(name, family, "source", context, version)


def release(req=None, version="1.0", requires=(), **changes):
    req = req or requirement()
    format = {
        "python": "zip", "wheel": "wheel", "executable": "zip",
        "collection": "collection.tar.gz", "library": "zip", "runtime": "zip",
        "image": "oci-manifest", "service": "host-service",
        "os-feature": "host-feature", "distribution": "wsl-rootfs",
    }[req.family]
    scopes = {
        "runtime": ("runtime",), "image": ("image",), "service": ("service",),
        "os-feature": ("os",), "distribution": ("distribution", "wsl"),
    }.get(req.family, ())
    values = dict(
        requirement=req, version=version, format=format, platforms=("linux",),
        architectures=("x86_64",), requires=requires, metadata_digest=METADATA,
        artifact=LockedAsset("source", req.name, "https://publisher.invalid/fixture", SHA, len(DATA))
        if format not in ("host-service", "host-feature") else None,
        python=">=3.9" if req.family == "wheel" else "",
        abis=("cp312",) if req.family == "wheel" else (),
        wheel_tags=("cp312-cp312-linux",) if req.family == "wheel" else (),
        scopes=scopes, resource="fixture-owned-resource"
        if req.family in ("runtime", "image", "service", "os-feature", "distribution") else None,
        members=(ManagedMember(req.name + ".fixture", SHA, len(DATA)),)
        if format in ("zip", "tar.gz", "wheel", "collection.tar.gz", "wsl-rootfs") else (),
    )
    values.update(changes)
    return _Release(**values)


class Source:
    def __init__(self, releases):
        self.releases = releases
        self.calls = []
        self.transform = lambda value: value

    def observe(self, wanted, target, clock, cancel, deadline):
        self.calls.append((wanted, target, deadline))
        return self.transform(_PublisherSnapshot(
            "source", c.digest(target), self.releases, METADATA, 9.0, 60.0,
        ))


def resolve(releases, roots=None, target=TARGET, source=None, clock=None, cancel=None):
    source = source or Source(releases)
    resolver = _FamilyResolver((_RegisteredSource(
        "source", _FAMILIES, ("publisher.invalid",), METADATA, source,
    ),))
    result = resolver.resolve(
        roots or (releases[0].requirement,), (target,), D,
        clock or Clock(), cancel or Cancel(), 70.0,
    )
    return result, source


def test_complete_transitive_lock_backtracks_and_is_prerequisite_ordered():
    dependency = requirement("dependency", version=">=1")
    root = requirement("root")
    fixed = requirement("fixed", version="==1")
    releases = (
        release(root, "2", (replace(dependency, version=">=2"),)),
        release(root, "1", (dependency,)),
        release(fixed, "1", (replace(dependency, version="<2"),)),
        release(dependency, "2"), release(dependency, "1"),
    )
    result, source = resolve(releases, (root, fixed))
    assert not result.needs
    lock = result.lock
    assert [(item.requirement.name, item.version) for item in lock.releases] == [
        ("dependency", "1"), ("root", "1"), ("fixed", "1"),
    ]
    assert len(source.calls) == 1
    lock.__post_init__()
    assert lock.digest == c.digest(lock)


def test_missing_transitive_metadata_does_not_truncate_selected_closure():
    missing = requirement("missing")
    root = release(requires=(missing,))
    result, _ = resolve((root,))
    assert result.lock is None
    assert result.needs[0].requirement == missing
    assert result.needs[0].reason == "compatible-publisher-release-required"


def test_cycle_never_becomes_a_ready_lock():
    a, b = requirement("a"), requirement("b")
    with pytest.raises(c.ContractError):
        resolve((release(a, requires=(b,)), release(b, requires=(a,))))


@pytest.mark.parametrize("changes", [
    {"platforms": ("win32",)}, {"architectures": ("aarch64",)},
    {"python": ">=3.13"}, {"abis": ("cp313",)},
    {"wheel_tags": ("cp313-cp313-linux",)}, {"version": "0.5"},
])
def test_incompatible_metadata_is_typed_needs_input(changes):
    result, _ = resolve((release(requirement(family="wheel"), **changes),))
    assert result.lock is None
    assert result.needs[0].reason == "compatible-publisher-release-required"


@pytest.mark.parametrize("change", [
    {"metadata_digest": SHA}, {"source": "substituted"},
    {"target_digest": SHA}, {"observed_at": 11.0}, {"expires_at": 10.0},
])
def test_publisher_observation_substitution_rejects_before_any_acquisition(change):
    item = release()
    source = Source((item,))
    source.transform = lambda value: replace(value, **change)
    with pytest.raises(c.ContractError):
        resolve((item,), source=source)


def test_wrong_origin_rejects_and_source_family_is_not_widened():
    with pytest.raises(c.ContractError):
        _RegisteredSource("pypi:fixture", ("wheel",), ("publisher.invalid",), METADATA, Source(()))
    item = release(artifact=LockedAsset(
        "source", "tool", "https://other.invalid/fixture", SHA, len(DATA),
    ))
    with pytest.raises(c.ContractError):
        resolve((item,))


@pytest.mark.parametrize("change", [
    {"format": "shell-script"}, {"version": "arbitrary command"},
    {"scopes": ("unregistered",)}, {"requires": (object(),)},
    {"artifact": None},
])
def test_malformed_release_rejects(change):
    with pytest.raises(c.ContractError):
        release(**change)


def test_decline_and_missing_source_never_call_source_port():
    # Selection decline is consumed by the guided bridge, not permission to
    # silently drop its roots from a subsequently complete lock.
    result = _FamilyResolver(()).resolve(
        (requirement(),), (TARGET,), D, Clock(), Cancel(), 60.0,
    )
    assert result.lock is None
    assert result.needs[0].reason == "registered-metadata-source-required"


@pytest.mark.parametrize("cancelled,deadline,error", [
    (True, 60.0, InterruptedError), (False, 10.0, TimeoutError),
])
def test_cancel_and_budget_precede_metadata_io(cancelled, deadline, error):
    source = Source((release(),))
    cancel = Cancel()
    cancel.value = cancelled
    resolver = _FamilyResolver((_RegisteredSource(
        "source", _FAMILIES, ("publisher.invalid",), METADATA, source,
    ),))
    with pytest.raises(error):
        resolver.resolve((requirement(),), (TARGET,), D, Clock(), cancel, deadline)
    assert not source.calls


def test_full_family_lock_requires_collection_controller_compatibility():
    core = requirement("ansible-core", "wheel", ">=2.16")
    releases = [release(core, "2.16")]
    for family in _FAMILIES:
        req = requirement("fixture-" + family, family)
        releases.append(release(req, requires=(core,) if family == "collection" else ()))
    result, _ = resolve(tuple(releases), tuple(item.requirement for item in releases))
    assert result.lock is not None
    assert {item.requirement.family for item in result.lock.releases} == set(_FAMILIES)
    with pytest.raises(c.ContractError):
        release(requirement("fixture", "collection"))


def test_lock_rejects_omitted_transitive_or_unselected_extra_and_reordering():
    dependency = release(requirement("dependency"))
    root = release(requires=(dependency.requirement,))
    result, _ = resolve((root, dependency))
    for values in ((root,), (root, dependency)):
        with pytest.raises(c.ContractError):
            replace(result.lock, releases=values)
    extra = release(requirement("extra"))
    source = result.lock.observations[0]
    with pytest.raises(c.ContractError):
        replace(
            result.lock, releases=(*result.lock.releases, extra),
            observations=(replace(source, releases=(*source.releases, extra)),),
        )


class Ledger:
    def __init__(self):
        self.resource = None
        self.pending = None
        self.revision = 0
        self.writes = []

    @contextmanager
    def lock(self, root):
        yield

    def read(self, root, resource_id):
        return self.revision, self.resource, self.pending

    def begin(self, root, operation, expected_revision):
        assert self.revision == expected_revision
        self.pending = operation
        self.revision += 1
        self.writes.append(("issued", operation))
        return self.revision

    def record(self, root, operation, result, expected_revision):
        assert self.revision == expected_revision and self.pending == operation
        self.pending = None
        self.revision += 1
        self.writes.append(("completed", operation))
        return self.revision


class Host:
    def __init__(self):
        self.calls = []
        self.fail = False
        self.claim = True
        self.result = _HostResult(SHA, True, True, True)

    def apply(self, release, operation, authority, existing):
        if self.claim:
            authority.enter(operation)
        self.calls.append((release, operation, authority))
        if self.fail:
            raise OSError("SOURCE fake host failure")
        return self.result

    python = wheel = executable = collection = library = runtime = image = service = (
        os_feature
    ) = distribution = apply


class ScopeReview:
    def __init__(self):
        self.denied = None
        self.prompts = []

    def confirm_scope(self, binding, scope, occurrence_ids, deadline):
        self.prompts.append((scope, occurrence_ids))
        return scope != self.denied


def admitted(
    tmp_path, policy, family="executable", action="install", owned_ledger=False,
    *, release_changes=None,
):
    core = release(requirement("ansible-core", "wheel", ">=2.16"), "2.16")
    item = release(requirement(family=family), requires=(
        (core.requirement,) if family == "collection" else ()
    ))
    if release_changes is not None:
        item = replace(item, **release_changes)
    result, _ = resolve((item, core) if family == "collection" else (item,))
    lock = result.lock
    operation = _operation(lock, item, action, "generation")
    effect_kind = {
        "install": "dependency-stage", "verify": "dependency-verify",
        "remove": "dependency-uninstall",
    }[action]
    env = environment(tmp_path, policy, effect_kind)
    plan, _, port, state, review, consent, broker, clock, _ = env
    if owned_ledger:
        facts = port.read("facts")
        root_manifest = c.public_object({
            **dict(facts.payload["root_manifest"]), "family_lock_digest": lock.digest,
        })
        port.seed("facts", {**dict(facts.payload), "root_manifest": root_manifest})
        plan = replace(plan, root=replace(plan.root, manifest_digest=c.digest(root_manifest)))
    descriptor = _descriptor(lock, item, operation, plan.root, "occurrence")
    categories = descriptor["consequential"]
    generation = replace(
        plan.generation, content_digest=SHA, manifest_digest=lock.digest, selected=(),
    )
    if action == "remove":
        generation = replace(generation, selected=(generation,))
    port.seed("generation", {
        "generation_id": "generation", "ordinal": 0, "content": tuple(DATA),
        "manifest": c.wire(lock),
    })
    if action == "install":
        source_content = DATA if item.artifact is not None else METADATA_BYTES
        port.seed("source", {
            "schema": "a02-owned-inert-v1", "content": tuple(source_content),
            "content_digest": hashlib.sha256(source_content).hexdigest(),
            "manifest": c.wire(operation),
        })
    port.seed(operation.resource_id, {
        "schema": "a02-owned-inert-v1", "reserved": True, "manifest": c.wire(lock),
    })
    port.seed("step", descriptor)
    pins = ()
    if action == "remove":
        pin = c.public_object({
            "generation_id": "generation", "manifest_digest": lock.digest,
            "revision": 0, "holders": (),
        })
        port.seed("pin", pin)
        pins = (pin,)
    occurrence = replace(
        plan.effects[0], resource_id=operation.resource_id,
        arguments_digest=lifecycle_arguments_digest(descriptor),
    )
    plan = replace(
        plan, generation=generation, effects=(occurrence,),
        required_consequential=tuple(
            lc.ConsequentialRequirement(category, ("occurrence",)) for category in categories
        ),
        content=c.public_object({
            **dict(plan.content), "steps": (descriptor,), "pins": pins,
        }),
    )
    plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    binding = bind_lifecycle(plan)
    scope_reviews = _ScopeReviews(ScopeReview())
    scope_review = scope_reviews.review(lock, binding, clock, Cancel(), 20.0)
    decision = decision_for(policy, binding)
    assert decision.decision == "allow"
    grant = broker.issue_lifecycle(plan, consent.review(plan, 10.0, 20.0), decision, 10.0)
    session = broker.consume_lifecycle(grant, binding, 10.0)
    effect = lc.LifecycleEffectBinding(binding, str(uuid4()), state.snapshot_lifecycle(binding).revision,
                                      "occurrence")
    permit = broker.permit_lifecycle(session, effect, 10.0)
    ledger, host = Ledger(), Host()
    if action != "install":
        ledger.resource = _Resource(
            operation.resource_id, "generation", lock.digest, c.digest(item),
            SHA, True, False, (),
        )
    if owned_ledger:
        port.seed("family-ledger", {
            "schema": "netops-family-resources-v1", "root": c.wire(binding.root),
            "lock_digest": lock.digest,
            "resources": (c.wire(ledger.resource),) if ledger.resource is not None else (),
            "pending": (),
        })
        ledger = _OwnedFamilyLedger(port, binding.root, "family-ledger", OWNER, policy[0], lock,
                                   state, clock)
    driver = _FamilyDriver(host, ledger, clock, scope_reviews, scope_review)
    return driver, lock, item, operation, broker, permit, effect, Cancel(), host, ledger, clock


@pytest.mark.parametrize("family", (
    "python", "wheel", "executable", "library", "runtime", "image", "service",
    "os-feature", "distribution", "collection",
))
def test_family_driver_consumes_actual_broker_permit_once(tmp_path, policy, family):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, family,
    )
    receipt = driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert receipt.result.verified
    assert len(host.calls) == 1
    assert [kind for kind, _ in ledger.writes] == ["issued", "completed"]
    with pytest.raises(AuthorizationError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert len(host.calls) == 1
    with pytest.raises(TypeError):
        pickle.dumps(host.calls[0][2])


@pytest.mark.parametrize("field,value", [
    ("owned", False), ("active", True), ("pins", ("another-generation",)),
    ("healthy_previous", True), ("identity_digest", METADATA),
])
def test_cleanup_preserves_unknown_external_pinned_active_and_previous(
    tmp_path, policy, field, value,
):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, "service", "remove",
    )
    ledger.resource = replace(ledger.resource, **{field: value})
    if field == "identity_digest":
        host.result = _HostResult(SHA, True, True, True)
    with pytest.raises(AuthorizationError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    if field != "identity_digest":
        assert not host.calls and not ledger.writes
    else:
        assert ledger.pending == operation


@pytest.mark.parametrize("case", ("cancel", "expiry", "wrong-operation", "wrong-permit", "pending"))
def test_family_guard_rejects_without_host_effect(tmp_path, policy, case):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, clock = admitted(
        tmp_path, policy,
    )
    if case == "cancel":
        cancel.value = True
    elif case == "expiry":
        clock.value = 30.0
    elif case == "wrong-operation":
        operation = replace(operation, resource_id="wrong")
    elif case == "wrong-permit":
        permit = lc.LifecycleEffectPermit()
    else:
        ledger.pending = operation
    with pytest.raises(AuthorizationError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert not host.calls and not ledger.writes


def test_issued_host_failure_retains_uncertainty_not_automatic_resume(tmp_path, policy):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy,
    )
    host.fail = True
    with pytest.raises(OSError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert ledger.pending == operation
    assert len(ledger.writes) == 1


def test_host_cannot_claim_changed_operation_or_return_unentered_success(tmp_path, policy):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy,
    )
    host.claim = False
    with pytest.raises(AuthorizationError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert ledger.pending == operation
    authority = host.calls[0][2]
    assert repr(authority) == "<private family authority>"
    with pytest.raises(AuthorizationError):
        authority.enter(replace(operation, action="remove"))


def test_owned_family_ledger_retains_actual_membership_and_exact_issued_cas(tmp_path, policy):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, owned_ledger=True,
    )
    receipt = driver.execute(lock, item, operation, broker, permit, effect, cancel)
    revision, owned, pending = ledger.read(effect.lifecycle.root, operation.resource_id)
    assert revision == receipt.ledger_revision == 2
    assert pending is None and owned.owned
    assert owned.identity_digest == SHA and owned.generation_id == "generation"
    with pytest.raises(AuthorizationError):
        ledger.begin(effect.lifecycle.root, operation, 0)
    with pytest.raises(AuthorizationError):
        ledger.record(effect.lifecycle.root, operation, receipt.result, revision)


def test_owned_family_ledger_preserves_unfinished_io_and_refuses_unknown_root(tmp_path, policy):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, owned_ledger=True,
    )
    host.fail = True
    with pytest.raises(OSError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    revision, owned, pending = ledger.read(effect.lifecycle.root, operation.resource_id)
    assert revision == 1 and owned is None and pending == operation
    with pytest.raises(AuthorizationError):
        ledger.begin(effect.lifecycle.root, operation, revision)
    with pytest.raises(AuthorizationError):
        ledger.read(replace(effect.lifecycle.root, resource_id="unknown"), operation.resource_id)


@pytest.mark.parametrize("damage", (
    "owner", "policy", "root", "schema", "lock", "duplicate", "pending-format", "extra-field",
))
def test_owned_family_ledger_rejects_tampered_membership_before_effect(tmp_path, policy, damage):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, owned_ledger=True,
    )
    port = ledger._state
    record = port.read("family-ledger")
    values = dict(record.payload)
    if damage == "owner":
        port.seed("family-ledger", values, owner=SHA)
    elif damage == "policy":
        record = replace(record, policy_identity=replace(policy[0], bundle_sha256=SHA),
                         policy_digest=SHA)
        port.filename("family-ledger").write_bytes(record.to_bytes())
    else:
        if damage == "root":
            values["root"] = c.wire(replace(effect.lifecycle.root, resource_id="unknown"))
        elif damage == "schema":
            values["schema"] = "unrecognized"
        elif damage == "lock":
            values["lock_digest"] = SHA
        elif damage == "duplicate":
            resource = _Resource(operation.resource_id, "generation", lock.digest,
                                 c.digest(item), SHA, True, False, ())
            values["resources"] = (c.wire(resource), c.wire(resource))
        elif damage == "pending-format":
            values["pending"] = ({"arbitrary": "command"},)
        else:
            values["unknown"] = True
        port.seed("family-ledger", values)
    with pytest.raises((c.ContractError, AuthorizationError)):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert not host.calls


@pytest.mark.parametrize("action", ("verify", "remove"))
def test_owned_ledger_verify_and_remove_preserve_exact_remaining_membership(tmp_path, policy, action):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, action=action, owned_ledger=True,
    )
    host.result = _HostResult(SHA, action == "remove", True, True)
    receipt = driver.execute(lock, item, operation, broker, permit, effect, cancel)
    revision, owned, pending = ledger.read(effect.lifecycle.root, operation.resource_id)
    assert revision == receipt.ledger_revision == 2 and pending is None
    assert (owned is None) == (action == "remove")


@pytest.mark.parametrize("case", (
    "wrong-resource", "wrong-generation", "wrong-lock", "wrong-release",
    "missing-resource", "malformed-resource", "bad-begin-cas", "bad-final-cas",
    "unverified-result", "unowned-result", "untyped-result",
))
def test_exact_resource_and_factual_completion_guards(tmp_path, policy, case):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, action="remove" if case == "missing-resource" else "install",
    )
    if case.startswith("wrong-"):
        ledger.resource = _Resource(
            operation.resource_id, "generation", lock.digest, c.digest(item), SHA, True, False, (),
        )
        field, value = {
            "wrong-resource": ("resource_id", "other"),
            "wrong-generation": ("generation_id", "other"),
            "wrong-lock": ("lock_digest", SHA),
            "wrong-release": ("release_digest", SHA),
        }[case]
        ledger.resource = replace(ledger.resource, **{field: value})
    elif case == "missing-resource":
        ledger.resource = None
    elif case == "malformed-resource":
        ledger.resource = object()
    elif case == "bad-begin-cas":
        ledger.begin = lambda *args: 100
    elif case == "bad-final-cas":
        ledger.record = lambda *args: 100
    elif case == "unverified-result":
        host.result = replace(host.result, verified=False)
    elif case == "unowned-result":
        host.result = replace(host.result, owned=False)
    else:
        host.result = object()
    with pytest.raises((c.ContractError, AuthorizationError)):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    if case in ("bad-final-cas", "unverified-result", "unowned-result", "untyped-result"):
        assert len(host.calls) == 1
    else:
        assert not host.calls


def test_port_authority_rechecks_cancellation_and_original_deadline(tmp_path, policy):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, clock = admitted(
        tmp_path, policy,
    )
    original = host.executable

    def cancel_before_claim(*args):
        cancel.value = True
        return original(*args)

    host.executable = cancel_before_claim
    with pytest.raises(AuthorizationError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert ledger.pending == operation and not host.calls


def test_port_authority_rejects_backward_clock_and_repeat_claim(tmp_path, policy):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, clock = admitted(
        tmp_path, policy,
    )
    driver.execute(lock, item, operation, broker, permit, effect, cancel)
    authority = host.calls[0][2]
    with pytest.raises(AuthorizationError):
        authority.enter(operation)
    clock.value = 9.0
    with pytest.raises(AuthorizationError):
        authority.check()


def test_metadata_parser_absence_is_typed_needs_input(monkeypatch):
    import builtins

    original = builtins.__import__

    def without_packaging(name, *args, **kwargs):
        if name.startswith("packaging."):
            raise ImportError("SOURCE dependency-denial control")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_packaging)
    result, _ = resolve((release(),))
    assert result.lock is None and result.needs[0].reason == "metadata-parser-required"


def test_metadata_observation_consumes_original_budget_without_renewal():
    clock = Clock()
    source = Source((release(),))

    def late(value):
        clock.value = 71.0
        return value

    source.transform = late
    with pytest.raises(TimeoutError):
        resolve(source.releases, source=source, clock=clock)


def test_missing_target_and_wrong_registered_family_do_not_call_source():
    req = requirement(context="controller")
    source = Source((release(req),))
    resolver = _FamilyResolver((_RegisteredSource(
        "source", ("python",), ("publisher.invalid",), METADATA, source,
    ),))
    result = resolver.resolve((req,), (TARGET,), D, Clock(), Cancel(), 60.0)
    assert result.needs[0].reason == "consuming-target-required" and not source.calls
    result = resolver.resolve((requirement(),), (TARGET,), D, Clock(), Cancel(), 60.0)
    assert result.needs[0].reason == "registered-metadata-source-required" and not source.calls


def test_invalid_version_and_incomplete_member_manifest_reject_before_acquisition():
    with pytest.raises(c.ContractError):
        resolve((release(requirement(version="not-a-specifier")),))
    with pytest.raises(c.ContractError):
        release(members=())
    with pytest.raises(c.ContractError):
        release(members=(ManagedMember("a", SHA, 1), ManagedMember("A", SHA, 1)))


@pytest.mark.parametrize("changes", [
    {"artifact": object()}, {"requires": [requirement()]},
    {"members": (object(),)}, {"extra_requires": (("extra", (object(),)),)},
    {"extra_requires": (("same", ()), ("same", ()))},
    {"extra_requires": (("extra", [requirement()]),)},
    {"extra_requires": (("not-a-pair",),)}, {"version": ""},
])
def test_normalized_publisher_schema_cannot_smuggle_untyped_operations(changes):
    with pytest.raises(c.ContractError):
        release(**changes)


@pytest.mark.parametrize("family,changes", [
    ("runtime", {"resource": None}),
    ("service", {"artifact": LockedAsset(
        "source", "tool", "https://publisher.invalid/fixture", SHA, len(DATA),
    )}),
    ("distribution", {"scopes": ("distribution",)}),
    ("distribution", {"format": "vm-image", "members": (), "scopes": ("distribution", "vm")}),
])
def test_consequential_publisher_metadata_requires_exact_resource_and_every_scope(family, changes):
    with pytest.raises(c.ContractError):
        release(requirement(family=family), **changes)


def test_untyped_snapshot_and_unregistered_family_do_not_reach_an_asset_port():
    item = release(requirement(family="python"))
    source = Source((item,))
    source.transform = lambda value: {"claimed_snapshot": True}
    with pytest.raises(c.ContractError):
        resolve((item,), source=source)
    source.transform = lambda value: value
    source.releases = (item, release(requirement("injected", "image")))
    resolver = _FamilyResolver((_RegisteredSource(
        "source", ("python",), ("publisher.invalid",), METADATA, source,
    ),))
    with pytest.raises(c.ContractError):
        resolver.resolve((item.requirement,), (TARGET,), D, Clock(), Cancel(), 60.0)


def test_owned_ledger_rechecks_real_root_cancellation_after_broker_entry(
    tmp_path, policy, monkeypatch,
):
    from netops.dependencies._family_provider import _Authority

    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, owned_ledger=True,
    )
    original = _Authority._admit

    def cancel_after_admit(authority):
        original(authority)
        facts = ledger._state.read("facts")
        ledger._state.seed("facts", {**dict(facts.payload), "cancelled": True},
                           revision=facts.revision)

    monkeypatch.setattr(_Authority, "_admit", cancel_after_admit)
    with pytest.raises(AuthorizationError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert not host.calls
    assert ledger.read(effect.lifecycle.root, operation.resource_id) == (0, None, None)


def test_owned_ledger_rejects_unknown_root_and_malformed_resource_on_private_port(
    tmp_path, policy,
):
    _, lock, _, operation, _, _, effect, _, _, ledger, _ = admitted(
        tmp_path, policy, owned_ledger=True,
    )
    root = effect.lifecycle.root
    with pytest.raises(AuthorizationError):
        with ledger.lock(replace(effect.lifecycle, root=replace(root, resource_id="unknown"))):
            pytest.fail("unknown root was locked")
    with pytest.raises(AuthorizationError):
        ledger.begin(replace(root, resource_id="unknown"), operation, 0)
    with pytest.raises(AuthorizationError):
        ledger.record(replace(root, resource_id="unknown"), operation,
                      _HostResult(SHA, True, True, True), 0)
    record = ledger._state.read("family-ledger")
    ledger._state.seed("family-ledger", {**dict(record.payload), "resources": ({"unknown": True},)})
    with pytest.raises(c.ContractError):
        ledger.read(root, operation.resource_id)


def test_interrupted_telemetry_preserves_actual_source_failure_and_completed_host_fact(
    tmp_path, policy, monkeypatch,
):
    from netops.dependencies import _family_lock, _family_provider

    def broken_sink(*args, **kwargs):
        raise KeyboardInterrupt()

    def broken_source(value):
        raise OSError("SOURCE fake metadata failure")

    monkeypatch.setattr(_family_lock._LOG, "debug", broken_sink)
    item = release()
    source = Source((item,))
    source.transform = broken_source
    with pytest.raises(OSError):
        resolve((item,), source=source)
    assert source.calls
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy,
    )
    monkeypatch.setattr(_family_provider._LOG, "info", broken_sink)
    assert driver.execute(lock, item, operation, broker, permit, effect, cancel).result.verified
    assert host.calls and ledger.pending is None


@pytest.mark.parametrize("at_revision", (1, 2))
def test_owned_resource_cas_failure_never_erases_issued_uncertainty(
    tmp_path, policy, monkeypatch, at_revision,
):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, owned_ledger=True,
    )
    port = ledger._state
    original = port.compare_replace

    def reject_resource_cas(resource_id, expected_revision, following):
        if resource_id == "family-ledger" and following.revision == at_revision:
            return port.read(resource_id)
        return original(resource_id, expected_revision, following)

    monkeypatch.setattr(port, "compare_replace", reject_resource_cas)
    with pytest.raises(AuthorizationError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    revision, owned, pending = ledger.read(effect.lifecycle.root, operation.resource_id)
    assert revision == at_revision - 1 and owned is None
    assert (pending == operation) == (at_revision == 2)
    assert len(host.calls) == at_revision - 1


@pytest.mark.parametrize("damage", ("resource-lock", "pending-lock", "oversize", "record-type"))
def test_owned_ledger_rejects_cross_lock_membership_and_unbounded_or_untyped_records(
    tmp_path, policy, monkeypatch, damage,
):
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, owned_ledger=True,
    )
    port = ledger._state
    record = port.read("family-ledger")
    values = dict(record.payload)
    resource = _Resource(operation.resource_id, "generation", lock.digest,
                         c.digest(item), SHA, True, False, ())
    if damage == "resource-lock":
        values["resources"] = (c.wire(replace(resource, lock_digest=SHA)),)
    elif damage == "pending-lock":
        values["pending"] = (c.wire(replace(operation, lock_digest=SHA)),)
    elif damage == "oversize":
        values["resources"] = (c.wire(resource),) * 257
    else:
        original = port.read
        monkeypatch.setattr(port, "read", lambda key: (
            object() if key == "family-ledger" else original(key)
        ))
    if damage != "record-type":
        port.seed("family-ledger", values)
    with pytest.raises((c.ContractError, AuthorizationError)):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert not host.calls
