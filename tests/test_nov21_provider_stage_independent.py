"""Original full-family closure constraints, explicitly SOURCE-only metadata ports.

These are not vendor metadata observations, real installer effects, publisher
qualification or public guided-flow proof. No network or service is used.
"""

from dataclasses import replace
from hashlib import sha256

import pytest

from netops.ansible import contracts as c
from netops.dependencies._assets import LockedAsset
from netops.dependencies._family_lock import (
    _FamilyResolver,
    _PublisherSnapshot,
    _RegisteredSource,
    _Release,
    _Requirement,
    _Target,
)
from netops.dependencies._managed import ManagedMember
from tests.policy.test_lifecycle_execution import policy as policy

SOURCE = "SOURCE-ONLY-independent-metadata"
METADATA = "a" * 64
REGISTRY = "b" * 64
CONTEXT = "c" * 64
TARGET = _Target("native", "source-platform", "source-arch", "3.12.8", "cp312",
                 ("cp312-cp312-source_arch",), CONTEXT)
FAMILIES = (
    "python", "wheel", "executable", "collection", "library", "runtime",
    "image", "service", "os-feature", "distribution",
)


class Clock:
    value = 10.0

    def monotonic(self):
        return self.value


class Cancel:
    value = False

    def is_cancelled(self):
        return self.value


class Metadata:
    """Deliberate external metadata fixture, never a trusted live publisher."""

    def __init__(self, releases):
        self.releases = tuple(releases)
        self.calls = []
        self.digest = METADATA
        self.expires = 50.0
        self.after = None

    def observe(self, requirement, target, clock, cancel, deadline):
        self.calls.append((requirement, target, deadline))
        value = _PublisherSnapshot(
            SOURCE, c.digest(target), self.releases, self.digest, 5.0, self.expires,
        )
        if self.after is not None:
            self.after(clock)
        return value


def requirement(name, family="wheel", version=">=1"):
    return _Requirement(name, family, SOURCE, "native", version)


def release(name, family="wheel", *, requires=(), version="1.0", scopes=()):
    formats = {
        "python": "zip", "wheel": "wheel", "executable": "zip",
        "collection": "collection.tar.gz", "library": "zip", "runtime": "zip",
        "image": "oci-manifest", "service": "host-service",
        "os-feature": "host-feature", "distribution": "wsl-rootfs",
    }
    categories = {
        "runtime": ("runtime",), "image": ("image",), "service": ("service",),
        "os-feature": ("os",), "distribution": ("distribution", "wsl"),
    }
    artifact = None if family in ("service", "os-feature") else LockedAsset(
        SOURCE, name, "https://source-fixture.invalid/not-a-vendor-asset",
        "d" * 64, 1,
    )
    return _Release(
        requirement(name, family), version, formats[family],
        (TARGET.platform,), (TARGET.architecture,), tuple(requires), METADATA, artifact,
        ">=3.9" if family == "wheel" else "",
        (TARGET.abi,) if family == "wheel" else (),
        TARGET.wheel_tags if family == "wheel" else (),
        scopes or categories.get(family, ()),
        name if family in categories else None,
        members=(ManagedMember("source-member", sha256(b"source-only").hexdigest(), 11),)
        if family not in ("image", "service", "os-feature") else (),
    )


def resolver(releases):
    port = Metadata(releases)
    source = _RegisteredSource(
        SOURCE, FAMILIES, ("source-fixture.invalid",), METADATA, port,
    )
    return _FamilyResolver((source,)), port


def resolve(engine, roots, clock=None, cancel=None, deadline=40.0):
    return engine.resolve(
        tuple(roots), (TARGET,), REGISTRY, clock or Clock(), cancel or Cancel(), deadline,
    )


def test_ac001_all_ten_families_lock_unknown_transitive_before_any_acquisition():
    helper = release("unknown-transitive-helper")
    core = release("ansible-core")
    values = [
        release(
            "ansible-core" if family == "wheel" else "source-" + family,
            family,
            requires=(core.requirement,) if family == "collection" else (
                (helper.requirement,) if family == "library" else ()
            ),
        ) for family in FAMILIES
    ]
    engine, metadata = resolver((*values, helper))
    result = resolve(engine, [value.requirement for value in values])
    assert not result.needs and result.lock is not None
    lock = result.lock
    assert {value.requirement.family for value in lock.releases} == set(FAMILIES)
    assert len(lock.releases) == 11
    assert "unknown-transitive-helper" in [value.requirement.name for value in lock.releases]
    assert len(metadata.calls) == 1
    positions = {value.requirement.key: index for index, value in enumerate(lock.releases)}
    for selected in lock.releases:
        assert all(positions[edge.key] < positions[selected.requirement.key]
                   for edge in selected.requires)
    assert lock.observations[0].metadata_digest == METADATA
    assert lock.registry_digest == REGISTRY and lock.targets == (TARGET,)


def test_ac001_missing_unknown_transitive_is_actionable_without_partial_lock():
    root = release("source-top", requires=(requirement("not-in-snapshot"),))
    engine, _ = resolver((root,))
    result = resolve(engine, (root.requirement,))
    assert result.lock is None
    assert any(value.requirement.name == "not-in-snapshot" for value in result.needs)
    assert all(value.fields for value in result.needs)


def test_ac001_transitive_version_solver_backtracks_before_locking():
    old = release("shared", version="1.0")
    new = release("shared", version="2.0")
    root = release("source-top", requires=(requirement("shared", version=">=1"),))
    constraint = requirement("shared", version="<2")
    engine, _ = resolver((root, new, old))
    result = resolve(engine, (root.requirement, constraint))
    assert result.lock is not None and not result.needs
    assert next(value.version for value in result.lock.releases
                if value.requirement.name == "shared") == "1.0"


def test_ac001_cyclic_publisher_transitives_never_produce_a_lock():
    first = release("source-a", requires=(requirement("source-b"),))
    second = release("source-b", requires=(first.requirement,))
    engine, _ = resolver((first, second))
    with pytest.raises(c.ContractError):
        resolve(engine, (first.requirement,))


@pytest.mark.parametrize("damage", ["abi", "tag", "python", "platform", "architecture"])
def test_ac001_incompatible_family_metadata_never_becomes_ready(damage):
    value = release("source-wheel")
    mutation = {
        "abi": {"abis": ("cp311",)}, "tag": {"wheel_tags": ("cp311-cp311-other",)},
        "python": {"python": "<3.12"}, "platform": {"platforms": ("other-platform",)},
        "architecture": {"architectures": ("other-arch",)},
    }
    engine, _ = resolver((replace(value, **mutation[damage]),))
    result = resolve(engine, (value.requirement,))
    assert result.lock is None and result.needs
    assert all(need.reason == "compatible-publisher-release-required" for need in result.needs)


@pytest.mark.parametrize("damage", ["digest", "expired", "deadline", "backward", "cancel"])
def test_ac003_publisher_lock_rejects_changed_metadata_and_original_budget(damage):
    value = release("source-wheel")
    engine, metadata = resolver((value,))
    clock, cancel = Clock(), Cancel()
    if damage == "digest":
        metadata.digest = "e" * 64
    elif damage == "expired":
        metadata.expires = 10.0
    elif damage == "deadline":
        metadata.after = lambda current: setattr(current, "value", 40.0)
    elif damage == "backward":
        metadata.after = lambda current: setattr(current, "value", 9.0)
    else:
        metadata.after = lambda current: setattr(cancel, "value", True)
    expected = {
        "digest": c.ContractError, "expired": c.ContractError,
        "deadline": TimeoutError, "backward": c.ContractError, "cancel": InterruptedError,
    }
    with pytest.raises(expected[damage]):
        resolve(engine, (value.requirement,), clock, cancel)
    assert len(metadata.calls) == 1


def test_fr004_omitted_consequential_category_rejected_before_provider_dispatch():
    for family in ("runtime", "image", "service", "os-feature", "distribution"):
        value = release("source-" + family, family)
        with pytest.raises(c.ContractError):
            replace(value, scopes=())


@pytest.mark.parametrize("damage", ["category", "replay", "expired", "pending"])
def test_ac003_real_family_broker_blocks_mismatched_or_stale_host_entry(
    tmp_path, policy, damage,
):
    from netops.ansible.policy.authorization import AuthorizationError
    from tests.test_family_provider_author import admitted

    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, clock = admitted(
        tmp_path, policy, "service",
    )
    if damage == "category":
        operation = replace(operation, scopes=("elevation",))
    elif damage == "expired":
        clock.value = 30.0
    elif damage == "pending":
        ledger.pending = operation
    else:
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    before_calls, before_writes = len(host.calls), len(ledger.writes)
    with pytest.raises(AuthorizationError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert len(host.calls) == before_calls and len(ledger.writes) == before_writes


def test_ac011_family_failed_io_retains_issued_marker_and_cannot_automatically_replay(
    tmp_path, policy,
):
    from netops.ansible.policy.authorization import AuthorizationError
    from tests.test_family_provider_author import admitted

    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, "service",
    )
    host.fail = True
    with pytest.raises(OSError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert ledger.pending == operation
    assert [kind for kind, _ in ledger.writes] == ["issued"]
    assert len(host.calls) == 1
    host.fail = False
    with pytest.raises(AuthorizationError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert len(host.calls) == 1 and ledger.pending == operation


@pytest.mark.parametrize("fails", [False, True])
def test_ac011_driver_consumes_protected_family_ledger_not_only_memory_fixture(
    tmp_path, policy, fails,
):
    from netops.ansible.policy.authorization import AuthorizationError
    from tests.test_family_provider_author import admitted

    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, "service", owned_ledger=True,
    )
    root = effect.lifecycle.root
    assert ledger.read(root, operation.resource_id) == (0, None, None)
    host.fail = fails
    if fails:
        with pytest.raises(OSError):
            driver.execute(lock, item, operation, broker, permit, effect, cancel)
        revision, resource, pending = ledger.read(root, operation.resource_id)
        assert revision == 1 and resource is None and pending == operation
    else:
        receipt = driver.execute(lock, item, operation, broker, permit, effect, cancel)
        revision, resource, pending = ledger.read(root, operation.resource_id)
        assert revision == receipt.ledger_revision == 2 and pending is None
        assert resource.owned and not resource.active and not resource.pins
        assert resource.generation_id == operation.generation_id
        assert resource.lock_digest == lock.digest and resource.release_digest == c.digest(item)
    before = ledger.read(root, operation.resource_id)
    with pytest.raises(AuthorizationError):
        driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert len(host.calls) == 1 and ledger.read(root, operation.resource_id) == before


@pytest.mark.parametrize("family,scopes", [
    ("runtime", ("runtime",)), ("image", ("image",)), ("service", ("service",)),
    ("os-feature", ("os",)), ("distribution", ("distribution", "wsl")),
])
def test_fr004_actual_driver_keeps_distinct_semantic_reviews_before_host_entry(
    tmp_path, policy, family, scopes,
):
    from tests.test_family_provider_author import admitted

    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, family,
    )
    prompts = driver._scope_reviews._review.prompts
    assert tuple(scope for scope, _ in prompts) == scopes
    assert all(occurrences == (effect.occurrence_id,) for _, occurrences in prompts)
    assert not host.calls and not ledger.writes
    receipt = driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert receipt.result.verified and len(host.calls) == 1
    with pytest.raises(c.ContractError):
        c.wire(driver._scope_review)


@pytest.mark.parametrize("damage", ["missing", "foreign", "expired"])
def test_fr004_valid_lifecycle_permit_does_not_replace_exact_separate_scope_review(
    tmp_path, policy, damage,
):
    from netops.ansible.policy.authorization import AuthorizationError
    from netops.dependencies._family_provider import _FamilyDriver
    from tests.test_family_provider_author import admitted

    (tmp_path / "service").mkdir()
    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, clock = admitted(
        tmp_path / "service", policy, "service",
    )
    override = None
    if damage == "missing":
        driver = _FamilyDriver(host, ledger, clock)
    elif damage == "foreign":
        (tmp_path / "runtime").mkdir()
        other = admitted(tmp_path / "runtime", policy, "runtime")
        override = other[0]._scope_review
    else:
        # Detailed scope review expires at20, before the actual broker grant30.
        clock.value = 20.0
    assert broker.reconcile_lifecycle(permit) == effect
    with pytest.raises(AuthorizationError):
        driver.execute(
            lock, item, operation, broker, permit, effect, cancel, scope_review=override,
        )
    assert not host.calls and not ledger.writes


@pytest.mark.parametrize("family", FAMILIES)
def test_ac001_source_real_broker_dispatches_each_family_only_to_its_fixed_effect_port(
    tmp_path, policy, family,
):
    from tests.test_family_provider_author import admitted

    driver, lock, item, operation, broker, permit, effect, cancel, host, ledger, _ = admitted(
        tmp_path, policy, family,
    )
    consumed = []
    expected = family.replace("-", "_")
    for selected in FAMILIES:
        name = selected.replace("-", "_")

        def fixed(release, operation, authority, existing, selected=name):
            consumed.append(selected)
            return host.apply(release, operation, authority, existing)

        setattr(host, name, fixed)
    if family == "collection":
        assert any(
            dependency.requirement.name == "ansible-core" for dependency in lock.releases
        )
    receipt = driver.execute(lock, item, operation, broker, permit, effect, cancel)
    assert consumed == [expected] and len(host.calls) == 1
    assert receipt.operation == operation and receipt.result.verified
    assert [kind for kind, _ in ledger.writes] == ["issued", "completed"]
