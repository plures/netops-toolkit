"""Offline SOURCE controls at the real publisher and managed-host boundaries."""

import hashlib
import json
import logging
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.artifacts import OwnedState
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    TrustedConsentAdapter,
    TrustedLifecycleConsentAdapter,
)
from netops.dependencies import _setup
from netops.dependencies._assets import AssetResponse, HttpsAssetTransport, LockedAsset
from netops.dependencies._composition import ManagedLifecycleState, _native_phase
from netops.dependencies._family_bridge import _requirement
from netops.dependencies._family_codec import _decode_lock
from netops.dependencies._family_integration import (
    _MaterializedFamilies,
    _validate_archives,
    _validate_entries,
)
from netops.dependencies._family_lock import (
    _FamilyLock,
    _FamilyResolver,
    _PublisherSnapshot,
    _Release,
    _Requirement,
)
from netops.dependencies._installation import _InstallationSpec, _predictable_path_limit, _Wheel
from netops.dependencies._managed import (
    ManagedArchive,
    ManagedMember,
    ProtectedGenerationFiles,
    unpack,
)
from netops.dependencies._publisher_metadata import (
    _edges,
    _PublisherMetadata,
    _registered_publishers,
)
from netops.dependencies.service import DependencyService
from tests.policy.test_lifecycle_execution import OWNER, Review
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_family_provider_author import TARGET, Cancel, Clock, D, release, resolve
from tests.test_i02_corrective_managed import manifest_for
from tests.test_i02_public_flow import public_case


def publisher_case(*, collection=False, requirements=None, extras=()):
    body = b"known offline publisher archive fixture"
    digest = hashlib.sha256(body).hexdigest()
    if collection:
        requirement = _Requirement("ansible.utils", "collection", "galaxy:ansible.utils",
                                   "native", ">=1")
        artifact = LockedAsset(requirement.source, requirement.name,
                               "https://galaxy.ansible.com/download/ansible-utils-1.0.tar.gz",
                               digest, len(body))
        document = {
            "version": "1.0", "namespace": {"name": "ansible"},
            "collection": {"name": "utils"}, "download_url": artifact.url,
            "artifact": {"sha256": digest, "size": len(body)},
            "metadata": {"dependencies": {"ansible.netcommon": ">=6"}},
            "requires_ansible": ">=2.16",
        }
        edges = (
            _Requirement("ansible.netcommon", "collection", "galaxy:ansible.netcommon",
                         "native", ">=6"),
            _Requirement("ansible-core", "wheel", "pypi:ansible-core", "native", ">=2.16"),
        )
        expected_extras = ()
        format = "collection.tar.gz"
        python, tags = "", ()
        member = "collections/ansible-utils-1.0.tar.gz"
    else:
        requirement = _Requirement("demo", "wheel", "pypi:demo", "native", ">=1")
        filename = "demo-1.0-py3-none-any.whl"
        artifact = LockedAsset(requirement.source, "demo",
                               "https://files.pythonhosted.org/packages/" + filename,
                               digest, len(body))
        document = {
            "info": {
                "name": "Demo", "version": "1.0", "requires_python": ">=3.9",
                "requires_dist": requirements or [], "provides_extra": list(extras),
            },
            "urls": [{
                "url": artifact.url, "packagetype": "bdist_wheel", "yanked": False,
                "size": len(body), "digests": {"sha256": digest}, "filename": filename,
            }],
        }
        edges, expected_extras = _edges(requirements or [], TARGET, extras)
        format, python, tags = "wheel", ">=3.9", ("py3-none-any",)
        member = "wheels/" + filename
    content = json.dumps(document, sort_keys=True).encode()
    item = _Release(
        requirement, "1.0", format, ("linux",), ("x86_64",), edges,
        hashlib.sha256(content).hexdigest(), artifact, python=python, wheel_tags=tags,
        members=(ManagedMember(member, digest, len(body)),), extra_requires=expected_extras,
    )
    return item, document, content, body


def transport_for(monkeypatch, content, calls=None, transform=None):
    calls = [] if calls is None else calls

    def read(self, url, timeout, limit, clock, cancel):
        calls.append((url, timeout, limit, cancel))
        response = AssetResponse(url, content)
        return transform(response) if transform is not None else response

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", read)
    return HttpsAssetTransport(), calls


@pytest.mark.parametrize("collection", (False, True))
def test_real_closed_client_uses_only_official_metadata_not_artifact_url(monkeypatch, collection):
    item, _, content, _ = publisher_case(collection=collection)
    transport, calls = transport_for(monkeypatch, content)
    source, = _registered_publishers((item,), transport)
    snapshot = source.port.observe(item.requirement, TARGET, Clock(), Cancel(), 50.0)
    assert snapshot.releases == (item,) and snapshot.metadata_digest == source.metadata_digest
    assert snapshot.target_digest == c.digest(TARGET)
    assert 10.0 == snapshot.observed_at < snapshot.expires_at <= 50.0
    assert len(calls) == 1 and calls[0][1:3] == (40.0, 1024 * 1024 + 1)
    assert calls[0][0] != item.artifact.url
    assert calls[0][0].startswith(
        "https://galaxy.ansible.com/api/v3/" if collection else "https://pypi.org/pypi/demo/1.0/"
    )


def test_metadata_projection_evaluates_markers_in_target_not_review_host():
    base, extras = _edges([
        "base>=1", "win-only; sys_platform == 'win32'",
        "linux-only; sys_platform == 'linux'", "optional[child]>=2; extra == 'pdf'",
    ], TARGET, ("pdf", "container"))
    assert [edge.name for edge in base] == ["base", "linux-only"]
    assert extras[0][1] == (
        _Requirement("optional", "wheel", "pypi:optional", "native", ">=2", ("child",)),
    )
    assert extras[1] == ("container", ())


@pytest.mark.parametrize("requirements", (
    ["demo @ https://unapproved.invalid/file.whl"], ["not a valid requirement!"],
    [1], ["x" * 4097], "not-a-list", ["demo"] * 257,
))
def test_external_dependency_text_cannot_supply_urls_or_unbounded_parser_input(requirements):
    with pytest.raises((c.ContractError, ValueError)):
        _edges(requirements, TARGET, ())


@pytest.mark.parametrize("damage", (
    "name", "version", "python", "size", "hash", "yanked", "format", "filename",
    "tags", "extras", "dependencies", "duplicate-file", "no-files", "unknown-info",
))
def test_even_independently_pinned_json_must_confirm_exact_wheel_projection(monkeypatch, damage):
    item, document, _, _ = publisher_case()
    info, artifact = document["info"], document["urls"][0]
    if damage == "name":
        info["name"] = "substitute"
    elif damage == "version":
        info["version"] = "2"
    elif damage == "python":
        info["requires_python"] = ">=99"
    elif damage == "size":
        artifact["size"] += 1
    elif damage == "hash":
        artifact["digests"]["sha256"] = D
    elif damage == "yanked":
        artifact["yanked"] = True
    elif damage == "format":
        artifact["packagetype"] = "sdist"
    elif damage == "filename":
        artifact["filename"] = "other-1.0-py3-none-any.whl"
    elif damage == "tags":
        item = replace(item, wheel_tags=("cp312-cp312-linux",))
    elif damage == "extras":
        info["provides_extra"] = ["unexpected"]
    elif damage == "dependencies":
        info["requires_dist"] = ["hidden>=1"]
    elif damage == "duplicate-file":
        document["urls"].append(artifact.copy())
    elif damage == "no-files":
        document["urls"] = {}
    else:
        document["info"] = []
    content = json.dumps(document).encode()
    item = replace(item, metadata_digest=hashlib.sha256(content).hexdigest())
    transport, _ = transport_for(monkeypatch, content)
    with pytest.raises((c.ContractError, ValueError)):
        _PublisherMetadata((item,), transport).observe(item.requirement, TARGET,
                                                       Clock(), Cancel(), 50.0)


@pytest.mark.parametrize("damage", ("hash", "duplicate-json", "redirect", "oversize", "late", "cancel"))
def test_real_boundary_retains_exact_pin_origin_and_original_control(monkeypatch, damage):
    item, _, content, _ = publisher_case()
    clock, cancel = Clock(), Cancel()
    if damage == "hash":
        content += b" "
    elif damage == "duplicate-json":
        content = b'{"info":{},"info":{}}'
        item = replace(item, metadata_digest=hashlib.sha256(content).hexdigest())
    elif damage == "oversize":
        content = b" " * (1024 * 1024 + 1)
        item = replace(item, metadata_digest=hashlib.sha256(content).hexdigest())

    def transform(response):
        if damage == "redirect":
            return AssetResponse("https://evil.invalid/json", response.content)
        if damage == "late":
            clock.value = 50.0
        if damage == "cancel":
            cancel.value = True
        return response

    transport, calls = transport_for(monkeypatch, content, transform=transform)
    with pytest.raises((c.ContractError, TimeoutError, InterruptedError)):
        _PublisherMetadata((item,), transport).observe(item.requirement, TARGET,
                                                       clock, cancel, 50.0)
    assert len(calls) == 1


@pytest.mark.parametrize("damage", ("dependency", "core", "hash", "namespace", "url"))
def test_collection_metadata_preserves_core_and_collection_transitive_edges(monkeypatch, damage):
    item, document, _, _ = publisher_case(collection=True)
    if damage == "dependency":
        document["metadata"]["dependencies"]["new.collection"] = ">=1"
    elif damage == "core":
        document["requires_ansible"] = None
    elif damage == "hash":
        document["artifact"]["sha256"] = D
    elif damage == "namespace":
        document["namespace"]["name"] = "other"
    else:
        document["download_url"] = "https://evil.invalid/substitute"
    content = json.dumps(document).encode()
    item = replace(item, metadata_digest=hashlib.sha256(content).hexdigest())
    transport, _ = transport_for(monkeypatch, content)
    with pytest.raises(c.ContractError):
        _PublisherMetadata((item,), transport).observe(item.requirement, TARGET,
                                                       Clock(), Cancel(), 50.0)


def test_requested_extra_is_part_of_the_observed_projection(monkeypatch):
    item, _, content, _ = publisher_case(
        requirements=["optional>=2; extra == 'pdf'"], extras=("pdf", "container"),
    )
    transport, _ = transport_for(monkeypatch, content)
    snapshot = _PublisherMetadata((item,), transport).observe(item.requirement, TARGET,
                                                             Clock(), Cancel(), 50.0)
    assert snapshot.releases[0].extra_requires[0][1][0].name == "optional"


def test_actual_client_feeds_the_existing_compatible_lock_resolver(monkeypatch):
    item, _, content, _ = publisher_case()
    transport, _ = transport_for(monkeypatch, content)
    target = replace(TARGET, wheel_tags=("py3-none-any",))
    lock = _FamilyResolver(_registered_publishers((item,), transport)).resolve(
        (item.requirement,), (target,), D, Clock(), Cancel(), 50.0,
    ).lock
    assert lock.releases == (item,) and lock.observations[0].metadata_digest != D
    assert _decode_lock(json.loads(c.canonical_bytes(lock))) == lock


@pytest.mark.parametrize("damage", ("extra-field", "source-port", "members", "target", "extras"))
def test_retained_lock_codec_never_decodes_executable_or_grant_authority(damage):
    result, _ = resolve((release(),))
    encoded = json.loads(c.canonical_bytes(result.lock))
    if damage == "extra-field":
        encoded["trusted"] = True
    elif damage == "source-port":
        encoded["observations"][0]["port"] = {"observe": "callable"}
    elif damage == "members":
        encoded["releases"][0]["members"][0]["path"] = "../escape"
    elif damage == "target":
        encoded["targets"][0]["wheel_tags"] = "not-a-sequence"
    else:
        encoded["selected_extras"] = [[]]
    with pytest.raises(c.ContractError):
        _decode_lock(encoded)


def test_raw_locked_wheel_is_staged_without_an_invented_outer_publisher_archive(policy):
    item, _, _, body = publisher_case()
    archive = ManagedArchive(item.artifact, "file", item.members)
    original = manifest_for(policy[0], body)
    manifest = replace(original, asset=archive.asset, archive="file",
                       members=archive.members, archives=(), installation=None)
    files = unpack(manifest, body, Clock(), Cancel(), 50.0)
    assert len(files) == 1 and files[0].content == body
    assert files[0].member.path.endswith(".whl")
    with pytest.raises(c.ContractError):
        unpack(manifest, body + b"substitution", Clock(), Cancel(), 50.0)


@pytest.mark.parametrize("damage", ("extra", "mode", "hash", "size"))
def test_raw_archive_does_not_weaken_exact_member_or_mode_guards(damage):
    item, _, _, _ = publisher_case()
    member, = item.members
    members = {
        "extra": (member, replace(member, path="other")),
        "mode": (replace(member, executable=True),),
        "hash": (replace(member, digest=D),),
        "size": (replace(member, size=1),),
    }[damage]
    with pytest.raises(c.ContractError):
        ManagedArchive(item.artifact, "file", members)


def managed_family_case(tmp_path, policy):
    control = tmp_path / "source-control"
    control.mkdir()
    service, scope, context, port, state, effects, engine, _ = public_case(control, policy)
    root = _setup._owned(tmp_path / "protected-materialized", True)
    manifest, = state.manifests
    lock_asset = replace(manifest.asset, source_id="python.org")
    manifest = replace(
        manifest, asset=lock_asset,
        archives=(ManagedArchive(lock_asset, manifest.archive, manifest.members),),
    )
    wanted = _requirement(service.registry.entry("native-python"))
    item = _Release(
        wanted, "3.12.10", "zip", ("linux",), ("x86_64",), (), D,
        lock_asset, members=manifest.members,
    )
    target = replace(TARGET, context_digest=manifest.consuming_contexts[0])
    observation = _PublisherSnapshot("python.org", c.digest(target), (item,), D, 9.0, 60.0)
    lock = _FamilyLock((wanted,), (target,), (item,), (observation,), service.registry.digest)
    facts = port.read("managed-root")
    root_manifest = c.public_object({
        **dict(c.public_object(facts.payload["root_manifest"])),
        "registered_manifests": (c.wire(manifest),),
        "family_locks": ((manifest.generation_id, c.wire(lock)),),
    })
    port.seed("managed-root", {
        **dict(facts.payload), "root_manifest": root_manifest,
    })
    root_binding = lc.OwnedRootBinding("managed-root", c.digest(root_manifest))
    ledger_id = "family-ledger-" + c.digest(manifest.generation_id)
    port.seed(ledger_id, {
        "schema": "netops-family-resources-v1", "root": c.wire(root_binding),
        "lock_digest": lock.digest, "resources": (), "pending": (),
    })
    state = ManagedLifecycleState(
        port, "managed-root", "managed-control", OWNER, policy[0], (manifest,),
        ProtectedGenerationFiles(root), effects,
        family_locks=((manifest.generation_id, lock),),
    )
    review = Review()
    broker = AuthorizationBroker(
        None, TrustedConsentAdapter(review), lifecycle_state=state,
        lifecycle_consent=TrustedLifecycleConsentAdapter(review),
    )
    service = DependencyService(
        service.registry, service.adapters, state, engine, broker, service.clock, service.events,
    )
    return service, scope, context, port, state, lock, ledger_id, root


def test_original_public_owner_dispatches_actual_materialized_family_with_owned_ledger(
    tmp_path, policy,
):
    service, scope, context, port, state, lock, ledger_id, _ = managed_family_case(tmp_path, policy)
    plan = service.plan(scope, context)
    assert not plan.blocked
    assert [effect.occurrence_id for effect in plan.lifecycle.effects][2:4] == [
        "family-install-0", "family-verify-0",
    ]
    assert not port.writes
    result = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    assert len(result.steps) == 5, result
    assert all(step.status == c.OutcomeStatus.SUCCEEDED for step in result.steps), result
    assert not any(step.changed for step in result.steps[2:4])
    ledger = port.read(ledger_id)
    assert ledger.revision == 4 and len(ledger.payload["resources"]) == 1
    assert ledger.payload["pending"] == ()
    assert ledger.payload["resources"][0]["lock_digest"] == lock.digest
    assert state.pointer() == lc.AbsentPointer("absent", 0)
    activation = service.plan(scope, context)
    assert [effect.kind for effect in activation.lifecycle.effects] == [
        "dependency-probe", "dependency-activate",
    ]
    activated = service.provision(
        activation, service.review(activation, 10.0, 20.0), Cancel(),
    )
    assert activated.status == c.OutcomeStatus.SUCCEEDED, activated
    assert state.pointer().revision == 1


def test_staged_family_reverification_does_not_reacquire_expired_publisher_authority(
    tmp_path, policy,
):
    service, scope, context, port, state, _, ledger_id, _ = managed_family_case(tmp_path, policy)
    initial = service.plan(scope, context)
    staged = service.provision(initial, service.review(initial, 10.0, 20.0), Cancel())
    assert all(step.status == c.OutcomeStatus.SUCCEEDED for step in staged.steps)
    before = port.read(ledger_id)
    service.clock.value = 80.0
    plan = service.plan(scope, context)
    assert [effect.occurrence_id for effect in plan.lifecycle.effects] == [
        "family-verify-0", "0-dependency-verify",
    ]
    assert all(effect.kind == "dependency-verify" for effect in plan.lifecycle.effects)
    result = service.provision(plan, service.review(plan, 80.0, 20.0), Cancel())
    assert all(step.status == c.OutcomeStatus.SUCCEEDED for step in result.steps), result
    assert port.read(ledger_id).revision == before.revision + 2
    assert state.pointer() == lc.AbsentPointer("absent", 0)


@pytest.mark.parametrize("damage", ("missing-pin", "changed-lock", "wrong-ledger", "unknown-family"))
def test_public_family_bridge_rechecks_owned_registration_before_any_new_effect(
    tmp_path, policy, damage,
):
    service, scope, context, port, state, lock, ledger_id, _ = managed_family_case(tmp_path, policy)
    if damage == "missing-pin":
        facts = port.read("managed-root")
        manifest = dict(c.public_object(facts.payload["root_manifest"]))
        manifest.pop("family_locks")
        port.seed("managed-root", {**dict(facts.payload), "root_manifest": manifest})
        with pytest.raises(AuthorizationError):
            service.plan(scope, context)
    elif damage == "changed-lock":
        state._family_locks = {state.manifests[0].generation_id: replace(
            lock, registry_digest="a" * 64,
        )}
        with pytest.raises(AuthorizationError):
            service.plan(scope, context)
    elif damage == "wrong-ledger":
        facts = port.read(ledger_id)
        port.seed(ledger_id, {**dict(facts.payload), "lock_digest": "a" * 64})
        plan = service.plan(scope, context)
        result = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
        assert result.status != c.OutcomeStatus.SUCCEEDED
        assert port.read(ledger_id).revision == 0
    else:
        effect = lc.LifecycleEffectOccurrence(
            "family-install-999", 0, "family-install-999", "resource", "dependency-stage", D,
        )
        with pytest.raises(AuthorizationError):
            state._family_step(state.manifests[0], lc.OwnedRootBinding("root", D), effect)
    assert state.pointer() == lc.AbsentPointer("absent", 0)


def installation_spec(platform="win32", member="wheels/netops_toolkit-1-py3-none-any.whl"):
    return _InstallationSpec(
        r"C:\Python\python.exe", D, "3.12.2", platform,
        (_Wheel(member, "netops-toolkit", "1", D),),
    )


def test_native_path_admission_is_prospective_not_a_retrospective_errno_claim():
    spec = installation_spec()
    assert not _predictable_path_limit(r"C:\n", "candidate", spec)
    assert _predictable_path_limit("C:\\" + "x" * 180, "candidate", spec)
    assert not _predictable_path_limit("/" + "x" * 500, "candidate",
                                       installation_spec("linux"))
    assert _predictable_path_limit(
        r"C:\n", "candidate", spec, ("package/" + "x" * 190,),
    )
    assert _predictable_path_limit("C:\\" + "\U0001f600" * 90, "candidate", spec)


@pytest.mark.parametrize("error,status", (
    (None, "returned"), (TimeoutError("secret-host-text"), "deadline"),
    (InterruptedError("secret-host-text"), "cancelled"),
    (AuthorizationError(), "raised"),
))
def test_native_cas_phase_is_bounded_factual_and_never_logs_host_exception_text(
    caplog, error, status,
):
    with caplog.at_level(logging.DEBUG, logger="netops.dependencies._composition"):
        try:
            with _native_phase("cas-owned-tree", Clock(), Cancel(), 20.0):
                if error is not None:
                    raise error
        except BaseException as actual:
            assert actual is error
    row, = [record for record in caplog.records
            if record.getMessage() == "dependency.native.boundary"]
    assert row.stage == "cas-owned-tree" and row.status == status
    assert row.remaining_seconds == 10.0 and row.deadline_elapsed is False
    assert row.cancelled is False and row.duration >= 0.0
    assert "secret-host-text" not in repr(row.__dict__)


def test_native_phase_logging_failure_cannot_replace_primary_outcome(monkeypatch):
    def broken(*args, **kwargs):
        raise KeyboardInterrupt("non-authoritative sink")

    monkeypatch.setattr("netops.dependencies._composition._NATIVE_LOG.debug", broken)
    primary = TimeoutError("original")
    with pytest.raises(TimeoutError) as caught:
        with _native_phase("untrusted-stage-with-path", Clock(), Cancel(), 20.0):
            raise primary
    assert caught.value is primary
    with _native_phase("cas-source-after", Clock(), Cancel(), 20.0):
        pass


def test_real_source_failure_becomes_typed_need_not_a_fabricated_compatible_lock(monkeypatch):
    item, _, content, _ = publisher_case()
    transport, _ = transport_for(monkeypatch, content + b"changed")
    result = _FamilyResolver(_registered_publishers((item,), transport)).resolve(
        (item.requirement,), (replace(TARGET, wheel_tags=("py3-none-any",)),),
        D, Clock(), Cancel(), 50.0,
    )
    assert result.lock is None
    assert result.needs[0].reason == "verified-publisher-metadata-required"
    assert result.needs[0].requirement == item.requirement


def test_public_publisher_composition_is_lazy_and_never_a_local_producer_capability(monkeypatch):
    from netops import setup

    item, _, content, _ = publisher_case()
    _, calls = transport_for(monkeypatch, content)
    metadata = setup.SetupMetadata.publishers(
        installation_spec(), (), (item,), (TARGET,),
    )
    assert not calls and metadata.source is None and metadata.consuming_root is None
    internal = metadata._metadata()
    assert internal.family_planning is not None and internal.owned_source is None
    source, = internal.family_planning.sources
    snapshot = source.port.observe(item.requirement, TARGET, Clock(), Cancel(), 50.0)
    assert snapshot.releases == (item,) and len(calls) == 1
    with pytest.raises(TypeError):
        replace(metadata, source=object())


@pytest.mark.parametrize("forgery", ("normalized-source-callback", "transport-callback"))
def test_public_publisher_facade_rejects_caller_supplied_source_authority(forgery):
    from types import SimpleNamespace

    from netops import setup
    from netops.dependencies._family_bridge import _FamilyPlanning

    item, _, _, _ = publisher_case()
    metadata = setup.SetupMetadata.publishers(installation_spec(), (), (item,), (TARGET,))
    source, = metadata._family_planning.sources

    def forbidden(*args, **kwargs):
        pytest.fail("A caller-supplied source authority was invoked.")

    port = (
        SimpleNamespace(observe=forbidden)
        if forgery == "normalized-source-callback" else
        replace(source.port, transport=SimpleNamespace(read_bounded=forbidden))
    )
    forged = _FamilyPlanning((replace(source, port=port),), (TARGET,))
    with pytest.raises(TypeError):
        replace(metadata, _family_planning=forged)


@pytest.mark.parametrize("changes", (
    {"releases": []}, {"releases": ()}, {"releases": (object(),)},
    {"source": "pypi:substituted"},
))
def test_real_publisher_registration_is_closed_not_a_source_trusted_boolean(changes):
    item, _, _, _ = publisher_case()
    releases = changes.get("releases", (replace(
        item, requirement=replace(item.requirement, source=changes.get("source", "pypi:demo")),
    ),))
    with pytest.raises(c.ContractError):
        _registered_publishers(releases)


def test_retained_codec_roundtrips_selected_extra_edges_without_dropping_choices():
    item = release(extra_requires=(("pdf", ()),))
    result, _ = resolve((item,), roots=(replace(item.requirement, extras=("pdf",)),))
    restored = _decode_lock(json.loads(c.canonical_bytes(result.lock)))
    assert restored == result.lock
    assert restored.selected_extras == ((item.requirement.key, ("pdf",)),)
    assert restored.releases[0].extra_requires == (("pdf", ()),)


@pytest.mark.parametrize("damage", ("extra-pair", "extra-limit", "root-limit"))
def test_codec_rejects_malformed_or_unbounded_retained_extra_graph(damage):
    result, _ = resolve((release(extra_requires=(("pdf", ()),)),))
    encoded = json.loads(c.canonical_bytes(result.lock))
    if damage == "extra-pair":
        encoded["releases"][0]["extra_requires"] = [["pdf"]]
    elif damage == "extra-limit":
        encoded["releases"][0]["extra_requires"] = [["pdf", []]] * 65
    else:
        encoded["roots"] *= 257
    with pytest.raises(c.ContractError):
        _decode_lock(encoded)


@pytest.mark.parametrize("damage", (
    "registry", "consumers", "archive-count", "origin", "members", "target-context",
))
def test_complete_lock_is_bound_to_actual_registry_consumers_layout_and_context(
    tmp_path, policy, damage,
):
    service, _, _, port, state, lock, _, _ = managed_family_case(tmp_path, policy)
    manifest, = state.manifests
    entries = (service.registry.entry("native-python"),)
    _validate_archives(lock, manifest, service.registry, ("native-python",))
    if damage == "registry":
        lock = replace(lock, registry_digest="a" * 64)
    elif damage == "consumers":
        entries = ()
    elif damage == "archive-count":
        manifest = replace(manifest, archives=())
    elif damage in ("origin", "members"):
        archive, = manifest.archives
        if damage == "origin":
            asset = replace(archive.asset, url="https://pypi.org/substituted.zip")
            archive = replace(archive, asset=asset)
        else:
            archive = replace(archive, members=(replace(archive.members[0], path="substitute"),))
        manifest = replace(manifest, archives=(archive,), members=archive.members,
                           asset=archive.asset)
    else:
        target = replace(lock.targets[0], context_digest="a" * 64)
        lock = replace(lock, targets=(target,), observations=(replace(
            lock.observations[0], target_digest=c.digest(target),
        ),))
    with pytest.raises(AuthorizationError):
        _validate_entries(lock, manifest, entries)
    assert not port.writes


def test_materialized_host_rejects_caller_callable_instead_of_actual_broker_authority(
    tmp_path, policy,
):
    from netops.dependencies._family_provider import _operation

    _, _, _, _, state, lock, _, _ = managed_family_case(tmp_path, policy)
    manifest, = state.manifests
    host = _MaterializedFamilies(state, manifest, lock)
    operation = _operation(lock, lock.releases[0], "install", manifest.generation_id)

    class ForgedAuthority:
        def enter(self, operation):
            pytest.fail("A caller-supplied enter callable was invoked.")

    with pytest.raises(AuthorizationError):
        host.python(lock.releases[0], operation, ForgedAuthority(), None)


@pytest.mark.parametrize("family", ("wheel", "executable", "collection", "library"))
def test_materialized_family_method_never_accepts_another_family_release(
    tmp_path, policy, family, monkeypatch,
):
    service, scope, context, port, state, _, ledger_id, _ = managed_family_case(tmp_path, policy)
    monkeypatch.setattr(_MaterializedFamilies, "python", getattr(_MaterializedFamilies, family))
    plan = service.plan(scope, context)
    outcome = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert port.read(ledger_id).payload["resources"] == ()
    assert port.read(ledger_id).payload["pending"]
    assert state.pointer() == lc.AbsentPointer("absent", 0)


def test_materialized_constructor_is_bound_to_the_actual_registered_original_owner(tmp_path, policy):
    _, _, _, _, state, lock, _, _ = managed_family_case(tmp_path, policy)
    manifest, = state.manifests
    with pytest.raises(AuthorizationError):
        _MaterializedFamilies(object(), manifest, lock)
    with pytest.raises(AuthorizationError):
        _MaterializedFamilies(state, manifest, replace(lock, registry_digest="a" * 64))


@pytest.mark.parametrize("damage", ("missing-wheel", "version", "platform", "python"))
def test_staged_transitive_wheel_cannot_be_ledgered_as_an_unrelated_installation(
    tmp_path, policy, damage,
):
    service, _, _, _, state, _, _, _ = managed_family_case(tmp_path, policy)
    entry = service.registry.entry("pyyaml")
    wanted = _requirement(entry)
    item, _, _, _ = publisher_case()
    asset = replace(item.artifact, dependency=wanted.name, source_id=wanted.source,
                    url="https://files.pythonhosted.org/packages/PyYAML-6.0-py3-none-any.whl")
    member = replace(item.members[0], path="wheels/PyYAML-6.0-py3-none-any.whl")
    spec = installation_spec("linux")
    toolkit_requirement = _Requirement("netops-toolkit", "wheel", "pypi:netops-toolkit",
                                      "native", ">=1")
    toolkit_member = ManagedMember(spec.wheels[0].member, D, 20)
    toolkit_asset = LockedAsset(
        toolkit_requirement.source, toolkit_requirement.name,
        "https://files.pythonhosted.org/packages/netops_toolkit-1-py3-none-any.whl",
        D, toolkit_member.size,
    )
    toolkit = replace(
        item, requirement=toolkit_requirement, artifact=toolkit_asset,
        members=(toolkit_member,),
    )
    item = replace(item, requirement=wanted, version="6.0", artifact=asset, members=(member,),
                   requires=(toolkit_requirement,))
    wheel = _Wheel(member.path, "PyYAML", "6.0", member.digest)
    spec = replace(spec, wheels=(*spec.wheels, wheel))
    archives = (
        ManagedArchive(toolkit_asset, "file", toolkit.members),
        ManagedArchive(asset, "file", item.members),
    )
    manifest = replace(
        state.manifests[0], asset=toolkit_asset, archive="file",
        members=(*toolkit.members, *item.members), archives=archives, installation=spec,
    )
    target = replace(TARGET, wheel_tags=("py3-none-any",),
                     context_digest=manifest.consuming_contexts[0])
    observations = (
        _PublisherSnapshot(toolkit_requirement.source, c.digest(target), (toolkit,), D, 9.0, 60.0),
        _PublisherSnapshot(wanted.source, c.digest(target), (item,), D, 9.0, 60.0),
    )
    lock = _FamilyLock((wanted,), (target,), (toolkit, item), observations, service.registry.digest)
    _validate_entries(lock, manifest, (entry,))
    if damage == "missing-wheel":
        spec = replace(spec, wheels=spec.wheels[:1])
    elif damage == "version":
        spec = replace(spec, wheels=(spec.wheels[0], replace(wheel, version="99")))
    elif damage == "platform":
        spec = replace(spec, platform="win32")
    else:
        spec = replace(spec, python_version="3.11.0")
    with pytest.raises(AuthorizationError):
        _validate_entries(lock, replace(manifest, installation=spec), (entry,))


def registration_case(tmp_path, policy):
    _, _, _, port, state, lock, ledger_id, _ = managed_family_case(tmp_path, policy)
    root = _setup._owned(tmp_path / "ledger-registration-unit", True)
    owned = OwnedState(root, OWNER)
    previous = c.public_object(port.read("managed-root").payload["root_manifest"])
    following = c.public_object({
        **dict(previous), "registered_manifests": (
            *previous["registered_manifests"], {"next-review-unit-fixture": True},
        ),
    })
    document = {"generation_id": state.manifests[0].generation_id, "family_lock": c.wire(lock)}
    with owned.lock((_setup._ROOT,), 0.0):
        _setup._register_family_ledgers(owned, (document,), previous, previous,
                                       document["generation_id"])
    return owned, document, previous, following, ledger_id


def test_owned_registration_initializes_rebinds_and_never_resets_existing_resource_inventory(
    tmp_path, policy,
):
    from netops.dependencies._family_provider import _Resource

    owned, document, previous, following, ledger_id = registration_case(tmp_path, policy)
    initial = owned.read(ledger_id)
    assert initial.revision == 0 and initial.payload["resources"] == ()
    resource = _Resource("fixture-resource", document["generation_id"],
                         initial.payload["lock_digest"], D, D, True, True, ("live-pin",), True)
    retained = replace(initial, revision=1, payload=c.public_object({
        **dict(initial.payload), "resources": (c.wire(resource),),
    }))
    with owned.lock((_setup._ROOT,), 0.0):
        owned.compare_replace(ledger_id, 0, retained)
        _setup._register_family_ledgers(
            owned, (document,), previous, following, document["generation_id"],
        )
    updated = owned.read(ledger_id)
    assert updated.revision == 2
    assert updated.payload["root"] == c.public_object(c.wire(
        lc.OwnedRootBinding(_setup._ROOT, c.digest(following)),
    ))
    assert updated.payload["resources"] == retained.payload["resources"]
    assert updated.payload["pending"] == ()
    with owned.lock((_setup._ROOT,), 0.0):
        _setup._register_family_ledgers(
            owned, (document,), following, following, document["generation_id"],
        )
    assert owned.read(ledger_id) == updated


@pytest.mark.parametrize("damage", ("pending", "root", "lock", "resources"))
def test_registration_cannot_erase_uncertainty_or_rebind_unrelated_ledger_facts(
    tmp_path, policy, damage,
):
    owned, document, previous, following, ledger_id = registration_case(tmp_path, policy)
    initial = owned.read(ledger_id)
    field, value = {
        "pending": ("pending", ("interrupted-unit-operation",)),
        "root": ("root", c.wire(lc.OwnedRootBinding("other-root", D))),
        "lock": ("lock_digest", D),
        "resources": ("resources", {"not": "an-inventory"}),
    }[damage]
    changed = replace(initial, revision=1, payload=c.public_object({
        **dict(initial.payload), field: value,
    }))
    with owned.lock((_setup._ROOT,), 0.0):
        owned.compare_replace(ledger_id, 0, changed)
        with pytest.raises(AuthorizationError):
            _setup._register_family_ledgers(
                owned, (document,), previous, following, document["generation_id"],
            )
    assert owned.read(ledger_id) == changed


@pytest.mark.parametrize("requested", (None, 60, 180))
def test_existing_root_observation_setting_is_readonly_and_cannot_be_extended(
    tmp_path, policy, requested,
):
    from netops.ansible.settings import ObservationSettings

    owned, _, previous, _, ledger_id = registration_case(tmp_path, policy)
    ledger = owned.read(ledger_id)
    root = replace(ledger, resource_id=_setup._ROOT, payload=c.public_object({
        "schema": "i02-managed-generations-v1", "generations": (),
        "root_manifest": {**dict(previous), "observation_max_age_seconds": 60},
    }))
    with owned.lock((_setup._ROOT,), 0.0):
        owned.compare_replace(_setup._ROOT, 0, root)
    displayed = []

    def forbidden(_):
        pytest.fail("A retained setting check asked for consequential authority.")

    actual = _setup._retained_review(
        owned, ObservationSettings(requested) if requested is not None else None,
        _setup._Review(forbidden, displayed.append),
    )
    assert owned.read(_setup._ROOT) == root
    if requested == 180:
        assert actual is None
        report, = [json.loads(row) for row in displayed]
        assert report["status"] == "NeedsInput"
        assert report["effects_performed"] == [] and report["consent_issued"] is False
        assert report["current_max_age_seconds"] == 60
    else:
        assert actual.observation.max_age_seconds == 60 and not displayed
