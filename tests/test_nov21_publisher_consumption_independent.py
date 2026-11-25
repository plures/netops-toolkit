"""Actual publisher clients with synthetic transport only, never publisher trust.

All JSON, digests and URL responses below are adversarial SOURCE fixtures. No
artifact is downloaded, accepted by a private producer, installed or qualified.
"""

import copy
import hashlib
import json
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.dependencies._assets import AssetResponse, HttpsAssetTransport, LockedAsset
from netops.dependencies._family_lock import _FamilyResolver, _Release, _Requirement, _Target
from netops.dependencies._managed import ManagedMember
from netops.dependencies._publisher_metadata import _PublisherMetadata, _registered_publishers

TARGET = _Target(
    "native", "linux", "x86_64", "3.12.8", "cp312", ("py3-none-any",), "c" * 64,
)
NAME = "source-only-family"
FILENAME = "source_only_family-1.0-py3-none-any.whl"
ARTIFACT_URL = "https://files.pythonhosted.org/packages/SOURCE-ONLY/" + FILENAME
ARTIFACT_SHA = hashlib.sha256(b"not-an-archive-not-acquired").hexdigest()


class Clock:
    value = 10.0

    def monotonic(self):
        return self.value


class Cancel:
    value = False

    def is_cancelled(self):
        return self.value


class Transport:
    """Only the external HTTPS boundary is replaced, not parser/resolver code."""

    def __init__(self, content):
        self.content = content
        self.calls = []
        self.after = None
        self.response_url = None
        self.error = None

    def read(self, url, timeout, limit):
        self.calls.append((url, timeout, limit))
        if self.error is not None:
            raise self.error
        if self.after is not None:
            self.after()
        return AssetResponse(self.response_url or url, self.content)


def fixture(document_change=None, release_change=None):
    document = {
        "info": {
            "name": NAME, "version": "1.0", "requires_python": ">=3.9",
            "provides_extra": [], "requires_dist": [],
        },
        "urls": [{
            "url": ARTIFACT_URL, "packagetype": "bdist_wheel", "yanked": False,
            "size": 28, "digests": {"sha256": ARTIFACT_SHA}, "filename": FILENAME,
        }],
    }
    if document_change is not None:
        document_change(document)
    content = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    item = _Release(
        _Requirement(NAME, "wheel", "pypi:" + NAME, "native", "==1.0"),
        "1.0", "wheel", ("linux",), ("x86_64",), (),
        hashlib.sha256(content).hexdigest(),
        LockedAsset("pypi:" + NAME, NAME, ARTIFACT_URL, ARTIFACT_SHA, 28),
        ">=3.9", ("cp312",), ("py3-none-any",), (), None,
        (ManagedMember("source_only_family.py", "d" * 64, 1),),
    )
    if release_change is not None:
        item = replace(item, **release_change)
    transport = Transport(content)
    sources = _registered_publishers((item,), transport)
    assert len(sources) == 1 and type(sources[0].port) is _PublisherMetadata
    return item, transport, _FamilyResolver(sources)


def consume(item, engine, clock=None, cancel=None):
    return engine.resolve(
        (item.requirement,), (TARGET,), "b" * 64, clock or Clock(), cancel or Cancel(), 40.0,
    )


def assert_unverified(result, requirement, transport):
    assert result.lock is None
    assert len(result.needs) == 1
    missing, = result.needs
    assert missing.requirement == requirement
    assert missing.reason == "verified-publisher-metadata-required"
    assert missing.fields == ("fresh-publisher-json", "retained-independent-metadata-pin")
    assert 1 <= len(transport.calls) <= 2
    assert all(call == (
        "https://pypi.org/pypi/source-only-family/1.0/json", 30.0, 1024 * 1024 + 1,
    ) for call in transport.calls)


def test_ac001_real_publisher_client_is_consumed_before_exact_lock_without_artifact_io():
    item, transport, engine = fixture()
    result = consume(item, engine)
    assert result.lock is not None and not result.needs
    assert result.lock.releases == (item,)
    assert transport.calls == [(
        "https://pypi.org/pypi/source-only-family/1.0/json", 30.0, 1024 * 1024 + 1,
    )]
    assert all(url != ARTIFACT_URL for url, _, _ in transport.calls)
    assert result.lock.observations[0].releases == (item,)
    assert result.lock.observations[0].target_digest == c.digest(TARGET)


def test_ac001_publisher_transitive_cannot_be_omitted_from_retained_catalogue():
    item, transport, engine = fixture(
        lambda value: value["info"].update(requires_dist=["unknown-helper>=2"]),
    )
    assert_unverified(consume(item, engine), item.requirement, transport)


def test_ac001_unknown_publisher_transitive_is_not_silently_truncated_after_parser():
    helper = _Requirement("unknown-helper", "wheel", "pypi:unknown-helper", "native", ">=2")
    item, transport, engine = fixture(
        lambda value: value["info"].update(requires_dist=["unknown-helper>=2"]),
        {"requires": (helper,)},
    )
    result = consume(item, engine)
    assert result.lock is None
    assert [(need.requirement, need.reason) for need in result.needs] == [
        (helper, "registered-metadata-source-required"),
    ]
    assert len(transport.calls) == 1


def test_ac001_target_markers_use_actual_consuming_platform_not_metadata_host():
    item, transport, engine = fixture(
        lambda value: value["info"].update(
            requires_dist=["windows-only-helper>=2; sys_platform == 'win32'"],
        ),
    )
    result = consume(item, engine)
    assert result.lock is not None and result.lock.releases == (item,)
    assert len(transport.calls) == 1


@pytest.mark.parametrize("damage", ["redirect", "digest", "duplicate-keys", "oversize"])
def test_ac003_real_metadata_boundary_rejects_redirect_digest_and_ambiguous_documents(damage):
    item, transport, engine = fixture()
    if damage == "redirect":
        transport.response_url = "https://unregistered.invalid/metadata"
    elif damage == "digest":
        transport.content = transport.content.replace(b'"1.0"', b'"2.0"')
    elif damage == "duplicate-keys":
        transport.content = b'{"info":{},"info":{},"urls":[]}'
        item = replace(item, metadata_digest=hashlib.sha256(transport.content).hexdigest())
        engine = _FamilyResolver(_registered_publishers((item,), transport))
    else:
        transport.content = b" " * (1024 * 1024 + 1)
        item = replace(item, metadata_digest=hashlib.sha256(transport.content).hexdigest())
        engine = _FamilyResolver(_registered_publishers((item,), transport))
    assert_unverified(consume(item, engine), item.requirement, transport)


@pytest.mark.parametrize("field,value", [
    ("requires_python", 7), ("requires_python", "not a version specifier"),
    ("provides_extra", [None]), ("requires_dist", [None]),
])
def test_ac001_malformed_publisher_schema_is_typed_rejection_not_parser_exception(field, value):
    item, transport, engine = fixture(
        lambda document: document["info"].update({field: copy.deepcopy(value)}),
    )
    assert_unverified(consume(item, engine), item.requirement, transport)


@pytest.mark.parametrize("damage,error", [
    ("deadline", TimeoutError), ("cancel", InterruptedError), ("backward", c.ContractError),
])
def test_ac003_actual_publisher_io_consumes_original_budget_without_renewal(damage, error):
    item, transport, engine = fixture()
    clock, cancel = Clock(), Cancel()
    if damage == "deadline":
        transport.after = lambda: setattr(clock, "value", 40.0)
    elif damage == "cancel":
        transport.after = lambda: setattr(cancel, "value", True)
    else:
        transport.after = lambda: setattr(clock, "value", 9.0)
    with pytest.raises(error):
        consume(item, engine, clock, cancel)
    assert len(transport.calls) == 1


def test_ac011_broken_metadata_observer_preserves_primary_error_identity(monkeypatch):
    from netops.dependencies import _family_lock

    item, transport, engine = fixture()
    primary = RuntimeError("SOURCE-only unexpected observer failure")
    transport.error = primary

    def interrupted_sink(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(_family_lock._LOG, "debug", interrupted_sink)
    with pytest.raises(RuntimeError) as captured:
        consume(item, engine)
    assert captured.value is primary and len(transport.calls) == 1


def test_ac011_expected_external_failure_is_safe_actionable_non_success(monkeypatch):
    from netops.dependencies import _family_lock

    item, transport, engine = fixture()
    transport.error = OSError("SOURCE-only private external diagnostic")

    def interrupted_sink(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(_family_lock._LOG, "debug", interrupted_sink)
    result = consume(item, engine)
    assert_unverified(result, item.requirement, transport)
    assert "private external diagnostic" not in c.canonical_bytes(result).decode()


def galaxy_fixture(document_change=None):
    collection = _Requirement("source_only.family", "collection", "galaxy:source_only.family",
                              "controller", "==1.0.0")
    core = _Requirement("ansible-core", "wheel", "pypi:ansible-core", "controller", ">=2.16")
    peer = _Requirement("vendor.peer", "collection", "galaxy:vendor.peer", "controller", ">=2")
    artifact = LockedAsset(
        collection.source, collection.name,
        "https://galaxy.ansible.com/SOURCE-ONLY/source_only-family-1.0.0.tar.gz",
        ARTIFACT_SHA, 28,
    )
    document = {
        "version": "1.0.0", "namespace": {"name": "source_only"},
        "collection": {"name": "family"}, "download_url": artifact.url,
        "artifact": {"sha256": ARTIFACT_SHA, "size": 28},
        "metadata": {"dependencies": {"vendor.peer": ">=2"}}, "requires_ansible": ">=2.16",
    }
    if document_change is not None:
        document_change(document)
    content = json.dumps(document, sort_keys=True).encode()
    item = _Release(
        collection, "1.0.0", "collection.tar.gz", ("linux",), ("x86_64",),
        (core, peer), hashlib.sha256(content).hexdigest(), artifact,
        members=(ManagedMember("MANIFEST.json", "d" * 64, 1),),
    )
    transport = Transport(content)
    source, = _registered_publishers((item,), transport)
    target = replace(TARGET, context="controller")
    return item, source.port, transport, target


def test_ac001_real_galaxy_client_consumes_core_and_collection_edges_without_artifact_io():
    item, client, transport, target = galaxy_fixture()
    snapshot = client.observe(item.requirement, target, Clock(), Cancel(), 40.0)
    assert snapshot.releases == (item,) and snapshot.metadata_digest == client.digest
    assert snapshot.target_digest == c.digest(target)
    assert {edge.name for edge in snapshot.releases[0].requires} == {"ansible-core", "vendor.peer"}
    assert transport.calls == [(
        "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/"
        "collections/index/source_only/family/versions/1.0.0/",
        30.0, 1024 * 1024 + 1,
    )]
    assert transport.calls[0][0] != item.artifact.url


@pytest.mark.parametrize("damage", ["namespace", "version", "digest", "size", "core", "edges"])
def test_ac001_galaxy_observation_cannot_substitute_artifact_core_or_transitives(damage):
    def alter(document):
        if damage == "namespace":
            document["namespace"] = {"name": "substituted"}
        elif damage == "version":
            document["version"] = "9.0.0"
        elif damage == "digest":
            document["artifact"]["sha256"] = "e" * 64
        elif damage == "size":
            document["artifact"]["size"] = True
        elif damage == "core":
            document["requires_ansible"] = ""
        else:
            document["metadata"]["dependencies"] = {}

    item, client, transport, target = galaxy_fixture(alter)
    with pytest.raises(c.ContractError):
        client.observe(item.requirement, target, Clock(), Cancel(), 40.0)
    assert len(transport.calls) == 1


def test_ac003_real_transport_composition_uses_only_bounded_cancel_aware_metadata_read(monkeypatch):
    item, transport, _ = fixture()
    calls = []

    def bounded(self, url, timeout, limit, clock, cancel):
        calls.append((url, timeout, limit, clock, cancel))
        return AssetResponse(url, transport.content)

    def forbidden(*args, **kwargs):
        pytest.fail("Actual publisher client selected the unbounded metadata transport.")

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", bounded)
    monkeypatch.setattr(HttpsAssetTransport, "read", forbidden)
    source, = _registered_publishers((item,), HttpsAssetTransport())
    engine = _FamilyResolver((source,))
    clock, cancel = Clock(), Cancel()
    result = consume(item, engine, clock, cancel)
    assert result.lock is not None and len(calls) == 1
    assert calls[0][3] is clock and calls[0][4] is cancel
    assert calls[0][1:3] == (30.0, 1024 * 1024 + 1)


@pytest.mark.parametrize("selected", [False, True])
def test_ac001_real_publisher_extra_markers_expand_only_requested_transitive_scope(selected):
    helper = _Requirement("unknown-helper", "wheel", "pypi:unknown-helper", "native", ">=2")
    item, transport, engine = fixture(
        lambda value: value["info"].update(
            provides_extra=["render"],
            requires_dist=["unknown-helper>=2; extra == 'render'"],
        ),
        {"extra_requires": (("render", (helper,)),)},
    )
    root = replace(item.requirement, extras=("render",)) if selected else item.requirement
    result = engine.resolve((root,), (TARGET,), "b" * 64, Clock(), Cancel(), 40.0)
    if selected:
        assert result.lock is None and result.needs[0].requirement == helper
    else:
        assert result.lock is not None and not result.needs
        assert result.lock.releases == (item,) and result.lock.selected_extras == ()
    assert len(transport.calls) == 1


def test_ac003_direct_reference_in_official_metadata_does_not_add_a_source_or_acquire_it():
    item, transport, engine = fixture(
        lambda value: value["info"].update(
            requires_dist=["unknown-helper @ https://unregistered.invalid/helper.whl"],
        ),
    )
    assert_unverified(consume(item, engine), item.requirement, transport)
    assert all("unregistered.invalid" not in url for url, _, _ in transport.calls)


def test_ac001_unsupported_publisher_target_is_safe_typed_non_success_not_keyerror():
    item, transport, _ = fixture(release_change={"platforms": ("unsupported-source-os",)})
    source, = _registered_publishers((item,), transport)
    engine = _FamilyResolver((source,))
    target = replace(TARGET, platform="unsupported-source-os")
    result = engine.resolve((item.requirement,), (target,), "b" * 64, Clock(), Cancel(), 40.0)
    assert_unverified(result, item.requirement, transport)
