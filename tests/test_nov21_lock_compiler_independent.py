"""AC-001 consuming lock/cache controls; synthetic publisher boundary, SOURCE only."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from netops.ansible import contracts as c
from netops.dependencies import _default_family, _setup
from tests.test_lock_catalog_compiler_author import compiler_case


def file_bytes(root):
    return {str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


@pytest.mark.parametrize("damage", ["content", "substitute-other-cache"])
def test_actual_default_compiler_never_reuses_missing_or_altered_selected_cache(
    tmp_path, monkeypatch, damage,
):
    """A valid prior consuming plan is not authority to trust subsequently bad bytes."""
    root = tmp_path / "new-root"
    registry, scope, diagnosis, selected, _, _ = compiler_case(root, monkeypatch)
    metadata = _default_family._default_metadata(registry)
    candidate, needs = metadata.resolve(diagnosis, selected, scope, root, registry)
    assert candidate is not None and needs == ()
    assert candidate.document["scope"] == c.wire(scope)
    wheel = next(item for item in candidate.document["archives"]
                 if item["asset"]["dependency"] == "netops-toolkit")
    path = Path(wheel["cache_path"])
    original = path.read_bytes()
    path.write_bytes(b"altered selected cache, not publisher-locked wheel bytes")
    if damage == "substitute-other-cache":
        alternative = path.parent.parent / hashlib.sha256(original).hexdigest() / "other.whl"
        alternative.parent.mkdir(exist_ok=True)
        alternative.write_bytes(original)
    before = file_bytes(tmp_path)
    retained_selection = c.wire(selected)
    failed, needs = metadata.resolve(diagnosis, selected, scope, root, registry)
    assert failed is None
    assert needs and {need.reason for need in needs} == {"verified-offline-cache-required"}
    assert c.wire(selected) == retained_selection
    assert not root.exists() and file_bytes(tmp_path) == before


def test_missing_cache_produces_only_a_precise_prospective_acquisition_plan(
    tmp_path, monkeypatch,
):
    """Clean installation may plan a consent-bound fetch, never implicitly download."""
    root = tmp_path / "new-root"
    registry, scope, diagnosis, selected, _, _ = compiler_case(root, monkeypatch)
    metadata = _default_family._default_metadata(registry)
    original, needs = metadata.resolve(diagnosis, selected, scope, root, registry)
    assert original is not None and needs == ()
    wheel = next(item for item in original.document["archives"]
                 if item["asset"]["dependency"] == "netops-toolkit")
    Path(wheel["cache_path"]).unlink()
    before = file_bytes(tmp_path)
    monkeypatch.setattr(
        "netops.dependencies._assets.HttpsAssetTransport.read",
        lambda *args: pytest.fail("Prospective missing-cache planning performed a download."),
    )
    planned, needs = metadata.resolve(diagnosis, selected, scope, root, registry)
    assert planned is not None and needs == ()
    assert planned.document["scope"] == c.wire(scope)
    acquisition = planned.acquisition
    assert acquisition is not None
    assert acquisition.document_digest == c.digest(c.public_object(planned.document))
    assert tuple(c.wire(asset) for asset in acquisition.assets) == tuple(
        item["asset"] for item in planned.document["archives"]
    )
    assert acquisition.cache_paths == tuple(
        Path(item["cache_path"]) for item in planned.document["archives"]
    )
    assert not root.exists() and file_bytes(tmp_path) == before


def test_actual_default_compiler_binds_complete_future_context_without_installing(
    tmp_path, monkeypatch,
):
    """Resolved SOURCE layout cannot be credited as performed or ready native effects."""
    root = tmp_path / "new-root"
    registry, scope, diagnosis, selected, native, _ = compiler_case(root, monkeypatch)
    before = file_bytes(tmp_path)
    candidate, needs = _default_family._default_metadata(registry).resolve(
        diagnosis, selected, scope, root, registry,
    )
    assert candidate is not None and needs == ()
    manifest, contexts = _setup._manifest(candidate.document, root, registry)
    assert candidate.document["scope"] == c.wire(scope)
    assert manifest.generation_id == candidate.document["generation_id"]
    assert manifest.installation.python_digest == native.members[0].digest
    assert manifest.consuming_contexts == (contexts["native"].digest,)
    assert {item.distribution for item in manifest.installation.wheels} == {"netops-toolkit"}
    assert {release.requirement.name for release in candidate.family_lock.releases
            if release.requirement.family == "wheel"} == {"netops-toolkit"}
    assert candidate.family_lock.targets[0].context_digest == contexts["native"].digest
    assert not root.exists() and file_bytes(tmp_path) == before
