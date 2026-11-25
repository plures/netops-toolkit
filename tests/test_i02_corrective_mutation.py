"""Isolated in-process guard ablations; no tracked source or independent tests edited."""

import struct

import pytest

from netops.ansible import contracts as c
from netops.dependencies import _managed
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel
from tests.test_i02_corrective_managed import Clock, archive_bytes, manifest_for


def test_central_directory_bound_is_loadbearing_not_just_archive_hash_validation(policy, monkeypatch):
    source = bytearray(archive_bytes())
    end = source.rfind(b"PK\x05\x06")
    # A lock can truthfully hash a malformed archive. The semantic metadata
    # guard must still reject it before ZipFile constructs its entry list.
    struct.pack_into("<HH", source, end + 8, 0, 0)
    content = bytes(source)
    manifest = manifest_for(policy[0], content)
    with pytest.raises(c.ContractError):
        _managed.unpack(manifest, content, Clock(), Cancel(), 20.0)
    monkeypatch.setattr(_managed, "_zip_directory", lambda value: None)
    assert _managed.unpack(manifest, content, Clock(), Cancel(), 20.0), (
        "Negative control must demonstrate that dropping this guard admits the malformed metadata"
    )


def test_path_rejection_is_loadbearing_even_for_an_exact_reviewed_archive_digest(policy, monkeypatch):
    path = "../outside"
    content = archive_bytes(path=path)
    with pytest.raises(c.ContractError):
        manifest_for(policy[0], content, path=path)
    # Read-only in-memory parser ablation only; never call a filesystem port
    # while the path validator is replaced.
    monkeypatch.setattr(_managed, "_parts", lambda value: tuple(value.split("/")))
    manifest = manifest_for(policy[0], content, path=path)
    files = _managed.unpack(manifest, content, Clock(), Cancel(), 20.0)
    assert files[0].member.path == path
