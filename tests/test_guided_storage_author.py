"""Actual task-owned native publication regression, not platform qualification."""

import os
from dataclasses import replace

import pytest

from netops.ansible.artifacts import ArtifactError, OwnedState
from netops.dependencies._setup import _owned
from tests.policy.test_lifecycle_execution import OWNER, FilePort
from tests.policy.test_lifecycle_execution import policy as policy


@pytest.mark.skipif(os.name != "nt", reason="Native Windows publication regression cell.")
def test_actual_owned_publication_non_bmp_parent_and_optional_member(tmp_path, policy):
    root = _owned(tmp_path / "owned-\U0001f6e1", True)
    state = OwnedState(root, OWNER)
    template = FilePort(tmp_path, policy[0]).seed("record", {"sample": "non-authority"})
    state.compare_replace("record", 0, template)
    assert state.read("record") == template
    following = replace(template, revision=1)
    state.compare_replace("record", 0, following)
    assert state.read("record").revision == 1
    with pytest.raises(FileNotFoundError):
        state.read("optional-absent")
    with pytest.raises(ArtifactError):
        state.compare_replace("record", 0, following)
    with pytest.raises(ArtifactError):
        OwnedState(root, "f" * 64).read("record")


@pytest.mark.skipif(os.name != "nt", reason="Native Windows task-owned member controls.")
@pytest.mark.parametrize("member", ("../escape", "a:stream", "/absolute", "", "CON", "aux", "a.", "a//b"))
def test_actual_owned_member_guard_rejects_aliases_before_writes(tmp_path, member):
    root = _owned(tmp_path / "member-controls", True)
    state = OwnedState(root, OWNER)
    before = tuple(os.listdir(root.path))
    with pytest.raises(ArtifactError):
        state.read(member)
    assert tuple(os.listdir(root.path)) == before


@pytest.mark.skipif(os.name != "nt", reason="Native Windows task-owned corruption control.")
def test_actual_changed_bytes_and_hardlink_never_reuse_decoded_record(tmp_path, policy):
    root = _owned(tmp_path / "changed-control", True)
    state = OwnedState(root, OWNER)
    template = FilePort(tmp_path, policy[0]).seed("record", {"sample": "non-authority"})
    state.compare_replace("record", 0, template)
    state.read("record")
    path = tmp_path / "changed-control" / state._filename("record")
    path.write_bytes(b'{"not":"an-owned-record"}')
    with pytest.raises(ArtifactError):
        state.read("record")
    path.write_bytes(template.to_bytes())
    state.read("record")
    os.link(path, tmp_path / "changed-control" / "task-owned-extra-link")
    with pytest.raises(ArtifactError):
        state.read("record")
