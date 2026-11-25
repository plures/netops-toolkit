"""Original full prospective consent through real descriptor-free public setup."""

import pytest

from netops import setup
from tests.test_nov21_guided_entrypoint_independent import first_run as first_run
from tests.test_nov21_guided_entrypoint_independent import public_report


def test_fr004_public_continuation_retains_review_choices_without_minting_consent(
    first_run, monkeypatch, capsys,
):
    root, sentinel, calls, prompts = first_run
    before = sentinel.read_bytes()
    monkeypatch.setattr("builtins.input", lambda prompt: (
        "install" if "Reuse/Install/Decline" in prompt else "review"
    ))
    initial = setup.main(["install", "--root", str(root), "--enhanced"])
    first = public_report(capsys.readouterr().out)
    assert initial != 0
    assert first["selection"]["categories"]
    assert all(value == "review" for _, value in first["selection"]["categories"])
    before_calls = len(calls)
    before_prompts = len(prompts)

    def retain(prompt):
        prompts.append(prompt)
        return ""

    monkeypatch.setattr("builtins.input", retain)
    status = setup.main(first["next_command"][6:])
    resumed = public_report(capsys.readouterr().out)
    assert status != 0 and resumed["status"] == "NeedsInput"
    assert resumed["selection"] == first["selection"]
    assert len(calls) > before_calls
    assert len(prompts) > before_prompts
    assert resumed["effects_performed"] == [] and resumed["consent_issued"] is False
    assert not root.exists() and sentinel.read_bytes() == before


@pytest.mark.parametrize("action", ["plan", "install"])
def test_ac001_ac003_unknown_root_preserves_every_native_user_state_class(
    tmp_path, monkeypatch, capsys, action,
):
    from netops.dependencies import _setup

    root = tmp_path / "existing-native-root"
    sentinel = tmp_path / "existing-inventory.yaml"
    sentinel.write_bytes(b"native-user-data: retained\n")
    root.mkdir()
    fixtures = {
        ("inventory.yaml",): b"native inventory",
        ("vault.enc",): b"native encrypted vault bytes",
        ("backups", "device.cfg"): b"native backup",
        ("settings.json",): b'{"native":"settings"}',
        ("unknown", "nested-file"): b"unknown owned-by-user resource",
    }
    for segments, content in fixtures.items():
        path = root.joinpath(*segments)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    before = {path.relative_to(root).as_posix(): path.read_bytes()
              for path in root.rglob("*") if path.is_file()}
    before_dirs = {path.relative_to(root).as_posix()
                   for path in root.rglob("*") if path.is_dir()}

    def forbidden(*args, **kwargs):
        pytest.fail("Unknown native root reached a probe, prompt, or owned-effect boundary.")

    monkeypatch.setattr(_setup.LocalDependencyAdapter, "probe", forbidden)
    monkeypatch.setattr(_setup, "_seed", forbidden)
    monkeypatch.setattr(_setup, "_host", forbidden)
    monkeypatch.setattr("builtins.input", forbidden)
    status = setup.main([action, "--root", str(root), "--enhanced"])
    assert status == 3
    assert capsys.readouterr().out == (
        "Setup did not complete. Preserve this root and prior generations. "
        "Review exact local pins, platform and owned metadata, then replan with fresh consent.\n"
    )
    assert {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()} == before
    assert {path.relative_to(root).as_posix()
            for path in root.rglob("*") if path.is_dir()} == before_dirs
    assert not (root / "netops-root.json").exists()
    assert sentinel.read_bytes() == b"native-user-data: retained\n"
