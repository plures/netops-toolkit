"""First-run public CLI obligations derived from original AC-001/003/013."""

import json
import os
import platform
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest

from netops import setup
from netops.dependencies import DependencyRegistry, ProbeResult

CONSEQUENTIAL = {
    "os", "elevation", "wsl", "distribution", "vm", "virtualization",
    "runtime", "service", "reboot", "security",
}


def selected_closure(enhanced):
    """Independently union the complete public census, not the service selector."""
    catalog = DependencyRegistry.load()
    required = set(catalog.native_baseline)
    for operation in catalog.operations:
        if operation.tier == "enhanced" and not enhanced:
            continue
        required.update(operation.dependencies)
        for _, edges in (*operation.intents, *operation.export_dependencies, *operation.variants):
            required.update(edges)
    pending = list(required)
    while pending:
        for edge in catalog.entry(pending.pop()).requires:
            if edge not in required:
                required.add(edge)
                pending.append(edge)
    return catalog, required


def public_report(output):
    """Consume only actual documented public stdout JSON, never private descriptors."""
    rows = []
    for line in output.splitlines():
        start = line.find("{")
        if start >= 0:
            value = json.loads(line[start:])
            if value.get("status") in ("NeedsInput", "Planned"):
                rows.append(value)
    assert len(rows) == 1, "Expected one actual first-run public diagnosis/selection outcome."
    return rows[0]


@pytest.fixture
def first_run(tmp_path, monkeypatch):
    from netops.dependencies import _setup

    calls, prompts = [], []
    root = tmp_path / "new-guided-root"
    sentinel = tmp_path / "existing-inventory.yaml"
    sentinel.write_bytes(b"native-user-data: retained\n")

    def missing(self, entry, context, deadline):
        calls.append((entry.id, context, deadline))
        return ProbeResult(
            entry.id, context.digest, "missing", "independent-source-only-missing",
            next_action="review-setup",
        )

    def forbidden(*args, **kwargs):
        pytest.fail("Incomplete/declined first-run diagnosis crossed an owned-effect boundary.")

    monkeypatch.setattr(_setup.LocalDependencyAdapter, "probe", missing)
    monkeypatch.setattr(_setup, "_owned", forbidden)
    monkeypatch.setattr(_setup, "_seed", forbidden)
    monkeypatch.setattr(_setup, "_host", forbidden)

    def answer(prompt):
        prompts.append(prompt)
        return ""

    monkeypatch.setattr("builtins.input", answer)
    return root, sentinel, calls, prompts


@pytest.mark.parametrize("enhanced", [False, True])
def test_ac001_first_run_diagnoses_complete_selected_closure_before_decline(
    first_run, capsys, enhanced,
):
    root, sentinel, calls, prompts = first_run
    before = sentinel.read_bytes()
    result = setup.main(["install", "--root", str(root)] + (["--enhanced"] if enhanced else []))
    report = public_report(capsys.readouterr().out)
    catalog, required = selected_closure(enhanced)
    assert result != 0
    assert report["status"] == "NeedsInput"
    assert report["scope"] == {
        "native_capabilities": [], "companions": [], "full_toolkit": True, "enhanced": enhanced,
    }
    closure = report["closure"]
    assert {item["dependency"] for item in closure} == required
    assert len(closure) == len(required)
    assert calls and prompts
    actual_native = {name for name, context, _ in calls if context.role == "native"}
    assert actual_native == {
        name for name in required if catalog.entry(name).context == "native"
    }
    for item in closure:
        entry = catalog.entry(item["dependency"])
        assert item["kind"] == entry.kind
        assert item["version"] == entry.version
        assert item["source"] == entry.source
        assert item["requires"] == list(entry.requires)
        assert item["platforms"] == list(entry.platforms)
        assert item["observation"]["status"] != "available"
    assert report["readiness"]["readiness"] == {
        "native": "blocked", "companion": "blocked",
        "enhanced": "blocked" if enhanced else "not-requested", "errors": [],
    }
    assert {need["dependency"] for need in report["needs"]} == required
    assert all(need["reason"] == "component-declined" for need in report["needs"])
    assert report["effects_performed"] == []
    assert report["consent_issued"] is False
    assert not root.exists()
    assert sentinel.read_bytes() == before


def test_ac001_choice_is_not_consent_and_requests_all_consequential_categories(
    first_run, monkeypatch, capsys,
):
    root, sentinel, calls, prompts = first_run

    def install_and_review(prompt):
        prompts.append(prompt)
        return "install" if "Reuse/Install/Decline" in prompt else "review"

    monkeypatch.setattr("builtins.input", install_and_review)
    result = setup.main(["install", "--root", str(root), "--enhanced"])
    report = public_report(capsys.readouterr().out)
    _, required = selected_closure(True)
    assert result != 0 and calls
    assert dict(report["selection"]["components"]) == dict.fromkeys(required, "install")
    assert dict(report["selection"]["categories"]) == dict.fromkeys(CONSEQUENTIAL, "review")
    assert report["status"] == "NeedsInput"
    assert report["consent_issued"] is False
    assert report["effects_performed"] == []
    needs = {item["dependency"]: item for item in report["needs"]}
    assert len(needs) == len(report["needs"])
    assert set(needs) == required | {"native:netops-toolkit", "controller:netops-toolkit"}
    current = metadata.version("netops-toolkit")
    import netops
    from netops.dependencies._lock_layout import _toolkit_requirement

    assert current == netops.__version__
    assert Path(netops.__file__).resolve() == Path(setup.__file__).resolve().with_name("__init__.py")
    requirement = _toolkit_requirement()
    assert (
        requirement.name, requirement.family, requirement.source,
        requirement.context, requirement.version,
    ) == ("netops-toolkit", "wheel", "pypi:netops-toolkit", "native", "==" + current)
    assert needs["native:netops-toolkit"] == {
        "dependency": "native:netops-toolkit", "kind": "wheel", "version": "==" + current,
        "platforms": [sys.platform], "source": "pypi:netops-toolkit",
        "fields": ["publisher-metadata"], "reason": "registered-metadata-source-required",
        "choices": ["install", "decline"],
    }
    metadata_needs = [item for item in report["needs"]
                      if item["reason"] == "verified-metadata-required"]
    assert metadata_needs
    for item in metadata_needs:
        assert {"compatible-version", "source-identity", "sha256", "size",
                "transitive-wheel-collection-lock", "provider-handler"} <= set(item["fields"])
    assert not root.exists()
    assert sentinel.read_bytes() == b"native-user-data: retained\n"


def test_ac001_selection_resumes_through_actual_public_command_without_private_archive(
    first_run, monkeypatch, capsys,
):
    root, sentinel, calls, prompts = first_run
    monkeypatch.setattr("builtins.input", lambda prompt: "install"
                        if "Reuse/Install/Decline" in prompt else "decline")
    first_result = setup.main(["install", "--root", str(root), "--enhanced"])
    first = public_report(capsys.readouterr().out)
    assert first_result != 0 and first["checkpoint"]
    assert first["next_command"][:6] == [
        sys.executable, "-I", "-B", "-c",
        "import sys; sys.path.insert(0,sys.argv.pop(1)); "
        "from netops.setup import main; raise SystemExit(main())",
        str(Path(setup.__file__).resolve().parents[1]),
    ]
    first_calls = len(calls)

    def retain_choices(prompt):
        prompts.append(prompt)
        return ""

    monkeypatch.setattr("builtins.input", retain_choices)
    second_result = setup.main(first["next_command"][6:])
    second = public_report(capsys.readouterr().out)
    assert second_result != 0
    assert len(calls) > first_calls, "Resume must obtain fresh factual observations."
    assert second["scope"] == first["scope"]
    assert second["selection"]["components"] == first["selection"]["components"]
    assert second["status"] == "NeedsInput"
    assert not second["consent_issued"] and second["effects_performed"] == []
    assert not root.exists()
    assert sentinel.read_bytes() == b"native-user-data: retained\n"


def test_ac003_public_full_preview_is_prompt_probe_and_write_free(first_run, capsys):
    root, sentinel, calls, prompts = first_run
    result = setup.main(["plan", "--root", str(root), "--enhanced"])
    report = public_report(capsys.readouterr().out)
    _, required = selected_closure(True)
    assert result in (0, 3)
    assert report["status"] == "Planned"
    assert {item["dependency"] for item in report["closure"]} == required
    assert report["readiness"] is None
    assert not calls and not prompts
    assert not report["consent_issued"] and report["effects_performed"] == []
    assert not root.exists()
    assert sentinel.read_bytes() == b"native-user-data: retained\n"


@pytest.mark.parametrize("damage", ["malformed", "root", "scope"])
def test_ac003_public_checkpoint_binding_rejects_before_probe_or_prompt(
    first_run, capsys, damage,
):
    root, sentinel, calls, prompts = first_run
    result = setup.main(["plan", "--root", str(root), "--enhanced"])
    report = public_report(capsys.readouterr().out)
    assert result in (0, 3) and not calls and not prompts
    token = report["checkpoint"]
    target = root
    enhanced = True
    if damage == "malformed":
        token = token + "!"
    elif damage == "root":
        target = root.parent / "different-guided-root"
    else:
        enhanced = False
    result = setup.main([
        "install", "--root", str(target), "--checkpoint", token,
    ] + (["--enhanced"] if enhanced else []))
    assert result != 0
    assert not calls and not prompts
    assert not root.exists() and not target.exists()
    assert sentinel.read_bytes() == b"native-user-data: retained\n"


def test_ac003_choice_cancel_preserves_native_state_and_uncreated_root(
    first_run, monkeypatch, capsys,
):
    root, sentinel, calls, prompts = first_run

    def cancel(prompt):
        prompts.append(prompt)
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", cancel)
    result = setup.main(["install", "--root", str(root), "--enhanced"])
    assert result == 130
    assert calls and prompts
    assert "cancelled" in capsys.readouterr().out.lower()
    assert not root.exists()
    assert sentinel.read_bytes() == b"native-user-data: retained\n"


def test_ac001_real_current_interpreter_first_run_has_full_factual_diagnosis_without_stubs(
    tmp_path,
):
    """Actual read-only host process/probes, not a provider fixture or platform qualification."""
    root = tmp_path / "actual-uncreated-guided-root"
    sentinel = tmp_path / "existing-native-state"
    sentinel.write_bytes(b"native: preserved\n")
    environment = {
        key: value for key, value in os.environ.items()
        if key.upper() in (
            "SYSTEMROOT", "WINDIR", "COMSPEC", "PATH", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
        )
    }
    environment.update(
        TEMP=str(tmp_path), TMP=str(tmp_path), PYTHONDONTWRITEBYTECODE="1",
        PYTHONNOUSERSITE="1",
    )
    checkout = Path(__file__).resolve().parents[1]
    script = (
        "import sys;"
        f"sys.path.insert(0,{str(checkout)!r});"
        "from netops.setup import main;"
        f"raise SystemExit(main({['install', '--root', str(root), '--enhanced']!r}))"
    )
    process = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", script], cwd=tmp_path,
        input="", capture_output=True, text=True, env=environment,
        timeout=100, check=False,
    )
    assert process.returncode == 3, process.stderr
    report = public_report(process.stdout)
    _, required = selected_closure(True)
    assert report["status"] == "NeedsInput"
    assert {item["dependency"] for item in report["closure"]} == required
    interpreter = next(item for item in report["closure"] if item["dependency"] == "native-python")
    assert interpreter["observation"]["status"] == "available"
    assert interpreter["observation"]["version"] == platform.python_version()
    assert interpreter["observation"]["evidence_digest"]
    assert report["readiness"]["readiness"]["companion"] == "blocked"
    assert report["readiness"]["readiness"]["enhanced"] == "blocked"
    assert report["consent_issued"] is False and report["effects_performed"] == []
    resumed = subprocess.run(
        report["next_command"], cwd=tmp_path, input="", capture_output=True,
        text=True, env=environment, timeout=100, check=False,
    )
    assert resumed.returncode == 3, resumed.stderr
    continued = public_report(resumed.stdout)
    assert {item["dependency"] for item in continued["closure"]} == required
    assert continued["selection"] == report["selection"]
    assert continued["consent_issued"] is False and continued["effects_performed"] == []
    assert not root.exists()
    assert sentinel.read_bytes() == b"native: preserved\n"


@pytest.mark.parametrize("metadata", [{"source": "not-private-authority"}, object()])
def test_ac003_public_typed_metadata_never_decodes_wire_authority(
    tmp_path, monkeypatch, metadata,
):
    root = tmp_path / "uncreated-wire-authority-root"

    def forbidden(*args, **kwargs):
        pytest.fail("Malformed public metadata reached diagnosis or an effect.")

    monkeypatch.setattr("netops.dependencies._setup._service", forbidden)
    with pytest.raises(TypeError, match="trusted typed composition"):
        setup.main(["install", "--root", str(root)], metadata=metadata)
    assert not root.exists()


def test_ac003_unknown_existing_root_rejects_before_probe_prompt_or_mutation(
    tmp_path, monkeypatch,
):
    root = tmp_path / "unknown-user-root"
    root.mkdir()
    sentinel = root / "inventory.yaml"
    sentinel.write_bytes(b"native user inventory: preserved\n")
    before = {path.name: path.read_bytes() for path in root.iterdir()}

    def forbidden(*args, **kwargs):
        pytest.fail("Unknown existing root reached a public probe or prompt.")

    monkeypatch.setattr("builtins.input", forbidden)
    monkeypatch.setattr("netops.dependencies._setup._service", forbidden)
    assert setup.main(["install", "--root", str(root)]) == 3
    assert {path.name: path.read_bytes() for path in root.iterdir()} == before
