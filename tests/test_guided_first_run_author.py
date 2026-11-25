"""Author controls. Synthetic probes/metadata are SOURCE ports, not qualification."""

import base64
import hashlib
import json
import platform
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from netops import setup
from netops.ansible import contracts as c
from netops.dependencies import _guided as g
from netops.dependencies import _setup
from netops.dependencies._guided_metadata import _CachedArchive, _Metadata
from netops.dependencies.service import (
    ConsumingContext,
    DependencyRegistry,
    ProbeResult,
    RegistryError,
)
from tests.test_owned_source_author import source_case


def scope(enhanced=False):
    return c.InstallScope(("native.stdlib",), (), enhanced, False)


def service_case(root, monkeypatch, selected=None, *, status="available", controller=False):
    registry = DependencyRegistry.load()
    contexts = g._existing_contexts()
    if controller:
        contexts["controller"] = ConsumingContext(
            "source-guided-setup", "linux", platform.machine(), sys.executable, "", "controller",
        )
    calls = []

    def probe(self, entry, context, deadline):
        calls.append(entry.id)
        return ProbeResult(
            entry.id, context.digest, status, "author-source-port",
            platform.python_version(), "a" * 64 if status == "available" else None,
        )

    monkeypatch.setattr(_setup.LocalDependencyAdapter, "probe", probe)
    review = _setup._Review(lambda _: "", lambda _: None)
    service = _setup._service(registry, contexts, review, None)
    selected = selected or scope()
    context = _setup._context(root, registry)
    return registry, selected, context, service, calls


def report_from(output):
    return next(json.loads(line[line.index('{"checkpoint"'):])
                for line in output.splitlines() if '{"checkpoint"' in line)


def test_first_run_uses_actual_current_context_and_full_shared_closure(tmp_path, monkeypatch, capsys):
    registry, _, _, _, calls = service_case(tmp_path / "new", monkeypatch, status="missing")
    prompts = []
    monkeypatch.setattr("builtins.input", lambda prompt: prompts.append(prompt) or "")
    assert setup.main(["install", "--root", str(tmp_path / "new"), "--enhanced"]) == 3
    result = report_from(capsys.readouterr().out)
    assert result["status"] == "NeedsInput"
    assert {row["dependency"] for row in result["closure"]} == {entry.id for entry in registry.entries}
    assert calls and prompts and not (tmp_path / "new").exists()
    assert result["effects_performed"] == [] and result["consent_issued"] is False
    assert {row["dependency"] for row in result["needs"]} == {entry.id for entry in registry.entries}
    assert result["readiness"]["readiness"]["companion"] == "blocked"
    assert "Next action: supply --plan-file" not in str(result)


def test_preview_is_probe_prompt_metadata_and_root_free(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("pure preview crossed a boundary")

    monkeypatch.setattr(_setup.LocalDependencyAdapter, "probe", forbidden)
    monkeypatch.setattr(_Metadata, "resolve", forbidden)
    monkeypatch.setattr(_setup, "_owned", forbidden)
    monkeypatch.setattr("builtins.input", forbidden)
    root = tmp_path / "preview"
    assert setup.main(["plan", "--root", str(root), "--enhanced"]) == 3
    report = report_from(capsys.readouterr().out)
    assert report["status"] == "Planned" and report["readiness"] is None
    assert all(row["observation"] is None for row in report["closure"])
    assert not root.exists()


def test_available_reuse_is_current_evidence_not_full_install_readiness(tmp_path, monkeypatch):
    _, selected, context, service, calls = service_case(tmp_path, monkeypatch)
    diagnosis = g._diagnose(service, selected, context, probe=True)
    chosen = g._choose(diagnosis, g._Selection(), lambda _: "", lambda _: None)
    candidate, needs = _Metadata().resolve(diagnosis, chosen, selected, tmp_path, service.registry)
    assert calls == ["native-python"]
    assert chosen.components == (("native-python", "reuse"),)
    assert candidate is None and needs[0].reason == "verified-metadata-required"
    assert "sha256" in needs[0].fields and needs[0].source == "python.org"


@pytest.mark.parametrize("answer", ["install", "reuse", "unexpected", "grant elevation", ""])
def test_missing_components_cannot_invent_reuse_or_consent(tmp_path, monkeypatch, answer):
    _, selected, context, service, _ = service_case(tmp_path, monkeypatch, status="missing")
    diagnosis = g._diagnose(service, selected, context, probe=True)
    prompts = []

    def ask(prompt):
        prompts.append(prompt)
        return answer

    chosen = g._choose(diagnosis, g._Selection(), ask, lambda _: None)
    assert chosen.components == (("native-python", "install" if answer == "install" else "decline"),)
    assert all(mode == "decline" for _, mode in chosen.categories)
    assert bool(chosen.categories) is (answer == "install")
    if answer == "install":
        assert len(prompts) == 1 + len(g._CATEGORIES)


@pytest.mark.parametrize("error", [EOFError, OSError])
def test_unavailable_stdin_uses_safe_component_decline(tmp_path, monkeypatch, capsys, error):
    service_case(tmp_path, monkeypatch, status="missing")

    def unavailable(_):
        raise error()

    monkeypatch.setattr("builtins.input", unavailable)
    root = tmp_path / "no-stdin"
    assert setup.main(["install", "--root", str(root), "--capability", "native.stdlib"]) == 3
    report = report_from(capsys.readouterr().out)
    assert report["selection"]["components"] == [["native-python", "decline"]]
    assert not root.exists()


def test_cancelled_first_run_never_reserves_or_adopts_a_root(tmp_path, monkeypatch, capsys):
    service_case(tmp_path, monkeypatch, status="missing")

    def cancel(_):
        raise KeyboardInterrupt()

    monkeypatch.setattr("builtins.input", cancel)
    monkeypatch.setattr(_setup, "_owned", lambda *args: pytest.fail("cancel created an owned root"))
    root = tmp_path / "cancelled"
    assert setup.main(["install", "--root", str(root), "--capability", "native.stdlib"]) == 130
    assert not root.exists()
    assert "cancelled" in capsys.readouterr().out


def test_checkpoint_roundtrip_public_command_reprobes_without_json_reconstruction(
    tmp_path, monkeypatch, capsys,
):
    _, _, _, _, calls = service_case(tmp_path, monkeypatch, status="missing")
    monkeypatch.setattr("builtins.input", lambda _: "install")
    root = tmp_path / "checkpoint"
    assert setup.main(["install", "--root", str(root), "--capability", "native.stdlib"]) == 3
    first = report_from(capsys.readouterr().out)
    argv = first["next_command"][6:]
    assert "--checkpoint" in argv and "--plan-file" not in argv
    monkeypatch.setattr("builtins.input", lambda _: "")
    assert setup.main(argv) == 3
    second = report_from(capsys.readouterr().out)
    assert second["selection"]["components"] == [["native-python", "install"]]
    assert calls == ["native-python", "native-python"]
    assert not root.exists() and not second["consent_issued"]


def test_actual_checkpoint_command_works_outside_checkout_without_installation(
    tmp_path, monkeypatch, capsys,
):
    root = tmp_path / "source-only-continuation"
    monkeypatch.setattr("builtins.input", lambda _: "")
    assert setup.main(["plan", "--root", str(root), "--capability", "native.stdlib"]) == 3
    preview = report_from(capsys.readouterr().out)
    resumed = subprocess.run(
        preview["next_command"], cwd=tmp_path, input=b"", capture_output=True, timeout=30,
    )
    assert resumed.returncode == 3, resumed.stderr.decode(errors="replace")
    report = report_from(resumed.stdout.decode())
    assert report["status"] == "NeedsInput"
    assert report["closure"][0]["observation"]["status"] == "available"
    assert not root.exists() and not report["consent_issued"]


@pytest.mark.parametrize("damage", ["root", "scope", "registry", "context", "unknown", "grant",
                                  "invalid-base64", "oversize", "duplicate", "shape", "argv"])
def test_checkpoint_drift_and_authority_injection_rejected(tmp_path, monkeypatch, damage):
    _, selected, context, service, _ = service_case(tmp_path, monkeypatch)
    diagnosis = g._diagnose(service, selected, context, probe=False)
    token = g._checkpoint(tmp_path, selected, diagnosis, g._Selection((("native-python", "install"),)))
    raw = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
    if damage == "root":
        raw["root"] += "-other"
    elif damage == "scope":
        raw["scope"]["enhanced"] = True
    elif damage == "registry":
        raw["registry_digest"] = "b" * 64
    elif damage == "context":
        raw["consuming_contexts"] = ["b" * 64]
    elif damage == "unknown":
        raw["selection"]["components"] = [["unregistered", "install"]]
    elif damage == "grant":
        raw["grant"] = True
    elif damage == "argv":
        raw["argv"] = ["unregistered-program.exe", "--effect"]
    elif damage == "shape":
        raw["selection"] = []
    content = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    if damage == "duplicate":
        content = content[:-1] + b',"schema":"netops-guided-selection-v1"}'
    token = base64.urlsafe_b64encode(content).decode().rstrip("=")
    if damage == "invalid-base64":
        token = "!!invalid!!"
    elif damage == "oversize":
        token = "A" * 32769
    with pytest.raises(c.ContractError):
        g._resume_selection(token, tmp_path, selected, diagnosis)


def test_checkpoint_invalid_before_probe_or_prompt(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid checkpoint triggered discovery")

    monkeypatch.setattr(_setup.LocalDependencyAdapter, "probe", forbidden)
    monkeypatch.setattr("builtins.input", forbidden)
    assert setup.main(["install", "--root", str(tmp_path / "new"), "--checkpoint", "bad"]) == 3
    assert "did not complete" in capsys.readouterr().out


@pytest.mark.parametrize("components,categories", [
    ([("native-python", "install")], ()),
    ((("native-python", "grant"),), ()),
    ((("native-python", "install"), ("native-python", "decline")), ()),
    ((("native-python",),), ()),
    ((), (("elevation", "granted"),)),
    ((), (("unknown", "review"),)),
])
def test_selection_rejects_malformed_modes_duplicates_and_grants(components, categories):
    with pytest.raises(c.ContractError):
        g._Selection(components, categories)


def test_install_group_requests_never_convert_to_grants(tmp_path, monkeypatch):
    _, selected, context, service, _ = service_case(tmp_path, monkeypatch, status="missing")
    diagnosis = g._diagnose(service, selected, context, probe=True)
    chosen = g._choose(
        diagnosis, g._Selection(), lambda prompt: "install" if "Reuse/Install" in prompt else "review",
        lambda _: None,
    )
    assert chosen.categories == tuple((name, "review") for name in g._CATEGORIES)
    candidate, needs = _Metadata().resolve(diagnosis, chosen, selected, tmp_path, service.registry)
    assert candidate is None and needs


def test_stale_reuse_reverts_to_decline_and_unknown_selection_rejects(tmp_path, monkeypatch):
    _, selected, context, service, _ = service_case(tmp_path, monkeypatch, status="missing")
    diagnosis = g._diagnose(service, selected, context, probe=True)
    chosen = g._choose(diagnosis, g._Selection((("native-python", "reuse"),)), lambda _: "", lambda _: None)
    assert chosen.components == (("native-python", "decline"),)
    with pytest.raises(c.ContractError):
        g._choose(diagnosis, g._Selection((("unknown", "install"),)), lambda _: "", lambda _: None)
    assert g._needs(diagnosis, g._Selection((("native-python", "reuse"),)))[0].reason == (
        "compatible-reuse-evidence-required"
    )


def test_transitive_decline_and_missing_controller_keep_full_report(tmp_path, monkeypatch):
    selected = c.InstallScope((), (), True, True)
    _, _, context, service, _ = service_case(tmp_path, monkeypatch, selected)
    diagnosis = g._diagnose(service, selected, context, probe=True)
    choices = tuple((item.dependency, "decline" if item.dependency == "native-python" else "install")
                    for item in diagnosis.components)
    needs = g._needs(diagnosis, g._Selection(choices))
    assert next(item for item in needs if item.dependency == "pyyaml").reason == "prerequisite-declined"
    assert next(item for item in needs if item.dependency == "netmiko").reason == "prerequisite-declined"
    if sys.platform == "win32":
        assert next(item for item in needs if item.dependency == "controller-python").reason == (
            "controller-context-required"
        )
    assert len(needs) == len(diagnosis.plan.steps)


def test_prospective_owned_provider_candidate_reaches_public_create_review_without_descriptor(
    tmp_path, monkeypatch, capsys,
):
    root = tmp_path / "not-created"
    source, host, manifest = source_case(root)
    # This is the explicitly synthetic author producer port, not actual build proof.
    spec = replace(
        manifest.installation, python_version=platform.python_version(),
        python=g._existing_python(),
        python_digest=hashlib.sha256(Path(g._existing_python()).read_bytes()).hexdigest(),
    )
    host.result = replace(host.result, receipt=c.public_object({
        **dict(host.result.receipt), "interpreter": {
            "path": spec.python, "digest": spec.python_digest,
            "version": spec.python_version, "platform": spec.platform,
        },
    }))
    from netops.dependencies._owned_source import _OwnedSource

    source = _OwnedSource(host, _setup._Clock(), _setup._Cancel(), _setup.time.monotonic() + 60.0)
    metadata = _Metadata(spec, owned_source=source, generation_id=manifest.generation_id)
    service_case(root, monkeypatch)
    prompts = []

    def ask(prompt):
        prompts.append(prompt)
        return "reuse" if "Reuse/Install" in prompt else ""

    monkeypatch.setattr("builtins.input", ask)
    monkeypatch.setattr(_setup, "_owned", lambda *args: pytest.fail("root creation was declined"))
    assert _setup._main(["install", "--root", str(root), "--capability", "native.stdlib"],
                        _metadata=metadata) == 3
    assert any("Create NEW owner-only root" in prompt for prompt in prompts)
    assert "Creation declined" in capsys.readouterr().out and not root.exists()


def test_interpreter_and_producer_scope_cannot_widen_with_metadata(tmp_path, monkeypatch):
    source, _, manifest = source_case(tmp_path)
    _, selected, context, service, _ = service_case(tmp_path, monkeypatch)
    diagnosis = g._diagnose(service, selected, context, probe=True)
    choices = g._Selection((("native-python", "reuse"),))
    metadata = _Metadata(replace(manifest.installation, python_version="1.0.0"))
    candidate, needs = metadata.resolve(diagnosis, choices, selected, tmp_path, service.registry)
    assert candidate is None and needs[0].reason == "compatible-existing-interpreter-required"
    full = c.InstallScope((), (), False, True)
    _, _, context, service, _ = service_case(tmp_path, monkeypatch, full, controller=True)
    diagnosis = g._diagnose(service, full, context, probe=True)
    metadata = _Metadata(
        replace(manifest.installation, python_version=platform.python_version(),
                python=g._existing_python(),
                python_digest=hashlib.sha256(Path(g._existing_python()).read_bytes()).hexdigest()),
        owned_source=source, generation_id=manifest.generation_id,
    )
    candidate, needs = metadata.resolve(
        diagnosis, g._Selection(tuple((item.dependency, "install") for item in diagnosis.components)),
        full, tmp_path, service.registry,
    )
    assert candidate is None and all(item.reason == "producer-selected-scope-unsupported" for item in needs)


def bound_prospective_metadata(tmp_path):
    """Synthetic SOURCE port; real protected root, not a genuine build receipt."""
    root = _setup._owned(tmp_path / "consumer", True)
    source, host, manifest = source_case(Path(root.path))
    spec = replace(
        manifest.installation, python_version=platform.python_version(),
        python=g._existing_python(),
        python_digest=hashlib.sha256(Path(g._existing_python()).read_bytes()).hexdigest(),
    )
    host.result = replace(host.result, receipt=c.public_object({
        **dict(host.result.receipt),
        "consuming_root": (root.path, str(root.device), str(root.inode)),
        "interpreter": {"path": spec.python, "digest": spec.python_digest,
                        "version": spec.python_version, "platform": spec.platform},
    }))
    from netops.dependencies._owned_source import _OwnedSource

    source = _OwnedSource(host, _setup._Clock(), _setup._Cancel(), _setup.time.monotonic() + 60.0)
    return setup.SetupMetadata(source, spec, root, manifest.generation_id), host


@pytest.mark.parametrize("outcome", ["decline", "initialize", "race", "source-expired", "update"])
def test_public_typed_source_composition_requires_exact_empty_root_review(
    tmp_path, monkeypatch, capsys, outcome,
):
    metadata, host = bound_prospective_metadata(tmp_path)
    root = Path(metadata.consuming_root.path)
    service_case(root, monkeypatch)
    prompts = []

    def ask(prompt):
        prompts.append(prompt)
        if "Reuse/Install" in prompt:
            return "reuse"
        if "initialize " in prompt and outcome != "decline":
            if outcome == "race":
                (root / "unknown-user-data").write_bytes(b"preserve")
            if outcome == "source-expired":
                host.inspect = Mock(side_effect=TimeoutError())
            return prompt.split("'")[1]
        return ""

    monkeypatch.setattr("builtins.input", ask)
    assert setup.main(
        ["update" if outcome == "update" else "install",
         "--root", str(root), "--capability", "native.stdlib"], metadata=metadata,
    ) == 3
    records = tuple(root.glob("*.json"))
    if outcome == "initialize":
        _, documents = _setup._load_host(metadata.consuming_root)
        assert documents[0]["generation_id"] == metadata.generation_id
        assert any("to consent" in prompt and "initialize" not in prompt for prompt in prompts)
    else:
        assert not records
    if outcome == "race":
        assert (root / "unknown-user-data").read_bytes() == b"preserve"
    assert "Pinned candidate" in capsys.readouterr().out


def test_typed_source_cannot_claim_another_root_or_adopt_unknown_files(tmp_path, monkeypatch):
    metadata, _ = bound_prospective_metadata(tmp_path)
    other = _setup._owned(tmp_path / "other", True)
    with pytest.raises(c.ContractError):
        replace(metadata, consuming_root=other)
    with pytest.raises(c.ContractError):
        _Metadata(consuming_root=other)
    with pytest.raises(TypeError):
        setup.main([], metadata={"trusted": True})
    root = Path(metadata.consuming_root.path)
    (root / "native-user-data").write_bytes(b"preserve")
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("unknown root was offered adoption"))
    monkeypatch.setattr(_setup.LocalDependencyAdapter, "probe",
                        lambda *args: pytest.fail("unknown root was probed"))
    assert setup.main(
        ["install", "--root", str(root), "--capability", "native.stdlib"], metadata=metadata,
    ) == 3
    assert (root / "native-user-data").read_bytes() == b"preserve"
    assert setup.main(
        ["install", "--root", str(tmp_path / "not-the-consumer"), "--capability", "native.stdlib"],
        metadata=metadata,
    ) == 3


@pytest.mark.parametrize("field", ["source", "installation", "consuming_root"])
def test_public_metadata_rejects_untyped_authority_fields(tmp_path, field):
    metadata, _ = bound_prospective_metadata(tmp_path)
    with pytest.raises(TypeError):
        replace(metadata, **{field: None})


def test_initialization_deadline_is_not_renewed_after_source_guard(tmp_path, monkeypatch):
    metadata, _ = bound_prospective_metadata(tmp_path)
    document = _setup._owned_document(
        metadata.source, metadata.installation, metadata.generation_id,
    )
    # Explicit unit SOURCE port: this does not patch clocks for native proof.
    guard = Mock()
    monkeypatch.setattr(metadata.source, "guard", guard)
    monkeypatch.setattr(_setup, "time", SimpleNamespace(monotonic=Mock(side_effect=[10.0, 71.0])))
    review = _setup._Review(lambda prompt: prompt.split("'")[1], lambda _: None)
    from netops.ansible.policy.authorization import AuthorizationError

    with pytest.raises(AuthorizationError):
        _setup._initialize_source_root(
            metadata.consuming_root, document, DependencyRegistry.load(), metadata.source, review,
        )
    assert guard.call_args.args[-1] == 70.0
    assert not tuple(Path(metadata.consuming_root.path).iterdir())


def test_cached_metadata_no_missing_or_reordered_asset_can_compile(tmp_path, monkeypatch):
    from netops.dependencies._assets import LockedAsset
    from netops.dependencies._managed import ManagedArchive

    _, _, manifest = source_case(tmp_path)
    registry, selected, context, service, _ = service_case(tmp_path, monkeypatch)
    diagnosis = g._diagnose(service, selected, context, probe=True)
    chosen = g._Selection((("native-python", "reuse"),))
    spec = replace(
        manifest.installation, python_version=platform.python_version(),
        python=g._existing_python(),
        python_digest=hashlib.sha256(Path(g._existing_python()).read_bytes()).hexdigest(),
    )
    candidate, needs = _Metadata(spec).resolve(diagnosis, chosen, selected, tmp_path, registry)
    assert candidate is None and needs[0].reason == "ordered-selected-closure-required"
    asset = LockedAsset("author-synthetic", "native-python", "https://www.python.org/source.zip", "a" * 64, 1)
    archive = ManagedArchive(asset, "zip", manifest.members)
    cache = _CachedArchive(archive, tmp_path / "cache.zip")
    metadata = _Metadata(spec, (cache,))
    candidate, needs = metadata.resolve(diagnosis, chosen, selected, tmp_path, registry)
    assert candidate is None and needs[0].reason == "verified-offline-cache-required"
    for dependency, url, expected_error in [
        ("unknown", "https://www.python.org/source.zip", RegistryError),
        ("native-python", "https://files.pythonhosted.org/source.zip", c.ContractError),
        ("pyyaml", "https://files.pythonhosted.org/source.zip", c.ContractError),
    ]:
        wrong = replace(cache, archive=replace(archive, asset=replace(asset, dependency=dependency, url=url)))
        with pytest.raises(expected_error):
            _Metadata(spec, (wrong,)).resolve(diagnosis, chosen, selected, tmp_path, registry)
    with pytest.raises(c.ContractError):
        _CachedArchive(archive, Path("relative.zip"))
    with pytest.raises(c.ContractError):
        _Metadata(spec, (cache, cache))
    with pytest.raises(c.ContractError):
        _Metadata(spec, owned_source=object(), generation_id=manifest.generation_id)


def test_extra_companion_is_selected_not_silently_removed(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _: "")
    root = tmp_path / "companion"
    assert setup.main(["plan", "--root", str(root), "--companion", "companion.ansible"]) == 3
    report = report_from(capsys.readouterr().out)
    assert report["scope"]["companions"] == ["companion.ansible"]
    assert report["scope"]["full_toolkit"] is False
    assert report["readiness"] is None and not root.exists()
    assert "--companion" in report["next_command"]


def test_existing_unknown_root_does_not_probe_or_prompt(tmp_path, monkeypatch, capsys):
    sentinel = tmp_path / "native-inventory"
    sentinel.write_bytes(b"native-data")
    probe = Mock(side_effect=AssertionError("unknown root must not probe"))
    monkeypatch.setattr(_setup.LocalDependencyAdapter, "probe", probe)
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("unknown root prompted"))
    assert setup.main(["install", "--root", str(tmp_path)]) == 3
    assert sentinel.read_bytes() == b"native-data"
    probe.assert_not_called()
    assert "did not complete" in capsys.readouterr().out


def test_actual_first_run_existing_interpreter_without_site_packages(tmp_path):
    root = tmp_path / "actual-native-not-created"
    program = """
import builtins,contextlib,io,json,pathlib,sys
sys.path.insert(0,sys.argv[1])
from netops.setup import main
builtins.input=lambda prompt:''
output=io.StringIO()
with contextlib.redirect_stdout(output):
    result=main(['install','--root',sys.argv[2],'--capability','native.stdlib'])
report=next(json.loads(line) for line in output.getvalue().splitlines() if line.startswith('{"checkpoint"'))
print(json.dumps({'exit':result,'report':report,'root_exists':pathlib.Path(sys.argv[2]).exists()}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", program, str(Path.cwd()), str(root)],
        capture_output=True, check=True, timeout=30,
    )
    observed = json.loads(result.stdout)
    assert observed["exit"] == 3 and observed["root_exists"] is False
    component = observed["report"]["closure"][0]
    assert component["dependency"] == "native-python"
    assert component["observation"]["status"] == "available"
    assert component["observation"]["version"] == platform.python_version()
    assert observed["report"]["status"] == "NeedsInput"
    assert observed["report"]["selection"]["components"] == [["native-python", "reuse"]]


def test_prospective_pinned_cache_compiles_only_through_existing_manifest_validator(
    tmp_path, monkeypatch,
):
    from netops.dependencies._assets import LockedAsset
    from netops.dependencies._managed import ManagedArchive

    _, _, manifest = source_case(tmp_path)
    registry, selected, context, service, _ = service_case(tmp_path, monkeypatch)
    diagnosis = g._diagnose(service, selected, context, probe=True)
    spec = replace(
        manifest.installation, python_version=platform.python_version(),
        python=g._existing_python(),
        python_digest=hashlib.sha256(Path(g._existing_python()).read_bytes()).hexdigest(),
    )
    # Synthetic constructor metadata tests SOURCE wiring, not publisher origin.
    archive = ManagedArchive(
        LockedAsset("author-source-port", "native-python",
                    "https://www.python.org/author-source-port.zip", "a" * 64, 1),
        "zip", manifest.members,
    )
    metadata = _Metadata(spec, (_CachedArchive(archive, tmp_path / "author-cache.zip"),))
    validated = []
    monkeypatch.setattr(_setup, "_cached_closure", lambda candidate, document: validated.append((candidate, document)))
    candidate, needs = metadata.resolve(
        diagnosis, g._Selection((("native-python", "reuse"),)), selected, tmp_path, registry,
    )
    assert candidate is not None and not needs and candidate.owned_source is None
    assert len(validated) == 1
    actual, _ = _setup._manifest(candidate.document, tmp_path, registry)
    assert actual == validated[0][0]
    assert actual.scope == selected and actual.assets == (archive.asset,)
    assert actual.installation == spec and not (tmp_path / "author-cache.zip").exists()


@pytest.mark.parametrize("damage", ["pin", "missing-file", "version", "platform", "path"])
def test_bad_existing_interpreter_pin_reports_exact_need_before_root(tmp_path, monkeypatch, damage):
    _, _, manifest = source_case(tmp_path)
    registry, selected, context, service, _ = service_case(tmp_path, monkeypatch)
    diagnosis = g._diagnose(service, selected, context, probe=True)
    spec = replace(manifest.installation, python_version=platform.python_version())
    if damage == "missing-file":
        from netops.dependencies import _guided_metadata

        monkeypatch.setattr(_guided_metadata, "_hash", Mock(side_effect=FileNotFoundError()))
    elif damage == "version":
        spec = replace(spec, python_version="1.0.0")
    elif damage == "platform":
        spec = replace(spec, platform="linux" if sys.platform == "win32" else "win32")
    elif damage == "path":
        spec = replace(spec, python=str(tmp_path / "unregistered-interpreter.exe"))
    candidate, needs = _Metadata(spec).resolve(
        diagnosis, g._Selection((("native-python", "reuse"),)), selected, tmp_path, registry,
    )
    assert candidate is None
    if damage in ("pin", "missing-file"):
        assert needs[0].reason == "existing-interpreter-pin-mismatch"
        assert needs[0].fields == ("existing-interpreter-sha256",)
    else:
        assert needs[0].reason == "compatible-existing-interpreter-required"


def test_future_registered_entry_is_consumed_by_actual_diagnosis_without_new_type_switch(
    tmp_path, monkeypatch,
):
    registry, selected, _, _, _ = service_case(tmp_path, monkeypatch)
    package = Path("netops/dependencies")
    data = json.loads((package / "registry.json").read_bytes())
    operations = json.loads((package / "operations.json").read_bytes())
    qualification = json.loads((package / "qualification.json").read_bytes())
    future = {
        **data["entries"][0], "id": "future-registered-python",
        "requires": ["native-python"], "consumers": ["native.stdlib"],
    }
    data["entries"].append(future)
    next(item for item in operations["operations"]
         if item["module"] == "netops.logging_setup")["dependencies"] = ["future-registered-python"]
    registry = DependencyRegistry.from_data(data, operations, qualification)
    service = _setup._service(registry, g._existing_contexts(), _setup._Review(lambda _: "", lambda _: None), None)
    diagnosis = g._diagnose(service, selected, _setup._context(tmp_path, registry), probe=True)
    assert [item.dependency for item in diagnosis.components] == ["native-python", "future-registered-python"]
    assert all(item.observation.status == "available" for item in diagnosis.components)
    candidate, needs = _Metadata().resolve(
        diagnosis, g._Selection(tuple((item.dependency, "install") for item in diagnosis.components)),
        selected, tmp_path, registry,
    )
    assert candidate is None
    assert {item.dependency for item in needs} == {"native-python", "future-registered-python"}


@pytest.mark.parametrize("venv,system", [(True, "nt"), (False, "nt"), (False, "posix")])
def test_existing_interpreter_vendor_selection_preserves_venv_and_resolves_only_base(
    tmp_path, monkeypatch, venv, system,
):
    executable = str(tmp_path / "selected-python.exe")
    monkeypatch.setattr(g, "sys", SimpleNamespace(
        executable=executable, prefix="venv" if venv else str(tmp_path),
        base_prefix=str(tmp_path),
    ))
    monkeypatch.setattr(g, "os", SimpleNamespace(name=system))
    selected = g._existing_python()
    assert selected == (
        executable if venv or system == "posix" else str(tmp_path / "python.exe")
    )


def test_aggregate_diagnosis_deadline_remains_actionable_without_renewal(tmp_path, monkeypatch):
    registry, selected, context, service, _ = service_case(tmp_path, monkeypatch)
    monkeypatch.setattr(service, "verify", Mock(side_effect=RegistryError("deadline-exceeded")))
    diagnosis = g._diagnose(service, selected, context, probe=True)
    assert diagnosis.readiness is None
    assert diagnosis.components[0].observation.reason == "diagnosis-budget-exhausted"
    candidate, needs = _Metadata().resolve(
        diagnosis, g._Selection((("native-python", "install"),)), selected, tmp_path, registry,
    )
    assert candidate is None and needs[0].reason == "fresh-consuming-observation-required"
    monkeypatch.setattr(service, "verify", Mock(side_effect=RegistryError("clock-invalid")))
    with pytest.raises(RegistryError, match="clock-invalid"):
        g._diagnose(service, selected, context, probe=True)


@pytest.mark.parametrize("damage", ["missing", "shape", "conflict"])
def test_incomplete_or_conflicting_readiness_never_supplies_reuse(tmp_path, monkeypatch, damage):
    _, selected, context, service, _ = service_case(tmp_path, monkeypatch)
    report = service.verify(selected, context)
    record = dict(report.capabilities[0])
    observations = list(record["probes"])
    if damage == "missing":
        record["probes"] = []
    elif damage == "shape":
        record["probes"] = "not-a-probe-list"
    else:
        observations.append({**dict(observations[0]), "reason": "conflicting-observation"})
        record["probes"] = observations
    bad = replace(report, capabilities=(c.public_object(record),))
    monkeypatch.setattr(service, "verify", lambda *args: bad)
    with pytest.raises(c.ContractError):
        g._diagnose(service, selected, context, probe=True)


def test_reordered_complete_cache_closure_rejects_before_metadata_dispatch(tmp_path, monkeypatch):
    from netops.dependencies._assets import LockedAsset
    from netops.dependencies._managed import ManagedArchive, ManagedMember

    _, _, manifest = source_case(tmp_path)
    selected = c.InstallScope(("netops.core.inventory:Device",), (), False, False)
    registry, _, context, service, _ = service_case(tmp_path, monkeypatch, selected)
    diagnosis = g._diagnose(service, selected, context, probe=True)
    assert tuple(item.dependency for item in diagnosis.components) == ("native-python", "pyyaml")
    spec = replace(
        manifest.installation, python=g._existing_python(), python_version=platform.python_version(),
        python_digest=hashlib.sha256(Path(g._existing_python()).read_bytes()).hexdigest(),
    )
    assets = (
        _CachedArchive(ManagedArchive(
            LockedAsset("author-pypi-port", "pyyaml",
                        "https://files.pythonhosted.org/author-port.zip", "a" * 64, 1),
            "zip", (ManagedMember("author-yaml.whl", "b" * 64, 1),),
        ), tmp_path / "yaml.zip"),
        _CachedArchive(ManagedArchive(
            LockedAsset("author-python-port", "native-python",
                        "https://www.python.org/author-port.zip", "c" * 64, 1),
            "zip", manifest.members,
        ), tmp_path / "python.zip"),
    )
    monkeypatch.setattr(_setup, "_cached_closure", lambda *args: pytest.fail("reordered closure dispatched"))
    candidate, needs = _Metadata(spec, assets).resolve(
        diagnosis, g._Selection((("native-python", "reuse"), ("pyyaml", "install"))),
        selected, tmp_path, registry,
    )
    assert candidate is None
    assert {need.dependency for need in needs} == {"native-python", "pyyaml"}
    assert all(need.reason == "ordered-selected-closure-required" for need in needs)


@pytest.mark.parametrize("system,controller", [("win32", False), ("linux", True), ("darwin", True)])
def test_prospective_context_selection_never_invents_windows_controller_or_grants(
    tmp_path, monkeypatch, system, controller,
):
    monkeypatch.setattr(g, "sys", SimpleNamespace(
        platform=system, executable=str(tmp_path / "existing-python"),
    ))
    contexts = g._existing_contexts()
    assert ("controller" in contexts) is controller
    assert all(context.grants == () and context.python == str(tmp_path / "existing-python")
               for context in contexts.values())
    if controller:
        assert contexts["controller"].id == "source-guided-setup"


