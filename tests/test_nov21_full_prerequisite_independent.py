"""Original full prerequisite acceptance; fake probes are not platform qualification."""

import copy
import hashlib
import json
import platform
import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from netops import setup
from netops.ansible import contracts as c
from netops.ansible.policy import LocalReferencePolicyEngine, PolicyIdentity, load_policy
from netops.dependencies import (
    ConsumingContext,
    DependencyRegistry,
    DependencyService,
    ProbeResult,
    RegistryError,
)
from netops.dependencies.service import ADAPTERS


@pytest.fixture(scope="module")
def independent_policy():
    root = Path("netops/ansible/policy")
    source = (root / "ansible_molecule.px").read_bytes()
    contracts = (root / "ansible_molecule.contracts.px").read_bytes()
    bundle = (root / "bundle.json").read_bytes()
    parsed = json.loads(bundle)
    identity = PolicyIdentity(
        parsed["canonical_revision"], hashlib.sha256(source).hexdigest(),
        hashlib.sha256(contracts).hexdigest(), hashlib.sha256(bundle).hexdigest(),
        tuple(item["id"] for item in parsed["manifest"]), parsed["reducer_version"],
    )
    return identity, LocalReferencePolicyEngine(load_policy(source, contracts, bundle, identity))


class SourceOnlyProbe:
    """Deliberately missing observations; never a qualified actual controller."""

    def __init__(self):
        native = ConsumingContext(
            "independent-native", sys.platform, platform.machine(), sys.executable, "", "native",
        )
        self.contexts = {
            "native": native,
            "controller": ConsumingContext(
                "source-only-not-qualified", "linux", platform.machine(),
                sys.executable, "", "controller",
            ),
        }
        self.calls = []

    def probe(self, entry, context, deadline):
        self.calls.append((entry.id, context.digest, deadline))
        return ProbeResult(
            entry.id, context.digest, "missing", "source-only-missing", next_action="review-setup",
        )


def independent_service(independent_policy):
    identity, policy = independent_policy
    registry = DependencyRegistry.load()
    probe = SourceOnlyProbe()
    clock = Mock()
    clock.monotonic.side_effect = time.monotonic
    service = DependencyService(
        registry, dict.fromkeys(ADAPTERS, probe), Mock(), policy, Mock(), clock, Mock(),
    )
    context = c.InstallContext(c.Context(
        "source-only-not-qualified", "a" * 64, "independent-no-device-route", "b" * 64,
        identity, registry.digest, "c" * 64,
    ))
    return service, context, probe


@pytest.mark.parametrize("enhanced", [False, True])
def test_ac001_full_selection_covers_every_public_and_selected_intent(
    independent_policy, enhanced,
):
    service, context, probe = independent_service(independent_policy)
    plan = service.plan(c.InstallScope(
        native_capabilities=(), companions=(), full_toolkit=True, enhanced=enhanced,
    ), context)
    catalog = service.catalog()
    expected = set(catalog.native_baseline)
    for operation in catalog.operations:
        if operation.tier == "enhanced" and not enhanced:
            continue
        expected.update(operation.dependencies)
        for _, dependencies in operation.intents:
            expected.update(dependencies)
        for _, dependencies in operation.export_dependencies:
            expected.update(dependencies)
        for _, dependencies in operation.variants:
            expected.update(dependencies)
    pending = list(expected)
    while pending:
        for dependency in service.registry.entry(pending.pop()).requires:
            if dependency not in expected:
                expected.add(dependency)
                pending.append(dependency)
    actual = [step.dependency for step in plan.steps]
    assert len(actual) == len(set(actual))
    assert set(actual) == expected
    positions = {dependency: index for index, dependency in enumerate(actual)}
    for dependency in actual:
        assert all(
            positions[edge] < positions[dependency]
            for edge in service.registry.entry(dependency).requires
        )
    kinds = {service.registry.entry(dependency).kind for dependency in actual}
    assert {"python", "pip", "galaxy", "executable", "library", "platform"} <= kinds
    assert ({"runtime", "image"} <= kinds) is enhanced
    assert not probe.calls
    service.authorization.assert_not_called()
    service.events.emit.assert_not_called()


@pytest.mark.parametrize("damage", ["missing-transitive", "indirect-cycle", "unknown-provider"])
def test_ac001_invalid_registry_closure_rejected_before_provider_dispatch(damage):
    root = Path("netops/dependencies")
    data = json.loads((root / "registry.json").read_bytes())
    operations = json.loads((root / "operations.json").read_bytes())
    qualification = json.loads((root / "qualification.json").read_bytes())
    entries = {item["id"]: item for item in data["entries"]}
    if damage == "missing-transitive":
        entries["paramiko"]["requires"].append("unregistered-wheel-transitive")
    elif damage == "indirect-cycle":
        entries["native-python"]["requires"] = ["netmiko"]
    else:
        entries["native-python"]["adapter"] = "run-arbitrary-provider-argv"
    with pytest.raises(RegistryError):
        DependencyRegistry.from_data(copy.deepcopy(data), operations, qualification)


def test_ac001_missing_descriptor_runs_guided_diagnosis_before_decline(
    tmp_path, monkeypatch, capsys,
):
    """First run must guide repair rather than ask users to handcraft a plan file."""
    from netops.dependencies import _setup

    calls = []
    prompts = []
    sentinel = tmp_path / "existing-native-user-data.txt"
    sentinel.write_bytes(b"keep-user-native-state")
    root = tmp_path / "new-guided-root"

    def missing(self, entry, context, deadline):
        calls.append(entry.id)
        return ProbeResult(
            entry.id, context.digest, "missing", "source-only-missing", next_action="review-setup",
        )

    def decline(prompt):
        prompts.append(prompt)
        return ""

    def forbid_root(*args, **kwargs):
        pytest.fail("Declined first-run diagnosis tried to create/adopt an owned root.")

    monkeypatch.setattr(_setup.LocalDependencyAdapter, "probe", missing)
    monkeypatch.setattr("builtins.input", decline)
    monkeypatch.setattr(_setup, "_owned", forbid_root)
    result = setup.main(["install", "--root", str(root), "--enhanced"])
    output = capsys.readouterr().out
    assert result != 0
    assert not root.exists()
    assert sentinel.read_bytes() == b"keep-user-native-state"
    assert calls, "No actual consuming-context diagnosis occurred for missing first-run setup."
    assert prompts, "No guided resolution/review/consent was offered before abandonment."
    assert "Next action: supply --plan-file" not in output


@pytest.mark.parametrize("enhanced", [False, True])
def test_ac003_setup_plan_is_prompt_probe_and_write_free(tmp_path, monkeypatch, capsys, enhanced):
    from netops.dependencies import _setup

    def forbidden(*args, **kwargs):
        pytest.fail("Pure setup plan crossed a prompt/probe/root mutation boundary.")

    root = tmp_path / "uncreated-root"
    monkeypatch.setattr(_setup.LocalDependencyAdapter, "probe", forbidden)
    monkeypatch.setattr("builtins.input", forbidden)
    monkeypatch.setattr(_setup, "_owned", forbidden)
    argv = ["plan", "--root", str(root)] + (["--enhanced"] if enhanced else [])
    result = setup.main(argv)
    output = capsys.readouterr().out
    assert result in (0, 3)
    assert not root.exists()
    assert "native-python" in output
    assert "not an Ansible controller" in output
    assert "all installed" not in output.lower()


def test_ac001_unknown_existing_root_never_becomes_owned(tmp_path, monkeypatch, capsys):
    root = tmp_path / "unknown-user-root"
    root.mkdir()
    sentinel = root / "inventory-user-state.yaml"
    sentinel.write_bytes(b"sentinel: unchanged\n")
    before = {item.name: item.read_bytes() for item in root.iterdir()}
    prompts = []
    monkeypatch.setattr("builtins.input", lambda prompt: prompts.append(prompt) or "")
    result = setup.main(["install", "--root", str(root)])
    assert result != 0
    assert not prompts
    assert {item.name: item.read_bytes() for item in root.iterdir()} == before
    assert sentinel.read_bytes() == b"sentinel: unchanged\n"
    assert "did not complete" in capsys.readouterr().out
