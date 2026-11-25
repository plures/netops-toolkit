"""Semantic I01 regressions; fixture observations are never qualification."""

import ast
import io
import json
import logging
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from netops.ansible import contracts as c
from netops.dependencies import DependencyRegistry, LocalDependencyAdapter, RegistryError
from tests.test_dependency_probes import context, service_and_context
from tests.test_dependency_probes import policy as policy


def _public_optional_import_consumers():
    """Derive consuming cases from real public bodies, not manifest dependency lists."""
    libraries = {
        "yaml": "pyyaml", "netmiko": "netmiko", "paramiko": "paramiko",
        "cryptography": "cryptography", "jinja2": "jinja2", "pysnmp": "pysnmp",
        "textual": "textual",
    }
    cases = set()
    for operation in DependencyRegistry.load().operations:
        if operation.tier != "native":
            continue
        path = Path(*operation.module.split(".")).with_suffix(".py")
        if not path.is_file():
            continue
        source = ast.parse(path.read_text(encoding="utf-8"))
        definitions = {node.name: node for node in source.body if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        )}
        for export in operation.exports:
            pending, visited = [export], set()
            while pending:
                name = pending.pop()
                if name in visited or name not in definitions:
                    continue
                visited.add(name)
                for node in ast.walk(definitions[name]):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                        pending.append(node.func.id)
                    if isinstance(node, ast.Import):
                        modules = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom):
                        modules = [node.module or ""]
                    else:
                        continue
                    for module in modules:
                        dependency = libraries.get(module.split(".")[0])
                        if dependency is not None:
                            default = dict(operation.export_dependencies).get(
                                export, operation.dependencies,
                            )
                            mode = next((
                                operation.capability + ":" + intent
                                for intent, dependencies in operation.intents
                                if dependency in dependencies and dependency not in default
                            ), "")
                            cases.add((operation.module + ":" + export, dependency, mode))
    return sorted(cases)


@pytest.mark.parametrize(("selector", "missing", "mode"), _public_optional_import_consumers())
def test_source_derived_public_optional_imports_fail_closed(policy, selector, missing, mode):
    service, selected, adapter, _ = service_and_context(policy, (missing,))
    scope = c.InstallScope(tuple(x for x in (selector, mode) if x), (), False, False)
    assert missing in {step.dependency for step in service.plan(scope, selected).steps}
    assert not adapter.calls
    assert service.verify(scope, selected).readiness.native == "blocked"


@pytest.mark.parametrize(("selector", "missing"), [
    ("netops.core.community:extract_communities_via_ssh", "netmiko"),
    ("netops.core.community:extract_communities_via_ssh", "paramiko"),
    ("netops.core.community:extract_communities_via_ssh", "cryptography"),
    ("netops.core.community:try_communities", "pysnmp"),
    ("netops.core.vault:CredentialVault", "pyyaml"),
    ("netops.core.vault:CredentialVault", "cryptography"),
    ("netops.core.vault:main", "pyyaml"),
    ("netops.ansible.credentials:ScopedCredentialResolver", "pyyaml"),
    ("netops.report.health_dashboard:main", "netmiko"),
    ("netops.report.health_dashboard:main", "paramiko"),
    ("netops.report.health_dashboard:main", "pyyaml"),
    ("netops.report.health_dashboard:render_html", "jinja2"),
    ("netops.collect.config:collect_config", "netmiko"),
    ("netops.check.health:run_health_check", "netmiko"),
    ("netops.change.push:run_push", "netmiko"),
    ("netops.collect.backup:git_commit", "git"),
])
def test_actual_consumer_prerequisite_failure_blocks_plan_and_verify(policy, selector, missing):
    """Cover SSH chains, vault serialization, rendering and explicit tool consumers."""
    service, selected, adapter, _ = service_and_context(policy, (missing,))
    scope = c.InstallScope((selector,), (), False, False)
    assert missing in {step.dependency for step in service.plan(scope, selected).steps}
    assert not adapter.calls
    report = service.verify(scope, selected)
    assert report.readiness.native == "blocked"
    assert missing in {call[0] for call in adapter.calls}


@pytest.mark.parametrize("selector", [
    "netops.core.community:CommunityRegistry",
    "netops.report.health_dashboard:normalize_device_result",
    "netops.report.health_dashboard:aggregate_dashboard",
    "netops.report.health_dashboard:format_table",
    "netops.inventory.scan:results_to_inventory_fragment",
    "native.scan:skip-ping-and-snmp",
])
def test_actual_stdlib_consumers_remain_ready_without_optional_libraries(policy, selector):
    registry = DependencyRegistry.load()
    missing = tuple(entry.id for entry in registry.entries if entry.id != "native-python")
    service, selected, adapter, _ = service_and_context(policy, missing)
    report = service.verify(c.InstallScope((selector,), (), False, False), selected)
    assert report.readiness.native == "ready"
    assert {call[0] for call in adapter.calls} == {"native-python"}


def _registered_public_aliases():
    root = Path("netops") / "dependencies" / "operations.json"
    return [
        (operation["module"], export, target)
        for operation in json.loads(root.read_text())["operations"]
        for export, target in operation.get("aliases", {}).items()
    ]


@pytest.mark.parametrize(("module", "export", "target"), _registered_public_aliases())
def test_all_public_aliases_share_canonical_capability_plan_and_readiness(
    policy, module, export, target,
):
    registry = DependencyRegistry.load()
    missing = tuple(entry.id for entry in registry.entries if entry.id != "native-python")
    service, selected, _, _ = service_and_context(policy, missing)
    canonical_module, canonical_export = target.split(":")
    alias = registry.operation(module, export)
    canonical = registry.operation(canonical_module, canonical_export)
    assert (alias.capability, alias.tier, alias.dependencies, alias.intents) == (
        canonical.capability, canonical.tier, canonical.dependencies, canonical.intents,
    )
    observations = []
    for selector in (module + ":" + export, target):
        scope = c.InstallScope((selector,), (), False, False)
        observations.append((
            {step.dependency for step in service.plan(scope, selected).steps},
            service.verify(scope, selected).readiness,
        ))
    assert observations[0] == observations[1]


@pytest.mark.parametrize("dependency", [
    "native-python", "pyyaml", "native-pdf-libraries", "ansible.netcommon", "ansible-playbook",
])
def test_every_consuming_python_dispatch_disables_actual_bytecode(monkeypatch, dependency):
    entry = DependencyRegistry.load().entry(dependency)
    entry = replace(entry, platforms=(sys.platform,))
    selected = context(id=entry.context, role=entry.context)
    commands = []

    class Process:
        def __init__(self, command, **kwargs):
            commands.append(command)
            self.stdout = io.BytesIO(b"{}")
            self.returncode = 1

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = 1

    monkeypatch.setattr("netops.dependencies.adapters.subprocess.Popen", Process)
    LocalDependencyAdapter({entry.context: selected}).probe(
        entry, selected, time.monotonic() + 2.0,
    )
    assert commands and commands[0][1:3] == ["-I", "-B"]


def test_isolated_child_flags_prevent_cache_in_owned_scratch(tmp_path):
    source = tmp_path / "owned_probe.py"
    source.write_text("value = 1\n", encoding="utf-8")
    script = (
        "import sys; assert sys.dont_write_bytecode; "
        "sys.path.insert(0,sys.argv[1]); import owned_probe"
    )
    subprocess.run([sys.executable, "-I", "-B", "-c", script, str(tmp_path)], check=True)
    assert not (tmp_path / "__pycache__").exists()


@pytest.mark.parametrize("rejection", [
    "context-missing", "registry-drift", "policy-identity-drift", "controller-drift",
    "deadline-exceeded",
])
def test_service_rejections_pair_observations_once(policy, caplog, rejection):
    service, selected, adapter, events = service_and_context(policy)
    selector = "native.transport"
    if rejection == "context-missing":
        adapter.contexts = {}
    elif rejection == "registry-drift":
        selected = replace(selected, context=replace(selected.context, registry_digest="d" * 64))
    elif rejection == "policy-identity-drift":
        identity = replace(selected.context.policy_identity, bundle_sha256="d" * 64)
        selected = replace(selected, context=replace(selected.context, policy_identity=identity))
    elif rejection == "controller-drift":
        selected = replace(selected, context=replace(selected.context, controller_id="other"))
        selector = "netops.ansible.modules.netops_command:run_module"
    else:
        service.clock.monotonic.side_effect = iter([0.0] + [61.0] * 100)
    with caplog.at_level(logging.INFO):
        service.verify(c.InstallScope((selector,), (), False, False), selected)
    records = [r for r in caplog.records if getattr(r, "metric_name", "") ==
               "netops.dependency.probe.count" and r.reason == rejection]
    assert records
    assert len({r.dependency for r in records}) == len(records)
    assert all(r.metric_value == 1 and r.category == "dependency" and
               r.next_action == "verify-consuming-context" and r.duration >= 0 for r in records)


def test_probe_telemetry_sink_failures_do_not_escape(policy, monkeypatch):
    service, selected, adapter, events = service_and_context(policy)
    adapter.contexts = {}
    events.emit.side_effect = RuntimeError("private sink detail")
    monkeypatch.setattr("logging.Logger.info", Mock(side_effect=RuntimeError("private detail")))
    report = service.verify(c.InstallScope(("native.transport",), (), False, False), selected)
    assert report.readiness.native == "blocked"
    local = LocalDependencyAdapter({"native": context()})
    result = local.probe(DependencyRegistry.load().entry("native-python"), context(), 0.0)
    assert result.reason == "deadline-exceeded"


def test_service_and_real_adapter_emit_exactly_one_observation(policy, caplog):
    service, selected, _, events = service_and_context(policy)
    adapter = LocalDependencyAdapter({"native": context()})
    service.adapters = dict.fromkeys(service.adapters, adapter)
    with caplog.at_level(logging.INFO):
        report = service.verify(
            c.InstallScope(("native.scan:skip-ping-and-snmp",), (), False, False), selected,
        )
    records = [r for r in caplog.records if getattr(r, "metric_name", "") ==
               "netops.dependency.probe.count"]
    assert report.readiness.native == "ready"
    assert len(records) == events.emit.call_count == 1
    assert sum(adapter.counts.values()) == 1


@pytest.mark.parametrize("requirement", [
    "ansible.netcommon", "ANSIBLE_netcommon", "ansible-netcommon[extra]>=6; python_version>'3'",
    "ansible.netcommon @ https://invalid.example/collection.whl",
])
def test_pep508_galaxy_names_never_become_pip(requirement):
    project = Path("pyproject.toml").read_text(encoding="utf-8")
    candidate = project.replace(
        'ansible = [\n', f"ansible = [\n    {json.dumps(requirement)},\n", 1,
    )
    with pytest.raises(RegistryError, match="package-metadata-drift"):
        DependencyRegistry.load().validate_package_metadata(candidate)


@pytest.mark.parametrize("replacement", [
    "", '"PyYAML>=6.0; python_version < \'3.0\'",',
])
def test_required_pip_declaration_cannot_disappear_or_become_inapplicable(replacement):
    project = Path("pyproject.toml").read_text(encoding="utf-8")
    candidate = project.replace('"pyyaml>=6.0",', replacement)
    with pytest.raises(RegistryError, match="package-metadata-drift"):
        DependencyRegistry.load().validate_package_metadata(candidate)


def test_toml_and_pep508_parsing_accept_equivalent_requirement_spelling():
    project = Path("pyproject.toml").read_text(encoding="utf-8")
    candidate = project.replace('"pyyaml>=6.0"', "'PyYAML >= 6.0'")
    candidate = candidate.replace('"netmiko>=4.3.0,<4.5.0"', "'NETMIKO <4.5.0, >=4.3.0'")
    candidate += '\n[tool.unrelated]\nexample = "ansible.netcommon"\n'
    DependencyRegistry.load().validate_package_metadata(candidate)


@pytest.mark.parametrize("missing", [("ping",), ("pysnmp",), ("ping", "pysnmp")])
def test_default_scan_checks_both_real_default_prerequisites(policy, missing):
    service, selected, adapter, _ = service_and_context(policy, missing)
    report = service.verify(c.InstallScope(("native.scan",), (), False, False), selected)
    assert report.readiness.native == "blocked"
    assert {"ping", "pysnmp"} <= {call[0] for call in adapter.calls}


@pytest.mark.parametrize(("export", "required"), [
    ("ping_host", {"ping"}), ("ping_sweep", {"ping"}),
    ("scan_subnet", {"ping", "pysnmp"}), ("scan_subnet_async", {"ping", "pysnmp"}),
])
def test_registered_scan_exports_describe_their_actual_consumers(export, required):
    operation = DependencyRegistry.load().operation("netops.inventory.scan", export)
    assert required <= set(operation.dependencies)


@pytest.mark.parametrize(("selector", "expected"), [
    ("native.scan:skip-ping", {"native-python", "pysnmp"}),
    ("native.scan:skip-snmp", {"native-python", "ping"}),
    ("native.scan:skip-ping-and-snmp", {"native-python"}),
    ("netops.inventory.scan:ping_host", {"native-python", "ping"}),
    ("netops.inventory.scan:scan_subnet", {"native-python", "ping", "pysnmp"}),
    ("netops.inventory.scan:scan_subnet_async", {"native-python", "ping", "pysnmp"}),
    ("netops.inventory.scan:results_to_inventory_fragment", {"native-python"}),
    ("netops.inventory.scan:identify_vendor", {"native-python"}),
])
def test_selected_consumer_has_no_fictional_scanning_prerequisites(policy, selector, expected):
    service, selected, adapter, _ = service_and_context(policy)
    scope = c.InstallScope((selector,), (), False, False)
    plan = service.plan(scope, selected)
    assert {step.dependency for step in plan.steps} == expected
    assert not adapter.calls
    report = service.verify(scope, selected)
    assert report.readiness.native == "ready"
    assert {call[0] for call in adapter.calls} == expected


@pytest.mark.parametrize(("selector", "missing", "ready"), [
    ("native.scan:skip-ping", ("ping",), True),
    ("native.scan:skip-ping", ("pysnmp",), False),
    ("native.scan:skip-snmp", ("pysnmp",), True),
    ("native.scan:skip-snmp", ("ping",), False),
    ("native.scan:skip-ping-and-snmp", ("ping", "pysnmp"), True),
    ("netops.inventory.scan:ping_host", ("ping",), False),
    ("netops.inventory.scan:results_to_inventory_fragment", ("ping", "pysnmp"), True),
])
def test_reduced_modes_only_skip_explicitly_unselected_probes(policy, selector, missing, ready):
    service, selected, _, _ = service_and_context(policy, missing)
    report = service.verify(c.InstallScope((selector,), (), False, False), selected)
    assert report.readiness.native == ("ready" if ready else "blocked")


@pytest.mark.parametrize("adapter", ["python", "module", "executable", "collection", "pdf",
                                    "runtime", "asset", "grant"])
def test_registry_rejects_symbols_without_fixed_probe_implementations(adapter):
    root = Path("netops") / "dependencies"
    data = json.loads((root / "registry.json").read_text())
    operations = json.loads((root / "operations.json").read_text())
    lock = json.loads((root / "qualification.json").read_text())
    next(entry for entry in data["entries"] if entry["adapter"] == adapter)["probe"] = "unknown"
    with pytest.raises(RegistryError, match="probe-unregistered"):
        DependencyRegistry.from_data(data, operations, lock)


def test_registered_rm_uses_only_safe_bounded_consuming_context_help(monkeypatch):
    selected = context(id="controller", role="controller", path="fixture-controller-path")
    entry = replace(DependencyRegistry.load().entry("rm"), platforms=(sys.platform,))
    calls = []

    class Process:
        def __init__(self, command, **kwargs):
            calls.append((command, kwargs))
            self.stdout = io.BytesIO(b"Usage: rm [OPTION]... [FILE]...\n")
            self.returncode = 1 if sys.platform == "darwin" else 0

        def wait(self, timeout=None):
            assert 0 < timeout <= 5.0
            return self.returncode

        def kill(self):
            self.returncode = 1

    which = Mock(return_value=str(Path(sys.executable).with_name("rm")))
    monkeypatch.setattr("netops.dependencies.adapters.shutil.which", which)
    monkeypatch.setattr("netops.dependencies.adapters.subprocess.Popen", Process)
    result = LocalDependencyAdapter({"controller": selected}).probe(
        entry, selected, time.monotonic() + 2.0,
    )
    assert result.status == "available"
    assert result.evidence_digest
    which.assert_called_once_with("rm", path=selected.path)
    assert calls[0][0][1:] == ([] if sys.platform == "darwin" else ["--help"])
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["env"]["PATH"] == selected.path


def test_registered_rm_missing_is_actionable_without_dispatch(monkeypatch):
    selected = context(id="controller", role="controller")
    entry = replace(DependencyRegistry.load().entry("rm"), platforms=(sys.platform,))
    monkeypatch.setattr("netops.dependencies.adapters.shutil.which", Mock(return_value=None))
    process = Mock(side_effect=AssertionError("No rm process may start"))
    monkeypatch.setattr("netops.dependencies.adapters.subprocess.Popen", process)
    result = LocalDependencyAdapter({"controller": selected}).probe(
        entry, selected, time.monotonic() + 2.0,
    )
    assert (result.status, result.reason) == ("missing", "executable-missing")
    process.assert_not_called()


@pytest.mark.parametrize("export", ["git_init", "git_commit"])
def test_selected_git_export_cannot_omit_always_consumed_git(policy, export):
    registry = DependencyRegistry.load()
    assert "git" in registry.operation("netops.collect.backup", export).dependencies
    service, selected, adapter, _ = service_and_context(policy, ("git",))
    report = service.verify(
        c.InstallScope((f"netops.collect.backup:{export}",), (), False, False), selected,
    )
    assert report.readiness.native == "blocked"
    assert "git" in {call[0] for call in adapter.calls}


def test_enhanced_catalog_plans_the_actual_molecule_cli_not_just_imports(policy):
    service, selected, _, _ = service_and_context(policy)
    plan = service.plan(c.InstallScope((), (), True, True), selected)
    assert "molecule-cli" in {step.dependency for step in plan.steps}


def test_generated_help_describes_default_scan_and_exact_reduced_selectors():
    help_text = DependencyRegistry.load().documentation()
    assert "netops.inventory.scan:ping_host" in help_text
    assert "native.scan:skip-ping" in help_text
    assert "native.scan:skip-ping-and-snmp" in help_text


def test_read_only_i01_boundary_never_consumes_or_reconstructs_lifecycle_authority(policy):
    service, selected, adapter, events = service_and_context(policy)
    denied = Mock(side_effect=AssertionError("Read-only I01 cannot use lifecycle authority"))
    service.state = denied
    service.authorization = denied
    service.catalog()
    scope = c.InstallScope(("native.transport",), (), False, False)
    service.plan(scope, selected)
    service.verify(scope, selected)
    denied.assert_not_called()
    assert denied.mock_calls == []
    assert adapter.calls
    assert events.emit.call_count == len(adapter.calls)


def test_full_catalog_plan_has_no_unrepresented_required_dependency(policy):
    service, selected, _, _ = service_and_context(policy)
    plan = service.plan(c.InstallScope((), (), True, True), selected)
    assert {step.dependency for step in plan.steps} == {entry.id for entry in service.registry.entries}
    assert all(step.ownership and step.recovery and step.source for step in plan.steps)
    assert plan.free_space is None
    assert all(step.size is None and step.digest is None for step in plan.steps)


@pytest.mark.parametrize(("payload", "returncode"), [
    (b"not an rm help receipt", 0), (b"Usage: rm [FILE]...\n", 7),
])
def test_rm_never_treats_unknown_output_or_wrong_exit_as_availability(monkeypatch, payload, returncode):
    selected = context(id="controller", role="controller")
    entry = replace(DependencyRegistry.load().entry("rm"), platforms=(sys.platform,))

    class Process:
        def __init__(self, command, **kwargs):
            self.stdout = io.BytesIO(payload)
            self.returncode = returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = 1

    monkeypatch.setattr("netops.dependencies.adapters.shutil.which", Mock(return_value="owned-rm"))
    monkeypatch.setattr("netops.dependencies.adapters.subprocess.Popen", Process)
    result = LocalDependencyAdapter({"controller": selected}).probe(
        entry, selected, time.monotonic() + 2.0,
    )
    assert (result.status, result.reason) == ("blocked", "functional-probe-failed")


@pytest.mark.parametrize("damage", ["base-to-dev", "snmp-extra-removed"])
def test_required_pip_declarations_stay_in_their_actual_consuming_extra(damage):
    project = Path("pyproject.toml").read_text(encoding="utf-8")
    if damage == "base-to-dev":
        candidate = project.replace('    "pyyaml>=6.0",\n', "", 1).replace(
            "dev = [\n", 'dev = [\n    "pyyaml>=6.0",\n', 1,
        )
    else:
        candidate = project.replace('snmp = [\n    "pysnmp>=7.0",\n]', "snmp = []", 1)
    assert candidate != project
    with pytest.raises(RegistryError, match="package-metadata-drift"):
        DependencyRegistry.load().validate_package_metadata(candidate)


def test_a_whole_removed_public_module_cannot_hide_behind_export_iteration(monkeypatch):
    registry = DependencyRegistry.load()
    original = Path.rglob

    def without_mailer(self, pattern):
        return (path for path in original(self, pattern) if path.name != "mailer.py")

    monkeypatch.setattr(Path, "rglob", without_mailer)
    with pytest.raises(RegistryError, match="public-manifest-drift"):
        registry.validate_public_sources(Path("netops"))
