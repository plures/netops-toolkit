"""Registry and pure planning tests; no platform qualification is inferred."""

import copy
import json
from pathlib import Path

import pytest

from netops.dependencies import DependencyRegistry, RegistryError


def test_packaged_catalog_is_complete_and_topologically_ordered():
    registry = DependencyRegistry.load()
    registry.validate_public_sources(Path("netops"))
    ordered = registry.ordered()
    positions = {entry.id: index for index, entry in enumerate(ordered)}
    assert len(ordered) >= 30
    for entry in ordered:
        assert all(positions[edge] < positions[entry.id] for edge in entry.requires)
    assert registry.qualification["qualified"] == []
    assert registry.operation("netops.report.mailer", "ReportMailer").dependencies == ()
    assert registry.operation("netops.report.scheduler", "ReportScheduler").dependencies == ("jinja2",)


@pytest.mark.parametrize("damage", ["cycle", "adapter", "collection-pip", "consumer", "duplicate"])
def test_corrupt_registry_fails_closed(damage):
    root = Path("netops") / "dependencies"
    data = json.loads((root / "registry.json").read_text())
    operations = json.loads((root / "operations.json").read_text())
    qualification = json.loads((root / "qualification.json").read_text())
    if damage == "cycle":
        data["entries"][0]["requires"] = [data["entries"][0]["id"]]
    elif damage == "adapter":
        data["entries"][0]["adapter"] = "run-arbitrary-command"
    elif damage == "collection-pip":
        next(x for x in data["entries"] if x["id"] == "ansible.netcommon")["kind"] = "pip"
    elif damage == "consumer":
        data["entries"][0]["consumers"] = []
    else:
        data["entries"].append(copy.deepcopy(data["entries"][0]))
    with pytest.raises(RegistryError):
        DependencyRegistry.from_data(data, operations, qualification)


def test_unregistered_public_function_is_rejected():
    registry = DependencyRegistry.load()
    with pytest.raises(RegistryError, match="public-manifest-drift"):
        registry.validate_exports({"netops.report.mailer": ("ReportMailer", "new_public_function")})


def test_qualification_cannot_be_fabricated_by_adding_version_ranges():
    registry = DependencyRegistry.load()
    assert not registry.is_qualified({"os": "Linux", "core": ">=2.16"})


def test_generated_help_and_documentation_do_not_drift():
    registry = DependencyRegistry.load()
    documentation = Path("docs") / "api" / "dependencies.md"
    snapshot = documentation.read_text(encoding="utf-8").split(
        "<!-- dependency-catalog:start -->", 1,
    )[1].split("<!-- dependency-catalog:end -->", 1)[0].strip()
    assert snapshot == registry.documentation()


def test_missing_public_ui_action_is_rejected():
    root = Path("netops") / "dependencies"
    data = json.loads((root / "registry.json").read_text())
    operations = json.loads((root / "operations.json").read_text())
    qualification = json.loads((root / "qualification.json").read_text())
    next(x for x in operations["operations"] if x.get("ui_actions"))["ui_actions"].pop()
    registry = DependencyRegistry.from_data(data, operations, qualification)
    with pytest.raises(RegistryError, match="public-ui-action-drift"):
        registry.validate_public_sources(Path("netops"))


@pytest.mark.parametrize("damage", ["omitted", "retargeted", "cycle", "unknown"])
def test_canonical_public_alias_metadata_drift_is_rejected(damage):
    root = Path("netops") / "dependencies"
    data = json.loads((root / "registry.json").read_text())
    operations = json.loads((root / "operations.json").read_text())
    qualification = json.loads((root / "qualification.json").read_text())
    report = next(x for x in operations["operations"] if x["module"] == "netops.report.__init__")
    aliases = report.setdefault("aliases", {})
    if damage == "omitted":
        aliases.pop("aggregate_dashboard", None)
    elif damage == "retargeted":
        aliases["aggregate_dashboard"] = "netops.report.health_dashboard:render_html"
    elif damage == "cycle":
        aliases["aggregate_dashboard"] = "netops.report.__init__:aggregate_dashboard"
    else:
        aliases["aggregate_dashboard"] = "netops.report.health_dashboard:unknown_export"
    with pytest.raises(RegistryError, match="public-alias"):
        registry = DependencyRegistry.from_data(data, operations, qualification)
        registry.validate_public_sources(Path("netops"))


def test_alias_dependency_consumers_are_validated_at_the_canonical_capability():
    root = Path("netops") / "dependencies"
    data = json.loads((root / "registry.json").read_text())
    operations = json.loads((root / "operations.json").read_text())
    qualification = json.loads((root / "qualification.json").read_text())
    templates = next(x for x in operations["operations"]
                     if x["module"] == "netops.playbooks.templates.__init__")
    # A future cross-capability alias must not invent a stdlib crypto consumer.
    templates["aliases"]["get_template"] = "netops.core.vault:CredentialVault"
    registry = DependencyRegistry.from_data(data, operations, qualification)
    alias = registry.operation(templates["module"], "get_template")
    assert alias.capability == "native.core"
    assert set(alias.dependencies) == {"cryptography", "pyyaml"}
    with pytest.raises(RegistryError, match="public-alias-drift"):
        registry.validate_public_sources(Path("netops"))


def test_dependency_metadata_drift_and_collection_as_pip_are_detected():
    registry = DependencyRegistry.load()
    project = Path("pyproject.toml").read_text(encoding="utf-8")
    registry.validate_package_metadata(project)
    with pytest.raises(RegistryError, match="package-metadata-drift"):
        registry.validate_package_metadata(project.replace("netmiko>=4.3.0,<4.5.0", "netmiko>=9.0"))
    contaminated = project.replace(
        'ansible = [\n', 'ansible = [\n    "ansible.netcommon>=6.0",\n', 1,
    )
    assert contaminated != project
    with pytest.raises(RegistryError, match="package-metadata-drift"):
        registry.validate_package_metadata(contaminated)
