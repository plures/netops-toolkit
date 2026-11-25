"""Regression coverage for I01's pip versus Galaxy packaging boundary."""

from pathlib import Path

import pytest

from netops.dependencies import DependencyRegistry, RegistryError


def test_current_package_metadata_matches_dependency_registry():
    project = Path("pyproject.toml").read_text(encoding="utf-8")
    DependencyRegistry.load().validate_package_metadata(project)


def test_galaxy_collection_reintroduced_into_pip_extra_is_rejected():
    project = Path("pyproject.toml").read_text(encoding="utf-8")
    contaminated = project.replace(
        'ansible = [\n', 'ansible = [\n    "ansible.netcommon>=6.0",\n', 1,
    )
    with pytest.raises(RegistryError, match="package-metadata-drift"):
        DependencyRegistry.load().validate_package_metadata(contaminated)
