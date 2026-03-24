"""Integration tests for Ansible role file-system structure.

These tests verify that each Galaxy-compatible role (netops_backup,
netops_health, netops_update, netops_acl, netops_ntp) is present with all
required files and contains well-formed YAML.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ROLES_ROOT = (
    Path(__file__).parent.parent / "netops" / "ansible" / "roles"
)

ROLE_NAMES = [
    "netops_backup",
    "netops_health",
    "netops_update",
    "netops_acl",
    "netops_ntp",
]

# Required files for every role.
REQUIRED_FILES = [
    "defaults/main.yml",
    "tasks/main.yml",
    "handlers/main.yml",
    "meta/main.yml",
    "README.md",
    "molecule/default/molecule.yml",
    "molecule/default/converge.yml",
    "molecule/default/verify.yml",
]


def _load_yaml(path: Path) -> object:
    """Load a YAML file and return the parsed object."""
    return yaml.safe_load(path.read_text())


# ---------------------------------------------------------------------------
# Parametrised structure tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ROLE_NAMES)
def test_role_directory_exists(role: str) -> None:
    assert (ROLES_ROOT / role).is_dir(), f"Role directory missing: {role}"


@pytest.mark.parametrize("role", ROLE_NAMES)
@pytest.mark.parametrize("rel_path", REQUIRED_FILES)
def test_role_required_file_exists(role: str, rel_path: str) -> None:
    path = ROLES_ROOT / role / rel_path
    assert path.exists(), f"Missing required file: {role}/{rel_path}"


@pytest.mark.parametrize("role", ROLE_NAMES)
@pytest.mark.parametrize(
    "rel_path",
    [f for f in REQUIRED_FILES if f.endswith(".yml")],
)
def test_role_yaml_is_valid(role: str, rel_path: str) -> None:
    path = ROLES_ROOT / role / rel_path
    try:
        data = _load_yaml(path)
    except yaml.YAMLError as exc:
        pytest.fail(f"YAML parse error in {role}/{rel_path}: {exc}")
    # A YAML file should not be completely empty, except handlers files
    # for roles that have no handlers (comment-only files parse to None).
    if rel_path != "handlers/main.yml":
        assert data is not None, f"{role}/{rel_path} is empty"


# ---------------------------------------------------------------------------
# Galaxy metadata tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ROLE_NAMES)
def test_galaxy_meta_has_required_keys(role: str) -> None:
    meta = _load_yaml(ROLES_ROOT / role / "meta/main.yml")
    assert isinstance(meta, dict), f"{role}/meta/main.yml must be a mapping"
    assert "galaxy_info" in meta, f"{role}/meta/main.yml missing 'galaxy_info'"
    gi = meta["galaxy_info"]
    for key in ("role_name", "author", "description", "license", "min_ansible_version"):
        assert key in gi, f"{role}/meta/main.yml galaxy_info missing '{key}'"


@pytest.mark.parametrize("role", ROLE_NAMES)
def test_galaxy_meta_role_name_matches(role: str) -> None:
    meta = _load_yaml(ROLES_ROOT / role / "meta/main.yml")
    assert meta["galaxy_info"]["role_name"] == role, (
        f"{role}/meta/main.yml role_name does not match directory name"
    )


@pytest.mark.parametrize("role", ROLE_NAMES)
def test_galaxy_meta_license_is_mit(role: str) -> None:
    meta = _load_yaml(ROLES_ROOT / role / "meta/main.yml")
    assert meta["galaxy_info"]["license"] == "MIT", (
        f"{role}/meta/main.yml license should be MIT"
    )


# ---------------------------------------------------------------------------
# Defaults variable tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ROLE_NAMES)
def test_defaults_is_mapping(role: str) -> None:
    defaults = _load_yaml(ROLES_ROOT / role / "defaults/main.yml")
    assert isinstance(defaults, dict), f"{role}/defaults/main.yml must be a YAML mapping"


def test_backup_defaults_has_retention() -> None:
    defaults = _load_yaml(ROLES_ROOT / "netops_backup" / "defaults/main.yml")
    assert "netops_backup_retention" in defaults
    assert int(defaults["netops_backup_retention"]) > 0


def test_health_defaults_thresholds_sane() -> None:
    defaults = _load_yaml(ROLES_ROOT / "netops_health" / "defaults/main.yml")
    assert int(defaults["netops_health_cpu_critical"]) <= 100
    assert int(defaults["netops_health_memory_critical"]) <= 100


def test_update_defaults_dry_run_is_true() -> None:
    defaults = _load_yaml(ROLES_ROOT / "netops_update" / "defaults/main.yml")
    assert defaults["netops_update_dry_run"] is True, (
        "netops_update dry_run should default to True for safety"
    )


def test_acl_defaults_list_is_empty() -> None:
    defaults = _load_yaml(ROLES_ROOT / "netops_acl" / "defaults/main.yml")
    assert defaults["netops_acl_list"] == [], (
        "netops_acl_list default should be empty list"
    )


def test_ntp_defaults_servers_is_empty() -> None:
    defaults = _load_yaml(ROLES_ROOT / "netops_ntp" / "defaults/main.yml")
    assert defaults["netops_ntp_servers"] == [], (
        "netops_ntp_servers default should be empty list"
    )


def test_ntp_defaults_validate_sync_is_true() -> None:
    defaults = _load_yaml(ROLES_ROOT / "netops_ntp" / "defaults/main.yml")
    assert defaults["netops_ntp_validate_sync"] is True, (
        "netops_ntp validate_sync should default to True"
    )


# ---------------------------------------------------------------------------
# README sanity tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ROLE_NAMES)
def test_readme_contains_example_playbook(role: str) -> None:
    readme = (ROLES_ROOT / role / "README.md").read_text()
    assert "roles:" in readme, f"{role}/README.md missing 'roles:' usage example"


@pytest.mark.parametrize("role", ROLE_NAMES)
def test_readme_contains_molecule_section(role: str) -> None:
    readme = (ROLES_ROOT / role / "README.md").read_text()
    assert "molecule" in readme.lower(), f"{role}/README.md missing Molecule section"


# ---------------------------------------------------------------------------
# Molecule configuration tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ROLE_NAMES)
def test_molecule_yml_has_driver(role: str) -> None:
    mol = _load_yaml(ROLES_ROOT / role / "molecule/default/molecule.yml")
    assert "driver" in mol, f"{role}/molecule/default/molecule.yml missing 'driver'"


@pytest.mark.parametrize("role", ROLE_NAMES)
def test_molecule_yml_has_platforms(role: str) -> None:
    mol = _load_yaml(ROLES_ROOT / role / "molecule/default/molecule.yml")
    assert "platforms" in mol, f"{role}/molecule/default/molecule.yml missing 'platforms'"
    assert len(mol["platforms"]) > 0, f"{role}: platforms list must not be empty"
