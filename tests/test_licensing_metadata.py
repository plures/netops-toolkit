"""Regression checks for the single, source-available licensing declaration."""

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_public_license_surfaces_consistently_declare_busl() -> None:
    """Distribution metadata, license text, and README cannot drift into dual licensing."""
    license_text = (REPOSITORY_ROOT / "LICENSE").read_text(encoding="utf-8")
    package_metadata = (REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")

    assert "Business Source License 1.1" in license_text
    assert "Dual License Notice" not in license_text
    assert 'license = "BUSL-1.1"' in package_metadata
    assert 'license-files = ["LICENSE"]' in package_metadata
    assert "LICENSE-MIT" not in readme
    assert "BUSL-1.1" in readme

    for role in ("netops_acl", "netops_backup", "netops_health", "netops_ntp", "netops_update"):
        role_meta = REPOSITORY_ROOT / "netops" / "ansible" / "roles" / role / "meta" / "main.yml"
        role_readme = REPOSITORY_ROOT / "netops" / "ansible" / "roles" / role / "README.md"

        assert 'license: BUSL-1.1' in role_meta.read_text(encoding="utf-8")
        assert "BUSL-1.1" in role_readme.read_text(encoding="utf-8")
