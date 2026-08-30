"""Regression checks for the local and published documentation delivery contract."""

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_installers_build_a_local_documentation_site() -> None:
    """Both supported installers retain the offline-documentation build step."""
    linux_installer = (REPOSITORY_ROOT / "install.sh").read_text(encoding="utf-8")
    windows_installer = (REPOSITORY_ROOT / "install.ps1").read_text(encoding="utf-8")

    assert "NETOPS_DOCS_DIR" in linux_installer
    assert "[tui,snmp,report,docs]" in linux_installer
    assert "-m mkdocs build --strict" in linux_installer
    assert "[tui,snmp,report,docs]" in windows_installer
    assert "-m mkdocs build --strict" in windows_installer


def test_release_owns_github_pages_and_bundles_build_configuration() -> None:
    """Published documentation and release archives are derived from one release run."""
    release_workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    docs_workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "docs.yml").read_text(
        encoding="utf-8"
    )

    assert 'cp mkdocs.yml     "/tmp/${NAME}/"' in release_workflow
    assert 'grep -F "${NAME}/mkdocs.yml"' in release_workflow
    assert "Deploy release documentation to GitHub Pages" in release_workflow
    assert "python -m mkdocs gh-deploy --force" in release_workflow
    assert "mkdocs gh-deploy" not in docs_workflow
