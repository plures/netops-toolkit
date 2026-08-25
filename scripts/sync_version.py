"""Synchronize and verify netops-toolkit release version metadata.

The release workflow is the only routine writer for these values. This tool
also provides a fast CI check so a divergent runtime version cannot reach a
tag or release archive.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SEMVER_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
PYPROJECT_RE = re.compile(r'(?m)^(version\s*=\s*")([^"]+)(")$')
RUNTIME_RE = re.compile(r'(?m)^(__version__\s*=\s*")([^"]+)(")$')
VERSION_FILES = (
    (Path("pyproject.toml"), PYPROJECT_RE),
    (Path("netops") / "__init__.py", RUNTIME_RE),
)


def _read_version(path: Path, pattern: re.Pattern[str]) -> str:
    """Extract exactly one version from *path*."""
    matches = list(pattern.finditer(path.read_text(encoding="utf-8")))
    if len(matches) != 1:
        raise ValueError(f"expected one version declaration in {path}, found {len(matches)}")
    return matches[0].group(2)


def read_versions(root: Path) -> dict[Path, str]:
    """Return the version recorded by each tracked source."""
    return {relative: _read_version(root / relative, pattern) for relative, pattern in VERSION_FILES}


def check_versions(root: Path) -> int:
    """Return zero only when the package and runtime versions agree."""
    versions = read_versions(root)
    invalid = [(path, actual) for path, actual in versions.items() if not SEMVER_RE.fullmatch(actual)]
    if invalid:
        details = ", ".join(f"{path.as_posix()}: {actual}" for path, actual in invalid)
        raise ValueError(f"invalid semantic version metadata: {details}")
    expected = versions[Path("pyproject.toml")]
    mismatches = [(path, actual) for path, actual in versions.items() if actual != expected]
    if mismatches:
        print(f"Version metadata mismatch: expected {expected}", file=sys.stderr)
        for path, actual in mismatches:
            print(f"  {path.as_posix()}: {actual}", file=sys.stderr)
        return 1
    print(f"Version metadata is synchronized: {expected}")
    return 0


def sync_versions(root: Path, version: str) -> None:
    """Set all tracked version declarations to a validated semantic version."""
    if not SEMVER_RE.fullmatch(version):
        raise ValueError(f"version must be MAJOR.MINOR.PATCH, got: {version}")

    updates: list[tuple[Path, str]] = []
    for relative, pattern in VERSION_FILES:
        path = root / relative
        updated, replacements = pattern.subn(rf"\g<1>{version}\g<3>", path.read_text(encoding="utf-8"))
        if replacements != 1:
            raise ValueError(f"expected one version declaration in {path}, found {replacements}")
        updates.append((path, updated))

    for path, updated in updates:
        path.write_text(updated, encoding="utf-8")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synchronize netops-toolkit release metadata")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (default: repository containing this script)",
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="fail when tracked versions differ")
    action.add_argument("--current", action="store_true", help="print the package version")
    action.add_argument("--version", metavar="MAJOR.MINOR.PATCH", help="synchronize tracked versions")
    return parser.parse_args()


def main() -> int:
    """Run the version synchronization command."""
    args = _parse_args()
    root = args.root.resolve()
    try:
        if args.check:
            return check_versions(root)
        if args.current:
            print(read_versions(root)[Path("pyproject.toml")])
            return 0
        sync_versions(root, args.version)
        return check_versions(root)
    except (OSError, ValueError) as exc:
        print(f"Version metadata error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
