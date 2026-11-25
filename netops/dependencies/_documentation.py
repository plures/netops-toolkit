"""Owned offline strict documentation delivery from an exactly reviewed source.

The standalone source installer retains documentation delivery while the full
managed-generation bridge is being qualified. It does not install dependencies,
modify an existing output, repair ACLs or certify publisher/platform readiness.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import site
import stat
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

from netops.ansible import contracts as c

from ._context_facts import _ContextUnavailable, _evaluate_marker, _marker_environment
from ._installation_process import _DocumentationChildFailure, _run
from .service import DependencyRegistry

__all__: tuple[str, ...] = ()
_LIMIT = 128 * 1024 * 1024


class _DocsBlocked(c.ContractError):
    def __init__(self, reason: str, fields: tuple[str, ...] = ()) -> None:
        super().__init__()
        self.reason, self.fields = reason, fields


@dataclass(frozen=True)
class _SourceFile:
    path: str
    digest: str
    size: int


@dataclass(frozen=True)
class _DocumentationPlan:
    source: str
    output: str
    python: str
    python_digest: str
    registry_digest: str
    selected_dependencies: tuple[str, ...]
    distributions: tuple[tuple[str, str], ...]
    source_files: tuple[_SourceFile, ...]
    user_base: str

    @property
    def digest(self) -> str:
        return c.digest(self)

    @property
    def command(self) -> tuple[str, ...]:
        """Return the sole fixed build argv; no arbitrary script/plugin callback."""
        source = Path(self.output) / "reviewed-source"
        return (
            self.python, "-B", "-m", "mkdocs", "build", "--strict",
            "--config-file", str(source / "mkdocs.yml"),
            "--site-dir", str(Path(self.output) / "site"),
        )


def _safe_file(path: Path, limit: int) -> bytes:
    for parent in (path, *path.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise _DocsBlocked("documentation-source-substituted")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise _DocsBlocked("documentation-source-invalid")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        value = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    final = path.lstat()
    def identity(item: os.stat_result) -> tuple[int, int, int, int]:
        return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns
    if (
        identity(before) != identity(opened) or identity(opened) != identity(after)
        or identity(after) != identity(final) or len(value) != before.st_size
        # Windows Python can expose creation time from lstat and change time
        # from fstat as st_ctime. Compare each observation through its own API.
        or before.st_ctime_ns != final.st_ctime_ns or opened.st_ctime_ns != after.st_ctime_ns
    ):
        raise _DocsBlocked("documentation-source-changed")
    return value


def _installed_dependencies(registry: DependencyRegistry) -> tuple[
    tuple[str, ...], tuple[tuple[str, str], ...],
]:
    """Select the real registry docs intent and validate its complete installed closure."""
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet
    from packaging.utils import canonicalize_name
    from packaging.version import Version

    operation = registry.operation("netops.setup", "main")
    selected = dict(operation.intents).get("docs")
    if not selected:
        raise _DocsBlocked("documentation-registry-selection-missing")
    entries = registry.ordered(selected)
    environment = _marker_environment()
    expected = {str(canonicalize_name(entry.source[5:])): entry.version
                for entry in entries if entry.source.startswith("pypi:")}
    pending = list(expected)
    versions: dict[str, str] = {}
    while pending:
        name = pending.pop()
        if name in versions:
            continue
        if len(versions) >= 256:
            raise _DocsBlocked("documentation-closure-limit")
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            raise _DocsBlocked("documentation-dependency-missing", (name,)) from None
        version = distribution.version
        if name in expected and Version(version) not in SpecifierSet(expected[name]):
            raise _DocsBlocked("documentation-version-incompatible", (name,))
        versions[name] = version
        for raw in distribution.requires or ():
            requirement = Requirement(raw)
            if requirement.url is not None:
                raise _DocsBlocked("documentation-unqualified-direct-source", (name,))
            extras = ("", "python") if name == "mkdocstrings" else ("",)
            if requirement.marker is not None:
                try:
                    active = any(_evaluate_marker(requirement.marker, environment, extra)
                                 for extra in extras)
                except _ContextUnavailable:
                    raise _DocsBlocked("documentation-marker-facts-unavailable", (name,)) from None
                if not active:
                    continue
            dependency = str(canonicalize_name(requirement.name))
            try:
                observed = importlib.metadata.version(dependency)
            except importlib.metadata.PackageNotFoundError:
                raise _DocsBlocked("documentation-dependency-missing", (dependency,)) from None
            if Version(observed) not in requirement.specifier:
                raise _DocsBlocked("documentation-version-incompatible", (dependency,))
            pending.append(dependency)
    return tuple(entry.id for entry in entries), tuple(sorted(versions.items()))


def _plan(source: Path, output: Path) -> _DocumentationPlan:
    source, output = source.absolute(), output.absolute()
    if (
        ".." in source.parts or ".." in output.parts or source == output
        or output in source.parents or output.exists()
        or any(source / name == output or source / name in output.parents
               for name in ("docs", "netops", "documentation"))
    ):
        raise _DocsBlocked("documentation-new-owned-output-required")
    registry = DependencyRegistry.load()
    selected, versions = _installed_dependencies(registry)
    paths = [source / "mkdocs.yml", source / "pyproject.toml"]
    for directory in ("docs", "netops", "documentation"):
        paths.extend(path for path in (source / directory).rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts
                     and path.suffix not in (".pyc", ".pyo"))
    if not (source / "docs" / "index.md").is_file() or len(paths) > 8192:
        raise _DocsBlocked("documentation-reviewed-source-required")
    files = []
    total = 0
    for path in sorted(set(paths)):
        content = _safe_file(path, _LIMIT)
        total += len(content)
        if total > _LIMIT:
            raise _DocsBlocked("documentation-source-limit")
        files.append(_SourceFile(str(path.relative_to(source)),
                                 hashlib.sha256(content).hexdigest(), len(content)))
    from ._guided import _existing_python

    python = Path(_existing_python())
    return _DocumentationPlan(
        str(source), str(output), str(python),
        hashlib.sha256(_safe_file(python, _LIMIT)).hexdigest(),
        registry.digest, selected, versions, tuple(files), site.getuserbase(),
    )


class _DocsConsent:
    """One process/thread-local exact build review; never persisted or hydrated."""

    def __init__(self, plan: _DocumentationPlan) -> None:
        self._digest = plan.digest
        self._pid, self._thread = os.getpid(), threading.get_ident()
        self._deadline, self._used = time.monotonic() + 300.0, False
        self._mutex = threading.Lock()

    def __repr__(self) -> str:
        return "<private documentation review>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("Documentation consent cannot be serialized.")

    def consume(self, plan: _DocumentationPlan) -> float:
        with self._mutex:
            if (
                self._used or self._digest != plan.digest or self._pid != os.getpid()
                or self._thread != threading.get_ident() or time.monotonic() >= self._deadline
            ):
                raise _DocsBlocked("documentation-consent-stale")
            self._used = True
            return self._deadline


class _Clock:
    def monotonic(self) -> float:
        return time.monotonic()

    def utc_now(self) -> datetime:
        return datetime.now(timezone.utc)


class _Cancel:
    def __init__(self) -> None:
        self._event = threading.Event()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout)


def _directory(path: Path) -> None:
    if os.name == "nt":
        from netops.ansible.artifact_platform import windows

        windows().create_private_directory(str(path), inherit=True)
    else:
        path.mkdir(mode=0o700)


def _build(plan: _DocumentationPlan, consent: _DocsConsent) -> c.FrozenObject:
    if type(plan) is not _DocumentationPlan or type(consent) is not _DocsConsent:
        raise _DocsBlocked("documentation-consent-required")
    # All observations, source bytes and selected versions must still agree
    # before output creation. Reading a saved receipt never supplies this grant.
    if _plan(Path(plan.source), Path(plan.output)) != plan:
        raise _DocsBlocked("documentation-plan-drift")
    deadline = consent.consume(plan)
    root = Path(plan.output)
    _directory(root)
    source = root / "reviewed-source"
    _directory(source)
    for item in plan.source_files:
        if time.monotonic() >= deadline:
            raise TimeoutError()
        content = _safe_file(Path(plan.source) / item.path, item.size)
        if hashlib.sha256(content).hexdigest() != item.digest:
            raise _DocsBlocked("documentation-source-changed")
        target = source / item.path
        for parent in reversed(target.parents):
            if parent != source and source in parent.parents and not parent.exists():
                _directory(parent)
        with target.open("xb") as stream:
            stream.write(content)
    try:
        _run(plan.command, source, _Clock(), _Cancel(), deadline, _documentation=plan)
    except _DocumentationChildFailure as error:
        for name, content in (("mkdocs-stdout.log", error.stdout), ("mkdocs-stderr.log", error.stderr)):
            with (root / name).open("xb") as stream:
                stream.write(content)
        raise _DocsBlocked("documentation-strict-build-failed",
                           ("exit-code-" + str(error.exit_code), "preserve-owned-partial-output")) from None
    except (OSError, TimeoutError, InterruptedError):
        # Strict failure and partial task-owned output remain available; do not
        # relax links, clean unknown output, retry with a fresh budget or call it installed.
        raise _DocsBlocked("documentation-strict-build-failed",
                           ("preserve-owned-partial-output", "correct-source-and-review-new-output")) from None
    observed: list[tuple[str, str, int]] = []
    total = 0
    for path in sorted((root / "site").rglob("*")):
        if time.monotonic() >= deadline:
            raise TimeoutError()
        if not path.is_file():
            continue
        if os.name == "nt":
            from ._installation_files import _private_windows

            _private_windows(path, directory=False)
        content = _safe_file(path, _LIMIT)
        total += len(content)
        if total > _LIMIT or len(observed) >= 8192:
            raise _DocsBlocked("documentation-output-limit")
        observed.append((str(path.relative_to(root)), hashlib.sha256(content).hexdigest(), len(content)))
    if not observed or not (root / "site" / "index.html").is_file():
        raise _DocsBlocked("documentation-output-incomplete")
    # Source drift during plugin execution prevents a successful receipt.
    for item in plan.source_files:
        for base in (Path(plan.source), source):
            if hashlib.sha256(_safe_file(base / item.path, item.size)).hexdigest() != item.digest:
                raise _DocsBlocked("documentation-source-changed")
    receipt = c.public_object({
        "schema": "netops-owned-documentation-v1", "plan_digest": plan.digest,
        "source_seal": c.digest(plan.source_files), "registry_digest": plan.registry_digest,
        "selected_dependencies": plan.selected_dependencies, "distributions": plan.distributions,
        "python_digest": plan.python_digest, "strict_exit_code": 0, "outputs": tuple(observed),
        "publisher_qualification": "unqualified", "managed_generation_qualification": "unqualified",
    })
    if time.monotonic() >= deadline:
        raise TimeoutError()
    with (root / "documentation-receipt.json").open("xb") as stream:
        stream.write(c.canonical_bytes(receipt))
    return receipt


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review an owned offline strict documentation build.")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args(argv)
    try:
        plan = _plan(args.source, args.output)
        print(c.canonical_bytes(c.public_object({
            "status": "NeedsInput", "plan_digest": plan.digest, "source": plan.source,
            "output": plan.output, "selected_dependencies": plan.selected_dependencies,
            "command": plan.command, "effects_performed": (),
            "choices": ("review-exact-source-and-new-owned-output", "cancel"),
        })).decode("utf-8"))
        if args.plan:
            return 3
        if input("Type 'build-docs " + plan.digest + "' to consent: ").strip() != "build-docs " + plan.digest:
            return 3
        _build(plan, _DocsConsent(plan))
        return 0
    except _DocsBlocked as error:
        print(json.dumps({"status": "NeedsInput", "reason": error.reason, "fields": error.fields}))
        return 3
    except (c.ContractError, OSError, ValueError, ImportError):
        print(json.dumps({"status": "NeedsInput", "reason": "documentation-prerequisite-invalid"}))
        return 3
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(_main())
