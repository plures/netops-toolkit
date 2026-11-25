"""Closed publisher metadata observations; artifact acquisition is never performed.

The retained catalogue supplies independently pinned member inventories. Official
metadata must confirm the exact artifact and complete dependency projection before
the catalogue can become a planning observation. TLS or a caller URL alone does
not turn arbitrary bytes into a trusted catalogue.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from urllib.parse import quote

from netops.ansible import contracts as c

from ._assets import AssetTransport, HttpsAssetTransport, _origin
from ._context_facts import _evaluate_marker, _target_environment
from ._family_lock import (
    _CatalogueUnavailable,
    _check,
    _ParserUnavailable,
    _PublisherSnapshot,
    _RegisteredSource,
    _Release,
    _Requirement,
    _SourceUnavailable,
    _Target,
    _trace,
)

__all__: tuple[str, ...] = ()
_LIMIT = 1024 * 1024


def _parser_preflight() -> None:
    """Require the actual optional parsers before crossing a publisher boundary."""
    try:
        __import__("packaging.requirements")
        __import__("packaging.utils")
        __import__("packaging.specifiers")
        __import__("packaging.version")
    except ImportError:
        raise _ParserUnavailable() from None


def _object(value: object) -> dict:
    if type(value) is not dict:
        raise c.ContractError()
    return value


def _pairs(values: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in values:
        if key in result:
            raise c.ContractError()
        result[key] = value
    return result


def _canonical_name(value: str) -> str:
    from packaging.utils import canonicalize_name

    return str(canonicalize_name(value))


def _edges(values: object, target: _Target, extras: tuple[str, ...]) -> tuple[
    tuple[_Requirement, ...], tuple[tuple[str, tuple[_Requirement, ...]], ...],
]:
    from packaging.requirements import InvalidRequirement, Requirement

    if type(values) is not list or len(values) > 256:
        raise c.ContractError()
    environment = _target_environment(target.platform, target.architecture, target.python)
    base: list[_Requirement] = []
    selected: dict[str, list[_Requirement]] = {extra: [] for extra in extras}
    for text in values:
        if type(text) is not str or len(text) > 4096:
            raise c.ContractError()
        try:
            parsed = Requirement(text)
        except InvalidRequirement:
            raise c.ContractError() from None
        if parsed.url is not None:
            raise c.ContractError()
        name = _canonical_name(parsed.name)
        edge = _Requirement(
            name, "wheel", "pypi:" + name, target.context, str(parsed.specifier),
            tuple(sorted(parsed.extras)),
        )
        if parsed.marker is None or _evaluate_marker(parsed.marker, environment):
            base.append(edge)
        else:
            for extra in extras:
                if _evaluate_marker(parsed.marker, environment, extra):
                    selected[extra].append(edge)
    return tuple(base), tuple((extra, tuple(edges)) for extra, edges in selected.items())


def _pypi(release: _Release, document: dict, target: _Target) -> None:
    from packaging.specifiers import SpecifierSet
    from packaging.utils import parse_wheel_filename
    from packaging.version import Version

    info = _object(document.get("info"))
    artifact = release.artifact
    files = document.get("urls")
    if artifact is None or type(files) is not list or len(files) > 1024:
        raise c.ContractError()
    if (
        type(info.get("name")) is not str
        or _canonical_name(info["name"]) != release.requirement.name
        or info.get("version") != release.version
        or str(SpecifierSet(info.get("requires_python") or "")) != str(
            SpecifierSet(release.python)
        )
    ):
        raise c.ContractError()
    matches = [
        _object(item) for item in files
        if _object(item).get("url") == artifact.url
    ]
    if len(matches) != 1:
        raise c.ContractError()
    item = matches[0]
    if (
        item.get("packagetype") != "bdist_wheel" or item.get("yanked") is not False
        or type(item.get("size")) is not int or item["size"] != artifact.size
        or _object(item.get("digests")).get("sha256") != artifact.sha256
        or type(item.get("filename")) is not str
        or artifact.url.rsplit("/", 1)[-1] != quote(item["filename"], safe="-_.")
    ):
        raise c.ContractError()
    name, version, _, tags = parse_wheel_filename(item["filename"])
    if (
        str(name) != release.requirement.name or version != Version(release.version)
        or set(map(str, tags)) != set(release.wheel_tags)
    ):
        raise c.ContractError()
    extras = info.get("provides_extra") or []
    if (
        type(extras) is not list or any(type(extra) is not str for extra in extras)
        or tuple(extras) != tuple(name for name, _ in release.extra_requires)
    ):
        raise c.ContractError()
    base, extra = _edges(info.get("requires_dist") or [], target, tuple(extras))
    if base != release.requires or extra != release.extra_requires:
        raise c.ContractError()


def _galaxy(release: _Release, document: dict) -> None:
    artifact = release.artifact
    metadata = _object(document.get("metadata"))
    archive = _object(document.get("artifact"))
    namespace, name = release.requirement.name.split(".")
    if artifact is None or (
        document.get("version") != release.version
        or _object(document.get("namespace")).get("name") != namespace
        or _object(document.get("collection")).get("name") != name
        or document.get("download_url") != artifact.url
        or archive.get("sha256") != artifact.sha256
        or type(archive.get("size")) is not int or archive["size"] != artifact.size
    ):
        raise c.ContractError()
    dependencies = _object(metadata.get("dependencies"))
    if len(dependencies) > 256:
        raise c.ContractError()
    edges = tuple(
        _Requirement(key, "collection", "galaxy:" + key, release.requirement.context, value)
        for key, value in sorted(dependencies.items())
    )
    core_version = document.get("requires_ansible")
    if type(core_version) is not str:
        raise c.ContractError()
    core = _Requirement(
        "ansible-core", "wheel", "pypi:ansible-core", release.requirement.context,
        core_version,
    )
    if not core.version or set((*edges, core)) != set(release.requires):
        raise c.ContractError()


@dataclass(frozen=True)
class _PublisherMetadata:
    """A real bounded HTTPS implementation with an injectable transport boundary."""

    releases: tuple[_Release, ...]
    transport: AssetTransport
    source: str | None = None

    def __post_init__(self) -> None:
        if type(self.releases) is not tuple or len(self.releases) > 1024:
            raise c.ContractError()
        if not self.releases:
            if type(self.source) is not str or not self.source.startswith(("pypi:", "galaxy:")):
                raise c.ContractError()
            return
        for release in self.releases:
            if type(release) is not _Release:
                raise c.ContractError()
            release.__post_init__()
            if release.requirement.source not in (
                "pypi:" + release.requirement.name, "galaxy:" + release.requirement.name,
            ):
                raise c.ContractError()
        c.unique(tuple(c.digest(release) for release in self.releases))
        if len({release.requirement.source for release in self.releases}) != 1:
            raise c.ContractError()
        if self.source is not None and self.source != self.releases[0].requirement.source:
            raise c.ContractError()

    @property
    def digest(self) -> str:
        return c.digest(self.releases)

    def observe(
        self, requirement: _Requirement, target: _Target,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _PublisherSnapshot:
        """Validate official version records without following artifact URLs."""
        self.__post_init__()
        requirement.__post_init__()
        target.__post_init__()
        started = _check(clock, cancel, deadline)
        deadline = min(deadline, started + 60.0)
        if not self.releases:
            if requirement.source != self.source:
                raise c.ContractError()
            raise _CatalogueUnavailable((
                "official-package-version", "exact-publisher-filename",
                "independently-retained-official-json-sha256", "approved-metadata-read",
            ))
        source = self.releases[0].requirement.source
        if requirement.source != source:
            raise c.ContractError()
        _parser_preflight()
        observed: list[_Release] = []
        for release in self.releases:
            if release.requirement.context != target.context:
                continue
            if source.startswith("pypi:") and release.requirement.family == "wheel":
                url = "https://pypi.org/pypi/" + quote(
                    release.requirement.name, safe="",
                ) + "/" + quote(release.version, safe="") + "/json"
            elif source.startswith("galaxy:") and release.requirement.family == "collection":
                namespace, name = release.requirement.name.split(".")
                url = (
                    "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/"
                    "collections/index/" + quote(namespace, safe="") + "/"
                    + quote(name, safe="") + "/versions/" + quote(release.version, safe="") + "/"
                )
            else:
                raise c.ContractError()
            now = _check(clock, cancel, deadline)
            _trace("publisher-json", requirement.family, "attempt")
            try:
                if type(self.transport) is HttpsAssetTransport:
                    response = self.transport.read_bounded(
                        url, deadline - now, _LIMIT + 1, clock, cancel,
                    )
                else:
                    response = self.transport.read(url, deadline - now, _LIMIT + 1)
                _check(clock, cancel, deadline)
                if (
                    response.url != url or _origin(response.url) != _origin(url)
                    or type(response.content) is not bytes or len(response.content) > _LIMIT
                    or hashlib.sha256(response.content).hexdigest() != release.metadata_digest
                ):
                    raise c.ContractError()
                document = _object(json.loads(response.content, object_pairs_hook=_pairs))
                if source.startswith("pypi:"):
                    _pypi(release, document, target)
                else:
                    _galaxy(release, document)
            except (InterruptedError, TimeoutError):
                _trace("publisher-json", requirement.family, "interrupted")
                raise
            except (c.ContractError, OSError, ValueError, KeyError, TypeError):
                _trace("publisher-json", requirement.family, "failed")
                raise _SourceUnavailable() from None
            except BaseException:
                _trace("publisher-json", requirement.family, "failed")
                raise
            _trace("publisher-json", requirement.family, "returned")
            observed.append(release)
        now = _check(clock, cancel, deadline)
        return _PublisherSnapshot(
            source, c.digest(target), tuple(observed), self.digest, now, min(now + 300.0, deadline),
        )


def _registered_publishers(
    releases: tuple[_Release, ...], transport: AssetTransport | None = None,
) -> tuple[_RegisteredSource, ...]:
    """Bind retained catalogue pins to closed real clients, never caller origins."""
    grouped: dict[str, list[_Release]] = {}
    if type(releases) is not tuple or not 1 <= len(releases) <= 1024:
        raise c.ContractError()
    for release in releases:
        if type(release) is not _Release:
            raise c.ContractError()
        grouped.setdefault(release.requirement.source, []).append(release)
    result = []
    for source, values in grouped.items():
        if source.startswith("pypi:"):
            families, origins = ("wheel",), ("files.pythonhosted.org",)
        elif source.startswith("galaxy:"):
            families, origins = ("collection",), ("galaxy.ansible.com",)
        else:
            raise c.ContractError()
        port = _PublisherMetadata(tuple(values), transport or HttpsAssetTransport())
        result.append(_RegisteredSource(source, families, origins, port.digest, port))
    return tuple(result)
