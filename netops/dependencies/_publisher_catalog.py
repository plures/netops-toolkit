"""Populate release catalogues from independently pinned official JSON records.

Only the raw metadata identity and exact version/file selector are retained.
Artifact SHA256/size, requirements, extras and wheel tags are compiled from the
actual bounded publisher response, never a caller-normalized release.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from urllib.parse import quote

from netops.ansible import contracts as c

from ._assets import HttpsAssetTransport, LockedAsset, _origin
from ._family_lock import (
    _CatalogueUnavailable,
    _check,
    _PublisherSnapshot,
    _RegisteredSource,
    _Release,
    _Requirement,
    _SourceUnavailable,
    _Target,
    _trace,
)
from ._installation import _normalize
from ._managed import ManagedMember, _parts
from ._publisher_metadata import _edges, _galaxy, _object, _pairs, _parser_preflight, _pypi

__all__: tuple[str, ...] = ()
_LIMIT = 1024 * 1024


@dataclass(frozen=True)
class _PublisherSeed:
    """A reviewed exact official metadata pin, not download or execution authority."""

    source: str
    name: str
    version: str
    filename: str
    metadata_digest: str

    def __post_init__(self) -> None:
        _Requirement(self.name, self.family, self.source, "native", "==" + self.version)
        if self.source not in ("pypi:" + self.name, "galaxy:" + self.name):
            raise c.ContractError()
        if self.source.startswith("pypi:") and _normalize(self.name) != self.name:
            raise c.ContractError()
        if len(_parts(self.filename)) != 1 or not self.filename.endswith(
            ".whl" if self.family == "wheel" else ".tar.gz",
        ):
            raise c.ContractError()
        c.sha256(self.metadata_digest)

    @property
    def family(self) -> str:
        if self.source.startswith("pypi:"):
            return "wheel"
        if self.source.startswith("galaxy:") and self.name.count(".") == 1:
            return "collection"
        raise c.ContractError()

    @property
    def url(self) -> str:
        if self.family == "wheel":
            return (
                "https://pypi.org/pypi/" + quote(self.name, safe="")
                + "/" + quote(self.version, safe="") + "/json"
            )
        namespace, name = self.name.split(".")
        return (
            "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/"
            "collections/index/" + quote(namespace, safe="") + "/"
            + quote(name, safe="") + "/versions/" + quote(self.version, safe="") + "/"
        )


def _populate(seed: _PublisherSeed, document: dict, target: _Target) -> _Release:
    """Compile the exact publisher fields, then apply the existing full validator."""
    seed.__post_init__()
    requirement = _Requirement(
        seed.name, seed.family, seed.source, target.context, "==" + seed.version,
    )
    if seed.family == "wheel":
        from packaging.utils import parse_wheel_filename

        info = _object(document.get("info"))
        files = document.get("urls")
        if type(files) is not list or len(files) > 1024:
            raise c.ContractError()
        selected = tuple(_object(item) for item in files
                         if _object(item).get("filename") == seed.filename)
        if len(selected) != 1:
            raise c.ContractError()
        item = selected[0]
        url, size = item.get("url"), item.get("size")
        digest = _object(item.get("digests")).get("sha256")
        if (
            type(url) is not str or type(size) is not int or type(digest) is not str
            or _origin(url) != "files.pythonhosted.org"
        ):
            raise c.ContractError()
        artifact = LockedAsset(seed.source, seed.name, url, digest, size)
        raw_extras = info.get("provides_extra")
        extras = [] if raw_extras is None else raw_extras
        if type(extras) is not list or any(type(extra) is not str for extra in extras):
            raise c.ContractError()
        raw_requirements = info.get("requires_dist")
        base, optional = _edges(
            [] if raw_requirements is None else raw_requirements, target, tuple(extras),
        )
        _, _, _, tags = parse_wheel_filename(seed.filename)
        item_python = item.get("requires_python")
        raw_python = info.get("requires_python")
        python = "" if raw_python is None else raw_python
        if type(python) is not str:
            raise c.ContractError()
        if item_python is not None and item_python != python:
            raise c.ContractError()
        release = _Release(
            requirement, seed.version, "wheel", (target.platform,), (target.architecture,),
            base, seed.metadata_digest, artifact, python=python,
            wheel_tags=tuple(sorted(map(str, tags))),
            members=(ManagedMember("wheels/" + seed.filename, artifact.sha256, artifact.size),),
            extra_requires=optional,
        )
        _pypi(release, document, target)
        return release
    metadata, raw_artifact = _object(document.get("metadata")), _object(document.get("artifact"))
    url, size = document.get("download_url"), raw_artifact.get("size")
    if (
        type(url) is not str or type(size) is not int or _origin(url) != "galaxy.ansible.com"
        or url.rsplit("/", 1)[-1] != quote(seed.filename, safe="-_.")
    ):
        raise c.ContractError()
    digest = raw_artifact.get("sha256")
    if type(digest) is not str:
        raise c.ContractError()
    artifact = LockedAsset(seed.source, seed.name, url, digest, size)
    dependencies = _object(metadata.get("dependencies"))
    if len(dependencies) > 256 or type(document.get("requires_ansible")) is not str:
        raise c.ContractError()
    edges = tuple(
        _Requirement(name, "collection", "galaxy:" + name, target.context, version)
        for name, version in sorted(dependencies.items())
    )
    core = _Requirement(
        "ansible-core", "wheel", "pypi:ansible-core", target.context, document["requires_ansible"],
    )
    release = _Release(
        requirement, seed.version, "collection.tar.gz", (target.platform,),
        (target.architecture,), (*edges, core), seed.metadata_digest, artifact,
        members=(ManagedMember("collections/" + seed.filename, artifact.sha256, artifact.size),),
    )
    _galaxy(release, document)
    return release


@dataclass(frozen=True)
class _SeededPublisherMetadata:
    """Real closed metadata client; only external HTTPS I/O is replaceable in tests."""

    seeds: tuple[_PublisherSeed, ...]
    transport: HttpsAssetTransport

    def __post_init__(self) -> None:
        if (
            type(self.seeds) is not tuple or not 1 <= len(self.seeds) <= 1024
            or type(self.transport) is not HttpsAssetTransport
        ):
            raise c.ContractError()
        for seed in self.seeds:
            if type(seed) is not _PublisherSeed:
                raise c.ContractError()
            seed.__post_init__()
        if len({seed.source for seed in self.seeds}) != 1:
            raise c.ContractError()
        c.unique(tuple(seed.filename for seed in self.seeds))

    @property
    def digest(self) -> str:
        return c.digest(self.seeds)

    def observe(
        self, requirement: _Requirement, target: _Target,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _PublisherSnapshot:
        self.__post_init__()
        requirement.__post_init__()
        target.__post_init__()
        started = _check(clock, cancel, deadline)
        deadline = min(deadline, started + 60.0)
        if requirement.source != self.seeds[0].source or requirement.family != self.seeds[0].family:
            raise c.ContractError()
        _parser_preflight()
        observed = []
        for seed in self.seeds:
            now = _check(clock, cancel, deadline)
            _trace("publisher-catalogue-json", requirement.family, "attempt")
            try:
                response = self.transport.read_bounded(
                    seed.url, deadline - now, _LIMIT + 1, clock, cancel,
                )
                _check(clock, cancel, deadline)
                if (
                    response.url != seed.url or type(response.content) is not bytes
                    or len(response.content) > _LIMIT
                    or hashlib.sha256(response.content).hexdigest() != seed.metadata_digest
                ):
                    raise c.ContractError()
                observed.append(_populate(
                    seed, _object(json.loads(response.content, object_pairs_hook=_pairs)), target,
                ))
            except (InterruptedError, TimeoutError):
                _trace("publisher-catalogue-json", requirement.family, "interrupted")
                raise
            except (c.ContractError, OSError, ValueError, KeyError, TypeError):
                _trace("publisher-catalogue-json", requirement.family, "failed")
                raise _SourceUnavailable() from None
            _trace("publisher-catalogue-json", requirement.family, "returned")
        now = _check(clock, cancel, deadline)
        if not observed:
            raise _CatalogueUnavailable()
        return _PublisherSnapshot(
            requirement.source, c.digest(target), tuple(observed), self.digest,
            now, min(now + 300.0, deadline),
        )


def _seeded_publishers(
    seeds: tuple[_PublisherSeed, ...], transport: HttpsAssetTransport,
) -> tuple[_RegisteredSource, ...]:
    grouped: dict[str, list[_PublisherSeed]] = {}
    for seed in seeds:
        seed.__post_init__()
        grouped.setdefault(seed.source, []).append(seed)
    result = []
    for source, values in grouped.items():
        port = _SeededPublisherMetadata(tuple(values), transport)
        result.append(_RegisteredSource(
            source, (values[0].family,),
            ("files.pythonhosted.org",) if values[0].family == "wheel" else ("galaxy.ansible.com",),
            port.digest, port,
        ))
    return tuple(result)
