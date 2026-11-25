"""Pinned official Python release-file metadata over the bounded HTTPS boundary."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

from netops.ansible import contracts as c

from ._assets import AssetTransport, HttpsAssetTransport, LockedAsset
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
from ._managed import ManagedMember
from ._publisher_metadata import _pairs

__all__: tuple[str, ...] = ()
_LIMIT = 1024 * 1024


@dataclass(frozen=True)
class _PythonSeed:
    """Retained official record and independently verified archive/member pins.

    The official API has no established SHA256 field. Its legacy MD5 cannot
    supply this pin. Compatibility/member facts must come from actual separately
    approved archive qualification; a response filename is not qualification.
    """

    file_id: int
    version: str
    metadata_digest: str
    artifact_digest: str
    format: str
    platforms: tuple[str, ...]
    architectures: tuple[str, ...]
    members: tuple[ManagedMember, ...]

    def __post_init__(self) -> None:
        c.counter(self.file_id, positive=True)
        c.sha256(self.metadata_digest)
        c.sha256(self.artifact_digest)
        _Requirement("native-python", "python", "python.org", "native", "==" + self.version)
        if self.format not in ("zip", "tar.gz"):
            raise c.ContractError()
        for values in (self.platforms, self.architectures):
            if type(values) is not tuple or not values:
                raise c.ContractError()
            c.unique(values)
            for value in values:
                c.text(value)
        if type(self.members) is not tuple or not 1 <= len(self.members) <= 4096:
            raise c.ContractError()
        for member in self.members:
            if type(member) is not ManagedMember:
                raise c.ContractError()
            member.__post_init__()


@dataclass(frozen=True)
class _SeededPythonMetadata:
    seeds: tuple[_PythonSeed, ...]
    transport: HttpsAssetTransport

    def __post_init__(self) -> None:
        if (
            type(self.seeds) is not tuple or not 1 <= len(self.seeds) <= 1024
            or type(self.transport) is not HttpsAssetTransport
        ):
            raise c.ContractError()
        for seed in self.seeds:
            if type(seed) is not _PythonSeed:
                raise c.ContractError()
            seed.__post_init__()
        c.unique(tuple(str(seed.file_id) for seed in self.seeds))

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
        if (
            requirement.source != "python.org" or requirement.family != "python"
            or requirement.name not in ("native-python", "controller-python")
        ):
            raise c.ContractError()
        started = _check(clock, cancel, deadline)
        deadline = min(deadline, started + 60.0)
        releases = []
        for seed in self.seeds:
            now = _check(clock, cancel, deadline)
            url = f"https://www.python.org/api/v2/downloads/release_file/{seed.file_id}/"
            _trace("python-catalogue-json", "python", "attempt")
            try:
                response = self.transport.read_bounded(
                    url, deadline - now, _LIMIT + 1, clock, cancel,
                )
                _check(clock, cancel, deadline)
                if (
                    response.url != url or type(response.content) is not bytes
                    or len(response.content) > _LIMIT
                    or hashlib.sha256(response.content).hexdigest() != seed.metadata_digest
                ):
                    raise c.ContractError()
                data = json.loads(response.content, object_pairs_hook=_pairs)
                if (
                    type(data) is not dict or type(data.get("id")) is not int
                    or data["id"] != seed.file_id or type(data.get("url")) is not str
                    or type(data.get("filesize")) is not int
                    or not data["url"].endswith("." + seed.format)
                ):
                    raise c.ContractError()
                artifact = LockedAsset(
                    "python.org", requirement.name, data["url"],
                    seed.artifact_digest, data["filesize"],
                )
                release = _Release(
                    _Requirement(requirement.name, "python", "python.org", target.context),
                    seed.version, seed.format, seed.platforms, seed.architectures, (),
                    seed.metadata_digest, artifact, members=seed.members,
                )
                # Reuse the original exact official-release path predicate.
                _PythonFile(release, seed.file_id)
                releases.append(release)
            except (InterruptedError, TimeoutError):
                _trace("python-catalogue-json", "python", "interrupted")
                raise
            except (OSError, ValueError, KeyError, TypeError, c.ContractError):
                _trace("python-catalogue-json", "python", "failed")
                raise _SourceUnavailable() from None
            _trace("python-catalogue-json", "python", "returned")
        now = _check(clock, cancel, deadline)
        return _PublisherSnapshot(
            "python.org", c.digest(target), tuple(releases), self.digest,
            now, min(now + 300.0, deadline),
        )


def _seeded_python(
    seeds: tuple[_PythonSeed, ...], transport: HttpsAssetTransport,
) -> _RegisteredSource:
    port = _SeededPythonMetadata(seeds, transport)
    return _RegisteredSource("python.org", ("python",), ("www.python.org",), port.digest, port)


@dataclass(frozen=True)
class _PythonFile:
    release: _Release
    file_id: int

    def __post_init__(self) -> None:
        if type(self.release) is not _Release:
            raise c.ContractError()
        self.release.__post_init__()
        c.counter(self.file_id, positive=True)
        artifact = self.release.artifact
        if (
            self.release.requirement.source != "python.org"
            or self.release.requirement.family != "python" or artifact is None
            or artifact.source_id != "python.org"
            or urlsplit(artifact.url).netloc != "www.python.org"
            or not urlsplit(artifact.url).path.startswith(
                "/ftp/python/" + self.release.version + "/",
            )
        ):
            raise c.ContractError()


@dataclass(frozen=True)
class _PythonOrgMetadata:
    """Confirm independently pinned official file records, never invent native pins.

    The API's legacy MD5 field is deliberately not treated as an integrity pin.
    SHA256, size and member inventory come from the independently retained
    package catalogue; the raw official metadata must match its separate pin.
    """

    files: tuple[_PythonFile, ...]
    transport: AssetTransport

    @property
    def digest(self) -> str:
        return c.digest(self.files)

    def observe(
        self, requirement: _Requirement, target: _Target,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _PublisherSnapshot:
        requirement.__post_init__()
        target.__post_init__()
        started = _check(clock, cancel, deadline)
        deadline = min(deadline, started + 60.0)
        if requirement.source != "python.org" or requirement.family != "python":
            raise c.ContractError()
        if type(self.files) is not tuple or len(self.files) > 1024:
            raise c.ContractError()
        if not self.files:
            raise _CatalogueUnavailable((
                "official-release-file-id", "independently-retained-official-json-sha256",
                "separately-verified-archive-sha256", "exact-archive-members",
                "qualified-platform-architecture",
            ))
        observed = []
        for item in self.files:
            if type(item) is not _PythonFile:
                raise c.ContractError()
            item.__post_init__()
            release = item.release
            if release.requirement.context != target.context:
                continue
            url = f"https://www.python.org/api/v2/downloads/release_file/{item.file_id}/"
            now = _check(clock, cancel, deadline)
            _trace("python-release-json", "python", "attempt")
            try:
                response = (
                    self.transport.read_bounded(url, deadline - now, _LIMIT + 1, clock, cancel)
                    if type(self.transport) is HttpsAssetTransport else
                    self.transport.read(url, deadline - now, _LIMIT + 1)
                )
                _check(clock, cancel, deadline)
                if (
                    response.url != url or type(response.content) is not bytes
                    or len(response.content) > _LIMIT
                    or hashlib.sha256(response.content).hexdigest() != release.metadata_digest
                ):
                    raise c.ContractError()
                data = json.loads(response.content, object_pairs_hook=_pairs)
                artifact = release.artifact
                if (
                    type(data) is not dict or artifact is None
                    or type(data.get("id")) is not int or data["id"] != item.file_id
                    or data.get("url") != artifact.url
                    or type(data.get("filesize")) is not int or data["filesize"] != artifact.size
                ):
                    raise c.ContractError()
            except (InterruptedError, TimeoutError):
                _trace("python-release-json", "python", "interrupted")
                raise
            except (OSError, ValueError, KeyError, TypeError, c.ContractError):
                _trace("python-release-json", "python", "failed")
                raise _SourceUnavailable() from None
            _trace("python-release-json", "python", "returned")
            observed.append(release)
        now = _check(clock, cancel, deadline)
        return _PublisherSnapshot(
            "python.org", c.digest(target), tuple(observed), self.digest, now,
            min(now + 300.0, deadline),
        )
