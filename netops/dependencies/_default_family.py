"""Default trusted catalogue and target composition, without implicit network I/O.

The installed package owns the catalogue. An empty catalogue is an explicit
absence of retained independent pins, not an unsigned publisher observation.
Neither interactive selection nor a catalogue can grant acquisition.
"""

from __future__ import annotations

import json
import platform
from dataclasses import dataclass
from importlib import resources

from netops.ansible import contracts as c

from ._assets import HttpsAssetTransport
from ._context_facts import _interpreter_tags
from ._family_bridge import _FamilyPlanning, _requirement
from ._family_codec import _release
from ._family_lock import (
    _CatalogueUnavailable,
    _check,
    _PublisherSnapshot,
    _RegisteredSource,
    _Release,
    _Requirement,
    _Target,
)
from ._guided import _existing_contexts
from ._guided_metadata import _Metadata
from ._lock_layout import _LockLayout
from ._managed import ManagedMember
from ._official_profiles import _decode_pin, _official_sources, _OfficialPin
from ._publisher_catalog import _PublisherSeed, _seeded_publishers
from ._publisher_metadata import _pairs, _PublisherMetadata, _registered_publishers
from ._python_metadata import _PythonFile, _PythonOrgMetadata, _PythonSeed, _seeded_python
from .service import DependencyRegistry

__all__: tuple[str, ...] = ()
_LIMIT = 1024 * 1024


@dataclass(frozen=True)
class _RetainedCatalogue:
    """The factual installed-package catalogue, never a request-supplied path."""

    releases: tuple[_Release, ...]
    python_files: tuple[_PythonFile, ...]
    publisher_records: tuple[_PublisherSeed, ...] = ()
    python_records: tuple[_PythonSeed, ...] = ()
    official_records: tuple[_OfficialPin, ...] = ()

    def __post_init__(self) -> None:
        for values, kind in (
            (self.releases, _Release), (self.python_files, _PythonFile),
            (self.publisher_records, _PublisherSeed), (self.python_records, _PythonSeed),
            (self.official_records, _OfficialPin),
        ):
            if type(values) is not tuple or len(values) > 1024:
                raise c.ContractError()
            for value in values:
                if type(value) is not kind:
                    raise c.ContractError()
                value.__post_init__()
            c.unique(tuple(c.digest(value) for value in values))
        if (
            any(not item.requirement.source.startswith(("pypi:", "galaxy:"))
                for item in self.releases)
            or set(item.source for item in self.publisher_records) & set(
                item.requirement.source for item in self.releases
            )
            or (self.python_files and self.python_records)
        ):
            raise c.ContractError()

    def register(self) -> tuple[_RegisteredSource, ...]:
        """Bind factual pins to exact production clients without I/O or grants."""
        self.__post_init__()
        transport = HttpsAssetTransport()
        sources = (
            _registered_publishers(self.releases, transport) if self.releases else ()
        ) + _seeded_publishers(self.publisher_records, transport)
        if self.official_records:
            sources += tuple(source for source in _official_sources(self.official_records)
                             if any(pin.source == source.source for pin in self.official_records))
        if self.python_records:
            sources += (_seeded_python(self.python_records, transport),)
        elif self.python_files:
            python = _PythonOrgMetadata(self.python_files, transport)
            sources += (_RegisteredSource(
                "python.org", ("python",), ("www.python.org",), python.digest, python,
            ),)
        return sources

    @classmethod
    def load(cls) -> _RetainedCatalogue:
        """Read only the fixed packaged resource, rejecting partial/unknown schemas."""
        content = resources.files("netops.dependencies").joinpath("publisher-catalogue.json").read_bytes()
        if len(content) > _LIMIT:
            raise c.ContractError()
        try:
            document = json.loads(content, object_pairs_hook=_pairs)
        except (ValueError, UnicodeError):
            raise c.ContractError() from None
        if type(document) is not dict:
            raise c.ContractError()
        schema = document.get("schema")
        expected = {"schema", "releases", "python_files"}
        if schema in ("netops-publisher-catalogue-v2", "netops-publisher-catalogue-v3"):
            expected.update(("publisher_records", "python_records"))
        if schema == "netops-publisher-catalogue-v3":
            expected.add("official_records")
        if (
            set(document) != expected
            or schema not in (
                "netops-publisher-catalogue-v1", "netops-publisher-catalogue-v2",
                "netops-publisher-catalogue-v3",
            )
            or type(document["releases"]) is not list or len(document["releases"]) > 1024
            or type(document["python_files"]) is not list or len(document["python_files"]) > 1024
        ):
            raise c.ContractError()
        releases = tuple(_release(item) for item in document["releases"])
        files = []
        for item in document["python_files"]:
            if type(item) is not dict or set(item) != {"release", "file_id"}:
                raise c.ContractError()
            files.append(_PythonFile(_release(item["release"]), item["file_id"]))
        if any(not item.requirement.source.startswith(("pypi:", "galaxy:")) for item in releases):
            raise c.ContractError()
        c.unique(tuple(c.digest(item) for item in releases))
        c.unique(tuple(c.digest(item.release) for item in files))
        records = document.get("publisher_records", [])
        if type(records) is not list or len(records) > 1024:
            raise c.ContractError()
        seeds = []
        for item in records:
            if type(item) is not dict or set(item) != set(_PublisherSeed.__dataclass_fields__):
                raise c.ContractError()
            seeds.append(_PublisherSeed(**item))
        c.unique(tuple(c.digest(item) for item in seeds))
        if set(item.source for item in seeds) & set(
            item.requirement.source for item in releases
        ):
            raise c.ContractError()
        python_records = document.get("python_records", [])
        if type(python_records) is not list or len(python_records) > 1024:
            raise c.ContractError()
        native_seeds = []
        for item in python_records:
            if type(item) is not dict or set(item) != set(_PythonSeed.__dataclass_fields__):
                raise c.ContractError()
            if type(item["members"]) is not list:
                raise c.ContractError()
            members = []
            for member in item["members"]:
                if type(member) is not dict or set(member) != set(ManagedMember.__dataclass_fields__):
                    raise c.ContractError()
                members.append(ManagedMember(**member))
            if type(item["platforms"]) is not list or type(item["architectures"]) is not list:
                raise c.ContractError()
            native_seeds.append(_PythonSeed(
                item["file_id"], item["version"], item["metadata_digest"], item["artifact_digest"],
                item["format"], tuple(item["platforms"]), tuple(item["architectures"]), tuple(members),
            ))
        if files and native_seeds:
            raise c.ContractError()
        c.unique(tuple(str(item.file_id) for item in native_seeds))
        official = document.get("official_records", [])
        if type(official) is not list or len(official) > 1024:
            raise c.ContractError()
        return cls(
            releases, tuple(files), tuple(seeds), tuple(native_seeds),
            tuple(_decode_pin(item) for item in official),
        )


@dataclass(frozen=True)
class _UnretainedPlatform:
    """A fixed platform source whose independent catalogue is presently absent."""

    source: str

    def observe(
        self, requirement: _Requirement, target: _Target,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _PublisherSnapshot:
        requirement.__post_init__()
        target.__post_init__()
        _check(clock, cancel, deadline)
        if requirement.source != self.source:
            raise c.ContractError()
        raise _CatalogueUnavailable()


def _default_metadata(registry: DependencyRegistry) -> _Metadata:
    """Construct the actual production resolver inputs for descriptor-free setup."""
    catalogue = _RetainedCatalogue.load()
    transport = HttpsAssetTransport()
    registered = {source.source: source for source in catalogue.register()}
    for official in _official_sources(catalogue.official_records):
        registered.setdefault(official.source, official)
    grouped: dict[str, set[str]] = {}
    for entry in registry.entries:
        requirement = _requirement(entry)
        grouped.setdefault(requirement.source, set()).add(requirement.family)
    for source, families in grouped.items():
        if source in registered:
            continue
        if source.startswith(("pypi:", "galaxy:")):
            port = _PublisherMetadata((), transport, source)
            registered[source] = _RegisteredSource(
                source, tuple(sorted(families)),
                ("files.pythonhosted.org",) if source.startswith("pypi:")
                else ("galaxy.ansible.com",),
                port.digest, port,
            )
        elif source == "python.org":
            python = _PythonOrgMetadata(catalogue.python_files, transport)
            registered[source] = _RegisteredSource(
                source, ("python",), ("www.python.org",), python.digest, python,
            )
        else:
            registered[source] = _RegisteredSource(
                source, tuple(sorted(families)),
                ("www.python.org",) if source == "python.org" else (),
                c.digest(()), _UnretainedPlatform(source),
            )
    targets = []
    try:
        from packaging import tags as packaging_tags

        observed_tags = _interpreter_tags(packaging_tags)
        tags = tuple(dict.fromkeys(str(tag) for tag in observed_tags))[:1024]
        abi = str(getattr(observed_tags[0], "abi"))
    except ImportError:
        # No compatible release can be selected without the resolver's PEP440
        # parser either. This records no wheel compatibility or readiness.
        tags, abi = (), "unobserved"
    for name, context in _existing_contexts().items():
        targets.append(_Target(
            name, context.platform, context.architecture, platform.python_version(), abi,
            tags, context.digest,
        ))
    return _Metadata(
        family_planning=_FamilyPlanning(tuple(registered.values()), tuple(targets)),
        layout=_LockLayout(),
    )
