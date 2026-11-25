"""Proactive local setup entry point over the protected dependency lifecycle."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import cast

from .ansible.artifacts import ProtectedRoot
from .ansible.settings import ObservationSettings
from .dependencies._bootstrap import _BootstrapContribution
from .dependencies._family_bridge import _FamilyPlanning
from .dependencies._family_lock import _Release, _Target
from .dependencies._guided_metadata import _CachedArchive, _Metadata
from .dependencies._installation import _InstallationSpec
from .dependencies._lock_layout import _InterpreterPin, _LockLayout
from .dependencies._official_profiles import _OfficialMetadata, _OfficialPin, _PublisherContext
from .dependencies._owned_source import _OwnedSource
from .dependencies._publisher_catalog import _PublisherSeed
from .dependencies._python_metadata import _PythonFile, _PythonSeed
from .dependencies._setup import _main

__all__ = ["SetupMetadata", "main"]


@dataclass(frozen=True)
class SetupMetadata:
    """Trusted producer or retained publisher-catalogue composition, never grants.

    The producer must independently retain its protected source ledger and exact
    consuming root. This wrapper neither issues that authority nor widens its
    native-only scope. No CLI option reconstructs it.
    """

    source: _OwnedSource | None = None
    installation: _InstallationSpec | None = None
    consuming_root: ProtectedRoot | None = None
    generation_id: str | None = None
    _family_planning: _FamilyPlanning | None = field(default=None, repr=False)
    _archives: tuple[_CachedArchive, ...] = field(default=(), repr=False)
    observation: ObservationSettings | None = None
    _bootstrap: _BootstrapContribution | None = field(default=None, repr=False)
    _interpreters: tuple[_InterpreterPin, ...] = field(default=(), repr=False)
    _publisher_contexts: tuple[_PublisherContext, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        """Validate the typed private composition without issuing authority."""
        self._metadata()

    def _metadata(self) -> _Metadata:
        if self._family_planning is not None:
            from .dependencies._assets import HttpsAssetTransport
            from .dependencies._publisher_catalog import _SeededPublisherMetadata
            from .dependencies._publisher_metadata import _PublisherMetadata
            from .dependencies._python_metadata import _PythonOrgMetadata, _SeededPythonMetadata

            if (
                type(self._family_planning) is not _FamilyPlanning or self.source is not None
                or self.consuming_root is not None
                or (self.installation is not None and type(self.installation) is not _InstallationSpec)
                or (self.installation is None and self._archives)
                or (self.installation is not None and (self._interpreters or self._publisher_contexts))
                or any(
                    type(source.port) not in (
                        _PublisherMetadata, _SeededPublisherMetadata,
                        _PythonOrgMetadata, _SeededPythonMetadata,
                        _OfficialMetadata,
                    )
                    or type(cast(
                        "_PublisherMetadata | _SeededPublisherMetadata | "
                        "_PythonOrgMetadata | _SeededPythonMetadata | _OfficialMetadata", source.port,
                    ).transport) is not HttpsAssetTransport
                    for source in self._family_planning.sources
                )
            ):
                raise TypeError("Publisher metadata requires closed real publisher clients.")
            return _Metadata(
                installation=self.installation, archives=self._archives,
                generation_id=self.generation_id, family_planning=self._family_planning,
                observation=self.observation,
                layout=_LockLayout(self._interpreters, self._publisher_contexts)
                if self.installation is None else None,
                bootstrap=self._bootstrap,
            )
        if (
            type(self.source) is not _OwnedSource
            or type(self.installation) is not _InstallationSpec
            or type(self.consuming_root) is not ProtectedRoot
            or self._archives or self.generation_id is None
            or self._bootstrap is not None
            or self._interpreters
            or self._publisher_contexts
        ):
            raise TypeError("Setup metadata requires an existing producer, pin and protected root.")
        return _Metadata(
            installation=self.installation, owned_source=self.source,
            generation_id=self.generation_id, consuming_root=self.consuming_root,
            observation=self.observation,
        )

    @classmethod
    def publishers(
        cls, installation: _InstallationSpec | None, archives: tuple[_CachedArchive, ...],
        releases: tuple[_Release, ...], targets: tuple[_Target, ...],
        *, generation_id: str | None = None, observation: ObservationSettings | None = None,
        python_files: tuple[_PythonFile, ...] = (),
        python_records: tuple[_PythonSeed, ...] = (),
        publisher_records: tuple[_PublisherSeed, ...] = (),
        official_records: tuple[_OfficialPin, ...] = (),
        interpreters: tuple[_InterpreterPin, ...] = (),
        publisher_contexts: tuple[_PublisherContext, ...] = (),
    ) -> SetupMetadata:
        """Use closed real publisher clients over independently retained catalogue pins.

        An absent installation with empty archives selects the production lock
        compiler, including exact interpreter qualification and content-addressed
        cache layout. The complete current toolkit wheel remains mandatory.
        This method performs no I/O. Interactive selection later verifies the
        official version metadata through the bounded HTTPS boundary. Neither
        a release object nor its hashes grant acquisition or installation.
        ``python_files`` retains exact official release-file IDs with qualified
        releases; ``python_records`` instead supplies the raw-metadata seeds.
        They are exclusive. ``publisher_records`` adds raw PyPI/Galaxy seeds,
        exclusive with retained releases for the same source. No transport or
        normalized response callback is accepted.
        """
        from .dependencies._default_family import _RetainedCatalogue

        catalogue = _RetainedCatalogue(
            releases, python_files, publisher_records, python_records, official_records,
        )

        return cls(
            installation=installation, generation_id=generation_id,
            _family_planning=_FamilyPlanning(catalogue.register(), targets),
            _archives=archives,
            observation=observation,
            _interpreters=interpreters,
            _publisher_contexts=publisher_contexts,
        )

    @classmethod
    def compose(
        cls, bootstrap: SetupMetadata, publishers: SetupMetadata,
    ) -> SetupMetadata:
        """Join a live qualified native bootstrap to a separate complete family plan.

        No producer bytes become python.org/PyPI assets. The original bootstrap
        still qualifies only native.stdlib, and the future toolkit must retain
        its own exact current publisher wheel and complete selected closure.
        """
        if type(bootstrap) is not cls or type(publishers) is not cls:
            raise TypeError("Composition requires closed setup metadata.")
        native, family = bootstrap._metadata(), publishers._metadata()
        if (
            native.owned_source is None or native.installation is None
            or native.consuming_root is None or native.generation_id is None
            or family.family_planning is None or family.layout is None
            or family.bootstrap is not None
        ):
            raise TypeError("Composition requires a native producer and production family compiler.")
        contribution = _BootstrapContribution(
            native.owned_source, native.installation,
            native.consuming_root, native.generation_id,
        )
        if (
            native.observation is not None and family.observation is not None
            and native.observation != family.observation
        ):
            raise TypeError("Composition must retain the selected bootstrap observation setting.")
        return replace(
            publishers, _bootstrap=contribution,
            observation=family.observation or native.observation,
        )


def main(argv: list[str] | None = None, *, metadata: SetupMetadata | None = None) -> int:
    """Diagnose first-run prerequisites or review an explicit owned lifecycle action."""
    if metadata is not None and type(metadata) is not SetupMetadata:
        raise TypeError("Setup metadata requires the trusted typed composition.")
    return _main(argv, _metadata=metadata._metadata() if metadata is not None else None)


if __name__ == "__main__":
    raise SystemExit(main())
