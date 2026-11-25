"""Closed qualified bootstrap contribution, separate from publisher acquisition."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from netops.ansible import contracts as c
from netops.ansible.artifacts import ProtectedRoot
from netops.ansible.policy.authorization import AuthorizationError

from ._family_source import _BoundFamilyContributions
from ._installation import _InstallationSpec
from ._owned_source import _OwnedSource

if TYPE_CHECKING:
    from .service import DependencyRegistry

__all__: tuple[str, ...] = ()


@dataclass(frozen=True)
class _BootstrapContribution:
    """Retain the actual native-only actor; factual bindings cannot recreate it."""

    source: _OwnedSource
    installation: _InstallationSpec
    root: ProtectedRoot
    generation_id: str
    family: _BoundFamilyContributions | None = None

    def __post_init__(self) -> None:
        if (
            type(self.source) is not _OwnedSource
            or type(self.installation) is not _InstallationSpec
            or type(self.root) is not ProtectedRoot
        ):
            raise c.ContractError()
        self.installation.__post_init__()
        c.uuid_text(self.generation_id)
        receipt = self.source._issued._result.receipt
        if self.family is not None and (
            type(self.family) is not _BoundFamilyContributions
            or self.family.bootstrap.family is not None
            or self.family.bootstrap.source is not self.source
            or self.family.bootstrap.root != self.root
            or self.family.bootstrap.installation != self.installation
            or self.family.bootstrap.generation_id != self.generation_id
        ):
            raise AuthorizationError()
        if receipt["consuming_root"] != (
            self.root.path, str(self.root.device), str(self.root.inode),
        ):
            raise AuthorizationError()

    @property
    def digest(self) -> str:
        """Bind native bootstrap facts, without exposing an issuing capability."""
        native = (
            self.source.asset, self.installation, self.root.path,
            str(self.root.device), str(self.root.inode), self.generation_id,
        )
        return c.digest(native if self.family is None else (native, self.family.digest))

    def guard(
        self, root: Path, registry: DependencyRegistry, clock: c.ClockPort,
        cancel: c.CancelPort, deadline: float,
    ) -> None:
        """Reinspect the protected producer's exact independently qualified subset."""
        from ._family_lock import _trace
        from ._setup import _manifest, _owned_document

        self.__post_init__()
        if root != Path(self.root.path):
            raise AuthorizationError()
        manifest, _ = _manifest(
            _owned_document(self.source, self.installation, self.generation_id),
            root, registry, self.source,
        )
        _trace("bootstrap-source-reinspection", "python", "attempt")
        try:
            self.source.guard(manifest, clock, cancel, deadline)
            if self.family is not None:
                self.family.guard(root, clock, cancel, deadline)
        except BaseException as error:
            _trace(
                "bootstrap-source-reinspection", "python",
                "cancelled" if isinstance(error, InterruptedError)
                else "deadline" if isinstance(error, TimeoutError) else "failed",
            )
            raise
        _trace("bootstrap-source-reinspection", "python", "returned")
