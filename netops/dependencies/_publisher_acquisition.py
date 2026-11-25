"""Exact prospective publisher downloads consumed only by the admitted owner.

This live constructor value is not serialized in setup documents. An installed
descriptor or a historical family lock cannot reconstruct it on resume.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from netops.ansible import contracts as c

from ._assets import AssetResponse, HttpsAssetTransport, LockedAsset, _origin

__all__: tuple[str, ...] = ()


@dataclass(frozen=True)
class _PublisherAcquisition:
    """Closed exact source binding; no argv, callbacks, caller URL or grants."""

    assets: tuple[LockedAsset, ...]
    cache_paths: tuple[Path, ...]
    document_digest: str
    source_deadline: float

    def __post_init__(self) -> None:
        c.sha256(self.document_digest)
        c.finite(self.source_deadline)
        if self.source_deadline <= 0:
            raise c.ContractError()
        if (
            type(self.assets) is not tuple or not 1 <= len(self.assets) <= 128
            or type(self.cache_paths) is not tuple or len(self.cache_paths) != len(self.assets)
            or any(type(asset) is not LockedAsset for asset in self.assets)
            or any(not isinstance(path, Path) for path in self.cache_paths)
        ):
            raise c.ContractError()
        c.unique(tuple(asset.url for asset in self.assets))
        for asset, path in zip(self.assets, self.cache_paths):
            if not path.is_absolute() or ".." in path.parts:
                raise c.ContractError()
            asset.__post_init__()
            expected = (
                "files.pythonhosted.org" if asset.source_id.startswith("pypi:")
                else "galaxy.ansible.com" if asset.source_id.startswith("galaxy:")
                else "www.python.org" if asset.source_id == "python.org" else None
            )
            if expected is None or _origin(asset.url) != expected:
                raise c.ContractError()

    def read(self, url: str, timeout: float, limit: int) -> AssetResponse:
        """Read exact reviewed bytes after the original handler checks its live permit."""
        return self._read(url, timeout, limit)

    def read_bounded(
        self, url: str, timeout: float, limit: int, clock: c.ClockPort, cancel: c.CancelPort,
    ) -> AssetResponse:
        """Preserve the owner's live supervision through the exact HTTPS boundary."""
        if cancel.is_cancelled():
            raise InterruptedError()
        return self._read(url, timeout, limit, clock, cancel)

    def _read(
        self, url: str, timeout: float, limit: int,
        clock: c.ClockPort | None = None, cancel: c.CancelPort | None = None,
    ) -> AssetResponse:
        from ._setup import _OfflineAssets

        self.__post_init__()
        now = c.finite(time.monotonic())
        if now >= self.source_deadline:
            raise c.ContractError()
        matches = tuple((asset, path) for asset, path in zip(self.assets, self.cache_paths)
                        if asset.url == url)
        if len(matches) != 1 or c.finite(timeout) <= 0:
            raise c.ContractError()
        asset, path = matches[0]
        timeout = min(timeout, self.source_deadline - now)
        if path.exists() or path.is_symlink():
            # Corrupt or unknown existing cache is not replaced or downloaded over.
            cached = _OfflineAssets(())
            cached.sources[url] = (asset, path)
            response = cached.read(url, timeout, limit)
        else:
            # No cache writes, redirects, global pip, or publisher fallback occur.
            # The caller retains the actual acquired bytes in its admitted staging.
            transport = HttpsAssetTransport()
            if clock is not None and cancel is not None:
                response = transport.read_bounded(
                    url, timeout, min(limit, asset.size + 1), clock, cancel,
                )
            else:
                response = transport.read(url, timeout, min(limit, asset.size + 1))
        if c.finite(time.monotonic()) >= self.source_deadline:
            raise c.ContractError()
        return response
