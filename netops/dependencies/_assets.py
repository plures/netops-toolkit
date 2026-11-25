"""Pinned HTTPS acquisition primitive for an explicitly admitted dependency effect.

No metadata locator is an artifact lock. This primitive does not install a wheel,
execute an archive, extend consent, or publish a platform qualification.
"""

from __future__ import annotations

import hashlib
import logging
import random
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.client import HTTPMessage
from typing import IO, TYPE_CHECKING, Protocol

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import AuthorizationBroker, AuthorizationError

if TYPE_CHECKING:
    from .service import DependencyEntry

__all__: tuple[str, ...] = ()

_LOG = logging.getLogger(__name__)
_MAX_ASSET = 128 * 1024 * 1024
_DOWNLOAD_SECONDS = 300.0
_ASSET_EVENT = "install.step"
_ASSET_METRIC = "netops.install.step.count"


class _MonotonicClock:
    """Latch invalid/backward readings across the caller and body watchdog."""

    def __init__(self, clock: c.ClockPort) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._last = 0.0
        self._invalid = False

    def monotonic(self) -> float:
        with self._lock:
            if self._invalid:
                raise c.ContractError()
            try:
                value = c.finite(self._clock.monotonic())
                if value < self._last:
                    raise c.ContractError()
            except Exception:
                self._invalid = True
                raise
            self._last = value
            return value

    def utc_now(self) -> datetime:
        return self._clock.utc_now()


@dataclass(frozen=True)
class LockedAsset:
    """Nonsecret immutable reviewed source; a hash is not an approval signature."""

    source_id: str
    dependency: str
    url: str = field(repr=False)
    sha256: str
    size: int

    def __post_init__(self) -> None:
        """Validate lock structure without performing I/O."""
        c.text(self.source_id)
        c.text(self.dependency)
        c.sha256(self.sha256)
        c.counter(self.size, positive=True)
        if self.size > _MAX_ASSET:
            raise c.ContractError()
        _origin(self.url)


@dataclass(frozen=True)
class AssetResponse:
    """A bounded transport observation with no credentials or diagnostic body repr."""

    url: str = field(repr=False)
    content: bytes = field(repr=False)


@dataclass(frozen=True)
class DownloadReceipt:
    """Returned bytes are a factual acquisition, not permission to stage or execute."""

    content: bytes = field(repr=False)
    digest: str
    cancelled_after_acquisition: bool


def _origin(url: str) -> str:
    if type(url) is not str or len(url) > 4096 or any(ord(char) < 33 for char in url):
        raise c.ContractError()
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        raise c.ContractError() from None
    if (
        parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
        or parsed.fragment or parsed.query or port not in (None, 443)
        or parsed.hostname is None
    ):
        raise c.ContractError()
    return parsed.hostname


def _approved(entry: DependencyEntry, asset: LockedAsset) -> None:
    if asset.dependency != entry.id or entry.ownership == "external-observe-only":
        raise c.ContractError()
    # Authority is a registered source family, never an arbitrary lock host.
    hosts: tuple[str, ...] = ()
    if entry.source.startswith("pypi:"):
        hosts = ("files.pythonhosted.org",)
    elif entry.source.startswith("galaxy:"):
        hosts = ("galaxy.ansible.com",)
    elif entry.source == "python.org":
        hosts = ("www.python.org",)
    if _origin(asset.url) not in hosts:
        raise c.ContractError()
    if entry.digest is not None and asset.sha256 != entry.digest:
        raise c.ContractError()
    if entry.size is not None and asset.size != entry.size:
        raise c.ContractError()


class AssetTransport(Protocol):
    """Transport seam used only after private lifecycle handler admission."""

    def read(self, url: str, timeout: float, limit: int) -> AssetResponse:
        """Fetch at most limit bytes without credentials or cross-origin redirects."""
        ...


class _SameOrigin(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: urllib.request.Request, fp: IO[bytes], code: int, msg: str,
        headers: HTTPMessage, newurl: str,
    ) -> urllib.request.Request | None:
        if _origin(req.full_url) != _origin(newurl):
            raise c.ContractError()
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _BodyStream(Protocol):
    def read1(self, maximum: int) -> bytes:
        """Return at most one bounded raw transport read."""
        ...


class HttpsAssetTransport:
    """TLS-verified, credential-free HTTPS with fail-closed redirect handling."""

    def read(self, url: str, timeout: float, limit: int) -> AssetResponse:
        """Bound a standalone request by elapsed time, not one timeout per byte."""
        class Clock:
            """Standalone real elapsed clock, never a renewed grant."""

            def monotonic(self) -> float:
                """Return real monotonic seconds."""
                return time.monotonic()

            def utc_now(self) -> datetime:
                """Return non-authoritative display time."""
                return datetime.now(timezone.utc)

        class Cancel:
            """Standalone requests have no external cancellation handle."""

            def is_cancelled(self) -> bool:
                """Report no requested cancellation."""
                return False

            def wait(self, timeout: float) -> bool:
                """Do not introduce a retry sleep at this transport boundary."""
                return False

        return self.read_bounded(url, timeout, limit, Clock(), Cancel())

    def read_bounded(
        self, url: str, timeout: float, limit: int, clock: c.ClockPort, cancel: c.CancelPort,
    ) -> AssetResponse:
        """Bound DNS, connect, redirects and body with one joined owned process."""
        _origin(url)
        c.finite(timeout)
        c.counter(limit, positive=True)
        if timeout <= 0.0 or timeout > _DOWNLOAD_SECONDS or limit > _MAX_ASSET + 1:
            raise c.ContractError()
        clock = _MonotonicClock(clock)
        from ._https_process import _read

        final_url, content = _read(url, timeout, limit, clock, cancel)
        if _origin(final_url) != _origin(url):
            raise c.ContractError()
        return AssetResponse(final_url, content)

    @staticmethod
    def _body(
        response: _BodyStream, stream_socket: socket.socket, final_url: str, limit: int,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> AssetResponse:
        finished = threading.Event()
        aborted = threading.Event()

        def interrupt() -> None:
            while not finished.wait(0.05):
                try:
                    stop = cancel.is_cancelled() or c.finite(clock.monotonic()) >= deadline
                except Exception:
                    stop = True
                if stop:
                    aborted.set()
                    try:
                        stream_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return

        watcher = threading.Thread(target=interrupt, name="netops-asset-body", daemon=False)
        watcher.start()
        chunks: list[bytes] = []
        total = 0
        try:
            while total < limit:
                if cancel.is_cancelled():
                    raise InterruptedError()
                remaining = deadline - c.finite(clock.monotonic())
                if remaining <= 0.0:
                    raise TimeoutError()
                # Windows select-backed socket reads need not wake promptly on
                # another thread's shutdown. Also bound each real blocking
                # read; a timeout aborts this response, never retries a poisoned
                # HTTPResponse buffer. Acquisition may retry a fresh response
                # only within its original aggregate budget.
                stream_socket.settimeout(min(0.5, remaining))
                chunk = response.read1(min(65536, limit - total))
                if not chunk:
                    break
                if type(chunk) is not bytes or len(chunk) > limit - total:
                    raise c.ContractError()
                chunks.append(chunk)
                total += len(chunk)
            if cancel.is_cancelled():
                raise InterruptedError()
            if aborted.is_set() or c.finite(clock.monotonic()) >= deadline:
                raise TimeoutError()
            return AssetResponse(final_url, b"".join(chunks))
        except OSError:
            if cancel.is_cancelled():
                raise InterruptedError() from None
            if aborted.is_set() or c.finite(clock.monotonic()) >= deadline:
                raise TimeoutError() from None
            raise
        finally:
            finished.set()
            watcher.join()


class VerifiedAssetAcquisition:
    """One-use admitted download; no package-manager, global state or auto-replay."""

    def __init__(
        self, authorization: AuthorizationBroker, transport: AssetTransport,
        clock: c.ClockPort, events: c.EventPort,
    ) -> None:
        if type(authorization) is not AuthorizationBroker:
            raise c.ContractError()
        self._authorization = authorization
        self._transport, self._clock, self._events = transport, clock, events

    def _duration(self, started: float) -> float:
        try:
            return max(0.0, c.finite(self._clock.monotonic()) - started)
        except Exception:
            return 0.0

    @staticmethod
    def _retryable(error: urllib.error.URLError | OSError) -> bool:
        if isinstance(error, urllib.error.HTTPError):
            return error.code in (429, 500, 502, 503, 504)
        if isinstance(error, urllib.error.URLError):
            return isinstance(error.reason, (TimeoutError, ConnectionError)) and not isinstance(
                error.reason, ssl.SSLError,
            )
        return isinstance(error, (TimeoutError, ConnectionError)) and not isinstance(
            error, ssl.SSLError,
        )

    def _observe(
        self, binding: lc.LifecycleEffectBinding, status: c.OutcomeStatus,
        reason: c.ReasonCode | None, duration: float,
    ) -> None:
        dimensions = {
            "metric_name": _ASSET_METRIC, "metric_value": 1,
            "kind": binding.lifecycle.kind, "step_kind": "dependency-download",
            "status": status.value, "stage": "download", "duration": duration,
            "category": "dependency" if reason is not None else "none",
            "reason": reason.value if reason is not None else "none",
            "next_action": "review-install-plan" if reason is not None else "none",
            "operation_id": binding.lifecycle.lifecycle_id,
            "step_id": binding.occurrence_id,
            "context_digest": binding.lifecycle.context_digest,
            "metric_labels": ("kind", "step_kind", "status", "stage", "category", "reason"),
        }
        try:
            _LOG.info(_ASSET_EVENT, extra=dimensions)
        except Exception:
            pass
        try:
            self._events.emit(c.SafeEvent(
                binding.lifecycle.lifecycle_id, binding.occurrence_id,
                binding.lifecycle.root.resource_id, binding.lifecycle.context_digest,
                c.Mode.APPLY, status, c.ErrorCategory.DEPENDENCY if reason is not None else None,
                reason, False, duration,
            ))
        except Exception:
            pass

    def download(
        self, entry: DependencyEntry, asset: LockedAsset,
        permit: lc.LifecycleEffectPermit, binding: lc.LifecycleEffectBinding, cancel: c.CancelPort,
    ) -> DownloadReceipt:
        """Validate exact reviewed source before entering one bounded download effect."""
        if type(asset) is not LockedAsset or type(binding) is not lc.LifecycleEffectBinding:
            raise c.ContractError()
        asset.__post_init__()
        _approved(entry, asset)
        actual = self._authorization.reconcile_lifecycle(permit)
        if actual != binding:
            raise AuthorizationError()
        selected = tuple(effect for effect in binding.lifecycle.effects
                         if effect.occurrence_id == binding.occurrence_id)
        if len(selected) != 1 or selected[0].kind != "dependency-download":
            raise AuthorizationError()
        steps = binding.lifecycle.content["steps"]
        if type(steps) is not tuple:
            raise c.ContractError()
        step = c.public_object(steps[selected[0].ordinal])
        source = c.public_object(step["source"])
        if (
            source["source_id"] != asset.source_id or source["artifact_digest"] != asset.sha256
            or source["registry_digest"] != binding.lifecycle.registry_digest
            or source["descriptor_digest"] != c.digest(asset)
        ):
            raise AuthorizationError()
        clock = _MonotonicClock(self._clock)
        try:
            started = clock.monotonic()
        except Exception:
            self._authorization.revoke_lifecycle(binding.lifecycle.kind, binding.lifecycle.plan_id)
            raise
        if cancel.is_cancelled():
            self._authorization.revoke_lifecycle(binding.lifecycle.kind, binding.lifecycle.plan_id)
            self._observe(binding, c.OutcomeStatus.CANCELLED, c.ReasonCode.CANCELLED, 0.0)
            raise InterruptedError()
        self._authorization.enter_lifecycle(permit, binding, started)
        scope = self._authorization._life_scope(permit)
        if scope is None:
            raise AuthorizationError()
        deadline = min(c.checked_deadline(started, _DOWNLOAD_SECONDS), scope.deadline)
        try:
            for attempt in range(3):
                now = clock.monotonic()
                if cancel.is_cancelled() or now >= deadline:
                    raise InterruptedError()
                # This is a recheck, not another entry or a renewed grant.
                # Revalidate revocation, original deadline and current owned
                # facts before every fresh transport attempt.
                with self._authorization._lock, self._authorization._life_current(scope, now):
                    pass
                from ._composition import ManagedLifecycleState

                state = self._authorization._lifecycle_state
                if type(state) is ManagedLifecycleState:
                    manifest = state._manifest(binding.lifecycle)
                    if manifest.bootstrap_digest is not None:
                        state.guard_source(manifest, clock, cancel, deadline)
                        now = clock.monotonic()
                        if cancel.is_cancelled() or now >= deadline:
                            raise InterruptedError()
                        with self._authorization._lock, self._authorization._life_current(scope, now):
                            pass
                try:
                    from ._publisher_acquisition import _PublisherAcquisition

                    if (
                        isinstance(self._transport, HttpsAssetTransport)
                        or type(self._transport) is _PublisherAcquisition
                    ):
                        response = self._transport.read_bounded(
                            asset.url, deadline - now, asset.size + 1, clock, cancel,
                        )
                    else:
                        # Injected I/O ports must enforce their own in-flight
                        # bound. The concrete production transport above owns
                        # actual socket interruption, not just this return check.
                        response = self._transport.read(
                            asset.url, min(30.0, deadline - now), asset.size + 1,
                        )
                    if (
                        type(response) is not AssetResponse or _origin(response.url) != _origin(asset.url)
                        or type(response.content) is not bytes or len(response.content) != asset.size
                        or hashlib.sha256(response.content).hexdigest() != asset.sha256
                    ):
                        raise c.ContractError()
                    observed = clock.monotonic()
                    if observed >= deadline:
                        raise TimeoutError()
                    with self._authorization._lock, self._authorization._life_current(scope, observed):
                        pass
                    result = DownloadReceipt(
                        response.content, asset.sha256, cancel.is_cancelled(),
                    )
                    break
                except (urllib.error.URLError, socket.timeout, ConnectionError) as exc:
                    if attempt == 2 or not self._retryable(exc):
                        raise
                    delay = (2 ** attempt) * random.SystemRandom().uniform(0.8, 1.2)
                    if clock.monotonic() + delay >= deadline or cancel.wait(delay):
                        raise InterruptedError() from None
            else:
                raise c.ContractError()
        except BaseException as exc:
            self._authorization.revoke_lifecycle(binding.lifecycle.kind, binding.lifecycle.plan_id)
            self._observe(
                binding, c.OutcomeStatus.CANCELLED if isinstance(exc, InterruptedError) else c.OutcomeStatus.FAILED,
                c.ReasonCode.CANCELLED if isinstance(exc, InterruptedError) else c.ReasonCode.PROVISION_FAILED,
                self._duration(started),
            )
            raise
        self._observe(binding, c.OutcomeStatus.SUCCEEDED, None, self._duration(started))
        return result
