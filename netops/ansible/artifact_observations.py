"""Paired artifact counters and safe structured logs without exporter setup."""

from __future__ import annotations

import hashlib
import logging
import math
import threading
import time
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from itertools import count

from netops.ansible.contracts import ArtifactBinding, SafeError
from netops.ansible.policy import contracts as lc

_PUBLISH = "artifact.publish"
_CLEANUP = "cleanup.result"
_UNHANDLED = "Unhandled"
_METRICS = {_PUBLISH: "netops.artifact.publish.count", _CLEANUP: "netops.cleanup.result.count"}
_IO_SEQUENCE = count()
_OWNED_IO_METRIC = "netops.lifecycle.owned_io.count"
_OWNED_IO_BOUNDARIES = frozenset(("owned_read", "owned_cas"))
_IO_STARTED = "started"
_IO_SUCCEEDED = "succeeded"
_IO_FAILED = "failed"
_IO_ERROR_CATEGORY = "storage"
_IO_ERROR_REASON = "owned-io-failed"
_IO_NEXT_ACTION = "Inspect the owned receipt and current state before any new reviewed attempt."


@dataclass(frozen=True)
class _ObservationContext:
    operation_id: str = "none"
    step_id: str = "none"
    occurrence_id: str = "none"
    target_id: str = "none"
    context_id: str = "none"
    mode: str = "none"


_CONTEXT: ContextVar[_ObservationContext] = ContextVar(
    "lifecycle_observation_context", default=_ObservationContext(),
)


def _correlation(value: str) -> str:
    """Make deterministic log-only references without leaking caller identifiers."""
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


@contextmanager
def _lifecycle_observation_context(
    binding: lc.LifecycleBinding, occurrence: str = "none",
) -> Iterator[None]:
    """Scope non-authoritative safe correlation; nested locks preserve occurrence."""
    context = _ObservationContext()
    try:
        if type(binding) in (lc.InstallBinding, lc.UninstallBinding, lc.RestoreBinding):
            operation = _correlation(binding.plan_id)
            parent = _CONTEXT.get()
            effect = next((e for e in binding.effects if e.occurrence_id == occurrence), None)
            context = _ObservationContext(
                operation_id=operation,
                step_id=_correlation(effect.step_id) if effect is not None else
                parent.step_id if parent.operation_id == operation else "none",
                occurrence_id=_correlation(effect.occurrence_id) if effect is not None else
                parent.occurrence_id if parent.operation_id == operation else "none",
                context_id=_correlation(binding.context_digest),
                mode=binding.kind if binding.kind in ("install", "uninstall", "restore") else "none",
            )
    except BaseException:
        # Malformed observation input is not a new admission check.
        pass
    token = _CONTEXT.set(context)
    try:
        yield
    finally:
        _CONTEXT.reset(token)


def _record_lifecycle_handler(outcome: str, kind: str, logger: logging.Logger) -> None:
    """Observe a fixed handler without changing its factual completion."""
    try:
        logger.info("lifecycle.handler.%s kind=%s", outcome, kind)
    except BaseException:
        # Bare handler records need the same isolation as metric-bearing records.
        return


class ArtifactObservations:
    """Keep local aggregate counters available to the host's metrics exporter."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._counts: Counter[tuple[str, str, str, str, str, str]] = Counter()
        self._io_counts: Counter[tuple[str, str]] = Counter()
        self._logger = logging.getLogger(__name__)

    @staticmethod
    def _time() -> float | None:
        try:
            now = time.monotonic()
            return now if math.isfinite(now) and now >= 0.0 else None
        except BaseException:
            # Reporting clocks must not consume or revoke lifecycle authority.
            return None

    def _record_io(
        self, boundary: str, outcome: str, correlation: str, duration: float,
        logger: logging.Logger,
    ) -> None:
        dimensions = {"boundary": boundary, "outcome": outcome}
        try:
            context = _CONTEXT.get()
            failed = outcome == _IO_FAILED
            with self._lock:
                self._io_counts[(boundary, outcome)] += 1
                logger.info("lifecycle.%s.%s", boundary, outcome, extra={
                    "metric": _OWNED_IO_METRIC, "metric_value": 1,
                    "metric_dimensions": dimensions, **dimensions,
                    "io_id": correlation, "duration": duration,
                    "operation_id": context.operation_id, "step_id": context.step_id,
                    "occurrence_id": context.occurrence_id, "target_id": context.target_id,
                    "context_id": context.context_id, "mode": context.mode, "status": outcome,
                    "error_category": _IO_ERROR_CATEGORY if failed else "none",
                    "reason": _IO_ERROR_REASON if failed else "none", "retryable": False,
                    "next_action": _IO_NEXT_ACTION if failed else "none",
                })
        except BaseException:
            # Even interrupting sinks cannot replace I/O errors or factual receipts.
            return

    @contextmanager
    def _io(self, boundary: str, logger: logging.Logger) -> Iterator[None]:
        if boundary not in _OWNED_IO_BOUNDARIES:
            raise ValueError("unknown-owned-io-boundary")
        correlation = str(next(_IO_SEQUENCE))
        started = self._time()
        self._record_io(boundary, _IO_STARTED, correlation, 0.0, logger)
        outcome = _IO_FAILED
        try:
            yield
            outcome = _IO_SUCCEEDED
        finally:
            finished = self._time()
            duration = (
                max(0.0, finished - started)
                if started is not None and finished is not None else 0.0
            )
            self._record_io(boundary, outcome, correlation, duration, logger)

    def record(
        self, boundary: str, status: str, *, kind: str = "none",
        classification: str = "none", binding: ArtifactBinding | None = None,
        size: int = 0, duration: float = 0.0,
        error: SafeError | None = None, input_binding: str | None = None,
    ) -> None:
        """Emit each metric/log pair together; IDs are log-only, never labels."""
        metric = _METRICS[boundary]
        category = "none" if status == "succeeded" else (
            "cleanup" if boundary == _CLEANUP else "rendering"
        )
        reason = "none" if status == "succeeded" else (
            "cleanup-failed" if boundary == _CLEANUP else "output-rejected"
        )
        if error is not None:
            category, reason = error.category.value, error.reason.value
        dimensions = {
            "kind": kind, "classification": classification, "status": status,
            "error_category": category, "reason": reason,
            "stage": _UNHANDLED if category == "execution" else
            "finalize" if boundary == _CLEANUP else "publish",
        }
        correlation = {} if binding is None else {
            "operation_id": binding.effect.plan.operation_id,
            "step_id": binding.effect.step_id, "target_id": binding.effect.target_id,
            "context_id": binding.effect.plan.context_digest,
        }
        if input_binding is not None:
            correlation["input_binding"] = input_binding
        try:
            with self._lock:
                self._counts[(boundary, status, kind, classification, category, reason)] += 1
                self._logger.info(boundary, extra={
                    "metric": metric, "metric_dimensions": dimensions, **dimensions, **correlation,
                    "duration": duration, "bytes": size,
                    "next_action": error.next_action if error is not None else
                    "none" if status == "succeeded" else
                    "Inspect the exact owned manifest and retain the original failure.",
                })
        except BaseException:
            # Telemetry is not effect authority; never retry a partially emitted pair.
            return

    def counters(self) -> tuple[tuple[str, str, str, str, str, str, int], ...]:
        """Return detached low-cardinality totals, never admission facts."""
        with self._lock:
            return tuple((*key, count) for key, count in sorted(self._counts.items()))
