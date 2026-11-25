"""Paired bounded process/worker I/O observations with non-authoritative sinks."""

from __future__ import annotations

import hashlib
import logging
import math
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from . import contracts as c
from .controller_protocol import ProtocolError

_EVENT = "controller.io"
_METRIC = "netops.controller.io.count"
_DURATION_METRIC = "netops.controller.io.duration_seconds"
_IO_NEXT_ACTION = "Inspect the exact owned boundary and current authority; do not replay issued work."
_BOUNDARIES = frozenset((
    "process.verify", "process.launch", "process.readiness", "process.input",
    "process.control", "process.teardown", "worker.input", "worker.ready",
    "worker.broker", "worker.launch", "worker.auth", "worker.wait",
    "worker.cleanup", "worker.result", "broker.dispatch", "broker.pulse",
    "broker.content", "broker.channel", "action.channel", "action.native",
    "action.connect", "action.close", "action.read", "action.write", "action.mutation",
    "backend.cleanup", "process.proof", "process.cancel", "worker.group",
    "worker.control", "worker.startup", "worker.verify", "worker.exit",
))


class _ControllerIo:
    """Keep metric/log pairing in one helper; observations never grant authority."""

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)
        self._lock = threading.Lock()
        self.counts: Counter[tuple[str, str, str, str]] = Counter()
        self.durations: dict[tuple[str, str, str, str], float] = {}
        self.sink_failures = 0

    @staticmethod
    def _time() -> float:
        try:
            now = time.perf_counter()
            return now if math.isfinite(now) and now >= 0 else 0.0
        except BaseException:
            return 0.0

    def _record(
        self, boundary: str, outcome: str, duration: float,
        operation: str, context: str, reason: c.ReasonCode | None = None,
        *, unhandled: bool = False, target: str = "none", step: str = "none",
    ) -> None:
        # All values are host/worker-selected constants. Never include a
        # credential, native result, raw exception or attacker-controlled label.
        if boundary not in _BOUNDARIES or outcome not in ("started", "succeeded", "failed"):
            return
        stage = "Unhandled" if unhandled else boundary.split(".", 1)[0]
        selected_reason = reason.value if reason is not None else "none"
        category = (
            c.ErrorCategory.CLEANUP if boundary in (
                "process.teardown", "worker.cleanup", "worker.group", "action.close", "backend.cleanup",
            ) else (
                c.ErrorCategory.DEPENDENCY if boundary == "process.verify"
                else c.ErrorCategory.EXECUTION
            )
        )
        dimensions = {
            "boundary": boundary, "outcome": outcome, "stage": stage, "reason": selected_reason,
        }
        duration = max(0.0, duration) if math.isfinite(duration) else 0.0
        try:
            key = (boundary, outcome, stage, selected_reason)
            with self._lock:
                self.counts[key] += 1
                self.durations[key] = self.durations.get(key, 0.0) + duration
            self._logger.info(_EVENT, extra={
                "metric": _METRIC, "metric_value": 1,
                "duration_metric": _DURATION_METRIC, "duration": duration,
                "metric_dimensions": dimensions, **dimensions,
                "operation_ref": "sha256:" + hashlib.sha256(operation.encode("utf-8")).hexdigest(),
                "context_ref": "sha256:" + hashlib.sha256(context.encode("utf-8")).hexdigest(),
                "target_ref": "sha256:" + hashlib.sha256(target.encode("utf-8")).hexdigest(),
                "step_ref": "sha256:" + hashlib.sha256(step.encode("utf-8")).hexdigest(),
                "category": category.value if outcome == "failed" else "none",
                "next_action": _IO_NEXT_ACTION if outcome == "failed" else "none",
            })
        except BaseException:
            with self._lock:
                self.sink_failures += 1

    @contextmanager
    def span(
        self, boundary: str, operation: str = "none", context: str = "none",
        *, target: str = "none", step: str = "none",
    ) -> Iterator[None]:
        started = self._time()
        self._record(boundary, "started", 0.0, operation, context, target=target, step=step)
        try:
            yield
        except BaseException as error:
            self._record(
                boundary, "failed", self._time() - started, operation, context,
                error.reason if type(error) is ProtocolError else c.ReasonCode.HANDOFF_INVALID,
                unhandled=type(error) is not ProtocolError,
                target=target, step=step,
            )
            raise
        else:
            self._record(
                boundary, "succeeded", self._time() - started, operation, context,
                target=target, step=step,
            )

    def cleanup(
        self, boundary: str, operation: str, action: Callable[[], c.CleanupOutcome],
    ) -> c.CleanupOutcome:
        """Pair factual returned cleanup failures, not just thrown exceptions."""
        started = self._time()
        self._record(boundary, "started", 0.0, operation, "none")
        try:
            result = action()
        except BaseException as error:
            self._record(
                boundary, "failed", self._time() - started, operation, "none",
                error.reason if type(error) is ProtocolError else c.ReasonCode.CLEANUP_FAILED,
                unhandled=type(error) is not ProtocolError,
            )
            raise
        self._record(
            boundary, "failed" if result.status == "failed" else "succeeded",
            self._time() - started, operation, "none",
            c.ReasonCode.CLEANUP_FAILED if result.status == "failed" else None,
        )
        return result
