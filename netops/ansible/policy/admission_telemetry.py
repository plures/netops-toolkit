"""Paired, safe local lifecycle-admission rejection observations."""

from __future__ import annotations

import logging
import threading
from collections import Counter

_METRIC = "policy_decisions_total"
_LOG = "policy.rejected"
_STAGE = "lifecycle-admission"
_OUTCOME = "Rejected"
_KINDS = ("install", "uninstall", "restore", "unknown")
_CAUSES = ("consent-stale", "policy-input-invalid", "evidence-mismatch")


class LifecycleAdmissionTelemetry:
    """Local counter and structured log, emitted only together from one helper.

    Hosts may read the detached counters for their existing metrics exporter.
    No exporter or logging configuration is initialized here.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._counts: Counter[tuple[str, str]] = Counter()
        self._logger = logging.getLogger(__name__)

    def rejected(self, kind: str, cause: str) -> None:
        """Record one rejection without rendering supplied values or exceptions."""
        safe_kind = kind if type(kind) is str and kind in _KINDS else "unknown"
        safe_cause = cause if type(cause) is str and cause in _CAUSES else "consent-stale"
        with self._lock:
            self._counts[(safe_kind, safe_cause)] += 1
            self._logger.warning(_LOG, extra={
                "metric": _METRIC, "outcome": _OUTCOME, "stage": _STAGE,
                "kind": safe_kind, "cause": safe_cause,
            })

    def counters(self) -> tuple[tuple[str, str, int], ...]:
        """Return safe kind/cause totals; never use these as admission facts."""
        with self._lock:
            return tuple((kind, cause, count) for (kind, cause), count in sorted(self._counts.items()))
