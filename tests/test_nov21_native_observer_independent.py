"""Coarse native diagnostics cannot become a new operation failure boundary."""

from types import SimpleNamespace

import pytest

from netops.dependencies import _composition


class Clock:
    def monotonic(self):
        return 10.0


class Cancel:
    def is_cancelled(self):
        return False


@pytest.mark.parametrize("boundary", ["clock", "cancel", "sink", "observer-clock"])
@pytest.mark.parametrize("operation_fails", [False, True])
def test_ac011_native_diagnostic_fault_cannot_prevent_or_replace_primary_operation(
    monkeypatch, boundary, operation_fails,
):
    clock, cancel = Clock(), Cancel()
    primary = RuntimeError("SOURCE-only primary operation") if operation_fails else None
    diagnostic = OSError("SOURCE-only diagnostic failure")
    entered, errors = [], []

    def unavailable(*args, **kwargs):
        raise diagnostic

    if boundary == "clock":
        monkeypatch.setattr(clock, "monotonic", unavailable)
    elif boundary == "cancel":
        monkeypatch.setattr(cancel, "is_cancelled", unavailable)
    elif boundary == "sink":
        monkeypatch.setattr(_composition._NATIVE_LOG, "debug", unavailable)
    else:
        monkeypatch.setattr(_composition, "time", SimpleNamespace(monotonic=unavailable))
    try:
        with _composition._native_phase("cas-owned-tree", clock, cancel, 20.0):
            entered.append("real-operation-boundary")
            if primary is not None:
                raise primary
    except BaseException as error:
        errors.append(error)
    assert entered == ["real-operation-boundary"]
    assert errors == ([primary] if primary is not None else [])
