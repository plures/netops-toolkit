"""Independent actual thread/store drain ownership, no controller qualification."""
from __future__ import annotations

import threading
import time

from netops.ansible import contracts as c
from netops.ansible.controller_control import _Stop
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_nov19_independent_controller_execution import Cancel
from tests.test_nov20_successor_controller_generation import launch_for, source_case


def test_t04_same_host_actual_join_and_adapter_release_leave_drain_successful(tmp_path, policy):
    _, context, _, runs, installed, process, adapter = source_case(tmp_path, policy)
    stop = _Stop(Cancel())
    entered = threading.Event()
    results = []
    primary = c.SafeError(
        c.ErrorCategory.EXECUTION, c.ReasonCode.CANCELLED, c.Stage.CONTROLLER,
    )
    process.error = primary

    def actual_join_after_cancel():
        entered.set()
        assert stop._event.wait(3.0)

    process.inspect = actual_join_after_cancel
    thread = threading.Thread(target=lambda: results.append(adapter.run(
        launch_for(context, installed), b"independent-source-only-private-frame", stop,
    )))
    thread.start()
    try:
        assert entered.wait(3.0)
        assert runs.pins()[0]["holders"]
        clock = type("RealClock", (), {"monotonic": lambda self: time.monotonic()})()
        drained = runs.drain(Cancel(), clock, time.monotonic() + 3.0)
    finally:
        stop.stop(c.ReasonCode.CANCELLED)
        thread.join(4.0)
    assert not thread.is_alive() and len(results) == 1
    assert results[0].error is primary and results[0].cleanup == c.CleanupOutcome("succeeded")
    assert runs.pins()[0]["holders"] == ()
    assert drained is True, "A genuinely joined, already released same-host holder is not a crash blocker"
