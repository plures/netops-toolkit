"""Actual-host cancellation must signal before a stalled resolver's broker lock."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

from netops.ansible import contracts as c
from tests.test_controller_backend_integration import composed as composed
from tests.test_controller_backend_integration import integrated as integrated
from tests.test_controller_backend_integration import policy as policy


def test_cancel_signals_actual_host_while_credential_preparation_holds_broker(
    integrated, monkeypatch, record_property,
):
    service, host, request, _, process, credentials, vault = integrated
    grant = host.review(service, request)
    entered, release, requested = threading.Event(), threading.Event(), threading.Event()
    native_session = vault.private_session
    timing = {}

    @contextmanager
    def blocked_native_reader():
        entered.set()
        if not release.wait(5.0):
            raise RuntimeError("synthetic-vault-read-timeout")
        with native_session() as reader:
            yield reader

    monkeypatch.setattr(vault, "private_session", blocked_native_reader)

    def stop():
        timing["received"] = time.perf_counter()
        requested.set()
        return service.cancel(request.operation_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        executing = pool.submit(service.execute, request, grant)
        assert entered.wait(3.0)
        cancelling = pool.submit(stop)
        try:
            assert requested.wait(1.0)
            signalled = host._cancellations[request.operation_id]._signal.wait(0.5)
            timing["observed"] = time.perf_counter()
            # The broker is genuinely still held by the native resolver, not
            # replaced with a fake permissive admission or released for cancel.
            assert not cancelling.done()
        finally:
            release.set()
        result = executing.result(timeout=5.0)
        receipt = cancelling.result(timeout=5.0)
    assert signalled, "accepted cancel waited behind resolver before signalling actual host"
    assert timing["observed"] - timing["received"] < 2.0
    assert receipt.accepted and host.authorization.is_revoked(request.operation_id)
    assert result.status != c.OutcomeStatus.SUCCEEDED
    assert process.runs == [] and credentials._resolvers == {}
    record_property("fake_preparation_cancel_received_perf_seconds", timing["received"])
    record_property("fake_preparation_signal_observed_perf_seconds", timing["observed"])
    record_property("fake_preparation_stop_seconds", timing["observed"] - timing["received"])
