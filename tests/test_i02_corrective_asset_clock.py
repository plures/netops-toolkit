"""Post-entry clock and live-authority controls with real private broker permits."""

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import AuthorizationError
from netops.dependencies._assets import AssetResponse, _MonotonicClock
from netops.dependencies.service import DependencyRegistry
from tests.policy.test_lifecycle_execution import DATA
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_assets import URL, WaitingCancel, admitted


@pytest.mark.parametrize("bad", (5.0, -1.0, float("nan"), float("inf")))
def test_post_entry_bad_clock_revokes_without_transport(tmp_path, policy, bad):
    acquisition, lock, permit, invocation, transport, *_ = admitted(tmp_path, policy, ())
    clock = acquisition._clock
    reads = iter((10.0, bad, 10.0))
    clock.monotonic = lambda: next(reads)
    with pytest.raises((c.ContractError, AuthorizationError)):
        acquisition.download(
            DependencyRegistry.load().entry("paramiko"), lock, permit, invocation, WaitingCancel(),
        )
    assert not transport.calls
    assert (invocation.lifecycle.kind, invocation.lifecycle.plan_id) in acquisition._authorization._life_revoked


@pytest.mark.parametrize("phase", ("retry", "post-response"))
def test_clock_rollback_never_enters_another_transport_or_returns_verified_bytes(tmp_path, policy, phase):
    acquisition, lock, permit, invocation, transport, *_ = admitted(tmp_path, policy, ())
    clock = acquisition._clock
    calls = []

    def read(url, timeout, limit):
        calls.append(timeout)
        clock.value = 5.0
        if phase == "retry":
            raise ConnectionError()
        return AssetResponse(URL, DATA)

    transport.read = read
    with pytest.raises((c.ContractError, AuthorizationError)):
        acquisition.download(
            DependencyRegistry.load().entry("paramiko"), lock, permit, invocation, WaitingCancel(),
        )
    assert calls == [20.0]
    assert (invocation.lifecycle.kind, invocation.lifecycle.plan_id) in acquisition._authorization._life_revoked


def test_revocation_during_retry_delay_blocks_second_transport(tmp_path, policy):
    acquisition, lock, permit, invocation, transport, *_ = admitted(
        tmp_path, policy, (ConnectionError(), AssetResponse(URL, DATA)),
    )

    class RevokeDuringWait(WaitingCancel):
        def wait(self, timeout):
            acquisition._authorization.revoke_lifecycle(invocation.lifecycle.kind, invocation.lifecycle.plan_id)
            return False

    with pytest.raises(AuthorizationError):
        acquisition.download(
            DependencyRegistry.load().entry("paramiko"), lock, permit, invocation, RevokeDuringWait(),
        )
    assert len(transport.calls) == 1


def test_clock_failure_remains_latched_even_if_subsequent_read_recovers():
    class Clock:
        readings = iter((10.0, 5.0, 12.0))

        def monotonic(self):
            return next(self.readings)

    observed = _MonotonicClock(Clock())
    assert observed.monotonic() == 10.0
    with pytest.raises(c.ContractError):
        observed.monotonic()
    with pytest.raises(c.ContractError):
        observed.monotonic()


def test_live_authority_rechecks_hold_the_original_broker_lock(tmp_path, policy, monkeypatch):
    acquisition, lock, permit, invocation, transport, state, _ = admitted(
        tmp_path, policy, (AssetResponse(URL, DATA),),
    )
    broker = acquisition._authorization
    inner = broker._lock
    depth = [0]

    class TrackedBrokerLock:
        def __enter__(self):
            inner.__enter__()
            depth[0] += 1
            return self

        def __exit__(self, *args):
            depth[0] -= 1
            return inner.__exit__(*args)

    original = state.snapshot_lifecycle

    def snapshot(binding):
        assert depth[0] > 0
        return original(binding)

    monkeypatch.setattr(broker, "_lock", TrackedBrokerLock())
    monkeypatch.setattr(state, "snapshot_lifecycle", snapshot)
    result = acquisition.download(
        DependencyRegistry.load().entry("paramiko"), lock, permit, invocation, WaitingCancel(),
    )
    assert result.content == DATA and len(transport.calls) == 1
