"""AC001/011/014: exact deadline safety, not platform qualification."""

import logging
from unittest.mock import Mock

import pytest

from netops.ansible import contracts as c
from netops.dependencies import RegistryError
from tests.test_dependency_probes import policy as policy
from tests.test_dependency_probes import service_and_context


@pytest.mark.parametrize("phase", ["before-probe", "late-probe", "late-policy"])
def test_exact_sixty_second_exhaustion_blocks_and_drops_cached_readiness(policy, caplog, phase):
    service, context, adapter, events = service_and_context(policy)
    scope = c.InstallScope(("native.scan:skip-ping-and-snmp",), (), False, False)
    now = [0.0]
    service.clock.monotonic.side_effect = lambda: now[0]
    original_probe = adapter.probe
    original_policy = service.policy
    decisions = []

    def probe(*args):
        result = original_probe(*args)
        if phase == "late-probe":
            now[0] = 60.0
        return result

    def decide(*args):
        decisions.append(args)
        result = original_policy.decide(*args)
        if phase == "late-policy":
            now[0] = 60.0
        return result

    adapter.probe = probe
    service.policy = Mock(decide=decide)
    if phase == "before-probe":
        samples = iter([0.0] + [60.0] * 30)
        service.clock.monotonic.side_effect = lambda: next(samples)
    with caplog.at_level(logging.INFO):
        report = service.verify(scope, context)
    assert report.readiness.native == "blocked"
    assert report.readiness.companion == report.readiness.enhanced == "not-requested"
    assert report.capabilities[-1]["reason"] == "deadline-exceeded"
    assert not service._observed
    assert len(decisions) == (1 if phase == "late-policy" else 0)
    assert len(adapter.calls) == (0 if phase == "before-probe" else 1)
    if adapter.calls:
        assert adapter.calls[0][2] == 5.0
    observations = [r for r in caplog.records
                    if getattr(r, "metric_name", "") == "netops.dependency.probe.count"]
    assert len(observations) == events.emit.call_count == 1
    assert observations[0].metric_value == 1
    service.authorization.assert_not_called()
    service.state.assert_not_called()


@pytest.mark.parametrize("boundary", ["adapter", "policy"])
def test_primary_defect_is_not_hidden_as_deadline_non_success(policy, boundary):
    service, context, adapter, _ = service_and_context(policy)
    service.clock.monotonic.return_value = 0.0
    service.clock.monotonic.side_effect = None
    defect = RuntimeError("independent-primary-defect")
    if boundary == "adapter":
        adapter.probe = Mock(side_effect=defect)
    else:
        service.policy = Mock(decide=Mock(side_effect=defect))
    with pytest.raises(RuntimeError) as caught:
        service.verify(c.InstallScope(("native.scan:skip-ping-and-snmp",), (), False, False),
                       context)
    assert caught.value is defect


@pytest.mark.parametrize("sample", [-1.0, float("nan"), float("inf"), 1])
def test_invalid_clock_is_contract_failure_not_extra_budget(policy, sample):
    service, context, _, _ = service_and_context(policy)
    service.clock.monotonic.side_effect = None
    service.clock.monotonic.return_value = sample
    with pytest.raises(RegistryError, match="clock-invalid"):
        service.verify(c.InstallScope(("native.scan:skip-ping-and-snmp",), (), False, False),
                       context)
