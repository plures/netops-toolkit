"""Original C01 normative producer error categories and stages, not labels."""

from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from tests.test_c01_independent_nov17 import environment as environment
from tests.test_c01_independent_nov17 import hydrated, input_source, request


@pytest.mark.parametrize(("producer", "reason", "category", "stage"), (
    ("route", c.ReasonCode.ROUTE_UNAVAILABLE, c.ErrorCategory.TRANSPORT, c.Stage.CONNECT),
    ("readiness", c.ReasonCode.DEPENDENCY_NOT_READY, c.ErrorCategory.DEPENDENCY, c.Stage.READINESS),
))
def test_preview_error_producer_uses_frozen_original_matrix(environment, producer, reason,
                                                          category, stage):
    service, context, _ = environment
    if producer == "route":
        req, loaded = hydrated(request(context))
    else:
        req, loaded = hydrated(
            replace(request(context, "config.apply"), mode=c.Mode.APPLY),
            input_source("intent", {}),
        )
    plan = service.preview(req, loaded)
    failures = tuple(error for error in plan.preconditions if error.reason == reason)
    assert failures
    assert all((error.category, error.stage) == (category, stage) for error in failures)
    assert all(error.next_action for error in failures)
    assert plan.native_payload["execution_performed"] is False
