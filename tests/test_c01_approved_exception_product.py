"""Product regressions for contextual SNMP syntax and diagnostic producers."""

import json
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.change.diff import diff_configs, format_json
from tests.test_workflow_contracts import operation_request as operation_request
from tests.test_workflow_contracts import policy as policy
from tests.test_workflow_contracts import service as service
from tests.test_workflow_contracts import source, with_sources


@pytest.mark.parametrize("command", (
    "snmp-server enable traps snmp authentication linkdown linkup",
    "snmp-server enable traps snmp authentication-failure",
    "NO SNMP-SERVER ENABLE TRAPS SNMP AUTHENTICATION",
))
def test_notification_selector_preserves_native_comparison(operation_request, service, command):
    before, after = "hostname before\n", command + "\nhostname after\n"
    request, loaded = with_sources(
        replace(operation_request, operation="compare.compare"),
        source("before", before.encode(), "text"),
        source("after", after.encode(), "text"),
    )
    plan = service.preview(request, loaded)
    assert c.wire(plan.native_payload["native_payload"]) == json.loads(
        format_json(diff_configs(before, after)),
    )
    assert plan.native_payload["execution_performed"] is False


@pytest.mark.parametrize(("operation", "reason", "category", "stage", "inputs"), (
    ("health.gather", "route-unavailable", "transport", "connect", ()),
    ("health.gather", "dependency-not-ready", "dependency", "readiness", ()),
    ("config.apply", "observation-required", "precondition", "authorize", ("intent",)),
    ("config.apply", "consent-required", "platform", "provision", ("intent",)),
    ("config.backup", "output-rejected", "rendering", "publish", ()),
))
def test_real_preview_producers_use_original_error_rows(
    operation_request, service, operation, reason, category, stage, inputs,
):
    request, loaded = with_sources(
        replace(operation_request, operation=operation),
        *(source(kind) for kind in inputs),
    )
    errors = tuple(error for error in service.preview(request, loaded).preconditions
                   if error.reason.value == reason)
    assert errors
    assert all((error.category.value, error.stage.value) == (category, stage) for error in errors)
    assert all(error.next_action for error in errors)


def test_dependency_error_mapping_is_shared_with_blocked_execute(operation_request, service):
    request, loaded = with_sources(operation_request)
    preview_errors = service.preview(request, loaded).preconditions
    execution_errors = service.execute(request).errors
    preview = next(error for error in preview_errors if error.reason.value == "dependency-not-ready")
    execution = next(error for error in execution_errors if error.reason.value == "dependency-not-ready")
    assert c.canonical_bytes(preview) == c.canonical_bytes(execution)
