"""Literal consumed wire/CLI contracts; synthetic identity is not qualification."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import PolicyIdentity
from netops.report import generator

OP = "60000000-0000-4000-8000-000000000006"
D = "1111111111111111111111111111111111111111111111111111111111111111"
PIN = "6d367fe673756dabaa6085bc6b5202debaaabe6f"

EXPECTED_REQUEST = (
    b'{"context":{"assets_digest":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"controller_id":"native-fixture","mapping_digest":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"policy_identity":{"bundle_sha256":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"canonical_revision":"6d367fe673756dabaa6085bc6b5202debaaabe6f",'
    b'"contracts_sha256":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"numeric_profile":"exact-int53-finite-order-v1","profile":"netops-reference-v1",'
    b'"reducer_version":"1","rule_manifest":["fixture.rule"],"schema":"1.0",'
    b'"source_sha256":"1111111111111111111111111111111111111111111111111111111111111111"},'
    b'"registry_digest":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"route_digest":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"source_id":"native-fixture"},"inputs":[],"mode":"preview","operation":"report.aggregate",'
    b'"operation_id":"60000000-0000-4000-8000-000000000006",'
    b'"output_intent":{"git":false,"kinds":[],"overwrite":"reject","retention":false,"root_ref":null},'
    b'"plan_digest":null,"schema_version":"1.0","scope":{"exclusions":[],"limit":100,"target_ids":[]}}'
)
EXPECTED_RESPONSE = (
    b'{"artifacts":[],"changed":false,"cleanup":{"errors":[],"remaining_refs":[],"status":"not-requested"},'
    b'"errors":[],"executed_mode":null,"findings":[],"operation_id":"60000000-0000-4000-8000-000000000006",'
    b'"provenance":{},"readiness":{"companion":"blocked","enhanced":"not-requested","errors":[],"native":"blocked"},'
    b'"requested_mode":"preview","schema_version":"1.0","status":"blocked","steps":[],"targets":[]}'
)


def test_consumed_full_operation_request_has_exact_literal_wire():
    identity = PolicyIdentity(PIN, D, D, D, ("fixture.rule",), "1")
    request = c.OperationRequest(
        OP, "report.aggregate", c.Mode.PREVIEW, c.Scope(()),
        c.Context("native-fixture", D, "native-fixture", D, identity, D, D),
    )
    assert c.canonical_bytes(request) == EXPECTED_REQUEST
    assert c.OperationRequest.from_json(EXPECTED_REQUEST) == request


def test_consumed_full_operation_response_has_exact_literal_wire():
    outcome = c.OperationOutcome(
        OP, c.Mode.PREVIEW, None, c.ReadinessProjection(), (), (), c.OutcomeStatus.BLOCKED,
        False, (), (), (), c.CleanupOutcome(), c.public_object({}),
    )
    assert c.canonical_bytes(outcome) == EXPECTED_RESPONSE
    assert c.OperationOutcome.from_json(EXPECTED_RESPONSE) == outcome
    assert outcome.exit_code == 3


@pytest.mark.parametrize("field", ["schema_version", "requested_mode", "executed_mode", "status"])
def test_consumed_response_unknown_schema_mode_status_is_not_success(field):
    value = json.loads(EXPECTED_RESPONSE)
    value[field] = "99.0" if field == "schema_version" else "unknown-value"
    with pytest.raises(c.ContractError):
        c.OperationOutcome.from_json(json.dumps(value).encode())


def test_report_cli_literal_help_matches_documented_input_output_preview(capsys):
    with pytest.raises(SystemExit) as caught:
        generator.main(["--help"])
    assert caught.value.code == 0
    help_text = capsys.readouterr().out
    assert "--input" in help_text and "--preview" in help_text
    assert "--output" in help_text
    assert "--format" in help_text


def test_report_native_api_and_documented_cli_do_not_drift():
    import inspect

    assert str(inspect.signature(generator.main)) == (
        "(argv: 'list[str] | None' = None) -> 'int'"
    )
    parameters = inspect.signature(generator.ReportGenerator.generate_html).parameters
    assert tuple(parameters) == ("self", "report_data", "output_path")
    reference = (Path(__file__).resolve().parents[1] / "docs/api/report.md").read_text(encoding="utf-8")
    assert "--input" in reference and "--preview" in reference
    assert "does not define a command-line" not in reference
