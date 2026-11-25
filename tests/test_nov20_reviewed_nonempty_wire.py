"""Independent nonempty public contract examples; no serialized private authority."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from unittest.mock import Mock

from netops.ansible import contracts as c
from netops.ansible.policy import PolicyIdentity
from netops.ansible.policy.contracts import DecisionResult
from netops.ansible.workflows import WorkflowService, hydrate_inputs
from netops.report.companion import project_outcome
from tests.test_companion_compare import bound, input_source
from tests.test_companion_compare import pure_composition as pure_composition

OP = "60000000-0000-4000-8000-000000000006"
D = "1111111111111111111111111111111111111111111111111111111111111111"
PIN = "6d367fe673756dabaa6085bc6b5202debaaabe6f"
CONTEXT = (
    b'{"assets_digest":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"controller_id":"native-fixture","mapping_digest":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"policy_identity":{"bundle_sha256":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"canonical_revision":"6d367fe673756dabaa6085bc6b5202debaaabe6f",'
    b'"contracts_sha256":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"numeric_profile":"exact-int53-finite-order-v1","profile":"netops-reference-v1",'
    b'"reducer_version":"1","rule_manifest":["fixture.rule"],"schema":"1.0",'
    b'"source_sha256":"1111111111111111111111111111111111111111111111111111111111111111"},'
    b'"registry_digest":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"route_digest":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"source_id":"native-fixture"}'
)
OUTPUT = b'{"git":false,"kinds":["html"],"overwrite":"reject","retention":false,"root_ref":"owned-output"}'
EXPECTED_REQUEST = (
    b'{"context":' + CONTEXT
    + b',"inputs":[{"digest":"1111111111111111111111111111111111111111111111111111111111111111","kind":"outcomes","ref":"saved-outcomes"}],'
    b'"mode":"output","operation":"report.render","operation_id":"60000000-0000-4000-8000-000000000006",'
    b'"output_intent":' + OUTPUT
    + b',"plan_digest":null,"schema_version":"1.0","scope":{"exclusions":["192.0.2.0/24"],"limit":100,"target_ids":["r1","r2"]}}'
)
EXPECTED_CATALOG = (
    b'{"capabilities":['
    b'{"area":"scan","effects":["scan"],"modes":["preview","check","observe"],"network":true,"observation_required":false,"operation":"discover","required_inputs":[]},'
    b'{"area":"scan","effects":[],"modes":["preview","check"],"network":false,"observation_required":false,"operation":"inventory-preview","required_inputs":["inventory","fragment"]},'
    b'{"area":"scan","effects":["save"],"modes":["preview","check","output"],"network":false,"observation_required":false,"operation":"save","required_inputs":[]},'
    b'{"area":"inventory","effects":[],"modes":["preview","check"],"network":false,"observation_required":false,"operation":"validate","required_inputs":["inventory"]},'
    b'{"area":"inventory","effects":["export"],"modes":["preview","check","output"],"network":false,"observation_required":false,"operation":"export","required_inputs":["inventory"]},'
    b'{"area":"inventory","effects":["refresh"],"modes":["preview","check","observe"],"network":false,"observation_required":false,"operation":"refresh","required_inputs":["inventory"]},'
    b'{"area":"vault","effects":[],"modes":["preview","check"],"network":false,"observation_required":false,"operation":"preflight","required_inputs":[]},'
    b'{"area":"vault","effects":["resolve-for-run"],"modes":["preview","check","observe"],"network":false,"observation_required":false,"operation":"resolve-for-run","required_inputs":[]},'
    b'{"area":"config","effects":["collect"],"modes":["preview","check","observe"],"network":true,"observation_required":false,"operation":"collect","required_inputs":[]},'
    b'{"area":"config","effects":["collect","backup"],"modes":["preview","check","observe","output"],"network":true,"observation_required":false,"operation":"backup","required_inputs":[]},'
    b'{"area":"config","effects":[],"modes":["preview","check"],"network":false,"observation_required":true,"operation":"plan","required_inputs":["intent"]},'
    b'{"area":"config","effects":["apply"],"modes":["preview","check","apply"],"network":true,"observation_required":true,"operation":"apply","required_inputs":["intent"]},'
    b'{"area":"config","effects":["rollback"],"modes":["preview","check","rollback"],"network":true,"observation_required":true,"operation":"rollback","required_inputs":["intent"]},'
    b'{"area":"health","effects":["gather"],"modes":["preview","check","observe"],"network":true,"observation_required":false,"operation":"gather","required_inputs":[]},'
    b'{"area":"health","effects":[],"modes":["preview","check"],"network":false,"observation_required":true,"operation":"evaluate","required_inputs":[]},'
    b'{"area":"compare","effects":[],"modes":["preview","check"],"network":false,"observation_required":false,"operation":"compare","required_inputs":["before","after"]},'
    b'{"area":"compare","effects":[],"modes":["preview","check"],"network":false,"observation_required":false,"operation":"remediation-preview","required_inputs":["findings"]},'
    b'{"area":"compare","effects":["save"],"modes":["preview","check","output"],"network":false,"observation_required":false,"operation":"generate","required_inputs":["findings"]},'
    b'{"area":"report","effects":[],"modes":["preview","check"],"network":false,"observation_required":false,"operation":"aggregate","required_inputs":["outcomes"]},'
    b'{"area":"report","effects":["render"],"modes":["preview","check","output"],"network":false,"observation_required":false,"operation":"render","required_inputs":["outcomes"]}],'
    b'"next_action":"Obtain consuming-context dependency and controller qualification before execution.",'
    b'"qualification":"unqualified","schema_version":"1.0"}'
)
EXPECTED_OUTCOME = (
    b'{"artifacts":[{"digest":"1111111111111111111111111111111111111111111111111111111111111111","media_type":"text/html","ref":"owned-output/report.html","size":42}],'
    b'"changed":true,"cleanup":{"errors":[],"remaining_refs":[],"status":"not-requested"},'
    b'"errors":[],"executed_mode":"output","findings":[],"operation_id":"60000000-0000-4000-8000-000000000006",'
    b'"provenance":{"execution_performed":true,"source":"saved-outcomes"},'
    b'"readiness":{"companion":"not-requested","enhanced":"not-requested","errors":[],"native":"ready"},'
    b'"requested_mode":"output","schema_version":"1.0","status":"partial",'
    b'"steps":[{"attempted":true,"changed":true,"errors":[],"findings":[],"native_payload":{"rendered":true},"remote_state":"unchanged","selected":true,"status":"succeeded","step_id":"render","unapplied_effects":[]}],'
    b'"targets":[{"attempted":true,"changed":true,"errors":[],"findings":[],"native_payload":{"count":1},"remote_state":"unchanged","selected":true,"status":"succeeded","target_id":"r1","unapplied_effects":[]},'
    b'{"attempted":false,"changed":false,"errors":[],"findings":[],"native_payload":{},"remote_state":"unchanged","selected":true,"status":"blocked","target_id":"r2","unapplied_effects":["render"]}]}'
)
R1_COVERAGE = (
    b'{"attempted":true,"changed":true,"errors":[],"findings":[],"remote_state":"unchanged",'
    b'"status":"succeeded","target_id":"r1","unapplied_effects":[]}'
)
R2_COVERAGE = (
    b'{"attempted":false,"changed":false,"errors":[],"findings":[],"remote_state":"unchanged",'
    b'"status":"blocked","target_id":"r2","unapplied_effects":["render"]}'
)
EXPECTED_REPORT = (
    b'{"changed":true,"cleanup":{"errors":[],"remaining_count":0,"remaining_refs":[],"status":"not-requested"},'
    b'"counts":{"blocked":1,"cancelled":0,"failed":0,"not-requested":0,"partial":0,"succeeded":1,"unsupported":0},'
    b'"coverage":[' + R1_COVERAGE + b',' + R2_COVERAGE + b'],"coverage_complete":true,'
    b'"errors":[],"execution_performed":false,"findings":[],"missing_count":0,"overall_alert":true,'
    b'"readiness":{"companion":"not-requested","enhanced":"not-requested","errors":[],"native":"ready"},'
    b'"remote_uncertain":false,"schema_version":"1.0","selected_count":2,"source_executed_mode":"output",'
    b'"source_exit_code":4,"source_operation_id":"60000000-0000-4000-8000-000000000006",'
    b'"source_requested_mode":"output","source_status":"partial",'
    b'"steps":[{"attempted":true,"changed":true,"errors":[],"remote_state":"unchanged","selected":true,"status":"succeeded","step_id":"render","unapplied_effects":[]}],'
    b'"targets":[' + R1_COVERAGE + b',' + R2_COVERAGE + b']}'
)
EXPECTED_SETTINGS = (
    b'{"NETOPS_INVENTORY":null,"NETOPS_INVENTORY_CACHE":null,"NETOPS_LOG_DIR":null,'
    b'"NETOPS_LOG_SETTINGS":null,"NETOPS_STATE_ROOT":null,"NETOPS_TUI_SETTINGS":null,"NETOPS_VAULT":null,'
    b'"ansible":{"enabled":false,"enhanced":false,"mode":"audit"},'
    b'"authorization":{"ttl_seconds":60},"backup":{"git":false,"retention_count":10},'
    b'"controller":{"id":null,"start_timeout_seconds":30,"wsl_distribution":null},'
    b'"diagnostics":{"retention_days":7},'
    b'"execution":{"ping_concurrency":50,"snmp_concurrency":10,"ssh_concurrency":5,"target_limit":100,"timeout_seconds":300},'
    b'"health":{"cpu_threshold":80.0,"memory_threshold":85.0},"inventory":{"cache_ttl_seconds":300},'
    b'"logging":{"level":"INFO","max_bytes":10485760},"observation":{"max_age_seconds":60},"schema":"1.0"}'
)
# Independently hash the literal examples using standard JSON/SHA-256 only.
# These are fixed bytes, not a dump/round-trip of WorkflowService output.
SOURCE_DIGEST = "a7b50da245e265ccd1fc5f227f3cd6c369fecd4d5f41352c0dc30af75c1b5ce1"
CONTEXT_DIGEST = "160cbac2ec0874d45ab7470974fee266d08b444dd5d2bc2ae8aec9a743ad7bd8"
REQUEST_DIGEST = "fd16f14e92d4adcedf83a4ee970b178002961962cdb200a14b8b214d81443d6c"
BINDING_DIGEST = "587909228842ee86967d69a34c9bb59ade1f5cac532aa29e5ca1fcfb58f03393"
PLAN_DIGEST = "ea65e5f9151630b1e3d91416d7645721ad1e5192b0243008a018ea52c29f8b43"
EXPECTED_OBSERVATIONS = (
    b'[{"age_ms":0.0,"content_digest":"' + SOURCE_DIGEST.encode()
    + b'","context_digest":"' + CONTEXT_DIGEST.encode()
    + b'","controller_id":"native-fixture","observation_id":"saved-r1","observed_at":"2026-11-20T06:30:00Z",'
    b'"route_digest":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"source":{"digest":"' + SOURCE_DIGEST.encode() + b'","kind":"outcomes","ref":"saved-outcomes"},"target_id":"r1"},'
    b'{"age_ms":0.0,"content_digest":"' + SOURCE_DIGEST.encode()
    + b'","context_digest":"' + CONTEXT_DIGEST.encode()
    + b'","controller_id":"native-fixture","observation_id":"saved-r2","observed_at":"2026-11-20T06:30:00Z",'
    b'"route_digest":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"source":{"digest":"' + SOURCE_DIGEST.encode() + b'","kind":"outcomes","ref":"saved-outcomes"},"target_id":"r2"}]'
)
EXPECTED_PLAN = (
    b'{"concurrency":5,"context":' + CONTEXT + b',"deadline_ms":300000,'
    b'"effects":[{"destination_ref":"owned-output","kind":"render","occurrence_id":"60000000-0000-4000-8000-000000000006:0","ordinal":0,"step_id":"render","target_id":"local"}],'
    b'"input_binding_digest":"' + BINDING_DIGEST.encode()
    + b'","native_payload":{"area":"report","execution_performed":false,"inputs":[{"digest":"'
    + SOURCE_DIGEST.encode() + b'","kind":"outcomes","ref":"saved-outcomes","value":'
    + EXPECTED_OUTCOME + b'}],"operation":"render","report":' + EXPECTED_REPORT + b'},'
    b'"observations":' + EXPECTED_OBSERVATIONS
    + b',"operation":"report.render","operation_id":"60000000-0000-4000-8000-000000000006","output_intent":'
    + OUTPUT + b',"plan_digest":"' + PLAN_DIGEST.encode()
    + b'","policy_digest":"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"preconditions":[{"category":"dependency","detail":"","next_action":"Complete qualified dependency and controller setup before execution.","reason":"dependency-not-ready","retryable":false,"stage":"readiness","step_id":null,"target_id":null},'
    b'{"category":"platform","detail":"","next_action":"Obtain consent for the exact planned effects.","reason":"consent-required","retryable":false,"stage":"provision","step_id":null,"target_id":null}],'
    b'"recovery_scope":[],"reducer_version":"1","request_digest":"' + REQUEST_DIGEST.encode()
    + b'","requested_mode":"output","routes":[{"resolved":false,"target_id":"r1"},{"resolved":false,"target_id":"r2"}],'
    b'"schema_version":"1.0","settings":' + EXPECTED_SETTINGS + b',"targets":["r1","r2"]}'
)
EXPECTED_GENERATED_NATIVE = (
    b'{"created_at":"2026-11-20T06:30:00Z","description":"Auto-generated remediation for r1: cpu_high",'
    b'"dry_run":true,"failure_types":["cpu_high"],"host":"r1",'
    b'"playbook_id":"60000000-0000-4000-8000-000000000006",'
    b'"plays":[{"gather_facts":false,"hosts":"r1","name":"Remediation playbook for r1 [cpu_high]",'
    b'"tasks":[{"ansible.builtin.pause":{"prompt":"Remediation plan for r1 is ready. Review the task list above and press Enter to proceed, Ctrl-C to abort."},'
    b'"name":"HUMAN-REVIEW: Pending human review before remediation","when":"not dry_run | bool"},'
    b'{"block":[{"cisco.ios.ios_command":{"commands":["show processes cpu sorted","show processes cpu history"]},'
    b'"name":"PRE-CHECK: Capture state for Investigate high CPU utilisation","register":"pre_cpu_high"},'
    b'{"ansible.builtin.debug":{"msg":"No automated remediation available. High CPU has no automated remediation. Escalate to NOC for manual investigation."},'
    b'"name":"REMEDIATE: Investigate high CPU utilisation"},'
    b'{"cisco.ios.ios_command":{"commands":["show processes cpu sorted"]},'
    b'"name":"POST-CHECK: Verify state after Investigate high CPU utilisation","register":"post_cpu_high"}],'
    b'"rescue":[{"ansible.builtin.debug":{"msg":"High CPU has no automated remediation. Escalate to NOC for manual investigation."},'
    b'"name":"ROLLBACK-NOTE: cpu_high"}]}],"vars":{"dry_run":"true"}}],'
    b'"source_report_timestamp":"2026-11-20T06:30:00Z","vendor":"cisco_ios"}'
)


def request_example():
    """Frozen schema example, not a policy/controller qualification identity."""
    identity = PolicyIdentity(PIN, D, D, D, ("fixture.rule",), "1")
    return c.OperationRequest(
        OP, "report.render", c.Mode.OUTPUT, c.Scope(("r1", "r2"), ("192.0.2.0/24",)),
        c.Context("native-fixture", D, "native-fixture", D, identity, D, D),
        (c.InputRef("outcomes", "saved-outcomes", D),),
        output_intent=c.OutputIntent(("html",), "owned-output"),
    )


def outcome_example():
    """Compute actual central aggregation from explicit frozen mixed facts."""
    return c.aggregate_outcome(
        request_example(),
        (c.TargetOutcome("r1", c.OutcomeStatus.SUCCEEDED, True,
                         native_payload=c.public_object({"count": 1}), changed=True),
         c.TargetOutcome("r2", c.OutcomeStatus.BLOCKED, False, unapplied_effects=("render",))),
        (c.StepOutcome("render", c.OutcomeStatus.SUCCEEDED, True,
                       native_payload=c.public_object({"rendered": True}), changed=True),),
        executed_mode=c.Mode.OUTPUT,
        readiness=c.ReadinessProjection("ready", "not-requested", "not-requested"),
        artifacts=(c.public_object({
            "ref": "owned-output/report.html", "digest": D, "size": 42, "media_type": "text/html",
        }),),
        provenance=c.public_object({"execution_performed": True, "source": "saved-outcomes"}),
    )


def test_nonempty_whole_request_literal_not_roundtrip_only():
    request = request_example()
    assert c.canonical_bytes(request) == EXPECTED_REQUEST
    assert c.OperationRequest.from_json(EXPECTED_REQUEST) == request


def test_actual_catalog_whole_literal_all_operations_and_unqualified_status():
    service = WorkflowService(None, None, None, None, None, None, None, None)
    assert c.canonical_bytes(service.catalog()) == EXPECTED_CATALOG


def test_actual_mixed_aggregation_whole_outcome_literal():
    outcome = outcome_example()
    assert c.canonical_bytes(outcome) == EXPECTED_OUTCOME
    assert outcome.status == c.OutcomeStatus.PARTIAL and outcome.exit_code == 4
    assert c.OperationOutcome.from_json(EXPECTED_OUTCOME) == outcome


def test_actual_minimized_report_projection_whole_literal():
    outcome = outcome_example()
    assert c.canonical_bytes(project_outcome(c.public_object(c.wire(outcome)), ("r1", "r2"))) == EXPECTED_REPORT


def test_actual_comparison_projection_whole_literal_noop_not_empty_input(pure_composition):
    service, request = pure_composition
    request, loaded = bound(
        request, input_source("before", "a\n", parser="flat"),
        input_source("after", "a\n", parser="flat"),
    )
    from netops.ansible.workflows import _comparison, _validate_loaded

    projection = _comparison(request, loaded, _validate_loaded(request, loaded))
    assert c.canonical_bytes(projection) == (
        b'{"comparison":{"counts":{"drift":0,"missing":0,"unmatched":0},"execution_performed":false,'
        b'"input_missing":false,"status":"no-change","style":"flat"},'
        b'"native_payload":{"entries":[],"style":"flat","summary":{"added":0,"changed":0,"removed":0,"security":0}}}'
    )


def test_actual_preview_complete_nonempty_plan_literal_effect_observation_route_projection():
    """Actual pure planner with inert decision port; not executable save consent."""
    request = replace(
        request_example(), inputs=(c.InputRef("outcomes", "saved-outcomes", SOURCE_DIGEST),),
    )
    ref = request.inputs[0]
    observations = tuple(c.Observation(
        "saved-" + target, target, CONTEXT_DIGEST, D, "native-fixture", ref, SOURCE_DIGEST,
        "2026-11-20T06:30:00Z", 0.0,
    ) for target in request.scope.target_ids)

    class Clock:
        def monotonic(self):
            return 0.0

    loaded = hydrate_inputs(request, (
        c.InputSource(ref, "json", EXPECTED_OUTCOME, "parser-1", "vendor-1",
                      observations=observations),
    ), Clock())
    decision_port = Mock()
    decision_port.decide.return_value = DecisionResult("allow", (), "pure-example", (), D)
    service = WorkflowService(decision_port, None, None, None, None, None, None, None)
    plan = service.preview(request, loaded)
    assert hashlib.sha256(EXPECTED_OUTCOME).hexdigest() == SOURCE_DIGEST
    assert c.canonical_bytes(plan) == EXPECTED_PLAN
    assert plan.effects[0].kind == "render" and len(plan.observations) == 2
    assert plan.preconditions  # This pure plan is not an admitted executable permit.


def test_actual_native_generated_projection_full_nonempty_literal():
    """Pin the retained CPU template semantics, not the implementation's own golden."""
    from netops.playbooks.generator import _generate_playbook

    playbook = _generate_playbook({
        "host": "r1", "device_type": "cisco_ios", "success": True,
        "timestamp": "2026-11-20T06:30:00Z", "checks": {"cpu": {"alert": True}},
    }, "cisco_ios", True, True, OP, "2026-11-20T06:30:00Z")
    assert playbook is not None
    assert c.canonical_bytes(c.public_object(playbook.to_dict())) == EXPECTED_GENERATED_NATIVE
