"""Independent frozen C01 criteria: service-free contracts, planning and bounds."""

import hashlib
import itertools
import json
import platform
import socket
import subprocess
import time
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import LocalReferencePolicyEngine, PolicyIdentity, load_policy
from netops.ansible.workflows import WorkflowService, hydrate_inputs, plan_digest
from netops.change.diff import diff_configs, format_json
from netops.core.inventory import Inventory

RUN = Path(
    r".sdlc\runs\it-s-now-time-to-implement-full-ansible-and-mole-20261104-225210156-fb1f9495"
)
OPERATIONS = {
    "scan.discover": (), "scan.inventory-preview": ("inventory", "fragment"), "scan.save": (),
    "inventory.validate": ("inventory",), "inventory.export": ("inventory",),
    "inventory.refresh": ("inventory",), "vault.preflight": (), "vault.resolve-for-run": (),
    "config.collect": (), "config.backup": (), "config.plan": ("intent",),
    "config.apply": ("intent",), "config.rollback": ("intent",),
    "health.gather": (), "health.evaluate": (),
    "compare.compare": ("before", "after"), "compare.remediation-preview": ("findings",),
    "compare.generate": ("findings",), "report.aggregate": ("outcomes",),
    "report.render": ("outcomes",),
}


class ForbiddenPort:
    def __getattr__(self, name):
        raise AssertionError("C01 crossed forbidden host port: " + name)


class HydrationClock:
    def monotonic(self):
        return 12.5


@pytest.fixture(scope="module")
def environment():
    root = Path("netops") / "ansible" / "policy"
    source = (root / "ansible_molecule.px").read_bytes()
    contracts = (root / "ansible_molecule.contracts.px").read_bytes()
    bundle = (root / "bundle.json").read_bytes()
    metadata = json.loads(bundle)
    identity = PolicyIdentity(
        canonical_revision=metadata["canonical_revision"],
        source_sha256=hashlib.sha256(source).hexdigest(),
        contracts_sha256=hashlib.sha256(contracts).hexdigest(),
        bundle_sha256=hashlib.sha256(bundle).hexdigest(),
        rule_manifest=tuple(row["id"] for row in metadata["manifest"]),
        reducer_version=metadata["reducer_version"],
    )
    engine = LocalReferencePolicyEngine(load_policy(source, contracts, bundle, identity))
    forbidden = ForbiddenPort()
    service = WorkflowService(
        engine, forbidden, forbidden, forbidden, forbidden, forbidden, forbidden, forbidden,
    )
    context = c.Context("local-test-controller", "1" * 64, "selection", "2" * 64,
                        identity, "3" * 64, "4" * 64)
    return service, context, engine


def request(context, operation="health.gather", targets=("edge-b", "edge-a")):
    return c.OperationRequest(
        "5f35ae82-15e7-48ce-8fbb-948dfca492c1", operation, c.Mode.PREVIEW,
        c.Scope(targets), context,
    )


def input_source(kind, value=None, content=None):
    fmt = "text" if kind in ("before", "after") else "json"
    if content is None:
        content = json.dumps({} if value is None else value).encode()
    ref = c.InputRef(kind, "explicit-" + kind, hashlib.sha256(content).hexdigest())
    return c.InputSource(ref, fmt, content, "independent-parser-v1", "independent-vendor-v1")


def hydrated(req, *sources):
    req = replace(req, inputs=tuple(item.source for item in sources))
    return req, hydrate_inputs(req, sources, HydrationClock())


@pytest.mark.parametrize("operation", tuple(OPERATIONS))
@pytest.mark.parametrize("mode", (c.Mode.PREVIEW, c.Mode.CHECK))
def test_all_seven_areas_are_pure_and_preserve_every_selected_target(environment, operation, mode):
    service, context, _ = environment
    sources = tuple(input_source(kind, content=b"interface eth0\n" if kind in
                                 ("before", "after") else b"{}")
                    for kind in OPERATIONS[operation])
    req, loaded = hydrated(replace(request(context, operation), mode=mode), *sources)
    fail = AssertionError("pure C01 unexpectedly attempted I/O")
    with patch("builtins.open", side_effect=fail), \
            patch.object(Path, "open", side_effect=fail), \
            patch.object(socket, "socket", side_effect=fail), \
            patch.object(subprocess, "Popen", side_effect=fail), \
            patch.object(time, "monotonic", side_effect=fail), \
            patch.object(time, "time", side_effect=fail):
        catalog = service.catalog()
        plan = service.preview(req, loaded)
        again = service.preview(req, loaded)
    assert {item.id for item in catalog.capabilities} == set(OPERATIONS)
    assert catalog.qualification == "unqualified"
    assert plan.targets == ("edge-b", "edge-a")
    assert tuple(route["target_id"] for route in plan.routes) == plan.targets
    assert plan.policy_digest == context.policy_identity.bundle_sha256
    assert plan.reducer_version == context.policy_identity.reducer_version
    assert plan_digest(plan) == plan.plan_digest == again.plan_digest
    assert plan.native_payload["execution_performed"] is False


@pytest.mark.parametrize("mutation", ("bytes", "extra", "missing", "swap", "context", "order"))
def test_rehydration_is_not_a_preview_fallback(environment, mutation):
    service, context, _ = environment
    req, loaded = hydrated(request(context, "compare.compare"),
                           input_source("before", content=b"a\n"),
                           input_source("after", content=b"b\n"))
    if mutation == "bytes":
        loaded = replace(loaded, contents=(replace(loaded.contents[0], content=b"tampered\n"),
                                           loaded.contents[1]))
    elif mutation == "extra":
        loaded = replace(loaded, contents=loaded.contents + (loaded.contents[0],))
    elif mutation == "missing":
        loaded = replace(loaded, contents=loaded.contents[:1])
    elif mutation == "swap":
        loaded = replace(loaded, contents=loaded.contents[::-1])
    elif mutation == "context":
        req = replace(req, context=replace(context, controller_id="other-controller"))
    else:
        req = replace(req, scope=c.Scope(req.scope.target_ids[::-1]))
    with patch("builtins.open", side_effect=AssertionError("fallback read")):
        with pytest.raises(c.ContractError, match="input-binding-invalid"):
            service.preview(req, loaded)


def test_descriptor_hydration_owns_no_handle_and_preview_never_reopens(environment):
    service, context, _ = environment
    path = RUN / "tester-nov17-selected-inventory.json"
    content = b'{"devices":{"edge-a":{"host":"192.0.2.1"}}}'
    assert not path.exists()
    try:
        with path.open("xb") as stream:
            stream.write(content)
        src = input_source("inventory", content=content)
        req = replace(request(context), inputs=(src.source,))
        with path.open("rb") as stream:
            loaded = hydrate_inputs(req, (replace(src, content=stream),), HydrationClock())
            assert not stream.closed
            assert stream.tell() == len(content)
        path.unlink()
        assert service.preview(req, loaded).targets == req.scope.target_ids
    finally:
        path.unlink(missing_ok=True)


@pytest.mark.parametrize("mutation", ("version", "effect", "bool", "float", "overflow",
                                     "duplicate", "nonfinite"))
def test_closed_request_rejects_unsafe_wire_forms(environment, mutation):
    _, context, _ = environment
    data = json.loads(c.canonical_bytes(request(context)))
    if mutation == "version":
        data["schema_version"] = "2.0"
    elif mutation == "effect":
        data["authorization"] = True
    elif mutation in ("bool", "float", "overflow"):
        data["scope"]["limit"] = {"bool": True, "float": 2.0,
                                  "overflow": 9007199254740992}[mutation]
    elif mutation == "nonfinite":
        data["scope"]["limit"] = float("nan")
    raw = json.dumps(data).encode()
    if mutation == "duplicate":
        raw = raw[:-1] + b',"mode":"preview"}'
    elif mutation == "nonfinite":
        assert b'"limit": NaN' in raw
    with pytest.raises(c.ContractError):
        c.OperationRequest.from_json(raw)


def test_frozen_contracts_and_ordered_native_payload_remain_exact(environment):
    _, context, _ = environment
    req = request(context)
    with pytest.raises(FrozenInstanceError):
        req.scope.target_ids = ()
    payload = {"output": ["second", "first"], "big": 10**45, "reading": 0.125}
    target = c.TargetOutcome("edge-b", c.OutcomeStatus.SUCCEEDED, True,
                             native_payload=c.public_object(payload))
    other = c.TargetOutcome("edge-a", c.OutcomeStatus.SUCCEEDED, True)
    outcome = c.aggregate_outcome(req, (target, other), ())
    raw = c.canonical_bytes(outcome)
    additive = json.loads(raw)
    additive["future_optional"] = {"display": "safe"}
    roundtrip = c.OperationOutcome.from_json(json.dumps(additive).encode())
    assert roundtrip == outcome
    assert roundtrip.targets[0].native_payload["output"] == ("second", "first")
    assert roundtrip.targets[0].native_payload["big"] == 10**45
    assert b'"output":["second","first"]' in raw
    assert c.OperationRequest.from_json(c.canonical_bytes(req)) == req


STATUSES = ("succeeded", "failed", "cancelled", "unsupported", "blocked")


@pytest.mark.parametrize("pair", tuple(itertools.product(STATUSES, repeat=2)))
def test_complete_status_matrix_matches_frozen_partial_failure_precedence(environment, pair):
    _, context, _ = environment
    if all(status == "succeeded" for status in pair):
        expected, exit_code = "succeeded", 0
    elif "succeeded" in pair:
        expected, exit_code = "partial", 4
    else:
        expected = next(status for status in
                        ("failed", "cancelled", "unsupported", "blocked") if status in pair)
        exit_code = {"failed": 5, "cancelled": 130, "unsupported": 6, "blocked": 3}[expected]
    targets = tuple(c.TargetOutcome(name, c.OutcomeStatus(status),
                                   status in ("succeeded", "failed"))
                    for name, status in zip(("edge-b", "edge-a"), pair))
    outcome = c.aggregate_outcome(request(context), targets, ())
    assert outcome.status.value == expected
    assert outcome.exit_code == exit_code
    assert tuple(item.target_id for item in outcome.targets) == ("edge-b", "edge-a")


def test_default_routes_match_native_inventory_without_mutating_native_defaults(environment):
    service, context, _ = environment
    value = {"defaults": {"vendor": "cisco_ios", "transport": "ssh", "port": 2200},
             "devices": {"edge-a": {"host": "192.0.2.10"},
                         "edge-b": {"host": "192.0.2.20", "port": 2222}}}
    src = input_source("inventory", value=value)
    req, loaded = hydrated(request(context), src)
    with patch.object(Path, "read_text", return_value=json.dumps(value)):
        native = Inventory.from_file("explicit.json")
    plan = service.preview(req, loaded)
    for route in plan.routes:
        device = native.get(route["target_id"])
        for field in ("host", "vendor", "transport", "port"):
            assert route[field] == getattr(device, field)
    assert native.defaults == value["defaults"]


def test_native_diff_domain_seam_uses_exact_supplied_bytes(environment):
    service, context, _ = environment
    before = "hostname one\ninterface Ethernet1\n description old\n"
    after = "hostname one\ninterface Ethernet1\n description new\n"
    req, loaded = hydrated(request(context, "compare.compare"),
                           input_source("before", content=before.encode()),
                           input_source("after", content=after.encode()))
    actual = c.wire(service.preview(req, loaded).native_payload["native_payload"])
    assert actual == json.loads(format_json(diff_configs(before, after)))


def test_missing_observations_are_preconditions_but_forged_provenance_is_invalid(environment):
    service, context, _ = environment
    src = input_source("findings", value={"result": "unknown"})
    req, loaded = hydrated(request(context, "health.evaluate"), src)
    plan = service.preview(req, loaded)
    missing = tuple(error.target_id for error in plan.preconditions
                    if error.reason == c.ReasonCode.OBSERVATION_REQUIRED)
    assert missing == req.scope.target_ids
    observation = c.Observation(
        "selected-reading", "edge-b", c.digest(context), context.route_digest,
        context.controller_id, src.source, src.source.digest, "2026-11-17T00:00:00Z", 0.0,
    )
    req, valid = hydrated(req, replace(src, observations=(observation,)))
    assert not any(error.target_id == "edge-b"
                   and error.reason == c.ReasonCode.OBSERVATION_REQUIRED
                   for error in service.preview(req, valid).preconditions)
    forged = replace(observation, controller_id="foreign-controller")
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(req, replace(valid, observations=(forged,)))


def test_health_primary_cleanup_and_remote_uncertainty_remain_visible(environment):
    _, context, _ = environment
    primary = c.SafeError(c.ErrorCategory.EXECUTION, c.ReasonCode.APPLY_FAILED, c.Stage.APPLY)
    cleanup_error = c.SafeError(c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED,
                                c.Stage.FINALIZE)
    findings = (c.Finding("cpu", "health", "error", "alert", 99.0, 80.0),)
    targets = (
        c.TargetOutcome("edge-b", c.OutcomeStatus.SUCCEEDED, True, changed=True,
                        remote_state="uncertain", findings=findings),
        c.TargetOutcome("edge-a", c.OutcomeStatus.BLOCKED, False),
    )
    cleanup = c.CleanupOutcome("failed", ("owned-pending",), (cleanup_error,))
    result = c.aggregate_outcome(request(context), targets, (), errors=(primary,), cleanup=cleanup)
    assert result.status == c.OutcomeStatus.PARTIAL
    assert result.exit_code == 4 and result.changed
    assert primary in result.errors
    assert result.cleanup.errors == (cleanup_error,)
    assert result.cleanup.remaining_refs == ("owned-pending",)
    assert result.targets[0].remote_state == "uncertain"
    assert result.targets[0].findings == findings
    healthy_transport = tuple(replace(target, status=c.OutcomeStatus.SUCCEEDED,
                                     attempted=True, errors=()) for target in targets)
    health_result = c.aggregate_outcome(request(context), healthy_transport, ())
    assert health_result.status == c.OutcomeStatus.FAILED
    assert health_result.exit_code == 5


@pytest.mark.parametrize("content", (
    b'{"devices":{"edge-a":{"password":"private-sentinel"}}}',
    b'{"devices":{},"devices":{}}',
    b'{"reading":NaN}',
))
def test_unsafe_input_hydration_fails_with_safe_memory_only_error(environment, content):
    _, context, _ = environment
    src = input_source("inventory", content=content)
    with pytest.raises(c.ContractError) as caught:
        hydrated(request(context), src)
    assert str(caught.value) == "input-binding-invalid"
    assert b"private-sentinel" not in c.canonical_bytes(caught.value.error)


def test_no_grant_can_activate_c01_and_cancel_cannot_claim_revocation(environment):
    service, context, engine = environment
    req = replace(request(context, "config.apply"), mode=c.Mode.APPLY)
    for grant in (None, object(), {"approved": True}):
        outcome = service.execute(req, grant)
        assert outcome.status == c.OutcomeStatus.BLOCKED
        assert outcome.exit_code == 3 and outcome.executed_mode is None
        assert tuple(target.target_id for target in outcome.targets) == req.scope.target_ids
        assert all(not target.attempted for target in outcome.targets)
        assert outcome.provenance["execution_performed"] is False
    forbidden = ForbiddenPort()
    cancelling = WorkflowService(engine, forbidden, forbidden, forbidden, forbidden,
                                 forbidden, HydrationClock(), forbidden)
    receipt = cancelling.cancel(req.operation_id)
    assert receipt.accepted is False
    assert receipt.reason == "dependency-not-ready"


def test_hundred_record_twenty_warm_preview_nearest_rank_p95(environment, record_property):
    service, context, _ = environment
    names = tuple(f"router-{number:03d}" for number in range(100))
    inventory = {"devices": {name: {"host": f"192.0.2.{number + 1}", "vendor": "cisco_ios"}
                              for number, name in enumerate(names)}}
    src = input_source("inventory", inventory)
    start = time.perf_counter()
    req, loaded = hydrated(request(context, targets=names), src)
    hydration = time.perf_counter() - start
    start = time.perf_counter()
    cold = service.preview(req, loaded)
    cold_seconds = time.perf_counter() - start
    samples = []
    for _ in range(20):
        start = time.perf_counter()
        plan = service.preview(req, loaded)
        samples.append(time.perf_counter() - start)
        assert plan.targets == names
        assert len(plan.routes) == 100
        assert plan_digest(plan) == cold.plan_digest
    p95 = sorted(samples)[18]
    record_property("C01_independent_T29", json.dumps({
        "records": 100, "warm_calls": 20, "raw_seconds": samples,
        "rank": 19, "p95_seconds": p95, "hydration_seconds": hydration,
        "cold_seconds": cold_seconds, "platform": platform.platform(),
        "processor": platform.processor(), "python": platform.python_version(),
        "context": "actual local evaluator; branch coverage; no host ports or network",
    }))
    assert p95 <= 2.0
