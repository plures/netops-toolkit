"""C01 public contract, real-policy, purity, parity and performance controls."""

from __future__ import annotations

import hashlib
import io
import itertools
import json
import math
import platform
import time
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest import mock
from uuid import UUID

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import (
    DecisionEvent,
    DecisionFacts,
    EventKind,
    LocalReferencePolicyEngine,
    PolicyIdentity,
    load_policy,
)
from netops.ansible.workflows import WorkflowService, hydrate_inputs, plan_digest, request_digest
from netops.change.diff import diff_configs, format_json

ROOT = Path(__file__).resolve().parents[1]
OPERATION_ID = "e9c85d98-b991-4d8c-a92b-a7c3e3437816"
D = "a" * 64


class Bomb:
    def __getattr__(self, name):
        raise AssertionError("Unexpected host port access: " + name)


class Clock:
    def __init__(self, value=10.0):
        self.value = value
        self.calls = 0

    def monotonic(self):
        self.calls += 1
        return self.value


@pytest.fixture(scope="module")
def policy():
    root = ROOT / "netops" / "ansible" / "policy"
    source = (root / "ansible_molecule.px").read_bytes()
    contracts = (root / "ansible_molecule.contracts.px").read_bytes()
    bundle = (root / "bundle.json").read_bytes()
    parsed = json.loads(bundle)
    identity = PolicyIdentity(
        canonical_revision=parsed["canonical_revision"],
        source_sha256=hashlib.sha256(source).hexdigest(),
        contracts_sha256=hashlib.sha256(contracts).hexdigest(),
        bundle_sha256=hashlib.sha256(bundle).hexdigest(),
        rule_manifest=tuple(item["id"] for item in parsed["manifest"]),
        reducer_version=parsed["reducer_version"],
    )
    return identity, LocalReferencePolicyEngine(load_policy(source, contracts, bundle, identity))


@pytest.fixture
def operation_request(policy):
    identity, _ = policy
    return c.OperationRequest(
        OPERATION_ID, "health.gather", c.Mode.PREVIEW, c.Scope(("r1", "r2")),
        c.Context("controller-local", D, "fixture", D, identity, D, D),
    )


@pytest.fixture
def service(policy):
    _, engine = policy
    bomb = Bomb()
    return WorkflowService(engine, bomb, bomb, bomb, bomb, bomb, bomb, bomb)


def source(kind, content=b"{}", fmt="json", ref=None):
    identity = c.InputRef(kind, ref or "selected-" + kind, hashlib.sha256(content).hexdigest())
    return c.InputSource(identity, fmt, content, "parser-1", "vendor-1")


def with_sources(request, *sources):
    request = replace(request, inputs=tuple(item.source for item in sources))
    return request, hydrate_inputs(request, sources, Clock())


@pytest.mark.parametrize("content", [
    b"snmp-server user monitor ops v3 auth sha AUTH_SENTINEL priv aes 128 PRIV_SENTINEL\n",
    b"snmp-server user monitor ops v3 encrypted auth sha AUTH_SENTINEL\n",
    b"snmpv3 user monitor auth sha AUTH_SENTINEL priv aes PRIV_SENTINEL\n",
    b"tacacs server AUTH\n address ipv4 192.0.2.1\n key 7 TACACS_SENTINEL\n",
    b"radius server AUTH\n address ipv4 192.0.2.2\n key RADIUS_SENTINEL\n",
    b"tacacs-server host 192.0.2.1 key TACACS_SENTINEL\n",
    b"radius-server host 192.0.2.1 auth-port 1812 key RADIUS_SENTINEL\n",
    b"set snmp v3 usm local-engine user ops authentication-sha authentication-key AUTH_SENTINEL\n",
])
def test_credential_configuration_rejected_before_hash(operation_request, content):
    from netops.ansible import workflows

    src = source("before", content, "text")
    request = replace(operation_request, operation="compare.compare",
                      inputs=(src.source, source("after", b"interface Eth1\n", "text").source))
    after = source("after", b"interface Eth1\n", "text")
    with mock.patch.object(workflows.hashlib, "sha256", side_effect=AssertionError("secret hashed")):
        with pytest.raises(c.ContractError) as error:
            hydrate_inputs(request, (src, after), Clock())
    assert "SENTINEL" not in repr(error.value)
    with pytest.raises(c.ContractError):
        c.public_value(content.decode())


@pytest.mark.parametrize("key", [
    "authKey", "privKey", "auth_password", "priv_password", "shared_key",
    "radiusSecret", "tacacs_key", "snmp_auth_key", "snmp_priv_key",
    "authenticationKey", "privacyKey", "provider_shared_key",
    "AUTHKEY", "privkey", "community", "communityString", "read_community",
    "sharedsecret", "radiusServerKey",
])
def test_structured_credentials_rejected_before_hash(operation_request, key):
    from netops.ansible import workflows

    src = source("intent", json.dumps({key: "STRUCTURED_SENTINEL"}).encode())
    request = replace(operation_request, operation="config.plan", inputs=(src.source,))
    with mock.patch.object(workflows.hashlib, "sha256", side_effect=AssertionError("secret hashed")):
        with pytest.raises(c.ContractError) as error:
            hydrate_inputs(request, (src,), Clock())
    assert "SENTINEL" not in str(error.value)


@pytest.mark.parametrize("factory", [c.StepOutcome, c.TargetOutcome])
@pytest.mark.parametrize(("attempted", "pending"), [(False, ()), (True, ("apply",))])
def test_contradictory_selected_success_is_not_representable(factory, attempted, pending):
    with pytest.raises(c.ContractError):
        factory("selected", c.OutcomeStatus.SUCCEEDED, attempted, unapplied_effects=pending)


def test_mixed_completed_and_pending_apply_retains_coverage_and_changed(operation_request):
    request = replace(operation_request, operation="config.apply", mode=c.Mode.APPLY)
    outcomes = (
        c.TargetOutcome("r1", c.OutcomeStatus.SUCCEEDED, True, changed=True, remote_state="committed"),
        c.TargetOutcome("r2", c.OutcomeStatus.BLOCKED, False, unapplied_effects=("apply",)),
    )
    result = c.aggregate_outcome(request, outcomes)
    assert result.status == c.OutcomeStatus.PARTIAL
    assert result.exit_code == 4 and result.changed
    assert result.targets == outcomes


@pytest.mark.parametrize("exception_name", ["PolicyInputError", "PolicyEvaluationError", "PolicyBudgetError"])
def test_internal_policy_failure_is_safe_policy_exit5(operation_request, exception_name):
    from netops.ansible import policy, workflows

    class BrokenPolicy:
        def decide(self, event, facts):
            raise getattr(policy, exception_name)("PRIVATE_SENTINEL")

    bomb = Bomb()
    service = WorkflowService(BrokenPolicy(), bomb, bomb, bomb, bomb, bomb, bomb, bomb)
    request, loaded = with_sources(operation_request)
    with pytest.raises(workflows.PolicyFailure) as error:
        service.preview(request, loaded)
    assert error.value.error.category == c.ErrorCategory.POLICY
    assert error.value.error.stage == c.Stage.EVALUATE
    assert error.value.exit_code == 5
    assert "PRIVATE_SENTINEL" not in repr(error.value)
    result = c.aggregate_outcome(request, tuple(
        c.TargetOutcome(target, c.OutcomeStatus.FAILED, False)
        for target in request.scope.target_ids
    ), errors=(error.value.error,))
    assert result.exit_code == 5


def test_settings_are_explicit_pure_bound_snapshot_not_public_override(operation_request, service):
    from netops.ansible.settings import SettingsSnapshot, resolve_settings
    from netops.ansible.workflows import bind_settings

    request, loaded = with_sources(operation_request)
    snapshot = resolve_settings(SettingsSnapshot(), {
        "execution.ssh_concurrency": 3, "execution.ping_concurrency": 8,
        "execution.snmp_concurrency": 2, "execution.timeout_seconds": 25,
    })
    rebound = bind_settings(request, loaded, snapshot)
    assert rebound.settings is snapshot
    plan = service.preview(request, rebound)
    assert plan.settings is snapshot
    assert plan.concurrency == 3 and plan.deadline_ms == 25000
    assert plan.plan_digest == plan_digest(plan)
    assert service.preview(request, loaded).plan_digest != plan.plan_digest
    assert rebound.binding_digest != loaded.binding_digest
    assert rebound.contents is loaded.contents
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(request, replace(loaded, settings=snapshot))
    for field in ("settings", "overrides"):
        raw = json.loads(c.canonical_bytes(request))
        raw[field] = json.loads(c.canonical_bytes(snapshot))
        with pytest.raises(c.ContractError):
            c.OperationRequest.from_json(json.dumps(raw).encode())
    raw = json.loads(c.canonical_bytes(request))
    raw["context"]["settings"] = json.loads(c.canonical_bytes(snapshot))
    with pytest.raises(c.ContractError):
        c.OperationRequest.from_json(json.dumps(raw).encode())
    raw = json.loads(c.canonical_bytes(request))
    raw["scope"]["limit"] = float("nan")
    with pytest.raises(c.ContractError):
        c.OperationRequest.from_json(json.dumps(raw).encode())


def test_settings_default100_absolute4096_no_clipping_and_no_native_effect_drift(operation_request, service):
    from netops.ansible.settings import SettingsSnapshot, resolve_settings
    from netops.ansible.workflows import bind_settings

    assert c.Scope(("r1",)).limit == 100
    with pytest.raises(c.ContractError):
        c.Scope(tuple(f"r{i}" for i in range(4097)), limit=4097)
    request = replace(operation_request, scope=c.Scope(tuple(f"r{i}" for i in range(101)), limit=101))
    request, loaded = with_sources(request)
    with pytest.raises(c.ContractError):
        service.preview(request, loaded)
    settings = resolve_settings(SettingsSnapshot(), {"execution.target_limit": 4096})
    plan = service.preview(request, bind_settings(request, loaded, settings))
    assert len(plan.targets) == 101 and plan.settings.execution.target_limit == 4096
    settings = replace(settings, backup=replace(settings.backup, git=True),
                       controller=replace(settings.controller, id="other-controller"))
    with pytest.raises(c.ContractError):
        service.preview(request, bind_settings(request, loaded, settings))
    request, loaded = with_sources(operation_request)
    settings = replace(settings, controller=replace(settings.controller, id=None))
    plan = service.preview(request, bind_settings(request, loaded, settings))
    assert not any(effect.kind in ("git", "retention") for effect in plan.effects)


def test_safe_native_aaa_snmp_config_diff_parity(operation_request, service):
    before = ("snmp-server contact operations\nsnmp-server user monitor ops v3\n"
              "snmp-server group readonly v3 priv\nsnmp-server host 192.0.2.9 version 3 auth monitor\n"
              "radius server AUTH\n address ipv4 192.0.2.1\n!\ninterface Eth1\n description before\n")
    after = before.replace("before", "after")
    request = replace(operation_request, operation="compare.compare")
    request, loaded = with_sources(request, source("before", before.encode(), "text"),
                                   source("after", after.encode(), "text"))
    plan = service.preview(request, loaded)
    assert c.wire(plan.native_payload["native_payload"]) == json.loads(format_json(diff_configs(before, after)))


def test_direct_response_and_corrupted_outcomes_cannot_invent_completion(operation_request):
    targets = tuple(c.TargetOutcome(t, c.OutcomeStatus.SUCCEEDED, True)
                    for t in operation_request.scope.target_ids)
    valid = c.aggregate_outcome(operation_request, targets)
    with pytest.raises(c.ContractError):
        replace(valid, targets=(replace(targets[0], status=c.OutcomeStatus.BLOCKED), targets[1]))
    corrupted = replace(targets[0])
    object.__setattr__(corrupted, "unapplied_effects", ("apply",))
    with pytest.raises(c.ContractError):
        c.aggregate_outcome(operation_request, (corrupted, targets[1]))


def test_settings_and_secret_boundary_defenses_have_reachable_fault_controls(operation_request, service):
    from netops.ansible import workflows
    from netops.ansible.settings import SettingsSnapshot

    request, loaded = with_sources(operation_request)
    with pytest.raises(c.ContractError):
        replace(loaded, settings={})
    with pytest.raises(c.ContractError):
        workflows.bind_settings(request, loaded, None)
    corrupt = replace(loaded)
    object.__setattr__(corrupt, "settings", None)
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(request, corrupt)
    plan = service.preview(request, loaded)
    with pytest.raises(c.ContractError):
        replace(plan, settings={})
    with mock.patch("builtins.open", side_effect=AssertionError("implicit settings read")), \
            mock.patch("os.getenv", side_effect=AssertionError("implicit environment")):
        assert workflows.bind_settings(request, loaded, SettingsSnapshot()).settings == SettingsSnapshot()
    for invalid in (
        {"authorization": {"ttl_seconds": 301}},
        {"authorization": {"ttl_seconds": 1.0}},
        {"authorization": {"ttl_seconds": 0}},
        {"authorization": {"grant": "PRIVATE"}},
        {"snmpv3": {"sha": "AUTH_SENTINEL", "aes": "PRIV_SENTINEL"}},
        {"radius": {"value": "RADIUS_SENTINEL"}},
    ):
        with pytest.raises(c.ContractError):
            c.public_value(invalid)
    assert workflows.PolicyFailure("PRIVATE_SENTINEL").diagnostic == "policy-evaluation-failed"
    c.nonsecret_text("\n \n{\n snmp-server contact operations\n}\nend\n")


def test_request_roundtrip_closed_nested_schema_and_absolute_scope_ceiling(operation_request):
    request = operation_request
    request = replace(request, scope=replace(request.scope, limit=4096))
    assert c.OperationRequest.from_json(c.canonical_bytes(request)) == request
    assert request.scope.limit == 4096
    assert c.counter(c.MAX_SAFE_INT) == 9007199254740991
    with pytest.raises(FrozenInstanceError):
        request.mode = c.Mode.APPLY
    for path, key, value in (
        ((), "authorization", True), ((), "execute", True), ((), "schema_version", "2.0"),
        (("scope",), "limit", True), (("scope",), "limit", 1.0),
        (("scope",), "limit", 4097), (("scope",), "limit", 9007199254740992),
        (("context",), "qualified", True), (("context",), "settings", {}),
        (("output_intent",), "shell", "never-run"), ((), "mode", "invalid"),
        ((), "operation_id", "not-a-uuid"),
    ):
        data = json.loads(c.canonical_bytes(request))
        target = data
        for item in path:
            target = target[item]
        target[key] = value
        with pytest.raises(c.ContractError, match="invalid-request"):
            c.OperationRequest.from_json(json.dumps(data).encode())


@pytest.mark.parametrize("data", [
    b'{"a":1,"a":2}', b'{"nested":{"a":1,"a":2}}', b'{"a":NaN}',
    b'{"a":Infinity}', b'{"a":1e9999}', b'{"password":"sentinel-never-retain"}',
    b'{"native_payload":{"ansible_password":"sentinel-never-retain"}}',
    b'[]', b'"\xff"', b'{' + b" " * c.MAX_CONTENT_BYTES,
], ids=lambda data: hashlib.sha256(data).hexdigest()[:12])
def test_strict_decoder_rejects_bad_or_private_content(data):
    with pytest.raises(c.ContractError) as error:
        c.decode_json(data)
    assert "sentinel" not in str(error.value)


@pytest.mark.parametrize("factory", [
    lambda r: replace(r, scope=c.Scope(("r1", "r1"))),
    lambda r: replace(r, scope=c.Scope(("r1",), ("bad/cidr",))),
    lambda r: replace(r, scope=c.Scope(("r1", "r2"), limit=1)),
    lambda r: replace(r, scope=c.Scope(())),
    lambda r: replace(r, mode=c.Mode.ROLLBACK),
    lambda r: replace(r, schema_version="9.0"),
    lambda r: replace(r, operation="unknown.run"),
    lambda r: replace(r, operation_id=str(UUID(OPERATION_ID)).upper()),
    lambda r: replace(r, context=replace(r.context, route_digest="x")),
    lambda r: replace(r, context=replace(r.context, policy_identity=replace(
        r.context.policy_identity, reducer_version="2",
    ))),
    lambda r: replace(r, output_intent=c.OutputIntent(("pdf",))),
    lambda r: replace(r, output_intent=c.OutputIntent(retention=True)),
    lambda r: replace(r, inputs=(c.InputRef("inventory", "https://never", D),)),
    lambda r: replace(r, inputs=(c.InputRef("executable", "never", D),)),
    lambda r: replace(r, plan_digest="wrong"),
])
def test_python_construction_rejects_invalid_public_contracts(operation_request, factory):
    request = operation_request
    with pytest.raises(c.ContractError):
        factory(request)


def test_catalog_is_complete_and_does_not_invent_registry_readiness(service):
    result = service.catalog()
    assert {item.area for item in result.capabilities} == {
        "scan", "inventory", "vault", "config", "health", "compare", "report",
    }
    assert len({item.id for item in result.capabilities}) == 20
    assert result.qualification == "unqualified"
    assert "qualification" in result.next_action


@pytest.mark.parametrize("item", c.CAPABILITIES, ids=lambda item: item.id)
@pytest.mark.parametrize("mode", [c.Mode.PREVIEW, c.Mode.CHECK])
def test_every_operation_pure_preview_has_real_policy_identity_and_coverage(
    operation_request, service, item, mode,
):
    request = operation_request
    request = replace(request, operation=item.id, mode=mode)
    if item.id == "compare.compare":
        request, loaded = with_sources(
            request, source("before", b"ntp server 1.1.1.1", "text"),
            source("after", b"ntp server 2.2.2.2", "text"),
        )
    else:
        request, loaded = with_sources(
            request, *(source(kind) for kind in item.required_inputs),
        )
    fail = AssertionError("forbidden effect or clock in pure preview")
    with (
        mock.patch("builtins.open", side_effect=fail),
        mock.patch("pathlib.Path.open", side_effect=fail),
        mock.patch("os.open", side_effect=fail),
        mock.patch("socket.socket", side_effect=fail),
        mock.patch("subprocess.Popen", side_effect=fail),
        mock.patch("time.time", side_effect=fail),
        mock.patch("time.monotonic", side_effect=fail),
    ):
        plan = service.preview(request, loaded)
        again = service.preview(request, loaded)
        assert service.catalog().qualification == "unqualified"
    assert plan == again
    assert plan.targets == ("r1", "r2")
    assert plan.policy_digest == request.context.policy_identity.bundle_sha256
    assert plan.reducer_version == "1"
    assert plan.plan_digest == plan_digest(plan)
    assert all(effect.ordinal == ordinal for ordinal, effect in enumerate(plan.effects))
    assert plan.native_payload["execution_performed"] is False
    assert not any(error.category == c.ErrorCategory.POLICY for error in plan.preconditions)


@pytest.mark.parametrize("change", ["bytes", "swap", "extra", "missing", "format", "parser", "binding"])
def test_preview_rejects_all_tampering_without_fallback(operation_request, service, change):
    request = operation_request
    request, loaded = with_sources(
        request, source("before", b"one", "text"), source("after", b"two", "text"),
    )
    if change == "bytes":
        loaded = replace(loaded, contents=(replace(loaded.contents[0], content=b"bad"), loaded.contents[1]))
    elif change == "swap":
        loaded = replace(loaded, contents=tuple(reversed(loaded.contents)))
    elif change == "extra":
        loaded = replace(loaded, contents=loaded.contents + (loaded.contents[0],))
    elif change == "missing":
        loaded = replace(loaded, contents=loaded.contents[:1])
    elif change == "format":
        loaded = replace(loaded, contents=(replace(loaded.contents[0], format="yaml"), loaded.contents[1]))
    elif change == "parser":
        loaded = replace(loaded, contents=(replace(loaded.contents[0], parser_revision="changed"), loaded.contents[1]))
    else:
        loaded = replace(loaded, binding_digest=D)
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(request, loaded)


def test_context_target_controller_and_intent_changes_invalidate_loaded_binding(operation_request, service):
    request = operation_request
    request, loaded = with_sources(request, source("inventory"))
    changes = (
        replace(request, scope=c.Scope(("r2", "r1"))),
        replace(request, context=replace(request.context, route_digest="b" * 64)),
        replace(request, context=replace(request.context, controller_id="other-controller")),
        replace(request, output_intent=c.OutputIntent(("json",), "owned-results")),
        replace(request, mode=c.Mode.OBSERVE),
    )
    for changed in changes:
        with pytest.raises(c.ContractError, match="input-binding-invalid"):
            service.preview(changed, loaded)
    # A previous plan's self-referential digest is not a new input or authority.
    same = replace(request, plan_digest=D)
    assert service.preview(same, loaded).request_digest == request_digest(request)


def test_observation_provenance_binding_and_absence_are_distinct(operation_request, service):
    request = operation_request
    request = replace(request, operation="config.apply", mode=c.Mode.APPLY)
    data = source("observations")
    intent = source("intent")
    request = replace(request, inputs=(data.source, intent.source))
    observation = c.Observation(
        "observation-1", "r1", c.digest(request.context), D, "controller-local",
        data.source, data.source.digest, "2026-11-17T22:00:00Z", 5.0,
    )
    hydrated = hydrate_inputs(request, (replace(data, observations=(observation,)), intent), Clock())
    plan = service.preview(request, hydrated)
    missing = [error.target_id for error in plan.preconditions if error.reason == c.ReasonCode.OBSERVATION_REQUIRED]
    assert missing == ["r2"]
    assert c.ReasonCode.CONSENT_REQUIRED in tuple(error.reason for error in plan.preconditions)
    for bad in (
        replace(observation, target_id="other"), replace(observation, route_digest="b" * 64),
        replace(observation, controller_id="other"), replace(observation, content_digest="b" * 64),
        replace(observation, context_digest="b" * 64),
    ):
        with pytest.raises(c.ContractError, match="input-binding-invalid"):
            hydrate_inputs(request, (replace(data, observations=(bad,)), intent), Clock())
    with pytest.raises(c.ContractError):
        replace(observation, age_ms=float("nan"))
    with pytest.raises(c.ContractError):
        replace(observation, observed_at="2026-11-17T22:00:00")
    with pytest.raises(c.ContractError):
        hydrate_inputs(request, (replace(data, observations=(observation, observation)), intent), Clock())


@pytest.mark.parametrize("content,fmt", [
    (b'{"a":1,"a":2}', "json"), (b"a: 1\na: 2", "yaml"),
    (b"a: &alias [1, 2]\nb: *alias", "yaml"), (b"a: .nan", "yaml"),
    (b"password: sentinel-private", "yaml"),
    (b"username admin password sentinel-private", "text"),
    (b"-----BEGIN PRIVATE KEY-----\nsentinel", "text"),
    (b"\xff", "text"), (b"x" * (c.MAX_CONTENT_BYTES + 1), "text"),
], ids=lambda value: hashlib.sha256(value).hexdigest()[:12] if isinstance(value, bytes) else value)
def test_hydration_rejects_unsafe_sources_without_values_in_errors(operation_request, content, fmt):
    request = operation_request
    data = source("inventory", content, fmt)
    request = replace(request, inputs=(data.source,))
    with pytest.raises(c.ContractError, match="input-binding-invalid") as error:
        hydrate_inputs(request, (data,), Clock())
    assert "sentinel" not in str(error.value)


def test_explicit_descriptor_is_read_only_bounded_and_never_owned_by_hydrator(operation_request):
    request = operation_request
    selected = ROOT / "tests" / "fixtures" / "c01-selected-input.json"
    # No tmp/system directory: this task owns this exact fixture path.
    selected.parent.mkdir(exist_ok=True)
    selected.write_bytes(b'{"devices":{}}')
    try:
        data = source("inventory", selected.read_bytes())
        request = replace(request, inputs=(data.source,))
        with selected.open("rb") as descriptor:
            loaded = hydrate_inputs(request, (replace(data, content=descriptor),), Clock())
            assert descriptor.closed is False
            assert descriptor.tell() == len(b'{"devices":{}}')
        assert loaded.contents[0].content == b'{"devices":{}}'
        with selected.open("r+b") as descriptor:
            with pytest.raises(c.ContractError):
                hydrate_inputs(request, (replace(data, content=descriptor),), Clock())
        with pytest.raises(c.ContractError):
            hydrate_inputs(request, (replace(data, content=io.BytesIO(b"{}")),), Clock())
    finally:
        selected.unlink()


def test_comparison_uses_same_loaded_native_diff_and_never_opens_refs(operation_request, service):
    request = operation_request
    before = "interface Ethernet1\n description before\nntp server 1.1.1.1"
    after = "interface Ethernet1\n description after\nntp server 2.2.2.2"
    request = replace(request, operation="compare.compare")
    request, loaded = with_sources(
        request, source("before", before.encode(), "text"), source("after", after.encode(), "text"),
    )
    actual = service.preview(request, loaded).native_payload["native_payload"]
    assert c.wire(actual) == json.loads(format_json(diff_configs(before, after)))


def test_native_payload_order_and_public_numeric_range_are_not_policy_narrowed(operation_request):
    request = operation_request
    payload = {"output": ["second-command", "first-command"], "stdout": "second\nfirst", "total": 10**30}
    targets = tuple(c.TargetOutcome(
        target, c.OutcomeStatus.SUCCEEDED, True, native_payload=payload,
    ) for target in request.scope.target_ids)
    result = c.aggregate_outcome(request, targets)
    payload["output"].reverse()
    assert result.exit_code == 0
    encoded = json.loads(c.canonical_bytes(result))
    assert encoded["targets"][0]["target_id"] == "r1"
    assert encoded["targets"][0]["native_payload"]["output"] == ["second-command", "first-command"]
    assert encoded["targets"][0]["native_payload"]["total"] == 10**30


STATUSES = tuple(status for status in c.OutcomeStatus if status not in (
    c.OutcomeStatus.PARTIAL, c.OutcomeStatus.NOT_REQUESTED,
))


@pytest.mark.parametrize("first,second", tuple(itertools.product(STATUSES, repeat=2)))
def test_aggregate_all_terminal_pairs_match_actual_px_rules(operation_request, policy, first, second):
    request = operation_request
    identity, engine = policy
    request = replace(request, operation="report.aggregate", mode=c.Mode.CHECK)
    targets = (c.TargetOutcome("r1", first, first == c.OutcomeStatus.SUCCEEDED),
               c.TargetOutcome("r2", second, second == c.OutcomeStatus.SUCCEEDED))
    outcome = c.aggregate_outcome(request, targets)
    statuses = (first, second)
    result = {
        "selected": 2, "completed": statuses.count(c.OutcomeStatus.SUCCEEDED),
        "unsuccessful": sum(status != c.OutcomeStatus.SUCCEEDED for status in statuses),
        "failed": statuses.count(c.OutcomeStatus.FAILED),
        "cancelled": statuses.count(c.OutcomeStatus.CANCELLED),
        "unsupported": statuses.count(c.OutcomeStatus.UNSUPPORTED),
        "blocked": statuses.count(c.OutcomeStatus.BLOCKED),
        "policy_failed": False, "cleanup_failed": False, "remote_uncertain": False,
    }
    event = DecisionEvent(
        "47f5bb7b-8c31-428f-8acf-dd8c177b66e6", EventKind.STEP_COMPLETED, 0,
        D, D, identity.bundle_sha256, "r1", "aggregate",
        c.public_object({
            "invocation_id": "invocation-1", "effect_id": "effect-1",
            "target_id": "r1", "step_id": "aggregate", "safe_result_digest": D,
            "primary": "success", "cleanup": "success", "remote_uncertain": False,
        }), operation_id=request.operation_id,
    )
    facts = DecisionFacts(c.public_object({
        "request": {"area": "report", "operation": "aggregate", "mode": "check"},
        "binding": {"input_valid": True, "plan_current": True, "policy_current": True},
        "control": {"cancelled": False, "remaining_ms": 1}, "result": result,
        "change": {"poststate_verified": True},
    }))
    decision = engine.decide(event, facts)
    assert decision.decision == "allow"
    canonical = [effect.params["status"] for effect in decision.effects if effect.name == "record_outcome"]
    assert canonical == ["success" if outcome.status == c.OutcomeStatus.SUCCEEDED else outcome.status.value]
    assert outcome.exit_code == {
        "succeeded": 0, "partial": 4, "failed": 5, "cancelled": 130, "unsupported": 6, "blocked": 3,
    }[outcome.status.value]


def test_cleanup_health_and_primary_failures_do_not_disappear(operation_request):
    request = operation_request
    targets = tuple(c.TargetOutcome(
        target, c.OutcomeStatus.SUCCEEDED, True, changed=True,
    ) for target in request.scope.target_ids)
    cleanup_error = c.SafeError(c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE)
    cleanup = c.CleanupOutcome("failed", ("owned-unremoved",), (cleanup_error,))
    result = c.aggregate_outcome(request, targets, cleanup=cleanup)
    assert result.status == c.OutcomeStatus.FAILED and result.exit_code == 5 and result.changed
    alert = c.Finding("cpu", "health", "error", "alert", 99.0, 90.0)
    assert c.aggregate_outcome(request, targets, findings=(alert,)).exit_code == 5
    uncertain = replace(targets[0], status=c.OutcomeStatus.FAILED, remote_state="uncertain")
    mixed = c.aggregate_outcome(request, (uncertain, targets[1]), cleanup=cleanup)
    assert mixed.exit_code == 4 and mixed.targets[0].remote_state == "uncertain"
    assert mixed.cleanup == cleanup
    unselected = c.StepOutcome("enhanced-unselected", c.OutcomeStatus.FAILED, False, selected=False)
    assert c.aggregate_outcome(request, targets, (unselected,)).exit_code == 0
    invalid = c.SafeError(c.ErrorCategory.INVALID_INPUT, c.ReasonCode.INVALID_REQUEST, c.Stage.VALIDATE)
    assert c.aggregate_outcome(request, (uncertain, replace(targets[1], status=c.OutcomeStatus.BLOCKED)),
                               errors=(invalid,)).exit_code == 2
    with pytest.raises(c.ContractError):
        c.aggregate_outcome(request, targets[:1])
    with pytest.raises(c.ContractError):
        c.aggregate_outcome(request, (replace(targets[0], selected=False), targets[1]))


def test_effectful_execution_is_honestly_unmet_without_consuming_any_grant(operation_request, service):
    request = operation_request
    request = replace(request, mode=c.Mode.OBSERVE)
    result = service.execute(request)
    assert result.exit_code == 3 and result.executed_mode is None
    assert tuple(target.target_id for target in result.targets) == ("r1", "r2")
    assert all(not target.attempted for target in result.targets)
    assert result.errors[0].reason == c.ReasonCode.DEPENDENCY_NOT_READY
    assert result.readiness.companion == "blocked"
    with pytest.raises(TypeError):
        c.Authorization()


@pytest.mark.parametrize("value", [True, -1, 1.0, 9007199254740992])
def test_host_binding_counters_reject_coercion_and_overflow(operation_request, value):
    request = operation_request
    with pytest.raises(c.ContractError):
        c.PlanBinding(request.operation_id, D, D, D, D, D, D, D, "owned", value, ())


@pytest.mark.parametrize("now,duration", [
    (float("nan"), 1.0), (float("inf"), 1.0), (-1.0, 1.0),
    (1.0, float("inf")), (float.fromhex("0x1.fffffffffffffp+1023"), float.fromhex("0x1.fffffffffffffp+1023")),
])
def test_deadline_rejects_nonfinite_negative_and_computed_overflow(now, duration):
    with pytest.raises(c.ContractError):
        c.checked_deadline(now, duration)


def test_nearest_rank_warm_preview_hundred_records(operation_request, service, record_property):
    request = operation_request
    records = [{"id": f"r{index}", "host": f"192.0.2.{index + 1}", "port": 22} for index in range(100)]
    data = source("inventory", json.dumps({
        "devices": {record["id"]: {"host": record["host"], "port": record["port"]} for record in records},
    }).encode())
    request = replace(
        request, scope=c.Scope(tuple(record["id"] for record in records)), inputs=(data.source,),
    )
    hydration_start = time.perf_counter()
    loaded = hydrate_inputs(request, (data,), Clock())
    hydration_seconds = time.perf_counter() - hydration_start
    cold_start = time.perf_counter()
    service.preview(request, loaded)
    cold_seconds = time.perf_counter() - cold_start
    timings = []
    for _ in range(20):
        start = time.perf_counter()
        plan = service.preview(request, loaded)
        timings.append(time.perf_counter() - start)
        assert len(plan.targets) == 100
    p95 = sorted(timings)[math.ceil(0.95 * len(timings)) - 1]
    record_property("C01_T29", json.dumps({
        "records": 100, "warm_calls": 20, "raw_seconds": timings, "nearest_rank_p95": p95,
        "rank": 19, "hydration_seconds": hydration_seconds, "cold_seconds": cold_seconds,
        "machine": platform.machine(), "processor": platform.processor(), "python": platform.python_version(),
        "platform": platform.platform(), "downloads": False, "coverage_active": True,
        "context": "checkout; actual local policy engine; content and binding digests revalidated",
    }))
    assert p95 <= 2.0


def test_response_additive_fields_roundtrip_and_closed_value_validation(operation_request):
    request = operation_request
    finding = c.Finding("cpu", "health", "error", "unknown", raw_source_ref="owned-observation")
    error = c.SafeError(c.ErrorCategory.POLICY, c.ReasonCode.READING_UNAVAILABLE, c.Stage.EVALUATE)
    targets = tuple(c.TargetOutcome(
        target, c.OutcomeStatus.FAILED, True, findings=(finding,), errors=(error,),
    ) for target in request.scope.target_ids)
    result = c.aggregate_outcome(
        request, targets, (c.StepOutcome("evaluation", c.OutcomeStatus.FAILED, True),),
        executed_mode=c.Mode.CHECK,
        artifacts=(c.public_object({"ref": "owned-artifact", "digest": D}),),
    )
    encoded = json.loads(c.canonical_bytes(result))
    encoded["future_optional"] = {"display": "additive"}
    encoded["targets"][0]["future_optional"] = "ignored"
    assert c.OperationOutcome.from_json(json.dumps(encoded).encode()) == result
    for key, value in (("schema_version", "2.0"), ("status", "green"), ("changed", 1),
                       ("targets", {}), ("cleanup", None)):
        bad = dict(encoded)
        bad[key] = value
        with pytest.raises(c.ContractError):
            c.OperationOutcome.from_json(json.dumps(bad).encode())
    with pytest.raises(c.ContractError):
        replace(result, targets=(targets[0], targets[0]))
    with pytest.raises(c.ContractError):
        replace(result, status="succeeded")


@pytest.mark.parametrize("make", [
    lambda: c.Scope(["r1"]),
    lambda: c.Scope(("",)),
    lambda: c.Scope(("bad\nid",)),
    lambda: c.InputRef("inventory", "a" * 4097, D),
    lambda: c.OutputIntent(("xml",), "owned"),
    lambda: c.OutputIntent(("json",), "https://not-a-destination"),
    lambda: c.OutputIntent(overwrite="force"),
    lambda: c.OutputIntent(retention=1),
    lambda: c.SafeError("execution", c.ReasonCode.APPLY_FAILED, c.Stage.APPLY),
    lambda: c.Finding("cpu", "health", "error", "green"),
    lambda: c.Finding("cpu", "health", "fatal", "error"),
    lambda: c.Finding("cpu", "health", "error", "alert", float("inf")),
    lambda: c.CleanupOutcome("clean"),
    lambda: c.CleanupOutcome("succeeded", ("owned-unremoved",)),
    lambda: c.CleanupOutcome("failed", errors=("unsafe-error",)),
    lambda: c.StepOutcome("s", c.OutcomeStatus.PARTIAL, True),
    lambda: c.StepOutcome("s", c.OutcomeStatus.FAILED, 1),
    lambda: c.StepOutcome("s", c.OutcomeStatus.FAILED, True, remote_state="healthy"),
    lambda: c.StepOutcome("s", c.OutcomeStatus.FAILED, True, findings=(None,)),
    lambda: c.StepOutcome("s", c.OutcomeStatus.FAILED, True, errors=(None,)),
    lambda: c.ReadinessProjection(native="assumed-ready"),
    lambda: c.ReadinessProjection(errors=(None,)),
    lambda: c.Capability("a", "b", ("preview",), (), False),
    lambda: c.Capability("a", "b", (), (), False),
    lambda: c.Capability("a", "b", (c.Mode.CHECK,), (), 1),
    lambda: c.CapabilityCatalog(qualification="ready"),
    lambda: c.CancelReceipt(1, "cancelled", 1.0),
    lambda: c.CancelReceipt(False, "cancelled", float("inf")),
])
def test_public_safety_dtos_reject_wrong_types_without_coercion(make):
    with pytest.raises(c.ContractError):
        make()


def test_nonsecret_boundary_rejects_nested_keys_recursion_and_secret_text():
    cases = (
        {"jump_password": "sentinel"}, {"enable_password": None},
        {"config": "username admin secret sentinel"},
        {"config": "-----BEGIN OPENSSH PRIVATE KEY-----"},
        {"unsupported": object()}, {5: "nonstring-key"},
    )
    for value in cases:
        with pytest.raises(c.ContractError):
            c.public_object(value)
    recursive = {}
    recursive["recursive"] = recursive
    with pytest.raises(c.ContractError):
        c.public_object(recursive)
    with pytest.raises(c.ContractError):
        c.public_object([])
    with pytest.raises(c.ContractError):
        c.canonical_bytes(object())
    with pytest.raises(c.ContractError):
        c.public_value("x" * (c.MAX_CONTENT_BYTES + 1))
    with pytest.raises(c.ContractError):
        c.Scope(("\ud800",))


def test_checked_bindings_preserve_max_and_never_serialize_private_values(operation_request):
    import pickle

    binding = c.PlanBinding(OPERATION_ID, D, D, D, D, D, D, D, "owned", c.MAX_SAFE_INT, ("recovery-1",))
    effect = c.EffectBinding(binding, OPERATION_ID, c.MAX_SAFE_INT, "occurrence", "r1", "s", ("recovery-1",))
    assert effect.expected_revision == c.MAX_SAFE_INT
    for change in (
        {"expected_revision": True}, {"expected_revision": -1},
        {"expected_revision": c.MAX_SAFE_INT + 1}, {"recovery_scope": ("widened",)},
        {"plan": None}, {"event_id": "not-uuid"},
    ):
        with pytest.raises(c.ContractError):
            replace(effect, **change)
    class UntrustedAuthorization(c.Authorization):
        @property
        def _host_owned(self):
            return False
    grant = UntrustedAuthorization()
    assert repr(grant) == "<private>"
    with pytest.raises(c.ContractError):
        c.canonical_bytes(grant)
    with pytest.raises(TypeError, match="private-value"):
        pickle.dumps(grant)
    c.ArtifactBinding(effect, "sensitive")
    with pytest.raises(c.ContractError):
        c.ArtifactBinding(effect, "secret-log")
    descriptor = c.ArtifactDescriptor("owned", D, 10**30, "text/plain", "public", "proof", "explicit", "resource", D)
    assert descriptor.size == 10**30
    with pytest.raises(c.ContractError):
        replace(descriptor, size=True)


def test_hydration_metadata_clock_and_source_shape_controls(operation_request, service):
    data = source("inventory")
    request = replace(operation_request, inputs=(data.source,))
    for clock_value in (float("nan"), -1.0, True):
        with pytest.raises(c.ContractError):
            hydrate_inputs(request, (data,), Clock(clock_value))
    for sources in ((), (data, data), (replace(data, source=replace(data.source, ref="other")),)):
        with pytest.raises(c.ContractError):
            hydrate_inputs(request, sources, Clock())
    with pytest.raises(c.ContractError):
        hydrate_inputs(request, (replace(data, observations=[]),), Clock())
    with pytest.raises(c.ContractError):
        hydrate_inputs(request, (replace(data, format="executable"),), Clock())
    with pytest.raises(c.ContractError):
        hydrate_inputs(request, (replace(data, content=b"changed"),), Clock())
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        with_sources(operation_request, source("inventory", b'{"value":NaN}'))
    loaded = hydrate_inputs(request, (data,), Clock())
    with pytest.raises(c.ContractError):
        replace(loaded, observations=[])
    with pytest.raises(c.ContractError):
        replace(loaded, schema_version="2.0")
    # Frozen values are not a trust boundary against deliberately corrupted objects.
    object.__setattr__(loaded, "request_digest", "b" * 64)
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(request, loaded)


def test_route_normalization_keeps_defaults_overrides_and_unresolved_targets(operation_request, service):
    data = source("inventory", json.dumps({
        "defaults": {"vendor": "cisco_ios", "transport": "ssh", "port": 2222},
        "devices": {"r1": {"host": "192.0.2.1", "port": 22}},
    }).encode())
    request, loaded = with_sources(operation_request, data)
    plan = service.preview(request, loaded)
    assert plan.routes[0]["host"] == "192.0.2.1" and plan.routes[0]["port"] == 22
    assert plan.routes[0]["vendor"] == "cisco_ios"
    assert plan.routes[1] == c.public_object({"target_id": "r2", "resolved": False})
    assert any(error.target_id == "r2" and error.reason == c.ReasonCode.ROUTE_UNAVAILABLE for error in plan.preconditions)
    for invalid in (
        b'{"devices":[]}', b'{"defaults":[]}', b'{"devices":{"r1":{"port":65536}}}',
        b'{"devices":{"r1":{"host":"https://not-a-route"}}}',
    ):
        with pytest.raises(c.ContractError, match="input-binding-invalid"):
            bad_request, bad_loaded = with_sources(operation_request, source("inventory", invalid))
            service.preview(bad_request, bad_loaded)


def test_declared_output_effects_and_destinations_are_complete(operation_request, service):
    request = replace(
        operation_request, operation="report.render", mode=c.Mode.OUTPUT, scope=c.Scope(()),
        output_intent=c.OutputIntent(("html", "pdf"), "owned-reports", retention=True, git=True),
    )
    request, loaded = with_sources(request, source("outcomes"))
    plan = service.preview(request, loaded)
    assert [effect.kind for effect in plan.effects] == ["render", "retention", "git"]
    assert all(effect.destination_ref == "owned-reports" for effect in plan.effects)
    assert len({effect.occurrence_id for effect in plan.effects}) == 3
    with pytest.raises(c.ContractError):
        replace(plan, effects=(replace(plan.effects[0], ordinal=1),))
    with pytest.raises(c.ContractError):
        replace(plan, routes=(c.public_object({"target_id": "lost"}),))
    context = c.ControllerContext(request.context)
    c.ControllerReadiness(context, c.ReadinessProjection(), D)
    c.ControllerRequest(request, plan)
    with pytest.raises(c.ContractError):
        c.ControllerRequest(replace(request, context=replace(request.context, controller_id="other")), plan)
    event = c.SafeEvent(OPERATION_ID, "s", "local", "c", c.Mode.OUTPUT, c.OutcomeStatus.BLOCKED,
                        c.ErrorCategory.PRECONDITION, c.ReasonCode.CONSENT_REQUIRED, False, 0.1)
    with pytest.raises(c.ContractError):
        replace(event, duration=float("inf"))


@pytest.mark.parametrize("content", [
    b"1: nonstring-key", b"devices: []", b"defaults: []",
    b"devices:\n  r1:\n    arbitrary_secret_field: value",
    b"devices:\n  r1:\n    tags: []", b"devices:\n  r1:\n    tags:\n      item: 5",
    b"devices:\n  r1:\n    groups: scalar", b"devices:\n  r1:\n    groups: [1]",
    b"devices:\n  unused:\n    port: true",
    b"!!python/object/apply:os.system ['never-run']",
])
def test_invalid_dormant_inventory_fields_and_yaml_tags_reject_before_planning(operation_request, content):
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        with_sources(operation_request, source("inventory", content, "yaml"))


def test_valid_yaml_mapping_and_nonsecret_groups_remain_ordered(operation_request, service):
    data = source("inventory", b"""defaults:
  transport: ssh
devices:
  r1:
    host: 192.0.2.1
    groups: [second, first]
    tags: {site: lab}
    jump_host: 192.0.2.10
    jump_port: 22
""", "yaml")
    request, loaded = with_sources(operation_request, data)
    result = service.preview(request, loaded)
    native = result.native_payload["inputs"][0]["value"]
    assert native["devices"]["r1"]["groups"] == ("second", "first")
    assert result.routes[0]["resolved"] is True


@pytest.mark.parametrize("content,fmt", [
    (b'{"password":"sentinel-do-not-hash"}', "json"),
    (b"username admin password sentinel-do-not-hash", "text"),
])
def test_credential_bytes_are_rejected_before_hashing(operation_request, content, fmt):
    data = source("inventory", content, fmt)
    request = replace(operation_request, inputs=(data.source,))
    with mock.patch("netops.ansible.workflows.hashlib.sha256", side_effect=AssertionError("secret hashed")):
        with pytest.raises(c.ContractError, match="input-binding-invalid"):
            hydrate_inputs(request, (data,), Clock())


def test_cancel_is_truthful_and_does_not_invent_effectful_revocation(policy):
    _, engine = policy
    bomb = Bomb()
    clock = Clock(18.5)
    service = WorkflowService(engine, bomb, bomb, bomb, bomb, bomb, clock, bomb)
    receipt = service.cancel(OPERATION_ID)
    assert receipt.accepted is False and receipt.received_at == 18.5
    assert receipt.reason == "dependency-not-ready" and clock.calls == 1
    with pytest.raises(c.ContractError):
        service.cancel("not-an-operation")


def test_plan_and_outcome_safety_fields_reject_inconsistent_direct_construction(operation_request, service):
    request, loaded = with_sources(operation_request)
    plan = service.preview(request, loaded)
    for fields in (
        {"schema_version": "2.0"}, {"concurrency": True}, {"deadline_ms": float("inf")},
        {"policy_digest": "b" * 64}, {"reducer_version": "2"}, {"preconditions": (None,)},
    ):
        with pytest.raises(c.ContractError):
            replace(plan, **fields)
    with pytest.raises(c.ContractError):
        c.aggregate_outcome(request, (), cleanup=None)
    with pytest.raises(c.ContractError):
        c.aggregate_outcome(request, (), errors=[None])
    assert c.checked_deadline(10.0, 0.25) == 10.25
    assert c.digest(c.public_object({"first": 1, "second": 2})) == c.digest(
        c.public_object({"second": 2, "first": 1}),
    )
    assert c.digest(c.public_object({"commands": ("first", "second")})) != c.digest(
        c.public_object({"commands": ("second", "first")}),
    )


def test_remaining_public_shape_guards_and_required_operands(operation_request, service):
    request = operation_request
    data = source("inventory")
    for fields in (
        {"scope": None}, {"context": None}, {"output_intent": None},
        {"inputs": [data.source]}, {"inputs": (None,)}, {"inputs": (data.source, data.source)},
    ):
        with pytest.raises(c.ContractError):
            replace(request, **fields)
    for path, key, value in (((), "inputs", {}), (("output_intent",), "git", 1)):
        encoded = json.loads(c.canonical_bytes(request))
        target = encoded
        for item in path:
            target = target[item]
        target[key] = value
        with pytest.raises(c.ContractError):
            c.OperationRequest.from_json(json.dumps(encoded).encode())
    with pytest.raises(c.ContractError):
        hydrate_inputs(replace(request, operation="inventory.validate"), (), Clock())
    with pytest.raises(c.ContractError):
        c.aggregate_outcome(None, ())
    with pytest.raises(c.ContractError):
        c.ControllerContext(None)
    context = c.ControllerContext(request.context)
    with pytest.raises(c.ContractError):
        c.ControllerReadiness(context, None, D)
    with pytest.raises(c.ContractError):
        c.ControllerRequest(request, None)
    with pytest.raises(c.ContractError):
        c.ArtifactDescriptor("owned", D, 1, "text/plain", "unknown", "proof", "explicit", "resource", D)
    with pytest.raises(c.ContractError):
        c.SafeEvent(OPERATION_ID, "s", "r1", "c", "observe", c.OutcomeStatus.BLOCKED, None, None, False, 0.1)
    with pytest.raises(c.ContractError):
        c.PlannedEffect("effect", 0, "shell", "r1", "s")
    request, loaded = with_sources(request)
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(None, loaded)
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(request, None)
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        with_sources(operation_request, source("inventory", b'{"unknown":[] }'))


def test_policy_denial_and_malformed_identity_do_not_turn_into_permission(operation_request, policy):
    from netops.ansible.policy import PolicyInputError
    from netops.ansible.workflows import PolicyFailure

    identity, engine = policy
    class FaultPolicy:
        def __init__(self, kind):
            self.kind = kind
        def decide(self, event, facts):
            if self.kind == "exception":
                raise PolicyInputError("do-not-copy-private-detail")
            real = engine.decide(event, facts)
            if self.kind == "identity":
                return replace(real, policy_digest="b" * 64)
            return replace(real, decision="deny", effects=())
        def reduce(self, state, event, facts):
            raise AssertionError("preview must not reduce")
    request, loaded = with_sources(operation_request)
    bomb = Bomb()
    for fault in ("exception", "identity", "deny"):
        service = WorkflowService(FaultPolicy(fault), bomb, bomb, bomb, bomb, bomb, bomb, bomb)
        if fault == "deny":
            result = service.preview(request, loaded)
            assert result.policy_digest == identity.bundle_sha256
            assert any(error.category == c.ErrorCategory.POLICY for error in result.preconditions)
        else:
            with pytest.raises(PolicyFailure) as error:
                service.preview(request, loaded)
            assert error.value.error.category == c.ErrorCategory.POLICY
            assert error.value.exit_code == 5
            assert "private" not in str(error.value)


def test_remaining_loaded_container_defenses_have_explicit_fault_controls(operation_request, service):
    from netops.ansible import workflows

    request, loaded = with_sources(operation_request)
    for bad in ([], (None,)):
        corrupted = replace(loaded)
        object.__setattr__(corrupted, "observations", bad)
        with pytest.raises(c.ContractError, match="input-binding-invalid"):
            service.preview(request, corrupted)
    with pytest.raises(c.ContractError):
        workflows._content(None)
    with pytest.raises(c.ContractError):
        plan_digest(None)
    with pytest.raises(c.ContractError):
        c.Observation("observation", "r1", D, D, "controller", None, D, "2026-11-17T22:00:00Z", 0.0)
    result = service.execute(operation_request)
    with pytest.raises(c.ContractError):
        replace(result, steps=(None,))


def test_total_hydration_budget_and_bytes_subclasses_fail_closed(operation_request):
    data = b"x" * c.MAX_CONTENT_BYTES
    sources = tuple(source("before", data, "text", ref=f"explicit-source-{index}") for index in range(17))
    request = replace(operation_request, inputs=tuple(item.source for item in sources))
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        hydrate_inputs(request, sources, Clock())
    class NotExactBytes(bytes):
        pass
    data = source("before", b"x", "text")
    request = replace(operation_request, inputs=(data.source,))
    with pytest.raises(c.ContractError):
        hydrate_inputs(request, (replace(data, content=NotExactBytes(b"x")),), Clock())


def test_multiple_inventory_and_nontext_compare_inputs_are_not_silently_selected(operation_request, service):
    request, loaded = with_sources(
        operation_request, source("inventory", ref="first"), source("inventory", ref="second"),
    )
    with pytest.raises(c.ContractError):
        service.preview(request, loaded)
    request = replace(operation_request, operation="compare.compare")
    request, loaded = with_sources(request, source("before"), source("after"))
    with pytest.raises(c.ContractError):
        service.preview(request, loaded)


def test_descriptor_kind_and_return_type_are_rechecked_before_accepting_content(operation_request):
    import stat
    from types import SimpleNamespace

    selected = ROOT / "tests" / "fixtures" / "c01-descriptor-fault-input.json"
    selected.write_bytes(b"{}")
    try:
        data = source("inventory")
        request = replace(operation_request, inputs=(data.source,))
        with selected.open("rb") as descriptor:
            with mock.patch("netops.ansible.workflows.os.fstat", return_value=SimpleNamespace(st_mode=stat.S_IFIFO)):
                with pytest.raises(c.ContractError):
                    hydrate_inputs(request, (replace(data, content=descriptor),), Clock())
        with selected.open("rb") as descriptor:
            descriptor.read = lambda count: "not-binary"
            with pytest.raises(c.ContractError):
                hydrate_inputs(request, (replace(data, content=descriptor),), Clock())
    finally:
        selected.unlink()


def test_route_decoder_defense_is_independent_of_prior_inventory_validation(operation_request):
    from netops.ansible import workflows

    request = replace(operation_request, inputs=(source("inventory").source,))
    # Isolated post-validation defenses, not evidence that the public decoder
    # admits malformed inventory.
    for values in ((True,), (c.public_object({"devices": []}),)):
        with pytest.raises(c.ContractError):
            workflows._routes(request, values)


def test_dependency_port_values_are_typed_selection_and_evidence_not_fake_readiness(operation_request):
    scope = c.InstallScope(("native-inventory",), ("inventory.validate",), False)
    context = c.InstallContext(operation_request.context)
    report = c.ReadinessReport("selected-revision", context, (), c.ReadinessProjection())
    assert scope.full_toolkit is True and report.readiness.companion == "blocked"
    with pytest.raises(c.ContractError):
        replace(scope, enhanced=1)
    with pytest.raises(c.ContractError):
        c.InstallContext(None)
    with pytest.raises(c.ContractError):
        replace(report, schema_version="2.0")
