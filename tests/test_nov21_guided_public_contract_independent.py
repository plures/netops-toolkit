"""Actual public dependency-method contracts with explicit SOURCE-only typed ports."""

import base64
import hashlib
import json
import os
import platform
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.dependencies import service as dependency
from tests.test_nov21_lifecycle_literal_independent import (
    EXPECTED_CONTEXT,
    EXPECTED_SCOPE,
    D,
    expected,
    values,
)

CATALOG = (
    '{"digest":"@D@","entries":[{"adapter":"python","consumers":["native.stdlib"],'
    '"context":"native","digest":null,"effects":["owned-write"],"id":"native-python",'
    '"kind":"python","ownership":"toolkit-owned-only","platforms":["win32","linux","darwin"],'
    '"probe":"python","recovery":"retain-prior-generation","requires":[],"size":null,'
    '"source":"python.org","version":">=3.9"}],"native_baseline":["native-python"],'
    '"operations":[{"aliases":[],"capability":"native.stdlib",'
    '"dependencies":["native-python"],"export_dependencies":[["identity",["native-python"]]],'
    '"exports":["identity"],"intents":[],"module":"fixture.native","tier":"native",'
    '"ui_actions":[],"variants":[]}],"revision":"fixture-v1"}'
)


@pytest.fixture
def public_contract(monkeypatch):
    """Inject ordinary policy/probe ports, not a platform or live-grant qualification."""
    context, scope, _, _ = values()
    identity = context.context.policy_identity
    monkeypatch.setattr(dependency, "_packaged_identity", lambda: identity)
    original = dependency.DependencyRegistry.load()
    entry = replace(original.entry("native-python"), consumers=("native.stdlib",))
    operation = dependency.PublicOperation(
        "fixture.native", ("identity",), "native.stdlib", "native", ("native-python",),
        (), export_dependencies=(("identity", ("native-python",)),),
    )
    registry = dependency.DependencyRegistry(
        "fixture-v1", (entry,), (operation,), original.qualification, D, ("native-python",),
    )
    consuming = dependency.ConsumingContext(
        "native-fixture", "linux", "fixture-architecture",
        os.path.abspath(os.sep + "fixture-python"), "", "native",
    )
    probes = Mock()
    probes.contexts = {"native": consuming}
    probes.probe.side_effect = lambda entry, target, deadline: dependency.ProbeResult(
        entry.id, target.digest, "available", "source-only-not-qualified", "3.12.0", "b" * 64,
        "none",
    )
    policy = Mock()
    policy.decide.return_value = lc.DecisionResult("allow", (), "source-only", (), D)
    clock = Mock()
    clock.monotonic.return_value = 10.0
    authority, state, events = Mock(), Mock(), Mock()
    service = dependency.DependencyService(
        registry, dict.fromkeys(dependency.ADAPTERS, probes), state, policy,
        authority, clock, events,
    )
    return service, context, scope, consuming, probes, policy


def input_digest(value):
    """Independent canonical-input hashing, not serialization of returned DTOs."""
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()


def consuming_digest(consuming):
    """Pin every fixture context input independently of ConsumingContext.digest."""
    return input_digest({
        "architecture": "fixture-architecture", "collection_paths": [], "driver": None,
        "grants": [], "id": "native-fixture", "image": None, "path": "",
        "platform": "linux", "python": consuming.python, "role": "native",
    })


def readiness_literal(consuming, *, missing=False):
    digest = consuming_digest(consuming)
    version = None if missing else "3.12.0"
    # This digest binds the declared input fixture, never a returned report/receipt.
    qualification = input_digest({
        "contexts": [{
            "architecture": "fixture-architecture", "collection_paths": [], "driver": None,
            "grants": [], "id": "native-fixture", "image": None, "path": "",
            "platform": "linux", "python": consuming.python, "role": "native",
        }],
        "versions": {"native-python": version},
        "policy": {
            "schema": "1.0", "canonical_revision": "6d367fe673756dabaa6085bc6b5202debaaabe6f",
            "source_sha256": D, "contracts_sha256": D, "bundle_sha256": D,
            "rule_manifest": ["fixture.rule"], "reducer_version": "1",
            "profile": "netops-reference-v1", "numeric_profile": "exact-int53-finite-order-v1",
        },
        "assets": D, "route": D,
    })
    probe = (
        '{"context_digest":"@CONSUMING@","dependency":"native-python",'
        '"evidence_digest":null,"next_action":"review-setup","reason":"missing-interpreter",'
        '"status":"missing","version":null}'
        if missing else
        '{"context_digest":"@CONSUMING@","dependency":"native-python",'
        '"evidence_digest":"' + "b" * 64 + '","next_action":"none",'
        '"reason":"source-only-not-qualified","status":"available","version":"3.12.0"}'
    )
    template = (
        '{"capabilities":[{"capability":"native.stdlib","missing":@MISSING@,'
        '"next_action":"@ACTION@","probes":[' + probe + '],"qualification":"not-required",'
        '"status":"@STATUS@","tier":"native"},{"consuming_context_digests":["@CONSUMING@"],'
        '"policy_decision":"allow","policy_digest":"@D@","qualification_state":"unqualified",'
        '"qualification_tuple_digest":"@QUALIFICATION@"}],"context":@CONTEXT@,'
        '"readiness":{"companion":"not-requested","enhanced":"not-requested","errors":[],'
        '"native":"@STATUS@"},"revision":"fixture-v1","schema_version":"1.0"}'
    )
    return expected(
        template.replace("@MISSING@", '["native-python"]' if missing else "[]")
        .replace("@STATUS@", "blocked" if missing else "ready")
        .replace("@ACTION@", "resolve-prerequisites" if missing else "none")
        .replace("@CONSUMING@", digest).replace("@QUALIFICATION@", qualification),
    )


def test_ac002_actual_catalog_full_nested_literal_is_read_only(public_contract):
    service, _, _, _, probes, policy = public_contract
    assert c.canonical_bytes(service.catalog()) == expected(CATALOG)
    probes.probe.assert_not_called()
    policy.decide.assert_not_called()
    service.authorization.assert_not_called()
    service.events.emit.assert_not_called()
    assert not service.state.method_calls


@pytest.mark.parametrize("missing", [False, True])
def test_ac001_ac002_actual_verify_nonempty_nested_probe_and_qualification_literal(
    public_contract, missing,
):
    service, context, scope, consuming, probes, policy = public_contract
    if missing:
        probes.probe.side_effect = lambda entry, target, deadline: dependency.ProbeResult(
            entry.id, target.digest, "missing", "missing-interpreter",
            next_action="review-setup",
        )
    assert c.canonical_bytes(scope) == expected(EXPECTED_SCOPE)
    assert c.canonical_bytes(context) == expected(EXPECTED_CONTEXT)
    report = service.verify(scope, context)
    assert c.canonical_bytes(report) == readiness_literal(consuming, missing=missing)
    probes.probe.assert_called_once_with(service.registry.entry("native-python"), consuming, 15.0)
    policy.decide.assert_called_once()
    service.authorization.assert_not_called()
    assert not service.state.method_calls


@pytest.mark.parametrize("damage", ["registry", "policy", "controller"])
def test_ac003_actual_verify_binding_drift_is_blocked_before_probe(public_contract, damage):
    service, context, scope, _, probes, _ = public_contract
    if damage == "registry":
        context = c.InstallContext(replace(context.context, registry_digest="e" * 64))
        reason = "registry-drift"
    elif damage == "policy":
        context = c.InstallContext(replace(
            context.context,
            policy_identity=replace(context.context.policy_identity, source_sha256="e" * 64),
        ))
        reason = "policy-identity-drift"
    else:
        entry = replace(service.registry.entries[0], context="controller")
        service.registry.entries = (entry,)
        probes.contexts = {"controller": replace(
            probes.contexts["native"], id="wrong-controller", role="controller",
        )}
        reason = "controller-drift"
    report = service.verify(scope, context)
    assert report.readiness.native == "blocked"
    assert report.capabilities[0]["probes"][0]["reason"] == reason
    probes.probe.assert_not_called()
    service.authorization.assert_not_called()
    assert not service.state.method_calls


@pytest.mark.parametrize("preview", [False, True])
def test_ac002_public_first_run_whole_nonempty_json_literal(public_contract, monkeypatch, capsys,
                                                          preview):
    """Pin actual public CLI wire; injected composition is SOURCE-only, no private grants."""
    from netops import setup
    from netops.dependencies import _setup

    service, context, _, consuming, _, _ = public_contract
    root = Path(os.path.abspath(os.sep + "nov21-independent-contract-uncreated-root"))
    assert not root.exists()
    monkeypatch.setattr(_setup.DependencyRegistry, "load", lambda: service.registry)
    monkeypatch.setattr(_setup, "_context", lambda *_: context)
    monkeypatch.setattr(_setup, "_existing_contexts", lambda: {"native": consuming})

    def compose(registry, contexts, review, state):
        assert registry is service.registry and contexts == {"native": consuming}
        assert state is None
        return service

    monkeypatch.setattr(_setup, "_service", compose)
    monkeypatch.setattr("builtins.input", lambda _: "")
    argv = ["plan" if preview else "install", "--root", str(root),
            "--capability", "native.stdlib"]
    assert setup.main(argv) == 3
    output = [line for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    assert len(output) == 1
    root_json = json.dumps(str(root))
    digest = consuming_digest(consuming)
    scope_json = expected(EXPECTED_SCOPE).decode()
    selection = (
        '{"categories":[],"components":[]}' if preview else
        '{"categories":[],"components":[["native-python","reuse"]]}'
    )
    checkpoint_document = (
        '{"consuming_contexts":["' + digest + '"],"registry_digest":"' + D + '",'
        '"root":' + root_json + ',"schema":"netops-guided-selection-v1","scope":'
        + scope_json + ',"selection":' + selection + '}'
    )
    checkpoint = base64.urlsafe_b64encode(checkpoint_document.encode()).decode().rstrip("=")
    observation = (
        "null" if preview else
        '{"context_digest":"' + digest + '","dependency":"native-python",'
        '"evidence_digest":"' + "b" * 64 + '","next_action":"none",'
        '"reason":"source-only-not-qualified","status":"available","version":"3.12.0"}'
    )
    command_prefix = json.dumps([
        sys.executable, "-I", "-B", "-c",
        "import sys; sys.path.insert(0,sys.argv.pop(1)); "
        "from netops.setup import main; raise SystemExit(main())",
        str(Path(setup.__file__).resolve().parents[1]),
    ], separators=(",", ":"))[:-1]
    next_command = (
        command_prefix + ',"install","--root",' + root_json +
        ',"--capability","native.stdlib","--checkpoint","' + checkpoint + '"]'
    )
    literal = (
        '{"checkpoint":"' + checkpoint + '","closure":[{"choices":'
        + ('["install","decline"]' if preview else '["reuse","install","decline"]')
        + ',"context":"native","default":"' + ("decline" if preview else "reuse")
        + '","dependency":"native-python","kind":"python","observation":' + observation
        +         ',"platforms":["win32","linux","darwin"],"requires":[],"source":"python.org",'
        '"version":">=3.9"}],"consent_issued":false,"effects_performed":[],'
        '"host_architecture":' + json.dumps(platform.machine()) + ',"host_platform":'
        + json.dumps(sys.platform) + ','
        '"needs":[{"choices":'
        + ('["install","decline"]' if preview else '["reuse","install","decline"]')
        + ',"dependency":"native-python","fields":["compatible-version","platform",'
        '"source-identity","sha256","size","exact-members","transitive-wheel-collection-lock",'
        '"provider-handler"],"kind":"python","platforms":["win32","linux","darwin"],'
        '"reason":"verified-metadata-required","source":"python.org","version":">=3.9"}],'
        '"next_command":' + next_command + ',"readiness":'
        + ("null" if preview else readiness_literal(consuming).decode())
        + ',"registry_digest":"' + D + '","schema":"netops-guided-selection-v1",'
        '"scope":' + scope_json + ',"selection":' + selection + ',"status":"'
        + ("Planned" if preview else "NeedsInput") + '"}'
    )
    if not preview:
        original_needs = (
            '"needs":[{"choices":["reuse","install","decline"],'
            '"dependency":"native-python","fields":["compatible-version","platform",'
            '"source-identity","sha256","size","exact-members","transitive-wheel-collection-lock",'
            '"provider-handler"],"kind":"python","platforms":["win32","linux","darwin"],'
            '"reason":"verified-metadata-required","source":"python.org","version":">=3.9"}]'
        )
        reviewed_needs = (
            '"needs":[{"choices":["reuse","install","decline"],'
            '"dependency":"native-python","fields":["compatible-version","source-identity",'
            '"sha256","size","transitive-wheel-collection-lock","provider-handler",'
            '"official-release-file-id","independently-retained-official-json-sha256",'
            '"separately-verified-archive-sha256","exact-archive-members",'
            '"qualified-platform-architecture"],"kind":"python",'
            '"platforms":["win32","linux","darwin"],"reason":"verified-metadata-required",'
            '"source":"python.org","version":">=3.9"},'
            '{"choices":["install","decline"],"dependency":"native:netops-toolkit",'
            '"fields":["publisher-metadata"],"kind":"wheel","platforms":['
            + json.dumps(sys.platform) + '],"reason":"registered-metadata-source-required",'
            '"source":"pypi:netops-toolkit","version":"==0.52.2"}]'
        )
        assert literal.count(original_needs) == 1
        literal = literal.replace(original_needs, reviewed_needs)
    assert output[0].encode() == literal.encode()
    assert not root.exists()
