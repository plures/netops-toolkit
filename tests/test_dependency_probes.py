"""Focused probe failures using explicit foreign-platform fakes, not qualification."""

import hashlib
import io
import json
import platform
import sys
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import LocalReferencePolicyEngine, PolicyIdentity, load_policy
from netops.dependencies import (
    ConsumingContext,
    DependencyRegistry,
    DependencyService,
    LocalDependencyAdapter,
    ProbeResult,
    RegistryError,
)
from netops.dependencies.adapters import _version_matches
from netops.dependencies.service import ADAPTERS


def context(**changes):
    values = dict(
        id="native", platform=sys.platform, architecture=platform.machine(),
        python=sys.executable, path="", role="native",
    )
    values.update(changes)
    return ConsumingContext(**values)


def test_actual_interpreter_probe_and_missing_executable_are_distinct():
    registry = DependencyRegistry.load()
    adapter = LocalDependencyAdapter({"native": context()})
    python = adapter.probe(registry.entry("native-python"), context(), time.monotonic() + 5.0)
    assert python.status == "available"
    assert python.version
    missing = adapter.probe(registry.entry("git"), context(), time.monotonic() + 5.0)
    assert missing.status == "missing"
    assert missing.reason == "executable-missing"


def test_foreign_context_is_not_probed_or_qualified():
    registry = DependencyRegistry.load()
    foreign = context(platform="foreign-os")
    result = LocalDependencyAdapter({"native": foreign}).probe(
        registry.entry("native-python"), foreign, time.monotonic() + 5.0,
    )
    assert result.status == "blocked"
    assert result.reason == "context-unavailable"


def test_expired_deadline_never_dispatches():
    registry = DependencyRegistry.load()
    result = LocalDependencyAdapter({"native": context()}).probe(
        registry.entry("native-python"), context(), time.monotonic() - 1.0,
    )
    assert result.reason == "deadline-exceeded"


@pytest.fixture(scope="module")
def policy():
    root = Path("netops") / "ansible" / "policy"
    source = (root / "ansible_molecule.px").read_bytes()
    contracts = (root / "ansible_molecule.contracts.px").read_bytes()
    bundle = (root / "bundle.json").read_bytes()
    parsed = json.loads(bundle)
    identity = PolicyIdentity(
        parsed["canonical_revision"], hashlib.sha256(source).hexdigest(),
        hashlib.sha256(contracts).hexdigest(), hashlib.sha256(bundle).hexdigest(),
        tuple(x["id"] for x in parsed["manifest"]), parsed["reducer_version"],
    )
    return identity, LocalReferencePolicyEngine(load_policy(source, contracts, bundle, identity))


class FixtureAdapter:
    """Foreign-platform fixture observations, explicitly never Q03 evidence."""

    def __init__(self, missing=()):
        self.contexts = {
            "native": context(),
            "controller": context(id="controller", role="controller", platform="linux"),
        }
        self.missing = missing
        self.calls = []

    def probe(self, entry, consuming, deadline):
        self.calls.append((entry.id, consuming.digest, deadline))
        missing = entry.id in self.missing
        return ProbeResult(
            entry.id, consuming.digest, "missing" if missing else "available",
            "fixture-missing" if missing else "fixture-not-qualification",
            "1.0", None if missing else "a" * 64,
        )


def service_and_context(policy, missing=()):
    identity, engine = policy
    registry = DependencyRegistry.load()
    adapter = FixtureAdapter(missing)
    clock = Mock()
    clock.monotonic.side_effect = time.monotonic
    events = Mock()
    state, authorization = Mock(), Mock()
    service = DependencyService(
        registry, dict.fromkeys(ADAPTERS, adapter), state, engine, authorization, clock, events,
    )
    selected = c.InstallContext(c.Context(
        "controller", "a" * 64, "fixture", "b" * 64, identity, registry.digest, "c" * 64,
    ))
    return service, selected, adapter, events


def test_pure_plan_covers_all_prerequisites_and_separate_grants(policy):
    service, selected, adapter, events = service_and_context(policy)
    plan = service.plan(c.InstallScope((), (), True), selected)
    ids = {x.dependency for x in plan.steps}
    assert {"git", "ping", "pysnmp", "native-pdf-libraries", "molecule",
            "container-runtime", "container-image", "ansible.netcommon", "xargs"} <= ids
    platform_step = next(x for x in plan.steps if x.dependency == "controller-platform")
    assert {"wsl", "vm", "reboot", "elevation"} <= set(platform_step.separate_grants)
    assert plan.policy_identity == selected.context.policy_identity
    assert plan.qualification == "unqualified"
    assert not adapter.calls
    events.emit.assert_not_called()
    service.state.assert_not_called()
    service.authorization.assert_not_called()


def test_native_stays_usable_when_controller_and_enhanced_missing(policy):
    service, selected, _, events = service_and_context(policy, ("ansible-core", "molecule"))
    report = service.verify(c.InstallScope(("native.transport",), (), False, False), selected)
    assert isinstance(report, c.ReadinessReport)
    assert report.readiness.native == "ready"
    assert report.readiness.companion == "not-requested"
    assert report.readiness.enhanced == "not-requested"
    assert events.emit.call_count > 0


def test_full_scope_includes_optional_failures_and_never_qualifies_mocks(policy):
    service, selected, _, _ = service_and_context(policy, ("git", "native-pdf-libraries"))
    report = service.verify(c.InstallScope((), (), True), selected)
    assert report.readiness.native == "blocked"
    assert report.readiness.companion == "blocked"
    assert report.readiness.enhanced == "blocked"
    records = [x for x in report.capabilities if "qualification" in x]
    assert {x["qualification"] for x in records if x["tier"] == "companion"} == {"unqualified"}
    assert any("git" in x["missing"] for x in records)


def test_verified_reuse_is_bound_to_exact_context_and_policy(policy):
    service, selected, _, _ = service_and_context(policy)
    scope = c.InstallScope(("native.transport",), (), False, False)
    service.verify(scope, selected)
    assert all(x.reuse == "verified-reuse" for x in service.plan(scope, selected).steps)
    changed = c.InstallContext(replace(selected.context, assets_digest="d" * 64))
    assert all(x.reuse == "reprobe-required" for x in service.plan(scope, changed).steps)


def test_registry_drift_is_blocked_before_probe(policy):
    service, selected, adapter, _ = service_and_context(policy)
    changed = c.InstallContext(replace(selected.context, registry_digest="f" * 64))
    # Real policy rejects stale bindings, rather than laundering them into readiness.
    report = service.verify(c.InstallScope(("native.transport",), (), False, False), changed)
    assert report.readiness.native == "blocked"
    assert not adapter.calls
    assert report.capabilities[-1]["policy_decision"] == "deny"


def test_policy_source_identity_drift_blocks_even_with_same_bundle(policy):
    service, selected, adapter, _ = service_and_context(policy)
    identity = replace(selected.context.policy_identity, source_sha256="e" * 64)
    changed = c.InstallContext(replace(selected.context, policy_identity=identity))
    report = service.verify(c.InstallScope(("native.transport",), (), False, False), changed)
    assert report.readiness.native == "blocked"
    assert not adapter.calls
    assert report.capabilities[-1]["policy_decision"] == "deny"


def test_missing_adapter_and_unknown_capability_fail_closed(policy):
    service, selected, adapter, _ = service_and_context(policy)
    with pytest.raises(RegistryError, match="adapter-missing"):
        DependencyService(service.registry, {"python": adapter}, Mock(), service.policy,
                          Mock(), service.clock, Mock())
    with pytest.raises(RegistryError, match="capability-unknown"):
        service.plan(c.InstallScope(("invented",), (), False, False), selected)


@pytest.mark.parametrize(("actual", "required", "matches"), [
    ("3.12.0", ">=3.9", True), ("3.8.9", ">=3.9", False),
    ("5.0.0", ">=5.0.0,<6.0.0", True), ("6.0.0", ">=5.0.0,<6.0.0", False),
    ("garbage", ">=3.9", False),
])
def test_version_range_is_compatibility_not_qualification(actual, required, matches):
    assert _version_matches(actual, required) is matches


def test_probe_log_and_counter_pair_carries_safe_dimensions(caplog):
    caplog.set_level("INFO", logger="netops.dependencies.adapters")
    registry = DependencyRegistry.load()
    adapter = LocalDependencyAdapter({"native": context()})
    adapter.probe(registry.entry("git"), context(), time.monotonic() + 2.0)
    record = caplog.records[-1]
    assert record.msg == "dependency.probe"
    assert record.metric_name == "netops.dependency.probe.count"
    assert record.metric_value == 1
    assert record.status == "missing"
    assert record.category == "dependency"
    assert record.next_action == "review-install-plan"
    assert adapter.counts[record.context, record.status, record.reason] == 1


@pytest.mark.parametrize(("dependency", "reason"), [
    ("container-runtime", "runtime-functional-proof-required"),
    ("container-image", "asset-lock-required"),
    ("controller-platform", "platform-grant-unverified"),
])
def test_authority_dependent_probes_never_fabricate_success(monkeypatch, dependency, reason):
    # Explicit same-host controller fixture, not evidence qualifying that platform.
    selected = context(id="controller", role="controller")
    entry = replace(DependencyRegistry.load().entry(dependency), platforms=(sys.platform,))
    process = Mock(side_effect=AssertionError("Must not contact services or acquire assets"))
    monkeypatch.setattr("netops.dependencies.adapters.subprocess.Popen", process)
    result = LocalDependencyAdapter({"controller": selected}).probe(
        entry, selected, time.monotonic() + 1.0,
    )
    assert result.status == "blocked"
    assert result.reason == reason
    process.assert_not_called()


def test_missing_optional_git_blocks_only_explicit_git_intent(policy):
    service, selected, _, _ = service_and_context(policy, ("git",))
    plain = service.verify(c.InstallScope(("native.backup",), (), False, False), selected)
    selected_git = service.verify(
        c.InstallScope(("native.backup:git",), (), False, False), selected,
    )
    assert plain.readiness.native == "ready"
    assert selected_git.readiness.native == "blocked"


@pytest.mark.parametrize(("payload", "returncode", "reason"), [
    (b'{"version":"2.0"}', 0, "version-mismatch"),
    (b"ModuleNotFoundError: PRIVATE_SENTINEL", 1, "module-missing"),
    (b"not-json PRIVATE_SENTINEL", 0, "probe-receipt-invalid"),
    (b"x" * 65537, 0, "probe-output-limit"),
], ids=["version-mismatch", "module-missing", "invalid-receipt", "output-limit"])
def test_module_probe_failures_are_safe_and_bounded(monkeypatch, payload, returncode, reason):
    class Process:
        def __init__(self, command, **kwargs):
            self.command = command
            self.stdout = io.BytesIO(payload)
            self.returncode = returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = 1

    monkeypatch.setattr("netops.dependencies.adapters.subprocess.Popen", Process)
    entry = DependencyRegistry.load().entry("pyyaml")
    result = LocalDependencyAdapter({"native": context()}).probe(
        entry, context(), time.monotonic() + 2.0,
    )
    assert result.status != "available"
    assert result.reason == reason
    assert "PRIVATE_SENTINEL" not in repr(result)


def test_selected_controller_cli_uses_consuming_python_not_path_tool(monkeypatch):
    calls = []

    class Process:
        def __init__(self, command, **kwargs):
            calls.append((command, kwargs))
            self.stdout = io.BytesIO(b"ansible-playbook [core 2.16.8]")
            self.returncode = 0

        def wait(self, timeout=None):
            return 0

        def kill(self):
            self.returncode = 1

    monkeypatch.setattr("netops.dependencies.adapters.subprocess.Popen", Process)
    entry = replace(DependencyRegistry.load().entry("ansible-playbook"), platforms=(sys.platform,))
    selected = context(role="controller")
    result = LocalDependencyAdapter({"controller": selected}).probe(
        entry, selected, time.monotonic() + 2.0,
    )
    assert result.status == "available"
    assert calls[0][0][:5] == [sys.executable, "-I", "-B", "-m", "ansible.cli.playbook"]
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["env"]["PATH"] == selected.path
