"""Public installer composition proof with functional fake file/HTTP/probe ports.

The managed manifest is a product tree, not the predecessor inert-byte schema.
The fakes do not qualify any actual interpreter, controller, OS, or platform.
"""

from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile
from dataclasses import replace
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    TrustedConsentAdapter,
    TrustedLifecycleConsentAdapter,
)
from netops.dependencies._assets import AssetResponse, LockedAsset
from netops.dependencies._composition import ManagedLifecycleState
from netops.dependencies._lifecycle import InstallOutcome
from netops.dependencies._managed import ManagedGenerationManifest, ManagedMember
from netops.dependencies.service import ADAPTERS, DependencyRegistry, DependencyService
from tests import test_nov19_independent_dependency_lifecycle as predecessor
from tests.policy import test_lifecycle_execution as lifecycle
from tests.test_nov19_independent_controller_execution import Cancel, Events
from tests.test_nov19_independent_credentials import Clock

GENERATION = "52f739c9-53f6-48f4-9c46-8fa170c2f673"
MEMBER = "bin/python"
MEMBER_BYTES = b"functional fake interpreter image; never execute"


class Files:
    """Actual fake storage contract: exact staged tree must precede verification."""

    def __init__(self):
        self.content = None
        self.calls = []
        self.drift = False

    def stage(self, manifest, files, clock, cancel, deadline):
        assert clock.monotonic() < deadline and not cancel.is_cancelled()
        self.calls.append("stage")
        self.content = tuple((item.member, item.content) for item in files)
        assert self.content == ((manifest.members[0], MEMBER_BYTES),)

    def verify(self, manifest, clock, cancel, deadline):
        assert clock.monotonic() < deadline and not cancel.is_cancelled()
        self.calls.append("verify")
        if self.drift or self.content != ((manifest.members[0], MEMBER_BYTES),):
            raise PermissionError("fake product tree is missing or drifted")


class Transport:
    def __init__(self, content, url):
        self.content, self.url, self.calls = content, url, []

    def read(self, url, timeout, limit):
        assert url == self.url and 0 < timeout <= 30
        assert limit == len(self.content) + 1
        self.calls.append((url, timeout, limit))
        return AssetResponse(url, self.content)


def managed_environment():
    """Compose the real public service, actual reducer and real admission broker."""
    identity, engine = lifecycle.policy.__wrapped__()[:2]
    registry, probes, clock = DependencyRegistry.load(), predecessor.Probes(), Clock()
    scope = c.InstallScope(("native.stdlib",), (), False, False)
    context = c.InstallContext(c.Context(
        "owned-controller", "a" * 64, "inventory", "b" * 64,
        identity, registry.digest, "d" * 64,
    ))
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        info = zipfile.ZipInfo(MEMBER)
        info.external_attr = (stat.S_IFREG | 0o700) << 16
        archive.writestr(info, MEMBER_BYTES)
    content = stream.getvalue()
    asset = LockedAsset(
        "reviewed-python-archive", "native-python",
        "https://www.python.org/ftp/python/exact-reviewed.zip",
        hashlib.sha256(content).hexdigest(), len(content),
    )
    manifest = ManagedGenerationManifest(
        GENERATION, asset, "zip",
        (ManagedMember(MEMBER, hashlib.sha256(MEMBER_BYTES).hexdigest(), len(MEMBER_BYTES), True),),
        scope, context, tuple(sorted(item.digest for item in probes.contexts.values())),
    )
    records, files, review, events = predecessor.Records(identity), Files(), predecessor.Review(), Events()
    records.seed("managed-root", {
        "schema": "i02-managed-generations-v1",
        "root_manifest": {
            "control_resource": "managed-control", "registered_manifests": (c.wire(manifest),),
        }, "generations": (),
    })
    records.seed("managed-control", {
        "schema": "i02-managed-control-v1", "pointer": c.wire(lc.AbsentPointer("absent", 0)),
        "verification": None, "setup_enabled": True, "installation_id": None,
    })
    records.seed("user-inventory", {"preserve": "inventory"}, owner="2" * 64)
    transport = Transport(content, asset.url)
    state = ManagedLifecycleState(
        records, "managed-root", "managed-control", predecessor.OWNER, identity,
        (manifest,), files, transport,
    )
    consent = TrustedLifecycleConsentAdapter(review)
    broker = AuthorizationBroker(
        object(), TrustedConsentAdapter(review), lifecycle_state=state, lifecycle_consent=consent,
    )
    service = DependencyService(
        registry, dict.fromkeys(ADAPTERS, probes), state, engine, broker, clock, events,
    )
    return {
        "service": service, "records": records, "files": files, "transport": transport,
        "state": state, "scope": scope, "context": context, "clock": clock, "events": events,
        "review": review, "manifest": manifest, "probes": probes,
    }


def staged(env):
    service = env["service"]
    before = len(env["records"].writes)
    plan = service.plan(env["scope"], env["context"])
    assert len(env["records"].writes) == before, "Public planning must be read-only"
    assert not plan.blocked and plan.lifecycle is not None
    assert tuple(item.kind for item in plan.lifecycle.effects) == (
        "dependency-download", "dependency-stage", "dependency-verify",
    )
    consent = service.review(plan, env["clock"].now, 30.0)
    result = service.provision(plan, consent, Cancel())
    assert all(step.status == c.OutcomeStatus.SUCCEEDED for step in result.steps), result
    assert not result.errors
    assert env["files"].content is not None
    assert len(env["transport"].calls) == 1
    assert result.active_generation_id is None
    assert env["state"].pointer() == lc.AbsentPointer("absent", 0)
    return plan, consent, result


def test_public_plan_review_provision_stages_real_managed_manifest_and_canonical_events():
    env = managed_environment()
    original_user = env["records"].read("user-inventory")
    _, _, result = staged(env)
    assert result.pending_actions == ("review-activation-plan",)
    assert result.status == c.OutcomeStatus.PARTIAL
    assert env["records"].read("user-inventory") == original_user
    events = {
        record.payload["event"]["event_id"]: record.payload["event"]
        for resource, _, record in env["records"].writes
        if resource.startswith("dependency-policy-")
    }
    event_kinds = [event["kind"] for event in events.values()]
    assert event_kinds[0] == "InstallConsented"
    assert event_kinds.count("StepCompleted") == 3
    assert "Activated" not in event_kinds


def test_public_fresh_activation_review_uses_actual_pointer_cas_after_functional_reprobe():
    env = managed_environment()
    staged(env)
    service = env["service"]
    plan = service.plan(env["scope"], env["context"])
    assert not plan.blocked and plan.lifecycle is not None
    assert tuple(step.kind for step in plan.lifecycle.effects) == (
        "dependency-probe", "dependency-activate",
    )
    consent = service.review(plan, env["clock"].now, 30.0)
    result = service.provision(plan, consent, Cancel())
    assert result.status == c.OutcomeStatus.SUCCEEDED, c.canonical_bytes(result).decode()
    assert not result.errors and not result.pending_actions
    assert result.active_generation_id == GENERATION
    assert result.pointer_revision == 1
    assert env["state"].pointer().active_generation_id == GENERATION
    assert len(env["transport"].calls) == 1, "Activation must never redownload"
    assert env["files"].calls.count("stage") == 1
    kinds = [
        record.payload["event"]["kind"] for resource, _, record in env["records"].writes
        if resource.startswith("dependency-policy-")
    ]
    assert kinds[-1] == "Activated"
    assert "CandidateVerified" in kinds


def test_public_review_rejects_changed_plan_before_prompt_and_transport():
    env = managed_environment()
    plan = env["service"].plan(env["scope"], env["context"])
    assert plan.lifecycle is not None
    changed = replace(plan, lifecycle=replace(plan.lifecycle, plan_id=str(uuid4())))
    with pytest.raises((c.ContractError, AuthorizationError)):
        env["service"].review(changed, env["clock"].now, 30.0)
    assert not env["records"].writes
    assert not env["transport"].calls


def test_public_consumed_consent_never_replays_archive_stage():
    env = managed_environment()
    plan, consent, _ = staged(env)
    calls = len(env["transport"].calls), env["files"].calls.count("stage")
    try:
        result = env["service"].provision(plan, consent, Cancel())
    except (AuthorizationError, c.ContractError):
        pass
    else:
        assert result.status != c.OutcomeStatus.SUCCEEDED
    assert (len(env["transport"].calls), env["files"].calls.count("stage")) == calls


def test_installer_scope_request_serialization_is_exact():
    scope = c.InstallScope(("native.stdlib",), (), False, False)
    assert c.canonical_bytes(scope).decode() == (
        '{"companions":[],"enhanced":false,"full_toolkit":false,'
        '"native_capabilities":["native.stdlib"]}'
    )


def test_installer_outcome_response_serialization_is_exact():
    result = InstallOutcome(
        "installation", "plan", "install", c.OutcomeStatus.BLOCKED, (),
        c.ReadinessProjection("blocked", "not-requested", "not-requested"),
        GENERATION, None, None,
    )
    expected = {
        "active_generation_id": None, "candidate_generation_id": GENERATION,
        "cleanup_errors": [], "errors": [], "installation_id": "installation", "kind": "install",
        "original_errors": [], "pending_actions": [], "plan_id": "plan",
        "pointer_revision": None, "previous_generation_id": None,
        "readiness": {
            "companion": "not-requested", "enhanced": "not-requested",
            "errors": [], "native": "blocked",
        },
        "remote_state": "not-requested", "schema_version": "1.0", "selected_scope": None,
        "status": "blocked", "steps": [], "uncertain": False,
    }
    # Exact UTF-8 bytes, not a parsed-dict comparison or roundtrip-only assertion.
    assert c.canonical_bytes(result).decode() == json.dumps(
        expected, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
