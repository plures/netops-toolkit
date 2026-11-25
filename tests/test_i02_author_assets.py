"""Pinned acquisition controls; HTTP and every consequential effect are faked."""

import ssl
import urllib.error
from dataclasses import replace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationError,
    bind_lifecycle,
    lifecycle_plan_digest,
)
from netops.ansible.policy.lifecycle_evidence import lifecycle_arguments_digest
from netops.dependencies._assets import (
    AssetResponse,
    LockedAsset,
    VerifiedAssetAcquisition,
)
from netops.dependencies.service import DependencyRegistry
from tests.policy.test_lifecycle_execution import CONTENT, DATA, decision_for, environment
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel

URL = "https://files.pythonhosted.org/packages/fixture.whl"


class Transport:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def read(self, url, timeout, limit):
        self.calls.append((url, timeout, limit))
        value = next(self.responses)
        if isinstance(value, BaseException):
            raise value
        return value


class WaitingCancel(Cancel):
    def __init__(self):
        super().__init__()
        self.waits = []

    def wait(self, timeout):
        self.waits.append(timeout)
        return self.value


def admitted(tmp_path, policy, responses):
    env = environment(tmp_path, policy, "dependency-download")
    plan, _, port, state, _, consent, broker, clock, _ = env
    lock = LockedAsset("source", "paramiko", URL, CONTENT, len(DATA))
    source_record = port.read("source")
    port.seed("source", {**dict(source_record.payload), "manifest": c.wire(lock)})
    step = dict(plan.content["steps"][0])
    step["source"] = {**dict(step["source"]), "descriptor_digest": c.digest(lock)}
    step = c.public_object(step)
    port.seed("step", step)
    effect = replace(plan.effects[0], arguments_digest=lifecycle_arguments_digest(step))
    plan = replace(
        plan, effects=(effect,), content=c.public_object({**dict(plan.content), "steps": (step,)}),
    )
    plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    binding = bind_lifecycle(plan)
    grant = broker.issue_lifecycle(
        plan, consent.review(plan, 10.0, 20.0), decision_for(policy, binding), 10.0,
    )
    session = broker.consume_lifecycle(grant, binding, 10.0)
    invocation = lc.LifecycleEffectBinding(
        binding, str(uuid4()), state.snapshot_lifecycle(binding).revision, effect.occurrence_id,
    )
    permit = broker.permit_lifecycle(session, invocation, 10.0)
    transport = Transport(responses)
    events = Mock()
    acquisition = VerifiedAssetAcquisition(broker, transport, clock, events)
    return acquisition, lock, permit, invocation, transport, state, events


def test_actual_private_permit_returns_exact_verified_bytes_once(tmp_path, policy):
    acquisition, lock, permit, invocation, transport, state, _ = admitted(
        tmp_path, policy, (AssetResponse(URL, DATA),),
    )
    result = acquisition.download(
        DependencyRegistry.load().entry("paramiko"), lock, permit, invocation, Cancel(),
    )
    assert result.content == DATA and result.digest == CONTENT
    assert not result.cancelled_after_acquisition
    assert state.pointer().active_generation_id == "old"
    assert len(transport.calls) == 1
    assert transport.calls[0][1] <= 20.0  # original consent, not a renewed 300-second grant
    with pytest.raises(AuthorizationError):
        acquisition.download(
            DependencyRegistry.load().entry("paramiko"), lock, permit, invocation, Cancel(),
        )
    assert len(transport.calls) == 1


@pytest.mark.parametrize("url", (
    "http://files.pythonhosted.org/a.whl",
    "https://user:PRIVATE@files.pythonhosted.org/a.whl",
    "https://files.pythonhosted.org:444/a.whl",
    "https://files.pythonhosted.org/a.whl?token=PRIVATE",
    "https://files.pythonhosted.org/a.whl#fragment",
    "https://files.pythonhosted.org:invalid/a.whl",
    "https://[broken/a.whl",
))
def test_unsafe_source_lock_rejects_without_transport(url):
    with pytest.raises(c.ContractError):
        LockedAsset("source", "paramiko", url, CONTENT, len(DATA))


@pytest.mark.parametrize("change", (
    {"url": "https://unapproved.invalid/a.whl"},
    {"dependency": "netmiko"},
    {"sha256": "b" * 64},
    {"size": len(DATA) + 1},
))
def test_changed_reviewed_source_cannot_spend_permit(tmp_path, policy, change):
    acquisition, lock, permit, invocation, transport, *_ = admitted(tmp_path, policy, ())
    with pytest.raises((c.ContractError, AuthorizationError)):
        acquisition.download(
            DependencyRegistry.load().entry("paramiko"), replace(lock, **change),
            permit, invocation, Cancel(),
        )
    assert not transport.calls


@pytest.mark.parametrize("response", (
    AssetResponse("https://unapproved.invalid/a.whl", DATA),
    AssetResponse(URL, DATA + b"x"),
    AssetResponse(URL, DATA[:-1] + b"x"),
))
def test_redirect_size_and_hash_fail_closed_without_retry(tmp_path, policy, response):
    acquisition, lock, permit, invocation, transport, state, _ = admitted(
        tmp_path, policy, (response,),
    )
    with pytest.raises(c.ContractError):
        acquisition.download(
            DependencyRegistry.load().entry("paramiko"), lock, permit, invocation, Cancel(),
        )
    assert len(transport.calls) == 1
    assert state.pointer().active_generation_id == "old"


def test_transient_retry_is_bounded_and_only_for_idempotent_fetch(tmp_path, policy):
    acquisition, lock, permit, invocation, transport, _, _ = admitted(
        tmp_path, policy, (ConnectionError(), ConnectionError(), AssetResponse(URL, DATA)),
    )
    cancel = WaitingCancel()
    result = acquisition.download(
        DependencyRegistry.load().entry("paramiko"), lock, permit, invocation, cancel,
    )
    assert result.content == DATA
    assert len(transport.calls) == 3
    assert 0.8 <= cancel.waits[0] <= 1.2
    assert 1.6 <= cancel.waits[1] <= 2.4


def test_certificate_failure_is_not_retried_or_downgraded(tmp_path, policy):
    acquisition, lock, permit, invocation, transport, _, _ = admitted(
        tmp_path, policy, (urllib.error.URLError(ssl.SSLCertVerificationError()),),
    )
    cancel = WaitingCancel()
    with pytest.raises(urllib.error.URLError):
        acquisition.download(
            DependencyRegistry.load().entry("paramiko"), lock, permit, invocation, cancel,
        )
    assert len(transport.calls) == 1 and not cancel.waits


def test_cancel_before_acquisition_does_not_enter_transport(tmp_path, policy):
    acquisition, lock, permit, invocation, transport, *_ = admitted(tmp_path, policy, ())
    cancel = Cancel()
    cancel.value = True
    with pytest.raises(InterruptedError):
        acquisition.download(
            DependencyRegistry.load().entry("paramiko"), lock, permit, invocation, cancel,
        )
    assert not transport.calls


def test_telemetry_sink_failure_cannot_erase_verified_acquisition(tmp_path, policy, monkeypatch):
    acquisition, lock, permit, invocation, _, _, events = admitted(
        tmp_path, policy, (AssetResponse(URL, DATA),),
    )
    events.emit.side_effect = RuntimeError("PRIVATE-SENTINEL")
    import netops.dependencies._assets as assets

    monkeypatch.setattr(assets._LOG, "info", Mock(side_effect=RuntimeError("PRIVATE-SENTINEL")))
    result = acquisition.download(
        DependencyRegistry.load().entry("paramiko"), lock, permit, invocation, Cancel(),
    )
    assert result.digest == CONTENT
    assert "PRIVATE-SENTINEL" not in repr(result)
    assert DATA.decode() not in repr(result)
