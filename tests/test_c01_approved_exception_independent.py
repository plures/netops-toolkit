"""Frozen C01 nonsecret parity and prehash credential rejection regressions."""

import hashlib
import json
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible import workflows as w
from netops.change.diff import diff_configs, format_json
from tests.test_c01_independent_nov17 import (
    HydrationClock,
    hydrated,
    input_source,
    request,
)
from tests.test_c01_independent_nov17 import environment as environment


@pytest.mark.parametrize("mode", (c.Mode.PREVIEW, c.Mode.CHECK))
@pytest.mark.parametrize("after", (
    "snmp-server enable traps snmp authentication linkdown linkup\n",
    "SNMP-SERVER ENABLE TRAPS SNMP AUTHENTICATION LINKDOWN LINKUP\n",
    "no snmp-server enable traps snmp authentication\n",
))
def test_nonsecret_notification_compare_preserves_native_result(environment, mode, after):
    service, context, _ = environment
    before = "snmp-server enable traps snmp linkdown linkup\n"
    req, loaded = hydrated(
        replace(request(context, "compare.compare"), mode=mode),
        input_source("before", content=before.encode()),
        input_source("after", content=after.encode()),
    )
    plan = service.preview(req, loaded)
    assert c.wire(plan.native_payload["native_payload"]) == json.loads(
        format_json(diff_configs(before, after)),
    )
    assert plan.native_payload["execution_performed"] is False
    assert plan.targets == req.scope.target_ids


@pytest.mark.parametrize("kind", ("text", "json", "yaml"))
@pytest.mark.parametrize("credential", (
    "snmp-server user observer group v3 auth sha {secret} priv aes 128 {secret}",
    "tacacs server auth-server\n key 7 {secret}\n!",
    "radius-server host 192.0.2.1 key {secret}",
))
def test_notification_does_not_whitelist_neighbor_credentials_before_hash(
    environment, monkeypatch, kind, credential,
):
    _, context, _ = environment
    sentinel = "C01ExceptionPrivateCredentialSentinel"
    text = ("snmp-server enable traps snmp authentication linkdown linkup\n"
            + credential.format(secret=sentinel))
    if kind == "text":
        raw = text.encode()
    elif kind == "json":
        raw = json.dumps({"config": text}).encode()
    else:
        raw = ("config: |\n  " + text.replace("\n", "\n  ") + "\n").encode()
    ref = c.InputRef("before", "explicit-nonsecret-input", "0" * 64)
    source = c.InputSource(ref, kind, raw, "independent-v1", "cisco-v1")
    req = replace(request(context), inputs=(ref,))
    real_sha = hashlib.sha256

    def guarded_sha(data=b"", *args, **kwargs):
        assert sentinel.encode() not in data, "credential reached public hash boundary"
        return real_sha(data, *args, **kwargs)

    monkeypatch.setattr(w.hashlib, "sha256", guarded_sha)
    with pytest.raises(c.ContractError, match="input-binding-invalid") as caught:
        w.hydrate_inputs(req, (source,), HydrationClock())
    assert sentinel not in str(caught.value) + repr(caught.value.error) + repr(source)
    assert sentinel.encode() not in c.canonical_bytes(caught.value.error)
