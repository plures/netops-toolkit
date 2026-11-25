"""New contract-aligned retries; earlier failed assertion files remain unchanged."""

from __future__ import annotations

import copy
import io

import pytest

from netops.ansible import _action_health as health
from netops.ansible import _windows_job as native
from netops.ansible import contracts as c
from netops.ansible.controller_protocol import ProtocolError
from netops.ansible.worker_broker import _safe_action_result
from tests.test_nov20_cleanup_health_independent import PartialCloseKernel
from tests.test_nov20_native_successor_health import external_ports as external_ports
from tests.test_nov20_native_successor_health import gather


@pytest.mark.parametrize("failed_handle", [201, 301])
def test_ac011_retry_finalizes_exact_failed_handle_after_best_effort_closes(failed_handle):
    """FR-036 permits closing another joined handle while retaining the failed one."""
    kernel = PartialCloseKernel(failed_handle)
    process = native._WindowsProcess(kernel, 201, 301, 123, io.BytesIO(), io.BytesIO())
    process.returncode = 1
    with pytest.raises(native._KernelError) as caught:
        process.close(0.1)
    assert caught.value.kernel_stage == "CloseHandle" and not process._closed
    assert process._job == (201 if failed_handle == 201 else 0)
    assert process._process == (301 if failed_handle == 301 else 0)
    boundary = len(kernel.calls)
    assert process.close(0.1) is True
    assert process._job == process._process == 0 and process._closed
    assert kernel.calls[boundary:] == [("CloseHandle", (failed_handle,))]
    end = len(kernel.calls)
    assert process.close(0.1) is True and len(kernel.calls) == end


def test_ac008_reviewed_numeric_request_and_complete_target_response_golden(external_ports):
    """FR-027 allows only bounded parsed numeric provenance, never process dumps."""
    assert c.canonical_bytes(c.public_object(health._HealthSelection(
        ("cpu", "memory", "interfaces"), 70.0, 80.0,
    ).wire())).decode() == '{"checks":["cpu","memory","interfaces"],"cpu_threshold":70.0,"memory_threshold":80.0}'
    target = _safe_action_result(
        gather(external_ports, cpu_threshold=70.0, memory_threshold=80.0), "router", "gather",
    )
    actual = c.canonical_bytes(target).decode()
    assert actual == '{"attempted":true,"changed":false,"errors":[],"findings":[{"category":"health","check":"cpu","expected":null,"parser":"netops.check.cisco","raw_source_ref":null,"reading":12.0,"result":"pass","severity":"info","threshold":70.0,"vendor":"cisco_ios"},{"category":"health","check":"memory","expected":null,"parser":"netops.check.cisco","raw_source_ref":null,"reading":25.0,"result":"pass","severity":"info","threshold":80.0,"vendor":"cisco_ios"},{"category":"health","check":"interfaces","expected":null,"parser":"netops.check.cisco","raw_source_ref":null,"reading":0,"result":"pass","severity":"info","threshold":null,"vendor":"cisco_ios"}],"native_payload":{"health":{"checks":{"cpu":{"alert":false,"parser":"netops.check.cisco","raw":{"five_minutes":10.0,"five_seconds":12.0,"one_minute":12.0},"status":"succeeded","threshold":70.0,"utilization":12.0,"vendor":"cisco_ios"},"interfaces":{"alert":false,"parser":"netops.check.cisco","status":"succeeded","total":1,"vendor":"cisco_ios","with_errors":0},"memory":{"alert":false,"parser":"netops.check.cisco","raw":{"free":750,"total":1000,"used":250,"utilization":25.0},"status":"succeeded","threshold":80.0,"utilization":25.0,"vendor":"cisco_ios"}},"connection_cleanup_failed":false,"overall_alert":false},"line_count":5},"remote_state":"unchanged","selected":true,"status":"succeeded","target_id":"router","unapplied_effects":[]}'
    assert "source-only-private-credential-never-log" not in actual
    assert not target.changed and target.remote_state == "unchanged"


@pytest.mark.parametrize("check,raw", [
    ("cpu", {"peak": 12.0}),
    ("cpu", {"five_seconds": 12.0, "one_minute": 99.0, "five_minutes": 10.0}),
    ("memory", {"total": 0, "used": 2, "free": 4, "utilization": 99.0}),
    ("cpu", {"one_minute": "source-only-private-credential-never-log"}),
    ("cpu", {"five_seconds": 12.0, "one_minute": float("nan"), "five_minutes": 10.0}),
    ("cpu", {"five_seconds": 12.0, "one_minute": True, "five_minutes": 10.0}),
    ("memory", {"total": c.MAX_SAFE_INT + 1, "used": 1, "free": 0, "utilization": 25.0}),
])
def test_ac008_reviewed_provenance_rejects_wrong_owner_contradiction_and_invalid_numeric(
    external_ports, check, raw,
):
    result = copy.deepcopy(gather(external_ports, cpu_threshold=70.0, memory_threshold=80.0))
    result["health"]["checks"][check]["raw"] = raw
    with pytest.raises(ProtocolError):
        _safe_action_result(result, "router", "gather")
