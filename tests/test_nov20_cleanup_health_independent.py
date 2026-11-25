"""FR-028/036 independent measurement and cleanup contracts; no live device IO."""

from __future__ import annotations

import io
import json

import pytest

from netops.ansible import _action_health as health
from netops.ansible import _controller_wsl as transport
from netops.ansible import _windows_job as native
from netops.ansible import action_runtime as action
from netops.ansible import contracts as c
from netops.ansible.worker_broker import _safe_action_result
from tests.test_nov20_native_successor_health import external_ports as external_ports

JUNOS_HEADER = "Physical interface: ge-0/0/0, Enabled, Physical link is Up\n"
JUNOS_INPUT = "  Input errors:\n    Errors: {value}, Drops: 0, Framing errors: 0\n"
JUNOS_OUTPUT = "  Output errors:\n    Carrier transitions: 1, Errors: {value}, Drops: 0\n"
EOS_COUNTERS = {
    "inputErrors": 0, "outputErrors": 0, "inDiscards": 0,
    "outDiscards": 0, "alignmentErrors": 0,
}


def interface_result(ports, vendor, reading):
    device, connections, credential = ports
    credential["vendor"] = vendor
    command = "show interfaces extensive" if vendor == "juniper_junos" else "show interfaces | json"
    device.responses[command] = reading
    result = action._NativeActions().run_selected(
        "gather", credential, None, health._HealthSelection(("interfaces",)),
    )
    target = _safe_action_result(result, "router", "gather")
    assert connections == [vendor]
    assert device.commands == [command], "Only the selected read-only command may execute"
    assert device.closed
    assert not target.changed and target.remote_state == "unchanged"
    return result, target


@pytest.mark.parametrize("missing", ["input", "output", "both"])
def test_ac008_junos_absent_counter_is_unknown_not_healthy_zero(external_ports, missing, caplog):
    reading = JUNOS_HEADER
    if missing != "input" and missing != "both":
        reading += JUNOS_INPUT.format(value=0)
    if missing != "output" and missing != "both":
        reading += JUNOS_OUTPUT.format(value=0)
    result, target = interface_result(external_ports, "juniper_junos", reading)
    assert result["health"]["checks"]["interfaces"]["status"] != "succeeded"
    assert target.status in (c.OutcomeStatus.FAILED, c.OutcomeStatus.BLOCKED)
    assert target.findings[0].result == "unknown" and target.findings[0].reading is None
    assert any(error.reason == c.ReasonCode.READING_UNAVAILABLE for error in target.errors)
    assert "source-only-private-credential-never-log" not in caplog.text + c.canonical_bytes(target).decode()


@pytest.mark.parametrize("missing", ["inputErrors", "outputErrors", "both", "counter-object"])
def test_ac008_eos_absent_counter_is_unknown_not_healthy_zero(external_ports, missing):
    counters = dict(EOS_COUNTERS)
    if missing == "both":
        counters.pop("inputErrors")
        counters.pop("outputErrors")
    elif missing in counters:
        counters.pop(missing)
    item = {
        "interfaceStatus": "connected", "lineProtocolStatus": "up",
        "interfaceCounters": counters,
    }
    if missing == "counter-object":
        item.pop("interfaceCounters")
    result, target = interface_result(
        external_ports, "arista_eos", json.dumps({"interfaces": {"Ethernet1": item}}),
    )
    assert result["health"]["checks"]["interfaces"]["status"] != "succeeded"
    assert target.status in (c.OutcomeStatus.FAILED, c.OutcomeStatus.BLOCKED)
    assert target.findings[0].result == "unknown" and target.findings[0].reading is None


@pytest.mark.parametrize("vendor", ["juniper_junos", "arista_eos"])
@pytest.mark.parametrize("value", ["NaN", "invalid", "-1", "Infinity", "0.5"])
def test_ac008_invalid_interface_measurement_never_defaults_to_zero(external_ports, vendor, value):
    if vendor == "juniper_junos":
        reading = JUNOS_HEADER + JUNOS_INPUT.format(value=value) + JUNOS_OUTPUT.format(value=0)
    else:
        counters = {**EOS_COUNTERS, "inputErrors": value}
        reading = json.dumps({"interfaces": {"Ethernet1": {
            "interfaceStatus": "connected", "lineProtocolStatus": "up",
            "interfaceCounters": counters,
        }}})
    _, target = interface_result(external_ports, vendor, reading)
    assert target.status in (c.OutcomeStatus.FAILED, c.OutcomeStatus.BLOCKED)
    assert target.findings[0].result == "unknown" and target.findings[0].reading is None


@pytest.mark.parametrize("vendor", ["juniper_junos", "arista_eos"])
@pytest.mark.parametrize("value", [0, 1])
def test_ac008_measured_zero_is_healthy_and_positive_error_is_alert(external_ports, vendor, value):
    if vendor == "juniper_junos":
        reading = JUNOS_HEADER + JUNOS_INPUT.format(value=value) + JUNOS_OUTPUT.format(value=0)
    else:
        counters = {**EOS_COUNTERS, "inputErrors": value}
        reading = json.dumps({"interfaces": {"Ethernet1": {
            "interfaceStatus": "connected", "lineProtocolStatus": "up",
            "interfaceCounters": counters,
        }}})
    result, target = interface_result(external_ports, vendor, reading)
    assert result["health"]["checks"]["interfaces"]["status"] == "succeeded"
    assert target.status == (c.OutcomeStatus.SUCCEEDED if value == 0 else c.OutcomeStatus.FAILED)
    assert target.findings[0].reading == value
    assert target.findings[0].result == ("pass" if value == 0 else "alert")


class RetryOwner:
    """Source-only close-failure port; no fictitious handle reaches an OS call."""

    def __init__(self):
        self.calls = []
        self.succeed = False

    def close(self, timeout):
        self.calls.append(timeout)
        return self.succeed


def test_ac011_failed_normal_close_retains_owner_until_real_retry_success():
    adapter, owner = transport._WslProcessIo(), RetryOwner()
    first = adapter.close_launcher(owner, 0.1)
    assert first.status == "failed" and first.remaining_refs == ("owned-wsl-launcher",)
    assert any(item is owner for item in adapter._unfinished)
    second = adapter.close_pending(0.1)
    assert second.status == "failed" and second.remaining_refs == first.remaining_refs
    assert len(owner.calls) == 2 and any(item is owner for item in adapter._unfinished)
    owner.succeed = True
    third = adapter.close_pending(0.1)
    assert third.status == "succeeded" and third.remaining_refs == ()
    assert len(owner.calls) == 3 and not adapter._unfinished
    assert adapter.close_pending(0.1).status == "succeeded"
    assert len(owner.calls) == 3, "Successful owner finalization must not retry an absent owner"


class PartialCloseKernel:
    """Exact independently chosen handle ownership; source-only failure injection."""

    def __init__(self, fail_handle):
        self.fail_handle = fail_handle
        self.failed = False
        self.calls = []

    def require(self, stage, *args):
        self.calls.append((stage, args))
        assert args[0] != 0, "A released job/process handle must never be reused"
        if stage == "CloseHandle" and args[0] == self.fail_handle and not self.failed:
            self.failed = True
            raise native._KernelError(stage, 6)
        return 1

    def call(self, stage, *args):
        self.calls.append((stage, args))
        assert stage == "WaitForSingleObject" and args[0] == 301
        return 0

    def active(self, handle):
        self.calls.append(("active", (handle,)))
        assert handle == 201
        return 0


@pytest.mark.parametrize("failed_handle", [201, 301])
def test_ac011_partial_handle_finalization_retries_only_remaining_resources(failed_handle):
    kernel = PartialCloseKernel(failed_handle)
    process = native._WindowsProcess(kernel, 201, 301, 123, io.BytesIO(), io.BytesIO())
    process.returncode = 1
    with pytest.raises(native._KernelError) as caught:
        process.close(0.1)
    assert caught.value.kernel_stage == "CloseHandle"
    assert not process._closed
    assert process._process == (301 if failed_handle == 301 else 0)
    assert process._job == (201 if failed_handle == 201 else 0)
    boundary = len(kernel.calls)
    assert process.close(0.1) is True
    assert process._job == process._process == 0 and process._closed
    later = kernel.calls[boundary:]
    assert all(stage not in ("TerminateJobObject", "WaitForSingleObject", "active")
               for stage, _ in later), "Joined resources must stay in finalization, not teardown"
    expected = [failed_handle]
    assert [args[0] for stage, args in later if stage == "CloseHandle"] == expected
    end = len(kernel.calls)
    assert process.close(0.1) is True and len(kernel.calls) == end
