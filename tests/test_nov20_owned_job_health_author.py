"""Author SOURCE controls: real native helpers and owned Windows jobs, not Q03."""

from __future__ import annotations

import ctypes
import io
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops.ansible import _action_health as health
from netops.ansible import _windows_job as win
from netops.ansible import action_runtime as action
from netops.ansible import contracts as c
from netops.ansible._controller_pipe import _PipeFrames
from netops.ansible._controller_wsl import _kernel_detail, _WslProcessIo
from netops.ansible.controller import ProcessResult
from netops.ansible.controller_protocol import ProtocolError, _decode_frame
from netops.ansible.settings import HealthSettings
from netops.ansible.worker import _parse_envelope
from netops.ansible.worker_broker import _safe_action_result, _WorkerBroker
from tests.test_controller_backend_integration import integrated as integrated
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import policy as policy

CPU = "CPU utilization for five seconds: 5%/1%; one minute: 80%; five minutes: 6%"
MEMORY = "Processor  ABCDEF  1000  850  150"
INTERFACES = """GigabitEthernet0/0 is up, line protocol is up
  0 input errors, 0 CRC, 0 frame
  0 output errors, 0 collisions
"""
BGP = """Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
192.0.2.10 4 65001 100 100 2 0 0 1d 10
"""
VLAN = """VLAN Name                             Status    Ports
1    default                          active    Gi0/1
"""
ENVIRONMENT = "TEMPERATURE is OK\nFAN is OK\nPower Supply 1: Normal"
JUNOS_RE = """Routing Engine status:
  Slot 0:
  Current state Master
  Memory utilization 85 percent
  CPU utilization:
    User 10 percent
    Background 0 percent
    Kernel 10 percent
    Interrupt 0 percent
    Idle 20 percent
"""


class Device:
    """Fake device IO only; every check/parse/normalization remains actual source."""

    def __init__(self, responses=None):
        self.responses = {
            "show processes cpu": CPU, "show processes memory": MEMORY,
            "show interfaces": INTERFACES, "show ip bgp summary": BGP,
            "show vlan brief": VLAN, "show environment all": ENVIRONMENT,
            **(responses or {}),
        }
        self.commands = []
        self.disconnected = False
        self.cleanup_error = False

    def send(self, command):
        self.commands.append(command)
        value = self.responses.get(command, "malformed")
        if isinstance(value, BaseException):
            raise value
        return value

    def connect(self):
        pass

    def disconnect(self):
        self.disconnected = True
        if self.cleanup_error:
            raise RuntimeError("private-password-do-not-leak")


def gather(device=None, vendor="cisco_ios", checks=None, **kwargs):
    selection = health._HealthSelection(
        checks=tuple(checks) if checks else health._CHECKS, **kwargs,
    )
    return health._gather_native(device or Device(), vendor, selection)


def test_real_cisco_helpers_consume_measurements_not_generic_version(monkeypatch):
    device = Device()
    monkeypatch.setattr(action, "_StrictConnection", lambda *args: device)
    result = action._NativeActions().run("gather", {"vendor": "cisco_ios"}, None)
    assert device.disconnected
    assert "show version" not in device.commands
    assert device.commands == [
        "show processes cpu", "show processes memory", "show interfaces",
        "show ip bgp summary", "show vlan brief", "show environment all",
    ]
    assert result["health"]["checks"]["cpu"]["utilization"] == 80.0
    assert result["health"]["checks"]["memory"]["utilization"] == 85.0
    target = _safe_action_result(result, "router", "gather")
    assert target.status == c.OutcomeStatus.FAILED
    assert [finding.result for finding in target.findings[:2]] == ["alert", "alert"]
    assert all(error.reason == c.ReasonCode.HEALTH_ALERT for error in target.errors)
    assert CPU not in c.canonical_bytes(target).decode()
    assert target.native_payload["health"]["checks"]["cpu"]["raw"]["one_minute"] == 80.0
    assert not target.changed and target.remote_state == "unchanged"


@pytest.mark.parametrize("value,expected", [(0, False), (79, False), (80, True), (81, True), (100, True)])
def test_inclusive_cpu_threshold_consumed_by_factual_result(value, expected):
    device = Device({"show processes cpu": CPU.replace("one minute: 80%", f"one minute: {value}%")})
    result = gather(device, checks=("cpu",))
    assert result["health"]["checks"]["cpu"]["alert"] is expected
    target = _safe_action_result(result, "router", "gather")
    assert target.findings[0].result == ("alert" if expected else "pass")


@pytest.mark.parametrize("value", ["", "garbage", CPU.replace("80%", "150%"),
                                  RuntimeError("private-password-do-not-leak"), 42, "x" * (512 * 1024 + 1)],
                         ids=["empty", "malformed", "over-range", "native-error", "type", "oversize"])
def test_unavailable_cpu_retains_other_actual_readings_without_raw_errors(value, caplog):
    device = Device({"show processes cpu": value})
    result = gather(device)
    assert result["health"]["checks"]["cpu"]["status"] == "failed"
    assert result["health"]["checks"]["memory"]["utilization"] == 85.0
    target = _safe_action_result(result, "router", "gather")
    assert target.findings[0].reading is None and target.findings[0].result == "unknown"
    assert "private-password" not in caplog.text + c.canonical_bytes(target).decode()


@pytest.mark.parametrize("name,command", [
    ("memory", "show processes memory"), ("interfaces", "show interfaces"),
    ("bgp", "show ip bgp summary"), ("vlans", "show vlan brief"),
    ("environment", "show environment all"),
])
def test_empty_parsed_readings_never_become_healthy_zero(name, command):
    result = gather(Device({command: "garbage"}), checks=(name,))
    target = _safe_action_result(result, "router", "gather")
    assert target.status == c.OutcomeStatus.FAILED
    assert target.findings[0].result == "unknown"


def test_cleanup_failure_preserves_reading_facts(monkeypatch):
    device = Device()
    device.cleanup_error = True
    monkeypatch.setattr(action, "_StrictConnection", lambda *args: device)
    result = action._NativeActions().run_selected(
        "gather", {"vendor": "cisco_ios"}, None, health._HealthSelection(("interfaces",)),
    )
    assert result["health"]["checks"]["interfaces"]["status"] == "succeeded"
    assert result["health"]["connection_cleanup_failed"] is True
    assert _safe_action_result(result, "router", "gather").status == c.OutcomeStatus.FAILED


def test_unsupported_selection_opens_no_connection(monkeypatch):
    class NoConnection(Device):
        def connect(self):
            pytest.fail("unsupported check cannot open SSH")
    monkeypatch.setattr(action, "_StrictConnection", lambda *args: NoConnection())
    result = action._NativeActions().run_selected(
        "gather", {"vendor": "cisco_ios"}, None, health._HealthSelection(("ospf",)),
    )
    assert _safe_action_result(result, "router", "gather").status == c.OutcomeStatus.UNSUPPORTED
    assert result["attempted"] is False


@pytest.mark.parametrize("vendor", ["cisco_nxos", "cisco_xr", "unknown-device;secret"])
def test_unregistered_vendor_does_not_use_cisco_commands(vendor):
    device = Device()
    result = gather(device, vendor)
    assert device.commands == []
    assert result["status"] == "unsupported"
    assert "secret" not in json.dumps(result)
    _safe_action_result(result, "router", "gather")


@pytest.mark.parametrize("value", [
    {"checks": ["show running-config"], "cpu_threshold": 80, "memory_threshold": 85},
    {"checks": ["cpu", "cpu"], "cpu_threshold": 80, "memory_threshold": 85},
    {"checks": [], "cpu_threshold": 80, "memory_threshold": 85},
    {"checks": [True], "cpu_threshold": 80, "memory_threshold": 85},
    {"checks": "cpu", "cpu_threshold": 80, "memory_threshold": 85},
    {"checks": ["cpu"], "cpu_threshold": True, "memory_threshold": 85},
    {"checks": ["cpu"], "cpu_threshold": float("nan"), "memory_threshold": 85},
    {"checks": ["cpu"], "cpu_threshold": -1, "memory_threshold": 85},
    {"checks": ["cpu"], "cpu_threshold": 101, "memory_threshold": 85},
    {"checks": ["cpu"], "cpu_threshold": 80, "memory_threshold": 85, "command": "show config"},
])
def test_private_selection_rejects_untrusted_commands_and_thresholds(value):
    with pytest.raises(ProtocolError):
        health._HealthSelection.parse(value)


def test_private_selection_roundtrip_and_nondefault_threshold():
    selected = health._HealthSelection(("cpu", "memory"), 90.0, 90.0)
    assert health._HealthSelection.parse(selected.wire()) == selected
    result = gather(checks=selected.checks, cpu_threshold=90, memory_threshold=90)
    assert result["status"] == "succeeded"


def test_junos_real_re_helper_numeric_fields():
    device = Device({"show chassis routing-engine": JUNOS_RE})
    result = gather(device, "juniper_junos", ("cpu", "memory"))
    assert result["health"]["checks"]["cpu"]["utilization"] == 80.0
    assert result["health"]["checks"]["memory"]["utilization"] == 85.0
    _safe_action_result(result, "router", "gather")


def test_junos_invalid_idle_cannot_clamp_to_healthy_zero():
    result = gather(Device({"show chassis routing-engine": JUNOS_RE.replace("Idle 20", "Idle 150")}),
                    "juniper", ("cpu",))
    assert result["health"]["checks"]["cpu"]["status"] == "failed"


@pytest.mark.parametrize("vendor,cpu_command,cpu,memory_command,memory", [
    ("nokia_sros", "show system cpu", "CPU Usage : 5% 12%",
     "show system memory-pools", "Total In Use : 50\nTotal Available : 50"),
    ("brocade_fastiron", "show cpu", "1-second average: 5 percent\n5-second average: 4 percent\n60-second average: 3 percent",
     "show memory", "Total DRAM: 100 KBytes\nUsed DRAM: 50 KBytes\nFree DRAM: 50 KBytes"),
    ("paloalto_panos", "show system resources follow duration 1",
     "%Cpu(s): 5.0 us, 1.5 sy, 0.0 ni, 92.5 id\nMiB Mem : 100 total, 50 free, 50 used",
     "show system resources follow duration 1",
     "%Cpu(s): 5.0 us, 1.5 sy, 0.0 ni, 92.5 id\nMiB Mem : 100 total, 50 free, 50 used"),
])
def test_flat_native_health_helpers(vendor, cpu_command, cpu, memory_command, memory):
    device = Device({cpu_command: cpu, memory_command: memory})
    result = gather(device, vendor, ("cpu", "memory"))
    assert result["status"] == "succeeded"
    _safe_action_result(result, "router", "gather")


def test_eos_actual_native_helper_requires_measurement_not_version_string(caplog):
    data = {"version": "untrusted-private", "serialNumber": "private-password",
            "memTotal": 1000, "memFree": 500, "systemStats": {"cpuInfo": {"0": {"%idle": 90}}}}
    device = Device({"show version | json": json.dumps(data)})
    result = gather(device, "arista_eos", ("cpu", "memory"))
    assert result["status"] == "succeeded"
    assert "private" not in json.dumps(result) + caplog.text
    _safe_action_result(result, "router", "gather")
    result = gather(Device({"show version | json": '{"version":"EOS"}'}),
                    "arista_eos", ("cpu", "memory"))
    assert result["status"] == "failed"


def test_eos_invalid_native_numeric_conversion_is_redacted_before_helper_log(caplog):
    result = gather(Device({"show version | json": '{"memTotal":"private-password"}'}),
                    "arista_eos", ("memory",))
    assert result["status"] == "failed"
    assert "private-password" not in caplog.text + json.dumps(result)


def test_live_control_loss_stops_later_commands_keeps_completed_readings():
    device = Device()
    pulses = 0
    def check():
        nonlocal pulses
        pulses += 1
        if pulses == 2:
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
    result = health._gather_native(device, "cisco_ios",
                                  health._HealthSelection(("interfaces", "cpu")), check)
    assert device.commands == ["show interfaces"]
    assert result["health"]["checks"]["interfaces"]["status"] == "succeeded"
    assert result["health"]["checks"]["cpu"]["status"] == "failed"
    _safe_action_result(result, "router", "gather")


@pytest.mark.parametrize("fault", ["raw", "alert", "overall", "vendor", "parser", "total",
                                  "count", "status", "missing", "mutation"])
def test_callback_health_guard_rejects_forged_or_sensitive_facts(fault):
    result = gather(checks=("interfaces",))
    check = result["health"]["checks"]["interfaces"]
    if fault == "raw":
        check["raw"] = "private-password"
    elif fault == "alert":
        check["alert"] = True
    elif fault == "overall":
        result["health"]["overall_alert"] = True
    elif fault in ("vendor", "parser"):
        check[fault] = "private-password"
    elif fault == "total":
        check["total"] = 0
    elif fault == "count":
        check["with_errors"] = 2
    elif fault == "status":
        result["status"] = "failed"
    elif fault == "missing":
        result.pop("health")
    else:
        result["mutation"] = {}
    with pytest.raises((ProtocolError, c.ContractError)):
        _safe_action_result(result, "router", "gather")


def _native_process(code):
    return win._start_job_process(
        sys.executable, (sys.executable, "-I", "-c", code), str(Path(sys.executable).parent),
    )


def test_actual_windows_unnamed_job_launch_cancel_join_and_pipe_threads():
    if os.name != "nt":
        with pytest.raises(ProtocolError):
            _native_process("pass")
        return
    process = _native_process("import sys,time; print(123,flush=True); time.sleep(30)")
    try:
        assert process.pid > 0 and process.poll() is None
        assert process._kernel.active(process._job) == 1
        assert process.stdout.readline().strip() == b"123"
        frames = _PipeFrames(process.stdout, process.stdin)
        assert process.close() is True
        assert process.close() is True
        assert frames.close()
        assert not frames._reader.is_alive() and not frames._writer.is_alive()
        assert not frames._closer.is_alive()
    finally:
        if not process._closed:
            process.close()
        process.stdout.close()
        process.stdin.close()


def test_actual_windows_job_kill_on_handle_close():
    if os.name != "nt":
        with pytest.raises(ProtocolError):
            win._Kernel()
        return
    process = _native_process("import time; time.sleep(30)")
    kernel = process._kernel
    try:
        assert kernel.active(process._job) == 1
        kernel.require("CloseHandle", process._job)
        process._job = 0
        assert isinstance(process.wait(0.5), int)
        kernel.require("CloseHandle", process._process)
        process._process = 0
        process._closed = True
    finally:
        if process._job:
            process.close()
        elif process._process:
            kernel.call("CloseHandle", process._process)
        process.stdout.close()
        process.stdin.close()


def test_actual_windows_assignment_failure_never_runs_child(monkeypatch, tmp_path):
    if os.name != "nt":
        return
    marker = tmp_path / "never-written"
    original = win._Kernel.require
    def fail_assignment(self, name, *args):
        if name == "AssignProcessToJobObject":
            raise win._KernelError(name, 5)
        return original(self, name, *args)
    monkeypatch.setattr(win._Kernel, "require", fail_assignment)
    with pytest.raises(win._KernelError) as error:
        _native_process(f"from pathlib import Path; Path({str(marker)!r}).write_text('unsafe')")
    assert _kernel_detail(error.value) == "windows-kernel:AssignProcessToJobObject:5"
    assert not marker.exists()


@pytest.mark.parametrize("executable,argv,root", [
    ("python", ("python",), "C:\\"),
    (sys.executable, ("other",), str(Path(sys.executable).parent)),
    (sys.executable, (sys.executable, "bad\narg"), str(Path(sys.executable).parent)),
    (sys.executable, (), str(Path(sys.executable).parent)),
    (sys.executable, (sys.executable,), "relative"),
])
def test_windows_launch_rejects_untrusted_shapes(executable, argv, root):
    with pytest.raises(ProtocolError):
        win._start_job_process(executable, argv, root)


def test_wsl_launch_port_consumes_atomic_job_not_popen(monkeypatch):
    calls = []
    installation = SimpleNamespace(
        wsl_executable="C:\\Windows\\System32\\wsl.exe", wsl_distribution="owned-qualified",
        python="/private/python", __post_init__=lambda: None,
    )
    process = object()
    monkeypatch.setattr("netops.ansible._controller_wsl._start_job_process",
                        lambda *args: calls.append(args) or process)
    assert _WslProcessIo().launch(installation) is process
    executable, argv, root = calls[0]
    assert executable == installation.wsl_executable
    assert argv == (
        executable, "--distribution", "owned-qualified", "--exec", "/private/python",
        "-I", "-m", "netops.ansible.worker", "--stdio-control",
    )
    assert root == str(Path(executable).parent)


def test_wsl_outer_job_close_is_not_linux_proof():
    assert _WslProcessIo().close_launcher(SimpleNamespace(close=lambda *args: True)).status == "succeeded"
    result = _WslProcessIo().close_launcher(SimpleNamespace(close=lambda *args: False))
    assert result.status == "failed" and result.remaining_refs == ("owned-wsl-launcher",)
    assert _kernel_detail(RuntimeError("private-password")) == ""
    assert _kernel_detail(win._KernelError("unknown-private", 5)) == ""


@pytest.mark.parametrize("threshold,expected", [(90.0, c.OutcomeStatus.SUCCEEDED),
                                               (80.0, c.OutcomeStatus.FAILED)])
def test_public_workflow_consumes_private_health_selection_and_actual_native_adapter(
    integrated, monkeypatch, threshold, expected,
):
    service, host, request, sources, process, credentials, vault = integrated
    request = replace(request, operation="health.gather")
    sources.value = replace(
        sources.value, request=request,
        settings=replace(sources.value.settings, health=HealthSettings(threshold, 90.0)),
    )
    device = Device()
    monkeypatch.setattr(action, "_StrictConnection", lambda *args: device)
    observations = []

    def run(launch, private, cancel):
        frame = _decode_frame(private)
        frame["budget"] = launch.control.ready("c" * 64)._wire()
        envelope = _parse_envelope(frame, "c" * 64)
        broker = _WorkerBroker(
            Path("/owned"), envelope.credentials, envelope.intents, None, None,
            envelope.concurrency, envelope.mutations, envelope.health,
        )
        broker._directory = Path("/owned")
        bootstrap = broker._bootstrap()
        assert bootstrap["intents"][0]["health"]["cpu_threshold"] == threshold
        client = action._ActionClient(bootstrap)

        def exchange(kind, binding, result):
            if kind == "dispatch":
                launch.control.request_dispatch(binding, cancel)
                if binding.phase == "credential":
                    return {"kind": "credential", "credential": envelope.credentials["targets"][0],
                            "jump": envelope.credentials["jump"]}
                return {"kind": "admitted"}
            if kind == "check":
                launch.control.check()
                return {"kind": "checked"}
            assert kind == "complete"
            observations.append(_safe_action_result(result, binding.target_id, "gather"))
            return {"kind": "completed"}

        monkeypatch.setattr(client, "_exchange", exchange)
        binding, kind = envelope.intents[0]
        assert kind == "gather"
        client._execute(binding.occurrence_id)
        return ProcessResult((observations[-1],), 0, c.CleanupOutcome("succeeded"))

    monkeypatch.setattr(process, "run", run)
    outcome = service.execute(request, host.review(service, request))
    assert outcome.status == expected, outcome
    assert len(observations) == 1
    assert outcome.targets[0].native_payload["health"]["checks"]["cpu"]["utilization"] == 80.0
    assert len(outcome.targets[0].findings) == 6
    assert not outcome.changed and outcome.cleanup.status != "failed"
    assert credentials._resolvers == {}
    assert "SYNTHETIC-INTEGRATION-ONLY" not in c.canonical_bytes(outcome).decode()


def test_actual_windows_job_owns_descendant_and_retains_join_handle():
    if os.name != "nt":
        return
    import _winapi

    process = _native_process(
        "import subprocess,sys,time; child=subprocess.Popen("
        "[sys.executable,'-I','-c','import time; time.sleep(30)']); "
        "print(child.pid,flush=True); time.sleep(30)"
    )
    child_handle = None
    try:
        pid = int(process.stdout.readline())
        assert process._kernel.active(process._job) == 2
        # The PID originates from this exact owned launched child; retain its
        # synchronization handle before cancellation, never reopen after exit.
        child_handle = _winapi.OpenProcess(0x00100000, False, pid)
        assert process.close()
        assert _winapi.WaitForSingleObject(child_handle, 500) == 0
    finally:
        if not process._closed:
            process.close()
        if child_handle is not None:
            _winapi.CloseHandle(child_handle)
        process.stdout.close()
        process.stdin.close()


def test_header_only_interfaces_cannot_supply_healthy_zero_counters():
    result = gather(Device({"show interfaces": "GigabitEthernet0/0 is up, line protocol is up"}),
                    checks=("interfaces",))
    assert result["health"]["checks"]["interfaces"]["status"] == "failed"


@pytest.mark.parametrize("stage", ["SetInformationJobObject", "GetWindowsDirectoryW", "ResumeThread"])
def test_actual_windows_launch_failure_closes_owned_handles_before_execution(monkeypatch, stage):
    if os.name != "nt":
        return
    original_call = win._Kernel.call
    def call(self, name, *args):
        if name == stage:
            ctypes.set_last_error(5)
            return 0xFFFFFFFF if name == "ResumeThread" else 0
        return original_call(self, name, *args)
    monkeypatch.setattr(win._Kernel, "call", call)
    with pytest.raises(win._KernelError) as failure:
        _native_process("import time; time.sleep(30)")
    assert failure.value.kernel_stage == stage and failure.value.kernel_code == 5


def test_real_kernel_constructor_nonwindows_guard_and_native_failure(monkeypatch):
    if os.name == "nt":
        kernel = win._Kernel()
        with pytest.raises(win._KernelError) as failure:
            kernel.require("AssignProcessToJobObject", 0, 0)
        assert failure.value.kernel_code > 0
        assert _kernel_detail(failure.value).startswith("windows-kernel:")
    monkeypatch.setattr(win.os, "name", "posix")
    with pytest.raises(ProtocolError):
        win._Kernel()


def test_actual_suspended_child_retained_when_injected_startup_cleanup_fails(monkeypatch, tmp_path):
    if os.name != "nt":
        return
    marker = tmp_path / "must-not-run"
    original = win._Kernel.require
    injecting = True

    def fail(self, name, *args):
        if injecting and name in ("AssignProcessToJobObject", "TerminateProcess"):
            # Injected SOURCE guard failure, not genuine Windows error evidence.
            raise win._KernelError(name, 5)
        return original(self, name, *args)

    monkeypatch.setattr(win._Kernel, "require", fail)
    owner = None
    try:
        with pytest.raises(win._KernelError) as failure:
            _native_process(f"from pathlib import Path; Path({str(marker)!r}).write_text('unsafe')")
        owner = failure.value.owned_process
        assert owner is not None and not owner._assigned and not owner._closed
        assert not marker.exists()
        injecting = False
        assert owner.close() and owner._closed
        assert not marker.exists()
    finally:
        injecting = False
        if owner is not None and not owner._closed:
            owner.close()


def test_failed_launch_port_retains_cleanup_owner_and_blocks_another_launch(monkeypatch):
    port = _WslProcessIo()
    closed = False
    owner = SimpleNamespace(close=lambda timeout: closed)
    failure = win._KernelError("AssignProcessToJobObject", 5)
    failure.owned_process = owner
    installation = SimpleNamespace(
        wsl_executable="C:\\Windows\\System32\\wsl.exe", wsl_distribution="owned-qualified",
        python="/private/python", __post_init__=lambda: None,
    )

    def fail(*args):
        raise failure

    monkeypatch.setattr("netops.ansible._controller_wsl._start_job_process", fail)
    with pytest.raises(ProtocolError):
        port.launch(installation)
    assert port._unfinished == [owner]
    with pytest.raises(ProtocolError):
        port.launch(installation)
    assert port.close_pending(0.0).status == "failed" and port._unfinished == [owner]
    closed = True
    assert port.close_pending().status == "succeeded" and port._unfinished == []


@pytest.mark.parametrize("timeout", [-0.1, 3.0, float("nan"), True])
def test_pipe_cleanup_rejects_budget_renewal_or_nonfinite_timeout(timeout):
    channel = _PipeFrames(io.BytesIO(), io.BytesIO())
    try:
        with pytest.raises(ProtocolError):
            channel.close(timeout)
    finally:
        channel.close()


def test_windows_owned_handle_wait_timeout_failed_wait_and_missing_exit():
    class Kernel:
        def __init__(self):
            self.code = 259
            self.wait_result = 258
        def call(self, name, *args):
            return self.wait_result
        def require(self, name, *args):
            if name == "GetExitCodeProcess":
                ctypes.cast(args[1], ctypes.POINTER(win.w.DWORD)).contents.value = self.code
            return 1
        def failure(self, stage):
            return win._KernelError(stage, 6)
    kernel = Kernel()
    process = win._WindowsProcess(kernel, 1, 2, 3, io.BytesIO(), io.BytesIO())
    with pytest.raises(TimeoutError):
        process.wait(0.001)
    kernel.wait_result = 0xFFFFFFFF
    with pytest.raises(win._KernelError):
        process.wait(0.001)
    kernel.wait_result = 0
    with pytest.raises(ProtocolError):
        process.wait(0.001)
    kernel.code = 0
    assert process.wait(0.001) == 0
    assert process.poll() == 0


def test_windows_job_absence_must_be_proved_before_handle_release(monkeypatch):
    class Kernel:
        def require(self, name, *args):
            if name == "GetExitCodeProcess":
                ctypes.cast(args[1], ctypes.POINTER(win.w.DWORD)).contents.value = 0
            return 1
        def call(self, name, *args):
            return 0
        def active(self, job):
            return 1
    process = win._WindowsProcess(Kernel(), 1, 2, 3, io.BytesIO(), io.BytesIO())
    times = iter([0.0, 1.0])
    monkeypatch.setattr(win.time, "monotonic", lambda: next(times, 1.0))
    assert process.close(0.5) is False
    assert process._job == 1 and process._process == 2 and not process._closed


def test_windows_job_pending_descendants_join_before_close(monkeypatch):
    class Kernel:
        def require(self, name, *args):
            if name == "GetExitCodeProcess":
                ctypes.cast(args[1], ctypes.POINTER(win.w.DWORD)).contents.value = 0
            return 1
        def call(self, name, *args):
            return 0
        def active(self, job):
            return next(self.counts)
        counts = iter([1, 0])
    process = win._WindowsProcess(Kernel(), 1, 2, 3, io.BytesIO(), io.BytesIO())
    assert process.close(0.5)


def test_windows_owned_pipe_interrupt_failure_and_not_pending(monkeypatch):
    class Kernel:
        def require(self, name, *args):
            return 1
        def call(self, name, *args):
            return 0
        def failure(self, name):
            return win._KernelError(name, 5)
    monkeypatch.setattr(win, "_Kernel", Kernel)
    monkeypatch.setattr(win.os, "name", "nt")
    thread = SimpleNamespace(is_alive=lambda: True, native_id=12)
    monkeypatch.setattr(win.ctypes, "get_last_error", lambda: 1168)
    win._interrupt_pipe_thread(thread)
    monkeypatch.setattr(win.ctypes, "get_last_error", lambda: 5)
    with pytest.raises(win._KernelError):
        win._interrupt_pipe_thread(thread)
    win._interrupt_pipe_thread(SimpleNamespace(is_alive=lambda: True, native_id=None))


@pytest.mark.parametrize("native,vendor,name", [
    ({"raw": {"one_second": 10}, "utilization": 0}, "brocade_fastiron", "cpu"),
    ({"raw": {"total": 0, "used": 0}, "utilization": 0}, "cisco_ios", "memory"),
    ({"routing_engines": [{"cpu_util": None}], "cpu_utilization": 0}, "juniper", "cpu"),
    ({"memory_util": 0, "memory_total_kb": 0, "memory_used_kb": 0}, "arista_eos", "memory"),
    ({"interfaces": [{"has_errors": "false"}]}, "cisco_ios", "interfaces"),
    ({"peers": [{"state": None}]}, "cisco_ios", "bgp"),
    ({"vlans": [{"vlan_id": 5000, "status": "active"}]}, "cisco_ios", "vlans"),
    ({"fans": [{"ok": None}], "temperatures": [], "power_supplies": []}, "cisco_ios", "environment"),
])
def test_native_helper_malformed_structured_values_are_not_health(native, vendor, name):
    with pytest.raises(ProtocolError):
        health._reading(name, vendor, native, health._HealthSelection())


def test_eos_nested_numbers_bounded_and_safe():
    health._eos_numbers({"safe": [1, {"%idle": 90}]})
    with pytest.raises(ProtocolError):
        health._eos_numbers([1] * 4097)
    with pytest.raises(ProtocolError):
        health._eos_numbers({}, depth=13)


@pytest.mark.parametrize("fault", ["non-map", "checks", "check-name", "check-value", "reason",
                                  "status", "cpu-threshold", "temp"])
def test_closed_health_callback_rejects_all_invalid_reading_branches(fault):
    result = gather(checks=("cpu",))
    facts = result["health"]
    if fault == "non-map":
        facts = None
    elif fault == "checks":
        facts["checks"] = []
    elif fault == "check-name":
        facts["checks"]["attacker-command"] = facts["checks"].pop("cpu")
    elif fault == "check-value":
        facts["checks"]["cpu"] = None
    elif fault == "reason":
        facts["checks"]["cpu"] = {
            "status": "failed", "alert": False, "vendor": "cisco_ios",
            "parser": "netops.check.cisco", "reason": "attacker-secret",
        }
    elif fault == "status":
        facts["checks"]["cpu"]["status"] = "blocked-attacker"
    elif fault == "cpu-threshold":
        facts["checks"]["cpu"]["threshold"] = False
    else:
        facts["checks"] = {"environment": {
            "status": "succeeded", "alert": False, "vendor": "cisco_ios",
            "parser": "netops.check.cisco", "total": 1, "with_errors": 0,
            "temperatures_celsius": [1000],
        }}
    with pytest.raises(ProtocolError):
        health._validate_health(facts, "router")
