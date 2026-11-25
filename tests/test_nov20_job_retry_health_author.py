"""Bounded author SOURCE controls; neither independent approval nor Q03 proof."""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops.ansible import _action_health as health
from netops.ansible import _windows_job as win
from netops.ansible import contracts as c
from netops.ansible._controller_wsl import _WslProcessIo
from netops.ansible.controller_protocol import ProtocolError
from netops.ansible.worker_broker import _safe_action_result
from tests.native_windows_environment import create_native, suspended_environment
from tests.test_nov20_owned_job_health_author import CPU, Device, gather

JUNOS = """Physical interface: ge-0/0/0, Enabled, Physical link is Up
  Input errors:
    Errors: 0, Drops: 0
  Output errors:
    Errors: 0, Drops: 0
"""
EOS = {"interfaces": {"Ethernet1": {
    "interfaceStatus": "connected", "lineProtocolStatus": "up",
    "interfaceCounters": {"inputErrors": 0, "outputErrors": 0},
}}}


@pytest.mark.parametrize("value", [None, False, -1, 0.0, float("inf"), "0", c.MAX_SAFE_INT + 1])
def test_unavailable_counter_is_not_a_numeric_zero(value):
    with pytest.raises(ProtocolError):
        health._counter(value)


@pytest.mark.parametrize("value", [None, [], {}, {"interfaces": []}])
def test_eos_requires_actual_nonempty_interface_dictionary(value):
    with pytest.raises(ProtocolError):
        health._eos_interface_counters(value)


class Kernel:
    """Source-only handles are never passed to the operating system."""

    def __init__(self, failed=()):
        self.failed = set(failed)
        self.calls = []

    def require(self, stage, *args):
        self.calls.append((stage, args))
        if stage == "CloseHandle" and args[0] in self.failed:
            raise win._KernelError(stage, 6)
        assert stage != "TerminateJobObject" or args[0] != 0
        return 1

    def call(self, stage, *args):
        self.calls.append((stage, args))
        assert stage == "WaitForSingleObject" and args[0] == 301
        return 0

    def active(self, handle):
        assert handle == 201
        return 0


@pytest.mark.parametrize("failed", [(201,), (301,), (201, 301), (401,), (201, 301, 401)])
def test_partial_handle_close_retries_only_exact_still_owned_handles(failed):
    kernel = Kernel(failed)
    process = win._WindowsProcess(
        kernel, 201, 301, 123, io.BytesIO(), io.BytesIO(), _extra_handles=(401,),
    )
    process.returncode = 1
    adapter = _WslProcessIo()
    first = adapter.close_launcher(process)
    assert first.status == "failed" and len(first.errors) == len(failed)
    assert process._joined and not process._closed
    assert adapter._unfinished == [process]
    assert process._job == (201 if 201 in failed else 0)
    assert process._process == (301 if 301 in failed else 0)
    before = len(kernel.calls)
    kernel.failed.clear()
    assert adapter.close_pending().status == "succeeded"
    assert process._closed and process._job == process._process == 0
    assert process._extra_handles == [] and adapter._unfinished == []
    assert {args[0] for stage, args in kernel.calls[before:] if stage == "CloseHandle"} == set(failed)
    assert all(stage == "CloseHandle" for stage, args in kernel.calls[before:])
    before = len(kernel.calls)
    assert process.close() and adapter.close_pending().status == "succeeded"
    process.terminate()
    assert len(kernel.calls) == before


@pytest.mark.parametrize("raises", [False, True])
def test_failed_normal_close_blocks_relaunch_and_preserves_all_equal_owners(raises):
    class Owner:
        def __init__(self):
            self.attempts = 0
            self.succeeded = False

        def __eq__(self, other):
            return True

        def close(self, timeout):
            self.attempts += 1
            if raises and not self.succeeded:
                raise RuntimeError("private-password-must-not-leak")
            return self.succeeded

    first, second = Owner(), Owner()
    adapter = _WslProcessIo()
    for owner in (first, second):
        assert adapter.close_launcher(owner).status == "failed"
    assert len(adapter._unfinished) == 2
    assert adapter._unfinished[0] is first and adapter._unfinished[1] is second
    installation = SimpleNamespace(__post_init__=lambda: None)
    with pytest.raises(ProtocolError):
        adapter.launch(installation)
    first.succeeded = True
    pending = adapter.close_pending()
    assert pending.status == "failed" and len(pending.errors) == 1
    assert len(adapter._unfinished) == 1 and adapter._unfinished[0] is second
    assert first.attempts == second.attempts == 2
    assert "private-password" not in repr(pending)
    second.succeeded = True
    assert adapter.close_pending().status == "succeeded" and adapter._unfinished == []


def test_failed_start_without_child_retains_and_retries_pipe_and_stream_owners():
    kernel = Kernel((401,))

    class Stream(io.BytesIO):
        fail = True

        def close(self):
            if self.fail:
                raise OSError("source-only close failure")
            super().close()

    source, sink = Stream(), io.BytesIO()
    process = win._WindowsProcess(
        kernel, 201, 0, 0, source, sink, False,
        _extra_handles=(401,), _close_streams=True,
    )
    adapter = _WslProcessIo()
    outcome = adapter.close_launcher(process)
    assert len(outcome.errors) == 2
    assert process._job == 0 and process._extra_handles == [401]
    assert not source.closed and sink.closed and adapter._unfinished == [process]
    source.fail = False
    kernel.failed.clear()
    assert adapter.close_pending().status == "succeeded"
    assert source.closed and process._closed
    assert all(stage == "CloseHandle" for stage, _ in kernel.calls)


def test_actual_native_job_fixed_environment_and_explicit_private_handle_inheritance(monkeypatch):
    assert os.name == "nt", "Actual task-owned Windows helper control, not a platform fallback"
    import _winapi

    original = _winapi.CreateProcess
    observed = []
    runtimes = []
    baseline = False
    sentinel = "author-nov21-never-inherit-environment-canary"
    monkeypatch.setenv("NETOPS_NATIVE_ENV_SECRET", sentinel)
    monkeypatch.setenv("PYTHONUSERBASE", sentinel)
    monkeypatch.setenv("PYTHONPATH", str(Path(sys.executable).parent / "untrusted-never-import"))

    def create(executable, command, process_security, thread_security, inherit, flags, env, cwd, startup):
        observed.append({
            "executable": executable, "inherit": inherit, "flags": flags, "env": dict(env),
            "cwd": cwd, "handles": tuple(startup.lpAttributeList["handle_list"]),
            "stdin": startup.hStdInput, "stdout": startup.hStdOutput, "stderr": startup.hStdError,
        })
        result = (create_native if baseline else original)(
            executable, command, process_security, thread_security,
            inherit, flags, env, cwd, startup,
        )
        try:
            observed[-1]["kernel_environment"] = suspended_environment(result[0])
        except BaseException as failure:
            # Never strand the returned suspended process by raising inside the
            # observer before the real source receives and owns its handles.
            observed[-1]["kernel_environment"] = {"observation-failed": type(failure).__name__}
        return result

    monkeypatch.setattr(_winapi, "CreateProcess", create)
    root = str(Path(sys.executable).parent)
    helper = (
        "import json,os,sys,hashlib;"
        "print(json.dumps({'digests':{k:hashlib.sha256(v.encode()).hexdigest() "
        "for k,v in os.environ.items()},'path':sys.path,"
        "'isolated':sys.flags.isolated,'no_user_site':sys.flags.no_user_site}),flush=True)"
    )
    for baseline in (False, True):
        process = win._start_job_process(
            sys.executable, (sys.executable, "-I", "-c", helper), root,
        )
        try:
            actual = json.loads(process.stdout.readline())
            assert process.wait(2.0) == 0
            launch = observed[-1]
            assert launch["executable"] == sys.executable and launch["cwd"] == root
            assert launch["inherit"] is True
            assert launch["flags"] == win._SUSPENDED | win._NO_WINDOW
            assert set(launch["env"]) == {"SystemRoot", "LANG", "PYTHONNOUSERSITE"}
            # Corrected author assertion: actual pre-resume KERNEL environment,
            # not a false equivalence with Python's subsequently managed mapping.
            assert launch["kernel_environment"] == launch["env"]
            supplied = {
                key.upper(): hashlib.sha256(value.encode()).hexdigest()
                for key, value in launch["env"].items()
            }
            assert supplied.items() <= actual["digests"].items()
            assert set(actual["digests"]) - set(supplied) <= {"PYTHONUSERBASE"}
            assert hashlib.sha256(sentinel.encode()).hexdigest() not in actual["digests"].values()
            assert actual["isolated"] == actual["no_user_site"] == 1
            assert not any("untrusted-never-import" in path for path in actual["path"])
            assert len(set(launch["handles"])) == 3
            assert launch["handles"] == (launch["stdin"], launch["stdout"], launch["stderr"])
            assert process.close() is True
            runtimes.append(actual)
        finally:
            if not process._closed:
                process.close()
            process.stdout.close()
            process.stdin.close()
    # An additional Store-runtime key is permitted here only when the actual
    # direct native baseline produces exactly the same mapping and import path.
    # This never changes the source allowlist or qualifies strict post-start equality.
    assert len(observed) == 2 and runtimes[0] == runtimes[1]


@pytest.mark.parametrize("output", [
    "not interfaces", JUNOS + JUNOS, JUNOS.replace("Input errors:", "Input counters:"),
])
def test_junos_requires_unique_source_blocks_with_both_sections(output):
    with pytest.raises(ProtocolError):
        health._junos_interface_counters(output)


@pytest.mark.parametrize("vendor", ["juniper", "juniper_junos", "arista_eos"])
@pytest.mark.parametrize("value", [0, 1, 123, c.MAX_SAFE_INT])
def test_measured_counters_keep_correct_zero_or_alert_and_callback_provenance(vendor, value):
    if vendor == "arista_eos":
        data = json.loads(json.dumps(EOS))
        data["interfaces"]["Ethernet1"]["interfaceCounters"]["inputErrors"] = value
        responses = {"show interfaces | json": json.dumps(data)}
    else:
        responses = {"show interfaces extensive": JUNOS.replace("Errors: 0", f"Errors: {value}", 1)}
    result = gather(Device(responses), vendor, ("interfaces",))
    target = _safe_action_result(result, "router", "gather")
    assert target.findings[0].reading == int(value > 0)
    assert target.findings[0].result == ("pass" if value == 0 else "alert")
    assert target.findings[0].vendor == vendor
    assert target.status == (c.OutcomeStatus.SUCCEEDED if value == 0 else c.OutcomeStatus.FAILED)
    assert not target.changed and target.remote_state == "unchanged"


@pytest.mark.parametrize("fault", [
    "input", "output", "both", "header", "malformed", "negative", "fraction",
    "overflow", "other-errors", "second-interface", "duplicate",
])
@pytest.mark.parametrize("vendor", ["juniper", "juniper_junos"])
def test_missing_or_malformed_junos_measurements_remain_unknown(vendor, fault):
    output = JUNOS
    if fault in ("input", "both"):
        output = output.replace("    Errors: 0, Drops: 0", "    Drops: 0", 1)
    if fault in ("output", "both"):
        output = output.rsplit("    Errors: 0, Drops: 0", 1)[0] + "    Drops: 0\n"
    if fault == "header":
        output = JUNOS.splitlines()[0]
    if fault in ("malformed", "negative", "fraction", "overflow"):
        token = {"malformed": "private-password", "negative": "-1", "fraction": "0.1",
                 "overflow": str(c.MAX_SAFE_INT + 1)}[fault]
        output = output.replace("Errors: 0", f"Errors: {token}", 1)
    if fault == "other-errors":
        output = output.replace("Errors: 0", "Framing errors: 0")
    if fault == "second-interface":
        output += "Physical interface: ge-0/0/1, Enabled, Physical link is Up\n"
    if fault == "duplicate":
        output += JUNOS
    target = _safe_action_result(
        gather(Device({"show interfaces extensive": output}), vendor, ("interfaces",)),
        "router", "gather",
    )
    assert target.status == c.OutcomeStatus.FAILED
    assert target.findings[0].reading is None and target.findings[0].result == "unknown"


@pytest.mark.parametrize("fault", [
    "input", "output", "both", "counters", "interfaces", "interface-type",
    "empty", "bool", "none", "string", "float", "negative", "nan", "overflow", "second-interface",
])
def test_missing_or_malformed_eos_measurements_remain_unknown(fault, caplog):
    data = json.loads(json.dumps(EOS))
    counters = data["interfaces"]["Ethernet1"]["interfaceCounters"]
    if fault in ("input", "both"):
        counters.pop("inputErrors")
    if fault in ("output", "both"):
        counters.pop("outputErrors")
    if fault == "counters":
        data["interfaces"]["Ethernet1"].pop("interfaceCounters")
    elif fault == "interfaces":
        data.pop("interfaces")
    elif fault == "interface-type":
        data["interfaces"]["Ethernet1"] = []
    elif fault == "empty":
        data["interfaces"] = {}
    elif fault == "second-interface":
        data["interfaces"]["Ethernet2"] = {}
    elif fault in ("bool", "none", "string", "float", "negative", "nan", "overflow"):
        counters["inputErrors"] = {
            "bool": False, "none": None, "string": "private-password",
            "float": 0.0, "negative": -1, "nan": float("nan"), "overflow": c.MAX_SAFE_INT + 1,
        }[fault]
    output = json.dumps(data)
    result = gather(Device({"show interfaces | json": output, "show interfaces": output}),
                    "arista_eos", ("interfaces",))
    target = _safe_action_result(result, "router", "gather")
    assert target.status == c.OutcomeStatus.FAILED
    assert target.findings[0].reading is None and target.findings[0].result == "unknown"
    assert "private-password" not in caplog.text + c.canonical_bytes(target).decode()


def test_failed_selected_interfaces_keep_other_measured_health_and_source_failure():
    device = Device({"show interfaces extensive": JUNOS.splitlines()[0],
                     "show chassis routing-engine": RuntimeError("private-password")})
    result = gather(device, "juniper", ("interfaces", "cpu", "ospf"))
    target = _safe_action_result(result, "router", "gather")
    assert [finding.result for finding in target.findings] == ["unknown"] * 3
    assert result["health"]["checks"]["ospf"]["status"] == "unsupported"
    device = Device({"show interfaces": "malformed", "show processes cpu": CPU})
    result = gather(device, "cisco_ios", ("interfaces", "cpu"))
    assert result["health"]["checks"]["cpu"]["utilization"] == 80.0
    assert result["health"]["checks"]["interfaces"]["status"] == "failed"
    assert _safe_action_result(result, "router", "gather").status == c.OutcomeStatus.FAILED
