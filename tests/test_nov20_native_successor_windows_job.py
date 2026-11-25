"""AC-011/013 actual owned Windows helper jobs; never WSL/Q03 qualification."""

from __future__ import annotations

import ctypes
import gc
import json
import os
import sys
import threading
from ctypes import wintypes as w
from pathlib import Path

import pytest

from netops.ansible import _windows_job as win
from netops.ansible._controller_pipe import _PipeFrames
from netops.ansible._controller_wsl import _kernel_detail
from netops.ansible.controller_protocol import ProtocolError

HELPER = """import json,os,subprocess,sys
args=[sys.executable,'-I','-c','import time; time.sleep(25)']
child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
escaped=None
try:
    escaped=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True,creationflags=0x01000000)
except OSError:
    pass
print(json.dumps({'parent_pid':os.getpid(),'child_pid':child.pid,'escape_blocked':escaped is None,'escape_pid':None if escaped is None else escaped.pid}),flush=True)
if sys.argv[1]=='exit':
    sys.exit(0)
sys.stdin.readline()
"""


def native_api():
    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    dll.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    dll.OpenProcess.restype = w.HANDLE
    dll.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)]
    dll.IsProcessInJob.restype = w.BOOL
    dll.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    dll.WaitForSingleObject.restype = w.DWORD
    dll.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
    dll.TerminateProcess.restype = w.BOOL
    dll.CloseHandle.argtypes = [w.HANDLE]
    dll.CloseHandle.restype = w.BOOL
    dll.GetCurrentProcess.restype = w.HANDLE
    dll.GetProcessHandleCount.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
    dll.GetProcessHandleCount.restype = w.BOOL
    dll.GetHandleInformation.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
    dll.GetHandleInformation.restype = w.BOOL
    return dll


def handle_count(api):
    count = w.DWORD()
    assert api.GetProcessHandleCount(api.GetCurrentProcess(), ctypes.byref(count))
    return count.value


@pytest.mark.parametrize("parent_exit", [False, True])
def test_t04_real_owned_job_contains_child_denies_escape_and_closes_exact_handles(
    tmp_path, parent_exit, record_property,
):
    assert os.name == "nt", "This native proof must run on actual Windows, not be skipped or mocked"
    api = native_api()
    # The isolated diagnostic found a stable first-launch runtime allocation.
    # Initialize the kernel API before measuring owned-operation cleanup.
    win._Kernel()
    gc.collect()
    before_handles = handle_count(api)
    python = str(Path(sys.base_prefix) / "python.exe")
    helper = tmp_path / "owned-helper.py"
    helper.write_text(HELPER, encoding="utf-8")
    process = win._start_job_process(
        python, (python, "-I", "-u", str(helper), "exit" if parent_exit else "wait"),
        str(tmp_path),
    )
    owned_handles = (process._job, process._process)
    child_handle = escape_handle = None
    received, errors = [], []
    ready = threading.Event()

    def read(proc=process, signal=ready):
        try:
            received.append(json.loads(proc.stdout.readline()))
        except BaseException as error:
            errors.append(error)
        finally:
            signal.set()

    reader = threading.Thread(target=read)
    reader.start()
    try:
        assert ready.wait(5.0), "Actual native helper startup failed"
        assert errors == [] and len(received) == 1
        receipt = received[0]
        assert receipt["parent_pid"] == process.pid
        child_handle = api.OpenProcess(0x00100000 | 0x1000, False, receipt["child_pid"])
        assert child_handle, "Keep the exact child's native handle before cancellation"
        inside = w.BOOL()
        assert api.IsProcessInJob(child_handle, process._job, ctypes.byref(inside))
        assert inside.value
        if receipt["escape_pid"] is not None:
            # This is only a task-owned helper returned by our exact launcher.
            escape_handle = api.OpenProcess(0x00100000 | 0x0001, False, receipt["escape_pid"])
        assert receipt["escape_blocked"] is True, "Unqualified breakaway cannot escape ownership"
        if parent_exit:
            assert process.wait(5.0) == 0
            assert process._kernel.active(process._job) >= 1
            assert api.WaitForSingleObject(child_handle, 0) == 258
        else:
            assert process.poll() is None
            assert process._kernel.active(process._job) == 2
            with pytest.raises(TimeoutError):
                process.wait(0.01)
        assert process.close(2.0) is True
        assert api.WaitForSingleObject(child_handle, 1000) == 0
        assert process._job == process._process == 0
        flags = w.DWORD()
        assert all(not api.GetHandleInformation(handle, ctypes.byref(flags)) for handle in owned_handles)
        assert process.close(0.01) is True
        record_property("native_owned_job", json.dumps({
            **receipt, "actual_kernel": True, "child_in_exact_job": True,
            "job_and_process_handles_closed": True, "parent_exited_first": parent_exit,
            "wsl_or_controller_qualified": False,
        }))
    finally:
        if escape_handle:
            api.TerminateProcess(escape_handle, 1)
            api.WaitForSingleObject(escape_handle, 1000)
            api.CloseHandle(escape_handle)
        if process._job:
            process.close(2.0)
        win._interrupt_pipe_thread(reader)
        reader.join(2.0)
        process.stdin.close()
        process.stdout.close()
        if child_handle:
            api.CloseHandle(child_handle)
    assert not reader.is_alive()
    # Python's own process lock / event / thread objects also own handles.
    # Collect them as part of cleanup, without changing the no-leak comparison.
    del process, reader, ready, read
    gc.collect()
    assert handle_count(api) <= before_handles, "Owned native handles must not remain after teardown"


def test_t04_actual_unnamed_job_kill_on_close_is_not_launcher_exit(tmp_path, record_property):
    assert os.name == "nt"
    api = native_api()
    python = str(Path(sys.base_prefix) / "python.exe")
    helper = tmp_path / "owned-kill-on-close-helper.py"
    helper.write_text(HELPER, encoding="utf-8")
    process = win._start_job_process(
        python, (python, "-I", "-u", str(helper), "wait"), str(tmp_path),
    )
    child_handle = None
    try:
        data = json.loads(process.stdout.readline())
        child_handle = api.OpenProcess(0x00100000 | 0x1000, False, data["child_pid"])
        assert child_handle and data["escape_blocked"] is True
        assert process.poll() is None
        process._kernel.require("CloseHandle", process._job)
        process._job = 0
        assert isinstance(process.wait(3.0), int)
        assert api.WaitForSingleObject(child_handle, 1000) == 0
        process._kernel.require("CloseHandle", process._process)
        process._process = 0
        process._closed = True
        record_property("native_kill_on_close", json.dumps({
            "parent_pid": process.pid, "child_pid": data["child_pid"],
            "actual_job_handle_close_killed_both": True, "q03": False,
        }))
    finally:
        if process._job:
            process.close(2.0)
        elif process._process:
            process._kernel.call("TerminateProcess", process._process, 1)
            process._kernel.call("WaitForSingleObject", process._process, 1000)
            process._kernel.call("CloseHandle", process._process)
        process.stdin.close()
        process.stdout.close()
        if child_handle:
            api.CloseHandle(child_handle)


def test_t13_actual_owned_private_pipe_frames_roundtrip_and_threads_close(tmp_path):
    assert os.name == "nt"
    python = str(Path(sys.base_prefix) / "python.exe")
    helper = tmp_path / "owned-private-frame-helper.py"
    helper.write_text(
        "import json,struct,sys,time\n"
        "payload=b'{\"kind\":\"pulse\"}'\n"
        "sys.stdout.buffer.write(struct.pack('>I',len(payload))+payload)\n"
        "sys.stdout.buffer.flush()\n"
        "size=struct.unpack('>I',sys.stdin.buffer.read(4))[0]\n"
        "received=json.loads(sys.stdin.buffer.read(size))\n"
        "assert received=={'kind':'alive'}\n"
        "payload=b'{\"kind\":\"pulse\"}'\n"
        "sys.stdout.buffer.write(struct.pack('>I',len(payload))+payload)\n"
        "sys.stdout.buffer.flush()\n"
        "time.sleep(10)\n", encoding="utf-8",
    )
    process = win._start_job_process(
        python, (python, "-I", "-u", str(helper)), str(tmp_path),
    )
    frames = _PipeFrames(process.stdout, process.stdin)
    try:
        assert frames.receive(3.0) == {"kind": "pulse"}
        frames.send({"kind": "alive"}, 2.0)
        assert frames.receive(3.0) == {"kind": "pulse"}
        assert process.close(2.0)
        assert frames.close(2.0)
        assert not frames._reader.is_alive()
        assert not frames._writer.is_alive()
        assert frames._closer is not None and not frames._closer.is_alive()
        assert process.stdout.closed and process.stdin.closed
    finally:
        if process._job:
            process.close(2.0)
        frames.close(2.0)


def test_t13_real_kernel_failure_has_only_safe_numeric_source_provenance(record_property):
    assert os.name == "nt"
    kernel = win._Kernel()
    with pytest.raises(win._KernelError) as caught:
        kernel.require("OpenThread", 1, False, 0)
    error = caught.value
    assert error.kernel_stage == "OpenThread"
    assert 0 < error.kernel_code <= 0xFFFFFFFF
    assert _kernel_detail(error) == "windows-kernel:OpenThread:" + str(error.kernel_code)
    assert _kernel_detail(RuntimeError("private-credential-path-do-not-log")) == ""
    record_property("native_kernel_failure", _kernel_detail(error))


@pytest.mark.parametrize("fault", ["relative-exe", "relative-root", "argv-mismatch", "newline"])
def test_t13_invalid_native_outer_launch_never_creates_job(fault, tmp_path, monkeypatch):
    python = str(Path(sys.base_prefix) / "python.exe")
    executable, argv, root = python, (python, "-I", "-c", "pass"), str(tmp_path)
    if fault == "relative-exe":
        executable, argv = "python.exe", ("python.exe", "-c", "pass")
    elif fault == "relative-root":
        root = "relative"
    elif fault == "argv-mismatch":
        argv = ("foreign.exe", "-c", "pass")
    else:
        argv = (python, "-c", "pass\n")

    def forbidden():
        pytest.fail("Invalid outer launch must fail before any real kernel effect")

    monkeypatch.setattr(win, "_Kernel", forbidden)
    with pytest.raises(ProtocolError):
        win._start_job_process(executable, argv, root)
