"""Private Windows outer-process ownership; never Linux group qualification."""

from __future__ import annotations

import ctypes
import importlib
import io
import os
import subprocess
import threading
import time
from ctypes import wintypes as w
from pathlib import Path
from typing import BinaryIO, cast

from . import contracts as c
from .controller_protocol import ProtocolError

_KILL_ON_CLOSE = 0x2000
_SUSPENDED = 0x00000004
_NO_WINDOW = 0x08000000
_WAIT_OBJECT = 0
_WAIT_TIMEOUT = 258
_INFINITE_EXIT = 259


class _KernelError(ProtocolError):
    """Safe native failure provenance; no OS error text or sensitive values."""

    def __init__(self, stage: str, code: int) -> None:
        super().__init__(c.ReasonCode.CONTROL_LOST)
        self.kernel_stage, self.kernel_code = stage, max(0, min(code, 0xFFFFFFFF))
        self.owned_process: _WindowsProcess | None = None


class _Limits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", w.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", w.DWORD), ("Affinity", ctypes.c_size_t),
        ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD),
    ]


class _Counters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
    )]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _Limits), ("IoInfo", _Counters),
        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _Accounting(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong), ("TotalPageFaultCount", w.DWORD),
        ("TotalProcesses", w.DWORD), ("ActiveProcesses", w.DWORD),
        ("TotalTerminatedProcesses", w.DWORD),
    ]


class _Kernel:
    """Typed local kernel calls; errors contain only a bounded native numeric code."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
        self._dll = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
            "QueryInformationJobObject": (
                [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p], w.BOOL,
            ),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "TerminateProcess": ([w.HANDLE, w.UINT], w.BOOL),
            "ResumeThread": ([w.HANDLE], w.DWORD),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "WaitForSingleObject": ([w.HANDLE, w.DWORD], w.DWORD),
            "GetExitCodeProcess": ([w.HANDLE, ctypes.POINTER(w.DWORD)], w.BOOL),
            "GetWindowsDirectoryW": ([w.LPWSTR, w.UINT], w.UINT),
            "OpenThread": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            "CancelSynchronousIo": ([w.HANDLE], w.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self._dll, name)
            function.argtypes, function.restype = arguments, result

    def call(self, name: str, *args: object) -> int:
        return int(getattr(self._dll, name)(*args) or 0)

    @staticmethod
    def failure(stage: str) -> _KernelError:
        code = ctypes.get_last_error()
        # Do not copy FormatMessage, paths, argv or exception strings.
        return _KernelError(stage, code)

    def require(self, name: str, *args: object) -> int:
        result = self.call(name, *args)
        if result == 0:
            raise self.failure(name)
        return result

    def active(self, job: int) -> int:
        value = _Accounting()
        self.require("QueryInformationJobObject", job, 1, ctypes.byref(value),
                     ctypes.sizeof(value), None)
        return int(value.ActiveProcesses)


class _WindowsProcess:
    """Own exact process/job handles until actual job absence and process wait."""

    def __init__(
        self, kernel: _Kernel, job: int, process: int, pid: int,
        source: BinaryIO, sink: BinaryIO,
        assigned: bool = True,
        *, _extra_handles: tuple[int, ...] = (), _close_streams: bool = False,
    ) -> None:
        self._kernel, self._job, self._process = kernel, job, process
        self.pid, self.stdout, self.stdin = pid, source, sink
        self._lock = threading.Lock()
        self.returncode: int | None = None
        self._closed = False
        self._assigned = assigned
        self._joined = not process
        self._extra_handles = list(_extra_handles)
        # Normal IPC streams belong to _PipeFrames. Only failed startup, which
        # never hands streams to that owner, closes them here.
        self._close_streams = _close_streams
        self._close_failures: tuple[BaseException, ...] = ()

    def poll(self) -> int | None:
        """Poll the retained handle, never reopen a potentially reused PID."""
        if self.returncode is None:
            code = w.DWORD()
            self._kernel.require("GetExitCodeProcess", self._process, ctypes.byref(code))
            if code.value != _INFINITE_EXIT:
                self.returncode = int(code.value)
        return self.returncode

    def wait(self, timeout: float) -> int:
        """Wait bounded on the owned handle; a timeout is not successful teardown."""
        result = self._kernel.call("WaitForSingleObject", self._process, int(timeout * 1000))
        if result == _WAIT_TIMEOUT:
            raise TimeoutError("owned-process-wait")
        if result != _WAIT_OBJECT:
            raise self._kernel.failure("WaitForSingleObject")
        code = self.poll()
        if code is None:
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
        return code

    def terminate(self) -> None:
        """Cancel the owned outer tree without claiming WSL Linux termination."""
        if self._joined:
            return
        self._kernel.require(
            "TerminateJobObject" if self._assigned else "TerminateProcess",
            self._job if self._assigned else self._process, 1,
        )

    def close(self, timeout: float = 0.5) -> bool:
        """Join the process and prove job emptiness before relinquishing handles."""
        with self._lock:
            if self._closed:
                return True
            self._close_failures = ()
            if not self._joined:
                start = time.monotonic()
                self.terminate()
                self.wait(timeout)
                deadline = start + timeout
                while self._kernel.active(self._job):
                    now = time.monotonic()
                    if now < start or now >= deadline:
                        return False
                    time.sleep(min(0.005, deadline - now))
                # A failed handle close cannot erase actual wait/job proof or
                # cause a subsequent retry to terminate a closed handle.
                self._joined = True
            failures: list[BaseException] = []
            for field in ("_job", "_process"):
                handle = getattr(self, field)
                if handle:
                    try:
                        self._kernel.require("CloseHandle", handle)
                    except BaseException as failure:
                        failures.append(failure)
                    else:
                        setattr(self, field, 0)
            for handle in tuple(self._extra_handles):
                try:
                    self._kernel.require("CloseHandle", handle)
                except BaseException as failure:
                    failures.append(failure)
                else:
                    self._extra_handles.remove(handle)
            if self._close_streams:
                for stream in (self.stdout, self.stdin):
                    if not stream.closed:
                        try:
                            stream.close()
                        except BaseException as failure:
                            failures.append(failure)
            if failures:
                self._close_failures = tuple(failures)
                raise failures[0]
            self._closed = True
            return True


def _start_job_process(executable: str, argv: tuple[str, ...], root: str) -> _WindowsProcess:
    """Low-level private IO seam, called only with bootstrap-selected fixed launch.

    CreateProcess is suspended; assignment must succeed before ResumeThread.
    No breakaway flag, named/global job, ambient inherited handles or shell.
    Host-parent nested-job restrictions fail closed with the real kernel code.
    """
    if (
        os.name != "nt" or not Path(executable).is_absolute() or not Path(root).is_absolute()
        or not argv or argv[0] != executable
        or any(type(arg) is not str or any(ch in arg for ch in ("\x00", "\r", "\n")) for arg in argv)
        or not Path(root).is_dir()
    ):
        raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
    kernel = _Kernel()
    api = importlib.import_module("_winapi")
    crt = importlib.import_module("msvcrt")
    job = kernel.require("CreateJobObjectW", None, None)
    handles: list[int] = []
    process = thread = pid = 0
    assigned = False
    source: BinaryIO | None = None
    sink: BinaryIO | None = None
    try:
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = _KILL_ON_CLOSE
        kernel.require("SetInformationJobObject", job, 9, ctypes.byref(limits), ctypes.sizeof(limits))
        child_read, parent_write = cast(tuple[int, int], api.CreatePipe(None, 0))
        handles.extend((child_read, parent_write))
        parent_read, child_write = cast(tuple[int, int], api.CreatePipe(None, 0))
        handles.extend((parent_read, child_write))
        # Parent handles remain noninheritable. Only the two child IPC handles
        # and a separately duplicated NUL stderr occur in the explicit list.
        for handle in (child_read, child_write):
            os.set_handle_inheritable(handle, True)
        with open(os.devnull, "wb", buffering=0) as null:
            nul = int(api.DuplicateHandle(
                api.GetCurrentProcess(), crt.get_osfhandle(null.fileno()),
                api.GetCurrentProcess(), 0, True, api.DUPLICATE_SAME_ACCESS,
            ))
        handles.append(nul)
        startup = subprocess.STARTUPINFO()
        startup.dwFlags = subprocess.STARTF_USESTDHANDLES
        startup.hStdInput, startup.hStdOutput, startup.hStdError = child_read, child_write, nul
        startup.lpAttributeList = {"handle_list": [child_read, child_write, nul]}
        directory = ctypes.create_unicode_buffer(32768)
        count = kernel.require("GetWindowsDirectoryW", directory, len(directory))
        if count >= len(directory):
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
        environment = {
            "SystemRoot": directory.value, "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1",
        }
        process, thread, pid, _ = cast(tuple[int, int, int, int], api.CreateProcess(
            executable, subprocess.list2cmdline(argv), None, None, True,
            _SUSPENDED | _NO_WINDOW, environment, root, startup,
        ))
        kernel.require("AssignProcessToJobObject", job, process)
        assigned = True
        # All child ends close in the parent before the child can execute.
        for handle in (child_read, child_write, nul):
            kernel.require("CloseHandle", handle)
            handles.remove(handle)
        source = cast(BinaryIO, os.fdopen(
            int(crt.open_osfhandle(parent_read, os.O_RDONLY | os.O_BINARY)), "rb", buffering=0,
        ))
        handles.remove(parent_read)
        sink = cast(BinaryIO, os.fdopen(
            int(crt.open_osfhandle(parent_write, os.O_WRONLY | os.O_BINARY)), "wb", buffering=0,
        ))
        handles.remove(parent_write)
        if kernel.call("ResumeThread", thread) != 1:
            raise kernel.failure("ResumeThread")
        kernel.require("CloseHandle", thread)
        thread = 0
        return _WindowsProcess(kernel, job, process, pid, source, sink)
    except BaseException as failure:
        # Retained handles own these exact children even on assignment failure.
        # Never resume an unassigned process or use a PID/name/global kill.
        owner = _WindowsProcess(
            kernel, job, process, pid,
            source if source is not None else cast(BinaryIO, io.BytesIO()),
            sink if sink is not None else cast(BinaryIO, io.BytesIO()), assigned,
            _extra_handles=tuple(handle for handle in (thread, *handles) if handle),
            _close_streams=True,
        )
        try:
            proved = owner.close()
        except BaseException:
            proved = False
        if not proved:
            error = failure if type(failure) is _KernelError else _KernelError("LaunchCleanup", 0)
            error.owned_process = owner
            raise error from None
        raise


def _interrupt_pipe_thread(thread: threading.Thread) -> None:
    """Interrupt only this owned thread's blocking Windows synchronous pipe IO."""
    if os.name != "nt" or not thread.is_alive() or thread.native_id is None:
        return
    kernel = _Kernel()
    handle = kernel.require("OpenThread", 1, False, thread.native_id)
    try:
        # ERROR_NOT_FOUND means no IO is currently pending; close/EOF follows.
        if not kernel.call("CancelSynchronousIo", handle) and ctypes.get_last_error() != 1168:
            raise kernel.failure("CancelSynchronousIo")
    finally:
        kernel.require("CloseHandle", handle)
