"""Private Windows Job ownership for offline installation children only."""

from __future__ import annotations

import ctypes
import importlib
import os
import subprocess
from ctypes import wintypes as w
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import IO, cast

from netops.ansible.artifact_cleanup import _retain_cleanup_owner, release_all, teardown

__all__: tuple[str, ...] = ()


class _Basic(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
        ("flags", w.DWORD), ("minimum", ctypes.c_size_t), ("maximum", ctypes.c_size_t),
        ("active", w.DWORD), ("affinity", ctypes.c_size_t), ("priority", w.DWORD),
        ("scheduling", w.DWORD),
    ]


class _IO(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in
                ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]


class _Extended(ctypes.Structure):
    _fields_ = [
        ("basic", _Basic), ("io", _IO), ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t),
        ("peak_job", ctypes.c_size_t),
    ]


class _InstallationChild:
    """Retain the process and primary thread returned by this exact creation."""

    def __init__(
        self, command: tuple[str, ...], cwd: Path, environment: dict[str, str],
    ) -> None:
        api = importlib.import_module("_winapi")
        self.api = SimpleNamespace(**{
            name: getattr(api, name) for name in (
                "GetCurrentProcess", "DuplicateHandle", "DUPLICATE_SAME_ACCESS",
                "CreateProcess", "CloseHandle", "WaitForSingleObject",
                "GetExitCodeProcess", "TerminateProcess",
            )
        })
        crt = importlib.import_module("msvcrt")
        self._handle = 0
        self.thread_handle = 0
        self.pid = self.tid = 0
        self.returncode: int | None = None
        self._joined = False
        self._temporary: set[int] = set()
        self._descriptors: set[int] = set()
        self.stdout: IO[bytes] | None = None
        self.stderr: IO[bytes] | None = None
        try:
            current = self.api.GetCurrentProcess()

            def child_handle(descriptor: int) -> int:
                handle = int(self.api.DuplicateHandle(
                    current, crt.get_osfhandle(descriptor), current, 0, True,
                    self.api.DUPLICATE_SAME_ACCESS,
                ))
                if not handle:
                    raise OSError("installation-pipe-handle-unavailable")
                self._temporary.add(handle)
                return handle

            with open(os.devnull, "rb", buffering=0) as null:
                stdin = child_handle(null.fileno())
            outputs = []
            for name in ("stdout", "stderr"):
                read, write = os.pipe()
                self._descriptors.update((read, write))
                outputs.append(child_handle(write))
                self._close_descriptor(write)
                stream = os.fdopen(read, "rb")
                self._descriptors.remove(read)
                if name == "stdout":
                    self.stdout = stream
                else:
                    self.stderr = stream
            startup = subprocess.STARTUPINFO()
            startup.dwFlags = subprocess.STARTF_USESTDHANDLES
            startup.hStdInput, startup.hStdOutput, startup.hStdError = stdin, *outputs
            startup.lpAttributeList = {"handle_list": [stdin, *outputs]}
            self._handle, self.thread_handle, self.pid, self.tid = cast(
                tuple[int, int, int, int], self.api.CreateProcess(
                    command[0], subprocess.list2cmdline(command), None, None, True, 4,
                    environment, str(cwd), startup,
                ),
            )
            release_all(
                partial(self._close_temporary, handle) for handle in tuple(self._temporary)
            )
        except BaseException as exc:
            with teardown(exc):
                release_all(partial(self._close_descriptor, descriptor)
                            for descriptor in tuple(self._descriptors))
            if self._handle:
                with teardown(exc):
                    self.kill()
                with teardown(exc):
                    self.wait(timeout=1.0)
            with teardown(exc):
                self.close()
            with teardown(exc):
                release_all(stream.close for stream in (self.stdout, self.stderr)
                            if stream is not None)
            if (
                self._handle or self.thread_handle or self._temporary or self._descriptors
                or any(stream is not None and not stream.closed
                       for stream in (self.stdout, self.stderr))
            ):
                _retain_cleanup_owner(exc, self)
            raise

    def _close_descriptor(self, descriptor: int) -> None:
        if descriptor in self._descriptors:
            os.close(descriptor)
            self._descriptors.remove(descriptor)

    def _close_temporary(self, handle: int) -> None:
        if handle in self._temporary:
            self.api.CloseHandle(handle)
            self._temporary.remove(handle)

    def poll(self) -> int | None:
        """Observe only the retained exact process handle."""
        if self.returncode is None and not self._handle:
            raise OSError("installation-process-authority-unavailable")
        if self.returncode is None and self.api.WaitForSingleObject(self._handle, 0) == 0:
            self.returncode = int(self.api.GetExitCodeProcess(self._handle))
        return self.returncode

    def wait(self, timeout: float) -> int:
        """Join the retained process within the caller's unchanged cleanup bound."""
        if self._joined and self.returncode is not None:
            return self.returncode
        if not self._handle:
            raise OSError("installation-process-authority-unavailable")
        result = self.api.WaitForSingleObject(self._handle, max(0, int(timeout * 1000)))
        if result == 258:
            raise subprocess.TimeoutExpired("owned-installation-child", timeout)
        if result != 0:
            raise OSError("installation-process-wait")
        self.returncode = int(self.api.GetExitCodeProcess(self._handle))
        self._joined = True
        return self.returncode

    def kill(self) -> None:
        """Keep failed exact-handle termination retryable until actual join."""
        if self._handle and not self._joined:
            self.api.TerminateProcess(self._handle, 1)

    def close(self) -> None:
        """Close once, retaining every failed close and unjoined process right."""
        def close_thread() -> None:
            if self.thread_handle:
                self.api.CloseHandle(self.thread_handle)
                self.thread_handle = 0

        def close_process() -> None:
            if self._handle:
                if not self._joined:
                    raise OSError("installation-process-unjoined")
                self.api.CloseHandle(self._handle)
                self._handle = 0

        release_all((
            *(partial(self._close_descriptor, descriptor)
              for descriptor in tuple(self._descriptors)),
            *(partial(self._close_temporary, handle) for handle in tuple(self._temporary)),
            close_thread, close_process,
        ))


class _WindowsJob:
    """Assign a suspended exact child before it can spawn, then resume its thread."""

    def __init__(self) -> None:
        self._temporary: set[int] = set()
        self._stopped = False
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel = kernel
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        kernel.CreateJobObjectW.restype = w.HANDLE
        kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        kernel.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
        kernel.CloseHandle.argtypes = [w.HANDLE]
        for name in (
            "SetInformationJobObject", "AssignProcessToJobObject",
            "TerminateJobObject", "CloseHandle",
        ):
            getattr(kernel, name).restype = w.BOOL
        for name in ("GetProcessId", "GetProcessIdOfThread", "GetThreadId"):
            function = getattr(kernel, name)
            function.argtypes = [w.HANDLE]
            function.restype = w.DWORD
        kernel.ResumeThread.argtypes = [w.HANDLE]
        kernel.ResumeThread.restype = w.DWORD
        self.handle = kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise self._error("installation-job-create")
        info = _Extended()
        info.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            error = self._error("installation-job-limit")
            with teardown(error):
                self.close()
            if self.handle:
                _retain_cleanup_owner(error, self)
            raise error

    @staticmethod
    def _error(reason: str) -> OSError:
        error = OSError(reason)
        error.winerror = ctypes.get_last_error()
        return error

    def _close_temporary(self, handle: int) -> None:
        if handle in self._temporary:
            if not self.kernel.CloseHandle(handle):
                raise self._error("installation-thread-close")
            self._temporary.remove(handle)

    def assign(self, pid: int, process_handle: int, thread_handle: int, tid: int) -> None:
        """Validate creation handles, assign the private Job, then resume once."""
        kernel = self.kernel
        if not process_handle or not thread_handle or not pid or not tid:
            raise OSError("installation-thread-authority-unavailable")
        process_id = kernel.GetProcessId(process_handle)
        if not process_id:
            raise self._error("installation-process-identity")
        thread_process_id = kernel.GetProcessIdOfThread(thread_handle)
        if not thread_process_id:
            raise self._error("installation-thread-identity")
        thread_id = kernel.GetThreadId(thread_handle)
        if not thread_id:
            raise self._error("installation-thread-identity")
        if process_id != pid or thread_process_id != process_id or thread_id != tid:
            raise OSError("installation-thread-identity-mismatch")
        if not kernel.AssignProcessToJobObject(self.handle, process_handle):
            raise self._error("installation-job-assign")
        if kernel.ResumeThread(thread_handle) != 1:
            raise self._error("installation-thread-resume")

    def stop(self) -> None:
        """Terminate only this owned Job, including ensurepip's descendants."""
        if self.handle and not self._stopped:
            if not self.kernel.TerminateJobObject(self.handle, 1):
                raise self._error("installation-job-stop")
            self._stopped = True

    def close(self) -> None:
        """Close the exact private handle; kill-on-close cannot target foreign work."""
        def close_job() -> None:
            if self.handle:
                if not self.kernel.CloseHandle(self.handle):
                    raise self._error("installation-job-close")
                self.handle = None
                self._stopped = True

        release_all((
            *(partial(self._close_temporary, handle) for handle in tuple(self._temporary)),
            close_job,
        ))
