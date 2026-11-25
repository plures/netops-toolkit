"""Bounded fixed offline installation processes; never shell or detached work."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import IO, TYPE_CHECKING

from netops.ansible import contracts as c
from netops.ansible.artifact_cleanup import (
    _retain_cleanup_owner,
    _storage_io,
    release_all,
    teardown,
)

if TYPE_CHECKING:
    from ._documentation import _DocumentationPlan
    from ._installation_windows import _InstallationChild

__all__: tuple[str, ...] = ()

_VENV = """
import json, os, pathlib, re, subprocess, sys, venv
try:
    venv.main(["--copies", sys.argv[1]])
    executable = pathlib.Path(sys.argv[1], "Scripts", "python.exe") if os.name == "nt" else (
        pathlib.Path(sys.argv[1], "bin", "python")
    )
    if not executable.is_file():
        raise FileNotFoundError(2, "owned-venv-executable-missing")
except (OSError, subprocess.CalledProcessError) as error:
    def code(value):
        return value if type(value) is int and 0 <= value <= 4294967295 else None
    native = code(getattr(error, "winerror", None))
    number = code(getattr(error, "errno", None))
    origin = "child"
    exception_class = type(error).__name__
    allowed = ("OSError", "PermissionError", "FileNotFoundError", "NotADirectoryError",
               "FileExistsError", "CalledProcessError", "RuntimeError", "ValueError",
               "ModuleNotFoundError", "ImportError", "LookupError", "TypeError")
    if isinstance(error, subprocess.CalledProcessError):
        origin = "child-report"
        data = error.output
        if type(data) is bytes and len(data) <= 1048576:
            matches = re.findall(rb"\\[WinError ([0-9]{1,10})\\]", data)
            numbers = re.findall(rb"\\[Errno ([0-9]{1,10})\\]", data)
            if matches:
                native = code(int(matches[-1]))
            if numbers:
                number = code(int(numbers[-1]))
            classes = re.findall(rb"(?m)^([A-Za-z]+Error):", data)
            for candidate in classes:
                candidate = candidate.decode("ascii")
                if candidate in allowed:
                    exception_class = candidate
    print(json.dumps({"schema": "netops-venv-native-v1",
                      "errno": number, "winerror": native, "origin": origin,
                      "exception_class": exception_class if exception_class in allowed else "OSError",
                      "exit_code": code(getattr(error, "returncode", None))}),
          file=sys.stderr, flush=True)
    raise SystemExit(1)
"""


class _NativeChildFailure(OSError):
    """Transport only numeric facts from the fixed owned venv child."""

    def __init__(
        self, code: int | None, native: int | None, origin: str, exit_code: int | None,
        exception_class: str,
    ) -> None:
        super().__init__("owned-installation-child-failed")
        self.errno = code
        if native is not None:
            self.winerror = native
        self._storage_origin = origin
        self.child_exit_code = exit_code
        self.child_exception_class = exception_class


class _DocumentationChildFailure(OSError):
    """Keep bounded strict-build diagnostics within the reviewed owned output."""

    def __init__(self, exit_code: int, stdout: bytes, stderr: bytes) -> None:
        super().__init__("documentation-strict-child-failed")
        self.exit_code, self.stdout, self.stderr = exit_code, stdout, stderr


def _run(
    command: tuple[str, ...], cwd: Path, clock: c.ClockPort,
    cancel: c.CancelPort, deadline: float, *, accepted: tuple[int, ...] = (0,),
    _documentation: _DocumentationPlan | None = None,
    _source_guard: Callable[[], None] | None = None,
) -> bytes:
    """Join bounded output readers and terminate only this owned process group."""
    if cancel.is_cancelled():
        raise InterruptedError()
    if c.finite(clock.monotonic()) >= deadline:
        raise TimeoutError()
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() in ("SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC")}
    environment.update({
        "PATH": str(Path(command[0]).parent), "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1", "PIP_NO_INDEX": "1",
        "PIP_CONFIG_FILE": os.devnull, "ANSIBLE_GALAXY_SERVER_LIST": "",
        "TEMP": str(cwd), "TMP": str(cwd), "TMPDIR": str(cwd),
    })
    if _documentation is not None:
        from ._documentation import _DocumentationPlan

        if (
            type(_documentation) is not _DocumentationPlan or command != _documentation.command
            or cwd != Path(_documentation.output) / "reviewed-source"
        ):
            raise c.ContractError()
        # Only the standalone reviewed docs bridge may consume already installed
        # user-site tooling. Installation children remain isolated/no-user-site.
        environment.pop("PYTHONNOUSERSITE")
        environment["PYTHONUSERBASE"] = _documentation.user_base
        for key in ("USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOME"):
            if key in os.environ:
                environment[key] = os.environ[key]
    job = None
    process: subprocess.Popen[bytes] | _InstallationChild
    close_native_child: Callable[[], None] | None = None
    if os.name == "nt":
        from ._installation_windows import _InstallationChild, _WindowsJob

        if _source_guard is not None:
            _source_guard()
        job = _WindowsJob()
    try:
        with _storage_io("installation", "spawn-process", c.digest((
            str(cwd), command[0],
        ))):
            if _source_guard is not None:
                _source_guard()
            if job is not None:
                process = _InstallationChild(command, cwd, environment)
                close_native_child = process.close
            else:
                process = subprocess.Popen(
                    command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                    start_new_session=True,
                )
    except BaseException as exc:
        if job is not None:
            with teardown(exc):
                job.close()
            if job.handle is not None or job._temporary:
                _retain_cleanup_owner(exc, job)
        raise
    joined = False
    job_closed = False
    closed_pipes: set[str] = set()
    cleanup_deadline: float | None = None

    def cleanup_remaining() -> float:
        nonlocal cleanup_deadline
        now = time.monotonic()
        if cleanup_deadline is None:
            # A teardown self-limit, never an extension of source/operation authority.
            cleanup_deadline = now + 1.0
        return max(0.0, cleanup_deadline - now)

    def join_process() -> None:
        nonlocal joined
        if not joined:
            process.wait(timeout=cleanup_remaining())
            joined = True

    def close_job() -> None:
        nonlocal job_closed
        if job is not None and not job_closed:
            job.close()
            job_closed = job.handle is None and not job._temporary
            if not job_closed:
                raise OSError("installation-job-resources-unreleased")

    def close_pipe(name: str) -> None:
        if name not in closed_pipes:
            index = 0 if name == "stdout" else 1
            if readers[index].is_alive():
                # Buffered close can block on the lock held by a stuck reader.
                raise TimeoutError("installation-pipe-reader-unjoined")
            stream = getattr(process, name)
            if stream is not None:
                stream.close()
            closed_pipes.add(name)

    def close_process_handle() -> None:
        if close_native_child is not None:
            close_native_child()

    output: list[bytes] = []
    documentation_errors: list[bytes] = []
    exceeded = threading.Event()
    read_failed = threading.Event()
    native_diagnostics: list[tuple[int | None, int | None, str, int | None, str]] = []
    diagnostic_child = len(command) == 6 and command[1:5] == ("-I", "-B", "-c", _VENV)

    def read(stream: IO[bytes] | None, save: bool) -> None:
        if stream is None:
            return
        count = 0
        chunks = []
        diagnostic = bytearray()
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                count += len(chunk)
                if count > 1024 * 1024:
                    exceeded.set()
                elif save:
                    chunks.append(chunk)
                elif _documentation is not None:
                    chunks.append(chunk)
                elif diagnostic_child and len(diagnostic) <= 1024:
                    diagnostic.extend(chunk[:1025 - len(diagnostic)])
        except (OSError, ValueError):
            read_failed.set()
        if save:
            output.append(b"".join(chunks))
        elif _documentation is not None:
            documentation_errors.append(b"".join(chunks))
        elif diagnostic_child and len(diagnostic) <= 1024:
            try:
                value = json.loads(diagnostic)
                if type(value) is dict and set(value) == {
                    "schema", "errno", "winerror", "origin", "exit_code", "exception_class",
                } and (
                    value["schema"] == "netops-venv-native-v1"
                    and value["origin"] in ("child", "child-report")
                    and value["exception_class"] in (
                        "OSError", "PermissionError", "FileNotFoundError", "NotADirectoryError",
                        "FileExistsError", "CalledProcessError", "RuntimeError", "ValueError",
                        "ModuleNotFoundError", "ImportError", "LookupError", "TypeError",
                    )
                ) and all(
                    item is None or type(item) is int and 0 <= item <= 0xFFFFFFFF
                    for item in (value["errno"], value["winerror"], value["exit_code"])
                ) and any(value[key] is not None for key in ("errno", "winerror", "exit_code")):
                    native_diagnostics.append((
                        value["errno"], value["winerror"], value["origin"], value["exit_code"],
                        value["exception_class"],
                    ))
            except (ValueError, TypeError):
                pass

    readers = [threading.Thread(target=read, args=(process.stdout, True), daemon=True),
               threading.Thread(target=read, args=(process.stderr, False), daemon=True)]
    stopped = False
    joined_readers: set[int] = set()

    def join_reader(index: int) -> None:
        reader = readers[index]
        if reader.ident is not None and index not in joined_readers:
            reader.join(timeout=cleanup_remaining())
            if reader.is_alive():
                raise TimeoutError("installation-reader-unjoined")
            joined_readers.add(index)

    def stop() -> None:
        nonlocal stopped
        cleanup_remaining()
        try:
            if job is not None and not job_closed:
                job.stop()
            elif job is None and not joined:
                try:
                    getattr(os, "killpg")(process.pid, getattr(signal, "SIGKILL"))
                except ProcessLookupError:
                    pass
            stopped = True
        finally:
            if job is not None:
                # Even a failed explicit termination must attempt kill-on-close.
                with teardown():
                    close_job()
                    stopped = True

    killed = False

    def kill_child() -> None:
        nonlocal killed
        if not killed and not joined:
            process.kill()
            killed = True

    def finalize(*, assignment_failed: bool = False) -> None:
        cleanup_remaining()
        termination = (
            lambda: kill_child() if assignment_failed else None,
            lambda: stop() if not stopped and not joined else None,
            close_job,
        )
        remaining = (
            join_process,
            *(lambda index=index: join_reader(index) for index in range(len(readers))),
            lambda: close_pipe("stdout"), lambda: close_pipe("stderr"),
            close_process_handle,
        )
        # Finish both remaining stop/close attempts before any potentially blocking join.
        try:
            release_all(termination)
        finally:
            try:
                with teardown():
                    release_all(termination)
            finally:
                try:
                    with teardown():
                        release_all(remaining)
                finally:
                    with teardown():
                        release_all(remaining)

    if job is not None:
        try:
            if _source_guard is not None:
                _source_guard()
            if cancel.is_cancelled():
                raise InterruptedError()
            if c.finite(clock.monotonic()) >= deadline:
                raise TimeoutError()
            job.assign(
                process.pid, int(getattr(process, "_handle")),
                int(getattr(process, "thread_handle")), int(getattr(process, "tid")),
            )
        except BaseException as exc:
            with teardown():
                finalize(assignment_failed=True)
            _retain_cleanup_owner(exc, process)
            _retain_cleanup_owner(exc, job)
            raise

    try:
        if _source_guard is not None:
            _source_guard()
        for reader in readers:
            reader.start()
        while True:
            # Keep the POSIX leader unreaped until its owned group is stopped.
            if job is not None:
                finished = process.poll() is not None
            else:
                finished = getattr(os, "waitid")(
                    getattr(os, "P_PID"), process.pid,
                    getattr(os, "WEXITED") | getattr(os, "WNOHANG") | getattr(os, "WNOWAIT"),
                ) is not None
            if finished:
                break
            if exceeded.is_set() or read_failed.is_set():
                raise c.ContractError()
            if cancel.is_cancelled():
                raise InterruptedError()
            if c.finite(clock.monotonic()) >= deadline:
                raise TimeoutError()
            cancel.wait(min(0.05, max(0.0, deadline - c.finite(clock.monotonic()))))
        stop()
        join_process()
        for index in range(len(readers)):
            join_reader(index)
        exit_code = process.returncode
        if exit_code is None:
            raise c.ContractError()
        if (
            _documentation is not None and process.returncode not in accepted
            and not exceeded.is_set() and not read_failed.is_set()
        ):
            raise _DocumentationChildFailure(
                exit_code, output[0] if output else b"",
                documentation_errors[0] if documentation_errors else b"",
            )
        if (
            process.returncode not in accepted and not exceeded.is_set()
            and not read_failed.is_set() and len(native_diagnostics) == 1
        ):
            with _storage_io("installation", "create-environment", c.digest((
                str(cwd), command[-1],
            ))):
                raise _NativeChildFailure(*native_diagnostics[0])
        if process.returncode not in accepted or exceeded.is_set() or read_failed.is_set():
            raise c.ContractError()
        if _source_guard is not None:
            _source_guard()
        return output[0] if output else b""
    except BaseException as exc:
        _retain_cleanup_owner(exc, process)
        if job is not None:
            _retain_cleanup_owner(exc, job)
        raise
    finally:
        try:
            finalize()
        except BaseException as exc:
            _retain_cleanup_owner(exc, process)
            if job is not None:
                _retain_cleanup_owner(exc, job)
            raise
