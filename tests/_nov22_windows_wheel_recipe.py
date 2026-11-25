"""Exact fixed wheel recipe; no global patching or general runner admission."""

import ast
import ctypes
import hashlib
import importlib
import json
import os
import re
import subprocess
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from ctypes import wintypes
from functools import partial
from pathlib import Path
from types import SimpleNamespace

IMAGE = Path(
    "C:/Program Files/WindowsApps/"
    "PythonSoftwareFoundation.Python.3.12_3.12.2800.0_x64__qbz5n2kfra8p0/python3.12.exe"
)
IMAGE_HASH = "5365b422ee178f691988eb937b7abca5f48910b148f76fcce6dbaf5585c948d0"
VENDOR = IMAGE.parent / "Lib/site-packages/pip/_vendor"
CONTEXT = ContextVar("nov22_fixed_recipe", default=None)
INERT_PLATFORM = """\
def system(): return "Windows"
def machine(): return "AMD64"
def release(): return "11"
def version(): return "fixed-inert-profile"
def python_version(): return "3.12.10"
def python_version_tuple(): return ("3", "12", "10")
def python_implementation(): return "CPython"
"""


def register(path, digest):
    """Register only the exact wheel just created exclusively by this test."""
    context = CONTEXT.get()
    if context is None:
        from tests.test_nov22_recursive_extra_independent import source_program

        repo = Path(__file__).resolve().parents[1]
        context = {"repo": repo, "program": source_program(
            (repo / "netops/dependencies/_installation.py").read_bytes()),
            "roots": set(), "allocated": {}, "receipts": []}
        CONTEXT.set(context)
    root = path.parent
    context["roots"].add(root)
    info = path.stat()
    context["allocated"].setdefault(root, {})[path] = (info.st_dev, info.st_ino, digest)


@contextmanager
def strict_teardown(primary=None):
    """Never turn a native cleanup failure into success in this fixed test."""
    yield


def strict_release(actions):
    """Attempt exact known releases and retain every failed release."""
    errors = []
    for action in actions:
        try:
            action()
        except BaseException as error:
            errors.append(error)
    if errors:
        raise errors[0]


def retain(error, owner):
    """Keep exact cleanup owner reachable when native release fails."""
    error.fixed_owner = owner


def native_classes(repo, creation=None, expected=None):
    """Compile unchanged current captured-child classes, not a global import."""
    path = repo / "netops/dependencies/_installation_windows.py"
    raw = path.read_bytes()
    text = raw.decode()
    assert "Toolhelp" not in text and "Thread32" not in text
    names = {"_Basic", "_IO", "_Extended", "_InstallationChild", "_WindowsJob"}
    nodes = [node for node in ast.parse(text).body
             if isinstance(node, ast.ClassDef) and node.name in names]
    assert {node.name for node in nodes} == names
    namespace = {
        "ctypes": ctypes, "importlib": importlib, "os": os, "subprocess": subprocess,
        "w": wintypes, "partial": partial, "Path": Path, "SimpleNamespace": SimpleNamespace,
        "cast": lambda kind, value: value, "release_all": strict_release,
        "teardown": strict_teardown, "_retain_cleanup_owner": retain,
    }
    if creation is not None:
        assert expected is not None
        owner = threading.get_ident()
        api = importlib.import_module("_winapi")
        allocated = set()
        consumed = False

        def duplicate(*operands):
            assert threading.get_ident() == owner
            current = api.GetCurrentProcess()
            assert len(operands) == 6
            assert operands[0] == operands[2] == current
            assert operands[3:] == (0, True, api.DUPLICATE_SAME_ACCESS)
            handle = api.DuplicateHandle(*operands)
            allocated.add(int(handle))
            creation.setdefault("duplicates", []).append({
                "operands": list(operands), "returned_handle": int(handle),
            })
            return handle

        def create(*operands):
            nonlocal consumed
            assert threading.get_ident() == owner and not consumed
            assert len(operands) == 9
            command, cwd, environment = expected
            assert operands[:6] == (
                command[0], subprocess.list2cmdline(command), None, None, True, 4,
            )
            assert operands[6] == environment and operands[7] == str(cwd)
            startup = operands[8]
            handles = [startup.hStdInput, startup.hStdOutput, startup.hStdError]
            assert len(set(handles)) == 3 and set(handles) == allocated
            assert startup.dwFlags == subprocess.STARTF_USESTDHANDLES
            assert startup.wShowWindow == 0
            assert startup.lpAttributeList == {"handle_list": handles}
            creation.update({
                "owner_thread": owner, "application": operands[0],
                "command": operands[1], "process_security": operands[2],
                "thread_security": operands[3], "inherit": operands[4], "flags": operands[5],
                "environment": operands[6], "cwd": operands[7],
                "startup": {"flags": startup.dwFlags, "show_window": startup.wShowWindow,
                            "stdin": handles[0], "stdout": handles[1], "stderr": handles[2],
                            "handle_list": handles},
            })
            consumed = True
            returned = api.CreateProcess(*operands)
            creation["returned"] = list(returned)
            creation["one_use_consumed"] = True
            return returned

        proxy = SimpleNamespace(**{
            name: getattr(api, name) for name in (
                "GetCurrentProcess", "DUPLICATE_SAME_ACCESS", "CloseHandle",
                "WaitForSingleObject", "GetExitCodeProcess", "TerminateProcess",
            )
        }, DuplicateHandle=duplicate, CreateProcess=create)
        namespace["importlib"] = SimpleNamespace(
            import_module=lambda name: proxy if name == "_winapi"
            else importlib.import_module(name),
        )
    module = ast.Module(body=[ast.ImportFrom(
        module="__future__", names=[ast.alias(name="annotations")], level=0,
    ), *nodes], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(path), "exec"), namespace)
    return namespace, hashlib.sha256(raw).hexdigest()


def invoke(root, selected):
    """Execute only the fixed current/mutant metadata program and exact wheels."""
    context = CONTEXT.get()
    if context is None:
        raise RuntimeError("Dedicated sealed fixed recipe context required; no general dispatch")
    assert root in context["roots"]
    assert len(selected) <= 5
    for item in selected:
        path = Path(item["path"])
        assert path in context["allocated"][root]
        assert path.parent == root and not path.is_symlink()
        info = path.stat()
        assert (info.st_dev, info.st_ino, item["digest"]) == context["allocated"][root][path]
        data = path.read_bytes()
        assert len(data) <= 4096 and hashlib.sha256(data).hexdigest() == item["digest"]
    assert hashlib.sha256(IMAGE.read_bytes()).hexdigest() == IMAGE_HASH
    program = context["program"]
    shim = root / "platform.py"
    with shim.open("xb") as stream:
        stream.write(INERT_PLATFORM.encode())
    prefix = (
        "import sys; assert sys.platform == 'win32'; sys.path.insert(0, "
        + repr(str(VENDOR)) + "); sys.path.insert(0, " + repr(str(root)) + ")" + chr(10)
    )
    imports_path = root / "fixed-child-imports.json"
    child_program = prefix + (
        "program = " + repr(program) + chr(10)
        + "try:" + chr(10)
        + "    exec(compile(program, '<fixed-wheel-program>', 'exec'))" + chr(10)
        + "finally:" + chr(10)
        + "    import hashlib, json, pathlib" + chr(10)
        + "    origins = {n: {'path': m.__file__, 'sha256': "
        + "hashlib.sha256(pathlib.Path(m.__file__).read_bytes()).hexdigest()} "
        + "for n, m in tuple(sys.modules.items()) "
        + "if getattr(m, '__file__', None) and pathlib.Path(m.__file__).is_file()}" + chr(10)
        + "    with open(" + repr(str(imports_path)) + ", 'x') as proof:" + chr(10)
        + "        json.dump({'program_sha256': hashlib.sha256(program.encode()).hexdigest(), "
        + "'origins': origins}, proof)" + chr(10)
    )
    command = (str(IMAGE), "-I", "-S", "-B", "-c", child_program,
               json.dumps(selected), json.dumps({"python_version": "3.12.10", "platform": "win32"}))
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR")
                   if key in os.environ}
    environment.update(TEMP=str(root), TMP=str(root), PYTHONDONTWRITEBYTECODE="1",
                       PYTHONNOUSERSITE="1", PIP_NO_INDEX="1")
    creation = {}
    native, native_hash = native_classes(context["repo"], creation, (command, root, environment))
    job = native["_WindowsJob"]()
    child = None
    receipt = {"command_sha256": hashlib.sha256(json.dumps(command).encode()).hexdigest(),
               "cwd": str(root), "image_sha256": IMAGE_HASH, "native_source_sha256": native_hash,
               "program_sha256": hashlib.sha256(program.encode()).hexdigest(),
               "inert_platform_sha256": hashlib.sha256(shim.read_bytes()).hexdigest(),
               "platform_qualification": False,
               "actual_native_creation": creation,
               "fixture_descriptors": selected, "environment": environment,
               "native_fixed_operands": {
                   "process_security": None, "thread_security": None, "inherit": True,
                   "flags": 4, "startup_flags": subprocess.STARTF_USESTDHANDLES,
                   "handle_list": "only three DuplicateHandle objects allocated by this child",
               }}
    started = time.monotonic()
    try:
        child = native["_InstallationChild"](command, root, environment)
        receipt.update(pid=child.pid, tid=child.tid, hp=child._handle, ht=child.thread_handle,
                       temporary_after_creation=list(child._temporary),
                       descriptors_after_creation=list(child._descriptors))
        job.assign(child.pid, child._handle, child.thread_handle, child.tid)
        code = child.wait(timeout=10.0)
        stdout, stderr = child.stdout.read(8192), child.stderr.read(8192)
        assert len(stdout) < 8192 and len(stderr) < 8192
        receipt.update(exit_code=code, stdout=stdout.decode(), stderr=stderr.decode())
        lines = re.findall(r'File "<fixed-wheel-program>", line ([0-9]+)', receipt["stderr"])
        receipt["failure_statement"] = (
            program.splitlines()[int(lines[-1]) - 1] if lines else ""
        )
        receipt["import_proof"] = json.loads(imports_path.read_bytes())
        assert receipt["import_proof"]["program_sha256"] == receipt["program_sha256"]
        assert receipt["import_proof"]["origins"]["platform"]["path"] == str(shim)
    finally:
        if child is not None:
            if not child._joined:
                child.kill()
                child.wait(timeout=1.0)
            child.close()
            child.stdout.close()
            child.stderr.close()
            receipt.update(joined=child._joined, hp_after=child._handle,
                           ht_after=child.thread_handle, stdout_closed=child.stdout.closed,
                           stderr_closed=child.stderr.closed)
        job.close()
        receipt.update(job_after=job.handle, seconds=time.monotonic() - started)
        context["receipts"].append(receipt)
    return receipt
