"""Portable metadata unit dispatch, distinct from actual platform qualification."""

import hashlib
import json
import os
import re
import subprocess
import sys
from contextvars import ContextVar
from pathlib import Path

CONTEXT = ContextVar("nov22_portable_metadata", default=None)
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
    """Register exact test-owned wheels; never import Windows ports on POSIX."""
    if os.name == "nt":
        from tests._nov22_windows_wheel_recipe import register as windows_register

        windows_register(path, digest)
        return
    if os.name != "posix":
        raise RuntimeError("Unsupported metadata unit execution host")
    context = CONTEXT.get()
    if context is None:
        from tests.test_nov22_recursive_extra_independent import source_program

        repo = Path(__file__).resolve().parents[1]
        context = {
            "program": source_program(
                (repo / "netops/dependencies/_installation.py").read_bytes(),
            ),
            "allocated": {},
        }
        CONTEXT.set(context)
    info = path.stat()
    context["allocated"][path] = (info.st_dev, info.st_ino, digest)


def invoke(root, selected):
    """Run identical assertions in a child-local inert profile, not live OS probes."""
    if os.name == "nt":
        from tests._nov22_windows_wheel_recipe import invoke as windows_invoke

        return windows_invoke(root, selected)
    if os.name != "posix":
        raise RuntimeError("Unsupported metadata unit execution host")
    context = CONTEXT.get()
    if context is None:
        raise RuntimeError("Registered unit fixtures required")
    assert len(selected) <= 5
    for item in selected:
        path = Path(item["path"])
        assert path.parent == root and not path.is_symlink()
        info = path.stat()
        assert (info.st_dev, info.st_ino, item["digest"]) == context["allocated"][path]
        data = path.read_bytes()
        assert len(data) <= 4096 and hashlib.sha256(data).hexdigest() == item["digest"]
    program = context["program"]
    shim = root / "platform.py"
    with shim.open("xb") as stream:
        stream.write(INERT_PLATFORM.encode())
    # -I removes checkout/user/PYTHONPATH imports. Installed packaging is a test
    # dependency. Pre-import it explicitly so the literal cannot fall back to pip.
    # The inert module affects this child only; the host platform is never patched.
    # CRLF pins the original sixteen controls' exact protocol bytes on both hosts.
    child_program = chr(10).join((
        "import sys, io",
        "sys.path.insert(0, " + repr(str(root)) + ")",
        "import platform",
        "assert platform.__file__ == " + repr(str(shim)),
        "import packaging",
        "sys.stdout = io.TextIOWrapper(sys.stdout.buffer, newline=chr(13)+chr(10))",
        "program = " + repr(program),
        "exec(compile(program, '<fixed-wheel-program>', 'exec'))",
    ))
    command = (
        sys.executable, "-I", "-B", "-c", child_program, json.dumps(selected),
        json.dumps({"python_version": "3.12.10", "platform": "win32"}),
    )
    # Only true POSIX enters this branch. No Windows Popen or native fallback.
    result = subprocess.run(
        command, cwd=root, env={"PYTHONDONTWRITEBYTECODE": "1"},
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=False,
    )
    assert len(result.stdout) < 8192 and len(result.stderr) < 8192
    stderr = result.stderr.decode()
    lines = re.findall(r'File "<fixed-wheel-program>", line ([0-9]+)', stderr)
    return {
        "exit_code": result.returncode, "stdout": result.stdout.decode(), "stderr": stderr,
        "failure_statement": program.splitlines()[int(lines[-1]) - 1] if lines else "",
        "platform_qualification": False,
        "execution_kind": "POSIX isolated metadata unit with inert Windows marker profile",
    }
