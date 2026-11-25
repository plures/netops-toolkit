"""Dedicated sealed native recipe; never a general harness or whole-suite runner."""

import ast
import hashlib
import importlib
import json
import os
import sys
import time
import traceback
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
RUN = REPO / (
    ".sdlc/runs/it-s-now-time-to-implement-full-ansible-and-mole-"
    "20261104-225210156-fb1f9495"
)
# Prospective names selected in authored recipe BEFORE any product plan/grant.
# Never probe/reuse the old held namespace or rewrite after grants.
ROOT = REPO / ".sdlc/n22ccf1122t"
LAUNCH = REPO / ".sdlc/n22cclf1122t"
RAW = RUN / "nov22-context-consuming-tester-FOCUSED-RAW.jsonl"
RESULT = RUN / "nov22-context-consuming-tester-FOCUSED-RESULT.json"
PARENT_RAW = RUN / "nov22-context-consuming-tester-FOCUSED-PARENT-RAW.json"
sys.dont_write_bytecode = True


def digest(path):
    """Seal exact known bytes, never scan a directory."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_once(path, value):
    """Retain a private deliverable without overwriting existing evidence."""
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)


def raw_event(value):
    """Immediately retain exact private states, never print raw diagnostics."""
    with RAW.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(), "pid": os.getpid(),
            "cwd": str(Path.cwd()), **value,
        }) + "\n")


def guards():
    """Install rejection-only child baseline before production/platform imports."""
    import platform
    import subprocess

    def forbidden(*args, **kwargs):
        raw_event({"event": "forbidden-platform-or-process-attempt"})
        raise RuntimeError("Unauthorized implicit platform/process query blocked")

    # No synthetic platform return values. These are rejection fences, not
    # factual substitutes; a baseline query is an ERROR, never a pass.
    for name in (
        "machine", "uname", "system", "release", "version", "win32_ver",
        "_wmi_query", "_syscmd_ver", "_syscmd_file",
    ):
        if hasattr(platform, name):
            setattr(platform, name, forbidden)
    subprocess.Popen = forbidden
    os.system = forbidden
    import _winapi

    _winapi.CreateProcess = forbidden

    def audit(event, args):
        if event in (
            "subprocess.Popen", "os.system", "os.posix_spawn", "os.exec",
            "socket.__new__", "socket.connect", "socket.bind", "os.kill",
        ):
            raw_event({"event": "forbidden-audit-attempt", "audit_event": event})
            raise RuntimeError("Unauthorized effect blocked at baseline")

    sys.addaudithook(audit)


class Patches:
    """Unit external SOURCE ports only, with deterministic restoration."""

    def __init__(self):
        self.stack = ExitStack()

    def __enter__(self):
        self.stack.__enter__()
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def setattr(self, target, name, value):
        self.stack.enter_context(patch.object(target, name, value))


def exact_functions(path, names, namespace):
    """Compile original unchanged bodies, omitting unrelated pytest collection."""
    tree = ast.parse(path.read_bytes())
    nodes = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
    ]
    assert {node.name for node in nodes} == names
    assert all(not getattr(node, "decorator_list", []) for node in nodes)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)


def worker():
    """Execute exact independent controls only after parent seal admission."""
    guards()
    sys.path.insert(0, str(REPO))
    # Existing compiler's permitted offline packaging library only. -S avoids
    # site hooks; no install/download/cache/config/environment mutation.
    vendor = Path(sys.base_prefix) / "Lib/site-packages/pip/_vendor"
    sys.path.insert(0, str(vendor))
    admission = json.loads((RUN / "nov22-context-consuming-tester-ADMISSION.json").read_bytes())
    revision = json.loads((RUN / "nov22-context-consuming-tester-FOCUSED-ADMISSION.json").read_bytes())
    admission["seals"].update(revision["seal_overrides"])
    before = {path: digest(REPO / path) for path in admission["seals"]}
    assert before == admission["seals"]
    api = {}
    for key, module in (
        ("contracts", "netops.ansible.contracts"),
        ("authorization", "netops.ansible.policy.authorization"),
        ("storage", "netops.ansible.artifact_platform"),
        ("artifacts", "netops.ansible.artifacts"),
        ("installation", "netops.dependencies._installation"),
        ("managed", "netops.dependencies._managed"),
        ("assets", "netops.dependencies._assets"),
        ("process", "netops.dependencies._installation_process"),
        ("setup", "netops.dependencies._setup"),
        ("metadata", "netops.dependencies._guided_metadata"),
        ("guided", "netops.dependencies._guided"),
        ("service", "netops.dependencies.service"),
        ("owned_build", "netops.dependencies._owned_build"),
        ("owned_source", "netops.dependencies._owned_source"),
    ):
        api[key] = importlib.import_module(module)
    storage = api["storage"]
    # Exclusive original native protection; no adoption or ACL repair.
    storage.windows().create_private_directory(str(ROOT))
    raw_event({"event": "fresh-root-before-plans-grants", "root": str(ROOT)})
    native = storage._WINDOWS
    assert native is not None
    original_kernel = native.kernel
    original_create = original_kernel.CreateFileW
    kernel_names = (
        "CreateFileW", "CloseHandle", "FlushFileBuffers", "GetFileInformationByHandle",
        "CreateDirectoryW", "DeleteFileW", "RemoveDirectoryW", "MoveFileExW",
        "GetFileAttributesW", "SetFileInformationByHandle", "GetCurrentProcess",
        "LocalFree", "ReadFile", "WriteFile", "LockFileEx",
    )
    functions = {name: getattr(original_kernel, name) for name in kernel_names}
    import ctypes

    def createfile(*operands):
        path = Path(operands[0])
        assert path == ROOT or ROOT in path.parents or path in ROOT.parents
        handle = original_create(*operands)
        code = ctypes.get_last_error()  # capture immediately, before another native API
        security = operands[3]
        security_fact = None if security is None else {
            "type": type(security).__name__,
            "address": ctypes.cast(security, ctypes.c_void_p).value,
            "length": security._obj.length,
            "descriptor": security._obj.descriptor,
            "inherit": security._obj.inherit,
        }
        raw_event({
            "event": "native-createfile",
            "operands": [*operands[:3], security_fact, *operands[4:]],
            "raw_handle": handle, "immediate_error": code,
            "known_handles": {str(key): str(value) for key, value in native._paths.items()},
        })
        ctypes.set_last_error(code)
        return handle

    def information(handle, pointer):
        returned = functions["GetFileInformationByHandle"](handle, pointer)
        code = ctypes.get_last_error()
        facts = pointer._obj
        raw_event({
            "event": "native-handle-identity", "handle": handle,
            "returned": bool(returned), "immediate_error": code,
            "volume": facts.volume, "file_id": facts.index_high << 32 | facts.index_low,
            "attributes": facts.attributes, "links": facts.links,
        })
        ctypes.set_last_error(code)
        return returned

    def set_information(handle, kind, pointer, size):
        assert handle in native._paths
        known_path = Path(native._paths[handle])
        assert known_path == ROOT or ROOT in known_path.parents
        assert kind in (3, 4) and 0 < size <= 4096
        facts = pointer._obj
        before = {
            "event": "native-set-information-before", "handle": handle,
            "raw_source_path": str(known_path), "kind": kind, "size": size,
        }
        if kind == 3:
            if known_path.name.startswith("managed-pending-"):
                assert facts.replace == 0  # original candidate no-replace invariant
            before.update(
                replace=facts.replace, root_handle=facts.parent,
                name_bytes=facts.length, raw_name_words=list(facts.name),
            )
        raw_event(before)
        returned = functions["SetFileInformationByHandle"](handle, kind, pointer, size)
        code = ctypes.get_last_error()
        raw_event({
            "event": "native-set-information-after", "handle": handle,
            "kind": kind, "returned": bool(returned), "immediate_error": code,
        })
        ctypes.set_last_error(code)
        return returned

    native.kernel = SimpleNamespace(**{
        **functions, "CreateFileW": createfile,
        "GetFileInformationByHandle": information,
        "SetFileInformationByHandle": set_information,
    })
    namespace = {
        "hashlib": hashlib, "io": __import__("io"), "os": os, "sys": sys,
        "zipfile": __import__("zipfile"), "Path": Path, "uuid4": __import__("uuid").uuid4,
        "replace": __import__("dataclasses").replace,
        "QUALIFIED": "1" * 64, "c": api["contracts"], "storage": storage,
        "_setup": api["setup"], "build": api["owned_build"],
        "_root": api["artifacts"]._root, "_write_file": api["artifacts"]._write_file,
        "DependencyRegistry": api["service"].DependencyRegistry,
        "_owned_build": api["owned_build"], "_OwnedSource": api["owned_source"]._OwnedSource,
        "_InstallationSpec": api["installation"]._InstallationSpec,
        "_Wheel": api["installation"]._Wheel,
        "ManagedMember": api["managed"].ManagedMember,
        "ManagedGenerationManifest": api["managed"].ManagedGenerationManifest,
    }

    class Cancel:
        def is_cancelled(self):
            return False

    namespace["Cancel"] = Cancel
    exact_functions(REPO / "tests/test_owned_source_author.py", {"Clock", "build_case"}, namespace)
    exact_functions(
        REPO / "tests/test_nov21_bootstrap_layout_postfix_independent.py",
        {"producer"}, namespace,
    )
    api.update(
        original_producer=namespace["producer"], source_clock=namespace["Clock"],
        cancel=Cancel, patches=Patches, observations=[],
    )
    from tests import _nov22_context_consuming_controls as controls

    results = []
    try:
        control_index = 0
        for name in sorted(vars(controls)):
            test = getattr(controls, name)
            if not name.startswith("test_") or not callable(test):
                continue
            if name in (
                "test_original_guarded_intact_native_publication",
                "test_original_guarded_postpublication_context_drift_before_installer",
            ):
                # These remain REQUIRED and BLOCKED by the separate unchanged
                # native-bound attempt. This is not native retry, success,
                # acceptance, deferral or a weaker original-pair replacement.
                continue
            control_index += 1
            root = ROOT / ("c" + str(control_index).zfill(2))
            # Short namespace/leaf selected before each control's plans/grants.
            native.create_private_directory(str(root))
            observation_start = len(api["observations"])
            try:
                test(api, root)
            except AssertionError as error:
                raw_event({
                    "event": "assertion-failure", "test": name, "error": repr(error),
                    "traceback": traceback.format_exc(), "exact_error": str(error),
                })
                result = {"test": name, "result": "fail", "error_type": type(error).__name__}
            except Exception as error:
                raw_event({
                    "event": "route-error", "test": name, "error": repr(error),
                    "traceback": traceback.format_exc(), "exact_error": str(error),
                    "errno": getattr(error, "errno", None),
                    "winerror": getattr(error, "winerror", None),
                    "filename": getattr(error, "filename", None),
                })
                result = {"test": name, "result": "error", "error_type": type(error).__name__}
            else:
                result = {"test": name, "result": "pass"}
            result["observations"] = api["observations"][observation_start:]
            results.append(result)
            raw_event({"event": "completed-control", "test": name, "result": result["result"]})
    finally:
        native.kernel = original_kernel
        raw_event({
            "event": "worker-final-owned-state",
            "known_handles": {str(key): str(value) for key, value in native._paths.items()},
            "old_held_namespace_probed": False,
            "cleanup": "Owned fixture files retained privately; no recursive cleanup/adoption",
        })
    after = {path: digest(REPO / path) for path in before}
    report = {
        "type": "PRIVATE_FOCUSED_ROUTE_RESULT", "results": results,
        "unique": len(results), "pass": sum(item["result"] == "pass" for item in results),
        "fail": sum(item["result"] == "fail" for item in results),
        "error": sum(item["result"] == "error" for item in results),
        "before": before, "after": after, "source_stable": before == after,
        "native_handles_remaining": len(native._paths),
        "qualification": "Actual factual context, upstream baseline fence and actual consumers with SOURCE-port runner units. Required original native pair remains blocked after separate r3 timeout; no authentic artifact/admitted-install qualification.",
        "catalogue_unique": 14, "required_native_pair_blocked": 2,
        "interface_ref": admission["interface_ref"],
        "raw_ref": RAW.name,
        "native_task": None, "native_attempt": None, "native_fence": None, "native_lease": None,
    }
    write_once(RESULT, report)
    assert before == after and not native._paths
    print(json.dumps({key: report[key] for key in ("unique", "pass", "fail", "error", "source_stable")}))
    return 1 if report["fail"] or report["error"] else 0


def parent():
    """Admit one exact owned native child, retaining all operands and hp/ht."""
    sys.path.insert(0, str(REPO))
    from tests import _nov22_windows_wheel_recipe as native_recipe

    admission = json.loads((RUN / "nov22-context-consuming-tester-ADMISSION.json").read_bytes())
    revision = json.loads((RUN / "nov22-context-consuming-tester-FOCUSED-ADMISSION.json").read_bytes())
    admission["seals"].update(revision["seal_overrides"])
    assert {path: digest(REPO / path) for path in admission["seals"]} == admission["seals"]
    assert digest(native_recipe.IMAGE) == native_recipe.IMAGE_HASH
    assert not ROOT.exists() and not LAUNCH.exists()
    assert not RAW.exists() and not RESULT.exists() and not PARENT_RAW.exists()
    LAUNCH.mkdir()
    command = (
        str(native_recipe.IMAGE), "-I", "-S", "-B", str(Path(__file__).resolve()), "worker",
    )
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
    # Original Path.home rejection needs the actual caller's home fact. Copy
    # only this existing value into this exact child's predeclared environment;
    # never invent HOME/USERPROFILE from the task root or change global config.
    assert os.environ.get("USERPROFILE")
    environment["USERPROFILE"] = os.environ["USERPROFILE"]
    environment.update(TEMP=str(LAUNCH), TMP=str(LAUNCH), PYTHONDONTWRITEBYTECODE="1")
    creation = {}
    native, native_hash = native_recipe.native_classes(
        REPO, creation, (command, LAUNCH, environment),
    )
    job, child = native["_WindowsJob"](), None
    record = {
        "command": command, "cwd": str(LAUNCH), "environment": environment,
        "native_source_sha256": native_hash, "image_sha256": digest(native_recipe.IMAGE),
        "actual_full_native_creation": creation,
    }
    started = time.monotonic()
    try:
        child = native["_InstallationChild"](command, LAUNCH, environment)
        record.update(pid=child.pid, tid=child.tid, hp=child._handle, ht=child.thread_handle)
        write_once(PARENT_RAW, record)  # immediately retain exact owned raw handles
        job.assign(child.pid, child._handle, child.thread_handle, child.tid)
        record["exit_code"] = child.wait(timeout=60.0)
        record.update(
            stdout=child.stdout.read(8192).decode(), stderr=child.stderr.read(8192).decode(),
        )
    finally:
        if child is not None:
            if not child._joined:
                child.kill()  # exact newly created, captured owned child only
                child.wait(timeout=1.0)
            child.close()
            child.stdout.close()
            child.stderr.close()
            record.update(
                joined=child._joined, hp_after=child._handle, ht_after=child.thread_handle,
                stdout_closed=child.stdout.closed, stderr_closed=child.stderr.closed,
            )
        job.close()
        record.update(job_after=job.handle, seconds=time.monotonic() - started)
        # Updating this exact private deliverable is not output redirection.
        with PARENT_RAW.open("w", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2)
    print(json.dumps({
        "owned_child_exit": record.get("exit_code"),
        "joined": record.get("joined"), "raw_ref": PARENT_RAW.name,
    }))
    return record.get("exit_code", 1)


if __name__ == "__main__":
    raise SystemExit(worker() if sys.argv[1:] == ["worker"] else parent())
