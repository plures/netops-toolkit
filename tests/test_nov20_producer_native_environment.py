"""Actual owned native helper environment attribution, not Windows Ansible proof."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sys
from ctypes import wintypes as w
from pathlib import Path

from netops.ansible import _windows_job as win


def test_ac006_native_source_environment_and_actual_runtime_origin_are_separate(
    tmp_path, monkeypatch, record_property,
):
    """Observe the real source environment and child; never delete runtime keys."""
    assert os.name == "nt"
    import _winapi

    sentinel = "nov20-producer-proof-ambient-secret-do-not-inherit"
    canary = tmp_path / "ambient-python-path"
    canary.mkdir()
    monkeypatch.setenv("PYTHONUSERBASE", sentinel)
    monkeypatch.setenv("PYTHONPATH", str(canary))
    monkeypatch.setenv("NETOPS_PRODUCER_ENV_SECRET", sentinel)
    original = _winapi.CreateProcess
    environments = []

    def observe(*args):
        # Native CreateProcess parameter 7 is the environment mapping.
        environments.append(dict(args[6]))
        return original(*args)

    monkeypatch.setattr(_winapi, "CreateProcess", observe)
    helper = (
        "import json,os,sys;"
        "print(json.dumps({'pid':os.getpid(),'keys':sorted(os.environ),"
        "'sentinel_leak':any('nov20-producer-proof-ambient-secret-do-not-inherit' in v "
        "for v in os.environ.values()),"
        "'userbase_digest':__import__('hashlib').sha256("
        "os.environ.get('PYTHONUSERBASE','').encode()).hexdigest(),"
        "'isolated':sys.flags.isolated,'no_user_site':sys.flags.no_user_site,"
        "'path':sys.path}),flush=True);sys.stdin.readline()"
    )
    python = str(Path(sys.base_prefix) / "python.exe")
    process = win._start_job_process(
        python, (python, "-I", "-u", "-c", helper), str(tmp_path),
    )
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.GetHandleInformation.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
    api.GetHandleInformation.restype = w.BOOL
    owned = (process._job, process._process)
    try:
        observed = json.loads(process.stdout.readline())
        assert observed["pid"] == process.pid
        assert observed["sentinel_leak"] is False
        assert observed["isolated"] == observed["no_user_site"] == 1
        assert str(canary) not in observed["path"]
        assert len(environments) == 1
        source_environment = environments[0]
        assert set(source_environment) == {"SystemRoot", "LANG", "PYTHONNOUSERSITE"}
        assert source_environment["LANG"] == "C.UTF-8"
        assert source_environment["PYTHONNOUSERSITE"] == "1"
        assert sentinel not in json.dumps(source_environment)
        assert "PYTHONPATH" not in observed["keys"]
        assert "NETOPS_PRODUCER_ENV_SECRET" not in observed["keys"]
        assert process.close(2.0)
        flags = w.DWORD()
        assert all(not api.GetHandleInformation(handle, ctypes.byref(flags)) for handle in owned)
        assert process._job == process._process == 0
        record_property("native_environment_attribution", json.dumps({
            "actual_native_process": True,
            "source_environment_keys": sorted(source_environment),
            "runtime_environment_keys": observed["keys"],
            "runtime_added_keys": sorted(set(observed["keys"]) - set(source_environment)),
            "runtime_userbase_digest": observed["userbase_digest"],
            "source_module_sha256": hashlib.sha256(Path(win.__file__).read_bytes()).hexdigest(),
            "interpreter_path_sha256": hashlib.sha256(python.encode()).hexdigest(),
            "ambient_sentinel_absent": True,
            "exact_job_and_process_handles_closed": True,
            "runtime_keys_deleted": False,
            "cold_count_assertion_waived": False,
            "wsl_or_ansible_qualification": False,
        }))
    finally:
        if not process._closed:
            process.close(2.0)
        process.stdout.close()
        process.stdin.close()
