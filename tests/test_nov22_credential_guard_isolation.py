"""Failure-sensitive integration regression for exported credential fixture guards."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("mode", ["collection", "normal", "exception"])
def test_actual_pytest_guard_scope_and_exception_cleanup(tmp_path, mode):
    destination = tmp_path / "proof.json"
    result = subprocess.run(
        [sys.executable, "-B", str(Path(__file__).with_name("credential_guard_isolation_driver.py")),
         mode, str(destination), str(tmp_path / "pytest")],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, text=True, check=False, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    proof = json.loads(destination.read_bytes())
    assert proof["passed"]
    assert proof["restoration_errors"] == []
    assert all(port["id"] == port["original_id"] for port in proof["final_ports"])
    if mode != "collection":
        assert proof["bound_calls"] == 3
        assert sum(event["event"] == "after_teardown" for event in proof["events"]) == 5
