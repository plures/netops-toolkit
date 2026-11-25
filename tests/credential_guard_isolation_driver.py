"""Exercise actual collection, fixtures, failing calls and cleanup in one pytest process."""

import hashlib
import importlib
import inspect
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

bastion = importlib.import_module("netops.core.bastion")

PORTS = ((socket, "socket"), (subprocess, "Popen"), (bastion, "active_bastion"))
ORIGINALS = tuple(getattr(module, name) for module, name in PORTS)


def identities():
    return [
        {
            "port": module.__name__ + "." + name,
            "id": id(getattr(module, name)),
            "original_id": id(original),
            "is_original": getattr(module, name) is original,
            "original_source_sha256": hashlib.sha256(
                inspect.getsource(original).encode("utf-8")
            ).hexdigest(),
        }
        for (module, name), original in zip(PORTS, ORIGINALS)
    ]


class Proof:
    def __init__(self, inject_failure):
        self.inject_failure = inject_failure
        self.events = []
        self.restoration_errors = []
        self.bound_calls = 0
        self.call_reports = []

    def pytest_configure(self, config):
        config._credential_guard_originals = ORIGINALS

    def pytest_collection_finish(self, session):
        self.events.append({
            "event": "collection",
            "ports": identities(),
            "fixtures": [
                {"nodeid": item.nodeid, "names": item.fixturenames}
                for item in session.items
            ],
        })
        if any(not row["is_original"] for row in identities()):
            self.restoration_errors.append("collection-mutated-original-ports")

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_call(self, item):
        if "credential_guard_isolation_cases.py" in item.nodeid:
            return
        self.bound_calls += 1
        rows = identities()
        assert all(not row["is_original"] for row in rows)
        messages = []
        for module, name in PORTS:
            with pytest.raises(pytest.fail.Exception) as caught:
                getattr(module, name)()
            messages.append(str(caught.value))
        assert all("composition test attempted" in message
                   or "credential unit test attempted" in message for message in messages)
        self.events.append({"event": "bound_guard", "nodeid": item.nodeid,
                            "ports": rows, "messages": messages})
        if self.inject_failure:
            raise RuntimeError("intentional-isolation-call-failure")

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_runtest_teardown(self, item):
        yield
        rows = identities()
        self.events.append({"event": "after_teardown", "nodeid": item.nodeid, "ports": rows})
        if any(not row["is_original"] for row in rows):
            self.restoration_errors.append("teardown:" + item.nodeid)

    def pytest_unconfigure(self, config):
        rows = identities()
        self.events.append({"event": "unconfigure", "ports": rows})
        if any(not row["is_original"] for row in rows):
            self.restoration_errors.append("unconfigure")

    def pytest_runtest_logreport(self, report):
        if report.when == "call":
            self.call_reports.append({"nodeid": report.nodeid, "outcome": report.outcome})


def main():
    mode, destination, basetemp = sys.argv[1:4]
    proof = Proof(mode == "exception")
    composition = str(ROOT / "tests" / "test_credential_composition.py")
    bridge = str(ROOT / "tests" / "test_credential_admission_bridge.py")
    scoped = str(ROOT / "tests" / "test_scoped_credentials.py")
    unrelated = str(ROOT / "tests" / "credential_guard_isolation_cases.py")
    args = [
        unrelated + "::test_before_credential_modules",
        composition + "::test_original_deadline_cannot_be_extended_by_new_scope",
        bridge + "::test_bridge_expiry_retires_authority_before_scope_projection[False-admit]",
        scoped + "::test_private_delivery_is_spent_before_host_guard_release",
        unrelated + "::test_after_credential_modules",
        "--no-cov", "-p", "no:cacheprovider", "--tb=short", "-q",
        "--basetemp=" + basetemp,
    ]
    if mode == "collection":
        args += ["--collect-only"]
    code = pytest.main(args, plugins=[proof])
    expected = 1 if mode == "exception" else 0
    unrelated_reports = [row for row in proof.call_reports
                         if "credential_guard_isolation_cases.py" in row["nodeid"]]
    bound_reports = [row for row in proof.call_reports
                     if "credential_guard_isolation_cases.py" not in row["nodeid"]]
    expected_bound_outcome = "failed" if mode == "exception" else "passed"
    outcomes_correct = (
        mode == "collection"
        or (len(unrelated_reports) == 2
            and all(row["outcome"] == "passed" for row in unrelated_reports)
            and len(bound_reports) == 3
            and all(row["outcome"] == expected_bound_outcome for row in bound_reports))
    )
    report = {
        "mode": mode, "pytest_exit_code": int(code), "expected_exit_code": expected,
        "bound_calls": proof.bound_calls, "events": proof.events,
        "restoration_errors": proof.restoration_errors, "final_ports": identities(),
        "call_reports": proof.call_reports, "outcomes_correct": outcomes_correct,
        "passed": int(code) == expected and not proof.restoration_errors
        and outcomes_correct
        and all(row["is_original"] for row in identities())
        and (mode == "collection" or proof.bound_calls == 3),
    }
    Path(destination).write_bytes((json.dumps(report, indent=2) + "\n").encode("utf-8"))
    print(json.dumps({key: report[key] for key in (
        "mode", "pytest_exit_code", "expected_exit_code", "bound_calls",
        "restoration_errors", "passed",
    )}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
