"""Exact criteria-derived oracle for the managed, fresh-history pre-entry cancel."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from contextlib import contextmanager
from uuid import UUID

from netops.ansible import contracts as c
from netops.ansible.artifacts import OwnedRecord
from tests.policy.test_lifecycle_execution import FilePort


def capture_state(path, host, port, runs, effects):
    """Capture all existing bytes and operative facts immediately around restore."""
    return {
        "files": {str(p.relative_to(path)): p.read_bytes() for p in path.rglob("*")
                  if p.is_file()},
        "root": port.read("managed-root").to_bytes(),
        "control": port.read("managed-control").to_bytes(),
        "pointer": c.wire(host.pointer()),
        "pins": c.wire(runs.pins()),
        "effects": copy.deepcopy(effects.calls),
        "writes": copy.deepcopy(port.writes),
    }


@contextmanager
def observe_cas(port):
    """Observe the actual fixture CAS arguments without replacing its behavior."""
    calls = []
    previous = sys.getprofile()

    def observe(frame, event, argument):
        if event == "call" and frame.f_code is FilePort.compare_replace.__code__:
            if frame.f_locals["self"] is port:
                calls.append((
                    frame.f_locals["resource"], frame.f_locals["expected"],
                    frame.f_locals["record"].to_bytes(),
                ))
        if previous is not None:
            previous(frame, event, argument)

    sys.setprofile(observe)
    try:
        yield calls
    finally:
        sys.setprofile(previous)


def assert_exact_cancel(before, after, calls, plan, outcome):
    """Permit precisely one factual event/head pair, never arbitrary history writes."""
    for key in ("root", "control", "pointer", "pins", "effects"):
        assert after[key] == before[key], key
    assert after["writes"][:len(before["writes"])] == before["writes"]
    assert len(after["writes"]) == len(before["writes"]) + 2
    assert len(calls) == 2
    event_id, expected_event, event_bytes = calls[0]
    head_id, expected_head, head_bytes = calls[1]
    prefix = "dependency-outcome-event-"
    assert event_id.startswith(prefix)
    identifier = UUID(event_id[len(prefix):])
    assert identifier.version == 4 and str(identifier) == event_id[len(prefix):]
    assert event_id not in {row[0] for row in before["writes"]}
    assert head_id == "dependency-outcome-" + plan.lifecycle_id
    assert expected_event == expected_head == 0
    root = json.loads(before["root"])
    event = OwnedRecord.from_bytes(event_bytes)
    head = OwnedRecord.from_bytes(head_bytes)
    for record, name, content in ((event, event_id, event_bytes), (head, head_id, head_bytes)):
        assert 0 < len(content) <= 1024 * 1024
        assert record.resource_id == name
        assert record.kind == "checkpoint" and record.revision == 0
        actual = json.loads(record.to_bytes())
        assert set(actual) == set(root)
        for key in set(root) - {"resource_id", "revision", "payload"}:
            assert actual[key] == root[key], key
    assert after["writes"][len(before["writes"]):] == [
        (event_id, 0, 0), (head_id, 0, 0),
    ]
    expected_files = {
        hashlib.sha256(event_id.encode()).hexdigest() + ".json": event_bytes,
        hashlib.sha256(head_id.encode()).hexdigest() + ".json": head_bytes,
    }
    assert set(after["files"]) - set(before["files"]) == set(expected_files)
    assert set(before["files"]) <= set(after["files"])
    for name, content in before["files"].items():
        assert after["files"][name] == content, name
    for name, content in expected_files.items():
        assert name not in before["files"] and after["files"][name] == content
    assert set(event.payload) == {"schema", "outcome", "previous", "previous_digest"}
    assert event.payload["schema"] == "i02-outcome-event-v1"
    assert event.payload["previous"] is event.payload["previous_digest"] is None
    factual = c.wire(outcome)
    assert set(factual) == {
        "installation_id", "plan_id", "kind", "status", "steps", "readiness",
        "candidate_generation_id", "active_generation_id", "previous_generation_id",
        "errors", "cleanup_errors", "pending_actions", "uncertain", "pointer_revision",
        "schema_version", "selected_scope", "original_errors", "remote_state",
    }
    assert c.wire(event.payload["outcome"]) == factual
    assert factual["status"] == "cancelled"
    assert factual["installation_id"] == plan.lifecycle_id
    assert factual["plan_id"] == plan.plan_id
    assert factual["selected_scope"] == {
        "native_capabilities": ["native.stdlib"], "companions": [],
        "enhanced": False, "full_toolkit": False,
    }
    assert factual["candidate_generation_id"] == plan.generation.generation_id
    assert factual["previous_generation_id"] is None
    assert factual["kind"] == "restore" and factual["schema_version"] == "1.0"
    assert factual["active_generation_id"] == before["pointer"]["active_generation_id"]
    assert factual["pointer_revision"] == before["pointer"]["revision"]
    assert factual["uncertain"] is False
    assert factual["cleanup_errors"] == factual["pending_actions"] == []
    assert factual["original_errors"] == [] and factual["remote_state"] == "not-requested"
    assert factual["steps"] == [{
        "occurrence_id": "restore-active-pointer", "step_id": "restore-active-pointer",
        "kind": "restore-active-pointer", "status": "cancelled", "changed": False,
        "error": None,
    }]
    assert factual["readiness"] == {
        "native": "blocked", "companion": "blocked",
        "enhanced": "not-requested", "errors": [],
    }
    assert factual["errors"] == [{
        "category": "precondition", "reason": "cancelled", "stage": "finalize",
        "target_id": None, "step_id": "restore-active-pointer", "retryable": False,
        "detail": "", "next_action":
        "Admission remains stopped; inspect actual pointer and review new restore consent.",
    }]
    assert set(head.payload) == {"schema", "latest", "latest_digest"}
    assert head.payload["schema"] == "i02-outcome-head-v1"
    assert head.payload["latest"] == event_id
    assert head.payload["latest_digest"] == c.digest(event.payload)
