"""Task-owned failure-only observations; no tracing or public error changes."""

import hashlib
import json
import os
import secrets
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from netops.ansible.artifact_cleanup import _storage_diagnostics

_ROOT = Path(__file__).resolve().parents[1]
_SALT = secrets.token_bytes(32)
_ALLOWED = frozenset((
    "test_original_producer_drift_stops_real_stage_before_installer",
    "test_new_observation_window_is_owned_root_bound_before_plan",
))
_REASONS = frozenset((
    "protected-storage-native", "protected-storage-busy", "protected-storage-missing",
    "protected-storage-exists", "protected-storage-write",
))


def _hash(value):
    return hashlib.sha256(_SALT + str(value).encode("utf-8")).hexdigest()


def _number(value):
    return value if type(value) is int and 0 <= value <= 0xFFFFFFFF else None


def capture(exc, test, phase, roots=()):
    """Never let diagnostic failures, including interrupts, replace a caught primary."""
    try:
        _capture(exc, test, phase, roots)
    except BaseException:
        # Diagnostic cancellation must not replace the product's existing exception.
        return


def _capture(exc, test, phase, roots=()):
    """Inspect only an already caught failure, omitting messages, paths and locals."""
    target = os.environ.get("NETOPS_EXACT_FAILURE_OBSERVATIONS")
    if not target or test not in _ALLOWED or not isinstance(exc, BaseException):
        return
    path = Path(target).resolve()
    run = _ROOT / ".sdlc" / "runs"
    if not path.is_relative_to(run):
        return
    sites = []
    tb = exc.__traceback__
    while tb is not None:
        filename = Path(tb.tb_frame.f_code.co_filename)
        if filename.is_absolute() and filename.is_relative_to(_ROOT):
            relative = filename.relative_to(_ROOT)
            if relative.parts[:2] in (("netops", "dependencies"), ("netops", "ansible")) or str(relative) in (
                r"tests\test_nov21_bootstrap_layout_postfix_independent.py",
                r"tests\test_nov21_activation_resources_author.py",
            ):
                sites.append({
                    "path": str(relative), "line": tb.tb_lineno,
                    "function": tb.tb_frame.f_code.co_name,
                })
        tb = tb.tb_next
    diagnostics = {}
    for cleanup in (False, True):
        values = []
        for diagnostic in _storage_diagnostics(exc, cleanup=cleanup):
            value = asdict(diagnostic)
            for key in ("resource_sha256", "operation_sha256"):
                value[key] = _hash(value[key])
            values.append(value)
        diagnostics["cleanup" if cleanup else "primary"] = values
    record = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "test": test, "phase": phase, "pid": os.getpid(),
        "thread_id": threading.get_ident(), "native_thread_id": threading.get_native_id(),
        "exception_type": type(exc).__name__, "exception_module": type(exc).__module__,
        "errno": _number(getattr(exc, "errno", None)),
        "winerror": _number(getattr(exc, "winerror", None)),
        "native_code": _number(getattr(exc, "native_code", None)),
        "fixed_reason": exc.args[0] if exc.args and type(exc.args[0]) is str and exc.args[0] in _REASONS else None,
        "traceback": sites, "diagnostics": diagnostics,
        "owned_root_hashes": [_hash(value) for value in roots],
        "lock_identity": None, "foreign_owner": None,
        "raw_locals_messages_paths_payloads_captured": False,
    }
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
