"""Bounded offline probes executed in the actual selected consuming interpreter."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Mapping

from ._context_program import _CONTEXT_PROGRAM
from ._probe_catalog import CONTROLLER_TOOLS as _CONTROLLER_TOOLS
from ._probe_catalog import MODULES as _MODULES
from ._probe_catalog import PROBE_SYMBOLS
from ._probe_catalog import TOOLS as _TOOLS
from .service import ConsumingContext, DependencyEntry, ProbeResult, observe_probe

logger = logging.getLogger(__name__)

_PYTHON_PROBE = _CONTEXT_PROGRAM + "\n" + (
    "import json,sys,platform;"
    "print(json.dumps({'version':platform.python_version(),'executable':sys.executable,"
    "'platform':sys.platform,'architecture':_host_architecture()}))"
)
_MODULE_PROBE = """
import importlib, importlib.metadata, json, sys
m = importlib.import_module(sys.argv[1])
name = sys.argv[1]
if name == 'yaml':
    assert m.safe_load('probe: true') == {'probe': True}
elif name == 'jinja2':
    assert m.Environment().from_string('{{ value }}').render(value='probe') == 'probe'
elif name == 'cryptography':
    from cryptography.fernet import Fernet
    f = Fernet(Fernet.generate_key())
    assert f.decrypt(f.encrypt(b'probe')) == b'probe'
elif name == 'paramiko':
    assert m.Message(b'').asbytes() == b''
elif name == 'netmiko':
    assert callable(m.ConnectHandler)
elif name == 'pysnmp':
    from pysnmp.proto.rfc1902 import Integer
    assert int(Integer(1)) == 1
elif name == 'textual':
    from textual.widgets import Static
    assert Static('probe') is not None
print(json.dumps({'version': importlib.metadata.version(sys.argv[2])}))
"""
_PDF_PROBE = (
    "import json,importlib.metadata;"
    "from weasyprint import HTML;"
    "b=HTML(string='<p>offline readiness</p>',url_fetcher=lambda u: "
    "(_ for _ in ()).throw(ValueError('fetch-denied'))).write_pdf();"
    "assert b.startswith(b'%PDF');"
    "print(json.dumps({'version':importlib.metadata.version('weasyprint'),'bytes':len(b)}))"
)


class LocalDependencyAdapter:
    """Run fixed allowlisted probes; foreign controllers require their own real adapter."""

    def __init__(self, contexts: Mapping[str, ConsumingContext]) -> None:
        self.contexts = dict(contexts)
        self.counts: dict[tuple[str, str, str], int] = {}

    def _result(
        self, entry: DependencyEntry, context: ConsumingContext, start: float,
        status: str, reason: str, output: bytes = b"", version: str | None = None,
    ) -> ProbeResult:
        next_action = {
            "available": "none", "missing": "review-install-plan",
            "unsupported": "select-qualified-platform", "blocked": "verify-consuming-context",
        }[status]
        dimensions = (context.role, status, reason)
        self.counts[dimensions] = self.counts.get(dimensions, 0) + 1
        result = ProbeResult(
            entry.id, context.digest, status, reason, version,
            hashlib.sha256(context.digest.encode() + output).hexdigest() if status == "available" else None,
            next_action,
        )
        observe_probe(result, context.role, time.monotonic() - start, logger)
        return result

    def probe(
        self, entry: DependencyEntry, context: ConsumingContext, deadline: float,
    ) -> ProbeResult:
        """Return safe factual evidence; no downloads, daemon starts, unlocks or shell."""
        start = time.monotonic()
        if type(deadline) is not float or not math.isfinite(deadline):
            return self._result(entry, context, start, "blocked", "deadline-invalid")
        if deadline <= start:
            return self._result(entry, context, start, "blocked", "deadline-exceeded")
        if context.platform != sys.platform or context.role != entry.context:
            return self._result(entry, context, start, "blocked", "context-unavailable")
        if context.platform not in entry.platforms:
            return self._result(entry, context, start, "unsupported", "platform-unsupported")
        if entry.probe not in PROBE_SYMBOLS.get(entry.adapter, frozenset()):
            return self._result(entry, context, start, "blocked", "probe-unregistered")
        if entry.adapter == "grant":
            # A caller-supplied grant label is not an authoritative OS receipt.
            return self._result(entry, context, start, "blocked", "platform-grant-unverified")
        if entry.adapter == "asset":
            return self._result(entry, context, start, "blocked", "asset-lock-required")
        if entry.adapter == "runtime":
            # Inspecting a daemon is separately authorized, never an implicit status side effect.
            return self._result(entry, context, start, "blocked", "runtime-functional-proof-required")
        environment = {
            key: value for key, value in os.environ.items()
            if key.upper() in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC")
        }
        environment.update({
            "PATH": context.path, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
            "ANSIBLE_COLLECTIONS_PATH": os.pathsep.join(context.collection_paths),
            "ANSIBLE_GALAXY_SERVER_LIST": "", "PIP_NO_INDEX": "1",
        })
        if entry.adapter == "python":
            command = [context.python, "-I", "-B", "-c", _PYTHON_PROBE]
        elif entry.adapter == "module":
            if entry.probe not in _MODULES:
                return self._result(entry, context, start, "blocked", "probe-unregistered")
            module, distribution = _MODULES[entry.probe]
            command = [context.python, "-I", "-B", "-c", _MODULE_PROBE, module, distribution]
        elif entry.adapter == "pdf":
            command = [context.python, "-I", "-B", "-c", _PDF_PROBE]
        elif entry.adapter == "collection":
            command = [context.python, "-I", "-B", "-m", "ansible.cli.galaxy",
                       "collection", "list", entry.probe, "--format", "json"]
        elif entry.adapter == "executable" and entry.probe in _CONTROLLER_TOOLS:
            command = [context.python, "-I", "-B", "-m", _CONTROLLER_TOOLS[entry.probe], "--version"]
        elif entry.adapter == "executable" and entry.probe in _TOOLS:
            tool, *args = _TOOLS[entry.probe]
            executable = shutil.which(tool, path=context.path)
            if executable is None:
                return self._result(entry, context, start, "missing", "executable-missing")
            command = [executable, *args]
        else:
            return self._result(entry, context, start, "blocked", "probe-unregistered")
        try:
            # TemporaryFile would violate the read-only/no-temp probe boundary.
            # Fixed local probes have bounded expected output; reject oversized receipts.
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=environment, shell=False,
            )
            output: list[bytes] = []

            def read_bounded() -> None:
                if process.stdout is not None:
                    output.append(process.stdout.read(65537))
                    if len(output[0]) > 65536:
                        process.kill()

            reader = threading.Thread(target=read_bounded, daemon=True)
            reader.start()
            try:
                process.wait(timeout=max(0.001, min(5.0, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                reader.join(timeout=1.0)
                if process.stdout is not None and not reader.is_alive():
                    process.stdout.close()
                raise
            reader.join(timeout=1.0)
            if reader.is_alive():
                return self._result(entry, context, start, "blocked", "probe-output-unclosed")
            completed = subprocess.CompletedProcess(command, process.returncode, b"".join(output))
            if process.stdout is not None:
                process.stdout.close()
        except FileNotFoundError:
            return self._result(entry, context, start, "missing", "interpreter-missing")
        except subprocess.TimeoutExpired:
            return self._result(entry, context, start, "blocked", "probe-timeout")
        except (OSError, ValueError):
            return self._result(entry, context, start, "blocked", "probe-failed")
        if len(completed.stdout) > 65536:
            return self._result(entry, context, start, "blocked", "probe-output-limit")
        rm_usage = (
            entry.adapter == "executable" and entry.probe == "rm"
            and completed.returncode == (1 if context.platform == "darwin" else 0)
            and re.search(rb"\busage:\s+(?:\S*[/\\])?rm(?:\s|\[)", completed.stdout, re.IGNORECASE)
            is not None
        )
        if entry.adapter == "executable" and entry.probe == "rm" and not rm_usage:
            return self._result(entry, context, start, "blocked", "functional-probe-failed")
        if completed.returncode != 0 and not rm_usage:
            reason = "module-missing" if b"ModuleNotFoundError" in completed.stdout else "functional-probe-failed"
            return self._result(entry, context, start, "missing", reason)
        version = None
        try:
            if entry.adapter in ("python", "module", "pdf"):
                payload = json.loads(completed.stdout)
                version = payload["version"]
                if entry.adapter == "python" and (
                    os.path.normcase(payload["executable"]) != os.path.normcase(context.python)
                    or payload["platform"] != context.platform
                    or payload["architecture"].casefold() != context.architecture.casefold()
                ):
                    return self._result(entry, context, start, "blocked", "interpreter-drift")
            elif entry.adapter == "collection":
                payload = json.loads(completed.stdout)
                found = [values[entry.probe]["version"] for values in payload.values() if entry.probe in values]
                if len(found) != 1:
                    return self._result(entry, context, start, "missing", "collection-missing-or-ambiguous")
                version = found[0]
            else:
                # Tool output is hashed, not exposed (runtime info can carry host details).
                match = re.search(rb"\b(\d+(?:\.\d+)+)\b", completed.stdout)
                version = match.group(1).decode("ascii") if match else None
        except (ValueError, KeyError, TypeError, AttributeError):
            return self._result(entry, context, start, "blocked", "probe-receipt-invalid")
        if entry.version.startswith((">=", "<", "==")):
            if version is None or not _version_matches(version, entry.version):
                return self._result(entry, context, start, "blocked", "version-mismatch")
        return self._result(entry, context, start, "available", "functional-probe-passed",
                            completed.stdout, version)


def _version_matches(version: str, requirement: str) -> bool:
    """Compare bounded numeric release ranges without installing a packaging tool."""
    if len(version) > 128 or len(requirement) > 128:
        return False
    actual_match = re.fullmatch(r"(\d+(?:\.\d+)*)", version)
    if actual_match is None:
        return False
    actual = tuple(int(x) for x in actual_match.group(1).split("."))
    for constraint in requirement.split(","):
        match = re.fullmatch(r"(>=|<=|==|<|>)(\d+(?:\.\d+)*)", constraint)
        if match is None:
            return False
        expected = tuple(int(x) for x in match.group(2).split("."))
        size = max(len(actual), len(expected))
        left, right = actual + (0,) * (size - len(actual)), expected + (0,) * (size - len(expected))
        op = match.group(1)
        if not {">=": left >= right, "<=": left <= right, "==": left == right,
                "<": left < right, ">": left > right}[op]:
            return False
    return True
