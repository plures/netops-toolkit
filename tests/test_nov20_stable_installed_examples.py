"""Actual installed native/companion previews, never controller qualification."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

from netops.ansible import contracts as c
from netops.ansible.policy import LocalReferencePolicyEngine, PolicyIdentity, load_policy
from netops.ansible.workflows import WorkflowService, hydrate_inputs
from netops.report.generator import ReportGenerator

OP = "60000000-0000-4000-8000-000000000006"
D = "2" * 64


class Forbidden:
    """No effectful port may be used by a loaded-input preview."""

    def __getattr__(self, name):
        raise AssertionError("Unexpected preview effect: " + name)


class Clock:
    """Hydration timestamp only; never passed as an effectful preview clock."""

    def monotonic(self):
        return 10.0


def policy():
    root = Path(c.__file__).parent / "policy"
    source = (root / "ansible_molecule.px").read_bytes()
    contracts = (root / "ansible_molecule.contracts.px").read_bytes()
    bundle = (root / "bundle.json").read_bytes()
    parsed = json.loads(bundle)
    identity = PolicyIdentity(
        parsed["canonical_revision"], hashlib.sha256(source).hexdigest(),
        hashlib.sha256(contracts).hexdigest(), hashlib.sha256(bundle).hexdigest(),
        tuple(item["id"] for item in parsed["manifest"]), parsed["reducer_version"],
    )
    return identity, LocalReferencePolicyEngine(load_policy(source, contracts, bundle, identity))


def previews():
    identity, engine = policy()
    forbidden = Forbidden()
    service = WorkflowService(
        engine, forbidden, forbidden, forbidden, forbidden, forbidden, forbidden, forbidden,
    )
    outputs = []
    pairs = (
        ("cisco_ios", b"interface Gi0/1\n description old\n", b"interface Gi0/1\n description new\n"),
        ("junos", b"set system host-name old\n", b"set system host-name new\n"),
        ("flat", b"hostname old\n", b"hostname new\n"),
    )
    for vendor, before, after in pairs:
        for right in (after, before):
            data = (before, right)
            refs = tuple(
                c.InputRef(kind, "loaded-" + kind, hashlib.sha256(value).hexdigest())
                for kind, value in zip(("before", "after"), data)
            )
            request = c.OperationRequest(
                OP, "compare.compare", c.Mode.PREVIEW, c.Scope(()),
                c.Context("fixture-controller", D, "fixture-source", D, identity, D, D), refs,
            )
            sources = tuple(
                c.InputSource(ref, "text", value, "parser-1", vendor)
                for ref, value in zip(refs, data)
            )
            loaded = hydrate_inputs(request, sources, Clock())
            with patch("socket.socket", side_effect=AssertionError("unexpected network")), \
                    patch.object(Path, "open", side_effect=AssertionError("unexpected file")):
                first = service.preview(request, loaded)
                second = service.preview(request, loaded)
                assert c.canonical_bytes(first) == c.canonical_bytes(second)
            assert first.native_payload["execution_performed"] is False
            summary = first.native_payload["native_payload"]["summary"]
            changed = any(summary[name] for name in ("added", "removed", "changed"))
            assert changed is (right != before)
            outputs.append(c.canonical_bytes(first))
    report = ReportGenerator()
    empty = report.generate_html({
        "title": "Offline installed", "generated_at": "2026-11-20T08:00:00+00:00",
        "period": None, "sections": [], "overall_alert": False,
    }).encode()
    assert empty.startswith(b"<!DOCTYPE html>") and b"Offline installed" in empty
    outputs.append(empty)
    return outputs


def test_actual_native_and_companion_loaded_examples_are_deterministic_and_nonmutating():
    assert len(previews()) == 7


def installed(expected_path, output):
    import netops

    package = Path(netops.__file__).resolve().parent
    assert package.is_relative_to(Path(sys.prefix).resolve()), "checkout import injection"
    expected = json.loads(Path(expected_path).read_bytes())
    rendered = previews()
    hashes = [hashlib.sha256(value).hexdigest() for value in rendered]
    assert hashes == expected["preview_sha256"], "source/installed preview output drift"
    record = {
        "import_origin": str(netops.__file__), "prefix": sys.prefix,
        "preview_sha256": hashes, "loaded_compare_cases": 6,
        "html_bytes": len(rendered[-1]), "controller_qualified": False,
        "no_device_collection_or_apply": True, "source_exact_bytes": True,
    }
    Path(output).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record))


if __name__ == "__main__":
    installed(sys.argv[1], sys.argv[2])
