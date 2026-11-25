"""Actual installed HTML bytes and origin proof; executable in an isolated interpreter."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def documents():
    return [
        {"title": "Empty offline", "generated_at": "2026-11-20T08:00:00+00:00",
         "period": None, "sections": [], "overall_alert": False},
        {"title": '<script>PRIVATE_XSS_TITLE</script>{{7*7}}',
         "generated_at": "2026-11-20T08:00:00+00:00", "period": None,
         "sections": [{"name": '<img src=x onerror="PRIVATE_XSS_SECTION">',
                       "type": "companion",
                       "data": {"source_status": "failed", "cleanup_failed": True,
                                "remote_uncertain": True, "counts": {"failed": 1, "blocked": 1},
                                "message": "</script><script>PRIVATE_XSS_DATA</script>",
                                "raw": "PRIVATE_RAW_SECRET", "config": "PRIVATE_CONFIG_SECRET"}}],
         "overall_alert": True},
    ]


def render_documents():
    from netops.report.generator import ReportGenerator

    generator = ReportGenerator()
    return [generator.generate_html(document).encode("utf-8") for document in documents()]


def test_source_html_preserves_offline_failure_facts_and_escapes_minimized_data():
    empty, failed = render_documents()
    assert empty.startswith(b"<!DOCTYPE html>")
    assert b"Empty offline" in empty
    assert b"failed" in failed and b"remote_uncertain" in failed and b"cleanup_failed" in failed
    assert b"PRIVATE_XSS_TITLE" in failed and b"&lt;script&gt;" in failed
    assert b'<script>PRIVATE_XSS_TITLE' not in failed
    assert b'<img src=x onerror="PRIVATE_XSS_SECTION">' not in failed
    assert b"</script><script>PRIVATE_XSS_DATA</script>" not in failed
    assert b"PRIVATE_RAW_SECRET" not in failed and b"PRIVATE_CONFIG_SECRET" not in failed
    assert b"{{7*7}}" in failed


def installed(expected_path: str, output: str):
    import netops
    from netops.report import generator

    expected = json.loads(Path(expected_path).read_text(encoding="utf-8"))
    package = Path(netops.__file__).resolve().parent
    assert package.is_relative_to(Path(sys.prefix).resolve()), "checkout import injection"
    mismatches = []
    for relative, digest in expected["files"].items():
        path = package / relative.removeprefix("netops/")
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            mismatches.append(relative)
    assert not mismatches, "installed-source-byte-drift:" + repr(mismatches)
    template = Path(generator._BUILTIN_TEMPLATE)
    assert template.is_relative_to(package)
    assert hashlib.sha256(template.read_bytes()).hexdigest() == expected["files"][
        "netops/report/templates/default.html.j2"
    ]
    test_source_html_preserves_offline_failure_facts_and_escapes_minimized_data()
    content = render_documents()
    actual = [hashlib.sha256(value).hexdigest() for value in content]
    assert actual == expected["html_sha256"], "source/installed exact rendered-byte mismatch"
    for index, value in enumerate(content):
        (Path(output) / f"installed-{index}.html").write_bytes(value)
    print(json.dumps({
        "import_origin": str(netops.__file__), "prefix": sys.prefix,
        "template_origin": str(template), "source_files_exact": len(expected["files"]),
        "html_sha256": actual, "html_bytes": [len(value) for value in content],
        "source_injection_ignored": True, "qualified_controller": False,
    }))


if __name__ == "__main__":
    installed(sys.argv[1], sys.argv[2])
