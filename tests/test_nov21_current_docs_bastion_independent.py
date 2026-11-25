"""AC006/011/014: owned docs and protected token boundaries, no services."""

import json
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock

import pytest

from netops.core import bastion
from netops.dependencies import _documentation as docs


def test_real_docs_registry_closure_selects_python_handler_and_fixed_strict_command(tmp_path):
    plan = docs._plan(Path.cwd(), tmp_path / "new-docs")
    distributions = dict(plan.distributions)
    assert "mkdocstrings-python" in distributions
    assert {"mkdocs", "mkdocs-material", "mkdocstrings"} <= set(distributions)
    assert plan.command == (
        plan.python, "-B", "-m", "mkdocs", "build", "--strict", "--config-file",
        str(Path(plan.output) / "reviewed-source" / "mkdocs.yml"),
        "--site-dir", str(Path(plan.output) / "site"),
    )
    assert {"mkdocs.yml", "pyproject.toml", "docs\\index.md"} <= {
        item.path for item in plan.source_files
    }
    assert not Path(plan.output).exists()


def test_existing_or_forged_documentation_output_cannot_supply_consent(tmp_path):
    output = tmp_path / "forged"
    output.mkdir()
    receipt = output / "documentation-receipt.json"
    receipt.write_text('{"strict_exit_code":0}', encoding="utf-8")
    with pytest.raises(docs._DocsBlocked) as caught:
        docs._plan(Path.cwd(), output)
    assert caught.value.reason == "documentation-new-owned-output-required"
    assert receipt.read_text() == '{"strict_exit_code":0}'


def test_documentation_consent_is_one_use_and_exact_plan_bound(tmp_path):
    plan = docs._plan(Path.cwd(), tmp_path / "new-docs")
    consent = docs._DocsConsent(plan)
    assert consent.consume(plan) > 0.0
    with pytest.raises(docs._DocsBlocked) as caught:
        consent.consume(plan)
    assert caught.value.reason == "documentation-consent-stale"


def test_documentation_source_drift_precedes_output_creation(tmp_path, monkeypatch):
    plan = docs._plan(Path.cwd(), tmp_path / "new-docs")
    monkeypatch.setattr(docs, "_plan", lambda *_: object())
    creation = Mock(side_effect=AssertionError("must not create output"))
    monkeypatch.setattr(docs, "_directory", creation)
    with pytest.raises(docs._DocsBlocked) as caught:
        docs._build(plan, docs._DocsConsent(plan))
    assert caught.value.reason == "documentation-plan-drift"
    creation.assert_not_called()


def test_legacy_bastion_token_read_requires_protected_parent_handle(tmp_path, monkeypatch):
    path = tmp_path / "legacy.json"
    token = "independent-private-token"
    state = {
        "host": "example.invalid", "port": 22, "username": "user", "key_file": None,
        "socks_host": "127.0.0.1", "socks_port": 1, "control_host": "127.0.0.1",
        "control_port": 2, "token": token, "pid": 123,
    }
    native = Mock()
    active = []

    @contextmanager
    def directory(value):
        assert value == str(path.parent)
        active.append(77)
        try:
            yield 77
        finally:
            active.pop()

    def read(parent, name, limit):
        assert active == [77] and parent == 77 and name == "legacy.json"
        assert limit == 1024 * 1024
        return json.dumps(state).encode()

    native.directory = directory
    native.read = read
    monkeypatch.setattr("netops.ansible.artifact_platform.windows", lambda: native)
    result = bastion._read_state(path)
    assert result.token == token
    assert not active


def test_unsafe_legacy_parent_rejection_never_reads_token(tmp_path, monkeypatch):
    native = Mock()
    native.directory.side_effect = OSError("independent-unsafe-parent")
    monkeypatch.setattr("netops.ansible.artifact_platform.windows", lambda: native)
    with pytest.raises(OSError, match="independent-unsafe-parent"):
        bastion._read_state(tmp_path / "legacy.json")
    native.read.assert_not_called()


def test_bastion_log_is_fixed_protected_handle_not_raw_open(tmp_path, monkeypatch):
    path = tmp_path / "active.log"
    native = Mock()
    active = []

    @contextmanager
    def directory(value):
        active.append(value)
        try:
            yield 88
        finally:
            active.pop()

    @contextmanager
    def log(parent, name):
        assert active == [str(path.parent)]
        assert parent == 88 and name == "active.log"
        yield "protected-log-handle"

    native.directory, native.log = directory, log
    monkeypatch.setattr("netops.ansible.artifact_platform.windows", lambda: native)
    with bastion._state_log(path) as handle:
        assert handle == "protected-log-handle"
    assert not active and not path.exists()
