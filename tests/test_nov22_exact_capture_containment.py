"""Diagnostic-only fault injection; no product provisioning/staging is executed."""

import ast
import builtins
import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import _nov22_exact_failure_capture as observation

TEST = "test_new_observation_window_is_owned_root_bound_before_plan"
SOURCES = Path(__file__).parent


def fail(error):
    def operation(*args, **kwargs):
        raise error

    return operation


def teardown_wrapper(original, root):
    tree = ast.parse((SOURCES / "test_nov21_activation_resources_author.py").read_text())
    outer = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and
                 node.name == TEST)
    wrapper = next(node for node in outer.body if isinstance(node, ast.FunctionDef) and
                   node.name == "failure_teardown")
    namespace = {"original_teardown": original, "tmp_path": root}
    exec(compile(ast.Module(body=[wrapper], type_ignores=[]), "<diagnostic-wrapper>", "exec"),
         namespace)
    return namespace["failure_teardown"]


def stage_observation(primary):
    tree = ast.parse(
        (SOURCES / "test_nov21_bootstrap_layout_postfix_independent.py").read_text(),
    )
    outer = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and
                 node.name == "test_original_producer_drift_stops_real_stage_before_installer")
    block = next(node for node in outer.body if isinstance(node, ast.If) and
                 isinstance(node.test, ast.Compare) and
                 isinstance(node.test.left, ast.Name) and node.test.left.id == "effects")
    assertion = outer.body[outer.body.index(block) + 1]
    host = SimpleNamespace(root=SimpleNamespace(path="owned-a"),
                           consuming_root=SimpleNamespace(path="owned-b"))
    namespace = {"effects": [], "boundary": "after-publication",
                 "rejection": SimpleNamespace(value=primary), "host": host}
    exec(compile(ast.Module(body=[block, assertion], type_ignores=[]),
                 "<diagnostic-stage-assertion>", "exec"), namespace)


@pytest.mark.parametrize("operation", ("open", "write"))
def test_observation_io_failure_is_nonfatal(monkeypatch, operation):
    primary = OSError("primary")
    error = OSError("diagnostic-absolute-filename")
    monkeypatch.setenv("NETOPS_EXACT_FAILURE_OBSERVATIONS",
                       str(observation._ROOT / ".sdlc" / "runs" / "unused-observation.jsonl"))

    class Stream:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        write = staticmethod(fail(error))

    monkeypatch.setattr(Path, "open", fail(error) if operation == "open" else
                        lambda *args, **kwargs: Stream())
    assert observation.capture(primary, TEST, "diagnostic-only") is None
    assert primary.args == ("primary",)


@pytest.mark.parametrize("error", (RuntimeError("diagnostic"), KeyboardInterrupt(), SystemExit(4)))
def test_helper_contains_diagnostic_control_exceptions(monkeypatch, error):
    primary = SystemExit(9)
    monkeypatch.setattr(observation, "_capture", fail(error))
    assert observation.capture(primary, TEST, "diagnostic-only") is None
    assert primary.code == 9


@pytest.mark.parametrize("error", (OSError("diagnostic"), KeyboardInterrupt(), SystemExit(4)))
@pytest.mark.parametrize("boundary", ("capture", "import"))
def test_original_teardown_receives_primary_despite_diagnostic_failure(
    monkeypatch, error, boundary,
):
    primary = KeyboardInterrupt("original-product-interrupt")
    received = []
    entered = []

    @contextmanager
    def original(value=None):
        received.append(value)
        try:
            yield
        finally:
            entered.append(value)

    wrapper = teardown_wrapper(original, "owned-root")
    if boundary == "capture":
        monkeypatch.setattr(observation, "capture", fail(error))
    else:
        original_import = builtins.__import__

        def import_module(name, *args, **kwargs):
            if name == "tests._nov22_exact_failure_capture":
                raise error
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", import_module)
    with wrapper(primary):
        pass
    assert received == [primary]
    assert entered == [primary]
    with pytest.raises(KeyboardInterrupt) as caught, wrapper(primary):
        raise primary
    assert caught.value is primary


def test_success_does_not_initialize_capture(monkeypatch):
    calls = []
    capture = observation.capture
    wrapper = teardown_wrapper(lambda primary: calls.append(primary) or "original", "owned")
    monkeypatch.setattr(observation, "capture", fail(AssertionError("must not capture")))
    assert wrapper() == "original"
    assert calls == [None]
    monkeypatch.delenv("NETOPS_EXACT_FAILURE_OBSERVATIONS", raising=False)
    monkeypatch.setattr(Path, "open", fail(AssertionError("must not observe")))
    assert capture(None, TEST, "success") is None


def test_safe_codes_do_not_fabricate_values(monkeypatch):
    primary = OSError("protected-storage-write")
    primary.errno = True
    primary.winerror = -1
    primary.native_code = "5"
    rows = []

    class Stream:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def write(self, value):
            rows.append(json.loads(value))

    monkeypatch.setenv("NETOPS_EXACT_FAILURE_OBSERVATIONS",
                       str(observation._ROOT / ".sdlc" / "runs" / "unused-observation.jsonl"))
    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: Stream())
    observation.capture(primary, TEST, "diagnostic-only")
    assert len(rows) == 1
    assert (rows[0]["errno"], rows[0]["winerror"], rows[0]["native_code"]) == (None, None, None)
    assert rows[0]["fixed_reason"] == "protected-storage-write"


@pytest.mark.parametrize("boundary", ("capture", "import"))
def test_stage_original_assertion_not_masked(monkeypatch, boundary):
    primary = ValueError("original-stage-rejection")
    if boundary == "capture":
        monkeypatch.setattr(observation, "capture", fail(OSError("diagnostic-private-path")))
    else:
        original_import = builtins.__import__

        def import_module(name, *args, **kwargs):
            if name == "tests._nov22_exact_failure_capture":
                raise ImportError("diagnostic-private-path")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", import_module)
    with pytest.raises(AssertionError) as caught:
        stage_observation(primary)
    assert str(caught.value) == repr(primary)


def test_expected_body_error_and_unexpected_success_keep_pytest_semantics(monkeypatch):
    primary = ValueError("expected-body-error")

    @contextmanager
    def original(value=None):
        yield

    wrapper = teardown_wrapper(original, "owned")
    monkeypatch.setattr(observation, "capture", fail(OSError("diagnostic")))
    with pytest.raises(ValueError) as caught, wrapper(primary):
        raise primary
    assert caught.value is primary
    with pytest.raises(pytest.fail.Exception, match="DID NOT RAISE"):
        with pytest.raises(ValueError), wrapper():
            pass
