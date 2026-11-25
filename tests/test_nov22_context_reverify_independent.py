"""Decoder and upstream ordering controls; no foreign-runtime qualification."""

import ast
import hashlib
import inspect
from pathlib import Path
from types import SimpleNamespace

from tests.test_nov22_recursive_extra_independent import source_program

REPO = Path(__file__).resolve().parents[1]


def test_decoder_materializes_actual_prelude_and_literal():
    source = (REPO / "netops/dependencies/_installation.py").read_bytes()
    tree = ast.parse(source)
    assignment = next(
        node for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "_WHEEL_METADATA"
                for target in node.targets)
    )
    expected = (
        (REPO / "netops/dependencies/_context_facts.py").read_text(encoding="utf-8")
        + "\n" + ast.literal_eval(assignment.value.right)
    )
    assert source_program(source) == expected
    assert hashlib.sha256(source_program(source).encode()).digest() == hashlib.sha256(
        expected.encode(),
    ).digest()


def test_decoder_retains_historical_literal():
    assert source_program('_WHEEL_METADATA = "historical\\nbytes\\r\\n"') == (
        "historical\nbytes\r\n"
    )


def test_decoder_rejects_expression_outside_fixed_composition():
    for expression in (
        '_OTHER + "\\n" + "body"', '_CONTEXT_PROGRAM + "wrong" + "body"',
        '_CONTEXT_PROGRAM + "\\n" + str("body")',
    ):
        try:
            source_program("_WHEEL_METADATA = " + expression)
        except (AssertionError, ValueError):
            pass
        else:
            raise AssertionError("Unsealed decoder expression accepted")


def tag_selection(interpreter):
    """Compare selection and exact order to installed upstream's sys_tags rule."""
    from packaging import tags

    # sys_tags' branch is independently pinned to its actual installed source.
    upstream = inspect.getsource(tags.sys_tags)
    assert 'interp_name == "cp"' in upstream
    assert 'interp_name == "pp"' in upstream
    assert 'interp = "pp3"' in upstream
    assert 'interp = "cp" + interpreter_version(warn=warn)' in upstream
    assert 'interp = None' in upstream
    assert 'compatible_tags(interpreter=interp)' in upstream
    path = REPO / "netops/dependencies/_context_facts.py"
    function = next(
        node for node in ast.parse(path.read_bytes()).body
        if isinstance(node, ast.FunctionDef) and node.name == "_interpreter_tags"
    )
    calls = []

    def compatible(**kwargs):
        calls.append(kwargs)
        return tags.compatible_tags(**kwargs)

    proxy = SimpleNamespace(
        interpreter_name=lambda: interpreter,
        interpreter_version=tags.interpreter_version,
        cpython_tags=tags.cpython_tags, generic_tags=tags.generic_tags,
        compatible_tags=compatible,
    )
    namespace = {
        "ModuleType": object, "sys": SimpleNamespace(platform="win32"),
        "sysconfig": SimpleNamespace(get_platform=lambda: "win-amd64"),
        "_ContextUnavailable": ValueError,
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
    actual = namespace["_interpreter_tags"](proxy)
    platforms = ["win_amd64"]
    choice = "pp3" if interpreter == "pp" else (
        interpreter + tags.interpreter_version() if interpreter == "cp" else None
    )
    primary = tags.cpython_tags if interpreter == "cp" else tags.generic_tags
    expected = tuple(primary(platforms=platforms)) + tuple(tags.compatible_tags(
        interpreter=choice, platforms=platforms,
    ))
    assert actual == expected
    assert calls == [{"interpreter": choice, "platforms": platforms}]


def test_upstream_cpython_selection_and_order():
    tag_selection("cp")


def test_upstream_pypy_selection_and_order_pure_not_runtime():
    tag_selection("pp")


def test_upstream_other_selection_and_order_pure_not_runtime():
    tag_selection("other")
