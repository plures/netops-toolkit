"""Fixed metadata controls from AC001/011/014; not installation qualification."""

import ast
import hashlib
import io
import json
import zipfile
from pathlib import Path


def wheel(root, name, requires=(), provides=(), extras=()):
    """Write one bounded, deterministic, matching wheel in the test-owned root."""
    filename = name.replace("-", "_") + "-1.0-py3-none-any.whl"
    lines = ["Metadata-Version: 2.1", "Name: " + name, "Version: 1.0"]
    lines += ["Provides-Extra: " + item for item in provides]
    lines += ["Requires-Dist: " + item for item in requires]
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w", compression=zipfile.ZIP_STORED) as archive:
        member = zipfile.ZipInfo(name.replace("-", "_") + "-1.0.dist-info/METADATA")
        archive.writestr(member, (chr(10).join(lines) + chr(10) * 2).encode("ascii"))
    data = content.getvalue()
    path = root / filename
    with path.open("xb") as stream:
        stream.write(data)
    from tests._nov22_fixed_wheel_recipe import register

    register(path, hashlib.sha256(data).hexdigest())
    return {
        "path": str(path), "distribution": name, "version": "1.0",
        "digest": hashlib.sha256(data).hexdigest(), "extras": list(extras),
    }


def source_program(source):
    """Read the actual source literal without importing production dependencies."""
    tree = ast.parse(source)
    found = [
        node.value for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "_WHEEL_METADATA"
                for target in node.targets)
    ]
    assert len(found) == 1
    value = found[0]
    if isinstance(value, ast.Constant):
        return ast.literal_eval(value)
    # Materialize the actual packaged prelude, not a synthetic platform profile
    # or arbitrary expression evaluation. Only the documented concatenation is
    # admitted; calls, additional names and alternate operands fail closed.
    assert isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add)
    left = value.left
    assert isinstance(left, ast.BinOp) and isinstance(left.op, ast.Add)
    assert isinstance(left.left, ast.Name) and left.left.id == "_CONTEXT_PROGRAM"
    assert ast.literal_eval(left.right) == "\n"
    body = ast.literal_eval(value.right)
    assert isinstance(body, str)
    dependency = Path(__file__).resolve().parents[1] / "netops/dependencies"
    exported = ast.parse((dependency / "_context_program.py").read_bytes())
    assignments = [node for node in exported.body if isinstance(node, ast.Assign)]
    expected = ast.parse(
        '_CONTEXT_PROGRAM = Path(__file__).with_name("_context_facts.py")'
        '.read_text(encoding="utf-8")'
    ).body[0]
    assert len(assignments) == 1
    assert ast.dump(assignments[0]) == ast.dump(expected)
    prelude = (dependency / "_context_facts.py").read_text(encoding="utf-8")
    program = prelude + "\n" + body
    ast.parse(program)
    return program


def check(root, selected, success, assertion=None):
    """Run the sealed direct-owned recipe and enforce the original assertion."""
    from tests._nov22_fixed_wheel_recipe import invoke

    result = invoke(root, selected)
    marker = b"verified-wheel-metadata-closure" + bytes((13, 10))
    if success:
        assert result["exit_code"] == 0, result
        assert result["stdout"].encode() == marker, result
        assert result["stderr"] == "", result
    else:
        assert result["exit_code"] != 0, result
        assert marker.decode().strip() not in result["stdout"], result
        assert "AssertionError" in result["stderr"], result
        if assertion is not None:
            assert assertion in result["failure_statement"], result


def transitive(root, declared=True, leaf=True, requested="feature", declaration="feature"):
    """Require a transitive extra whose active leaf belongs to the selected closure."""
    toolkit = wheel(root, "toolkit", ("dependency[" + requested + "]==1.0",))
    dependency = wheel(
        root, "dependency", ("leaf==1.0; extra == 'feature-name'",)
        if declaration != "feature" else ("leaf==1.0; extra == 'feature'",),
        (declaration,) if declared else (),
    )
    return [toolkit, dependency, *([wheel(root, "leaf")] if leaf else [])]


def test_undeclared_transitive_extra_rejects_at_pending_gate(tmp_path):
    check(tmp_path, transitive(tmp_path, declared=False), False,
          "assert extras[name] <= declared_extras[name]")


def test_declared_transitive_extra_activates_exact_leaf(tmp_path):
    check(tmp_path, transitive(tmp_path), True)


def test_declared_transitive_extra_missing_leaf_rejects(tmp_path):
    check(tmp_path, transitive(tmp_path, leaf=False), False,
          "assert dependency in versions")


def test_late_contribution_revisits_dependency(tmp_path):
    # LIFO visits dependency before toolkit contributes feature.
    selected = transitive(tmp_path)
    assert [item["distribution"] for item in selected] == ["toolkit", "dependency", "leaf"]
    check(tmp_path, selected, True)


def test_late_contribution_revisit_rejects_missing_leaf(tmp_path):
    check(tmp_path, transitive(tmp_path, leaf=False), False, "assert dependency in versions")


def test_inactive_marker_demands_neither_extra_nor_wheel(tmp_path):
    check(tmp_path, [wheel(tmp_path, "toolkit", (
        "absent[feature]==1.0; sys_platform == 'linux'",
    ))], True)


def test_active_marker_requires_selected_dependency(tmp_path):
    check(tmp_path, [wheel(tmp_path, "toolkit", (
        "absent[feature]==1.0; sys_platform == 'win32'",
    ))], False, "assert dependency in versions")


def test_canonical_transitive_alias_activates_leaf(tmp_path):
    check(tmp_path, transitive(
        tmp_path, requested="Feature_Name", declaration="FEATURE.NAME",
    ), True)


def test_canonical_transitive_alias_requires_leaf(tmp_path):
    check(tmp_path, transitive(
        tmp_path, leaf=False, requested="Feature_Name", declaration="FEATURE.NAME",
    ), False, "assert dependency in versions")


def test_distinct_undeclared_canonical_extra_rejects(tmp_path):
    check(tmp_path, transitive(
        tmp_path, requested="other_name", declaration="FEATURE.NAME",
    ), False, "assert extras[name] <= declared_extras[name]")


def test_canonical_root_alias_activates_leaf(tmp_path):
    selected = [
        wheel(tmp_path, "toolkit", ("leaf==1.0; extra == 'feature-name'",),
              ("FEATURE.NAME",), ("Feature_Name",)),
        wheel(tmp_path, "leaf"),
    ]
    check(tmp_path, selected, True)


def test_canonical_root_alias_requires_leaf(tmp_path):
    selected = [wheel(tmp_path, "toolkit", ("leaf==1.0; extra == 'feature-name'",),
                      ("FEATURE.NAME",), ("Feature_Name",))]
    check(tmp_path, selected, False, "assert dependency in versions")


def union_cycle(root, missing=None):
    selected = [
        wheel(root, "first", ("shared[one]==1.0",)),
        wheel(root, "second", ("shared[two]==1.0",)),
        wheel(root, "shared", ("leaf-one==1.0; extra == 'one'",
                              "leaf-two==1.0; extra == 'two'", "first==1.0"),
              ("one", "two")),
    ]
    for name in ("leaf-one", "leaf-two"):
        if name != missing:
            selected.append(wheel(root, name))
    return selected


def test_two_roots_union_extras_and_cycle_terminates(tmp_path):
    check(tmp_path, union_cycle(tmp_path), True)


def test_union_extra_one_missing_leaf_rejects(tmp_path):
    check(tmp_path, union_cycle(tmp_path, "leaf-one"), False, "assert dependency in versions")


def test_union_extra_two_missing_leaf_rejects(tmp_path):
    check(tmp_path, union_cycle(tmp_path, "leaf-two"), False, "assert dependency in versions")


def test_original_plain_selected_closure_preserved(tmp_path):
    check(tmp_path, [wheel(tmp_path, "toolkit", ("dependency==1.0",)),
                     wheel(tmp_path, "dependency")], True)


def descriptors_digest(selected):
    """Bind exact fixture descriptors in the execution receipt."""
    return hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest()
