"""
Semantic-aware configuration diff engine.

Understands network device config structure rather than treating configs as
plain text.  Supports three input formats:

* **cisco** – IOS/IOS-XE/IOS-XR indented hierarchical style
* **junos**  – JunOS set-format *or* bracketed hierarchical style
* **flat**   – one directive per line (Nokia SR-OS, simple key/value)

Three output formats are available:

* **unified**  – classic unified diff (compatible with ``patch(1)``)
* **semantic** – human-readable tree view with parent context and highlights
* **json**     – machine-readable dict suitable for programmatic consumption

Usage::

    # From files:
    python -m netops.change.diff --before before.txt --after after.txt

    # With format selection:
    python -m netops.change.diff --before b.txt --after a.txt --format semantic

    # JSON output (suitable for CI pipelines):
    python -m netops.change.diff --before b.txt --after a.txt --format json

Public API::

    from netops.change.diff import diff_configs, format_unified, format_semantic, format_json

    result = diff_configs(before_text, after_text, style="cisco")
    print(format_semantic(result))
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

__all__ = [
    "ConfigStyle",
    "ChangeKind",
    "ConfigNode",
    "DiffEntry",
    "DiffResult",
    "parse_config",
    "diff_configs",
    "format_unified",
    "format_semantic",
    "format_json",
]

# ---------------------------------------------------------------------------
# Security-sensitive keyword patterns
# ---------------------------------------------------------------------------

_SECURITY_PATTERNS: list[re.Pattern] = [
    re.compile(r"\b(ip\s+access(-list|-group)?|access-list)\b", re.IGNORECASE),
    re.compile(r"\b(acl|permit\s|deny\s)\b", re.IGNORECASE),
    re.compile(r"\b(username|password|secret|enable\s+secret|crypto\s+key|ssh\s+key)\b", re.IGNORECASE),
    re.compile(r"\b(aaa\s+(authentication|authorization|accounting))\b", re.IGNORECASE),
    re.compile(r"\b(tacacs(-server|\+)?|radius(-server)?)\b", re.IGNORECASE),
    re.compile(r"\b(route(-map|-policy)?|prefix-list|community-list)\b", re.IGNORECASE),
    re.compile(r"\b(no\s+)?snmp(-server)?\s+(community|host|user)\b", re.IGNORECASE),
    re.compile(r"\b(login\s+user|system\s+login)\b", re.IGNORECASE),
    re.compile(r"\b(ntp\s+authenticate|ntp\s+authentication-key)\b", re.IGNORECASE),
    re.compile(r"\b(firewall|security-policy|policy-map\s+type\s+inspect)\b", re.IGNORECASE),
    re.compile(r"\bip\s+ssh\b", re.IGNORECASE),
]


def _is_security_sensitive(text: str) -> bool:
    """Return *True* if *text* matches any security-sensitive pattern."""
    return any(pat.search(text) for pat in _SECURITY_PATTERNS)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ConfigStyle(str, Enum):
    """Config syntax style used for hierarchical parsing."""

    CISCO = "cisco"
    JUNOS = "junos"
    FLAT = "flat"

    @classmethod
    def detect(cls, text: str) -> "ConfigStyle":
        """Heuristically detect the config style from *text*."""
        lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("!")]
        set_lines = sum(1 for ln in lines if ln.lstrip().startswith("set "))
        if set_lines > len(lines) * 0.4:
            return cls.JUNOS
        indented = sum(1 for ln in lines if ln.startswith((" ", "\t")))
        if indented > len(lines) * 0.2:
            return cls.CISCO
        return cls.FLAT


class ChangeKind(str, Enum):
    """Type of diff change."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
    UNCHANGED = "unchanged"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ConfigNode:
    """One node in the hierarchical config tree.

    For **cisco** style each node corresponds to a block header (e.g.
    ``interface GigabitEthernet0/0``) or a leaf line inside that block.

    For **junos** set-format each ``set …`` directive is stored as a flat
    node with its full path as ``key``.

    For **flat** style each non-blank, non-comment line is a leaf node.
    """

    key: str
    """Canonical identifier for this node (stripped, normalised)."""

    raw: str
    """Original line as it appeared in the config (may include whitespace)."""

    children: list["ConfigNode"] = field(default_factory=list)
    """Child nodes (sub-stanzas in Cisco hierarchical config)."""

    depth: int = 0
    """Nesting depth (0 = top-level)."""

    is_security: bool = False
    """True when the line matches a security-sensitive pattern."""

    def __post_init__(self) -> None:
        """Auto-detect security sensitivity when not explicitly set."""
        if not self.is_security:
            self.is_security = _is_security_sensitive(self.raw)

    def flat_lines(self) -> list[str]:
        """Return all lines in this subtree as a flat list (DFS order)."""
        result = [self.raw]
        for child in self.children:
            result.extend(child.flat_lines())
        return result

    def signature(self) -> str:
        """Return a string that uniquely identifies this node's *content*.

        For leaf nodes this is the stripped line itself.  For block headers
        it is ``header + sorted(child signatures)`` so that reordering
        children (where order does not matter) does not produce a diff.
        """
        if not self.children:
            return self.key
        child_sigs = sorted(c.signature() for c in self.children)
        return self.key + "\n" + "\n".join(child_sigs)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def _indent_level(line: str) -> int:
    """Return the leading-whitespace indent count (spaces; tabs count as 1)."""
    return len(line) - len(line.lstrip())


def _parse_cisco(text: str) -> list[ConfigNode]:
    """Parse Cisco IOS/IOS-XE/IOS-XR indented hierarchical config."""
    root_nodes: list[ConfigNode] = []
    # stack holds (indent_level, ConfigNode)
    stack: list[tuple[int, ConfigNode]] = []

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("!"):
            continue
        indent = _indent_level(raw_line)
        node = ConfigNode(key=stripped, raw=raw_line, depth=indent)

        # Pop stack until parent indent is strictly less than current indent
        while stack and stack[-1][0] >= indent:
            stack.pop()

        if stack:
            stack[-1][1].children.append(node)
        else:
            root_nodes.append(node)

        stack.append((indent, node))

    return root_nodes


def _parse_junos_set(lines: list[str]) -> list[ConfigNode]:
    """Parse JunOS set-format config into flat ConfigNode list."""
    nodes: list[ConfigNode] = []
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key = stripped
        nodes.append(ConfigNode(key=key, raw=raw_line, depth=0))
    return nodes


_ROOT_INDENT = -1  # Sentinel indent for the virtual root stack entry


def _parse_junos_hierarchical(text: str) -> list[ConfigNode]:
    """Parse JunOS bracketed hierarchical format (``{…}`` blocks)."""
    root_nodes: list[ConfigNode] = []
    stack: list[tuple[int, Optional[ConfigNode]]] = [(_ROOT_INDENT, None)]

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = _indent_level(raw_line)

        if stripped == "}":
            # Close current block — pop to parent
            if len(stack) > 1:
                stack.pop()
            continue

        # Strip trailing " {" to get the node key
        if stripped.endswith("{"):
            key = stripped[:-1].strip()
            node = ConfigNode(key=key, raw=raw_line, depth=indent)
            parent_indent, parent_node = stack[-1]
            if parent_node is None:
                root_nodes.append(node)
            else:
                parent_node.children.append(node)
            stack.append((indent, node))
        else:
            # Leaf line inside current block
            node = ConfigNode(key=stripped, raw=raw_line, depth=indent)
            _, parent_node = stack[-1]
            if parent_node is None:
                root_nodes.append(node)
            else:
                parent_node.children.append(node)

    return root_nodes


def _parse_flat(text: str) -> list[ConfigNode]:
    """Parse flat one-directive-per-line config."""
    nodes: list[ConfigNode] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("!"):
            continue
        nodes.append(ConfigNode(key=stripped, raw=raw_line, depth=0))
    return nodes


def parse_config(text: str, style: ConfigStyle = ConfigStyle.CISCO) -> list[ConfigNode]:
    """Parse *text* according to *style* and return a list of top-level nodes.

    Parameters
    ----------
    text:
        Raw configuration text.
    style:
        One of :class:`ConfigStyle`.  Use ``ConfigStyle.detect(text)`` to
        auto-detect.
    """
    if style == ConfigStyle.JUNOS:
        lines = text.splitlines()
        set_lines = sum(1 for ln in lines if ln.strip().startswith("set "))
        if set_lines > 0:
            return _parse_junos_set(lines)
        return _parse_junos_hierarchical(text)
    if style == ConfigStyle.FLAT:
        return _parse_flat(text)
    return _parse_cisco(text)


# ---------------------------------------------------------------------------
# Diff entry
# ---------------------------------------------------------------------------


@dataclass
class DiffEntry:
    """A single semantic diff entry."""

    kind: ChangeKind
    """Type of change."""

    path: list[str]
    """Breadcrumb path from the root to this node (list of key strings)."""

    before_lines: list[str]
    """Lines from the *before* config (for REMOVED / CHANGED)."""

    after_lines: list[str]
    """Lines from the *after* config (for ADDED / CHANGED)."""

    is_security: bool = False
    """True when any involved line is security-sensitive."""

    @property
    def section(self) -> str:
        """Human-readable section label (deepest non-trivial breadcrumb)."""
        return " > ".join(self.path) if self.path else "(root)"


# ---------------------------------------------------------------------------
# Diff algorithm
# ---------------------------------------------------------------------------


def _node_map(nodes: list[ConfigNode]) -> dict[str, ConfigNode]:
    """Return a ``{key: node}`` dict from a list of nodes.

    When duplicate keys exist (which can happen in flat/Cisco ACL sequences)
    the key is suffixed with ``#N`` so every entry is retained.
    """
    result: dict[str, ConfigNode] = {}
    counts: dict[str, int] = {}
    for node in nodes:
        base = node.key
        if base in result:
            # second occurrence: rename existing entry
            count = counts.get(base, 1)
            if count == 1:
                existing = result.pop(base)
                result[f"{base}#1"] = existing
            counts[base] = count + 1
            result[f"{base}#{counts[base]}"] = node
        else:
            result[base] = node
            counts[base] = 1
    return result


def _diff_nodes(
    before: list[ConfigNode],
    after: list[ConfigNode],
    path: list[str],
    entries: list[DiffEntry],
) -> None:
    """Recursively diff two lists of :class:`ConfigNode` objects."""
    before_map = _node_map(before)
    after_map = _node_map(after)

    all_keys = list(dict.fromkeys(list(before_map) + list(after_map)))

    for key in all_keys:
        b_node = before_map.get(key)
        a_node = after_map.get(key)
        node_path = path + [key]

        if b_node is None and a_node is not None:
            # Added
            lines = a_node.flat_lines()
            entries.append(
                DiffEntry(
                    kind=ChangeKind.ADDED,
                    path=node_path,
                    before_lines=[],
                    after_lines=lines,
                    is_security=a_node.is_security or any(_is_security_sensitive(ln) for ln in lines),
                )
            )
        elif b_node is not None and a_node is None:
            # Removed
            lines = b_node.flat_lines()
            entries.append(
                DiffEntry(
                    kind=ChangeKind.REMOVED,
                    path=node_path,
                    before_lines=lines,
                    after_lines=[],
                    is_security=b_node.is_security or any(_is_security_sensitive(ln) for ln in lines),
                )
            )
        else:
            # Both exist — check for changes
            assert b_node is not None and a_node is not None  # mypy
            if b_node.signature() == a_node.signature():
                # Identical subtrees (order-normalised) — skip
                continue
            if b_node.children or a_node.children:
                # Recurse into children
                _diff_nodes(b_node.children, a_node.children, node_path, entries)
            else:
                # Leaf changed
                is_sec = _is_security_sensitive(b_node.raw) or _is_security_sensitive(a_node.raw)
                entries.append(
                    DiffEntry(
                        kind=ChangeKind.CHANGED,
                        path=node_path,
                        before_lines=[b_node.raw],
                        after_lines=[a_node.raw],
                        is_security=is_sec,
                    )
                )


# ---------------------------------------------------------------------------
# DiffResult
# ---------------------------------------------------------------------------


@dataclass
class DiffResult:
    """Container for the full diff between two configs."""

    style: ConfigStyle
    """Parsing style used."""

    entries: list[DiffEntry] = field(default_factory=list)
    """All detected diff entries."""

    before_text: str = ""
    """Original *before* config text (used by unified formatter)."""

    after_text: str = ""
    """Original *after* config text (used by unified formatter)."""

    @property
    def has_changes(self) -> bool:
        """True when at least one non-unchanged entry exists."""
        return any(e.kind != ChangeKind.UNCHANGED for e in self.entries)

    @property
    def security_changes(self) -> list[DiffEntry]:
        """Return only entries that touch security-sensitive config."""
        return [e for e in self.entries if e.is_security]

    @property
    def added(self) -> list[DiffEntry]:
        """Return only entries representing newly added lines."""
        return [e for e in self.entries if e.kind == ChangeKind.ADDED]

    @property
    def removed(self) -> list[DiffEntry]:
        """Return only entries representing removed lines."""
        return [e for e in self.entries if e.kind == ChangeKind.REMOVED]

    @property
    def changed(self) -> list[DiffEntry]:
        """Return only entries representing modified lines."""
        return [e for e in self.entries if e.kind == ChangeKind.CHANGED]


# ---------------------------------------------------------------------------
# Public diff API
# ---------------------------------------------------------------------------


def diff_configs(
    before: str,
    after: str,
    *,
    style: Optional[ConfigStyle] = None,
) -> DiffResult:
    """Compare two config strings and return a :class:`DiffResult`.

    Parameters
    ----------
    before:
        The *before* (original / running) configuration text.
    after:
        The *after* (new / candidate) configuration text.
    style:
        Parsing style.  When *None* (default) the style is auto-detected from
        *before*.
    """
    if style is None:
        style = ConfigStyle.detect(before or after)

    before_nodes = parse_config(before, style)
    after_nodes = parse_config(after, style)

    entries: list[DiffEntry] = []
    _diff_nodes(before_nodes, after_nodes, [], entries)

    return DiffResult(
        style=style,
        entries=entries,
        before_text=before,
        after_text=after,
    )


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------


def format_unified(result: DiffResult, fromfile: str = "before", tofile: str = "after") -> str:
    """Return a classic unified diff string.

    Uses Python's :mod:`difflib` on the original text lines so the output is
    compatible with ``patch(1)``.
    """
    lines_a = result.before_text.splitlines(keepends=True)
    lines_b = result.after_text.splitlines(keepends=True)
    return "".join(difflib.unified_diff(lines_a, lines_b, fromfile=fromfile, tofile=tofile))


def format_semantic(result: DiffResult) -> str:
    """Return a human-readable semantic diff.

    Each change is prefixed with its parent breadcrumb so the operator sees
    full context.  Security-sensitive changes are marked with ``[SECURITY]``.
    """
    if not result.has_changes:
        return "No configuration changes detected.\n"

    lines: list[str] = []
    sep = "-" * 72

    counts = {
        ChangeKind.ADDED: len(result.added),
        ChangeKind.REMOVED: len(result.removed),
        ChangeKind.CHANGED: len(result.changed),
    }
    security_count = len(result.security_changes)

    lines.append(sep)
    lines.append(
        f"Config diff summary: +{counts[ChangeKind.ADDED]} added, "
        f"-{counts[ChangeKind.REMOVED]} removed, "
        f"~{counts[ChangeKind.CHANGED]} changed"
        + (f"  ⚠ {security_count} security-sensitive" if security_count else "")
    )
    lines.append(sep)

    for entry in result.entries:
        sec_tag = "  [SECURITY]" if entry.is_security else ""
        kind_sym = {"added": "+", "removed": "-", "changed": "~"}.get(entry.kind.value, " ")

        lines.append(f"\n{kind_sym} Section: {entry.section}{sec_tag}")

        if entry.before_lines and entry.after_lines:
            # Changed — show both sides
            for ln in entry.before_lines:
                lines.append(f"  - {ln.rstrip()}")
            for ln in entry.after_lines:
                lines.append(f"  + {ln.rstrip()}")
        elif entry.before_lines:
            for ln in entry.before_lines:
                lines.append(f"  - {ln.rstrip()}")
        else:
            for ln in entry.after_lines:
                lines.append(f"  + {ln.rstrip()}")

    lines.append(f"\n{sep}\n")
    return "\n".join(lines)


def format_json(result: DiffResult) -> str:
    """Return a JSON string representing the diff.

    The structure is::

        {
          "style": "cisco",
          "summary": {"added": 1, "removed": 0, "changed": 2, "security": 1},
          "entries": [
            {
              "kind": "added",
              "section": "interface GigabitEthernet0/0",
              "path": ["interface GigabitEthernet0/0"],
              "is_security": false,
              "before_lines": [],
              "after_lines": [" description WAN uplink"]
            },
            ...
          ]
        }
    """
    entries_data = []
    for entry in result.entries:
        entries_data.append(
            {
                "kind": entry.kind.value,
                "section": entry.section,
                "path": entry.path,
                "is_security": entry.is_security,
                "before_lines": entry.before_lines,
                "after_lines": entry.after_lines,
            }
        )

    payload = {
        "style": result.style.value,
        "summary": {
            "added": len(result.added),
            "removed": len(result.removed),
            "changed": len(result.changed),
            "security": len(result.security_changes),
        },
        "entries": entries_data,
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for the semantic config diff engine."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m netops.change.diff --before before.txt --after after.txt
  python -m netops.change.diff --before b.txt --after a.txt --format semantic
  python -m netops.change.diff --before b.txt --after a.txt --format json
  python -m netops.change.diff --before b.txt --after a.txt --style junos --format unified
""",
    )
    parser.add_argument("--before", required=True, metavar="FILE", help="Before (original) config file")
    parser.add_argument("--after", required=True, metavar="FILE", help="After (new) config file")
    parser.add_argument(
        "--format",
        choices=["unified", "semantic", "json"],
        default="semantic",
        help="Output format (default: semantic)",
    )
    parser.add_argument(
        "--style",
        choices=[s.value for s in ConfigStyle],
        default=None,
        help="Config syntax style (default: auto-detect)",
    )
    parser.add_argument(
        "--fail-on-change",
        action="store_true",
        help="Exit with code 1 if any changes are detected",
    )
    parser.add_argument(
        "--fail-on-security",
        action="store_true",
        help="Exit with code 2 if any security-sensitive changes are detected",
    )
    args = parser.parse_args()

    before_path = Path(args.before)
    after_path = Path(args.after)

    for p in (before_path, after_path):
        if not p.exists():
            print(f"❌  File not found: {p}", file=sys.stderr)
            sys.exit(1)

    before_text = before_path.read_text(encoding="utf-8")
    after_text = after_path.read_text(encoding="utf-8")

    style = ConfigStyle(args.style) if args.style else None
    result = diff_configs(before_text, after_text, style=style)

    if args.format == "unified":
        output = format_unified(result, fromfile=str(before_path), tofile=str(after_path))
    elif args.format == "json":
        output = format_json(result)
    else:
        output = format_semantic(result)

    print(output)

    if args.fail_on_security and result.security_changes:
        sys.exit(2)
    if args.fail_on_change and result.has_changes:
        sys.exit(1)


if __name__ == "__main__":
    main()
