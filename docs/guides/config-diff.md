# Config Diff Engine

The `netops.change.diff` module provides a semantic-aware configuration diff
engine that understands network device config structure rather than treating
configs as plain text.

## Features

- **Hierarchical parsing** – Cisco IOS/IOS-XE/IOS-XR indented style, JunOS
  set-format and bracketed hierarchical style, and flat one-directive-per-line
  configs.
- **Order-insensitive comparison** – two stanzas whose children are identical
  but in different order are not reported as changed (important for ACL
  sequences where only content matters).
- **Parent context** – changed leaf lines always carry the full breadcrumb path
  to their parent block so you immediately see *where* the change occurred.
- **Security highlighting** – changes to ACLs, authentication config, routing
  policy, SNMP community strings, and SSH keys are automatically flagged with
  `[SECURITY]`.
- **Three output formats** – `unified` (patch-compatible), `semantic`
  (human-readable tree view), and `json` (machine-readable for CI pipelines).

---

## Quick start

```bash
# Compare two config snapshots (semantic view, auto-detects style)
python -m netops.change.diff --before before.txt --after after.txt

# Unified diff (patch-compatible)
python -m netops.change.diff --before b.txt --after a.txt --format unified

# JSON output for CI
python -m netops.change.diff --before b.txt --after a.txt --format json

# Fail the pipeline if security-sensitive changes are detected
python -m netops.change.diff --before b.txt --after a.txt --fail-on-security

# Force JunOS style (skip auto-detection)
python -m netops.change.diff --before b.txt --after a.txt --style junos
```

---

## CLI reference

```
python -m netops.change.diff --before FILE --after FILE [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--before FILE` | — | Before (original / running) config file **(required)** |
| `--after FILE` | — | After (new / candidate) config file **(required)** |
| `--format FORMAT` | `semantic` | Output format: `unified`, `semantic`, or `json` |
| `--style STYLE` | auto-detect | Config syntax: `cisco`, `junos`, or `flat` |
| `--fail-on-change` | off | Exit code 1 if *any* change is detected |
| `--fail-on-security` | off | Exit code 2 if any security-sensitive change is detected |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (or no changes when `--fail-on-change` not set) |
| `1` | Changes detected (only when `--fail-on-change` is active) |
| `2` | Security-sensitive changes detected (`--fail-on-security`) |

---

## Output formats

### `semantic` (default)

```
------------------------------------------------------------------------
Config diff summary: +2 added, -0 removed, ~0 changed  ⚠ 1 security-sensitive
------------------------------------------------------------------------

+ Section: ip access-list extended PERMIT_WEB > permit tcp any any eq 8080  [SECURITY]
  +  permit tcp any any eq 8080

+ Section: interface GigabitEthernet0/0 > description WAN uplink
  +  description WAN uplink

------------------------------------------------------------------------
```

### `unified`

Classic unified diff compatible with `patch(1)` and most code-review tools.

```diff
--- before.txt
+++ after.txt
@@ -6,9 +6,11 @@
 ip access-list extended PERMIT_WEB
   permit tcp any any eq 80
   permit tcp any any eq 443
+  permit tcp any any eq 8080
 !
 interface GigabitEthernet0/0
   ip address 10.0.0.1 255.255.255.0
+  description WAN uplink
   no shutdown
```

### `json`

```json
{
  "style": "cisco",
  "summary": {
    "added": 2,
    "removed": 0,
    "changed": 0,
    "security": 1
  },
  "entries": [
    {
      "kind": "added",
      "section": "ip access-list extended PERMIT_WEB > permit tcp any any eq 8080",
      "path": ["ip access-list extended PERMIT_WEB", "permit tcp any any eq 8080"],
      "is_security": true,
      "before_lines": [],
      "after_lines": [" permit tcp any any eq 8080"]
    },
    {
      "kind": "added",
      "section": "interface GigabitEthernet0/0 > description WAN uplink",
      "path": ["interface GigabitEthernet0/0", "description WAN uplink"],
      "is_security": false,
      "before_lines": [],
      "after_lines": [" description WAN uplink"]
    }
  ]
}
```

---

## Programmatic API

```python
from netops.change.diff import (
    ConfigStyle,
    diff_configs,
    format_semantic,
    format_unified,
    format_json,
)

before = Path("before.txt").read_text()
after  = Path("after.txt").read_text()

# Auto-detect style
result = diff_configs(before, after)

# Or specify explicitly
result = diff_configs(before, after, style=ConfigStyle.CISCO)

print(f"Changes detected: {result.has_changes}")
print(f"Security changes: {len(result.security_changes)}")

# Iterate entries
for entry in result.entries:
    print(f"[{entry.kind.value}] {entry.section}")
    if entry.is_security:
        print("  *** SECURITY-SENSITIVE ***")

# Format output
print(format_semantic(result))
print(format_json(result))
```

### `DiffResult` properties

| Property | Type | Description |
|----------|------|-------------|
| `has_changes` | `bool` | `True` when at least one change exists |
| `entries` | `list[DiffEntry]` | All diff entries |
| `added` | `list[DiffEntry]` | Only added entries |
| `removed` | `list[DiffEntry]` | Only removed entries |
| `changed` | `list[DiffEntry]` | Only changed (leaf) entries |
| `security_changes` | `list[DiffEntry]` | Entries touching security config |
| `style` | `ConfigStyle` | Parsing style used |

### `DiffEntry` fields

| Field | Type | Description |
|-------|------|-------------|
| `kind` | `ChangeKind` | `added`, `removed`, or `changed` |
| `path` | `list[str]` | Breadcrumb from root to this node |
| `section` | `str` | Human-readable section label (`" > "` joined path) |
| `is_security` | `bool` | `True` when this entry touches security config |
| `before_lines` | `list[str]` | Lines from before config (empty for added) |
| `after_lines` | `list[str]` | Lines from after config (empty for removed) |

---

## Supported config styles

### Cisco (`cisco`, auto-detected)

IOS / IOS-XE / IOS-XR indented hierarchical format.

```
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
ip access-list extended PERMIT_WEB
 permit tcp any any eq 80
 permit tcp any any eq 443
```

### JunOS (`junos`, auto-detected)

Both **set-format** and **bracketed hierarchical** format are supported.
The engine auto-selects between them based on whether `set ` prefix lines
exceed 40% of the config.

```
# set-format
set system host-name router1
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24

# bracketed hierarchical
system {
    host-name router1;
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
```

### Flat (`flat`)

One directive per line. Nokia SR-OS and similar.

```
configure
    system name router1
    interface eth0 address 10.0.0.1/24
commit
```

---

## Security-sensitive patterns

The following config constructs are automatically flagged as security-sensitive:

| Category | Examples |
|----------|---------|
| ACLs | `ip access-list`, `access-group`, `permit`/`deny` lines |
| Authentication | `username`, `password`, `secret`, `enable secret` |
| AAA | `aaa authentication`, `aaa authorization`, `aaa accounting` |
| TACACS / RADIUS | `tacacs-server`, `radius-server` |
| Routing policy | `route-map`, `prefix-list`, `community-list`, `route-policy` |
| SNMP | `snmp-server community`, `snmp-server host`, `snmp-server user` |
| SSH | `ip ssh`, `crypto key` |
| NTP auth | `ntp authenticate`, `ntp authentication-key` |
| Firewall | `firewall`, `security-policy`, `policy-map type inspect` |
| JunOS login | `login user`, `system login` |

---

## Integration with change push workflow

The diff engine integrates naturally with
[`netops.change.push`](../guides/cli-reference.md#netopschangepush--safe-config-push)
— capture pre/post snapshots with `push.py` and then run `diff.py` to get a
structured view of what changed:

```bash
# 1. Snapshot before
python -m netops.collect.config --host router1 --out before.txt

# 2. Apply change
python -m netops.change.push --host router1 --commands changes.txt --commit

# 3. Snapshot after
python -m netops.collect.config --host router1 --out after.txt

# 4. Semantic diff with CI-safe exit codes
python -m netops.change.diff \
  --before before.txt \
  --after after.txt \
  --format json \
  --fail-on-security
```
