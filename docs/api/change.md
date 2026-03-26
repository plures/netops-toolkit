# `netops.change` — Configuration Change Management

Semantic diff, change planning, safe push, and automated rollback.

---

## `netops.change.diff`

Semantic-aware configuration diff engine.

Understands network device config structure rather than treating configs as
plain text. Supports three input formats:

- **cisco** — IOS/IOS-XE/IOS-XR indented hierarchical style
- **junos** — JunOS set-format *or* bracketed hierarchical style
- **flat** — one directive per line (Nokia SR-OS, simple key/value)

Three output formats are available:

- **unified** — classic unified diff (compatible with `patch(1)`)
- **semantic** — human-readable tree view with parent context and highlights
- **json** — machine-readable dict suitable for programmatic consumption

**CLI usage:**
```
python -m netops.change.diff --before before.txt --after after.txt
python -m netops.change.diff --before b.txt --after a.txt --format semantic
python -m netops.change.diff --before b.txt --after a.txt --format json
```

**Public API:**
```python
from netops.change.diff import diff_configs, format_unified, format_semantic, format_json

result = diff_configs(before_text, after_text, style="cisco")
print(format_semantic(result))
```

### Classes

#### `ConfigStyle`

Config syntax style used for hierarchical parsing.

**Methods:**

##### `detect(text: str) -> 'ConfigStyle'`  *(classmethod)*
Heuristically detect the config style from *text*.

---

#### `ChangeKind`

Type of diff change (`added`, `removed`, `changed`, `unchanged`).

---

#### `ConfigNode`

One node in the hierarchical config tree.

For **cisco** style each node corresponds to a block header (e.g.
`interface GigabitEthernet0/0`) or a leaf line inside that block. For
**junos** set-format each `set …` directive is stored as a flat node with
its full path as `key`. For **flat** style each non-blank, non-comment line
is a leaf node.

**Fields:**
- `key: str` — node key / directive text
- `raw: str` — original raw line
- `children: list['ConfigNode']` — child nodes (default: `[]`)
- `depth: int` — indentation depth (default: `0`)
- `is_security: bool` — marks security-sensitive config (default: `False`)

**Methods:**

##### `flat_lines() -> list[str]`
Return all lines in this subtree as a flat list (DFS order).

##### `signature() -> str`
Return a string that uniquely identifies this node's *content*. For leaf
nodes this is the stripped line itself. For block headers it is
`header + sorted(child signatures)` so that reordering children (where
order does not matter) does not produce a diff.

---

#### `DiffEntry`

A single semantic diff entry.

**Fields:**
- `kind: ChangeKind` — type of change
- `path: list[str]` — breadcrumb path from root to this entry
- `before_lines: list[str]` — original lines
- `after_lines: list[str]` — new lines
- `is_security: bool` — marks security-sensitive change (default: `False`)

**Methods:**

##### `section() -> str`
Human-readable section label (deepest non-trivial breadcrumb).

---

#### `DiffResult`

Container for the full diff between two configs.

**Fields:**
- `style: ConfigStyle` — detected or specified config style
- `entries: list[DiffEntry]` — list of diff entries (default: `[]`)
- `before_text: str` — original config text (default: `""`)
- `after_text: str` — new config text (default: `""`)

**Methods:**

##### `has_changes() -> bool`
`True` when at least one non-unchanged entry exists.

##### `security_changes() -> list[DiffEntry]`
Return only entries that touch security-sensitive config.

##### `added() -> list[DiffEntry]`
Return only entries representing newly added lines.

##### `removed() -> list[DiffEntry]`
Return only entries representing removed lines.

##### `changed() -> list[DiffEntry]`
Return only entries representing modified lines.

### Functions

#### `parse_config(text: str, style: ConfigStyle = ConfigStyle.CISCO) -> list[ConfigNode]`
Parse *text* according to *style* and return a list of top-level nodes.

**Parameters:**
- `text` — raw configuration text
- `style` — one of `ConfigStyle`; use `ConfigStyle.detect(text)` to auto-detect

#### `diff_configs(before: str, after: str, style: Optional[ConfigStyle] = None) -> DiffResult`
Compare two config strings and return a `DiffResult`.

**Parameters:**
- `before` — the *before* (original / running) configuration text
- `after` — the *after* (new / candidate) configuration text
- `style` — parsing style; when `None` (default) the style is auto-detected from *before*

#### `format_unified(result: DiffResult, fromfile: str = 'before', tofile: str = 'after') -> str`
Return a classic unified diff string. Uses Python's `difflib` on the
original text lines so the output is compatible with `patch(1)`.

#### `format_semantic(result: DiffResult) -> str`
Return a human-readable semantic diff. Each change is prefixed with its
parent breadcrumb so the operator sees full context. Security-sensitive
changes are marked with `[SECURITY]`.

#### `format_json(result: DiffResult) -> str`
Return a JSON string representing the diff.

#### `main() -> None`
CLI entry point for the semantic config diff engine.

---

## `netops.change.plan`

Change approval workflow: plan → dry-run → review → approve → execute.

**Workflow:**
1. Call `generate_plan` with the *desired* config text and the *current*
   (running) config text for one or more devices.
2. Inspect the returned `ChangePlan`. The plan includes a human-readable
   preview (semantic diff), risk score, and per-device `ChangeStep` list.
3. Export the plan to JSON/YAML for offline review with `export_plan`.
4. When approved, call `apply_plan` (requires `approved=True`). Dry-run mode
   never modifies any device.

**CLI usage:**
```
python -m netops.change.plan plan \
    --host router1 --desired new_config.txt
python -m netops.change.plan plan \
    --host router1 --desired new_config.txt --export plan.json
python -m netops.change.plan apply --plan plan.json --approve
```

### Classes

#### `RiskLevel`

Overall risk classification for a change plan (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

---

#### `DeviceRole`

Criticality classification of a network device. Roles are ordered from
lowest (ACCESS) to highest (CORE) criticality. The role influences the
risk score of any change on that device.

**Methods:**

##### `weight() -> int`
Return the numeric risk weight for this role (higher value = greater risk).

---

#### `ChangeStep`

A single per-device step inside a `ChangePlan`.

**Fields:**
- `host: str` — target device hostname or IP
- `device_type: str` — Netmiko device type string
- `device_role: DeviceRole` — device criticality classification
- `commands: list[str]` — ordered list of configuration commands
- `current_config: str` — *before* config text (default: `""`)
- `desired_config: str` — *after* / target config text (default: `""`)
- `diff_preview: str` — human-readable semantic diff (default: `""`)
- `unified_diff: str` — unified diff string (default: `""`)
- `has_security_changes: bool` — `True` when diff touches security config (default: `False`)
- `applied: bool` — `True` after successful execution (default: `False`)
- `error: Optional[str]` — error message on failure (default: `None`)

---

#### `ChangePlan`

Full change plan: metadata + one `ChangeStep` per device.

**Fields:**
- `plan_id: str` — unique plan identifier (UUID)
- `created_at: str` — ISO-8601 creation timestamp
- `operator: str` — human-readable name of the person or system creating the plan
- `description: str` — free-text plan description or ticket reference
- `steps: list[ChangeStep]` — per-device steps (default: `[]`)
- `risk_level: RiskLevel` — overall risk classification (default: `LOW`)
- `risk_score: float` — computed numeric risk score (default: `0.0`)
- `dry_run: bool` — when `True`, no device changes are made (default: `True`)
- `approved: bool` — must be set to `True` before applying (default: `False`)
- `applied_at: Optional[str]` — ISO-8601 apply timestamp (default: `None`)
- `changelog_path: Optional[str]` — path to JSON-lines changelog (default: `None`)

### Functions

#### `generate_plan(steps_input: list[dict], operator: str = '', description: str = '', config_style: Optional[ConfigStyle] = None) -> ChangePlan`
Generate a `ChangePlan` from desired-vs-current state.

**Parameters:**
- `steps_input` — list of per-device dicts with keys: `host` (required),
  `device_type` (optional), `device_role` (optional), `commands` (optional),
  `current_config` (optional), `desired_config` (optional)
- `operator` — human-readable name of the person generating the plan
- `description` — free-text plan description or ticket reference
- `config_style` — force a specific `ConfigStyle`; `None` = auto-detect

Returns a fully populated plan ready for export or review. The plan is **never**
applied here — call `apply_plan` for that.

#### `apply_plan(plan: ChangePlan, connection_params: Optional[list[ConnectionParams]] = None, approved: bool = False, changelog_path: Optional[Path] = None) -> ChangePlan`
Apply an approved `ChangePlan` to the target devices.

**Dry-run guarantee:** if `approved` is `False` (the default) this function
immediately returns the plan unchanged — no device is ever modified.

**Parameters:**
- `plan` — the plan to apply
- `connection_params` — list of `ConnectionParams`, one per step, in the same order as `plan.steps`; required when `approved` is `True`
- `approved` — must be explicitly set to `True` to allow device modifications
- `changelog_path` — optional path to a JSON-lines file; the applied plan dict is appended after successful completion

#### `export_plan(plan: ChangePlan, path: Path, fmt: str = 'json') -> None`
Write *plan* to *path* in JSON or YAML format.

**Parameters:**
- `plan` — the plan to serialise
- `path` — destination file path; parent directories are created if needed
- `fmt` — `"json"` (default) or `"yaml"`

Raises `ValueError` when `fmt` is not `"json"` or `"yaml"`.

#### `load_plan(path: Path) -> ChangePlan`
Load a `ChangePlan` from a JSON or YAML file. Format is auto-detected from
the file extension (`.yaml`/`.yml` → YAML; everything else → JSON).

Raises `FileNotFoundError` when *path* does not exist.

#### `main() -> None`
CLI entry point for the change-plan generator and applier.

---

## `netops.change.push`

Safe configuration push with pre/post diff and auto-rollback confirm timer.

**Workflow:**
1. Connect to the device and snapshot the running config (pre-change).
2. Optionally push the given commands (requires `--commit` flag; dry-run by default).
3. Snapshot the config again (post-change) and compute a unified diff.
4. If `--confirm-timer N` is set, start a countdown. The operator must type
   `confirm` within *N* minutes or the pre-change config is restored (rollback).
5. Append a structured entry to a JSON-lines change log.

**CLI usage:**
```
python -m netops.change.push --host router1 --commands changes.txt
python -m netops.change.push --host router1 --commands changes.txt \
    --commit --confirm-timer 5
```

### Classes

#### `ChangeRecord`

Captures every meaningful attribute of a single config-push event.

**Fields:**
- `host: str` — target device hostname or IP
- `operator: str` — identifier of the person/system executing the change
- `started_at: str` — ISO-8601 start timestamp
- `commands: list[str]` — ordered list of commands that were (or would be) pushed
- `pre_config: str` — running config snapshot before the change
- `post_config: Optional[str]` — running config snapshot after the change (default: `None`)
- `diff: Optional[str]` — unified diff between pre and post configs (default: `None`)
- `committed: bool` — `True` when commands were actually sent (default: `False`)
- `confirmed: bool` — `True` when operator confirmed (default: `False`)
- `rolled_back: bool` — `True` when pre-change config was restored (default: `False`)
- `error: Optional[str]` — error message on failure (default: `None`)

### Functions

#### `run_push(params: ConnectionParams, commands: list[str], commit: bool = False, confirm_timer_minutes: int = 0, operator: str = '', changelog_path: Optional[Path] = None) -> ChangeRecord`
Execute the full safe-push workflow.

**Parameters:**
- `params` — connection parameters for the target device
- `commands` — ordered list of configuration commands to apply
- `commit` — when `False` (default) snapshot + diff are generated but nothing is pushed
- `confirm_timer_minutes` — if > 0 the operator must confirm within this many minutes or the pre-change config is restored
- `operator` — human-readable identifier of the person executing the change
- `changelog_path` — optional path to a JSON-lines changelog file; each call appends one record

#### `append_changelog(record: ChangeRecord, path: Path) -> None`
Append *record* as a JSON object to a newline-delimited log file.

#### `load_changelog(path: Path) -> list[dict]`
Return all change records from *path* as a list of dicts.

#### `main() -> None`
CLI entry point for safe config-push with pre/post diff and optional auto-rollback.

---

## `netops.change.rollback`

Automated rollback with pre/post health validation.

**Workflow:**
1. Connect to the device and capture the running configuration and health-check baseline.
2. Optionally save the snapshot via backup integration.
3. Apply the configuration change (requires `--commit`; dry-run by default).
4. Re-run health checks and capture a post-change snapshot + unified diff.
5. Compare pre/post health: any new alert → validation FAILED; unreachable → validation FAILED.
6. On failure (when `--rollback-on-failure` is set): restore the pre-change configuration.
7. Write a structured entry to a JSON-lines audit log.

**CLI usage:**
```
python -m netops.change.rollback --host router1 --commands changes.txt
python -m netops.change.rollback --host router1 --commands changes.txt \
    --commit --rollback-on-failure --validate-health
python -m netops.change.rollback --host router1 --commands changes.txt \
    --commit --rollback-on-failure --validate-health \
    --snapshot-dir /var/backups/network --cpu-threshold 70
```

### Classes

#### `RollbackRecord`

Full audit record for a single change-with-rollback event.

**Fields:**
- `change_id: str` — unique change identifier (UUID)
- `host: str` — target device hostname or IP
- `operator: str` — identifier of the person/system executing the change
- `reason: str` — change rationale or ticket reference
- `started_at: str` — ISO-8601 start timestamp
- `commands: list[str]` — ordered list of commands applied
- `pre_config: str` — running config snapshot before the change (default: `""`)
- `post_config: Optional[str]` — running config snapshot after the change (default: `None`)
- `diff: Optional[str]` — unified diff between pre and post configs (default: `None`)
- `pre_health: Optional[dict]` — health-check result before the change (default: `None`)
- `post_health: Optional[dict]` — health-check result after the change (default: `None`)
- `committed: bool` — `True` when commands were actually sent (default: `False`)
- `validation_passed: Optional[bool]` — result of health validation (default: `None`)
- `rolled_back: bool` — `True` when pre-change config was restored (default: `False`)
- `rollback_reason: Optional[str]` — reason for rollback if triggered (default: `None`)
- `snapshot_path: Optional[str]` — path to the saved pre-change snapshot (default: `None`)
- `completed_at: Optional[str]` — ISO-8601 completion timestamp (default: `None`)
- `error: Optional[str]` — error message on failure (default: `None`)

### Functions

#### `run_rollback_push(params: ConnectionParams, commands: list[str], commit: bool = False, validate_health: bool = True, rollback_on_failure: bool = True, cpu_threshold: float = DEFAULT_CPU_THRESHOLD, mem_threshold: float = DEFAULT_MEM_THRESHOLD, operator: str = '', reason: str = '', audit_log_path: Optional[Path] = None, snapshot_dir: Optional[Path] = None) -> RollbackRecord`
Execute a configuration change with pre/post health validation.

**Parameters:**
- `params` — connection parameters for the target device
- `commands` — ordered list of configuration commands to apply
- `commit` — when `False` (default) only a pre-change snapshot (and health check if enabled) are collected
- `validate_health` — when `True` run health checks before and after the change
- `rollback_on_failure` — when `True` automatically restore the pre-change config if validation fails
- `cpu_threshold` / `mem_threshold` — alert thresholds (%) forwarded to `run_health_check`
- `operator` — human-readable identifier of the person executing the change
- `reason` — change rationale or ticket reference written to the audit log
- `audit_log_path` — optional path to a JSON-lines audit log
- `snapshot_dir` — optional directory where pre-change snapshots are saved

#### `append_audit_log(record: RollbackRecord, path: Path) -> None`
Append *record* as a JSON object to a newline-delimited audit log file.

#### `load_audit_log(path: Path) -> list[dict]`
Return all audit records from *path* as a list of dicts.

#### `main() -> None`
CLI entry point for config push with health-validated auto-rollback.
