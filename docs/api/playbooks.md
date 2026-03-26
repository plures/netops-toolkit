# `netops.playbooks` — Ansible Playbook Generation

Auto-generate Ansible remediation playbooks from health check failures.

---

## `netops.playbooks.generator`

Playbook generator — auto-generate Ansible remediation playbooks from health
check failures.

Reads a health check report (produced by `netops.check.health.run_health_check`
or `netops.check.health.build_health_report`) and generates valid Ansible YAML
playbooks for each device with active alerts.

Generated playbooks:
- Use **vendor-specific** Ansible collection modules (e.g. `cisco.ios.ios_command`)
- Include **pre/post validation** tasks that capture device state before and after remediation
- Wrap each remediation in a `block/rescue` structure so the `rescue` section runs rollback tasks on failure
- Default to **dry-run mode** (`dry_run: "true"` variable) — remediation tasks are guarded by `when: not dry_run | bool`
- Prompt for **human review** before executing remediation (unless `--no-pause` is passed)

**CLI usage:**
```
python -m netops.playbooks.generator generate \
    --from-health-report health_report.json
python -m netops.playbooks.generator generate \
    --from-health-report health_report.json \
    --output-dir ./remediation-playbooks/
python -m netops.playbooks.generator generate \
    --from-health-report health_report.json \
    --vendor cisco_ios_xr
python -m netops.playbooks.generator generate \
    --from-health-report health_report.json \
    --live
```

### Classes

#### `FailureType`

Health-check failure categories that can be remediated.

Enum values: `CPU`, `MEMORY`, `INTERFACE_ERRORS`, `LOGS`, `BGP`, `OSPF`,
`ENVIRONMENT`, `MLAG`, `FPC`, `ALARMS`.

---

#### `GeneratedPlaybook`

A complete Ansible playbook generated from health-check failures.

**Fields:**
- `playbook_id: str` — UUID string for correlation with health report entries
- `host: str` — Ansible inventory hostname / IP targeted by the playbook
- `vendor: str` — device type string (e.g. `cisco_ios`) used to select the correct Ansible collection modules
- `failure_types: list[FailureType]` — failure types detected and addressed
- `description: str` — human-readable summary used in the top-level play name
- `plays: list[dict]` — list of Ansible play dicts ready for serialisation to YAML
- `dry_run: bool` — when `True` the vars block sets `dry_run: "true"` (default: `True`)
- `created_at: str` — ISO-8601 UTC timestamp of generation (default: `""`)
- `source_report_timestamp: str` — timestamp from the originating health check result (default: `""`)

**Methods:**

##### `to_yaml() -> str`
Serialise the playbook plays to Ansible-compatible YAML.

##### `to_dict() -> dict`
Return a JSON-serialisable dict representation of this playbook.

### Functions

#### `extract_failures(health_result: dict) -> list[tuple[FailureType, dict]]`
Extract alerting checks from a single device health-check result.

**Parameters:**
- `health_result` — a result dict as returned by `run_health_check` or a vendor-specific equivalent; must contain a `"checks"` key mapping check names to check result dicts with an `"alert"` boolean

Returns an ordered list of `(failure_type, check_detail)` pairs for every
check where `alert` is `True`.

#### `generate_playbook(health_result: dict, vendor: Optional[str] = None, dry_run: bool = True, include_pause: bool = True) -> Optional[GeneratedPlaybook]`
Generate a remediation playbook from a single device health-check result.

**Parameters:**
- `health_result` — a result dict as returned by `run_health_check`
- `vendor` — override the device vendor string; when `None`, taken from `health_result["device_type"]` if present
- `dry_run` — when `True` (default), remediation tasks are gated behind `when: not dry_run | bool`
- `include_pause` — when `True`, inserts a `ansible.builtin.pause` task that requires operator acknowledgement

Returns a `GeneratedPlaybook` when at least one alerting check is found.
Returns `None` when the device has no active alerts or the result is not
successful.

#### `generate_playbooks_from_report(health_report: dict, vendor: Optional[str] = None, dry_run: bool = True, include_pause: bool = True, host_filter: Optional[str] = None) -> list[GeneratedPlaybook]`
Generate remediation playbooks from an aggregated health report.

Accepts the dict returned by `build_health_report` (which contains a
`"results"` list) **or** a bare list of per-device health results.

**Parameters:**
- `health_report` — dict with a `"results"` key or a bare list of per-device health result dicts
- `vendor` — global vendor override; per-device `device_type` fields take precedence when `None`
- `dry_run` — passed to `generate_playbook` for every device
- `include_pause` — passed to `generate_playbook` for every device
- `host_filter` — when given, only generate a playbook for the device whose `host` field matches this value (case-insensitive substring match)

Returns one `GeneratedPlaybook` per device that has at least one active alert.

#### `main() -> None`
CLI entry point for the remediation playbook generator.

---

## `netops.playbooks.templates.remediation`

Vendor-specific remediation templates for playbook generation.

Each `RemediationTemplate` encapsulates the commands needed to pre-validate
device state, remediate the failure condition, post-validate the remediation,
and rollback when possible.

Vendor command modules are mapped by `VENDOR_COMMAND_MODULE` and
`VENDOR_CONFIG_MODULE` dicts so that the generator picks the correct Ansible
collection for each platform.

**Module-level constants:**
- `REMEDIATION_TEMPLATES: dict[str, RemediationTemplate]` — mapping from `FailureType` value to the corresponding template
- `VENDOR_COMMAND_MODULE: dict[str, str]` — mapping from vendor device type to Ansible command module (e.g. `"cisco_ios"` → `"cisco.ios.ios_command"`)
- `VENDOR_CONFIG_MODULE: dict[str, str]` — mapping from vendor device type to Ansible config module

### Classes

#### `RemediationTemplate`

Vendor-specific command sets for a single remediation action.

**Fields:**
- `failure_type: str` — the `FailureType` string value this template targets
- `description: str` — human-readable description shown in generated playbook task names
- `pre_commands: dict[str, list[str]]` — mapping from vendor `device_type` (plus `_default`) to list of commands run *before* remediation for state capture (default: `{}`)
- `remediation_commands: dict[str, list[str]]` — mapping from vendor to remediation commands; `None` or empty means "no automated remediation available" (default: `{}`)
- `post_commands: dict[str, list[str]]` — mapping from vendor to post-validation commands (default: `{}`)
- `rollback_commands: dict[str, list[str]]` — mapping from vendor to rollback/undo commands; empty when the action cannot be rolled back (default: `{}`)
- `rollback_note: str` — human-readable note explaining rollback behaviour or limitations (default: `""`)

**Methods:**

##### `commands_for(vendor: str, kind: str) -> list[str]`
Return the command list for *vendor* in *kind* (`pre`, `remediation`, `post`, or `rollback`).

Falls back to `_default` when the specific vendor is not listed. Returns an
empty list when neither vendor nor default exists.

### Functions

#### `get_template(failure_type: str) -> Optional[RemediationTemplate]`
Return the `RemediationTemplate` for *failure_type*, or `None`.
