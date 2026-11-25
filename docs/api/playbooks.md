# `netops.playbooks` — Ansible Playbook Generation

Composable Ansible remediation playbook generation from health-check reports.

---

## `netops.playbooks.generator`

Generate Ansible remediation playbooks from structured health-check failure data.

**CLI usage:**
```
python -m netops.playbooks.generator --report health-report.json --output remediation.yml
python -m netops.playbooks.generator --report health-report.json --vendor cisco_ios
```

::: netops.playbooks.generator

Companion `compare.remediation-preview` / `compare.generate` reuse the native
guarded generator with deterministic bound identity and supplied observation/
report time. Unknown active check categories remain unsupported. Missing,
failed and unexecuted selected targets are retained; no YAML execution,
collection, apply or credential resolution occurs while generating.
No eligible plays yield `generated_yaml=null`; output review blocks instead of
authorizing an empty YAML artifact. Mixed valid output retains ordered selected
failed/unsupported/missing targets and a partial nonzero aggregate.
Generic command tasks retain all commands via a loop, and rollback device tasks
also obey the dry-run guard. Explicit output still requires the A02 owner's
exact admitted protected YAML save integration; preview is not that permission.
See [remediation architecture](https://github.com/plures/netops-toolkit/blob/main/documentation/playbooks/playbooks-architecture.md).

---

## `netops.playbooks.templates.remediation`

Built-in remediation templates for common network failure types.

Provides `REMEDIATION_TEMPLATES` — a dict mapping `FailureType` to
`RemediationTemplate` — and helper functions for looking up and rendering
templates.

::: netops.playbooks.templates.remediation
