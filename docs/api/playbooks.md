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

---

## `netops.playbooks.templates.remediation`

Built-in remediation templates for common network failure types.

Provides `REMEDIATION_TEMPLATES` — a dict mapping `FailureType` to
`RemediationTemplate` — and helper functions for looking up and rendering
templates.

::: netops.playbooks.templates.remediation
