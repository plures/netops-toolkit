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

::: netops.change.diff

---

## `netops.change.plan`

Change planning — risk assessment, step ordering, and dry-run simulation.

**CLI usage:**
```
python -m netops.change.plan plan --steps steps.yaml --dry-run
python -m netops.change.plan apply --plan plan.json --approve
```

::: netops.change.plan

---

## `netops.change.push`

Safe configuration push — pre/post health validation with automatic rollback.

**CLI usage:**
```
python -m netops.change.push --host 10.0.0.1 --vendor cisco_ios --config changes.txt
python -m netops.change.push --host 10.0.0.1 --vendor cisco_ios --config changes.txt --commit
python -m netops.change.push --host 10.0.0.1 --vendor cisco_ios --config changes.txt \
    --commit --rollback-on-failure
```

::: netops.change.push

---

## `netops.change.rollback`

Automated rollback — pre-snapshot + health monitoring with rollback on degradation.

**CLI usage:**
```
python -m netops.change.rollback --host 10.0.0.1 --vendor cisco_ios --config changes.txt \
    --commit --rollback-on-failure --validate-health
```

::: netops.change.rollback
