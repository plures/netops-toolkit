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

Bound companion comparison independently validates loaded bytes, source
kind/digest and paired parser/vendor identity before invoking this native owner.
Explicit `cisco`, `junos` and `flat` parser selectors and retained `parser-1`
autodetection are supported. Paired namespaced source revisions, such as
`collector-parser-v2` / `collector-vendor-v2`, identify source provenance rather
than select a parser. Their namespace and positive revision must agree, and
both snapshots must retain the exact same parser/vendor pair. They use native
autodetection with the original decoded bytes, including case and final
newlines; no source normalization or rehash substitutes for the bound input.
Unsupported/mismatched identities and malformed
Junos/mixed syntax reject safely; missing configuration is blocked rather than
healthy absence. Native Junos bracket detection and repeated directive retention
also apply to ordinary native calls. No preview collection, device I/O, hidden
source reopen, credential resolution, logging or clock access is introduced.
See [comparison architecture](https://github.com/plures/netops-toolkit/blob/main/documentation/change/change-architecture.md).

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
python -m netops.change.plan plan --host 10.0.0.1 --desired desired.cfg --export plan.json
python -m netops.change.plan apply --plan plan.json --approve
```

::: netops.change.plan

---

## `netops.change.push`

Safe configuration push — pre/post health validation with automatic rollback.

**CLI usage:**
```
python -m netops.change.push --host 10.0.0.1 --vendor cisco_ios --commands changes.txt
python -m netops.change.push --host 10.0.0.1 --vendor cisco_ios --commands changes.txt --commit
python -m netops.change.rollback --host 10.0.0.1 --vendor cisco_ios --commands changes.txt \
    --commit --rollback-on-failure --validate-health
```

::: netops.change.push

The optional `run_push(..., hooks=PushHooks)` seam is for a trusted companion,
not a reusable confirmation bypass. It injects an exact selected connection,
checks cancellation/current authority immediately before issuance, requires a
measured protected prestate, and confirms only an observed approved poststate.
With hooks, raw changelog paths and interactive confirmation timers reject
before I/O; returned records omit raw pre/post configuration and diffs, and
exceptions use safe error codes. Ordinary calls without hooks retain their
existing behavior. Hooked apply does not automatically restore on an exception:
the companion must enter a separately authorized fixed recovery occurrence.
See [guarded mutation boundaries](ansible.md#guarded-native-configuration-mutation-a02-inert-adapter-qualification).

---

## `netops.change.rollback`

Automated rollback — pre-snapshot + health monitoring with rollback on degradation.

**CLI usage:**
```
python -m netops.change.rollback --host 10.0.0.1 --vendor cisco_ios --commands changes.txt \
    --commit --rollback-on-failure --validate-health
```

::: netops.change.rollback
