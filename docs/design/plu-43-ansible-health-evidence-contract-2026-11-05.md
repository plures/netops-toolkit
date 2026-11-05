# PLU-43: Ansible facts-to-health fail-closed contract — review v0.1

**Date:** 2026-11-05. **Scope:** Source-backed design/evidence. No production changes. M1 engineering preflight only, not construction approval.

## Direct source audit

Inspected the default branch in plures/netops-toolkit before proposing changes:

| Producer | Actual output or interface | Consumer expectation | Failure |
|---|---|---|---|
| parsers/health.py Cisco CPU | five_seconds, one_minute, five_minutes | netops_facts._gather_health reads five_sec_cpu | Null CPU metric despite valid output |
| parsers/health.py Nokia CPU | avg, peak | netops_facts reads five_sec_cpu | Null CPU metric despite valid output |
| Cisco/Nokia memory parsers | total, used, free, utilization | netops_facts reads total_bytes and used_bytes | Zero total or omitted memory utilization |
| Cisco interface errors parser | detail-format interface header and counter lines | netops_facts sends show interfaces status (table format) | Missing interface evidence returned as empty list |
| netops_facts Ansible gather choices | health, interfaces, bgp, vlans, all | netops_health role passes cpu, memory, ospf and sometimes empty strings | Invalid gather selector |
| netops_facts return shape | ansible_facts.netops.health.cpu_percent / memory_percent | netops_health role asserts flat netops_cpu / netops_memory_used_pct | Missing values can pass via default(0) |
| Molecule role mock | flat netops_cpu and memory_used_pct | real module emits nested netops.health | Mock does not cover integration contract |
| Unsupported vendor and exceptions | Cisco fallback and broad exception suppression | safety decision assumes metric coverage | Incomplete or incorrect facts have no provenance |

Source paths:
- netops/ansible/modules/netops_facts.py
- netops/parsers/health.py
- netops/ansible/roles/netops_health/tasks/main.yml
- netops/ansible/roles/netops_health/defaults/main.yml
- netops/ansible/roles/netops_health/molecule/default/converge.yml and verify.yml

This is a **static software defect**, not proof of a customer incident. The fact collection interface must not be used as a safety-grade post-change health gate in its present state.

## Proposed stable contract

Maintain ansible_facts.netops.health for observed scalar measurements, introducing a separate ansible_facts.netops.evidence object containing category-level status, source command, and reason code. Use statuses OBSERVED, UNKNOWN, UNSUPPORTED, NOT_REQUESTED. Do not emit a fabricated numeric value for missing measurements. A policy may evaluate HEALTHY / ALERT / UNKNOWN from valid, current, observed metrics and configured thresholds.

Examples:
- Observed CPU 0%: OBSERVED (valid); not the same as missing.
- CPU parser failed: UNKNOWN; no cpu_percent field, never 0 via fallback.
- Inventory-only interface discovery: preserve partial records with evidence UNKNOWN when the parser/command cannot prove health.
- Post-change validation: any required UNKNOWN blocks the success path; a reachable host or Ansible changed=false is not evidence of health.
- A BGP/OSPF check that is not supported or not configured as an expected requirement must be explicitly excluded, not silently treated as healthy.

## Safety invariants

1. Reject unknown vendor, command error, empty output, malformed parser output, NaN/infinite/out-of-range percentages and inconsistent memory totals. Never use Cisco fallback for other vendors.
2. CPU key mapping is Cisco five_seconds (if this observation window is selected) versus Nokia avg. Memory fields are total, used and utilization. Require 0 <= percent <= 100, total > 0, and 0 <= used <= total.
3. Interface inventory and detailed counter telemetry are different products. Never send the output of show interfaces status into a detail-counter parser. Require real input/output counter observations before classifying errors.
4. Never pass unsupported Ansible gather choices, empty string selectors, or unsupported OSPF directly to netops_facts.
5. Threshold assertions must read nested measured fields and fail on absent evidence rather than default(0); coverage must be explicit.
6. Preserve inventory-only workflows with partial fact visibility, but fail closed on monitoring and automated change acceptance.
7. Do not expose raw CLI data, credentials, subscriber identifiers or endpoint names through community telemetry without scoped authorization.

## Acceptance matrix

| ID | Synthetic scenario | Expected |
|---|---|---|
| AF-01 | Cisco CPU 0% observed | OBSERVED zero |
| AF-02 | CPU exceeds configured threshold | ALERT |
| AF-03 | Cisco utilization line missing | UNKNOWN |
| AF-04 | Nokia valid avg and peak | Correct selected avg observed |
| AF-05 | CPU transport exception | UNKNOWN with nonsecret reason |
| AF-06 | Unsupported vendor | UNSUPPORTED; no Cisco fallback |
| AF-07 | Cisco memory valid total/used | Correct percent and bytes |
| AF-08 | Nokia memory used plus available | Correct percent and bytes |
| AF-09 | Zero total or used greater than total | UNKNOWN |
| AF-10 | NaN, Infinity, nonnumeric or out-of-range | UNKNOWN |
| AF-11 | Cisco show interfaces status table | Inventory only; no invented counters |
| AF-12 | Interface header without counters | UNKNOWN |
| AF-13 | Observed input and output errors zero | OBSERVED zero |
| AF-14 | Observed nonzero input errors | ALERT |
| AF-15 | Empty or malformed interface output | UNKNOWN |
| AF-16 | BGP empty while BGP required | UNKNOWN |
| AF-17 | Unsupported OSPF selector | Visible failure, not silently dropped |
| AF-18 | Empty gather list member | Rejected before module invocation |
| AF-19 | Nested measured values below thresholds | HEALTHY |
| AF-20 | Nested CPU missing with fail-on-critical | UNKNOWN and fail |
| AF-21 | Partial inventory-only evidence | Partial facts with coverage status |
| AF-22 | Partial post-change evidence | Fail closed; block success |
| AF-23 | Molecule uses actual nested return shape | Assert correct contract |
| AF-24 | UNKNOWN in CLI/JSON summary | Explicit UNKNOWN and failing safety exit |

## Sequencing and dependency management

**Stage 1: module** Align CPU/memory parser keys, reject invalid values and preserve evidence status. Add no default zero.

**Stage 2: interface facts** Select matching command/parser pairs for vendor and intended fact category; use real Cisco IOS/IOS-XE and Nokia fixtures. Coordinate with draft [netops #149](https://github.com/plures/netops-toolkit/pull/149) interface-counter observation fields.

**Stage 3: Ansible role** Reconcile gather selectors, nested fact references and actual health policy, repair Molecule mocks, explicitly handle unsupported BGP/OSPF expectations. Reuse generic three-state policy in draft [netops #148](https://github.com/plures/netops-toolkit/pull/148) and Cisco legacy guard in [#150](https://github.com/plures/netops-toolkit/pull/150).

**Stage 4: acceptance** Independent green CI/Docs on final review SHA; vendor output fixtures; peer-reviewed policy and controlled lab device tests before merge/deployment. Update any downstream consumers of success, overall_alert, has_errors and netops facts.

## Provisional decision / blockers

**Decision:** Distinguish observation completeness from health classification. Preserve compatibility fields, add evidence metadata, and require complete current evidence for safety gates.

**Material blockers:** Verified vendor-specific CLI/transport fixtures, production-compatible parser semantics, peer review, green CI and controlled lab hardware validation are absent. Work around through explicit specification and synthetic tests only; no operational safety credit, protected-branch change, merge, financial/legal commitment or M1 construction approval.

Track under [Linear PLU-43](https://linear.app/plures/issue/PLU-43/m1-fail-closed-ansible-netops-facts-netops-health-role-contract-and).
