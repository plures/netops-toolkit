# netops-toolkit Roadmap

## Role in OASIS
netops-toolkit is a real-world automation suite that proves PluresDB + agents can drive measurable operational outcomes. It serves as a practical showcase for local-first data, orchestration, and auditability within OASIS.

## Current State
The toolkit is feature-rich (inventory, config backups, health checks, BGP/VLAN tools, safe config push) with solid documentation. Coverage is uneven across protocols, and packaging/release automation needs polish.

## Phases & Milestones

### Phase 1 — Stability & Packaging (Now → 30 days)
- Close parser gaps for core vendors (Nokia, Juniper, Arista).
- Add unit tests for parsers and CLI modules with coverage gates.
- Publish clean PyPI releases with reproducible build pipeline.
- Improve CLI docs with real-world workflow examples.

### Phase 2 — Data Backbone (30 → 90 days)
- PluresDB-backed inventory and metrics storage.
- Stable JSON/CSV export schemas across modules.
- Job runner for scheduled scans and retention policies.
- Integrate with netops-toolkit-app for one-click workflows.

### Phase 3 — OASIS Demonstrator (90 → 180 days)
- End-to-end change planning with rollback playbooks.
- Reference architecture for large telco deployments.
- Auditable reports tied to OASIS governance and QA evidence.

*Last updated: 2026-04-24*
