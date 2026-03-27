# netops-toolkit Roadmap

## Role in Plures Ecosystem
netops-toolkit is the Python automation core for telco operations. It powers discovery, config collection, health checks, and reporting that higher-level apps (like netops-toolkit-app) can orchestrate and present as productized workflows.

## Current State
The toolkit is functional and feature-rich: inventory scanning, config backup, health checks, BGP/VLAN tools, safe config push, reporting, and an Ansible bridge. The codebase includes vendor parsers, transport helpers, templates, and report generators, but coverage is uneven across protocols and test depth varies by module. Packaging exists via pyproject with optional extras, yet PyPI distribution and formal versioning automation still need polish.

## Milestones

### Near-term (Q2 2026)
- Expand protocol module coverage (SNMP inventory, BGP monitor parity, OSPF checks).
- Fill parser gaps for core vendors (Nokia, Juniper, Arista) with standardized outputs.
- Add fast unit tests for parsers and CLI modules; enforce minimum coverage.
- Publish PyPI package with release notes and reproducible build pipeline.
- Improve docs: CLI reference completeness, examples for common workflows.

### Mid-term (Q3–Q4 2026)
- Add structured data export (JSON/CSV) across all modules with stable schemas.
- Implement modular job runner for scheduled scans and retention policies.
- Add device capability registry for auto-selecting commands per platform.
- Expand report formats (PDF+HTML themes) and compliance pack templates.
- Integrate with netops-toolkit-app for one-click scan/backup workflows.

### Long-term
- PluresDB-backed inventory + metrics storage for historical analytics.
- Pluggable vendor pack system (out-of-tree parsers + command sets).
- End-to-end change planning engine with automated rollback playbooks.
- Certified reference architectures for large telco deployments.
