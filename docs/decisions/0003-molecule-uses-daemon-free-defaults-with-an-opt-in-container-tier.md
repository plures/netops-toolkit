# Decision 0003: Molecule uses daemon-free defaults with an opt-in container tier

| Field | Value |
| --- | --- |
| **Status** | accepted |
| **Date** | 2026-11-05 |
| **Feature** | ansible-molecule-integration |
| **Tags** | ansible, molecule, daemon-free, container-tier, consent |
| **Supersedes** | — |

## Context

Explicit companions preserve native commands (Decision 0001) and use the managed per-user Python controller (Decision 0002). Actual USER_APPROVAL 48b97ff2-b54e-43c9-b392-2e25e476e97a, ref step.design.brainstorm.molecule-target-choice, in current run journal approves the two-tier target strategy. Alternatives, rationale and qualification costs: brainstorm/turn-05.md and capability-evaluation.md in this run.

## Decision

Exact approved choice: Daemon-free default plus opt-in container tier — default coverage with optional enhanced isolation; two paths to maintain. Execute a real Molecule lifecycle using controlled local fixtures/mock SSH by default. Implement and document optional disposable container validation as a separately selected enhanced tier, with separately consented runtime/VM setup. Container targets do not replace the managed Python controller. Retain all seven areas: scan, inventory, vault, config, health, compare/analyze, report.

## Alternatives considered

- Daemon-free local fixtures only: least setup but lower isolation and no container-target qualification
- Disposable container targets by default: reproducibility/isolation, but mandatory runtime/VM/image setup and permissions even for default validation

## Rationale

User explicitly selected full daemon-free default coverage plus optional enhanced isolation, rather than imposing container infrastructure on default operation or dropping the enhanced path. Turn05 establishes local and container lifecycle feasibility, not a qualified version tuple. Both advertised paths need distinct real lifecycle and platform qualification evidence; controlled mocks are not real-vendor appliance fidelity.

## Consequences

Maintain and qualify two paths, state/command/failure fixtures, meaningful result/side-effect/check-mode/cleanup assertions and truthful mock-versus-vendor documentation. Unit tests remain network-free, including no loopback services; owned isolated services belong only in the integration tier. Optional container tier not selected is not-requested, not a default missing dependency; requested tier requires verified runtime access and actual strategy-specific collection/driver dependencies. No silent controller fallback, global Python mutation, privilege escalation, security relaxation, elevated OS/WSL/virtualization/service/reboot permission or installer authorization follows from this choice. No versions, images, packages, tests or installations are qualified by this decision. Requirements/HLD approvals and actual PX/foundation implementation gates remain outstanding.
