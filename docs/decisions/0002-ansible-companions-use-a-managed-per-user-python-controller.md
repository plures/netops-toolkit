# Decision 0002: Ansible companions use a managed per-user Python controller

| Field | Value |
| --- | --- |
| **Status** | accepted |
| **Date** | 2026-11-05 |
| **Feature** | ansible-molecule-integration |
| **Tags** | ansible, molecule, managed-python, controller, wsl, consent |
| **Supersedes** | — |

## Context

Native-preserving explicit companions need Ansible and Molecule on supported control-node platforms without changing the toolkit Python minimum or environment. Sources: brainstorm/turn-04.md; current run journal USER_APPROVAL 33588b9f-8e5d-4c30-b014-6342718568f1 ref step.design.brainstorm.controller-choice.

## Decision

Managed per-user Python controller — Linux/macOS directly; Windows through existing or explicitly consented guided WSL setup. Use an isolated managed user-local environment separate from toolkit Python. Qualify existing WSL or obtain meaningful explicit consent for guided WSL setup.

## Alternatives considered

- Pinned Linux container controller with explicitly consented runtime setup
- Capability-aware controller selection with recorded choice and no silent switching

## Rationale

Faithfully records the exact relayed user selection, retaining native commands/defaults and proactive default-driven dependency provisioning with actionable recovery/resume.

## Consequences

Controller choice does not validate any Python/core/Molecule version tuple or grant per-machine elevated OS, virtualization, service-start or reboot permission. No silent container selection. Molecule target-driver/runtime architecture is a separate pending choice; container targets do not replace this controller. Exact approved compatibility exception remains unapplied and implementation-inactive pending actual PX/foundation and stage gates. No Requirements/HLD approval or test execution is claimed.
