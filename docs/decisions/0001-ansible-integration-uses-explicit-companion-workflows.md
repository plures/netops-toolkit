# Decision 0001: Ansible integration uses explicit companion workflows

| Field | Value |
| --- | --- |
| **Status** | accepted |
| **Date** | 2026-11-04 |
| **Feature** | ansible-molecule-integration |
| **Tags** | ansible, molecule, companion-workflows, native-python |
| **Supersedes** | — |

## Context

Existing Python commands, Netmiko transport, inventory export, generated remediation and Ansible roles overlap. Source: brainstorm/turn-01.md in run it-s-now-time-to-implement-full-ansible-and-mole-20261104-225210156-fb1f9495; journal USER_APPROVAL af0820ac-6853-4ba0-8663-8605101b5e5c, ref step.design.brainstorm.execution-role. Prior find-decisions query ansible molecule companion workflows native python returned [].

## Decision

Approved user answer: Companion workflows — keep commands native; add explicit Ansible workflows. Preserve existing native commands and defaults; expose Ansible/Molecule as explicit companion functionality, not a selectable backend replacement and not Ansible-primary.

## Alternatives considered

- Selectable peer backend: choose native or Ansible for supported operations; preserves native defaults but adds adapter/parity/test cost.
- Ansible-primary automation: use Ansible for new network workflows while retaining native compatibility paths; reduces new Python orchestration overlap but makes controller availability central and requires careful rollback/result migration.

## Rationale

The user explicitly selected companion workflows. Turn01 identifies the lowest-disruption reuse of inventory export, generated remediation, custom modules and roles without an implicit Ansible controller dependency on native commands. This records the user selection, not the prior provisional peer-backend recommendation.

## Consequences

Native operations remain first-class; explicit workflows have narrower interchangeability and continued native/role overlap. Shared extensible dependency readiness/provisioning, full functional-area evaluation, honest Molecule validation and documentation remain in scope. This is execution ownership only: no Requirements/HLD approval, policy exemption, Python/Praxis bridge approval, or stack-migration approval; compatibility remains unresolved in turn02.
