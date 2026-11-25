# Guarded unexecuted remediation

Native `generate_playbook` keeps its source-compatible parameters and native
UUID/UTC defaults, `None` for failed/no-alert inputs, vendor templates, health
aliases, dry-run guards, human pause and block/rescue checks. Common internal
assembly accepts an explicit identity/time so companion planning never reads
the clock or generates a random UUID. Generic command modules now loop all
commands instead of discarding later commands. Rollback device tasks have the
same `not dry_run | bool` guard as remediation tasks.

Companion generation consumes bound validated findings, requires exact boolean
success/alerts, allowlisted vendor templates, unique literal selected host
identities and no Ansible pattern/Jinja target syntax. Unknown alert categories
are unsupported, not healthy/no-active-alert. Failed, missing and unexecuted
selected targets remain in the coverage projection. Output is repeatable from
the bound input digest and supplied report/observation timestamp.

Generated YAML is inspectable **UNEXECUTED** intent. It grants neither
collection nor apply, resolves no credentials, executes no YAML and opens no
device. Native pre/post validation can contact devices only if an operator
separately executes the native playbook; generating it does not do so.

The A02 `compare.generate` save handler validates YAML-only protected
output and publishes the exact reviewed `generated_yaml` bytes without
regenerating UUID/time or dumping the projection. The current owned canonical
generate-output selector emits the exact executable `request_effect(save)`
required by A01; older source/archives emitted factual `record_outcome` and
could not admit publication. No host-synthesized intent or operation relabeling
is used. Original one-use private consent and protected publication remain
mandatory.

Generation now distinguishes source eligibility before output-safe preflight
and canonical save consent. The native no-generation result is represented by
`generated_yaml=null`, not automatically publishable `[]` plus LF. With no
eligible plays, output review is blocked and no artifact is published; no-alert
coverage remains factual and is not permission for empty output. Failed,
unsupported and missing selected sources retain their dispositions. Coverage
is ordered by the requested selection, including missing targets; duplicate,
invalid vendor/check/host and out-of-selection records still reject.
Permitted mixed valid publication writes only eligible guarded plays and keeps
failed/unsupported/missing targets in the public partial, nonzero aggregate.
No-alert sources are unattempted facts, not generated or applied plays.

These are corrective source behaviors, not independent acceptance. Final
source-bound controls and a fresh consuming package remain necessary.
O03/O04 local acceptance can precede Q03 according to the approved DAG; this
does not waive real I02 managed installation, actual PDF/platform permissions,
both Molecule tiers or final full-feature qualification.
