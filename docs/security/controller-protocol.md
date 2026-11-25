# Controller private-channel security

The complete source contract and unfinished qualification are in the
[controller architecture](https://github.com/plures/netops-toolkit/blob/main/documentation/ansible-controller/ansible-controller-architecture.md).

## Trust boundaries

Public request/plan JSON is data, never authority. Actual A01 broker state and
already-entered pending occurrences remain host-owned. A private bridge cannot
mint consent, widen effects, change routes or renew original deadlines.
Host preparation and every worker credential/task/mutation dispatch recheck
current exact identity and host cancellation/kill-switch/deadline state.

Private anonymous input is one bounded length-prefixed strict UTF-8 JSON frame.
Malformed, duplicate, truncated, oversized, replayed, expired and wrong-scope
messages fail closed before broker/device I/O. Separate owned control/cancel
never uses credential-bearing environment, argv, inventory or secret files.
Worker budgets are readiness-start/request-start anchored and only shrink;
unrelated clock origins and delayed messages cannot renew consent.

Worker socket authentication is fresh 256-bit material inside a private owned
`0700` directory and `0600` Unix socket. It is consumed through an inherited
private pipe before Ansible forks; actions inherit a memory-only client.
Unsupported spawn tuples receive no plaintext fallback. Socket responses obey
the same bounded framing/strictness, exact target/task/field scopes and expiry.

The installed fixed play carries nonsecret occurrence handles only. Check mode
returns before client/connection access. No external playbook, module execution,
secret task-vars, async staging or token-bearing callback is accepted. Safe
results are a closed minimized schema; native exception/configuration bytes
cannot be included. `no_log` is not considered external-playbook qualification.

Strict selected SSH routes reject unknown/changed keys, preserve explicit ports
and selected bastion direct-tcpip transport, and do not enroll host keys, copy
keys or consult an ambient workstation bastion. Actual route/file/platform
qualification and hostile-path tests remain mandatory.

## Failure and cleanup

Lost control, cancellation and expiry revoke unused admission before waiting for
worker acknowledgement. Owned bounded teardown does not imply issued remote
work stopped; uncertainty remains separate from original/cleanup errors.
No mutation, reload, rollback or recovery is automatically replayed.
Temporary leftovers cause an explicit cleanup failure; there is no blind removal
of unmanifested files. Same-user/root/admin compromise is outside this boundary.

Python cannot promise erasure of immutable strings or forked process memory.
Fake sentinel controls demonstrate test sensitivity only: actual process argv,
environment, Ansible variables/callback/cache/staging and socket-state inspection
is still required before support/qualification. No remote telemetry is added.
## Protected collection return channel

The local action returns only minimized facts through Ansible. Collected bytes
use a distinct authenticated `content` request, canonical base64 and a 512 KiB
decoded limit. The worker relays it only for the selected collection's exact
already-admitted task phase; host control rechecks original binding, authority,
sequence, expiry and one-use receipt. Ordinary callbacks, outcomes, logs,
environment and task variables never carry that content. Backup consumes the
private handback under its own actual A02 permit and sensitive artifact owner.

Normal A02-owned completion closes that controller invocation, not the whole operation.
Cancellation/failure still revoke unused authority; no subsequent command or
content transfer can use the closed controller bridge. Protected buffers are
consumed or discarded on all public execute exits. Fixed-action guarded mutation
uses the original A02 owner and distinct recovery grants. Protected mutation
inputs in the private pipe do not authorize execution: host and worker consume
the exact credential/task/mutation phases independently. Check requests neither
refresh budgets nor authorize writes. The action compares actual apply prestate,
uses existing native push/vendor rollback, and verifies the exact poststate digest.
There is no host-native route fallback or implicit retry. Loss of completion after
the mutation phase retains uncertainty and permits only separately preapproved
A02 recovery, preserving the primary failure.

The minimized mutation handback contains bounded booleans, not configuration,
commands, passwords or exception text. Contradictory issuance/confirmation/state
facts are rejected. Native disconnect and independent host finalizer errors append
to factual cleanup without turning a verified command into an unissued command
or losing an earlier failure. Actual fork isolation and leak inspection remain
unqualified; ordinary pure-logic controls do not replace them.

The private A02 launcher entry verifies the concrete owner, broker and actual
cancellation identity. Standalone launcher calls retain terminal revocation.
Backup validates the same exact entered plan/effect/target/step/ordinal as
controller preparation; a forged cancellation object or substituted target
cannot consume protected bytes. Failed targets discard unpublished handback.

The actual host stop signal is set before broker revocation waits for a native
credential reader's admission guard. Cancellation therefore cannot be delayed
until that reader releases its broker lock before becoming visible to host
admission. An accepted receipt still requires revocation; no permissions are
created, renewed or reconstructed by signalling.

Controller cancellation additionally latches subauthority revocation without a
broker/state lock and attempts control and resolver revocation independently.
A snapshot lock may delay broker pruning, not acceptance of another controller
phase or signalling of its exact owned process. Revocation exceptions and still
pending revocation-owner references are retained as cleanup facts.

Action I/O logs correlate hashed target/occurrence references without adding IDs
to metric labels. Failure category/next action are fixed safe values. Terminal
credential discard cannot throw over a factual public outcome: its cleanup
failure is appended and central aggregate precedence is reapplied.

## Concrete private WSL control (source, not qualification)

Windows socket descriptor numbers and Windows launcher PIDs are never treated
as Linux authority or process-group identity. Fixed `wsl.exe --distribution
<qualified-name> --exec <managed-python> -I -m netops.ansible.worker
--stdio-control` uses only inherited private pipes. The closed startup carries
fresh private authentication, challenge and request/plan/context identity.
The worker consumes exact packaged consuming-tuple proof and actual private
runtime bytes before nonce readiness. HMAC readiness/stop/cleanup proofs bind
that one channel, never grant consent or renew execution.
Startup has a distinct host-floor-rounded remaining budget anchored at Linux
process entry. Lost control or stalled byte verification is bounded by an
independent startup watcher, before any broker or runner can be created; it
does not renew nonce-bound execution/authorization budgets.

One input frame is consumed through a separate memory-only source and closed
even when parsing fails. Control has a separate logical channel over the
inherited tunnel. No authentication fallback uses environment, files, public
state, inventory, callback or a socket TCP endpoint. Invalid proofs, unknown
PID fields, duplicated input, wrong context and lost control revoke admission.
The host watchdog samples the original parent stop without broker locks.

The worker owns the Linux-created runner session/group, retains its unreaped
leader through all destructive signals, and only probes absence after reaping.
It never receives a trusted PID from Windows. A stalled spawn/identity check
cannot yield a success proof. Independent Linux input/control-loss and deadline
watchers stop admission before bounded group cleanup, then exit only their own
supervisor if main work remains stalled. Lost or failed proof preserves
`owned-linux-runner-group` uncertainty; launcher/pipe cleanup failures append
their own references without replacing observed target facts.

These units use fake process/OS ports and owned synthetic byte fixtures. Real
WSL/POSIX/fork permissions, transit/suspend clocks, all descendants' teardown,
private pipe behavior and leak/staging qualification remain mandatory Q03
work. The current unqualified lock is not promoted by these tests.

