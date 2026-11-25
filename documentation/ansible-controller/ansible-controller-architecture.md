# Private controller implementation checkpoint (S02; not qualification)

## Nov 21 same-sample CPU consistency and cold native controls

The shared producer/callback numeric validator now rejects PAN-OS `user` +
`system` exceeding the same `top` row's non-idle budget. It does **not** require
equality: nice, interrupt, IO and other components are not exposed by the native
parser. Comparison uses decimal arithmetic on `user`, `system`, `idle`, not the
separately two-decimal-rounded derived utilization. Independently rounded
components have at most half their reported decimal unit of uncertainty each,
capped at the retained float's tenth-percent unit per component. Thus an
integer-valued field cannot create a whole-percent loophole. At the producer,
the exact matched native decimal tokens are checked too: trailing zero precision
cannot be discarded to enlarge the source's interval. This check is applied only
to CPU, so unavailable CPU does not poison an independently measured memory
reading from the same command. Neither tokens nor additional precision fields
are serialized. The complete closed numeric `raw` schema is unchanged.

Nokia's `avg` and `peak` are parsed from the **same matched CPU Usage row**;
`peak < avg` is unavailable at the producer and rejected at the callback.
This relation is not applied across IOS/Brocade's distinct temporal windows.
All existing vendor-specific memory ratios, finite percentage checks, inclusive
thresholds, missing-counter rejection, and exact-owner cleanup retry rules
remain in force. The four original independent malformed CPU assertions are
unchanged. A new author retry checks allowed exact numeric provenance and
unknown/credential-field rejection; the old contradictory blanket-raw-absence
assertion and its failed receipts are not erased or reclassified.

Fresh Windows native source controls additionally distinguish:

- A cold call using the **same packaged executable**, fixed flags, explicit
  three-handle inheritance list and fixed environment, but a deliberately
  nonexistent task-local working directory. `CreateProcess` returns error 267
  and **no child/process/thread handles**; full owned job/pipe/NUL teardown
  still leaves a whole-process delta of **+27**. This is a causal no-child
  control, not a warmup. A separate nonexistent-executable control leaves +23.
- An actual cold source launch and a separate direct `kernel32.CreateProcessW`
  baseline (not `Popen` or `_winapi.CreateProcess` for the baseline creation).
  Both are suspended, assigned to the exact private kill-on-close job before
  resume, and finalized by actual wait/zero-active-job proof and exact handle
  closes. The direct baseline uses the same explicit handle list. Attribute-list
  deletion releases memory, not a kernel handle; it is not counted as a handle
  close. Both diagnostic cells retain +28 in the first v3 observation. This
  extra difference is retained, not rounded away to match the old +27 failure.
- Read-only inspection of each **exact returned suspended child** PEB environment
  block before `ResumeThread`: its complete keys and value digests match the
  three supplied `SystemRoot`, `LANG`, `PYTHONNOUSERSITE` values. At the helper's
  first Python statements under `-I -S`, both creation implementations observe
  the same additional runtime-generated `PYTHONUSERBASE`; ambient canaries and
  an untrusted `PYTHONPATH` do not reach the child or its import path.

The run's `nov21-native-causal-v*-EVIDENCE.json` files retain per-phase own-process
kernel handle identities/types, module changes, every explicitly allocated
owned lifetime and its immediate successful close point. No system-wide handle
inventory, unowned handle closing, forced GC, blind warmup, increased threshold,
global environment cleanup, interpreter install or new launch allowance is
used. Source-created environment equality and Python-managed post-start
environment equality are different contracts: the former has direct native
evidence; the latter still fails the original strict three-key assertion.
The original cold whole-process assertion remains **failed and unwaived**.
These controls provide narrow causal evidence for review, **not** native/WSL,
Ansible/Molecule/Q03 qualification, source authority, or full S02 acceptance.

The later author environment helper was corrected only after those actual
kernel-block/direct-native observations. It now compares the complete supplied
mapping with the actual suspended kernel block; runtime output contains only
key/value digests, isolation flags and import paths. It rejects ambient canaries,
unknown runtime keys and untrusted import paths, and permits the Store-managed
key in that author diagnostic only when an independently created native
`CreateProcessW` child produces exactly the same runtime mapping/path. It does
not add that key to the source's fixed environment or certify strict post-start
three-key equality. The original independent cold/numeric/raw files are unchanged.
The failed first retained self-check (1135 passing, one author equivalence
failure) and provisional owner seal remain historical artifacts; the explicit
author-test remediation precedes the replacement owner seal and any joint
global tester package. No post-joint-seal source edit is authorized.

## Nov 20 owner-specific numeric health provenance

The fixed native reading producer and private callback receiver share
`_action_health._numeric_provenance`. A successful reading must carry the
selected owner's **complete closed numeric schema**, not a union of other
owners' keys. Normalized utilization must equal the selected source reading.
The callback does not accept arbitrary dictionaries, device output, configuration,
credentials, command/process text or additional callback/check/raw fields.

| Owner / check | Exact parsed numeric provenance | Selected utilization |
| --- | --- | --- |
| IOS / XE CPU | `five_seconds`, `one_minute`, `five_minutes` | `one_minute` |
| Nokia CPU | `avg`, `peak` | `avg` |
| Brocade CPU | Subset of `one_second`, `five_seconds`, `one_minute` | Present `one_minute`, otherwise required `five_seconds` |
| PAN-OS CPU | `user`, `system`, `idle`, `utilization` | `utilization`, equal to native `round(100.0 - idle, 2)` |
| Junos CPU / memory | `cpu_utilization` / `mem_utilization` | The matching field; every native routing engine must have the selected measurement and the normalized value must be their maximum |
| EOS CPU | `cpu_utilization` | That field |
| IOS / XE / Nokia / Brocade / PAN-OS memory | `total`, `used`, `free`, `utilization` | Native `round(used / total * 100, 2)` |
| EOS memory | `total`, `used`, `utilization` in bytes | Native **one-decimal** ratio from the original KiB counters |

Percentages must be actual finite int/float values in inclusive 0–100; booleans,
numeric text, nested containers, nonfinite and out-of-range values are rejected,
not coerced. Memory counters are exact integers in 0–9007199254740991, total
must be positive and used/free cannot exceed total. Flat IOS/Nokia/Brocade
used and free counts sum to total. PAN-OS `top` also reports buff/cache, which
its existing bounded parser deliberately does not expose: used + free may be
less than total but never greater. This preserves valid native cached-memory
readings rather than inventing another field. EOS byte counters must be exact
multiples of 1024 within the safe bound; the ratio is recomputed in native KiB
with the owner's one-decimal rounding, not the flat parsers' two decimals.

All selected checks remain independent. Missing or contradictory provenance
is unavailable/unknown, never healthy zero; an actual measured zero remains
valid. Threshold comparisons remain inclusive (`>=`). Cancellation and cleanup
retain previously measured findings and their own failure facts. These are
private validation corrections under FR-027/033 and AC-008, not new public
request commands, source authority or platform qualification.

### Current native Store-runtime diagnostic boundary

A source-only diagnostic on the current Windows Store Python tests both its
execution alias and actual packaged base executable. In four independent cold
helper processes (`-I`, and a separate `-I -S` control for each executable), the
first `CreateProcess` still increases whole-process handle count. The base
executable cells retain 27 additional handles; alias cells retain 33/35.
The kernel constructor itself adds none. Per-call own-process snapshots place
the increase inside `_winapi.CreateProcess`, alongside new Windows AppModel/
crypto DLLs (`daxexec`, `container`, `capauthz`, `ncrypt`; alias calls also load
`apisethost.appexecutionalias` / `AppXAllUserStore`). Observed retained types
include ETW registrations, registry keys, semaphores, events and runtime
threads. These are **not handles returned to the toolkit's child owner**;
the diagnostic does not close or claim ownership of them.

All six explicitly returned native job/process/thread/child-pipe/NUL handles
and both CRT-owned parent pipe streams close on each of 12 launches. Actual
process wait and zero-active-job proof run before release. Ordinary release
of the live owner also releases its synchronization lock; this is recorded
separately, without forced global GC. Each cell's next two complete owner
lifetimes have zero net growth. This supplements exact closure evidence; it
**does not waive or make green the original cold no-growth assertion**.
The original cold failed case and prior diagnostic attempts remain failures.

The actual `CreateProcess` environment is still exactly `SystemRoot`, `LANG`,
`PYTHONNOUSERSITE`, with an explicit three-handle inheritance list. The first
statement of all 12 Python helpers observes an additional `PYTHONUSERBASE`
pointing to the Store runtime's local-packages location, despite isolation,
ignored Python environment and disabled user-site flags; disabling `site`
does not remove it. This distinguishes the passed environment from a
runtime-generated value; it does not authorize that value in a public
allowlist or assert strict post-start environment equality. The current Store
tuple therefore remains **unsupported/unqualified for that strict assertion**.
No environment cleanup after observation, backend argument rewriting,
interpreter installation, global profile change or assertion relaxation is
performed. A cold environment/handle requirement needs a genuinely qualifying
runtime tuple and independent evidence, not a warm baseline substituted for
the failed cold control. Native Windows helpers remain diagnostic only, never
Ansible/WSL/Q03 qualification or source/execution authority.

## Nov 20 exact-owner retry and missing-measurement correction

Normal launcher close now registers the exact object before attempting cleanup,
not only after failed startup. Failed/throwing closes remain in the private
port's identity-based registry and block another launch. Pending cleanup retries
every retained owner, merges independent failure facts, and removes only an
owner whose actual close succeeds; one successful sibling cannot clear another.
The registry is serialized against launch and does not discover/reopen PIDs.

The Windows owner separately retains process/job/extra startup handles, startup
streams and actual process-wait/zero-job proof. After that proof, retries perform
only still-owned handle/stream closes. A successfully closed job is never passed
as zero to `TerminateJobObject`; a retained process handle can finish closing
without repeating termination or wait. All independent close attempts run even
when another fails, and their safe errors remain factual. Startup with no child
still retains failed job/pipe/thread closes. Normal IPC streams remain owned by
the framed pipe owner. Existing generation pins still require successful actual
group/pipe cleanup; neither outer-job join nor this retry registry supplies Linux
cleanup proof or releases an unproved dispatched holder.

For private native interface health, Junos requires an actual bounded integer
total `Errors` measurement in both input and output sections of every physical
interface. EOS requires present bounded integer `inputErrors` and `outputErrors`
in each interface's counter dictionary. Parsed native rows must match those
source measurements before successful normalization. Header-only, missing-one/
both, malformed, negative, boolean, nonfinite, over-range or partially missing
interface data is `reading-unavailable`, never synthesized healthy zero.
An actual measured zero remains a valid healthy reading; other selected check
facts and unsupported selections survive independently. CPU/memory numeric
`raw` dictionaries remain bounded parsed provenance, not device text/configuration
or credentials. No arbitrary commands, connectivity-based health, public schema,
dependency/source authority or qualification rule changes.

The exact diagnostic and original failed 1072/controller/whole-process-handle
attempts remain in the run history. New author controls exercise task-owned
native Python jobs and fake external device/kernel failure seams only. They are
not independent approval, full S02 acceptance, real SSH/Ansible/fork/WSL
qualification, or a waiver of the unchanged native handle-count assertion.

## Status and composition

This source increment implements closed private frames, conservative relative
budgets, real A01 pending-effect sub-dispatch checks, an owned POSIX process
adapter, worker socket broker, pre-fork private action client and a fixed local
Ansible play. It **does not accept S02, qualify a platform/Ansible fork, install
anything, or supply an automatically activated application bootstrap**.

The original `ControllerLauncher(processes, credentials, state, clock, events)`
constructor and `verify(ControllerContext)` / `run(ControllerRequest,
ScopedCredentials, CancelPort)` signatures are retained. The injected
`ProcessPort.verify(context, state)` must independently verify current executable,
installed assets, ownership and **actual exact tuple evidence**, returning
`ControllerInstallation` or `None`. A constructed installation value is not proof.
`OwnedPosixProcesses` delegates that evidence to `InstallationVerifier`; no
shipped verifier synthesizes qualification from versions or file presence.
`controller_installation._OwnedInstallationVerifier` now consumes matching
owner/policy `active` and `install` records, actual regular-file hashes, private
permissions, stable identity/mtime/ctime (not access time), the exact manifest
tree and a packaged Q03 installation/context lock. It requires the pinned
interpreter, worker, runner, native adapter, guarded mutation module, local action
and real Ansible base. Exact required-member validation rejects evidence omitting
`netops/ansible/_action_mutation.py`, even if other tree hashes match.
It rejects extra tree members rather than adopting paths or making asset pins.
The packaged lock is still unqualified. Staged/inert I02 product records are not
silently treated as activated controller installations.

`HostDispatchControl` accepts only the actual A01 broker and real already-entered,
still-pending effect permits. Each private `_HostInvocation` must match the
original plan, effect kind, occurrence, target, step and invocation identity.
One occurrence per target is admitted in one worker run; ordered occurrences
remain separate host invocations. JSON, nominal `EffectPermit` objects, a policy
allow or installer consent cannot create this authority.

`_ControllerCredentialAdmission` implements S01's private admission port inside
that existing operational pending entry. It checks exact source scope/routes,
minimal SSH fields, original deadline and current host facts before and after
one host resolution. It does not change S01's standalone vault-effect adapter.
The host resolves using `ScopedCredentialResolver` and `UnlockSession`, then
wraps the real private result, exact scope and bridge in
`HostControllerCredentials`. The wrapper never serializes through public DTOs.
The resolver's original delivery guard is retained.

The public WorkflowService constructor and execute authorization are unchanged:
execute still requires the concrete A02 ExecutionHost. Cancellation signals an
exact composed ControllerLauncher's private active stop before broker revocation
and receipt-clock observation. There is **no new execute bypass** and no automatic
controller/source/consent bootstrap. Private production composition now lives in
`controller_backend._compose_owned_controller_service`: it constructs the actual
consuming verifier, owned POSIX adapter, launcher, A02 host and service. Public
`execute` reaches that backend through the existing host, not a bypass.

The backend finds only A02's authentic already-entered pending permit and
invocation, reconciles it through the real broker and uses the broker scope's
original `issued_at`. It does not reconstruct an origin by subtracting unlike
consent and execution durations. `_VerifiedControllerSources` replaces source
controller-readiness claims with consuming installed proof on every reload.
Missing proof blocks before the vault, unlock provider, worker or device.

`_ControllerCredentialSource` selects only the immutable approved target/route,
rebinds the exact admitted task ID, validates approved file metadata through
S01's `ControllerOriginRoutePolicy`, and uses the real `ScopedCredentialResolver`
and one-use `UnlockSession`. It checks admission before asking the private unlock
provider. Sessions close and resolved payloads are discarded on every exit.

## Protocol and clock ownership

- One private anonymous input frame: unsigned four-byte big-endian size,
  `1..1048576` bytes of strict UTF-8 JSON. Reject duplicates at every depth,
  nonfinite numbers, malformed/truncated/extra frames, trailing outer whitespace,
  unknown fields, wrong types and unselected target/task/credential fields.
- Initial fields are exactly `protocol`, `request`, `scope`, `intents`,
  `credentials`, `budget`. Version is exact integer `1`, not boolean.
  Scope binds operation, plan, controller, route, selected nonsecret routes and
  field names, jump route and bounded concurrency. No inventory/vault file is
  supplied. Decrypted credentials appear only in the private credential subsection.
- Worker sends a fresh 256-bit ready nonce and records its own readiness start.
  Host remaining authorization/operation milliseconds are rounded **down**,
  bounded `1..300000` / `1..3600000`, with `control_timeout_ms=2000`.
  Deadlines are anchored to readiness **start**, never budget receipt.
- Every credential delivery, new local task and potential mutation has its own
  exact binding/sequence and one-use host bridge phase. Worker reduced budgets
  are anchored at request start and clamped to original local deadlines.
  Retry, heartbeat, delayed transit and reconnect cannot extend consent.
- Absolute clocks never cross the process boundary. Host accepted-execution and
  original consent deadlines remain authoritative. UTC is provenance only.
  Nonfinite/backwards clocks, expiry, cancellation and lost/malformed control
  fail closed. Control request/response fragments do not reset timeouts.

The host watchdog starts before verification/readiness and checks original
host-local deadlines independently of worker progress and broker snapshot I/O.
It sets the stop event before revocation/resolver locks; the adapter owns bounded
termination. Kill-switch/current binding checks remain serialized at every host
sub-dispatch. No telemetry observation supplies authorization.

## Owned processes, socket and action boundary

Linux/macOS launch an absolute verified managed interpreter with structured
`-I -m netops.ansible.worker` arguments, a private inherited control descriptor,
no shell and a fixed nonsecret environment. The modeled Windows shape is absolute
verified `wsl.exe --distribution <qualified-name> --exec <managed-linux-python>
-I -m netops.ansible.worker`; native Windows Ansible, shell fragments and default
distribution selection are rejected. The concrete private `_OwnedWslProcesses`
adapter now launches only that fixed module using inherited stdin/stdout frames
(`--stdio-control`), rather than passing a Windows socket FD into Linux.
**No real WSL execution or tuple qualification is supplied by these source units.**

The WSL adapter requires an existing ownership/active-install/consuming-context
`InstallationVerifier`; a request or constructed installation is not proof.
It additionally consumes the packaged exact Q03 entry and hashes current
Windows launcher bytes. That entry must pin `wsl_executable_digest`,
`wsl_distribution`, `python`, full `tuple`, `installation_digest`,
`context_digest` and `evidence_digest`. The Linux worker independently consumes
the same identities and `linux_root`/`runtime_pins` (closed absolute path/digest
pairs), checks current private regular-file bytes and stable identities, rejects
an extra tree member, and requires the interpreter, original runtime/action/base
and all four concrete private WSL modules. None of these records is manufactured
by the adapter; the present unqualified packaged lock still blocks support.

An inherited framed startup carries a fresh private key, host challenge and
request/plan/context binding. Readiness and stop/cleanup proofs are HMAC-bound to
that key, worker nonce and binding. They attest this channel's owned runtime,
not host permission. Authentication never enters argv, environment, state, logs
or an Ansible fork. The tunnel materializes exactly one separate in-memory
input source, consumed/closed before broker/runner work; later frames use a
separate logical control/cancel channel. Unknown fields, extra PID fields,
replayed input, wrong nonce/proof/context and lost control fail closed.
Bounded pipe reader/writer queues keep fragments and stalls from resetting
deadlines; a stuck handle remains an explicit cleanup reference.

The Linux supervisor creates a new runner session/group through the actual
fixed runner launch, verifies its group/session against the created child and
observes completion with `waitid(WNOWAIT)` without reaping the leader. It
signals only that owned group before reaping; afterward it only probes absence,
never signals a potentially reused PID. A cancellation racing a stalled spawn
cannot produce a successful group proof. An independent private-control reader
and budget watchdog latch cancellation before group locks, stop unused admission
and perform bounded owned teardown. If main worker I/O remains stalled, a
two-second supervisor fallback exits only its own Linux process. Unknown group
ownership, failed signalling or unverifiable absence stays a cleanup failure.
Windows launcher exit is never Linux teardown proof.
The separate startup budget is host-floor-rounded remaining milliseconds,
bounded `1..120000` and clamped to original startup/operation/consent deadlines.
Linux anchors it at process entry, not receipt or verification completion.
An independent startup watcher bounds stalled byte verification and inherited
control loss before readiness. This startup budget cannot grant admission or
extend the separately nonce-bound readiness/execution budgets.
Cancelled Linux input/control waiters observe the latch without consuming their
full timeout, allowing the supervisor to close its own private pipe promptly.
Cleanup frames are validated directly as closed cleanup facts; they are never
inserted into an unrelated successful outcome whose aggregate consistency would
discard a legitimate failed cleanup or its owned references.

Private `_compose_owned_wsl_controller_service` composes this real adapter with
the existing A02/S01 backend and an already qualified owner verifier. It performs
no acquisition, distribution adoption, activation or privilege effect.

Worker validates the entire input before creating a listener/session. Its unique
directory is beneath a bootstrap-selected owned `0700` root; the directory is
`0700`, Unix socket `0600`. A fresh 256-bit private authenticator and all credentials
stay in memory/private frames, never state, argv, environment or Ansible variables.
Each broker connection accepts exactly one framed request followed by EOF.
Authentication, scope, sequence and live host checks precede delivery.

The worker starts only the installed `controller_runner` using its managed
interpreter. Authentication is passed once through an inherited pipe, consumed
and closed before Ansible imports/forks. A module-private client is inherited by
forked actions; a direct same-process invocation or spawn import has no usable
client. There is no environment/file fallback. Installed action paths, an in-code
pinned play, a fixed callback and synthetic nonsecret host handles replace
external playbooks/inventory. System Ansible configuration is disabled, with
Ansible home/temp confined to the owned run directory. At most twice SSH
concurrency is presented to Ansible in a batch; concurrency is bounded `1..50`.

`NetopsWorkflowAction` subclasses the installed ActionBase. Check mode returns
before base execution, private client access, task-vars inspection or session
creation. The action never calls `_execute_module`, remote staging or arbitrary
plugins. It normalizes only Ansible's nonsecret tagged handle, then performs
private broker resolution and task admission before native I/O.

The current fixed native path actually runs `DeviceConnection.send` in-process
through a strict SSH adapter for selected Cisco IOS/XE/NXOS, Arista EOS and Nokia
SR-OS collection commands and operation-specific native health owners. It uses exact selected host/port, selected
known-hosts files and RejectPolicy for a selected SSH direct-tcpip bastion.
It never consults ambient bastions or enrolls host keys. No key copying or direct
fallback is provided. Native result/exception/configuration bytes do not enter
callbacks: only closed status/attempted/changed/remote-state/line-count facts
and bounded mutation/cleanup booleans.

Collection bytes have a separate protected handback. The in-process native
read returns a private, nonserializable `_NativeRead`; only its minimized facts
are exposed as the action result. The authenticated client sends bounded
canonical base64 content on a separate private frame. Broker and host recheck
the exact operation/plan/controller/invocation/target/task and spent task phase;
duplicate, stale, unselected, oversize or malformed content is rejected.
The limit is 512 KiB per collection, below the private frame ceiling.
Configuration never enters callbacks, ordinary outcomes, policy journals or
logs. The backend consumes the handback once. A02's separate entered backup
effect publishes it through the existing sensitive `ArtifactStore` owner;
retention and Git remain separate admitted native effects. Unpublished bytes
are dropped on every public-execute exit.

For configuration apply/rollback, A02 retains the authentic entered permit,
protected prestate retrieval, route/vendor qualification and separately reviewed
recovery grant. Its concrete controller backend now sends the exact reviewed
commands, bounded protected prestate, expected poststate digest and prestate
reference through the private input/runner pipe. These are inputs, not authority:
every credential, task and mutation still consumes its exact host phase.
No configuration or credential enters Ansible inventory, task variables or files.
The host-native connection fallback is removed.

The inherited action invokes the existing native `run_push` or
`_run_guarded_rollback`, using private `_action_mutation` hooks and the strict
selected connection. Apply compares actual prestate bytes before admission of
its one mutation. Poststate must match the exact expected digest; rollback uses
the existing vendor-aware native owner and verifies the protected snapshot digest.
Live checks before connection/prestate/postcheck carry no new budget. The worker
requires an acknowledged host check, rather than silently skipping one when its
control channel is busy. Worker and host independently enforce the original
one-use credential/task/mutation sequence and exact binding.

Native command failure, verified state and connection cleanup are independent
facts. The closed handback carries only issued/committed/confirmed/rolled-back/
poststate-verified/connection-opened/cleanup-failed booleans. If a mutation phase
was consumed but completion is lost, the host conservatively retains issued
uncertainty. There is no replay. Only A02's separately preapproved, bounded
recovery execution may follow; primary failure and both cleanups remain factual.
Post-action private finalizers are attempted independently and append cleanup
errors rather than replacing an already returned execution fact.

Ordinary author tests execute this actual pure runtime, parser, A02/S01 and
host-phase logic with fake process/device ports. They do **not** substitute a fake
ActionBase, simulate a supported fork tuple or establish POSIX/WSL qualification.

## Cancellation, factual completion and observations

Cancellation revokes unused permission idempotently; new dispatch is stopped,
not replayed. Already issued commands may complete or be uncertain. Late exact
factual completion cannot renew permission or overwrite revocation. Returned
target facts survive later cleanup/control failure. Primary error, secondary
cleanup and issued mutation uncertainty are separate. The POSIX adapter creates
a new owned group and signals only that group, retaining the unreaped leader
through teardown instead of confusing launcher exit with fork termination.
Pure unissued cancellation retains the admission-revocation category and exit
130 through the unchanged central aggregator. Factual failures, remote
uncertainty and cleanup failure retain their normal precedence.
Successful A02-owned controller completion closes only that invocation's sub-dispatch.
It does not revoke the whole A02 operation before the next selected target or
protected backup publication. A02 still revokes the grant at its normal
terminal boundary. Cancellation, malformed control, expiry and failure revoke
immediately instead. The standalone public launcher still revokes terminal
authority; only the private entry point validates the concrete A02 owner and
its actual broker/cancellation identity before retaining operation authority.

Cancellation signals the actual A02 host before waiting for broker revocation,
including while S01 preparation holds its admission guard across a native vault
reader. The active launcher is also signalled before those locks. The accepted
receipt still follows broker revocation and precedes no new authority; its clock
cannot postpone either stop signal. The author regression stalls the real S01
reader and observes the actual host signal before releasing the broker lock.
This proves the fake-I/O lock ordering, not real process/platform stop latency.

Both independent monitors also observe caller-port cancellation, not merely an
event that the stalled main loop would have to latch. For the concrete A02
cancellation object, they read its already-owned stop signal directly: ordinary
`is_cancelled()` can itself wait for broker/state locks. Generic injected ports
must provide nonblocking cancellation observation. Original monitor deadlines
remain independent and cannot renew. Final control/resolver revocation attempts
are independent; later failure appends a safe cleanup error without discarding
earlier owned resource references, teardown errors or primary execution facts.

A stalled host snapshot exposed a further serialization bug: the watchdog waited
for control/broker revocation before invoking the resolver. It now first latches
controller subauthority revocation with a monotonic private event, checked before
new dispatch/readiness/content admission and again during binding validation.
It then supervises control and resolver revocation independently. Neither owner
can delay the other or the exact owned-process monitor. Broker pruning may finish
after a currently held snapshot lock releases; no new controller phase can use
that wait as permission. Watchdog exceptions and pending owner references remain
explicit secondary cleanup facts. This does not change A01's broker protocol,
grant identity or recovery authority.

Protected backup and controller preparation use one exact entered-invocation
predicate: complete plan binding, effect ordinal/occurrence/target/step, actual
cancel identity and broker reconciliation. A substituted target, step, ordinal
or cancellation object cannot consume another target's private bytes. Failed
targets discard already received but unpublished content immediately; this
does not claim secure erasure of immutable Python objects.

The controller observation helper pairs structured records and process-local
counters for `controller.launch` / `netops.controller.launch.count`,
`operation.step`, `consent.invalidated`, `cleanup.result` and remote uncertainty.
Only bounded outcome/reason/stage dimensions enter metric labels; operation,
target, context and step correlations are hash references in logs only.
No exception text, configuration, credential or authenticator is logged.
Sink failures are counted and cannot discard factual outcomes. Unexpected
boundary failures use `stage=Unhandled`. Pure controller modes emit no events.

`controller_observations.py` pairs `controller.io` records with
`netops.controller.io.count` and `netops.controller.io.duration_seconds` local
measurements at process verification/launch/readiness/input/control/teardown,
worker input/ready/broker/launch/auth/wait/cleanup/result, private broker
dispatch/pulse/content/channel and local action channel/native boundaries.
Fixed-action mutation additionally pairs connect/read/write/close I/O and a
distinct mutation outcome, including failed confirmation and throwing-sink
controls. Commands, prestate, device output and raw exceptions are never labels
or log payloads.
Action-channel/native/connect/read/write/close records include operation,
controller, target and occurrence hash references in logs only. Failure records
carry a fixed safe category and next action alongside the metric's identical
bounded dimensions. Public terminal credential discard is also nonthrowing:
its independent cleanup error is merged with the host's factual result using
central aggregate precedence, rather than a `finally` exception replacing
already observed target/primary/cleanup facts.
Only fixed boundary/outcome/stage/reason values are metric dimensions; operation
and context are hash references in logs, not labels. Clock/logging-sink
exceptions cannot replace primary or cleanup facts. Host launch duration is
measured rather than a hard-coded zero. Complete resource, concurrency and real
platform observations remain qualification obligations.

The worker records its own owner-only `ansible-tmp` base. Teardown removes that
exact directory only if its identity is unchanged and it is empty; unexpected
Ansible/plugin residue still yields cleanup failure, never an unmanifested
recursive deletion.

## Exact remaining work (no support claim)

1. Qualify a real managed tuple and supply its actual trusted host selections.
   The managed factory now consumes registered generation pins and admitted
   installation receipts before proof/dispatch. A02 backend, S01
   provider, consuming installed-byte verifier and public-execute composition
   now exist; an unqualified lock and staged/inert records cannot make them ready.
2. Qualify the implemented fixed-action guarded configuration mutation path on
   legitimate POSIX/fork and WSL-origin tuples, and complete any remaining
   operation-specific update/image/reload/ACL/NTP adapters. Ordinary fake-port
   configuration tests do not establish full-S02 operation or route coverage.
3. Qualify actual Ansible ActionBase/plugin loading, private client fork
   inheritance, system/plugin isolation, argv/env/vars/callback/cache/staging
   inspection and private-directory cleanup. Temp residue currently produces
   cleanup failure rather than deleting unmanifested contents.
4. Prove actual Linux/macOS permissions and process-group teardown, suspended or
   stalled worker behavior, clock/suspend semantics and Windows-to-WSL Linux
   group teardown with approved key/bastion routes. Fake tests are not T13/T14/
   T30 platform proof or Q03 qualification.
5. Complete real-tuple worker/process I/O T32 evidence, private result correlation and
   independent high-security/concurrency review. Host paired observations and
   fake sink tests alone do not satisfy every real I/O-boundary obligation.
   Source now includes fixed process proof/cancel and owned worker-group I/O
   observations. Returned failed cleanup facts emit failed (not succeeded)
   paired count/duration/log records, and sink exceptions do not overwrite them.
    Linux startup, actual runtime verification and private control I/O also
    carry fixed safe boundaries; a forced supervisor exit emits a paired
    control-loss diagnostic. Signed failed cleanup retains all received owned
    references, and exact late completion is retained without renewing admission.
6. Integrate the complete public source census/operation manifest and shared API
   documentation delta with the separate dependency/documentation owner. Do
   not bypass full-registry validation to make this increment appear ready.

The author tests use fake process/socket/native ports and synthetic vaults only.
They retain deliberate secret/effect negative controls, actual A01 pending
authority checks and raw **fake-seam** cancellation timestamps. No network,
actual worker/Ansible process, controller resource or acquisition is authorized
or claimed by those tests.

### Managed installed-generation source

The owned controller factory accepts an explicit managed manifest/root resource
configuration without changing the public service constructor or legacy record
source. Its managed verifier reads the protected root registration, exactly
retained staged generation, admitted active pointer, activation verification and
generated installation receipt under their existing owned-state locks. Owner,
policy, descriptor, registry and consuming-context identities must agree.
Registered qualification metadata must match activation verification; it is
not itself sufficient authority or proof.

The exact generated installation membership is independently checked, including
the separately hashed receipt bytes. The unchanged packaged real Q03 tuple
lock, runtime-member census, platform and file checks remain mandatory.
Native-only descriptors without a controller installation cannot select this
controller source. A compound native parent selects its separately pinned
controller installation without changing the parent's role or digest. The
trusted root remains `installation-<digest of generation id>`: a child root
cannot satisfy the parent-root guard. The parent receipt and full tree, including
`controller/netops-installation.json`, are still checked against the staged
receipt, active pointer, qualification and generation pins. The qualification
must select `controller/bin/python` and require runtime members under
`controller/`; native runtime members cannot stand in for the child.
This written correction awaits independent current-byte verification.
No arbitrary
directory adoption, readiness boolean or synthetic host qualification bypasses
that boundary. Binding units deliberately remain non-ready without a real Q03
entry; they are not controller/platform execution evidence.

Trusted host selections are the actual `managed_manifest`,
`managed_root_resource`, `active_resource` (the exact control resource) and
`installed_root` (`installation-<digest of generation id>`), not request flags.
The managed branch of `_compose_owned_controller_service` now constructs the
consuming `_PinnedControllerProcesses`; public workflow execution reaches it
through the existing real A02/S01 host. No global service or automatic
CLI/Textual activation is introduced.

`controller_generation.py` derives the full registered immutable
`GenerationBinding` set from the same protected root and selected descriptor.
It either uses the explicitly shared `managed_runs` instance or constructs an
`OwnedGenerationRuns` reader against that exact state/root/control/owner/policy
and selected generation. It never initializes missing pins during composition.
A different owner, state instance, control, policy, registry or active pointer
blocks before installed-byte observation. Registration changes invalidate the
existing composition rather than reconstructing its scope.

Every verification acquires a durable holder before examining the managed
receipt or actual qualification/bytes, then releases after that observation
finishes. Actual dispatch acquires a distinct holder, rechecks the receipt and
same installation digest, and retains it through the concrete adapter's
verified group/pipe teardown. Failure, unknown completion or unproved cleanup
retains the durable holder and the closed `owned-generation-run-pin` reference;
native primary errors and previous cleanup references remain separate.
Callbacks signal only the owned cancellation latch and join actual completion.
No PID, deadline, timer, consent renewal or fresh host may expire a holder.
When composing the actual `DependencyService`/`ManagedLifecycleState`, the
factory automatically retains its exact existing `OwnedGenerationRuns` object
or attaches the new read-only-bound registry to that same private lifecycle
owner. State/root/control/owner/policy/manifest mismatch or two different live
registries is rejected. A lifecycle-selected candidate may differ from the
currently pinned active controller, but both must be registered exact bindings.
Lifecycle drain and controller execution therefore share `managed_runs` for
live cancel/join callbacks; independently reconstructed hosts can observe but cannot
cancel or steal crashed/sibling holders.

The existing WSL factory optionally consumes the same managed receipt/pin
bridge via `managed_verifier` and `managed_runs`, in addition to the existing
actual Windows-launcher and Linux-runtime verifier. Its installed digest must
match that managed receipt. This does not create qualification records or
permit a native Windows controller; real retained WSL descriptors and exact
Q03 proof are still required.

POSIX finalization now attempts child/channel/input close and owned group
teardown independently. A throwing or stalled broker revocation cannot skip
teardown: the private admission latch closes first, with bounded independent
revocation supervision. Missing completion retains its owner reference.
Received worker cleanup references are merged with later host references rather
than discarded. Launcher final control/resolver actions and backend control/
content/credential actions use the same bounded independent supervision.
The existing `backend.cleanup` I/O helper emits the matching bounded
count/duration/structured-log pair for actual returned cleanup failure,
including still-pending owner references; those references are never labels.

The new author controls use fake external verifier/process effects, including
the public factory-to-A02-to-S01 consuming path. They are source controls only,
not trusted installed tuple, fork, SSH route or real platform evidence. Complete
independent source census/coverage, shared lifecycle-drain release coordination,
actual application host selections, remaining operation adapters and platform
qualification remain explicit obligations; this increment alone does not accept
full S02.

The current shared `OwnedGenerationRuns.drain` snapshots live callbacks, then
unconditionally releases each snapshot pin after successful join. The consuming
controller already releases its exact pin after verified teardown, so concurrent
normal completion/drain can attempt a second release and raise `ContractError`.
The local source-only `nov20-s02-drain-gap-probe.py` reproduces this with the
real registry/adapter and fake process effects. This is unfinished shared SOURCE
coordination, not a missing platform qualification and not an approved deferral.
The dependency owner must establish one completion-aware release owner without
making release permissive or expiring crash/sibling holders. This increment
did not implement Windows kernel-job ownership or operation-specific health.
The following source increment supplies those two paths. Automatic application
bootstrap remains a separate source obligation; neither increment qualifies
an actual trusted tuple, fork, SSH route or platform.

## Windows outer Job Object and native health source (Nov 20)

The actual `_WslProcessIo` now calls the private `_windows_job` IO boundary,
not an unowned `Popen` leaf. It creates an unnamed, noninherited
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` job. `CreateProcess` uses
`CREATE_SUSPENDED`; assignment must succeed before `ResumeThread`.
No breakaway flag is used. A host-parent/nested-job restriction therefore
fails closed, never resumes an unassigned child and never changes privileges.
Executable, distribution, interpreter and argv remain the verified fixed
bootstrap selection. The Windows working directory is the selected executable's
parent, not ambient cwd. The explicit startup handle list contains only private
child stdin/stdout and a duplicated NUL stderr; parent pipe handles and the job
are not inherited. The environment contains only kernel-resolved SystemRoot,
LANG and PYTHONNOUSERSITE, never ambient tokens or credential fields.

The owner retains the actual process and job handles, waits on the process
handle and queries the job's active-process count before closing handles.
Cancellation terminates only this job. Kill-on-close also protects the owned
outer tree if the owner exits. An unproved startup cleanup retains its exact
process/job owner and blocks another launch on that port; it is not converted
to success or reopened by PID. Failures expose only a closed kernel-call name
and bounded numeric Windows error code when that provenance is available.
No raw FormatMessage/exception/path/argv is copied.

This is **Windows outer-tree ownership only**. The original private,
nonce/binding/HMAC-authenticated Linux group stop proof is still required and
consumed before terminating the outer job. Windows job emptiness never proves
that WSL Linux workers stopped. The finally path shares one original two-second
cleanup deadline across watchdog join, group proof, outer-job join and pipe
reader/writer/closer joins. Windows synchronous pipe IO is interrupted only on
the owned reader/writer thread handles. Unjoined monitors, pipes, jobs or Linux
groups remain explicit cleanup refs, preventing generation-pin release.

Gather no longer substitutes generic `show version` completion for health.
The authentic entered backend sends a closed, nonsecret `_HealthSelection`
through the existing intent frame, worker parser, broker bootstrap and private
action client. This selection is input, not host admission. Current
`OperationPlan.settings.health` supplies CPU/memory thresholds (80/85 by
default). The current fixed gather suite is CPU, memory, interfaces, BGP, VLANs
and environment; private selected subsets use those exact names only.
OSPF is explicitly unsupported. No arbitrary command, shell fragment, raw
configuration, native cache or ambient credential route is accepted.

| Native owner | Exact vendor selections | Measurement support |
|---|---|---|
| `netops.check.cisco` + native VLAN parser | `cisco_ios`, `cisco_xe` | CPU, memory, interface errors, BGP, VLAN status, temperature/fan/power |
| `netops.check.juniper` | `juniper`, `juniper_junos` | RE CPU/memory, interface errors, BGP, environment; VLAN unsupported |
| `netops.check.arista` + native VLAN parser | `arista_eos` | Parsed EOS CPU/memory measurements, interfaces, BGP, VLANs, environment |
| `netops.check.health` | `nokia_sros`, `brocade_fastiron` | CPU/memory and interface errors; other selected checks unsupported |
| `netops.check.health` | `paloalto_panos` | CPU/memory; other selected checks unsupported |

NXOS/XR/unknown formats are not silently passed to Cisco health parsers.
EOS's existing helper uses `show version` JSON for actual systemStats/memory
readings; a version-only response is unavailable, not a successful health check.
No vendor above is thereby SSH/platform-qualified.

Every native send uses fixed read-only commands and a 512-KiB reading bound.
Malformed/missing/empty parses, invalid percentages, absent required counters
and unsupported categories cannot become healthy zero. Native helper errors
are reduced before their legacy catch/log boundary, so logs contain a fixed
safe reason, not the native exception. Each selected check remains in order.
Minimized `health.checks` facts retain utilization/threshold/inclusive alert,
bounded numeric parsed `raw`, safe counts/temperatures and native parser/vendor
provenance. They contain no raw CLI output, interface descriptions, BGP
addresses, serial numbers or configuration. Findings distinguish pass, alert
and unknown independently of connection success. Later check/control or
disconnect failures retain already completed readings; the latter is a
separate cleanup fact. The callback guard recomputes consistency and refuses
unknown/sensitive fields. Backend/step/target aggregation preserves those
findings and FR-012 non-success.

Author controls exercise actual native helpers and the public A02/S01
workflow-to-frame-to-worker-to-broker-to-action-to-outcome source path using
fake device/private process ports. Separate controls launch legitimate
task-owned Windows Python helpers, observe actual job membership, cancel/join
descendants and test kernel handle closure. These are **author self-checks**,
not independent acceptance, actual Ansible fork execution, real SSH, consented
WSL execution, both-tier Molecule proof or complete Q03 qualification.
Both new modules are required installed-runtime members; exact public-source
registry regeneration belongs to the dependency owner, not this increment.
