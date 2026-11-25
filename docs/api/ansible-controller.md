# Private controller API checkpoint

PAN-OS CPU provenance now rejects impossible same-row component sums using
bounded original decimal precision, while allowing unreported interrupt/IO
components and preserving independent memory results. Nokia's same-row peak
must be at least its average; distinct Cisco/Brocade time windows are not
ordered. The wire schemas and numeric `raw` fields are unchanged. See the
[same-sample and native causal controls](https://github.com/plures/netops-toolkit/blob/main/documentation/ansible-controller/ansible-controller-architecture.md#nov-21-same-sample-cpu-consistency-and-cold-native-controls).
The fresh no-child native control reproduces +27 cold handles. Exact suspended
child kernel environment blocks also separate the fixed launch environment
from Store Python's subsequent `PYTHONUSERBASE` injection, with a direct native
creation baseline. Neither observation waives the retained cold/post-start
failures or qualifies a runtime.

Private successful CPU/memory callbacks retain bounded **numeric** `raw`
provenance under their exact native owner schema. Producer and receiver share
closed-key, required-reading and normalized-value validation; a Cisco reading
cannot substitute Nokia `peak`, and no owner can contradict its normalized
utilization. Memory counts must be exact safe integers with positive total and
consistent used/free/ratio values. PAN-OS permits its native omitted buff/cache
residual. EOS checks KiB-to-byte conversion and uses its native one-decimal
ratio; flat owners use two decimals. Unknown/text/credential/process fields
remain forbidden. The [owner table](https://github.com/plures/netops-toolkit/blob/main/documentation/ansible-controller/ansible-controller-architecture.md#nov-20-owner-specific-numeric-health-provenance)
defines each retained numeric field. This does not remove valid numeric
provenance to satisfy an obsolete blanket-raw-absence assertion.

Current native Windows Store-Python helper diagnostics do **not** satisfy
strict cold handle-count or post-start environment-equality assertions.
Exact returned job/process/thread/pipe handles close and repeated complete
owner lifetimes show no growth, but first `CreateProcess` initializes retained
Windows runtime resources. Store Python also adds `PYTHONUSERBASE` after the
minimal explicit environment was passed, even under `-I -S`. The
[diagnostic boundary](https://github.com/plures/netops-toolkit/blob/main/documentation/ansible-controller/ansible-controller-architecture.md#current-native-store-runtime-diagnostic-boundary)
preserves these failures and distinguishes OS/runtime initialization from
toolkit-owned resources. No environment-name allowlist, native launch argument,
handle threshold or qualification rule is changed.

Failed normal Windows-launcher close retains its exact cleanup owner and blocks
relaunch until actual teardown succeeds. Post-join retries close only remaining
owned handles, never a closed job handle. Private native Junos/EOS interface
health requires both actual input/output error measurements: missing/malformed
data is unavailable, whereas measured zero remains healthy. Other selected
facts and bounded numeric reading provenance are retained. These corrections
do not establish full S02 or platform qualification; see the architecture.

This is an implementation checkpoint, **not complete S02 support or platform
qualification**. See the [architecture and exact remaining work](https://github.com/plures/netops-toolkit/blob/main/documentation/ansible-controller/ansible-controller-architecture.md)
and [security boundary](../security/controller-protocol.md).

`netops.ansible.controller.ControllerLauncher(processes, credentials, state,
clock, events)` implements the existing `ControllerPort`:

- `verify(ControllerContext) -> ControllerReadiness` delegates to actual consuming
  installation verification; no import/version/path-presence inference.
- `run(ControllerRequest, ScopedCredentials, CancelPort) -> OperationOutcome`
  accepts only a private real host-prepared credential wrapper. Pure preview/
  check returns before every port/clock/event/credential access.

The trusted composition uses the existing real A01 broker/pending permit and
S01 resolver, not caller JSON authority. `HostDispatchControl` only subdivides
an already-entered exact effect. `HostControllerCredentials` contains the real
one-use resolved value and original scope. Both remain host-private and are not
public request DTOs or serialized consent tokens.

`ProcessPort.run(FixedLaunch, private_input: bytes, cancel) -> ProcessResult`
returns typed target facts, exit and independent cleanup, not stdout/exception
dumps. The optional `OwnedPosixProcesses` requires an injected actual
`InstallationVerifier`; it cannot certify itself. There is no delivered
automatically activated public bootstrap. A concrete private Windows/WSL adapter
now exists in `_controller_wsl`; it requires existing genuine installation
ownership and exact Q03 proof, current Windows byte pins and consuming Linux
runtime-byte proof, not a distro name or path-presence flag.

The fixed local action implements selected collection and native health observations and
guarded configuration apply/rollback using existing native engines. Configuration
mutation requires A02's authentic entered permit, protected prestate, exact
reviewed intent and distinct recovery consent. Credential/task/mutation phases
are one-use; check mode still returns before private-client access.
Actual ActionBase/fork/route qualification remains mandatory and unclaimed.
# Production composition checkpoint

Trusted bootstrap may compose the actual A02 host, S01 resolver, fixed controller
and public `WorkflowService.execute` using the private
`controller_backend._compose_owned_controller_service` factory. It is not a new
public API or permission source. Source readiness booleans cannot replace
current owned installed-byte/active-record and packaged exact-Q03 proof. The
current unqualified lock still blocks real execution.

Collected configuration has a separate bounded protected channel; only safe
line-count/status facts appear in ordinary results. A02's entered backup effect
consumes those bytes once and publishes them through the existing sensitive
artifact owner. Unpublished content is discarded on exit.

The backend transfers protected mutation inputs through the private inherited
pipe, never Ansible task variables, and the action invokes native guarded
push/vendor rollback through strict S01-selected routes. A02 retains prestate
ownership, exact host admission and separately preapproved recovery. There is
no host-native fallback. Lost completion after mutation admission stays uncertain;
verified state, primary failure and connection/controller cleanup remain separate.
Managed activation, remaining operation adapters, actual ActionBase/fork
qualification and Windows/WSL execution remain mandatory unfinished scope,
**not approved deferrals or qualified support**.

## Fixed WSL source checkpoint

Trusted bootstrap may use `_compose_owned_wsl_controller_service` with an
existing owner verifier. Only absolute pinned `wsl.exe`, the qualified explicit
distribution and managed Linux interpreter run the fixed worker module; no
shell, native Windows Ansible, install/adoption or arbitrary executable exists.
Private inherited frames carry startup/input/control; HMAC nonce/context proofs
and actual Linux-created runner-group control replace Windows-FD/PID assumptions.
Missing or failed group proof remains failed cleanup with owned references,
even when target facts or Windows launcher exit are already known.

These are source/fake-external-I/O author checks only. Actual POSIX/WSL/fork,
clock/suspend, isolation, leak, ownership and Linux teardown Q03 evidence is
mandatory later; no full S02 acceptance or qualified support is claimed.

# Managed installation binding

The private owned-controller composition can explicitly select I02 managed
installation records instead of the legacy active/install record pair. It
checks root registration, retained staged generation, activation verification,
pointer and exact generated installed receipt. Public constructor shape is
unchanged.

Real packaged Q03 qualification and exact installed runtime membership remain
required. Synthetic host qualification metadata, a native-only venv or an
arbitrary directory cannot enable a controller. The managed factory now wraps this existing public workflow-host path in
`controller_generation._PinnedControllerProcesses`. Trusted selections supply
the actual managed descriptor, root/control resources and installed runtime
location. Optional `managed_runs` must be the same private registry used by
lifecycle cancellation/drain, with identical protected state, owner, policy
and registered immutable generation bindings.

Pins precede managed receipt/installed-byte proof and actual dispatch. A
dispatched pin releases only after proved owned group/pipe teardown; unproved
completion or release failure retains its holder and safe cleanup reference.
Fresh hosts cannot expire or steal a holder. The WSL factory can use the same
managed binding through `managed_verifier`/`managed_runs`, while still requiring
its real Windows/Linux consuming verifier and Q03 tuple proof.

POSIX finalization attempts every owned close/teardown independently of throwing
or stalled revocation, preserving primary and all cleanup references.
These are source paths with author-only fake external-effect controls, not
full S02 acceptance or Linux/macOS/consented-WSL execution qualification.

The current shared lifecycle drain still has a source-level double-release race
after actual controller completion. The Nov 20 increment supplies the concrete
Windows outer kernel-job launcher and operation-specific native health adapter.
Application bootstrap remains separate source scope. No remaining source
obligation is relabeled a Q03-only qualification gap or approved deferral.

## Owned Windows outer launch and health adapter

`_WslProcessIo` now creates an unnamed kill-on-close Job Object and launches the
fixed trusted child suspended. It assigns the child before resume, explicitly
inherits only private IPC/NUL handles, uses the selected executable's parent as
cwd and excludes ambient environment/credentials. Real process/job handles are
retained until actual wait and zero job membership. Nested-job restrictions fail
closed with bounded numeric kernel error provenance. Windows job completion
**does not prove Linux cleanup**: the original authenticated owned Linux group
stop/join proof is still consumed separately. Unproved teardown retains cleanup
refs and the generation pin; one original two-second cleanup deadline bounds
group, job, watchdog and pipe joins.

Gather uses a closed private native-health selection with current plan CPU/
memory thresholds. The fixed suite is CPU, memory, interfaces, BGP, VLANs and
environment. Actual helpers in `netops.check` run only fixed read-only commands.
The [source-format support matrix](https://github.com/plures/netops-toolkit/blob/main/documentation/ansible-controller/ansible-controller-architecture.md#windows-outer-job-object-and-native-health-source-nov-20)
lists exact Cisco, Junos, EOS and flat-format support; unimplemented categories
(including OSPF) are unsupported, never Cisco fallback. Missing/malformed
measurements cannot become healthy zero. Safe ordered facts retain native
utilization/threshold/inclusive alert, numeric parsed provenance, bounded counts/
temperatures and independent findings/connection cleanup. Raw CLI/configuration/
native exception text and credentials are excluded. A version-only EOS response
does not qualify its actual numeric health readings.

Author controls include the consuming public workflow/private worker/action
source path with fake external ports, plus distinct actual task-owned Windows
Python job launch/cancel/descendant-join/kernel-close checks. They do not establish
actual Ansible forks, SSH vendor/route qualification, approved WSL execution or
Molecule/Q03 acceptance. Existing legacy `netops_facts`/role paths are not
silently executed or used as authority by this private adapter.
