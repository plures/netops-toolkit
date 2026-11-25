#  Dependency registry and readiness

For an operator-oriented walkthrough of the implemented commands, consent,
readiness, controller limits and owned update/recovery/uninstall actions, see
the [dependency setup and controller guide](../guides/setup-and-controller.md).
The guide distinguishes available interfaces from still-unqualified platforms
and companion tiers.

## Nov22 factual consuming context — no implicit Windows discovery

The production context producers no longer call `platform.machine()`.
On the actual Python 3.12 host, that seemingly read-only call enters
`platform.uname()` → `win32_ver()` → WMI OS metadata and `_get_machine_win32()`
→ WMI CPU architecture. Fallbacks also run `ver` through a shell.
`packaging.Marker.evaluate(environment)` **still** calls `default_environment()`
first, even when all overrides are supplied. Windows `packaging.tags.sys_tags()`
also enters `platform.system()` through its default platform selection.
These baseline paths were established from existing source, not executed.

The shared private `_context_facts` boundary now supplies bounded factual inputs:

- Windows `GetCurrentProcess()` returns only this process's pseudo handle;
  `IsWow64Process2(HANDLE, WORD*, WORD*)` returns native and process machine
  separately. There is no process enumeration, handle open/close, child creation,
  WMI or shell. Missing API, failure or unknown machine yields typed
  `_ContextUnavailable`, never an environment-variable guess.
  `GetNativeSystemInfo` is not substituted: emulation can obscure the native
  ARM64 host. Linux/macOS host architecture uses `os.uname().machine`.
- Frozen `ConsumingContext.architecture`, `_Target.architecture`, readiness
  interpreter observations and guided `host_architecture` retain **host**
  architecture meaning and existing canonical names (`x86`, `ARM`, `ia64`,
  `AMD64`, `ARM64`). Context IDs, executable/path/collection/runtime/grant
  inputs and digest fields are unchanged.
- Windows wheel tags retain **process-build** meaning. The actual upstream
  public `cpython_tags`/`generic_tags` and `compatible_tags` receive explicit
  `sysconfig.get_platform()` platforms in their original priority order,
  without Windows `sys_tags`/`platform_tags` discovery. Host architecture is
  not used as a substitute for interpreter ABI/tag compatibility.
  Compatibility selection independently follows installed packaging 24.2
  `sys_tags`: `cp` plus interpreter version for CPython, `pp3` for PyPy,
  and `None` for other implementations. Primary generic interpreter/ABI
  computation is unchanged. This fixes source mismatch `N22-CCR-TAGS-01`,
  not actual PyPy/other runtime qualification; independent assertions remain
  tester-owned and only prior actual AMD64 CPython facts are qualified.
- The actual upstream `Marker` parser/tree, `_evaluate_markers(markers,
  environment)` and `_repair_python_full_version(env)` are used unchanged.
  Extra canonicalization, version/comparison operators, Boolean/eager
  traversal and trailing-`+` repair remain upstream-owned. No global
  platform/packaging mutation, local marker grammar or operator port is used.
  These existing **private Python interfaces** are checked for their observed
  signatures, not asserted to be a stable public ABI. Installed and existing
  ensurepip-vendored packaging **24.2** were source-inspected; this is observed
  provenance, not a new dependency pin or universal version qualification.
- Marker inputs describe the actual running implementation/Python and host.
  Windows `platform_release`/`platform_version` are **unavailable**, not empty
  strings, fabricated marketing releases or kernel-version equivalence claims.
  A marker referencing either rejects `marker-fact-unavailable:<field>`;
  unsupported upstream interfaces reject `upstream-marker-interface-unavailable`.
  POSIX release/version come from `os.uname()`. Foreign target platform,
  architecture or Python version rejects
  `independent-target-marker-facts-required`, rather than overlaying host
  facts into an invented target environment.

The fixed isolated interpreter and wheel-metadata programs share the exact
packaged `_context_facts.py` prelude via `_context_program._CONTEXT_PROGRAM`.
They do not import a platform shim or an uninstalled toolkit in the selected
child. Existing actual wheel bytes, hashes, Python ranges, active dependency
closure, transitive-extra declaration gate and admitted interpreter/tag checks
remain required. Cache review's descriptive profile is not target qualification
and can no longer impersonate a foreign Python/platform marker environment.
Documentation closure maps unavailable marker facts to
`documentation-marker-facts-unavailable`; publisher and setup/installer paths
retain their existing safe failure categories and pre-effect boundaries.

This source increment supports FR-003/005/006/007/035 and AC-001/011/014;
it does not discharge them. Actual cached/guided/admitted-install controls,
independent semantic/omission tests and other runtime/platform cells remain
tester/reviewer work. Existing POSIX tag discovery is unchanged and was not
executed or qualified here. Windows release-sensitive markers and foreign
targets still need actual equivalent bounded facts, not a permission reset.
All historical incidents remain OPEN; original source guards, exact pins,
native captured hp/ht/PID/TID, deadlines and one-use/category grants are retained.

## Nov22 offline transitive extras — source correction awaiting tester proof

The existing offline wheel verifier now applies the same actual `Provides-Extra`
declaration check to root extras and extras contributed by active recursive
`Requires-Dist` edges. All extra names use packaging canonicalization, so case
and dash/underscore/dot aliases share one marker context and checked state.
Undeclared transitive extras reject the closure instead of being ignored.
Already visited dependencies are revisited when another edge adds an extra;
their newly active feature requirements must also have selected compatible
wheels. Inactive environment-marked edges contribute nothing. The existing
fixed-point traversal is retained, not replaced by a resolver or online install.

Private consuming contracts (no public signature, wire reason or exit changes):

| Consumer | Exact verifier inputs | Rejection boundary |
| --- | --- | --- |
| `_setup._cached_closure(manifest, document)` | Trusted `sys.executable -I -B -c _WHEEL_METADATA`, JSON wheel descriptors, JSON descriptive Python/platform profile | Before resolved guided candidate or direct setup root reservation/consent; guided metadata retains `verified-offline-cache-required` / `verified-cache-member` |
| `_OfflineInstallation.install(manifest, assets, clock, cancel, deadline)` | Pinned `spec.python -I -B -c _WHEEL_METADATA`, JSON selected descriptors, no profile | Before installation-target creation, `_VENV` or offline pip; existing guarded failure handling |

Success remains the private `verified-wheel-metadata-closure` marker after all
checks; it is not readiness, source authority, consent or platform qualification.
Cached profile checking uses same-host/interpreter facts only and does not replace
the admitted interpreter's real tag, Python-range and byte/hash checks.
All issuer/native identity/source guards,
original deadlines, one-use/category grants and owned cleanup remain required.

Tester proof is still pending for declared/undeclared transitive extras, missing
active feature leaves, later/multiple inbound extras, cycle convergence, inactive
markers and canonical aliases, including each real consuming rejection path.
An omission control must remove only the recursive declaration assertion and
make the negative test fail at its assertion. Existing public golden bytes and
source/issuer/member/context/consent controls must be retained.
This source/docs-only original I02 increment supports AC-001/011/014 without
closing them, full I02/S02, authentic publisher/platform or installed-delivery
qualification. Historical O03/O04 dispositions and the original DAG remain;
no new Q03 prerequisite is introduced.

## Nov22 live composite source increment — independent verification pending

Read-only first-run planning is distinct from admission: it consumes the actual
family resolver, preserves declined/reuse prerequisite needs, and reports both
current native/controller toolkit wheel requirements. Missing contributions
refuse a resolved compound candidate before layout compilation; they do not
overwrite unresolved factual metadata needs. Actual public/compiler/source/host
effect admission remains unchanged. Prior whole-suite evidence does not verify
these repaired bytes.
Separate source-owner grouped diagnostics did not reproduce native busy or the
one-second provision failure; both original whole-run causes remain unresolved.
No storage, duration or authority exemption follows from those passing controls.

The joint bootstrap/compiler route now retains the real resolver's private
per-release contributions, one for every selected native/controller family
subset and transitive edge. Only the existing closed PyPI, Galaxy, Python.org
and official-profile clients using the actual HTTPS transport can issue them
after their original pinned metadata observations validate. A decoded lock,
equal reconstructed contribution, callback, `trusted` flag or receipt cannot
replace the issuer-retained identities. Each contribution keeps its original
client/transport, target, source pins, process/thread and observation expiry.
This is source/input provenance, **not** new platform qualification or consent.

The complete compiled manifest, installation members, selected extras, original
protected consuming root/context, separate interpreters and cache presence/bytes
are bound before actual lifecycle admission. Its composite digest is factual
plan/receipt binding only. Every existing managed handler's live source guard
rechecks both the original independently qualified `native.stdlib` producer and
all selected publisher contributions. The native producer's scope, input/cache/
tool/output/member/ledger checks and original deadlines remain unchanged.
Missing live contribution authority blocks; historical JSON cannot renew it.
The existing broker, protected staging, offline installation and typed family
handlers still own effects, not a new parallel dispatcher.
Compound/full/enhanced public admission, concrete host construction and source
eligibility share the same predicate. A publisher-only compound request returns
`live-selected-family-contributions-required` before publisher observation,
setup consent, root creation or installation. Narrow legacy native layouts
retain their existing boundary. Actual typed family handler entry additionally
requires that operation's exact issuer-retained release, lock and generation.

Owned installation processes now recheck the same source guard after real
spawn/assignment and after joined completion. Successful child join, Job close,
reader join and pipe close are recorded individually; finalization retries only
remaining owned resources. It does not terminate a joined child again or replace
the primary source/cancellation/deadline failure with cleanup failure.
Windows installation creation now calls the already supported native
`_winapi.CreateProcess` directly, retaining its exact returned process handle,
primary thread handle, PID and TID. It no longer lets `Popen` discard the primary
thread and then discovers it again. Only the three explicitly duplicated child
standard-I/O handles are inherited; parent pipe handles remain noninheritable.
No Toolhelp snapshot, global process/thread scan, PID/TID reopening, speculative
Nt ABI or global `Popen`/`_winapi` mutation is used.
Before activation, `GetProcessId` on the retained process, `GetProcessIdOfThread`
on that same captured thread, and `GetThreadId` must agree with the retained
creation identities. The unnamed private Job is assigned **before** resuming
that exact thread. Missing APIs/authority and mismatched identities fail closed;
there is no discovery fallback. Cancellation, the original deadline and the
live source guard are rechecked while the child is still suspended.
The native child owns its primary thread through identity verification and
activation; the Job owns only its Job handle. Child-side pipe duplicates, the
primary thread and joined process handles close individually, once and never
as handle zero. A failed close leaves the exact handle retained; an unjoined
process handle remains available for rightful exact-child kill/wait retry.
Exceptions retain these actual cleanup owners through safe primary/secondary
wrapping, not PID-based reconstruction or renewed execution permission. Native
failures preserve their numeric Windows code. Failed cleanup never erases the
primary assignment/resume failure or marks remaining resources released.
The same private runner serves installation, owned builds, setup, platform
handlers and the strict documentation bridge; their admission and source
contracts are unchanged. POSIX process-group creation is unchanged.
These are source corrections, not fresh native platform qualification. The
earlier unapproved global-enumeration incident remains open; historical and
synthetic own-PID/TID receipts cannot qualify this runtime.
Finalization attempts remaining stop/kill-on-close releases twice before any
join, including assignment failure. Process waits and reader joins share one
nonrenewing, one-second real-monotonic teardown self-limit; this is not a probe,
grant or observation TTL extension. Successful waits, kills, joins and closes
are skipped on later passes. A reader still alive at the limit remains explicitly
unjoined; its buffered pipe is not synchronously closed while it holds the read
lock. Readers are daemon threads so cleanup uncertainty cannot become an
unbounded interpreter-exit join. Remaining timeout/close failures are reported
through the existing structured cleanup errors, preserving the exact primary.
Simultaneous native stop/close failure with a live owned child and never-finishing
reader controls require fresh independent tester verification of these bytes.

An isolated untraced unchanged publication/source-drift control reached real
generation publication and then rejected actual source mutation with zero
installer entries. Historical native `protected-storage-busy` was **not**
reproduced or causally resolved; no timing, locking or permission workaround was
introduced. The live composite route and post-spawn cleanup require independent
load-bearing tests. Authentic pins, actual supported POSIX/controller/guest
layouts, all selected host-package handlers, both real Molecule tiers, full
I02/S02 acceptance and configured build remain unqualified. No artificial
official archive, signing/license proof or new platform qualification was added.

## Nov21 source correction boundary

Public `verify` now returns typed blocked readiness when its original 60-second
budget expires, including a late policy return. It does not call policy after
exhaustion, renew a budget, cache expired readiness, or catch actual adapter,
policy or invalid-clock defects. Each attempted dependency still emits its one
paired probe observation. Guided diagnosis consumes the returned deadline reason
and requests a fresh bounded observation instead of reusing earlier probes.

### Closed official publisher source profiles

The Nov21 18:47 PST decision approved **source/models/mocked boundary checks** for
the official profiles; the old pending decision is historical, not present
authority. `_official_profiles` implements actual bounded metadata adapters for:

| Profile | Exact source scope | Metadata/integrity input |
| --- | --- | --- |
| Ubuntu packages | `archive.ubuntu.com/ubuntu/dists/`, `security.ubuntu.com/ubuntu/dists/`; corresponding `pool/` artifacts | Exact raw Packages SHA256 and independently reviewed package/qualification pins; exact package/version/architecture/size/filename/dependency fields |
| Homebrew | `formulae.brew.sh/api/formula/<formula>.json`, `ghcr.io/v2/homebrew/core/` | Exact formula SHA256, bottle SHA256, platform bottle tag, license and dependency closure |
| MSYS2 | `repo.msys2.org/mingw/` exact repository database/package | Bounded actual TAR database desc member, exact package/version/architecture/hash/size/license/dependency pins |
| Git for Windows / Podman | Exact numeric release records under the two official `api.github.com/repos/.../releases/` projects; matching `github.com/.../releases/download/v<version>/` assets | Independent raw release and artifact pins; exact asset ID, digest where published, size and release tag; draft/prerelease rejected |
| Fedora minimal image | `registry.fedoraproject.org/v2/fedora-minimal/` immutable manifest/config digest objects | Exact manifest plus complete ordered config/layer digest/size pins; actual bounded config verifies OS/architecture |
| Ubuntu cloud | `cloud-images.ubuntu.com/releases/` exact build/files | Raw checksum and independent image pins; WSL rootfs is not inferred from a VM image |

`SetupMetadata.publishers(..., official_records=())` accepts typed `_OfficialPin`
records through the same factual registry as existing publishers. The packaged
catalogue v3 adds an empty `official_records` array; v1/v2 remain readable.
No authentic key, artifact/metadata pin, license verification or platform
qualification was invented. The supported integrity branch requires an
independently reviewed **exact raw metadata and artifact pin**, bound to a
qualification reference and exact license identity. OpenPGP/OCI signing-key
enrolment and live verification are **not implemented or claimed** by these pins.
An empty official catalogue returns precise `NeedsInput` before HTTP.

The native host, controller/guest consuming target, layout (`native`,
`direct-controller`, `wsl2-guest`, `vm-guest`), platform release, Python, ABI and
wheel tags are separate immutable values. Native Windows Ansible is rejected.
Matching aliases such as x86_64/amd64 are comparisons, never fabricated responses.
Package formats stay truthful: Debian/MSYS2 packages are `host-package`, not TAR
archives. Unrepresentable native version/dependency ranges remain blockers rather
than being coerced into permissive PEP 440 ranges.

All metadata calls retain original cancellation and the same 60-second window.
Traversal, encoded-path aliases, queries, generic release projects, wildcard/CDN
redirects and caller transport/signature callbacks are rejected. The existing
acquisition/installation origin and producer guards remain unchanged: successful
metadata compilation is **not** permission to acquire a new publisher artifact.
Complete native-package extraction, cross-context controller layout, signing/
licensing qualification, runtime dispatch and fresh wheel/sdist installation
proof remain open. Existing daemon-free/delegated Molecule and optional container
tier qualification remain distinct; this increment does not claim either tier.

### Owned strict local documentation

The registry now owns the `native.core:docs` intent and `extra:docs` requirements
for MkDocs, Material, mkdocstrings and autorefs. Full selection includes that
intent; unrelated native selections do not import documentation tooling.
The family compiler requests mkdocstrings' actual `python` extra.

Both installers retain `[tui,snmp,report,docs]` delivery semantics without global
pip. After successful install/update they offer the owned strict docs bridge;
`install.sh --docs-only` / `install.ps1 -DocsOnly` runs it independently with
already installed compatible tooling. `NETOPS_DOCS_DIR` remains the output
contract (`-DocsDirectory` on PowerShell). Missing tooling is a precise input,
never a new download, global install or unchecked manual-install fallback.

The bridge reviews the exact registry/installed transitive dependency versions,
interpreter hash, source-file seal and **new** output path. A separate one-use
`build-docs <plan-digest>` confirmation precedes all writes. It copies reviewed
source into the new protected owner-only root and invokes exactly:

```text
<selected-python> -B -m mkdocs build --strict --config-file <owned-output>/reviewed-source/mkdocs.yml --site-dir <owned-output>/site
```

Only this closed standalone build may consume already installed user-site docs
tooling; all installation children retain isolated/no-user-site behavior.
No shell, pip/config/rc mutation, new network or existing output/ACL adoption is
performed. Source and output bounds, cancellation cleanup and the original
300-second build bound remain enforced. A successful strict receipt binds actual
output hashes, not publisher or managed-generation qualification. Failed strict
links and partial owned output are preserved; no link validation is weakened.
Existing output requires a new reviewed output choice, not destructive rebuild.
The strict source-link failures and independent proof that this delivery is
equivalent to installed-generation docs remain explicit blockers.

Source setup is importable without site packages/PyYAML: lifecycle admission
does not eagerly load operational YAML hydration. The real full registry still
owns selection; missing complete offline pins block before creation/installation.
Inactive uninstall terminal receipts now retain their factual `Admitted` phase
and require all selected trees absent, no remaining references, unchanged expected
pointer and empty bound pins before correlated one-use completion. Partial
failure preserves actual errors/removal/remaining references, not success.
These source corrections are not complete-installation or POSIX/WSL qualification.

Trusted owned setup composition can explicitly select the existing observation
maximum-age setting (default 60 seconds, allowed 1–300) when creating a new root.
The exact protected root-manifest digest binds it before planning and review;
the review prompt shows the selected value. Existing roots retain their default
and issued observations/grants are never extended. Functional source/tree verification,
public readiness and adapter deadlines remain unchanged, as do full byte,
ownership, source and context rechecks at activation CAS.

`netops.dependencies` provides the read-only I01 prerequisite product. That boundary does
not install, download, start a runtime, unlock a vault, contact network devices,
grant operating-system privileges, or certify a platform. Installation is I02;
actual platform/route qualification is Q03. No native workflow was replaced.
The later [I02 lifecycle increment](ansible.md#i02-dependency-lifecycle-increment-incomplete-product-integration)
adds admitted service coordination and a pinned acquisition primitive, but is
not the complete product installer. A catalog preview alone is not executable;
A02 inert evidence cannot qualify or activate a controller.
The public managed increment now composes exact registered native archive
effects through the actual broker, managed staging handler, functional probes,
canonical reducer checkpoints and pointer CAS. Actual interpreter provisioning,
pip/package/collection/runtime effects and full product qualification remain
unfinished. These are mandatory original obligations, not approved deferrals.

## Public contract

### Closed bootstrap contribution and separate Python layouts (source increment)

`SetupMetadata.compose(native_bootstrap, publisher_setup)` now joins the existing
live qualified producer to the production full-family setup route. Both operands
must be closed `SetupMetadata` values: the native operand retains its actual
`_OwnedSource`, exact installation, generation and protected consuming root; the
publisher operand selects the real lock compiler. Neither JSON nor a callback
can supply this contribution.

The contribution is **separate**, not an archive hidden in the publisher lock.
Its factual digest is pinned in the future generation manifest and therefore in
root metadata, plan, consent, installed receipt and activation bindings. Public
setup re-inspects the original producer before planning/effects; managed source
guards repeat that check before each dispatched occurrence, every fresh download
attempt after broker entry, staging intent and file/installation/verification
boundaries under the protected root lock, and family authority I/O boundaries.
Probes/activation, retained restore and bound uninstall retain their checks.
These are live inspections of the original actor, not cached equivalence or
renewed consent/deadlines; publisher assets do not suppress bootstrap inspection.
The actual stage handler retains a private in-process reference to that live
owner while holding its original lifecycle lock. Protected materialization
checks it before each new directory/member and generation publication, and
again after publication before entering the offline installer. The same
reference is carried to every subsequent installation directory/member/receipt
effect and fixed process spawn, consuming verification, and the controller
child installation. Windows checks again immediately before directory creation
and before assigning/resuming its newly created suspended process. No
serialized callback, reconstructed capability, new grant or extended budget is
accepted. Already written members, published generations and failed partial
installations remain factual owned evidence; rejection never sweeps them or
blindly replays installation. These boundary changes await independent
source-bound drift tests and review; they are not full-scope safety acceptance.
Resume/update must again supply the actual independently configured producer.
A stored digest is only a fact: absent producer authority returns
`qualified-bootstrap-producer-required`, not reconstructed consent or readiness.
Re-inspection retains exact process/thread, source/input/cache/tool/output/member,
native context and consuming-root guards. It never changes the producer's
qualified scope beyond **`native.stdlib`**, uses its wheel as a Python.org/PyPI
artifact, or qualifies the future full selected scope. The future toolkit wheel
still needs its own exact current publisher pin and complete dependency closure.
The source-bound empty root may be initialized only after exact separate review;
unknown/nonempty roots are never adopted.

The complete compiler now creates a native installation and, when selected, a
**distinct controller installation** under
`installation-<generation-digest>/controller` on the same supported Linux/macOS
host. The new optional `controller_installation` descriptor retains its own
Python path/digest/version, wheel closure, wheelhouse, tools, native libraries and
collections. Each installation validates and consumes its actual interpreter.
Both receipts bind the whole parent descriptor; verification rehashes both
trees, and owned parent removal includes only its pinned controller subtree.
The production managed controller consumer accepts the parent descriptor and
parent `installation-<generation-digest>` root, not a relabelled native descriptor
or a separately adopted child root. It retains the complete parent installed-file
receipt, active pointer, qualification and generation pins while selecting
`controller/bin/python` and requiring the qualified runtime members to lie in
that child. The child's installation receipt is a pinned member of the parent
tree. The complete parent tree is still independently owner/byte/member checked.
The packaged qualification lock remains mandatory; this source correction is
not a POSIX/controller or full selected-scope qualification.
Legacy descriptors omit the new optional fields and retain their original wire
bytes. A compound descriptor requires the complete family lock; it cannot be
introduced as an unqualified arbitrary-program descriptor.

`SetupMetadata.publishers(..., interpreters=(), publisher_contexts=())` consumes
typed `_InterpreterPin` and existing `_PublisherContext` values. These are
independently retained factual choices, **not** qualification/grants. A selected
direct interpreter must match its role-specific target, the independently locked
executable member, actual no-follow file bytes and qualification reference.
Native and controller Python versions/ABI/tags are not inferred from one another.
The compiler requires a current toolkit wheel in each selected installation;
the controller toolkit requests its actual `ansible` extra. An Ansible-only
selection neither requests Molecule nor invokes its CLI.

The existing `native`, `direct-controller`, `wsl2-guest` and `vm-guest` publisher
profiles are consumed before publisher observation. Guest framework, Python/ABI/
wheel tags, collection and native-library closures remain distinct factual
inputs. Guest layouts currently return typed
`qualified-guest-consuming-layout-required` with their exact missing root,
route/receipt and separate-category-review obligations **before HTTP, creation,
installation or grant issuance**. Native Windows remains prohibited as an
Ansible controller. Saved WSL/VM/runtime/security category choices remain only
prospective review requests; no guest, OS feature, runtime or service is started.
Actual existing/consented WSL dispatch, guest installation/storage and full
platform qualification remain mandatory unfinished work, not scope deferrals.

Composition preserves the selected creation-bound observation setting (including
180 seconds when selected), rejects conflicting settings, and does not extend
existing observations/grants. Source/probe and lifecycle limits remain the
original 60/300 seconds. These changes are source-only, pending independent
testing/review; authentic catalogue pins, both real Molecule tiers, all-platform
functional proof and complete I02/AC acceptance are **not** claimed.

The production family compiler now retains selected native package extras on
the exact current `netops-toolkit` root requirement. Complete registry groups
select `tui`, `snmp`, `report`, `report-pdf` and `docs`; controller-only Ansible
never adds the Ansible extra to native Windows. The resolver therefore checks
the toolkit wheel's actual extra dependency edges, not only independently
selected top-level versions. A stdlib-only selection keeps its original exact
unadorned toolkit requirement. Publisher pins and functional qualification are
still mandatory; this source change does not make an empty catalogue usable.
The exact selected extra sets are retained in the new optional
`requested_extras` installation field. Actual offline wheel metadata validates
declared extras and their active transitive dependencies separately for each
role before creating its venv. A changed extra set invalidates the descriptor,
lock/admission and receipt bindings.

Guided continuation preserves each saved prospective consequential-scope choice
when the user accepts its displayed default. A saved `review` remains only a
request for a later exact review: checkpoints contain neither grants nor
permission to install, change the OS, start a service or enable a container tier.

The compatible transitive family lock is now consumed by the existing guided
metadata compiler and managed lifecycle owner. Trusted embedding hosts can use
`SetupMetadata.publishers(...)` with an independently pinned complete catalogue,
actual consuming-context bindings and verified offline cache. Passing `None`
for installation and empty archives selects the same production lock compiler
used by descriptor-free setup; an explicitly supplied layout remains compatible.
Its closed bounded PyPI/Galaxy and Python.org clients read official version metadata;
construction performs no I/O and metadata never grants acquisition.
The public constructor accepts `python_files=()` containing typed retained
`_PythonFile` facts (qualified release plus exact official file ID), or the
exclusive `python_records=()` containing typed `_PythonSeed` raw-record and
separately verified archive/member facts. `publisher_records=()` accepts the
typed raw PyPI/Galaxy seeds, exclusive with retained releases for each source.
The same factual registry validates and registers public and packaged inputs.
A bare normalized Python release lacks the mandatory official file identity
and remains rejected: no endpoint ID, source pin or transport is invented.
There is no caller transport, callback, fallback URL or serialized grant input.
Descriptor-free install/update now constructs this production resolver itself,
with registry-derived requirements and observed native/controller target tags.
The fixed packaged `publisher-catalogue.json` owns retained PyPI/Galaxy releases
and Python.org release-file IDs; request JSON cannot replace that resource.
The exact v2 resource additionally supports `publisher_records` (source, package
name, version, filename, independently retained raw metadata SHA256) and
`python_records` (official file ID/version/raw metadata pin, separately verified
archive SHA256, archive format, qualified platforms/architectures and exact members).
The former compiles actual publisher SHA256/size, requirements/extras and wheel
tags from bounded official JSON, then runs the existing full validators. It does
not accept a request-supplied normalized response or transport. Missing official
`Requires-Python` is retained as the empty unrestricted PEP 440 range, not an
invented publisher constraint. V1 retained release records remain readable.
All installed arrays are deliberately empty: no independent publisher/artifact
pins have been invented. Every selected dependency is still examined and
missing catalogue evidence is a specific resumable `NeedsInput`, before HTTP,
root creation or consent. A complete compatible verified lock now feeds the actual
default archive/cache/installation/context compiler. Cache files have the fixed
layout `<selected-root-parent>/netops-publisher-cache/<sha256>/<publisher-filename>`;
the filename matters to the original wheel-metadata validator. No wrapper archive
or synthetic digest is created. The existing interpreter must match an executable
member's separately retained digest/version/platform/architecture. The current
toolkit wheel and its complete dependencies are mandatory even for native setup.
Future consuming-context paths are bound before metadata observation, not rewritten
into an existing lock afterward. Identical package contributions may serve both
roles through separately compiled native/controller venvs, or through a legacy
compatible shared descriptor. Conflicting role versions or ABI-specific wheel
bytes require the compound direct-host layout; a distinct Windows guest still
requires an actual separately qualified guest layout. Role aliases share an archive only
when publisher origin, URL, SHA256, size, family, version, format and every member
agree; role locks/receipts are not collapsed. Missing optional metadata parsers
return precise `NeedsInput` before any publisher HTTP request. An Ansible-only
controller does not force an unselected Molecule wheel or CLI invocation.
For a complete offline cache,
actual bytes, archive membership and wheel/collection metadata are revalidated
before root creation and again by the admitted original installer.
Missing pins are precise `NeedsInput`. Missing cache instead compiles prospective
exact publisher-download effects without doing them. Only that live compiler
result supplies the closed production acquisition port to the original host;
request JSON, saved documents and historical locks cannot reconstruct it.
The original live lifecycle permit still gates each exact download. This live
binding also retains the original publisher expiry, bounds each request by its
remaining time and checks it again after I/O; neither review nor a cache miss
renews it. The original acquisition owner dispatches the exact closed publisher
wrapper's bounded operation, passing its latched clock and the same live
cancellation handle through to HTTPS. An interrupted HTTP child retains its
original interruption; a response already returned by the external boundary
retains the original factual `cancelled_after_acquisition` receipt, with later
stage dispatch still guarded. Generic injected transports do not gain this
production-wrapper authority. Acquired
archive/package metadata is checked by the original stage/installer before
interpreter effects. No global or mutable cache is written; acquired bytes
contribute only to the consented protected generation. A present corrupt cache
is preserved and blocks, never triggers an overwrite or fallback.
Interrupted pre-stage acquisition requires verified cache or a newly qualified
current candidate/review; serialized history cannot renew network authority.
Separate controller provisioning and complete platform metadata/dispatch remain
unfinished; this is not a full-installation claim.

The bounded official Python.org adapter binds an exact release-file endpoint,
raw response digest, file ID, artifact URL and size to independently retained
SHA256/member pins. Legacy MD5 is not an integrity pin. Its live API/platform
compatibility is unqualified. Corrupt/missing default catalogue resources retain
the public selection/checkpoint and a bounded `planning_failure`; neither raw
paths nor exception messages become a public diagnostic.
Creation computes the immutable canonical root binding before writing seed
records. A mutable Python dictionary is not a canonical public DTO; hashing it
previously stopped the first-run producer route after initialization records,
before the later installation-consent prompt. This is separate from historical
native-child errors and does not adopt or rewrite previously partial roots.

The original admitted installer performs protected-tree effects; registered
interpreter/wheel/executable/collection/library hooks verify those effects and
record actual postconditions in owned family ledgers. A transitive artifact
merely present in staging cannot stand in for its consuming installation.
These real post-stage materialized hooks reverify already installed bytes under
the original grant; they do not reacquire a publisher artifact after its metadata
expires. General/platform install hooks retain the publisher-freshness gate.
Concrete prospective source drivers now route rootless Linux Podman binaries,
immutable OCI archives, generation-specific transient user services, the two
fixed Windows WSL/virtualization features and exact WSL2 imports through closed
typed operations. They use the original broker, extra live semantic reviews,
protected owner and exact resource ledger. No caller-supplied argv, global
daemon fallback, mutable image tag, implicit elevation/reboot or preexisting
service/distro adoption is accepted. OS-feature uninstall retires its recorded
declaration, never disables a shared feature. No real platform effect is
authorized or qualified by this source increment.

Inactive family uninstall composes reverse platform removal, exact original
tree removal, then materialized-family ledger retirement. Active/pinned and
recorded prior-healthy resources are preserved using live owner facts. A lost
materialized-install acknowledgement can reconcile only from fresh exact
read-only postconditions. Concrete platform handlers now separately retain an
exact post-I/O result in protected owned state before the family-ledger
acknowledgement. A fresh admitted verify can reconcile a lost install acknowledgement
only when that exact receipt matches and a new read-only resource query confirms
its identity/state. Fresh uninstall can reconcile an identical issued removal
without dispatching it again: protected removal receipt plus exact absence query
are required for platform effects; materialized removal requires the original
owned trees absent. Missing postcondition receipts, foreign identities, changed
state and unknown ownership remain blocked. These receipts are facts, not saved
consent or renewable authority. When an earlier platform failure prevented a
later materialized-family receipt, fresh admitted read-only verification of the
original protected tree and installed receipt can record that family's factual
membership. Unknown external resources cannot use this path. Complete
multi-platform provisioning, cache/layout bootstrap, platform-loss reconciliation
and full update/resume qualification remain unfinished. Missing metadata, incompatible
layouts and unsupported providers retain the full selection as `NeedsInput`;
they never manufacture readiness. Offline external-boundary controls prove
SOURCE, not live publisher/platform qualification or Q03. See the
[architecture boundary](https://github.com/plures/netops-toolkit/blob/main/documentation/dependencies/dependencies-architecture.md#private-full-family-resolution-and-dispatch-building-blocks)
for the remaining integration and ownership requirements.

An embedding host may explicitly bind an `ObservationSettings` value when
creating a new root. Retained roots keep their creation-bound setting; a later
request cannot extend it or existing evidence. Functional probes remain bounded
at 60 seconds and lifecycle grants at 300 seconds. Predictably excessive Windows
launcher/cwd/member paths return a shorter-user-owned-root choice **before**
staging; this neither relocates a root nor diagnoses a historical native failure.
Unsupported known setup schemas are read-only `NeedsInput`: no predecessor
transform, unknown-root adoption or historical-proof rewrite is implemented.

`DependencyRegistry.load()` loads the three packaged, versioned JSON resources.
Unknown adapters or host-owned probe symbols, invalid fields, Galaxy-as-pip entries, omitted consumers,
unknown edges, cycles and duplicate identities fail with `RegistryError`.
`validate_public_sources(Path("netops"))` checks public definitions and explicit
`__all__` exports through AST without importing optional modules. New public
exports must be registered; removing a whole source module also fails the
complete manifest check instead of silently omitting its iteration.
The dependency directory is included, including its package reexports, service
and probe adapter. Only underscore-prefixed implementation modules that explicitly
declare an empty public surface remain private; a new public module or declared
export is not silently exempted.
Public callable reexports declare `aliases` linking each exported name to its
registered canonical `module:export`. Alias targets, cycles, and competing
per-export overrides fail closed. Dependencies are projected from the canonical
export, not copied from the importing module's defaults. Exact selectors also
inherit canonical capability, tier and optional intents. The complete AST drift
check compares registered aliases against actual absolute/relative imports,
including renamed imports, without importing optional runtime dependencies.
`documentation()` is also the catalog's generated
help representation; the snapshot below is checked by tests.
`validate_package_metadata(project_text)` parses actual project dependency arrays
as TOML and PEP 508 requirements, normalizes distribution names (case and
dot/underscore/hyphen equivalence), and rejects Galaxy collections even when
unversioned, extra-qualified, conditional, or direct references. It rejects missing
registry-ranged pip requirements, conditional-only substitutes, changed ranges
and source URLs. Required declarations are bound to their actual base/extra
groups in `registry.json`: moving a base prerequisite into `dev`, or removing
`snmp` while leaving the same library in `tui`, is not a valid substitute.
Requirement ordering and TOML quote style are not drift.
Unrelated tool settings are not scanned as dependencies. This development-only
checker uses `packaging` and the standard `tomllib` (`tomli` on Python 3.9/3.10);
if parser tooling is absent it raises `package-metadata-parser-unavailable`,
never falls back to regex or affects ordinary catalog/plan/verify imports.

`DependencyService(registry, adapters, state, policy, authorization, clock, events)`
implements C01's `DependencyPort.verify(InstallScope, InstallContext) ->
ReadinessReport`. It uses the actual C02 `OwnedStatePort` seam, separate
`LocalPolicyPort` and `AuthorizationBroker`. Planning never probes or mutates
state and never accesses authorization. A configured `ManagedLifecycleState`
does read its existing owned metadata to compose the exact reviewed projection.
Every adapter supplies selected
`ConsumingContext` records, including interpreter, executable search path,
collection search paths, OS, architecture, selected driver/image and role.
Context labels never substitute for observations.

* `catalog()` returns immutable catalog metadata; no I/O beyond explicit resource loading.
* `plan(scope, context)` returns a UUID/digest-bound topological `InstallPlan`,
  source locators, unknown sizes/digests explicitly `None`, ownership, would-effects,
  reuse observations, recovery and separate elevation/WSL/VM/reboot/runtime/security
  boundaries. Unknown free space is `None`. Sources are locators, **not acquired
  trusted artifacts**; I02 must obtain approved digest locks and fresh consent.
  Prior probe availability only informs candidate reuse, never permits dispatch.
  A managed host additionally supplies `lifecycle` (an exact immutable closed
  lifecycle projection, or `None`), `blocked` dependency identities and each
  step's `disposition`/`reason`. The public digest seals this entire description.
* `verify(scope, context)` uses five-second individual probe deadlines within a
  sixty-second overall probe budget, preserving selected failures. Registry,
  controller, interpreter, architecture or receipt-context drift is blocked.
  A successful adapter return at or after its deadline becomes blocked evidence,
  never reusable availability. Nonfinite or backward samples fail closed across
  the entire verification, not just within an individual probe.
  Report construction and policy evaluation share that deadline; policy remaining
  milliseconds are factual, and late completion raises `RegistryError`.
  Native, companion and enhanced tiers remain independent.
* Full-toolkit scope covers all public native and companion surfaces and their
  optional intents. `enhanced=False` leaves Molecule `not-requested`. Explicit
  selected scope uses capability IDs; `native.backup:git` and `native.report:pdf`
  select optional prerequisites without imposing them on default backup or HTML.
  Full-toolkit enhanced planning includes both the Molecule module and its actual
  consuming-interpreter CLI probe, not just an import.
* Bare `native.scan` covers ordinary defaults and public scan operations, so ping
  and SNMP are required without extra opt-in. `native.scan:skip-ping` selects
  SNMP-only discovery; `native.scan:skip-snmp` selects ping-only discovery;
  `native.scan:skip-ping-and-snmp` selects address enumeration only. Existing
  `native.scan:ping`/`:snmp` spellings select those individual consuming modes.
  They do not execute scans or contact a device.
* Every registered `module:export` can be selected explicitly. For example,
  `netops.inventory.scan:ping_host` always requires ping, `:scan_subnet` and
  `:scan_subnet_async` require ping plus SNMP at default arguments, and
  `:results_to_inventory_fragment` requires neither. Pure transforms do not
  inherit SSH/SNMP/ping probes. `netops.collect.backup:git_init` and `:git_commit`
  always require Git even though default `run_backup(git=False)` does not.
  `registry.operation(module, export).dependencies` reflects exact export
  requirements when specified. Multiple selectors are unioned: requesting a
  default operation as well as a reduced mode never silently weakens the default.
  Plan and readiness use the same selection resolver.
* SSH community extraction includes the native transport chain; SNMP trials and
  the JSON community registry retain their separate SNMP-only/stdlib contracts.
  Vault and scoped credential resolution include YAML serialization. Dashboard
  `main` defaults to native host/table checks (transport and YAML), while pure
  aggregation/table exports remain stdlib-only and `render_html` requires Jinja2.
  Select `native.report:html` for the dashboard's optional HTML output mode.
  The package's aggregation/table aliases and filename helper retain their
  canonical stdlib-only requirements. Mailer aliases retain `native.mail`, not
  fictional HTML dependencies. Generator HTML and dashboard HTML still require
  Jinja2; selected PDF still requires the actual PDF-library functional probe.

### Explicitly reviewed managed public flow — bounded source integration

The seven-argument service constructor is unchanged. An explicitly configured
`ManagedLifecycleState` uses the real private `AuthorizationBroker` and existing
protected owned-record and generation-file ports; it does not adopt an inert
A02 state record. Its registered manifest must bind the exact scope, selected
consuming contexts, archive size/digest and every managed member.

```python
plan = service.plan(scope, context)      # read-only, no probe or prompt
if not plan.blocked and plan.lifecycle is not None:
    consent = service.review(plan, now, lifetime)
    outcome = service.provision(plan, consent, cancel)
```

`review()` uses the host's actual private lifecycle consent adapter.
`provision()` accepts that same **public** plan, independently recomposes its
registered description, and consumes the exact one-use receipt. The managed
entry rejects caller-supplied raw closed plans; legacy inert-host compatibility
does not bypass this check. Serialized checkpoints are never grants or permits.
Disabled setup, missing verified locks, selected-context drift, incomplete
staging and unsupported assets block rather than execute a partial
dependency closure. Multiple supplied archive locks compose only when their
ordered dependency identities equal the entire selected registry closure;
every contribution has its own admitted download and exact member digests.
One combined staging publication rejects duplicate/unsafe/extra members.
Full-toolkit selection still includes the whole registry
closure. No production pins are supplied or invented by this increment.

The admitted native milestone downloads, stages and functionally verifies a
distinct managed tree. Its result remains partial with
`review-activation-plan`: activation requires a fresh public plan and separate
review after factual verification exists. That plan re-probes the selected
context and tree under the original owned-root lock immediately before actual
pointer CAS. It never redownloads, implicitly restores or reverse-CASes on
cancellation. Pointer identity/revision report actual owned facts even if a
later checkpoint or cancellation fails.

The managed path persists factual `InstallConsented`, `StepCompleted`, `DependencyObserved`,
`CandidateVerified` and `Activated` reducer events, not a fresh
`InstallConsented` for every effect. Every actual occurrence still needs the
reducer's exact requested kind and the original broker's private permit.
Immutable event history and the CAS-updated policy head have distinct resource
names. A fresh service resumes from exact stored scope/context and current
observations only with a newly reviewed live binding; it cannot revive a
persisted grant.

The recovery observation advances to the exact post-install readiness report
only after real verification and broker/reducer completion succeed. A missing
pre-install interpreter is therefore not mistaken for drift after successful
installation. A denied or interrupted completion retains its previous baseline;
subsequent report or consuming-context drift still blocks resume before effects.
This checkpoint neither issues authority nor changes any freshness window.

After actual pointer CAS, correlated `Activated` completes the pending selected
disposition and consumes its factual receipt; no extra activation or forecast
completion is emitted. Actual `DependencyObserved` events project every selected
tier. Unselected tiers remain `not-requested`, not fictitious ready dependencies.
The changed source/contracts/bundle identities invalidate prior policy bindings.

### Qualified retained planning and restore

An explicitly configured managed host additionally needs immutable root-pinned
`ManagedQualification` descriptors and a host-owned `GenerationRunsPort`.
`plan_restore(id, context)` reads retained generation, scope, consuming identity,
qualification/report digests and exact expected pointer/revision metadata. It
does not execute either the retained or broken active interpreter. Missing
qualification, expired verification, context drift or missing target/current
run pins block; a supplied unit descriptor does not qualify a platform.

`restore(plan, consent, cancel)` spends fresh private one-use consent, stops new
admission, and drains owned runs outside broker/root locks so previously approved
recovery can finish. Under the original lock it revalidates reviewed pins
(release-only changes), owned root, candidate files/context and expected pointer,
then performs one CAS. Factual completion is recorded before postcheck. Pre-CAS
cancellation leaves the pointer unchanged; post-CAS cancellation/failure reports
the actual selected ID, performs no reverse CAS, leaves admission stopped and
requires new consent. Successful postcheck alone reopens admission.

Fresh-service resume replans/reviews from durable metadata, skips actually
completed staging and preserves original primary errors. Immutable safe outcomes
retain primary/cleanup/pending history behind a CAS-updated digest-linked head;
they never serialize grants or permits.

**Remaining mandatory scope:** the inert compatibility path is not qualified.
Real interpreter/venv creation, pip/wheel closure, collection/runtime installation,
production verified assets and run-pin bridge, long-lived qualification refresh,
interrupted multi-record reconciliation, managed uninstall, guided protected
platform bootstrap and Q03 evidence remain incomplete, not approved deferrals.

Author public-flow tests use compatible fake metadata, real registry identity,
actual owned record encoding/broker/reducer and fake tree/HTTP/probe effects.
They do not execute or qualify an interpreter or complete a product installer.
No new telemetry backend is introduced; existing paired `install.step` and
`netops.install.step.count` observations cover admitted managed staging and
the public lifecycle outcomes without source URLs, raw output or credentials.

`LocalDependencyAdapter` executes fixed host-owned Python/tool probes, never
registry-provided shell commands. Module smoke checks use the consuming
interpreter with explicit `-I -B` flags (isolated mode ignores the
`PYTHONDONTWRITEBYTECODE` environment setting); controller CLI and collection discovery use that
same interpreter and selected collection paths. PDF readiness renders a small
in-memory PDF with remote fetch disabled, rather than assuming an import proves
native libraries work. Output is bounded and hashed, not exposed as diagnostics.
Subprocess errors become safe categories, without exception text or raw output.
Foreign OS contexts are blocked locally, never simulated as real qualification.
Platform receipts, runtime functional service evidence, and image locks require
their later authorized owners; I01 does not invent them. Runtime/asset/platform
probes therefore return named blocked prerequisites rather than success stubs.
Executable symbols are shared by registry validation and adapter dispatch;
a registered tool cannot silently lack a fixed handler. `rm` is observed only
with GNU `--help`, or operand-free BSD usage on macOS, through the consuming PATH.
The bounded receipt must have the expected usage and exit status; no file operand,
deletion flag, shell, temporary file, or installation is used.

`ProbeResult.status` is `available`, `missing`, `blocked` or `unsupported`.
Its reason, observed version, context/evidence digest and safe next action are
preserved inside each capability record. Missing prerequisites are separate
from an installed-but-**unqualified** tuple. Native readiness remains usable
when companion/enhanced dependencies are absent.

`qualification.json` intentionally contains an empty qualified set. Ranges,
successful imports, fake adapters and passing unit tests are not qualification.
No exact support pins are invented. The observed tuple digest binds consuming
contexts, observed versions, assets, route and all policy identities. A change
invalidates cached planning reuse. Q03 must supply real evidence and a reviewed
admission path before any nonempty qualification record is accepted.

Real observations feed the packaged derived dependency rules. The derived
readiness fact schema now preserves `not-requested` for unselected tiers;
selected tiers must all be ready. This does not change individual dependency
probe statuses or qualify an unrequested tier.
Policy denial is reported separately and never used as certification or a
permission to install. B01v2 remains a bounded Python reference exception,
not foundation compliance.

Each local probe emits `dependency.probe` alongside the
`netops.dependency.probe.count` increment in the same helper. Both carry safe
context-role/status/reason/duration/category/next-action dimensions. Service-created
missing-context, identity-drift and deadline rejections use that same helper once,
without duplicating adapter observations. The service also emits C01 `SafeEvent`
records. Sink failures do not escape public readiness/probe calls. Policy-drift
observations are evaluated under the actual packaged policy identity, with the
supplied identity mismatch retained as a rejecting fact. Raw command output and credentials are not
logged; no new telemetry backend or service is required.

## Known boundaries

* The earlier `ansible.netcommon` pip-extra defect was repaired by its packaging
  owner. Current project metadata validates; regression checks inject forbidden
  requirements and removals in memory without editing `pyproject.toml`.
* Shell tools reflect the current backup role until its owner removes that
  dependency. A tool with an incompatible functional flavor is not called ready.
* This product does not claim that existing roles or Molecule scenarios are
  complete or that any controller tuple has passed real-platform qualification.
* Shared README/Ansible documentation links are coordinator-owned and untouched.

## Generated catalog

<!-- dependency-catalog:start -->
| Dependency | Context | Source | Range | Consumers |
| --- | --- | --- | --- | --- |
| native-python | native | python.org | >=3.9 | native.core, native.transport, native.scan, native.backup, native.change, native.check, native.report, native.tui, native.pdf, native.snmp |
| cryptography | native | pypi:cryptography | >=46.0.5 | native.core, native.transport, native.change, native.check, native.backup, native.scan, native.tui, companion.ansible |
| paramiko | native | pypi:paramiko | >=5.0.0,<6.0.0 | native.core, native.transport, native.scan, native.backup, native.change, native.check, native.tui |
| netmiko | native | pypi:netmiko | >=4.3.0,<4.5.0 | native.transport, native.scan, native.backup, native.change, native.check, native.tui, native.snmp, native.report, native.core, companion.ansible |
| pyyaml | native | pypi:PyYAML | >=6.0 | native.core, native.transport, native.scan, native.backup, native.change, native.check, native.tui, native.report, companion.ansible |
| textual | native | pypi:textual | >=8.2.8,<9.0 | native.tui |
| pysnmp | native | pypi:pysnmp | >=7.0 | native.scan, native.snmp, native.tui |
| ping | native | os-package-manager | functional-probe | native.scan, native.tui |
| git | native | git-scm.com | functional-probe | native.backup |
| jinja2 | native | pypi:Jinja2 | >=3.1.6 | native.report, native.pdf, native.core |
| weasyprint | native | pypi:weasyprint | >=62.0 | native.pdf |
| native-pdf-libraries | native | weasyprint-native-platform-packages | functional-render | native.pdf, native.report, native.core |
| controller-python | controller | python.org | >=3.10 | companion.ansible, enhanced.molecule |
| ansible-core | controller | pypi:ansible-core | >=2.16 | companion.ansible, enhanced.molecule |
| controller-cryptography | controller | pypi:cryptography | >=46.0.5 | companion.ansible |
| controller-paramiko | controller | pypi:paramiko | >=5.0.0,<6.0.0 | companion.ansible |
| controller-netmiko | controller | pypi:netmiko | >=4.3.0,<4.5.0 | companion.ansible |
| controller-pyyaml | controller | pypi:PyYAML | >=6.0 | companion.ansible |
| ansible-playbook | controller | pypi:ansible-core | >=2.16 | companion.ansible |
| ansible-inventory | controller | pypi:ansible-core | >=2.16 | companion.ansible |
| ansible-vault | controller | pypi:ansible-core | >=2.16 | companion.ansible |
| ansible.netcommon | controller | galaxy:ansible.netcommon | >=6.0 | companion.ansible |
| ansible.utils | controller | galaxy:ansible.utils | qualification-required | companion.ansible |
| cisco.ios | controller | galaxy:cisco.ios | qualification-required | companion.ansible |
| arista.eos | controller | galaxy:arista.eos | qualification-required | companion.ansible |
| junipernetworks.junos | controller | galaxy:junipernetworks.junos | qualification-required | companion.ansible |
| paloaltonetworks.panos | controller | galaxy:paloaltonetworks.panos | qualification-required | companion.ansible |
| community.network | controller | galaxy:community.network | qualification-required | companion.ansible |
| bash | controller | os-package-manager | functional-probe | companion.ansible |
| date | controller | os-package-manager | functional-probe | companion.ansible |
| ls | controller | os-package-manager | functional-probe | companion.ansible |
| tail | controller | os-package-manager | functional-probe | companion.ansible |
| xargs | controller | os-package-manager | functional-probe | companion.ansible |
| rm | controller | os-package-manager | functional-probe | companion.ansible |
| molecule | controller | pypi:molecule | qualification-required | enhanced.molecule |
| molecule-cli | controller | pypi:molecule | qualification-required | enhanced.molecule |
| molecule-plugins | controller | pypi:molecule-plugins | qualification-required | enhanced.molecule |
| container-runtime | controller | selected-runtime-vendor | qualification-required | enhanced.molecule |
| container-image | controller | selected-locked-image | exact-digest-required | enhanced.molecule |
| controller-platform | controller | host-platform | actual-grant-receipt-required | companion.ansible, enhanced.molecule |
| mkdocs | native | pypi:mkdocs | >=1.6.0 | native.core |
| mkdocs-material | native | pypi:mkdocs-material | >=9.0 | native.core |
| mkdocstrings | native | pypi:mkdocstrings | >=0.25 | native.core |
| mkdocs-autorefs | native | pypi:mkdocs-autorefs | >=1.0 | native.core |

Registry/manifest digest: `a8db2f15a1e7ad047f75346fe4764c629d300f09d2f02062a149aa51c44042a7`.

Exact export and reduced-mode requirements (native Python baseline also applies):

| Selector | Dependencies |
| --- | --- |
| netops.dependencies.service:observe_probe | stdlib only |
| netops.dependencies.service:RegistryError | stdlib only |
| netops.dependencies.service:DependencyEntry | stdlib only |
| netops.dependencies.service:PublicOperation | stdlib only |
| netops.dependencies.service:ConsumingContext | stdlib only |
| netops.dependencies.service:ProbeResult | stdlib only |
| netops.dependencies.service:DependencyAdapter | stdlib only |
| netops.dependencies.service:DependencyCatalog | stdlib only |
| netops.dependencies.service:InstallStep | stdlib only |
| netops.dependencies.service:InstallPlan | stdlib only |
| netops.dependencies.service:DependencyRegistry | stdlib only |
| netops.dependencies.service:DependencyService | stdlib only |
| netops.dependencies.service:OwnedStatePort | stdlib only |
| netops.dependencies.__init__:ConsumingContext | stdlib only |
| netops.dependencies.__init__:DependencyAdapter | stdlib only |
| netops.dependencies.__init__:DependencyCatalog | stdlib only |
| netops.dependencies.__init__:DependencyEntry | stdlib only |
| netops.dependencies.__init__:DependencyRegistry | stdlib only |
| netops.dependencies.__init__:DependencyService | stdlib only |
| netops.dependencies.__init__:InstallPlan | stdlib only |
| netops.dependencies.__init__:InstallStep | stdlib only |
| netops.dependencies.__init__:LocalDependencyAdapter | stdlib only |
| netops.dependencies.__init__:OwnedStatePort | stdlib only |
| netops.dependencies.__init__:ProbeResult | stdlib only |
| netops.dependencies.__init__:PublicOperation | stdlib only |
| netops.dependencies.__init__:RegistryError | stdlib only |
| netops.core.__init__:DeviceConnection | netmiko, pyyaml |
| netops.core.__init__:Device | pyyaml |
| netops.core.__init__:Inventory | pyyaml |
| netops.core.community:CommunityRegistry | stdlib only |
| netops.core.community:try_communities | pysnmp |
| netops.core.community:extract_communities_via_ssh | netmiko |
| netops.inventory.scan:ScanResult | stdlib only |
| netops.inventory.scan:ping_host | ping |
| netops.inventory.scan:ping_sweep | ping |
| netops.inventory.scan:identify_vendor | stdlib only |
| netops.inventory.scan:scan_subnet_async | ping, pysnmp |
| netops.inventory.scan:scan_subnet | ping, pysnmp |
| netops.inventory.scan:scan_subnet_through_active_bastion | stdlib only |
| netops.inventory.scan:results_to_inventory_fragment | stdlib only |
| netops.inventory.scan:merge_inventory | pyyaml |
| netops.inventory.scan:deep_enrich | netmiko, pyyaml |
| netops.inventory.scan:main | netmiko, pyyaml, ping, pysnmp |
| native.scan:ping | ping |
| native.scan:snmp | pysnmp |
| native.scan:skip-ping | pysnmp |
| native.scan:skip-snmp | ping |
| native.scan:skip-ping-and-snmp | stdlib only |
| netops.collect.backup:generate_diff | stdlib only |
| netops.collect.backup:save_backup | stdlib only |
| netops.collect.backup:git_init | git |
| netops.collect.backup:git_commit | git |
| netops.collect.backup:run_backup | netmiko |
| netops.collect.backup:main | netmiko, pyyaml |
| netops.playbooks.templates.__init__:RemediationTemplate | stdlib only |
| netops.playbooks.templates.__init__:REMEDIATION_TEMPLATES | stdlib only |
| netops.playbooks.templates.__init__:VENDOR_COMMAND_MODULE | stdlib only |
| netops.playbooks.templates.__init__:VENDOR_CONFIG_MODULE | stdlib only |
| netops.playbooks.templates.__init__:get_template | stdlib only |
| netops.report.__init__:ReportGenerator | jinja2 |
| netops.report.__init__:ReportMailer | stdlib only |
| netops.report.__init__:ReportScheduler | jinja2 |
| netops.report.__init__:generate_report | jinja2 |
| netops.report.__init__:default_output_filename | stdlib only |
| netops.report.__init__:aggregate_dashboard | stdlib only |
| netops.report.__init__:format_table | stdlib only |
| netops.report.__init__:render_html | jinja2 |
| netops.report.generator:ReportSection | stdlib only |
| netops.report.generator:ReportData | stdlib only |
| netops.report.generator:ReportDataWithHtml | stdlib only |
| netops.report.generator:ReportGenerator | jinja2 |
| netops.report.generator:default_output_filename | stdlib only |
| netops.report.generator:generate_report | jinja2 |
| netops.report.generator:probe_pdf | native-pdf-libraries |
| netops.report.generator:main | jinja2 |
| netops.report.health_dashboard:normalize_device_result | stdlib only |
| netops.report.health_dashboard:aggregate_dashboard | stdlib only |
| netops.report.health_dashboard:format_table | stdlib only |
| netops.report.health_dashboard:render_html | jinja2 |
| netops.report.health_dashboard:main | netmiko, pyyaml |
| netops.ansible.execution:ExecutionInputs | pyyaml |
| netops.ansible.execution:ExecutionSourcePort | pyyaml |
| netops.ansible.execution:EffectResult | pyyaml |
| netops.ansible.execution:EffectsBackend | pyyaml |
| netops.ansible.execution:OwnedAdmissionState | pyyaml |
| netops.ansible.execution:ExecutionHost | pyyaml, netmiko |

Canonical public aliases (capability, tier and intents are inherited):

| Selector | Canonical selector |
| --- | --- |
| netops.dependencies.service:OwnedStatePort | netops.ansible.artifacts:OwnedStatePort |
| netops.dependencies.__init__:ConsumingContext | netops.dependencies.service:ConsumingContext |
| netops.dependencies.__init__:DependencyAdapter | netops.dependencies.service:DependencyAdapter |
| netops.dependencies.__init__:DependencyCatalog | netops.dependencies.service:DependencyCatalog |
| netops.dependencies.__init__:DependencyEntry | netops.dependencies.service:DependencyEntry |
| netops.dependencies.__init__:DependencyRegistry | netops.dependencies.service:DependencyRegistry |
| netops.dependencies.__init__:DependencyService | netops.dependencies.service:DependencyService |
| netops.dependencies.__init__:InstallPlan | netops.dependencies.service:InstallPlan |
| netops.dependencies.__init__:InstallStep | netops.dependencies.service:InstallStep |
| netops.dependencies.__init__:LocalDependencyAdapter | netops.dependencies.adapters:LocalDependencyAdapter |
| netops.dependencies.__init__:OwnedStatePort | netops.dependencies.service:OwnedStatePort |
| netops.dependencies.__init__:ProbeResult | netops.dependencies.service:ProbeResult |
| netops.dependencies.__init__:PublicOperation | netops.dependencies.service:PublicOperation |
| netops.dependencies.__init__:RegistryError | netops.dependencies.service:RegistryError |
| netops.core.__init__:DeviceConnection | netops.core.connection:DeviceConnection |
| netops.core.__init__:Device | netops.core.inventory:Device |
| netops.core.__init__:Inventory | netops.core.inventory:Inventory |
| netops.playbooks.templates.__init__:RemediationTemplate | netops.playbooks.templates.remediation:RemediationTemplate |
| netops.playbooks.templates.__init__:get_template | netops.playbooks.templates.remediation:get_template |
| netops.report.__init__:ReportGenerator | netops.report.generator:ReportGenerator |
| netops.report.__init__:ReportMailer | netops.report.mailer:ReportMailer |
| netops.report.__init__:ReportScheduler | netops.report.scheduler:ReportScheduler |
| netops.report.__init__:generate_report | netops.report.generator:generate_report |
| netops.report.__init__:default_output_filename | netops.report.generator:default_output_filename |
| netops.report.__init__:aggregate_dashboard | netops.report.health_dashboard:aggregate_dashboard |
| netops.report.__init__:format_table | netops.report.health_dashboard:format_table |
| netops.report.__init__:render_html | netops.report.health_dashboard:render_html |

Required pip metadata by consuming package group:

| Group | Registry dependencies |
| --- | --- |
| base | netmiko, paramiko, pyyaml, cryptography |
| extra:tui | textual, pysnmp |
| extra:snmp | pysnmp |
| extra:ansible | ansible-core |
| extra:report | jinja2 |
| extra:report-pdf | jinja2, weasyprint |
| extra:docs | mkdocs, mkdocs-material, mkdocstrings, mkdocs-autorefs |
<!-- dependency-catalog:end -->
# Offline installation boundary

Trusted managed-generation descriptors can opt into a fresh owned interpreter
environment and exact offline wheel/collection closure. Public request JSON
does not supply these descriptors or confer consent. The existing protected
stage handler performs installation and consuming probes before verification
and pointer activation; generated receipts alone never establish readiness.

Absent descriptors preserve legacy canonical manifest identities. Present
descriptors pin interpreter bytes/version/platform and wheel hashes; no global
pip install, mutable cache resolution, environment clearing or unknown-tree
adoption is performed. Failed/partial environments remain owned evidence.

Installed-tree receipts use a separate closed safe filename contract, including
literal interior ASCII spaces/parentheses such as setuptools' `script (dev).tmpl`.
Artifact IDs, canonical PX and archive destination grammars are unchanged.
Owner/no-follow/hash/size/permission/root checks and case-folded alias rejection
remain mandatory; a name alone is never trusted membership. Final fresh
managed installation and full selected runtime/driver qualification remain
independent I02 obligations, not an inference from ordinary wheel installation.

## Guided protected source setup

`python -m netops.setup <action> --root <absolute-owned-root>` and both root
scripts invoke the same source host. Actions are `plan`, `install`, `update`,
`resume`, `verify`, `restore`, and `uninstall`. Full native/companion selection is
default; `--enhanced` includes Molecule and explicit `--capability` narrows scope.
With an existing protected registered host, `--plan-file` is optional: the
original exact descriptor and scope are read from owned metadata. `verify`
defaults to the factual active generation; `restore` requires `--generation-id`;
other operations default to the last registered candidate. Explicit scope
disagreement, duplicate/unknown generations and interrupted registration block
before any probe, consent or effect. This does not make retained byte evidence
qualified readiness or permit active-generation uninstall.
Plan/install/update retain their requested default full scope: a prior narrow
candidate cannot silently narrow a full request. A different requested scope
enters discovery for that complete scope, not reuse of the old candidate's scope.
Resume can use the durable installation ID when `--installation-id` is omitted;
an explicitly different ID is rejected before its private review.

`--plan-file` selects local `netops-local-setup-v1` metadata, not consent:
generation UUID, exact scope, pinned existing interpreter/version/platform,
exact wheel/collection closure, and ordered registered archive descriptors
(source identity, HTTPS family, size/SHA256, exact member hashes and local cache
path). Optional `native_files`, `tools` and `libraries` bind exact copied members
and fixed actual probes. Cache transport is offline; missing/unknown pins or
closure block before root creation. Source setup does not eagerly require
PyYAML/site packages; missing optional metadata parsers remain typed inputs.
The admitted stage additionally checks actual pinned wheel metadata, compatible
selected-interpreter tags, Python ranges and recursive active PEP 508 requirements
before venv creation/pip installation. Dependency extras propagate through that
closed wheel set; direct URL dependencies do not trigger network resolution.
Collections' actual declared closure is checked before environment creation too.
For a new local descriptor, exact cached archive membership and this same
metadata closure are validated read-only before root creation, consent or
acquisition. That phase uses the trusted running review interpreter, not an
unreviewed descriptor executable; it repeats actual selected-interpreter tag
checks after admission. Root distribution metadata is distinct from legitimate
nested vendored metadata. Retained operations do not depend on the old cache.
Closed publisher metadata source clients are implemented, but authentic pins
and live publisher/platform qualification remain absent. Complete OS/runtime/
service/guest handling and qualification remain unfinished.

### Descriptor-free first run

`install --root <absolute-new-root>` now diagnoses the complete selected registry
closure **before** root creation or setup-record writes. It calls the same public
`DependencyService.plan` and `verify` used by the Python service. Observations
come from the existing selected native interpreter and its executable PATH;
Linux/macOS may also inspect that existing interpreter as a controller. Windows
never launches WSL, installs a distro, starts a runtime/service, changes security,
or treats native Python as an Ansible controller during discovery. Missing
controller context and unimplemented runtime/image/platform proof remain blocked.
The existing fixed, bounded interpreter/module/executable/collection/PDF probes
remain authoritative; discovery does not import arbitrary registry-provided code.

Each component offers **Reuse / Install / Decline**. Reuse is eligible only with
fresh compatible consuming evidence. Missing or invalid input defaults to
Decline; available components default to Reuse. These are selection requests,
not grants, ownership, installed readiness or a promise to transfer global
packages into an owned environment. A declined prerequisite is retained in the
full selected report, including its dependents. Native files and unknown roots
are never adopted. Native/companion/enhanced readiness remain separate.
If the aggregate verifier exhausts its original budget, every selected key
remains blocked with `fresh-consuming-observation-required`; no partial ready
receipt or extended deadline is invented. Continuation retries diagnosis.

Install selections additionally show separate prospective OS, WSL, distribution,
VM, virtualization, runtime, service, security, elevation and reboot groups.
Requesting `review` is **not** consequential consent; only the existing exact
private lifecycle review can issue its original one-use, deadline-bound grants.
No effect is performed by either selection step.

When verified source metadata is unavailable, the host emits a structured
`netops-guided-selection-v1` **NeedsInput** report, with every selected component's
kind, required version, platforms, source, transitive edges, observation, eligible
choices and exact missing metadata fields, plus the actual host platform and
architecture. It does not report ReadinessReady or
exit zero. No private producer capability or hand-authored JSON descriptor is
required to start. Existing `--plan-file` support remains a legacy pinned-metadata
route, not the next-action requirement for a new user.

Trusted Python hosts can supply `netops.setup.SetupMetadata` to
`netops.setup.main(argv, metadata=metadata)`. Its constructor accepts only the
existing live private producer, pinned installation, producer-bound protected
consumer root and generation ID—not archive JSON, a URL, a trust boolean or a
grant. The accepted producer remains restricted to `native.stdlib`. An empty
consumer root already owned by that producer requires an exact separate
`initialize <digest>` review before setup records are written. Root identity and
emptiness are rechecked; unknown files, a different root, an expired source or a
declined review do not initialize it. Installation and activation still require
their original separate private reviews. This enables trusted composition; the
default CLI still reports missing full-scope production metadata honestly.

The report's `next_command` is an argument array using the exact current
interpreter and fixed isolated source bootstrap to call public `setup.main`.
It works before package installation and outside the checkout; neither a
caller-provided executable nor arbitrary argv is restored from the token.
Its `--checkpoint` restores only the selected scope and component requests.
It is a bounded canonical opaque token, not a file write, grant, producer
identity or trusted metadata. Root, registry, context or scope drift rejects it
before probes/prompts, and all reuse evidence is collected anew. It cannot
select an existing owned generation or be combined with `--plan-file`. No user
reconstructs private recovery documents. An existing installation's original
protected `resume`/installation-ID path is unchanged.

`plan` remains prompt-, probe-, metadata-provider- and write-free and emits a
`Planned` report rather than readiness. `--companion <registered-capability>`
is an explicit selection alongside `--capability`; absent either, the default
remains full toolkit, including its companion dependencies. `--enhanced` adds
the registered enhanced closure. `install.ps1` forwards `-Companion` and
`-Checkpoint`; `install.sh` forwards the equivalent public arguments.

Trusted owning composition can inject typed pinned cache metadata into the
internal setup host. The compiler checks the exact ordered selected closure,
registered source families, the actual existing interpreter hash and real
cached wheel/collection metadata through
the existing validators before root creation. It can also consume the existing
live private producer without serializing its capability or widening its
**native.stdlib-only** supported scope. Resulting candidates go through the same
root-create review (showing the exact candidate digest, scope and pins first),
public managed plan/review/provision and separate activation
review; no alternate executor is introduced. Packaged registry entries currently
contain no complete production pins. Full selected OS/runtime/service handlers
and their trustworthy metadata are still unfinished **SOURCE**, not platform
qualification debt or an approved deferral. No full I02 completion is implied.

### Private owning-build composition (not a CLI source option)

The internal `_owned_build` / `_owned_source` provider separates a real local
wheel/sdist build from existing-Python reuse. A wheel bundle is labeled
`owned-local-build` / `toolkit-wheel-bundle`, never `native-python` or a Python
publisher archive. The existing HTTPS lock validation and all three registered
publisher-domain families are unchanged.

A trusted owning host supplies the exact sealed source inputs, existing
interpreter/toolchain identities, independently qualified known-cache hashes,
protected producer/consumer roots and selected contexts. The fixed bounded
offline build creates a fresh working tree, wheel and sdist; exact outputs,
member inventory and build operation/exit facts are retained in a create-only
producer ledger. A serialized receipt, hash, successful install or arbitrary
local archive alone supplies no producer authority.
The isolated bootstrap resolves implicit namespaces only inside the exact
qualified backend wheel and uses its actual fixed wheel/sdist commands.
Only newly created output roots receive inherited owner-only security;
existing ACLs are never repaired to make an output acceptable.

Trusted private setup composition can supply the live process/thread-bound
provider to `_setup._seed` and `_setup._host`. Its durable
`netops-owned-build-v1` descriptor does not serialize that authority.
`--plan-file` cannot construct a provider and has no `trusted=true`,
adopt-archive or arbitrary-local-source option. Fresh-process composition must
recover the actual trusted producer with the independently retained expected
ledger digest, revalidate all current source/cache/tool/output/root facts and
then obtain new exact lifecycle consent/readiness through the public service.
Substituted receipts, contexts, producer identities and drift do not transfer.

The current private provider supports **only `native.stdlib`** with a pinned
existing native interpreter and exact complete toolkit/dependency wheel
closure. It is not complete Ansible/controller/full-toolkit source support,
Q03 trust, a Windows/WSL qualification or a historical-root migration path.
Staging, consuming verification and final activation guards revalidate this
private source under the same byte, consent, cancellation and deadline rules.
The two underscore-only modules explicitly expose no public callables and
remain checked by the existing complete source census.

New owner-only roots require typed confirmation. Existing roots must contain
matching protected host ownership records. Update separately reviews candidate
registration, preserves previous pointer/generations and uses a durable pending
registration marker for explicit retry; physical provisioning still requires the
original private broker. Activation requires a distinct private review.
Standalone and admitted HTTPS acquisition use a joined fixed-code child so
DNS/connect/redirect/body stalls cannot abandon a caller resolver thread.
Cancellation and both the original source-clock span and real elapsed cap are
checked by the parent. No proxy credentials, shell, cache, hooks or unrelated
processes are inherited as effect authority. Retries do not renew the private
grant or its aggregate budget.

`DependencyService.plan_uninstall(generation_id, context)` produces an exact
inactive-generation plan. Private lifecycle consent is required by `uninstall`;
live/crash-held pins, an active target, unknown members or drift block removal.
Partial outcomes retain primary/cleanup errors and exact remaining references;
unrelated distributions and user files are never swept.

`OwnedGenerationRuns` is registered with native core/YAML requirements. A
consuming host must use its exact-generation `acquire`/`release` around real
dispatch and provide recovery-preserving cancel/join callbacks. Durable
admission/pins cannot be replaced by process-local counters or a TTL.
Admission/reopening validate the full typed present pointer and its exact
generation/revision-derived digest under the root lock. A normal owner that
successfully releases during drain is recognized only for the exact
snapshotted same-host pin; direct duplicate release still fails. Sibling/crash
holders and arbitrary callback/storage failures remain blockers.

Install activation consumes functional evidence at its admitted probe, then
rehashes all protected archive/installed bytes at CAS against the exact staged
receipt without a duplicate interpreter consume. The live report digest,
consuming contexts, original evidence freshness and consent deadline must
still match; full ordinary verification and qualified restore keep functional
consumption. No root/receipt cache or historical policy becomes authority.
Only an actual completed same-host functional observation can be reused by the
activation probe, with full protected byte checks. A fresh-process resume first
reviews/performs actual verification, then asks new exact activation consent;
durable metadata cannot reconstruct that live proof or renew its expiry.

Production full locks, qualified controller/WSL/runtime/service consequential
drivers, clean host bootstrap, consuming pin integration and complete crash
reconciliation remain unfinished. Native author publication/installation is not
Ansible/Molecule or B02/Q03 qualification; expiry may still safely block native
activation. This is not a full-feature acceptance claim.
