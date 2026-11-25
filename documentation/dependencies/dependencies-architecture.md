# Dependency manifest and canonical public callables

I01 owns the read-only packaged registry, operation manifest and dependency
planning/probe adapters. See [component API](../../docs/api/dependencies.md)
for prerequisites, qualification limits and generated catalog.

## Nov22 factual context and upstream marker boundary

`_context_facts` owns bounded facts, not source authority, grants or readiness.
Frozen `ConsumingContext` fields (`id`, `platform`, `architecture`, `python`,
`path`, `role`, `collection_paths`, `driver`, `image`, `grants`) and `_Target`
fields (`context`, `platform`, `architecture`, `python`, `abi`, `wheel_tags`,
`context_digest`) are unchanged. Architecture remains the native host;
ABI/tags remain independently observed consuming-process properties.

### Exact removed Windows effect closure

Existing Python 3.12 `platform.py` shows:

1. `machine()` → `uname()` → `win32_ver()` → `_win32_ver()` →
   `_wmi_query("OS", Version/ProductType/BuildType/ServicePackMajorVersion/
   ServicePackMinorVersion)`.
2. `uname()` → `_get_machine_win32()` →
   `_wmi_query("CPU", Architecture)`.
3. Failure routes → `_syscmd_ver()` →
   `subprocess.check_output(shell=True)` for `ver`, `command /c ver`,
   `cmd /c ver`.
4. Actual packaging 24.2 `Marker.evaluate(environment)` obtains
   `default_environment()` before applying overrides, entering
   `platform.machine/release/system/version` on every evaluation.
5. Actual packaging 24.2 `sys_tags()` defaults platform selection through
   `platform_tags()` → `platform.system()` → `uname()`.

Baseline source was read; no actual WMI/shell query was used as evidence.
The installed markers source SHA-256 is
`73cf5337307b65d198864a2f9ba3d89aa1b21f15e561568b5b9f753c750d283f`.
The existing Python `ensurepip/_bundled/pip-25.0.1-py3-none-any.whl`
also contains packaging 24.2 with the same required evaluator/repair signatures;
its source was read without installation or source copying.
These are observations, not fabricated publisher/toolchain pins.

### Factual producer and consumer propagation

| Owner | Actual boundary |
| --- | --- |
| `_setup._contexts`, `_guided._existing_contexts`, `_guided._report`, `_lock_layout._compile_context` | Shared `_host_architecture()`, no `platform.machine` |
| `_default_family._default_metadata` | Existing context host facts and `_interpreter_tags()`; independent process ABI/tag observation |
| `adapters._PYTHON_PROBE` | Exact packaged standalone factual prelude in the selected isolated interpreter |
| `_publisher_metadata._edges` | `_target_environment()` refuses foreign unobserved facts; `_evaluate_marker()` uses actual upstream tree/evaluator |
| `_documentation._installed_dependencies` | Actual host environment and same upstream evaluation; typed unavailable maps to `documentation-marker-facts-unavailable` |
| `_setup._cached_closure`, `_OfflineInstallation.install` | Shared fixed `_WHEEL_METADATA` prelude/evaluation; cache profile is same-host/interpreter only, admitted installation independently repeats real tags/ranges/hash/closure before venv/pip |

On Windows the only native context queries are `GetCurrentProcess()` (this
process's pseudo handle) and `IsWow64Process2(HANDLE, USHORT*, USHORT*)`.
The prototypes use WinDLL/stdcall, pointer-sized HANDLE, 16-bit output words and
32-bit BOOL. Actual native/process machine values are distinct; no global PID/
thread discovery or handle lifetime change is introduced. Missing export,
failed query or unsupported machine rejects `_ContextUnavailable`.
`GetNativeSystemInfo` is deliberately not used as host authority under emulation.
Linux/macOS use the bounded kernel `os.uname()` facts.
Windows public packaging tag APIs receive explicit process-build platforms from
`sysconfig.get_platform()`, retaining upstream ordering and ABI computation.
Compatibility-interpreter selection separately mirrors the actual installed
packaging 24.2 `sys_tags`: CPython uses `cp` plus `interpreter_version()`,
PyPy uses `pp3`, and other implementations pass `None` to `compatible_tags`.
Primary `generic_tags` retains its own upstream interpreter/ABI calculation;
it is not replaced with the compatibility interpreter. Installed `tags.py`
SHA-256 is `085aab2730337365cd19ec5eac7fff4fe639230abb59bb185ec88b1112d6c58d`.
This source correction addresses local defect `N22-CCR-TAGS-01`; it does not
qualify an actual PyPy/other runtime. Only the prior actual AMD64 CPython facts
are qualified, and independent tag-selection/order assertions remain tester-owned.
POSIX upstream tag selection is unchanged, with no new no-effect qualification.

`_evaluate_marker(marker, environment, extra="")` accepts only the actual
packaging or pip-vendored `Marker` class. It calls the actual
`_repair_python_full_version(env)` and `_evaluate_markers(markers, environment)`;
the required private signatures and parsed-list shape are checked before use.
Unknown interfaces fail typed unavailable. No stable public ABI is asserted,
and no grammar, version/comparison operator, extra normalization or Boolean
algorithm is copied. Public `Marker.evaluate` is not invoked because its
unconditional default-environment discovery cannot be suppressed by overrides.
No platform/packaging global monkeypatch or fake environment authority exists.
`_context_program` reads this package's own standalone facts source once for
the two fixed child programs; selected children need no project import.

Unavailable Windows marketing-release/version fields are omitted, never
guessed as `""` or a possibly different kernel32 version. Referencing them
raises `marker-fact-unavailable:<field>`, including eagerly evaluated arms.
Foreign target platform/architecture/Python requires an actually observed
independent interpreter environment; a `_Target` or installation profile alone
cannot supply implementation/release authority. This exact remaining limit is
not a new generic approval gate, redesigned contract or platform qualification.

Original issuer-retained bootstrap/family contributions, authentic locks,
native identities, source guards, deadlines, category/one-use grants,
captured Windows-child hp/ht/PID/TID and owned cleanup are untouched.
Independent route/omission tests and full FR/AC/NFR, installed-delivery,
Molecule/platform/legal/CI obligations remain outstanding. All incidents and
failed attempts stay OPEN/retained. Narrow own offline compilation, lint/type
and helper observations are source-owner checks, never tester/reviewer approval.

## Nov22 recursive offline wheel extras — source correction, proof pending

`_installation._WHEEL_METADATA` remains the single fixed offline verifier.
Root selections and active `Requires-Dist` extras are canonicalized with
`packaging.utils.canonicalize_name` (case and runs of dash/underscore/dot).
Every pending distribution's accumulated extras must be a subset of its actual
wheel `Provides-Extra` before checked-state reuse or requirement-marker evaluation.
This same declaration gate covers initial selections and transitive contributions;
an undeclared extra is not silently ignored. A newly contributed canonical extra
requeues the dependency, even if it was already visited. The existing
`(distribution, sorted extras)` checked key reaches the same monotone fixed point;
no resolver, dependency selection, acquisition or fallback is introduced.
Inactive environment-marked edges add no extras and need no dependency wheel.
Active edges still require a selected compatible version and every newly
activated requirement, including feature-marked transitive leaves.

The two unchanged consuming interfaces are:

- `_setup._cached_closure(manifest, document)` invokes
  `(sys.executable, "-I", "-B", "-c", _WHEEL_METADATA, json.dumps(wheels),
  json.dumps(profile))` with the trusted review interpreter. The platform/Python
  profile is descriptive and must match current Python/platform marker facts;
  it is not interpreter/tag or platform qualification.
  `_guided_metadata._Metadata.resolve` maps its existing `OSError`/`ContractError`
  rejection to `verified-offline-cache-required` with `verified-cache-member`,
  before a resolved candidate or effect consent. Direct setup rejects before
  root reservation and installation.
- `_OfflineInstallation.install(manifest, assets, clock, cancel, deadline)`
  invokes `(spec.python, "-I", "-B", "-c", _WHEEL_METADATA,
  json.dumps(selected))` through its existing guarded runner, without a profile.
  Actual pinned interpreter, tags, wheel bytes/hashes and Python ranges remain
  mandatory. A closure rejection occurs before installation-target creation,
  `_VENV` and offline `pip --no-deps`; it uses existing failure handling,
  not a new public reason or success receipt.

Independent tester controls must exercise the actual shared program and both
consumers: declared/undeclared transitive extras, omitted active feature leaves,
multiple inbound contributions, a dependency visited before its later extra,
cycles reaching a fixed point, inactive environment markers and canonical extra
aliases. Removing only the pending declaration assertion must invalidate an
otherwise passing undeclared-transitive-extra rejection control. Caller controls
must assert no later root reservation/consent/dispatch or installation mkdir,
venv/pip effect respectively, not merely serialized selections.

This is an original I02 increment mapped to AC-001/011/014 and
FR-003/005/006/007/035, not full criterion acceptance. No tests, product execution,
build or analyzer proof was produced by this source/docs task. Actual issuer,
pin, native identity, source guard, original deadlines, one-use/category grants,
Windows child and cleanup contracts are unchanged. All original I02/S02 and
authentic publisher/platform/installed-delivery obligations remain; O03/O04
historic dispositions are retained, with no new Q03 prerequisite.

## Nov22 issuer-retained selected-family composition — source only

The repair preserves the distinction between factual planning and effect
admission. `_Metadata.resolve` first consumes `_FamilyPlanning._resolve`,
retaining original stopped-selection reasons and both native/controller
current-version toolkit requirements. Missing original bootstrap contributions
refuse a resolved compound candidate before layout compilation or any effect;
unresolved metadata needs are not replaced by authority diagnostics.
Public effect admission, compiler, source eligibility and host checks remain
unchanged. Corrected bytes cannot inherit the earlier whole-suite receipt.
The separate bounded original publication predecessor group returned without
a busy failure, and the original observation-window group returned without a
primary service error. These source-owner observations cannot classify either
whole-run recurrence. No storage or observation-duration workaround was made.
Exact isolated baseline/omitted/restored source namespaces preserve the original
checkout guard and tests for independent postassignment omission execution.

`_FamilyResolver` now retains a private identity-bearing contribution for every
selected release after actual closed publisher observations succeed.
`_FamilyPlanning._resolve` transports that original issuance alongside the
factual lock; its existing two-value `resolve` interface remains unchanged.
`_Metadata.resolve` binds the complete compiled candidate and live cache/tool/
root/context inputs, then joins it with `_BootstrapContribution`. The unchanged
managed broker/stage/installer/family handlers consume the joint live guard.
`ManagedLifecycleState.guard_source` additionally compares the exact selected
manifest with the bound contribution before effects. No native capability is
widened beyond its original `native.stdlib` subset.
The actual `_Authority` family entry checks its operation against the original
issuer-retained selected release, lock digest and candidate generation, not
just equal JSON. Full/compound/enhanced source eligibility, public effect entry
and host construction share `_requires_contributions`; missing native or family
actors cannot authorize a publisher-only full admission. Existing narrow native
compatibility remains distinct.

`_family_source` rejects serialized/value-substituted identities, foreign
process/thread, replaced source/client/transport, changed metadata/input/member/
context/interpreter/cache facts, backward clock and original observation expiry.
Its digest is not consent, a platform qualification, or authority reconstructed
from JSON. Only existing real PyPI/Galaxy/Python.org/profile client types issue
contributions; legacy injected metadata ports still return factual locks but
cannot issue composite authority. No new network operation or origin is added.
Existing protected root/control/pointer/ledger and one-use lifecycle permits
remain the effect owners. Prior healthy/pinned/unknown trees are untouched.

The fixed process wrapper carries the live guard through real spawn/assignment
and joined completion. Individual successful Job/child/reader/pipe releases are
remembered; failure finalization retries only unreleased resources while keeping
the original failure and owned-resource boundary.
Windows Job thread/snapshot handles also retain exact ownership until each
native close succeeds. Numeric native failure codes are preserved before
cleanup can overwrite the last-error slot.
Finalization completes both remaining stop/close attempts before joining, also
on assignment failure. Process waits and reader joins consume a single
nonrenewing one-second `time.monotonic` cleanup self-limit, separate from and
never renewing original operation/probe/grant/observation deadlines. Successful
child kills/waits, reader joins and handle/pipe closes are remembered. A live
reader at that limit retains explicit cleanup uncertainty and its buffered pipe
is not closed synchronously under a held read lock; daemon readers avoid an
implicit unbounded interpreter-exit join. Existing structured cleanup errors
retain the active primary and unreleased-resource uncertainty. Fresh independent
live-child simultaneous native stop/close failure, assignment-failure and
never-finishing reader controls remain tester obligations, not verified outcomes.

The first unchanged untraced isolated publication/source-drift control passed;
only expected native directory-exists outcomes were observed, not a busy failure.
This bounded nonreproduction does not establish a historical root/lock cause.
No sleep/retry/tracing, lock weakening, ACL/AV or Store frontend workaround is
part of the correction. Independent composite admission/each-subset/actual
child cleanup tests remain mandatory, along with authentic current pins,
complete platform/runtime/guest handlers, current wheel/sdist delivery and all
original 45 FR / 15 AC / 6 NFR. No source-only result turns formal gates green.

## Nov21 bootstrap/layout reviewer corrections — awaiting independent verification

The live bootstrap contribution is now inspected before each managed occurrence
and every acquired transport attempt after broker admission. The stage handler
recognizes the bootstrap digest independently of publisher asset type, and
rechecks under its original protected lock before staging intent, file staging,
installed verification and publication. Family authority checks inspect the
original actor before ledger/dispatch and subsequent fixed host I/O boundaries.
No private capability is reconstructed, no source/cache/tool/output/context/root
guard is removed, and no original consent or clock is renewed.

### LOCAL-BL-01 intra-stage correction — source written, verification pending

The handler now retains the actual `ManagedLifecycleState` source owner in a
private in-process guard while the original lifecycle lock remains held. The
guard is carried only through the host's exact `ProtectedGenerationFiles`
instance, not supplied by serialized metadata or reconstructed from a receipt.
It rechecks before each new materialization directory/member/sentinel and
generation publication, and after publication before offline installation.
Installer directory, wheel/native/lock/receipt writes, fixed process spawns,
functional consuming verification and the controller child retain that same
guard, manifest, original monotonic clock, cancellation and deadline. Windows
directory creation and suspended-process assignment also recheck at their
native boundaries. Existing member/interpreter hashes and protected path checks
remain unchanged. Rejection retains all prior factual writes/failures rather
than deleting partial trees, replaying effects or renewing producer authority.

The assigned source/docs-only correction does not execute tests or analyzers,
alter fixtures, or self-accept LOCAL-BL-01. Fresh actual producer drift after
publication and before each installer/child/process boundary must independently
prove zero subsequent effects. The original 45 FR / 15 AC / 6 NFR, native.stdlib
producer restriction, unqualified full product scope and all prior failures
remain unchanged.

The managed controller consumer selects the controller child from the unchanged
native parent descriptor. Its root must remain the parent installation root;
the full parent receipt, staged descriptor, active pointer, qualification,
context and generation pins remain load-bearing. Qualified executable/runtime
members must select the controller child, including its parent-pinned receipt.
Verification still hashes the complete parent tree, not just an independently
selected child. Legacy controller-only descriptors keep their direct layout.

These are production source corrections, not tester/reviewer acceptance.
The earlier full-run receipt predates these bytes. Authentic publisher signature
proof, real POSIX/guest layouts, configured isolated build, controller protocol,
both real Molecule tiers and full original 45 FR / 15 AC / 6 NFR scope remain open.

## Nov21 closed source correction milestone — not full I02 acceptance

The original 45 FR / 15 AC / 6 NFR scope is unchanged. `DependencyService.verify`
now projects expired public observation/policy budgets as typed blocked readiness.
It retains one paired observation per dependency, does not renew original budgets,
and never catches primary adapter/policy or invalid-clock defects. Expired results
cannot populate reuse caches; guided diagnosis requests a fresh bounded observation.

### Official source model and compiler

The Nov21 18:47 PST source authorization supersedes the historical pending
publisher decision only for code/models and mocked external-boundary work.
`_official_profiles` is a concrete HTTPS/raw-metadata implementation, not an
unsupported Protocol stub. Its fixed profiles cover Ubuntu Packages/pool,
Homebrew formula/bottles, MSYS2 repository TAR desc records, the exact Git for
Windows and Podman numeric project release/asset scopes, Fedora minimal immutable
manifest/config objects, and Canonical cloud-build checksum/image scopes.

Typed `_OfficialPin` separates logical requirement and authentic publisher package
identity, exact source/raw/artifact hashes and sizes, license identity,
qualification reference, complete members/dependencies/blob closure, and
`_PublisherContext` host/consuming guest/layout/platform-release/Python/ABI identity.
Raw metadata confirms those facts before compiling existing `_Release` formats.
No package is relabelled an archive, VM image a WSL rootfs, or Windows host a POSIX
Ansible controller. Unsupported native version/range/extraction schemes remain
explicit inputs. The exact reviewed-pin integrity branch is implemented;
OpenPGP/OCI key enrolment, signature verification and live publisher licensing
qualification remain separate unimplemented proof, not a manufactured success.

The v3 packaged factual catalogue adds empty `official_records` while retaining
v1/v2 readers. `SetupMetadata.publishers` and default family resolution wire the
same closed real clients. Missing pins block before HTTP. Calls keep the original
live cancellation and 60-second window; queries, path aliases, unrelated projects,
unsigned normalized callbacks and unreviewed CDN/token/redirect scopes fail.
No acquisition origin guard or qualified native producer scope was widened.
Consequential OS/WSL/VM/runtime/image/service/elevation/security/reboot grants,
full family owned-bootstrap contribution, separate controller install layouts,
both real Molecule tiers, and fresh installed wheel/sdist proof remain open.

### Registry-selected owned documentation bridge

`native.core:docs` and `extra:docs` are the single declared docs dependency
selection. Full setup selection includes this intent and real mkdocstrings Python
extra. `_documentation` validates the complete installed dependency closure,
selected interpreter bytes, reviewed source-file seal and new output before a
distinct process/thread-local one-use `build-docs <digest>` confirmation.
Both installers preserve the legacy extras/`NETOPS_DOCS_DIR` contract and invoke
this bridge after successful install/update, or explicitly via docs-only mode.

Only new output roots receive owner-only inheritable Windows protection; existing
roots/ACLs are never repaired/adopted. Reviewed source is copied to that root.
The sole command is selected Python `-B -m mkdocs build --strict --config-file
<owned>/reviewed-source/mkdocs.yml --site-dir <owned>/site`, with no shell,
global pip/cache/config/rc, network grant or validation relaxation. Only this
closed standalone docs mode may use already installed user-site tooling;
installer processes keep their original isolation. Strict failure retains partial
owned output. Success seals exact source and output hashes with explicitly
unqualified publisher/managed-generation state, not a runtime qualification.
Source-link errors and independent installed-delivery equivalence remain blockers.
Strict nonzero exits preserve bounded stdout/stderr in exclusive owned logs.
The standalone review has a single 300-second maximum, not a renewed managed
installer or publisher budget. Source reads compare stable device/inode/size/
mtime across path and handle observations, and ctime within each native API:
actual Windows Python 3.12 `lstat` and `fstat` expose different ctime semantics.
No differing cross-API ctime is relabelled a source mutation or ignored within
the same API.
The isolated installer docs entry explicitly adds only the selected interpreter's
standard user-site path for installed-tool observation, without running its `.pth`
startup hooks or accepting ambient `PYTHONPATH`; the setup entry remains unchanged.
The exact owned source build reached installed MkDocs and preserved its nonzero
strict exit with the original 15 out-of-doc-root link warnings. That is a source
delivery observation, not successful docs delivery or installer equivalence.

### Exact native builder and historical inventory boundaries

The source-owned venv path retains explicit `--copies` and now verifies that the
expected platform executable was really created before proceeding. Missing
executables use the existing bounded numeric native-child diagnostic, not raw
stderr or new wire enums. Actual installed `build.env._PipBackend` creation mode
and historical missing-executable gates are separate from this source mode.
Neither short-root success nor diagnostic WinError206 paths close the original
ensurepip101/storage diagnostic or justify AV/ACL/global-package workarounds.
The bounded Nov21 owned diagnostic reproduced the installed backend selecting
`symlinks=True`, then failing its executable lookup. The same no-pip source
probe with copies returned an existing `Scripts/python.exe`; the symlink probe
returned an inaccessible link (`WinError1920`, errno22). This is evidence about
that exact installed builder/interpreter/layout, not a blanket storage diagnosis,
historical ensurepip closure, or permission to patch the installed build package.

The exact preserved sidecar
`bundle.json.historical-nov13-current-proof-native-v3`, SHA256
`bd9a11722e0ae16c736ad1031ff7ff22a6d272f16305978bb683d8a0a62bcb90`,
is historical only. Original source/docs265 and preservation inventory198 remain
unchanged historical operands; the original actual runtime census is197.
Consumers and packaging select current `bundle.json`/PX/contracts and explicit
Rust sources only. There is no generic exclusion/deletion. New source modules
must additionally appear in the next independent fresh wheel AND sdist census.

`operations.json` owns canonical per-export requirements. Public callable
reexports link to registered canonical selectors through `aliases`; they do not
copy dependency lists. Loading rejects unknown/cyclic targets and competing
alias-specific dependency overrides, then projects canonical requirements into
the immutable catalog. Exact public selection additionally inherits canonical
capability, tier and optional intents through `DependencyRegistry.operation`.
Plan and verify use that same selection and requirement resolver.
Dependency consumer edges are validated at the canonical capability, rather than
inventing an additional consumer merely because a different module reexports it.

`validate_public_sources` statically checks the entire registered source set,
including public reexports from absolute, relative and renamed imports. Omitted
or retargeted alias links fail closed without importing optional dependencies.
Source-derived canonical import controls and a manifest-wide alias-equivalence
matrix complement actual report consumer import-denial controls.

Package-level aggregation, tables, mail and filename helpers therefore retain
their canonical stdlib requirements. HTML consumers retain Jinja2; explicit PDF
selection retains WeasyPrint and native PDF functional-render prerequisites.
Group/full-toolkit selections remain unions, never weakened by a stdlib alias.
The original I01 increment introduced no installer, dynamic broker, remote
service, runtime acquisition or qualification authority.

## I02 source increment and incomplete boundaries

### Private full-family resolution and dispatch building blocks

The private `_family_lock`, `_family_provider`, `_family_ledger`,
`_family_consent` and `_family_bridge` modules add immutable compatible closure
resolution and exact typed dispatch contracts for interpreters, wheels,
executables, collections, native libraries, runtimes, images, services, OS
features and distributions. `_guided_metadata` now consumes that lock;
`_setup` pins its complete factual representation in the owned root manifest
and initializes explicit family ledgers. `_composition` appends registered
family install/verify postconditions to the original admitted lifecycle. This
is consumed integration, **not completed platform provisioning or a completed
guided installation path**.

`_publisher_metadata` supplies closed production PyPI version-JSON and Galaxy
collection-version clients over the existing bounded HTTPS boundary. Raw
metadata hashes must already be independently retained; exact versions,
artifacts, hashes, sizes, target-specific PEP 508 edges and collection/core
constraints must agree. Neither the catalogue nor a response establishes
consent. `SetupMetadata.publishers(...)` composes these clients without I/O;
it still requires complete retained pins/cache/layout and consuming-context
bindings. Its `python_files` parameter supplies typed `_PythonFile` release/file-ID
facts; the exclusive `python_records` parameter supplies `_PythonSeed` official
raw-record/archive/member facts. `publisher_records` supplies typed raw
PyPI/Galaxy selectors, exclusive with retained releases for the same source.
The shared `_RetainedCatalogue` factual registry validates both public inputs
and packaged records and registers only the exact closed production clients.
A bare normalized Python release has no official file ID and remains invalid;
the registry never infers an endpoint, invents a digest or accepts a caller
transport/response callback. Python.org is an existing approved origin, not a
new trust profile. Descriptor-free install/update now constructs the production resolver,
target ABI/wheel tags and fixed installed-package catalogue automatically.
That catalogue separately represents PyPI/Galaxy releases and Python.org
release-file IDs. Its currently empty arrays truthfully retain missing pins:
default full selection reaches resolution and returns specific metadata needs,
without HTTP, private descriptor reconstruction or native-only readiness.
The v2 installed resource supports independently pinned raw official metadata
selectors in addition to retained normalized v1 releases. `_publisher_catalog`
compiles actual PyPI/Galaxy artifact hashes/sizes and full target-specific edges
from exact bounded raw responses, then reuses the original validators.
`_python_metadata` compiles exact official file ID/URL/size facts only against
separately verified archive/member/compatibility pins. Legacy MD5 is never promoted
to SHA256, and no native archive or publisher pin is fabricated.

`_lock_layout` now supplies the actual default installation compiler. Before
observation it binds targets to the prospective generation's consuming paths;
after observation it consumes the complete lock without modifying its evidence.
It derives ordered archives and the exact digest-directory/publisher-filename
cache paths, wheel/collection/native contributions and original `_InstallationSpec`.
The existing interpreter must match a separately locked executable member; its
freshly computed hash alone is not independent provenance. The current toolkit
wheel is an explicit additional root, never an invented private publisher wheel.
Identical artifacts serving both roles are keyed by source, URL, SHA256 and size,
and deduplicated only with identical family, version, format and member inventories.
All role locks and receipts remain distinct; conflicting per-role versions demand
separate installations. Both retained-v1 and seeded clients use the same actual
optional parser preflight before publisher HTTP. Missing parser tooling remains
a bounded typed `metadata-parser-required` input, not a bootstrap ImportError,
fabricated parser, vendor fallback or implicit parser installation.
An Ansible-only controller does not require or invoke unselected Molecule.
The original manifest, archive, wheel-metadata and collection validators still
run before creation for a fully cached closure and under admitted installation.
Missing exact cache compiles prospective download effects, not readiness or
effects. `_publisher_acquisition` is a live exact-document/asset-bound constructor
value supplied only by this compiler to the original owner. It is never stored
in a setup document and cannot be reconstructed from historical locks or caller
JSON. The original broker separately gates each exact download, and original
stage/installer guards check acquired metadata before interpreter effects.
The live acquisition additionally binds the earliest original publisher expiry,
caps transport time by its remaining window and rechecks that exact deadline after
I/O. `_assets.VerifiedAssetAcquisition` explicitly dispatches the exact closed
`_PublisherAcquisition.read_bounded` production type with its latched clock and
original live cancellation object, so cancellation remains operative inside the
HTTPS child. Original broker entry remains one-use and each retry retains the
same current-authority rechecks. This dispatch does not accept arbitrary bounded
callbacks or confer authority on wrapper subclasses. An actual interrupted I/O
retains its interruption; an already returned response retains the original
factual cancelled-after-acquisition flag and cannot reinstate a stage grant.
A review, missing cache or response never renews source freshness.
Real protected materialized hooks validate already installed stage effects rather
than reacquiring them; only those closed read-only hooks do not need a second
publisher window. General and platform installation keep the freshness gate.
Existing corrupt cache is preserved rather than overwritten or silently
downloaded over; no global/mutable cache is populated. Interrupted pre-stage
acquisition needs verified cache or a newly qualified current candidate/review.
`SetupMetadata.publishers(None, (), releases, targets)` uses this same compiler;
the existing explicitly supplied layout form is unchanged.

Separate controller provisioning and full platform metadata/dispatch remain
incomplete. Offline
known responses exercise the actual external boundary but do not prove live
publisher compatibility or platform qualification.
The first-run root binding is canonically frozen before seed writes; no private
producer object or mutable dictionary is serialized as authority. An earlier
mutable-dictionary digest failure is a distinct preinstallation source defect,
not an explanation of native-child errno 101. Existing partial/historical roots
are preserved rather than rewritten by this correction.

Resolution retains the registry's complete selected consumer census, including
executable aliases of Python distributions, and returns missing transitive
metadata rather than silently dropping dependencies. It checks PEP 440 versions,
requested extras, platform/architecture, Python/ABI/wheel tags, collection/core
requirements, metadata freshness, publisher digest pins, HTTPS origin
restrictions, exact member manifests and cycles before producing a lock. A
missing optional metadata parser blocks resolution; it is not replaced by
permissive version matching. Unrequested container extras remain absent.

The typed driver consumes the existing broker's exact one-use lifecycle permit;
a lock or saved selection never authorizes I/O. Distinct live semantic-scope
reviews additionally separate OS, WSL, distro, VM/virtualization, runtime, image,
service, security, elevation and reboot decisions. Distribution review does not
itself request WSL authority: the actual WSL-rootfs or VM-image format determines
the corresponding underlying consequential category. Review facts reject
replay, expiry and backward time and cannot be serialized as grants.

The owned ledger reads only an explicitly initialized known root with the exact
family-lock digest and policy identity. It reuses the actual lifecycle owner's
root lock, rechecks current cancellation/ownership/pins, records issued intent
before host I/O, then CAS-records the factual result. Interrupted operations
retain uncertainty and cannot replay automatically. Mutation rejects reused
external resources, active/pinned generations and the prior healthy generation.
`_family_codec` reconstructs closed immutable facts, never ports, grants or
producer authority. `_family_integration` binds the entire registry selection,
actual consuming-context digests, interpreter version/platform and every
transitive archive contribution. Wheels and collections must also match the
actual consuming installation layout. Raw locked wheel/collection bytes use
the managed `file` format: one exact nonexecutable member, without an invented
publisher wrapper archive.

The concrete protected-tree hooks consume actual broker authority and recheck
the original owner's real files/installation receipts. They do not execute
another install or claim ownership of a reused external interpreter, daemon or
OS facility. Registration rebinds only current owned ledger heads, preserving
resources, pins and historical receipts; pending uncertain operations block it.
`_platform_host` supplies fixed prospective Linux rootless-Podman, OCI-archive,
transient user-service, Windows feature and WSL2 import operations. Commands
are compiled from closed typed models and verified protected executable/payload
bytes; requests cannot supply argv, shell commands or runtime endpoints. The
service has a generation-specific name, private store/socket and exact live
invocation identity. Images require that owned service, not a global daemon.
WSL removal rechecks the exact registered UUID, location, version and disk tree.
Unknown/modified resources are never adopted or broadly deleted; shared OS
features are never disabled during uninstall. VM-image/macOS providers and
trusted platform publisher catalogues remain unimplemented.

The original uninstall owner now composes reverse platform removals, exact
manifest-owned tree deletion and materialized ledger retirement. A separate
platform directory is exclusively created under admitted authority and retained
with its filesystem identity; only that exact empty directory can be removed.
Nonempty stores and unknown user files remain references, not deletion targets.
The family ledger overlays current pointer/run-pin/prior-healthy facts from the
original owner. Pointer CAS retains the previous active generation in the same
control write; historical roots without this fact are not silently migrated.

Missing materialized-install acknowledgements can reconcile automatically:
an admitted fresh verify operation proves the same exact protected postcondition
and CAS-closes the identical pending install. No host mutation is replayed.
Concrete platform handlers also record an exact protected post-I/O result before
family-ledger CAS. Pending install reconciliation requires that prior operation/
manifest-bound receipt plus fresh read-only identity/state checks. Pending exact
remove reconciliation never calls the mutation handler: it requires the retained
removal receipt and a fresh closed absence query (or exact absent materialized
trees), then CAS-closes only that pending operation. Receipt-loss before this
post-I/O write, foreign/changed resources and uncertain ownership remain blocked,
not blindly replayed. Receipts contain no executable grants and cannot extend
original clocks, semantic reviews or broker permissions.
If platform failure interrupted the family sequence after the real whole-tree
installer completed, a later materialized receipt may never have been issued.
Only the actual protected materialized host can record that missing membership
from fresh admitted read-only tree/installation proof; the exact verify operation
is issued before observation and CAS-recorded afterward. An uncertain issued
verify can be reobserved without replaying mutation. Generic/platform hosts and
unknown external resources cannot create ownership through this route. Full
multi-platform lifecycle and default provisioning remain original open
obligations. Source-only external-boundary controls cannot qualify actual
OS/service/WSL/runtime behavior. No root adoption, historical-proof rewrite, source migration or
full-toolkit readiness is implied. Unsupported known setup schemas return a
factual read-only diagnosis; the creation-only design provides no predecessor
transform authority.

### Private native staging diagnostics

Owned stage and atomic-record I/O retain a bounded private diagnostic containing
only a fixed stage/operation/cause class, numeric native/errno values and SHA-256
operation/resource references. The first primary remains primary; at most eight
separate cleanup references accompany the existing cleanup errors. Diagnostic
logging is nonthrowing even for interrupting sinks. It cannot change admission,
publication facts, pointer state, retry eligibility or readiness.
Diagnostic timing acquisition is guarded even before entering the operation.
Unavailable, nonfinite or backward diagnostic timing omits duration; independent
clock/cancellation/logging observations cannot prevent the body or replace its
primary exception. Operative clocks and original deadlines are unchanged.

Public `SafeError` vocabulary and schema remain unchanged. Its existing `detail`
may contain `storage-diagnostic:<sha256>`; native messages, paths, command arguments,
stdout/stderr and credentials do not enter that reference or the structured log.
Metric dimensions are only fixed stage, operation and cause class; resource and
operation hashes are log-only correlation, not metric labels.

The fixed isolated venv child can relay bounded numeric failure information.
Direct native exceptions have origin `child`; numeric observations extracted
from an inner stdlib subprocess failure are explicitly `child-report`, not a
new host kernel observation or authority. Unknown failures remain failures.
No retry, alternate publisher, ACL repair, sharing relaxation, root relocation,
or Windows long-path-support claim follows from a diagnostic. In particular,
native errors 5 (access denied), 32 (sharing violation), 206 (path too long) and
267 (invalid current directory) are distinct observations, not proof of AV,
an ACL cause, or a common cause with a different historical run.

Four nonthrowing coarse CAS spans distinguish source-before, owned-tree,
installed-receipt and source-after checks. They record only fixed stage/status,
monotonic duration, remaining original budget, deadline and cancellation facts;
there is no per-call tracing, clock patch, grant renewal or skipped verification.
A public embedding host can select observation max-age prospectively at new
root creation; it is retained in the protected manifest and cannot be changed
for an existing root. Probe/grant bounds remain 60/300 seconds. A conservative
UTF-16 Windows launcher/cwd/member admission check can request an explicitly
chosen shorter user-owned root before staging. It cannot silently relocate
an existing root, enable OS long paths or attribute an earlier native failure.

### Host-private owned offline build source

`_owned_build.py` and `_owned_source.py` are closed internal modules (explicit
empty `__all__`, underscore-only definitions), not new public source families.
They remain subject to the complete AST census: adding public exports cannot
silently inherit a dependency-directory exemption.

The trusted constructor-supplied `_OfflineBuildHost` executes a bounded,
shell-free fixed `setuptools.build_meta` wheel/sdist operation against an exclusive
owned working copy of sealed current sources. It uses the existing explicitly pinned
interpreter/toolchain and an exact independently qualified local cache inventory.
The backend is imported directly from that exact qualified setuptools wheel
under `-I -S`; unrelated site packages and user-site entry points are not loaded.
Its ZIP namespace resolver accepts only implicit directory prefixes actually
present in that qualified wheel, including normalized native parent paths.
The real backend instance runs fixed `bdist_wheel`/`sdist` commands directly
in a newly created inheritable-owner-only output root. It does not repair
the different package ACLs produced by Store Python's temporary-directory
wrapper: those files remain rejected. Failed builds retain only safe exception
types, numeric codes and basename/line frames, never raw subprocess diagnostics.
It neither resolves/downloads dependencies nor installs globally. The producer
records both actual build outputs, exact source/cache/tool/file identities,
qualification references, root identities, consuming context, member sizes and
hashes, fixed operation and successful exit. Its create-only ledger is bound to
the expected digest supplied by trusted host composition on recovery. Merely
finding JSON with those fields does not qualify an actor, cache or build.

`_OwnedSource` issues a nonserialized process/thread-bound capability only after
that producer validates its own ledger and current inputs/outputs. The factual
asset has origin `owned-local-build`, dependency `toolkit-wheel-bundle` and **no
publisher URL**. Existing-Python reuse is a separate interpreter observation;
it is never asserted to be an interpreter packaged inside this wheel bundle.
The current private composition deliberately supports only `native.stdlib`
with pinned existing Python and a complete toolkit wheel closure. It does not
qualify a Windows Ansible controller, Linux/WSL, full native handlers, PDF,
services, runtime/image sources, or either Molecule tier.

Trusted `_setup._seed` / `_setup._host` composition may receive this private
provider explicitly. Owned durable `netops-owned-build-v1` documents contain
only facts; `_manifest` rejects them without that independently supplied
provider. Public `--plan-file`/CLI parsing cannot construct it. A fresh process
must obtain the trusted current producer with the exact original input/root
specification and independently retained expected ledger digest, then reissue
the source capability after validation. It does not deserialize a private
grant. The existing public service still owns plan/review/provision/resume;
fresh exact lifecycle consent and actual readiness are required as before.

The owned setup root may explicitly bind `observation_max_age_seconds` before
its first plan. This uses the existing `ObservationSettings` contract: 60 seconds
by default, with an explicitly selected integer range of 1–300. Absence retains
the historical root shape and default; a configured value participates in the
immutable root-manifest digest and therefore every exact lifecycle plan and
consent binding. Fresh host composition reads and validates that protected
setting and shows it in both the review display and exact-consent prompt.
Changing the selected host setting without the corresponding original root
binding rejects; it does not extend an already issued observation or grant.

This observation lifetime is distinct from the unchanged 60-second functional source/tree
probe window, 60-second public readiness budget, five-second adapter bounds and
original lifecycle grant deadline. Retained full-tree guards keep their original
predicate: the earlier of the original observation expiry and lifecycle grant
deadline. A newly configured observation does not add another guard deadline or
renew either issued bound. Actual source, ownership, membership and
installed bytes are still reverified before pointer CAS. No guard is skipped
to meet the window. A measured native activation can spend most of the default
observation lifetime on verification publication, public review, reducer
checkpoints, the admitted retained probe and the independent final CAS guard;
the owned setup host can now explicitly select the normative observation
setting before issuing fresh evidence instead of silently hardcoding the
default. Existing roots and expired 60-second observations are not migrated.

Recovery's observation digest describes the last **completed** consuming
verification, not the pre-install missing-interpreter observation. After the
real dependency-verify effect, broker completion and reducer completion all
succeed, the owned recovery head advances by CAS to that exact report digest.
Failed or denied completion retains its prior baseline. Fresh-process resume
still compares a new actual report and exact consuming contexts with that head;
readiness drift rejects before effects. The immutable generation selection,
audit history, source ledger and live capability remain separate from this
non-authoritative observation. This does not renew candidate evidence or
consent deadlines, and does not migrate historical producer/root bindings.

Managed byte acquisition consumes its original private one-use permit and
300-second aggregate cap. Stage, consuming verification and activation CAS
recheck the producer's exact ledger, inputs, toolchain, cache, outputs, roots
and selected contexts within their original deadline/cancellation bounds.
Changed actor, receipt, source, cache, tools, output, context, members or
ownership rejects before the corresponding effect. No HTTPS guards, three
publisher-domain families, installed-tree rules, pointer/drain predicates or
retained-policy checks are relaxed. Historical synthetic `python.org` archive
descriptors remain invalid origin evidence and are not adopted or migrated.

These are implementation boundaries, not independent test, source-origin,
platform or Q03 qualification claims. Native author runs and installed-package
proof must identify their exact source seal and actual remaining failures.

### Durable guided selection, census and original transport budgets

The public dependency package, service and local probe adapter now participate
in the canonical operation manifest and complete source census. There is no
dependency-directory exemption for future public modules. Underscore-prefixed
implementation modules with an explicit empty public surface remain private;
declared public exports are checked.

On a previously owned root, guided operations can select the exact registered
descriptor without `--plan-file`. Selection validates all durable descriptors
and unique generation IDs first. Verify defaults to the factual active pointer;
restore requires an explicit generation; other operations default to the last
explicitly registered candidate. Explicit scope disagreement, unknown IDs and
interrupted registration stop before probes, prompts or writes. This selection
does not confer consent or qualify retained bytes. Restore and uninstall still
use the original admitted planners and their verified scope, pointer, pin and
ownership guards. The POSIX guided controller's consuming identity now matches
the controller identity bound in its request context.
Resume defaults to the durable current installation ID and rejects a different
ID before review; neither ID nor saved descriptor reconstructs a private grant.
Plan/install/update preserve the requested scope, including the default full
toolkit. A previously narrow candidate cannot silently narrow a full request;
a different scope enters descriptor-free discovery for the complete new request.

### Descriptor-free discovery and metadata compilation

`_setup._first_run` now consumes the actual public `plan`/`verify` pair before
creating an owned root, installation or host record. `_guided.py` projects that
complete canonical closure, including all registered transitive requirements,
into typed observations, Reuse/Install/Decline requests and exact NeedsInput
metadata keys. It does not maintain a second operation/type allowlist. The
verifier's separate qualification record remains qualification, not an extra
dependency observation. Existing selected-context adapters own all bounded
probes; no WSL/distro/service launch, download or arbitrary module/argv dispatch
is introduced. Native Windows has no implicit controller context.
Discovery retains `sys.executable`, including an existing virtual environment
or the launch identity reported by Store Python. Interpreter pinning is a
separate check: a base Windows installation can pin its actual binary under
`sys.base_prefix`, not pretend that its unhashable Store launch alias is file
bytes; base POSIX pin selection resolves the existing executable. The actual
selected interpreter version and file hash must both match before root
creation. No alternative runtime is downloaded, installed or inferred from
a caller's executable argument.

Pure plan never probes, prompts, invokes a metadata provider or writes. Guided
install/update collect compatible existing-context evidence, default unavailable
components to decline, retain the full selected closure when any component is
declined, and show separate prospective consequential groups before effects.
Selection and `review` requests are not authorization. Exact lifecycle review,
one-use admission, cancellation/deadlines, retained guards and pointer CAS remain
with their existing owners.

`_guided_metadata.py` compiles constructor-supplied typed installation/locked
archive metadata into the existing manifest format, preserving source-family
validation and complete ordered asset checks. Actual cache membership and
wheel/collection transitive metadata validation and the actual existing
interpreter's regular-file hash run before root reservation.
Existing private owned-build composition can instead supply its live provider;
the original guard still rejects every scope except `native.stdlib`. No public
request or descriptor can instantiate that provider. Root creation, durable
registration, staging, public provision/resume and distinct activation review
then reuse the existing setup host and dependency service.

`netops.setup.SetupMetadata` is the supported public typed composition of that
existing live producer, installation, protected consuming root and generation.
It exposes no archive/URL/trust/grant input. The public `main(..., metadata=...)`
uses the same compiler, not a second installer. A producer-owned empty consumer
root is distinguished from an unknown existing directory by the exact private
producer receipt's path/device/inode and current protected-root validation.
Initialization requires a separate digest-bound review, original sixty-second
deadline, fresh producer guard and final empty-root check. Only then does the
host create its ordinary owned records and enter the unchanged public
plan/review/provision sequence. Nonempty unregistered roots still fail before
probes or prompts; existing registered hosts retain the original loader.
Synthetic source-port coverage of this path is not a genuine producer/install
receipt. The independent final build and admitted native proof remain required.

Absent verified metadata yields versioned `NeedsInput`, not generic abandonment,
success or invented readiness. Every selected key retains its kind, version,
platform, source, dependency edges and missing fields. A canonical bounded
`--checkpoint` and `next_command` carry only non-authoritative selections and
root/registry/context/scope binding. They do not carry private consent or source
capabilities, never select an owned generation, and require fresh actual probes
on continuation. No selection file or private JSON reconstruction is required.
The generated command uses the selected host interpreter and fixed isolated
source bootstrap, not an installed-package assumption, caller-supplied argv or
an arbitrary program decoded from the checkpoint. It therefore also works from
outside the source checkout before installation.
`--companion` selection and the PowerShell/shell forwarding routes retain the
same full/default/enhanced closure semantics.

Both new underscore-only modules explicitly expose an empty `__all__` and remain
inside the complete source census. No public-module exclusion was added.
Production full-scope source pins and OS/runtime/service handlers remain
unfinished original I02 SOURCE obligations. Typed missing metadata is not
qualification, a source-complete assertion, or a native delegation/gate waiver.

Before creating a managed venv or invoking pip installation, the admitted stage
checks the actual pinned wheel metadata with the selected interpreter's PEP 508
parser and compatible tag set. Name/version and Python ranges, active transitive
requirements and propagated dependency extras must resolve entirely within the
locked wheel set; direct URL dependencies fail closed. ZIP members are bounded
and cannot be links, encrypted aliases or traversal. Collection metadata closure
is likewise checked before environment creation, then rechecked at consumption.
The guided local descriptor path also parses the complete verified cached
archive membership and runs this same wheel-metadata guard before creation,
consent or acquisition. That read-only metadata phase runs the already trusted
review host, never the executable supplied by the descriptor. Its selected
version/platform profile is descriptive; actual compatible tag/environment
checks are repeated with the pinned selected interpreter after admission.
Retained operations do not require the old cache or execute a broken active
generation. Remote metadata discovery is not implemented.
Only the wheel's top-level `.dist-info/METADATA` is its distribution authority.
Setuptools' legitimate nested vendored metadata remains ordinary hashed wheel
content; it is not mistaken for another root distribution or an independent
dependency. No installed/archive path grammar or ownership guard was widened.

Verification latches clock samples across its original sixty-second budget.
A late successful probe is blocked before it enters reusable observations.
The policy's remaining milliseconds are derived from that same deadline, not
a fabricated positive value. Budget expiry during report construction or the
policy decision rejects the verification rather than returning late readiness.
Production HTTPS acquisition runs only fixed stdlib network code in one
credential-free, non-shell child. The parent samples cancellation and the
original source-clock deadline while a separate real elapsed cap prevents a
stalled child from renewing the granted span. DNS, connect, same-origin redirects,
body reads and pipe completion are all inside that span. Failure terminates
only that child PID and joins its output reader; no resolver thread is abandoned.
The child cannot acquire packages, run hooks, write caches or launch descendants.
TLS/redirect/unknown failures are not retryable; bounded HTTP/transient failures
retain the existing aggregate retry limit and original private permit.

These changes do not discharge the six older inert-host fixture failures.
Those fixtures contain no managed public projection, durable selected scope
or `dependency-readiness` verification. Promoting their inert byte observation
to an installed generation would violate the product trust boundary. Independent
tests must supply truthful managed prerequisites rather than weaken the old
assertions. Full selected runtime/image/service/OS composition, genuine
POSIX/WSL and both-tier Molecule qualification remain separate unfinished
original obligations, not author-approved deferrals.

### Installed-data naming correction (not managed-install qualification)

The installed-tree receipt validator is distinct from artifact logical IDs,
canonical PX grammar and archive member destinations. It now accepts literal
interior ASCII parentheses as well as spaces, including setuptools' legitimate
`Lib/site-packages/setuptools/script (dev).tmpl`. It does not normalize arbitrary
names or adopt members by their spelling. Separators, ADS, traversal, reserved
Windows device names, trailing dot/space, control/non-ASCII names and excessive
depth/length remain rejected. Case-folded inventory aliases also reject.
The actual owned tree still requires regular/no-link/no-reparse members,
owner-only permissions, exact hash/size membership, source-bound receipt and
the original root/deadline/cancellation checks. Uninstall consumes this same
installed-member grammar, not the stricter archive grammar.

The earlier final managed attempt genuinely failed at this legitimate member.
Source correction is not a successful installation receipt: the independent
tester must rebuild after final source sealing and own the actual fresh offline
managed install/uninstall proof. Ordinary package installs do not discharge I02;
actual full selected runtimes/drivers and downstream Q03 remain incomplete.

`service.py` preserves I01 catalog/plan/verify behavior and the seven-argument
constructor. It adds concrete lifecycle entry methods via internal
`_lifecycle.py`, using the actual A01 private lifecycle consent/broker and A02
owned state/handler. There is no operational `OperationPlan` coercion, alternate
broker or serialized grant. The original public `InstallPlan` remains the
read-only description. With an explicitly configured managed host it now also
contains the exact closed lifecycle projection and explicit blocked
dispositions. `review()` sends that exact projection to the original private
consent adapter; `provision()` accepts the public wrapper and independently
recomposes it from registry/current owned metadata before admission. A caller
cannot bypass this managed entry with a raw private lifecycle plan.

The service records selected dispositions and independent primary/cleanup/local
uncertainty, factual selected pointer/revision and durable safe outcome history.
Staging alone is partial/non-ready; missing or changed functional re-probe
identity blocks pointer mutation. A02's inert byte receipt is never controller
readiness. Actual package/controller installation, protected bootstrap, complete
crash reconciliation and production run-pin integration are not implemented
by this increment. Original I02 is not complete.

`_assets.py` owns a typed, separately pinned, one-use admitted HTTPS acquisition
primitive. Its reviewed source identity includes registry digest, descriptor
digest, exact bytes digest and size. Registered source-family origins are
allowlisted; TLS and same-origin redirects remain mandatory. Downloads are
checked against the original grant and 300 seconds, with
at most two transient idempotent retries. Production DNS/connect/redirect/body
work is contained in the joined fixed-code child described above; its body
uses `read1` calls with at most 0.5 seconds of socket blocking. A latched
observer rejects negative, nonfinite or backward clock samples across
acquisition, retry delays, response checks and the parent supervision loop.
Each fresh transport attempt and accepted response also rechecks
the original live broker authority and owned facts, without re-entering the
one-use permit or extending its deadline. Those live checks hold the original
broker lock. Managed staging enters the broker before taking its single owned
root lock, then revalidates the typed live snapshot, revision and evidence under
that lock before any staging write. Completion releases its metadata-read lock
before broker CAS: a concurrent revision becomes a safe conflict, never nested
acquisition of a potentially non-reentrant OS root lock. A per-read timeout abandons that
response; only a fresh bounded acquisition can retry it. Whole-transport
preemption terminates the exact owned child rather than abandoning a
platform resolver thread.
Trust/digest failures do not downgrade/retry. Returned bytes
do not grant extraction/staging. `_composition.py` now carries those bytes to
the admitted managed handler for the exact ordered selected archive closure;
the original interpreter/package/controller installation scope remains missing.

Both helpers pair `install.step` and `netops.install.step.count` with safe
context, bounded label names and nonthrowing sinks. IDs are log context, never
counter labels; generic service failures use `Unhandled`. No raw exception,
source URL, artifact content or private value is emitted.

The root scripts now invoke the registered `netops.setup.main` host rather than
an independent restricted pip bootstrap. The host displays the selected registry
plan, validates complete pinned local closure before creation, requires typed
creation and original private lifecycle confirmations, and invokes real managed
provision/resume/update/restore/uninstall dispatch. Unknown roots are not adopted.
No source descriptor, CLI flag or emitted receipt confers authority/qualification.
Missing production locks still block, and actual Q03 qualification is absent.

Author regression files are `tests/test_i02_author_lifecycle.py`,
`tests/test_i02_author_assets.py` and `tests/test_i02_author_bootstrap.py`.
They exercise the actual private broker/owned file handlers with fake effects
and the actual source lock validator, not real platform qualification. Private
implementation helpers declare an empty public surface. The dependency package,
service and local probe adapter are registered and included in the complete
census alongside the corrective S02 operations.

The correlated uninstall receipt controls in
`tests/test_nov20_policy_completion_author.py` first assert successful
download/stage/verify steps for their inactive generation. Their inert
provision outcome is truthfully `partial` with `review-activation-plan`
pending and an absent active pointer, not installed-runtime readiness.
Full safe provision diagnostics distinguish a failed positive prerequisite
from the later receipt mutation. The original remaining-resource, pointer,
pin, ownership, poststate, correlation and incomplete-result negative checks
remain unchanged; these controls do not qualify platform protection.

### Corrective managed staging and restart selection

`_recovery.py` persists non-authoritative selected scope/context, all consuming
identity digests, exact generation binding and baseline report digest through
the accepted protected owned port and root lock. Creation never adopts an
existing unknown record; resume advances only a re-read exact prior selection.
Fresh-service resume no longer needs the old `_plans`/`_contexts` dictionaries.
Changed probe/context facts revoke the new presented consent and return a
replan/reconsent requirement before handler/recovery writes. The managed public
path can now replan/review from a fresh service and revalidate the exact stored
context before dispatch. `OutcomeStore` writes immutable safe full outcomes and
a digest-linked CAS head, preserving original errors across fresh-service
resume. Interrupted multi-record recovery/reconciliation remains missing.
Retained planning validates exact stored scope/generation and functional
verification identity without executing the active installation; inert
verification cannot qualify a retained controller.

`_managed.py` is a distinct product-tree staging contract, not an inert schema
alias. Its manifest binds every regular file, byte digest, size, executable bit,
archive lock and selected context. Archive parsing is bounded and fail-closed;
PAX/GNU extensions, links/devices, encrypted entries, alternate names, extra
members and unsafe modes never reach storage. The concrete file port pins the
protected root and all directory handles, uses exclusive no-follow writes and
atomic no-replace generation publication, and reinspects exact content and
membership. Unknown resources are never swept. A failed private staging tree is
retained evidence and is not automatically adopted on retry.

`ManagedGenerationHandler` consumes only the real broker's exact stage permit,
requires that broker's same owned-state root and distinct managed schema, and
persists staging/staged states through root-locked CAS. Factual completion is
separate and cannot be reconstructed from its manifest. Its paired stage
observations use `install.step` / `netops.install.step.count`; sink failure is
non-authoritative. The public service now selects `ManagedLifecycleState` for
this distinct managed schema, and retains the old A02 host only as inert
compatibility. The connected acquisition/staging/verification/activation
milestone does not imply actual interpreter/package/collection/runtime
provisioning or full I02 completion.

### Actual public managed composition

`_composition.py` is an effect coordinator over constructor-supplied ports,
not another policy engine. `compose()` uses the same complete registry closure
as I01; it never drops unsupported selected dependencies. It reads only already
owned immutable manifest/control metadata and returns explicit blockers for
disabled setup, missing pins, incompatible context, unsupported assets or
interrupted staging. No archive locator becomes a trusted lock. The initial
native-only plan admits download/stage/verify; factual verification permits a
fresh separately reviewed probe/activate plan.
`ManagedArchive` contributions must flatten to the exact manifest membership and
ordered selected registry assets. Each download retains its own original permit;
the staged tree is inspected and published once, without treating extracted
bytes as a working interpreter/package installation.

The runner invokes the actual pure reducer over factual events/checkpoints.
The first genuine reducer intent is expanded to the exact reviewed aggregate
effect descriptors only to satisfy the existing private broker's whole-plan
grant contract. This compatibility bridge is not a forecast of successful
future events: each actual effect must match the next actual reducer intent
and receive/enter its own original private one-use permit. Immutable event
records are create-only under `dependency-lifecycle-event-*`; the distinct
`dependency-policy-*` head uses revision CAS. Neither contains a live receipt,
session or permit.

Managed staging and activation share the original owned root and broker.
The admitted activation probe performs actual selected-context and functional
checks. Its CAS guards that live proof with full file/owner/membership
verification under the same root lock. Thread-local nested lock depth avoids
reacquiring a non-reentrant OS lock within that same operation. Failed/revoked
admission never invents completion. Cancellation and errors preserve actual
pointer facts; no automatic reverse CAS or unknown-tree cleanup occurs.

The canonical reducer now correlates factual `Activated` to its pending
selected effect, consumes the receipt and checks factual completion counters.
Actual selected `DependencyObserved` facts are part of this chain; every
selected tier must be ready, while unselected tiers remain `not-requested`.
The schema enum bridge and generated bundle/corpus change with the PX sources;
old qualification/plan policy identities do not transfer automatically.

`_restore.py` integrates the retained product path over the same private broker,
root and pointer. Host-supplied `ManagedQualification` descriptors are immutable
root facts bound to generation/scope/context/report/qualification digests, never
generated by this coordinator. Metadata-only planning cannot run a broken active
interpreter. Exact reviewed target/current pins are mandatory. Restore stops
admission, drains outside broker/root locks (retaining approved recovery), and
rechecks release-only pin changes, files/context, consent/deadline and pointer
under the original lock before one CAS. Postcheck failure or late cancellation
keeps admission off and reports actual pointer truth, without implicit rollback.
Factual CAS completion precedes postcheck; admission reopens only after a live
successful postcheck. Generic unexpected failures use paired `Unhandled`
observations with safe, nonthrowing sinks.

Production run-pin ownership/operational bridging, installed interpreter/wheel/
collection/runtime effects, long-lived qualification refresh, complete crash
reconciliation, managed uninstall and protected bootstrap/Q03 evidence remain
mandatory and unresolved, not waived.
The dedicated `tests/test_i02_public_flow.py` exercises actual public
plan/review/provision and fresh-service resume with fake effects and protected
owned record encoding. It is not platform or installation qualification.

The exact S02 delta now registers controller/control host imports as native
SSH/vault/YAML consumers; the process bridge includes native imports plus
controller Ansible/transport/platform prerequisites. The protocol is genuinely
stdlib-only. The ActionBase export requires controller Ansible and native-engine
dependencies in that consuming interpreter. The strict public AST census is
unchanged. Catalog/consumer edges are not platform/support qualification.

The protected-storage helper `netops.ansible.artifact_cleanup` is registered
with its exact public exports (`cleanup_errors`, `StorageCleanupError`,
`teardown`, `release_all`), `native.stdlib` capability, native tier and no
external dependencies or optional intents. The strict public-source manifest
guard includes it; cleanup framing does not imply platform qualification.
The generated dependency catalog retains its dependency entries and consumer
edges; its registry/manifest digest changes with the newly registered module.

### Opt-in offline installed generations

The protected managed stage port now accepts an immutable installation
descriptor in addition to exact archive members. An absent descriptor retains
the legacy manifest's canonical JSON and digest. The supported immutable JSON
mapping representation binds a present descriptor into the same root, plan and
generation checks; per-archive validation still operates on each contribution
before the complete installed closure is selected.

The installer pins an existing regular interpreter by SHA-256, exact version
and platform, creates a new generation-owned venv with copies (never `--clear`),
and installs an exact wheel closure using offline, no-cache, hash-required pip
with dependency resolution disabled. `pip check`, exact installed distribution
closure, installed package origin and real CLI invocations must succeed.
Controller descriptors additionally consume actual Ansible/Molecule entry
points, ActionBase import and registered pinned collection archives through
offline Galaxy. Collection metadata, links, expansion and dependency closure
are checked before invocation. These source paths are not platform proof.

`installation-<generation-id digest>` is stable before consuming-context
binding; it is not derived from a recursively dependent manifest digest.
`netops-installation.json` records exact owned file/directory membership and
hashes. Verification checks the tree both before and after consuming probes.
The admitted lifecycle retains an immutable `dependency-installation-...`
owned receipt before pointer CAS. Only an explicit clean CAS conflict followed
by exact receipt equality permits an idempotent receipt retry; corruption,
ownership and cleanup failures are not treated as absence.

The factual staged-generation record also pins the generated installed receipt.
Both lifecycle probing and controller binding compare against that admitted
receipt; rewriting a local receipt to describe a changed tree is not evidence
of the original installed generation.

Child commands are fixed, shell-free, deadline/output/cancellation bounded and
use owned temporary paths. Windows starts suspended and assigns a private
kill-on-close Job before resume; POSIX retains its unreaped leader until group
termination. Output readers are joined, including explicit-stop failure paths.
New Windows directories inherit a newly created owner-only tree; no existing
ACL is repaired. Partial environments and unknown files remain retained.

Verified native executable/library descriptors copy exact pinned members into
owned `tools/`/`libraries/` and run only fixed allowlisted commands/symbol probes.
Windows installed-tree inspection uses a bounded joined worker pool with the same
per-member protections, hashes and original deadline. Final install pointer CAS
rechecks every protected archive and installed member against the exact staged
receipt under the protected root lock. It consumes neither the interpreter nor
the functional probes a second time: the admitted probe already established
the live report, which must still match the exact plan-bound report digest and
consuming contexts. The original evidence expiry and private consent deadline
are checked both before and after the full-tree guard; no cache metadata,
directory spelling, restored receipt or historical root grants readiness.
Ordinary full verification continues to inspect the installed tree before and
after interpreter consumption. Separately qualified restore retains its own
functional re-probe. Source controls and native author receipts are not Q03.
For an actual installed candidate, the host retains one completed live
functional observation per generation, keyed by the exact published verification
object with its original expiry, report and admitted installed receipt. The
separately consented activation probe can reuse that observation only while
rehashing every protected byte under the root lock. It does not renew evidence,
reconstruct consent or infer a live proof from a durable receipt. A fresh host
has no such observation: planning selects a separately consented actual
`dependency-verify`, then replans and asks for new exact activation consent after
that proof completes. Neither the planner nor read-only preview runs a probe or
writes this cache. This removes both redundant interpreter consumptions from
the old sixty-second window rather than extending the window.
Every lifecycle snapshot still re-reads the protected owned root/control bytes
and checks ownership, policy, descriptor, generation, pointer and staged state.
Its already validated immutable generation objects are reused rather than
rebuilding the complete installed inventory through the public JSON validator
on every snapshot. Only immutable decoding is reused: a changed owned record
is re-read/validated and still changes the snapshot; this is not a cached
root/path/permission proof, TTL, source adoption or skipped file verification.

`OwnedGenerationRuns` is an explicitly registered public host bridge. Durable
pins and admission changes share the same owned root/CAS as pointer writers.
Private cancel/join callbacks run outside root/broker locks. Unknown sibling or
crash-held pins block rather than expiring. Consuming workflow integration still
requires that host to acquire/release the exact generation around real runs.
Admission and reopening use one full typed present-pointer predicate, including
kind, exact int53 revision and the digest of the complete selected generation
binding plus that pointer revision. A same-UUID foreign digest rejects before
holder mutation. The normal owner may complete while drain is joining: its
successful durable release and private release revision are recorded atomically
under the same root lock and host mutex. Drain recognizes only that exact
snapshotted host-owned pin's successful release and checks that its durable
holder remains absent. Direct duplicate release still rejects. Missing holders,
failed joins, arbitrary callback/storage errors, sibling holders and crash
holders are never swept or reclassified as successful completion.

Managed inactive uninstall uses original one-use broker/reducer admission and
exact pinned generation membership. It checks all selected trees before deletion,
retains unknown/changed/link members, uses handle-based Windows removal, and
persists removed/remaining references independently of primary and cleanup errors.
Active removal requires a separately qualified retained-pointer restoration and
is blocked by this source host rather than inventing an absent-pointer transition.
Installed data uses a centralized literal-name grammar: verified wheels may
contain interior ASCII spaces (for example `Lorem ipsum.txt`), but traversal,
streams, separators, trailing dot/space and normalized DOS aliases remain rejected.
The same predicate applies while publishing installed receipts and removing their
exact members. Archive acquisition keeps its original stricter member grammar;
no native path/ACL/reparse/handle guard is relaxed.

Terminal inactive uninstall now records the actual correlated `StepCompleted`
from its factual `Admitted` phase. Canonical success and terminal reduction require
verified poststate/ownership/expected pointer; the real removal handler rechecks
absence of all selected tree roots and unchanged pointer/empty selected pins
under the original lock before receipt completion. Residual references, changed
pointer/pins, stale invocation/effect/revision or replay cannot report success.
Durable removal/errors and reconciliation remain separate from policy history.

The source setup import closure is now stdlib-safe: operational plan binding
defers its YAML hydrator import. An isolated no-site source invocation reaches
the real full registry and reports missing complete pins before any root write,
without assuming an installed toolkit or PyYAML. This does not provide missing
full production locks or qualify a real complete installation.

**Still incomplete:** production full closure locks, full clean installation
of every selected prerequisite, qualified POSIX/existing WSL controller binding,
runtime/image/service/OS consequential drivers, full multiwriter crash
reconciliation and consuming run-pin integration. Actual native Windows author
publication/installation is not Ansible, POSIX/WSL, B02 or Q03 qualification.
The native activation correction avoids duplicate interpreter consumption at
CAS while retaining full protected-byte guards and original freshness. Genuine
current-source public install/resume evidence remains an independent obligation;
no timeout/freshness guard is relaxed. Parent observations remain;
fine-grained new installer I/O telemetry is not claimed complete.

The unchanged strict AST census also registers the pure
`netops.report.companion.project_outcome` projection as stdlib-only, and the
native report generator's `main` and consuming `probe_pdf` exports. PDF probing
requires the existing `native-pdf-libraries` dependency; that registration is
not installation or PDF readiness evidence.

Package-data declarations now include the existing role YAML/Molecule assets
and report Jinja templates in wheels and sdists. Their exact source bytes must
match the built distribution. Historical local policy checkpoint copies are
not product assets and must not be included as packaged policy.
