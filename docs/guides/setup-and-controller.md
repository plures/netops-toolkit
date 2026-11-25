# Dependency setup and controller guide

Use this guide to inspect prerequisites, request guided user-local setup, and
recover an owned installation. It describes the interfaces present in the
source, **not a certification that a complete installation is qualified**.
Native operations remain independent of explicitly selected Ansible companions;
Molecule is an additional enhanced tier, not a replacement controller.

## What is available, and what is not yet qualified

The packaged registry describes dependencies, consuming contexts, sources,
ownership and recovery. Setup defaults to the full native/companion scope;
`--enhanced` additionally selects enhanced dependencies. An incomplete selected
scope is not a successful full installation. Narrowing scope is an explicit
operator choice, not a way to declare the original full request complete.

The current packaged `publisher-catalogue.json` has no retained release,
Python-file, publisher or official-profile records. `qualification.json` has
no qualified tuples. Consequently, starting guided setup is supported as an
interface, but does not establish that its selected installation can complete.
Ansible/enhanced readiness remains blocked even when individual dependency
probes pass. Actual platform, controller, both Molecule-tier, PDF and installed
wheel/sdist evidence remains outstanding. Do not treat this guide as release
readiness or universal platform support.

## 1. Start with a plan

Use an existing compatible Python and a reviewed local source tree. Toolkit
Python has a registry baseline of 3.9 or newer; controller Python has a separate
baseline of 3.10 or newer. These are minimum dependency constraints, not proof
that every combination is compatible.

Choose a dedicated absolute user-owned root, not your home directory,
filesystem root, project data directory or an unrelated existing installation.
Keep inventory, vaults, backups and settings outside it. Do not put credentials
in arguments or setup descriptors.

From the reviewed source directory on Linux/macOS:

```bash
bash ./install.sh plan --root "$HOME/.local/share/netops-toolkit"
```

From that directory in PowerShell on Windows:

```powershell
pwsh -NoProfile -File .\install.ps1 -Action plan -InstallRoot "$env:LOCALAPPDATA\netops-toolkit"
```

The scripts select an **existing** interpreter; they do not acquire one.
For an explicit selection, Linux/macOS accepts the `NETOPS_PYTHON` environment
variable, and PowerShell accepts `-Python` with the interpreter path.

When the toolkit is already importable in your selected Python, the common
entry point is:

```text
python -B -m netops.setup plan --root "<absolute-dedicated-owned-root>"
```

Replace angle-bracket placeholders; do not enter them literally. On systems
where the selected executable is named `python3`, use that name instead.
There is **no `netops setup install` command** in the unified `netops` dispatcher.
The source wrappers and `python -m netops.setup` call `netops.setup.main`.

`plan` does not run functional probes, request consent, download assets or
write installation state. It describes scope, dependency closure, sources,
destinations, reuse requirements, effects and separate grants. With no resolved
candidate it also emits a `Planned` guided report and selection checkpoint,
and returns **3**, not a false complete-installation success. Planning is not
verification.

### Select a scope deliberately

The default includes native and companion operations, but not enhanced ones.
These are real optional selectors:

| Setup arguments | Meaning |
| --- | --- |
| No selection flags | Full native/companion dependency scope |
| `--enhanced` | Add enhanced scope, including registered Molecule/runtime/image prerequisites |
| `--capability native.scan` | Explicitly restrict to that native capability and its dependency closure |
| `--companion companion.ansible` | Explicitly select the Ansible companion closure |

`--capability` and `--companion` can be repeated. Supplying either disables
the default full selection. PowerShell equivalents are `-Capability`,
`-Companion` and `-Enhanced`. Inspect the current registry rather than assuming
that installing a pip extra supplies executables, Galaxy collections, native
libraries, a runtime or a qualified controller.

## 2. Review guided discovery before consenting to effects

**The following action is interactive and potentially consequential.** Unlike
`plan`, `install` runs bounded consuming-context probes and, when retained
publisher inputs are available, may read official metadata. An installation
request is not a promise of an offline session.

```text
python -B -m netops.setup install --root "<absolute-dedicated-owned-root>"
```

The source-wrapper equivalents are the earlier commands with `plan` replaced
by `install` (or `-Action install`). There is no blanket `--yes` flag.

For each dependency, guided discovery displays observations and offers
`reuse`, `install` or `decline` as applicable. A compatible observed dependency
defaults to reuse; an unavailable one defaults to decline. Reuse requires
current evidence in the **consuming** interpreter/context, not a successful
import elsewhere on the workstation. Declining a dependency leaves it, and
dependent selected components, unresolved; setup does not silently omit them.

Choosing `install` or requesting consequential-category `review` only records
intent. Separate exact reviews are required for root initialization,
installation and activation, plus applicable elevation, OS/WSL/distribution,
VM/virtualization, runtime, service, security or reboot effects. Read the
displayed root, candidate, plan digest, effect list and time budget before
answering any confirmation. Never script copied consent strings.
Installer consent does **not** authorize network-device apply or rollback.

If setup returns `NeedsInput`, inspect `needs` entries (`reason`, `fields`,
`choices`) and any `planning_failure`. The report includes a `checkpoint` and
`next_command`. That command restores selections and rechecks evidence; it is
an `install` request, not another pure plan. Review it before running it.
The equivalent explicit continuation is:

```text
python -B -m netops.setup install --root "<same-root>" --checkpoint "<returned-checkpoint>"
```

Retain the same scope flags used to produce the checkpoint. A changed
root/scope/registry/context invalidates its binding. A checkpoint is neither
effect consent nor an installed-generation recovery record.
`--checkpoint` cannot be combined with `--plan-file`.

`--plan-file "<reviewed-local-descriptor>"` remains an optional legacy pinned
metadata route, not a first-run prerequisite. It is not arbitrary shell code,
a trusted-source override or a way to manufacture publisher evidence.
Missing exact source pins, original source authority, compatible interpreter
evidence or verified asset closure must remain actionable non-success.
Do not fill these gaps with invented hashes, versions or qualification flags.

The source wrappers additionally request a strict local documentation build
after successful `install`/`update`. That bridge has its own output-root review
before writes. A later documentation-build failure does not prove that earlier
installation steps had no effects: inspect the setup result before retrying.
Direct `python -m netops.setup` does not invoke that extra wrapper step.

## 3. Read readiness in the correct context

For an already registered protected installation:

```text
python -B -m netops.setup verify --root "<existing-owned-root>"
```

This performs bounded functional probes; it is not the no-probe plan command.
An uninitialized root instead needs first-run diagnosis and metadata.
The service checks the selected Python, packages, executables, collection
search paths and applicable native libraries. PDF probing attempts an in-memory
render with remote fetching denied. The local adapter does not start a runtime
or daemon to turn a runtime check into success.

| Observation/result | How to act |
| --- | --- |
| Probe `available` | A bounded functional observation, not platform qualification or install consent |
| Probe `missing` or `version-mismatch` | Review the exact prerequisite in the selected interpreter; replan |
| Probe `unsupported` / `platform-unsupported` | Select a genuinely qualified context; do not relabel the platform |
| `context-missing`, `context-unavailable`, `controller-drift` | Correct the selected context through its owning host; local probing cannot impersonate a foreign controller |
| `platform-grant-unverified`, `asset-lock-required`, `runtime-functional-proof-required` | Required independent proof is absent; a grant label, directory or executable alone is insufficient |
| `deadline-exceeded` | Request a fresh bounded observation, not reuse of an expired result |
| Tier `not-requested` | That tier was not selected; it is not a successful verification |
| Tier `blocked` | Selected prerequisites, policy or qualification are incomplete; consult capability `missing`, `probes` and `next_action` |

Read `native`, `companion` and `enhanced` separately. Native can be ready while
companion/enhanced is blocked. In the current service, non-native capabilities
remain `unqualified`/`blocked` even with no missing probes; the next action is
`collect-exact-tuple-evidence`. Do not bypass that result or interpret the
presence of an official source profile as an installed dependency.

Setup's normal return values are **0** for its completed selected action,
**3** for incomplete/blocked setup and handled setup errors, and **130** for
keyboard cancellation; argument-parser errors use argparse's exit behavior.
These are setup-host semantics, not a claim that every workflow command has
the same exit mapping.

## 4. Choose a controller without changing native defaults

| Host/controller choice | Boundary |
| --- | --- |
| Linux/macOS managed controller | Separate compatible user-local controller interpreter and collections; exact installed tuple still needs qualification |
| Windows with an existing WSL controller | Only an explicitly selected, qualified distribution/interpreter and credential/transport route; existence is not adoption or qualification |
| Windows needing WSL/OS/runtime setup | Requires separately reviewed consequential steps; no automatic WSL discovery, installation, registration or service start |
| Native Windows Ansible | Not a supported controller layout; native toolkit operations are separate |
| Container scenarios | Optional Molecule targets, not replacement controllers; runtime/image/driver prerequisites and opt-in consent remain separate |

The launcher interface is `ControllerLauncher.verify(context: ControllerContext)`.
It asks its supplied process verifier to revalidate the owned installation and
exact qualification. A matching `ControllerInstallation` is required; failure
returns dependency-not-ready with guidance to qualify the exact owned installed
controller tuple. Constructing that dataclass or copying a digest is not
qualification. There is no user-facing setup flag that turns it into proof.

Qualification binds OS/architecture, native/controller Python, Ansible,
Molecule, collections/assets, runtime/image, PDF, credential route and policy
identity. A passing package import, a successful metadata response or a mock
scenario does not establish those facts. Windows-to-WSL credentials, bastion
and key paths need their own real proof; do not substitute plaintext
argv/environment files or direct-route fallbacks.

### Official publisher profiles are metadata support, not a support matrix

The source contains closed profiles for Ubuntu packages, Homebrew, MSYS2,
Git for Windows, Podman, Fedora minimal images and Ubuntu cloud images.
They bind specific official metadata/artifact scopes and independently retained
pins; they are not permission to install from arbitrary URLs.

Ubuntu/Homebrew/MSYS2 package profiles describe platform prerequisites;
Git/Podman profiles describe exact project releases/assets; the Fedora profile
describes a manifest plus complete blob closure. These declarations do not
qualify a host/controller/guest layout, licensing/integrity evidence, runtime
dispatch or PDF rendering on that platform. With the current empty catalogue
and qualification set, do not claim these profiles make all those platforms
installable or supported. No global pip mutation, automatic network install,
automatic WSL setup or implicit host security change follows from a profile.

## 5. Update, resume, restore and uninstall owned generations

**These are potentially effectful actions, not previews.** Use only the exact
root and IDs reported by your installation. Preserve failure output and owned
metadata; do not delete, edit, unlock or adopt unknown resources to force
progress.

| Action and real command | Required interpretation |
| --- | --- |
| `python -B -m netops.setup update --root "<existing-owned-root>"` | Review a new candidate or exact interrupted registration. A different candidate may need its reviewed `--plan-file`; the command does not mean “download latest without review.” |
| `python -B -m netops.setup resume --root "<existing-owned-root>" --installation-id "<reported-installation-uuid>"` | Resume the retained installation with fresh review/probes. Omit the ID only to use the host's stored installation ID. |
| `python -B -m netops.setup restore --root "<existing-owned-root>" --generation-id "<retained-generation-uuid>"` | Review switching the owned active pointer to that qualified retained generation. This does not reinstall packages or undo device changes. |
| `python -B -m netops.setup uninstall --root "<existing-owned-root>" --generation-id "<inactive-generation-uuid>"` | Review removal of that inactive manifest-owned generation only. Active-generation removal is blocked; qualified restore must precede it. |

Both source wrappers accept the same actions. PowerShell maps the two IDs to
`-InstallationId` and `-GenerationId`, and a descriptor to `-PlanFile`.
No general-purpose source-root deletion or WSL-distribution removal command is
implied.

Staging and activation have separate plans/reviews. If an outcome requests
`review-activation-plan`, the setup host replans and requests new activation
consent. A staged candidate, successful cleanup or partially successful install
is not an active, ready generation.

Inspect `status`, selected scope, individual step `status`/`changed`,
`candidate_generation_id`, `active_generation_id`, `previous_generation_id`,
`pointer_revision`, `pending_actions`, `original_errors`, `errors`,
`cleanup_errors` and `uncertain`. Preserve the original failure even when
cleanup succeeds. Resume never reconstructs an expired one-use grant.
Generation pins protect active work; a crash-held pin is not automatically
expired or permission to steal a lock.

Unknown/corrupt ownership blocks changes. An unsupported known-root migration
offers preserve-root, choose a new empty user-owned root and replan, or cancel;
it does not authorize an in-place repair. Observation-setting mismatches on an
existing root similarly require retaining that setting or replanning with a
new root, not rewriting the old record. Retain prior known-good generations
and user inventory/vault/backups/settings/unknown files. Uninstall and restore
are bounded owned-resource operations, not a general system uninstaller or
automatic recovery guarantee.

For source-owned generations, later actions still need the same live qualified
producer and protected original ledger when requested; retained JSON is not a
replacement. `qualified-bootstrap-producer-required` means stop and supply
that original configured producer through its owning host, or cancel.
The native bootstrap contribution covers only `native.stdlib`; composing it
with publisher metadata does not turn local build bytes into official
publisher assets or qualify the future full toolkit/controller generation.

## Python integration and frontend limits

Read the current prerequisite authority without loading optional workflow
modules:

```python
from netops.dependencies import DependencyRegistry
from netops.ansible.contracts import InstallScope

registry = DependencyRegistry.load()
catalog_markdown = registry.documentation()
operations = registry.operations
full_scope = InstallScope(
    native_capabilities=(), companions=(), enhanced=False, full_toolkit=True,
)
```

For the same interactive setup host from an already importable installation:

```python
from netops.setup import main

exit_code = main(["plan", "--root", "/absolute/dedicated/user-owned-root"])
```

Use a Windows absolute path on Windows. Changing `"plan"` to an effectful action
has the same consent and possible I/O boundaries as the CLI.
`main(argv=None, *, metadata=None)` optionally accepts `SetupMetadata` from a
trusted owning host. Its `publishers(...)`/`compose(...)` interfaces retain
typed publisher/native producer contributions; ordinary JSON and a claimed
`trusted` flag cannot substitute for them.

For an embedding host, the public service constructor is
`DependencyService(registry, adapters, state, policy, authorization, clock, events)`.
It requires real owning state, policy, authorization and consuming-context ports;
there is no zero-argument install service. Given that host-supplied service and
typed `InstallContext`:

| Call | Boundary |
| --- | --- |
| `service.catalog()` | Metadata only, no probes |
| `service.plan(scope, context)` | Descriptive/public install plan; no effect grant |
| `service.verify(scope, context)` | Functional probes and separate readiness tiers |
| `service.review(plan, now, lifetime)` | Host's exact private one-use **install-plan** review |
| `service.provision(plan, consent, cancel)` | Execute only an admitted current executable plan |
| `service.resume(install_id, consent, cancel)` | Fresh consent/current context, not replayed checkpoint authority |
| `service.plan_restore(generation_id, context)` | Read-only retained-generation pointer planning, including bounded checks |
| `service.restore(plan, consent, cancel)` | Exact reviewed pointer restore |
| `service.plan_uninstall(generation_id, context)` | Exact inactive owned-generation removal plan |
| `service.uninstall(plan, consent)` | Admitted owned removal |

`now` is the host's monotonic clock value; `lifetime` is a bounded grant lifetime,
not an override for expired evidence. Do not pass a restore/uninstall plan to
`service.review`: it accepts the public install plan, not those distinct plan
types. Restore/uninstall require their host-owned lifecycle consent adapter;
use the interactive setup actions unless your embedding supplies that adapter.

The unified CLI and existing Textual interface do **not** currently expose a
complete setup/controller installation wizard with parity to this host/API.
Use these actual setup routes, not invented menu items or `netops setup`
subcommands. Full CLI/Textual/Python companion parity and authentic runtime
qualification remain required work, not accepted scope deferrals.

See the [dependency API and generated catalog](../api/dependencies.md),
[Ansible API](../api/ansible.md), and
[CLI reference](cli-reference.md) for adjacent interfaces.
