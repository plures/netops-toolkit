#  Protected artifacts and owned state (C02)

This is the bounded C02 storage increment, not acceptance of the full Ansible
feature. Import from `netops.ansible.artifacts`; package initialization and C01
contracts remain unchanged.

## Interfaces and authority

`ArtifactStore(filesystem, clock, events)` implements the frozen
`publish(OutputIntent, bytes, ArtifactBinding) -> ArtifactDescriptor`,
`read(descriptor, binding) -> bytes` and
`cleanup(Sequence[OwnedResource]) -> CleanupOutcome` methods. The injected
`ProtectedFilesystemPort` retains exactly `validate`, `publish` and `read`.

The effect binding is **not authorization**. The caller must obtain admission
for the exact output effect and independently consent to sensitive retention.
This synchronous API adds no permit, background work, cancellation token or
authority reconstructed from a receipt. Cancel before calling it; reconcile a
completed atomic publication if cancellation arrives after commit.

`LocalProtectedFilesystem.validate` selects an **existing**, explicitly named,
absolute protected directory. It does not create user roots, adopt unknown
state, repair permissions, consult `NETOPS_STATE_ROOT`, or execute processes.
`selected_state_root(explicit_selection)` computes an absolute selected path or
the platform default without opening it. Environment overrides must first be
explicitly selected by the composition owner. Host and WSL processes resolve
their own roots independently.

## Publication and cleanup

POSIX storage opens every ancestor without following symlinks, verifies the root
inode/device and owner, and requires directories `0700` and regular single-link
files `0600`. On macOS, each protected handle must additionally have a valid,
empty extended ACL; inherited or explicit ACL entries are rejected, not removed.
Native Windows storage pins every no-reparse ancestor with handles denying delete
sharing. It inspects the actual handle owner SID, protected non-null DACL, owner-only
allow ACEs with full control, object type, reparse attributes and file link count.
New files/directories receive a protected owner-only security descriptor **at
creation**, with handle-based proof before writing sensitive bytes. It never
changes ACLs on an existing user object. Rename and deletion operate on verified
native handles. Windows `FILE_RENAME_INFO` uses a NULL root handle and an exact
absolute UTF-16 destination while the destination parent and all ancestors remain
pinned against rename/delete. Relative names with a non-NULL root handle produce
native error 87 on this API; the correction does not loosen ownership or sharing.

Content and a bound receipt are staged in a private immutable generation, flushed,
then renamed in the same root. A separate canonical `publication-<binding>.json`
pointer commits the selected generation atomically. POSIX no-replace commits use
Linux `renameat2(RENAME_NOREPLACE)` or Darwin `renameatx_np(RENAME_EXCL)` rather
than a check-then-overwriting rename; unavailable primitives fail publication.
The descriptor is returned only after reopening the receipt and verifying exact
bytes, size, media type and digest. Crash-left staging or generations not named by
a successfully committed pointer are not silently adopted or purged.

Output names derive from the complete nonsecret binding, not device-provided
path text. `overwrite="reject"` preserves an existing publication.
`overwrite="replace"` first validates the exact existing canonical pointer,
binding, receipt, protected content and ownership. It commits a fresh immutable
generation by replacing only that pointer, retaining the previous generation and
its readable descriptor. A failed pointer commit preserves the previous pointer;
it can leave owned orphan staging/generations for explicit reconciliation.
Corrupt or unknown pointers are not replaced.

`git=True` writes a complete private bare Git snapshot under the new generation's
`git` directory, with blobs for the exact content and receipt, a tree, a commit
and local `artifacts` branch. Loose objects use Git's SHA-1 object identifiers;
artifact content identities remain SHA-256. Every object is created through the
same protected writer before the publication pointer can commit. Git encoding,
write or verification failures are non-success, never a downgrade to non-Git
output. No existing repository, index, hooks, user configuration, remote or
process is used. Each retained artifact has its own snapshot repository; this
is not an API for committing arbitrary user repositories or a cross-operation
backup-history service.

Ordinary output accepts UTF-8 data and rejects supported credential statements,
structured credential fields, persisted authority aliases and secret hashes
under known key spellings **before hashing or I/O**. This is rejection, not
redaction or certification of arbitrary encodings. Explicit `pdf` publication
also preserves binary PDF bytes: it checks the PDF envelope and scans binary-safe
text and bounded Flate-expanded streams for supported credential statements.
This is not a PDF renderer, complete PDF parser or proof of arbitrary encoded
content being credential-free. Trusted, credential-minimized rendering and
deny-network report-resource policy remain the report owner's responsibility.
Sensitive data preserves exact bytes and requires explicit retention; it is not
routed through public content validation.

Cleanup requires an exact `OwnedResource` with `explicit_cleanup=True`.
It verifies the manifest, binding, content and protected root, never recursively
deletes unknown children, never deletes lock files, and never diagnostic-purges
sensitive artifacts. Unknown resources and user inventory/vault/backups/settings
are not enumerated. Cleanup failures are separate `CleanupOutcome.errors` and
`remaining_refs`; the caller retains its original failure and remote uncertainty.
Cleanup validates generated Git members against exact expected object bytes
before removing them, and preserves unknown members. Removing an older retained
generation never removes a newer publication pointer. Failed staging cleanup
adds safe secondary `ArtifactError.cleanup_errors` without hiding the original
failure or cancellation.

## Owned v1 metadata and locks

A02's optional `OwnedPolicyJournal(..., occurrence_id=...)` uses a hashed
per-occurrence checkpoint resource under the same operation. The complete plan
binding remains unchanged, and each such journal requires exactly one disposition
whose effect ID matches that occurrence. The default constructor retains the
existing whole-operation resource. Operational policy facts containing the
nonsecret `credentials.channel_qualified` flag are stored as group/leaf pairs
and revalidated by the real reducer on replay, without allowing public
credential objects. This is factual history, never stored admission authority.

`OwnedState(root, ownership_token)` implements `OwnedStatePort`:

* `read(resource_id) -> OwnedRecord`;
* `compare_replace(resource_id, expected_revision, record) -> OwnedRecord`;

Missing optional metadata under a successfully verified root is
`FileNotFoundError`; missing/unowned roots still fail safe ownership validation.
Native numeric diagnostics remain internal, without native text/path exposure.
Atomic replacement now carries a bounded private primary diagnostic through its
sanitized `ArtifactError`, preserving native/errno codes, fixed operation/stage
and hashed owned-resource correlation. The existing public error category and
reason are unchanged; `detail` may reference `storage-diagnostic:<sha256>`.
Cleanup retains separate safe references and never replaces an active primary.
Logs/metrics expose only fixed dimensions and hashed log-only correlation, not
paths, exception text or record bytes. A code is an observation, not permission
to retry, relax delete sharing, modify ACLs or attribute a failure to AV.
Immutable decoded records may be reused only after rereading identical protected
bytes with live path/ACL/root checks; changed bytes are fully validated again.
This bounded decode cache grants no authority, skips no read and has no TTL.
* `lock(resource_ids, timeout) -> OwnedLock`.

`OwnedRecord` is frozen and binds schema `1.0`, kind, resource ID, exact checked
revision/generation, ownership token (excluded from repr), full `PolicyIdentity`,
policy digest, reducer version and immutable nonsecret payload. The digest and
reducer must match that identity. Tokens, grants, sessions, permits and private
credential values cannot be serialized as checkpoint payloads.

The supported paths are `active.json`, `operations/<UUID>/outcome.json`,
`installs/<id>/state.json` and hashed checkpoint IDs. Active payloads bind
environment/content/prior ID and state revision. Operation payloads contain
safe request/plan/outcome/provenance/artifacts, separate primary/cleanup errors,
integrity-bound chunks and an explicit diagnostic TTL in `1..365` days
(composition should select the specified seven-day default). Install payloads
contain a content-digest manifest, plan/controller/registry digests, step states,
original errors, pending actions and previous generation. Metadata is bounded to
1 MiB. Larger payloads must use owned integrity-bound references.

Creation uses expected revision `0` and record revision `0`. Subsequent CAS
requires expected current revision and next revision exactly `current+1`.
Unknown fields/versions, corrupt ownership, invalid counters (including bool,
float and values above int53), stale revision, wrong prior ID and exhausted
revision fail before pointer mutation. Old bytes are retained as `.r<revision>`;
`retained(resource_id, revision)` loads an exact checked restore operand.
Restore is an explicitly planned new CAS, not an automatic selection or switch
of an in-flight generation. Active updates name the actual current environment
as their prior ID. There is no migration, predecessor adoption, transform,
secret dual write, vault change, TTL sweep or automatic active/previous cleanup.

Locks use POSIX `flock` or Windows native byte-range file-handle locks, normalized resource ordering and bounded contention
(`resource-busy`); lock-file age/content never grants ownership. Same-thread
nested acquisition reuses the held OS lock; other threads/processes contend.
Timeouts are finite nonnegative floats. Lock descriptors close on all exits,
without deleting another writer's lock.

## Verification limitations and integration work

The development host is Windows, but this increment is authorized for **offline
fixtures only**. Native Windows and macOS backend code is present; its presence
is not a support or qualification verdict. Real Windows ACL/handle/lock,
Linux/macOS/WSL mode/ACL/mount, cross-process crash/race and durability
qualification remain blocked/unexecuted. All native platform cells require
independent Q03 evidence before sensitive apply; no caller trust boolean grants it.

Unit tests use injected memory I/O, synthetic Win32 API results and synthetic
Darwin ACL results. The actual owner/DACL parser and pre-write enforcement paths
run against those fixtures, without calling native Windows protection APIs.
Legacy native test cells inject unavailable storage on this unqualified host;
those branches are not reported as native protection qualification.
The first local test run exposed an authority-alias persistence defect; a focused
test now rejects it. Further cases cover swapped descriptors, exact sensitive
bytes, malicious members, revisions, restore operands and cancellation before
atomic replacement.

Publication retains C01 `SafeEvent` values and additionally emits paired
`artifact.publish` / `netops.artifact.publish.count` and `cleanup.result` /
`netops.cleanup.result.count` observations from one shared helper. Logs include
safe correlation, category/reason/next action, outcome, duration and bytes;
cleanup uses a digest of selected input bindings when operation IDs are unavailable.
Aggregate dimensions contain only kind/classification/status/category/reason/stage,
never operation/step/target IDs, paths, binding digests, byte counts or durations.
Unexpected execution errors have structured stage `Unhandled`.
`store.observations.counters()` returns detached local totals for an existing
host exporter; no exporter, service or logging configuration is initialized.
Event-sink failure does not hide an existing primary failure or double-count it.

Supported YAML/text credential keys use the same normalization and rejection
domain as C01 structured objects, including camel-case auth/priv password and
passphrase aliases, before hashing or filesystem I/O. C01 remains unchanged.
Pending publication/state-file teardown preserves the original exception
(including cancellation), with independently validated `cleanup_errors`.
Unexpected public-boundary exception conversion retains those safe secondary
errors without copying native exception text.

Logging-handler or aggregate-sink exceptions are contained within the paired
observation helper. A completed effect remains completed; existing failures and
cleanup outcomes remain authoritative. The helper does not retry partially
emitted observations: a successful counter increment is retained exactly once
even when its paired log sink fails. Log delivery is best effort, not an
authorization, publication receipt or reason to repeat an effect.

Windows lock acquisition now receives the selected root's identity-checked
handle, not its path. The root and no-reparse ancestor handles remain pinned
through native lock release; reentrancy is keyed by device/inode and lock name.
Synthetic lifetime/order controls do not establish native Windows qualification.

Shared `docs/api/ansible.md` and `docs/api/core.md` linking is reserved for the
coordinator's integration change; this worker did not edit those owned files.
