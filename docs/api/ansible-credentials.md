# Private companion credentials (S01)

This increment implements the operation-private resolver, not controller/platform
qualification or a new native connection engine. It does not enable companion
execution by itself.

## Interfaces

`netops.ansible.credentials` retains the frozen resolver interface:

```python
ScopedCredentialResolver(vault, routes, clock)
resolver.resolve(scope, session)  # ScopedCredentials, not a credential dictionary
resolver.revoke(operation_id)    # idempotent
```

`RoutePolicyPort.validate(context, scope) -> RouteBinding` is an injected trusted
controller-origin adapter. `CredentialScope` binds the operation, controller and
route identities, exact ordered canonical targets/tasks/fields and host monotonic
expiry. `CredentialTarget.from_device` snapshots inventory identity, vendor,
transport, groups and the native effective port; it does not copy inventory
passwords. Invalid explicit ports are rejected, not turned into defaults.

`UnlockSession(scope, password, admission)` is **host-private composition**, not
a public request or wire DTO. The trusted `CredentialAdmissionPort` must provide:

* `admit(scope)`: a context manager atomically admitting the fixed private
  resolution effect under the current A01 host session/permit.
* `validate(scope)`: a non-consuming context manager holding current host
  authority during private delivery, checking original grant deadline,
  cancellation, controller/route/effect binding and revocation.

Neither a resolver reference, a policy decision, an installer consent boolean
nor a caller-provided implementation of this trusted port is operational
authority. The application composition root must supply the actual A01 adapter.
`netops.ansible.credential_admission.HostCredentialAdmission` now supplies that
adapter:

```python
# Private host composition, not a public request constructor.
admission = HostCredentialAdmission(broker, admission_session, plan, scope, clock)
session = UnlockSession(scope, unlock_password, admission)
credentials = resolver.resolve(scope, session)
```

The adapter accepts only the actual `AuthorizationBroker` and a session present
by identity in that broker's private registry. It retains detached copies of the
exact plan and private scope. The host must derive task-selected fields/groups
from its canonical inputs; public callers must never construct this adapter,
supply ports, or choose private field scopes. Neither a forged private-looking
session, a different plan, nor a selected policy decision is sufficient.

Each selected target/task must match an exact ordered `resolve-for-run`
occurrence and the admitted plan's normalized host/port/vendor/transport route.
The adapter reserves and enters those actual A01 occurrences once. Delivery
validation checks the original live session and still-pending entered receipts
without reserving another effect or advancing host revision. The host broker
and host-state locks stay held through each resolution/delivery guard, with
resolver locks acquired afterward. Cancellation writers must use that same
host-state lock.

This is deliberately a **private A01 integration seam**: it uses the broker's
existing session registry, `_critical` and `_current` rather than reconstructing
authority from a snapshot. Changes to those private members require matching
adapter/preservation tests. No new broker API or native constructor was added.
Scope expiry cannot exceed the original grant deadline. Both entry and exit
recheck the host's monotonic clock, current plan/context, cancellation, dispatch
switch and revocation; time spent unlocking or validating consumes the original
budget. A host-exit rejection discards any newly resolved retained payload.
There is no deadline renewal or persisted/session-token recovery.

Every trusted clock callback, including permit reservation and entry, runs with
the exact private session selected under the broker lock. A raising provider
irreversibly revokes that registry-owned operation before ordinary failures
become `credential-scope-invalid`; cancellation retains its original exception.
Restoring the provider cannot revive admission. No substitute timestamp is
created, and pending factual receipts remain available for reconciliation and
valid monotonic late completion.

The host workflow/controller owner must keep resolution receipts pending until
protected delivery succeeds, then correlate completion through A01. Completing
them early blocks delivery; failure never retries a spent occurrence. This
adapter does not implement the A02 application composition root, broker
completion protocol, or S02 private controller dispatch channel.

Sessions are one-use and erase their mutable password buffer on use, denial or
`close()`. Call `close()` for an unused session after cancellation/startup
failure. `revoke()` clears every retained private payload for that operation.
Session and credential reprs are `<private>`; copying/pickling is rejected.
Ordinary contract serializers reject these values.

## Native-preserving vault seam

The only native-owner addition is
`CredentialVault.private_session()`, an isolated context-managed reader sharing
**only** the explicitly selected vault path. It is necessary to avoid
concurrently unlocking or clearing a native caller's existing vault object.
Every exit clears the isolated reader's decrypted dictionary and derived key
reference. Existing constructors, `unlock`, AES-GCM/PBKDF2 parameters, lookup
behavior and native connection/bastion defaults are unchanged.

Only the selected hostname is looked up, using the existing native precedence:
environment, device, first matching ordered group, defaults. A selected
environment credential does not require opening/unlocking the vault.
Missing required selected fields fail closed; fields from different precedence
levels are never silently merged. `ntp_authentication_key` is a private field
reference, resolved only when selected and present in the selected encrypted
record; it is never an inline plan value. This does not add a native NTP vault
management command.

Expected failures expose `SafeError` using a closed reason-to-category/stage
mapping, preserving the producing consumer's frozen wire contract:

| Reasons | Category | Stage |
| --- | --- | --- |
| `vault-locked`, `vault-missing`, `vault-password-invalid` | `credentials` | `credentials` |
| `credential-scope-invalid`, `handoff-invalid`, `deadline-exceeded` | `credentials` | `controller` |
| `route-unavailable`, `host-key-invalid` | `transport` | `connect` |

These are already-materialized safe errors, not exceptions awaiting controller
translation. Raw vault, route or admission exception messages never become
public diagnostics. This classification does not change admission, qualification,
route policy or dispatch authority.

## Route and private delivery boundary

The route port must validate the current selected controller, qualification
tuple and approved controller-local key/known-host access. The resolver rejects
changed identities, unavailable keys, unqualified private channels and any
host-key policy other than `reject`. A separately scoped SSH bastion is encoded
as `jump`, never added to command targets. No workstation SOCKS descriptor/token,
`active_bastion()` probe, AutoAdd trust enrollment, direct fallback, private-key
copy or vault/master-password transfer is provided.

`netops.ansible.credential_routes.ControllerOriginRoutePolicy(origin, approved,
files)` implements the selected-origin file observation. Trusted setup captures
an `ApprovedRouteFile.observe(ref, absolute_path, purpose)` for each selected
`private-key` or `known-hosts` reference after separate approval. These values
contain only file identity/size/time/mode/owner metadata, never file content or
secret hashes. They are drift evidence, **not consent or qualification**.
Validation requires the exact reference/purpose set, controller/route/context
and approved target/jump selection. It opens selected files read-only, compares
`lstat`/`fstat` identity and metadata, and closes descriptors without reading key
bytes. Missing, replaced, empty, nonregular, multiply-linked, symlink/reparse,
or changed files block; so do aliased parents, UNC/device/network paths,
alternate-stream aliases and POSIX unsafe ownership/modes.
There is no key search, trust enrollment, direct fallback or active-bastion call.

The adapter must run **in the selected controller origin**. It is not a
workstation-to-WSL probe or an authenticated origin attestation. S02 must carry
origin observations over its private bridge and Q03 must prove actual
origin/known-host/Windows ACL/fork/platform behavior. Supplying an approved
binding with a true qualification flag does not create that proof. Windows
metadata observation uses birth time when available, because Python's deprecated
`ctime` differs between `lstat` and `fstat`; it is not an ACL validation substitute.
Known-host contents must already have been approved; metadata/access checks
never establish host trust or replace the strict SSH host-key verifier.

The returned concrete credential value has a private one-use
`_protected_payload(scope)` seam for the controller adapter. It rechecks current
host authority, exact scope, monotonic expiry and the entire current route
binding before returning the minimal credential subsection; success **or failure**
clears its retained payload. Successful consumption spends the payload while both
host and resolver locks remain held, before the host guard releases. The
subsection is bounded to 1 MiB. It is **not**
the complete controller frame: the controller owner must add and validate the
frozen protocol/nonce/budget framing, reserve dispatch, and write only to its
already-admitted private pipe. Never place this subsection in argv, environment,
inventory, callbacks, caches, staging files or ordinary artifacts.

Python cannot promise cryptographic zeroization of immutable strings, returned
pipe bytes, interpreter copies or cryptography-library allocations. This
increment clears owned mutable buffers and drops decrypted references; it does
not claim stronger erasure.

Native SSH/SSH2/Telnet effective-port normalization remains 22/22/23 unless
explicitly overridden. This resolver fails closed for Telnet companion routes:
no plaintext route qualification is claimed, and it never downgrades SSH.
Native standalone Telnet behavior is untouched.

## Safe local observations

The two concrete adapters accept an optional `CredentialTelemetry` instance.
Its detached `counters()` pair execution-only rejection counts with structured
`credential.rejected` logs using `credential_rejections_total`, fixed stage and
safe reason dimensions. It never logs paths, exceptions, operation identifiers
or credential values, initializes logging configuration, writes files or exports
metrics. Saturation is latched per counter with a paired Failure observation;
these observational values never participate in authorization. Route rejection
is logged by the route helper, not logged again by the admission wrapper.
No resolver/route port is called by preview.

## Validation and remaining qualification

`tests/test_scoped_credentials.py` uses only synthetic encrypted vaults in
repository-owned test directories, injected clocks, host admission and route
ports. Network, subprocess and active-bastion effects are forbidden by spies.
It exercises precedence, safe unlock errors, field minimization, scope
substitution, changed keys/qualification, independent jump identity, expiry,
host cancellation, replay/revocation, serialization and sentinel negative
controls. `tests/test_vault.py` remains the native regression suite.

These are local unit checks, **not** AC-006 real handoff proof. A01 composition
is additionally exercised against real private broker sessions in
`tests/test_credential_composition.py`, including lock serialization, original
deadline, host drift/cancel/revoke, forged sessions, one-use delivery and
cancel/expiry during resolution. Local file fixtures exercise metadata-only key
access, known-host drift and symlink rejection. A deterministic host-release
negative control reproduces the former duplicate-delivery window; another
reproduces retained buffers after a host-exit rejection.

Independent S01 review/testing, A02 service composition, complete S02 controller
frame validation, owned private-pipe/fork inheritance and
actual Linux/macOS/Windows-to-WSL key/bastion/host-key routes remain unqualified
until independent T13/T14/T33 and Q03 evidence. No support/readiness matrix is
promoted by these tests. Independent high-security review remains mandatory.
