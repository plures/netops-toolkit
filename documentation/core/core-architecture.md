# Native active-bastion state publication

The active-bastion state carries a random local bearer token, not the SSH
password or key passphrase. Child secrets continue to travel over stdin, never
argv. This correction covers token publication, protected reads and default/log lifecycle;
it adds no service, platform permission, global ACL change or connection mode.

POSIX publication retains the existing explicit owner-only mode. Windows
publication uses the existing low-level `artifact_platform.WindowsHandles`
primitives, not the companion workflow service, authorization broker or policy
engine. No companion bootstrap or dependency installation is performed.

The selected parent must already have the actual current-user owner and
protected owner-only DACL. Every ancestor is opened without delete sharing and
checked for reparse substitution. The temporary member uses an unpredictable
name and exclusive creation with the owner-only DACL before any token bytes.
The native writer proves its file handle, writes and flushes exact bytes, and
renames the verified DELETE handle to the validated single-member destination.
Successful replacement removes the temporary name. Neither mode-bit emulation
nor raw-path rename/preflight substitutes for these checks.

An existing unsafe parent fails closed without being rewritten. On Windows the
new default `.netops-bastion` parent is created exclusively with a protected
owner-only DACL beneath pinned no-reparse ancestors. An existing default parent
must pass the ordinary native proof, never a sentinel or ACL repair. Explicit
`NETOPS_BASTION_STATE` parents are not automatically created/adopted.

Existing `.netops/active-bastion.json` is retained as the selected legacy path
when no new-default state is present. Every Windows state read, including legacy
reads, proves the actual protected parent and stable single-link file handle
before decoding or using the token. Unsafe state is an error, not disabled
routing/direct-connection fallback. No legacy migration or ACL repair occurs.
The fixed `.log` member is also created/opened through a proved native handle
before truncation/child stdout attachment; stdin-only secrets are unchanged.
New-default and legacy/read/log behavior still needs fresh independent tests.
A write/flush failure may
leave its private exclusively created temporary member; the writer must not
delete an unproved pre-existing member after an exclusive-create failure.

Actual native tests create only task-owned protected roots, inspect the file
handle DACL via the existing native proof, replace the exact state, and reject
ordinary inherited parents without ACL repair. Legacy POSIX `st_mode == 0600`
assertions are not valid Windows permission evidence and are left unchanged
for independent test-contract review.
