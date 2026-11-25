# Protected storage teardown ownership

C02 uses `artifact_cleanup.py` for the shared primary/secondary exception
boundary in `artifacts.py` and `artifact_platform.py`. The public contracts and
v1-only state/CAS/retained restore behavior are unchanged.

An active primary exception, including the exact `KeyboardInterrupt` or
`SystemExit` object, remains primary. Each failed owned release contributes only
validated `SafeError` cleanup evidence; native exception text is not copied.
Without an active primary, ordinary cleanup failure crosses the internal
platform boundary as a sanitized `StorageCleanupError` and is translated by the
existing public artifact wrappers. A cancellation originating during cleanup
remains that cancellation. Failure is never relabelled as successful cleanup.

Windows file, rename and delete handles close inside this boundary. Directory
ancestors and separately acquired lock streams are each attempted in reverse
order even after an earlier release fails. Native handle ownership begins
before the security-descriptor context exits. Lock acquisition transfers
ownership exactly once from a native handle to a CRT descriptor to a stream;
failed conversion releases only the representation still owned locally.
Security descriptors, token handles and Darwin ACL allocations use the same
primary-preserving release framing.

POSIX reads/writes close the non-owning stream separately from the descriptor,
preserving both failures. Directory traversal retains acquired ancestor
descriptors until exit and attempts each release once. Failed stream creation
during lock acquisition releases the descriptor before propagating its primary.

A failed close leaves reconciliation uncertainty: it is not retried, and no
unknown file is removed to compensate. A successful native rename followed by
a close failure is reported as non-success without retrying the rename,
reverting a committed publication pointer, or adopting/removing an orphan.
Manifest ownership remains the only deletion boundary.

The four unchanged independent backend controls and the focused mutation,
creation, lock and stream fault matrix inject OS primitives while executing
the actual backend algorithms. They are local algorithm evidence, **not**
native Windows ACL/locking, Linux/macOS/WSL, process-crash or durability
qualification. Those platform cells remain Q03 responsibilities.
