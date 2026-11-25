# Native and companion reports

`ReportGenerator` remains the native owner of `ReportSection`, `ReportData`,
UTC report timestamps, HTML and actual WeasyPrint PDF rendering. The unified
CLI now returns `generator.main(argv)` status rather than invoking an absent
function and unconditionally returning success. It accepts saved `sections`
or a versioned companion outcome. No device collection is implied.

The native saved-input CLI retains the immutable object admitted by
`decode_json` for `project_outcome` and its canonical `OperationOutcome`
validation. A separate mutable `wire` view is used only to classify inputs and
read native sections; it is not resubmitted to the strict canonical serializer.
Valid partial saved outcomes therefore retain exit `4` in both preview and
HTML rendering. Duplicate keys, malformed outcomes and unadmitted mutable
objects remain rejected; no serializer admission rule is relaxed.

## Pure preview and coverage

`netops.report.companion.project_outcome(value, selected_target_ids=())` is
in-memory only. It preserves source status/exit, selected target coverage,
missing/blocked/unattempted states, ordered steps, findings, error categories,
cleanup, changed and remote uncertainty. Raw native payloads and error details
are not report facts. Missing coverage cannot be labeled healthy. Empty loaded
findings/outcomes in workflow preview produce an explicit invalid-input
precondition, not successful generation. Report/compare preview and check have
no publication effect intents.

`WorkflowService.execute` applies pure source-disposition preservation to
actually returned report data. Successful publication remains factual
(`changed`, verified descriptors); failed source work and source cleanup do not
become successful merely because HTML was produced.

## Rendering boundary

Jinja autoescape is explicitly enabled for the actual `.html.j2` suffix.
Jinja's HTML-safe `tojson` filter is retained. Device strings are values, not
templates. The default companion path uses only the packaged trusted template;
explicit native custom-template behavior remains source-compatible.

Raw configuration/check payload keys are omitted; supported credential-bearing
content is rejected by the shared public-value boundary. This is bounded
minimization, not perfect redaction or memory erasure. No generated active links
or external assets are introduced. PDF denies every resource fetch, including
local files and remote/data URLs. A denial swallowed by WeasyPrint still rejects
the output. Returned bytes must have a PDF header and EOF; HTML is never emitted
with a PDF extension. `probe_pdf()` explicitly renders through the real imported
native library in the consuming Python environment. Missing extras/native
libraries produce blocked guidance, not installation or platform qualification.

## Output and remaining integration

The A02 companion uses its existing exact broker-admitted `ArtifactStore`
publication; no companion path calls native `_resolve_path` writes. Native
explicit file output remains the legacy API, now with atomic file replacement
and symlink rejection. This native helper is **not** an A02 protected permission
or ownership proof.

The A02 host separates pure local output from controller/device readiness.
It still binds current source bytes/settings, actual one-use admission and
protected publication. Explicit empty offline scope is valid only with a
complete versioned source outcome; selected target coverage remains mandatory.
Validated minimized source facts remain in the returned report section if a
later preflight or renderer fails, alongside the original attempted/unapplied
render disposition, source errors and cleanup. The independent public controls
and installed consuming proof remain necessary; source edits alone are not
qualification. Native OS,
ACL, installed-package, real PDF tuple and both Molecule tier qualification
remain independent obligations. Unit driver bytes are never real PDF evidence.
The approved dependency DAG permits O03/O04 local source acceptance before Q03;
it does not permit whole-feature completion without those downstream checks.
Earlier ordinary installed-template/HTML receipts are historical source-bound
proof, not a final managed I02 installation or proof of later source revisions.

Current packaging declarations include `report/templates/*.j2` in package data
and `recursive-include netops/report/templates *.j2` in the sdist manifest.
Earlier archives omitted the trusted template; they are not fresh proof of
these declarations or subsequent source edits. A stable-source offline rebuild
and independent consuming install remain required; copying a template into an
installed package is not qualification. An isolated consuming environment without the report
extra correctly blocks HTML, and without WeasyPrint/native libraries correctly
blocks PDF. Those real dependency failures do not establish that template
packaging or either rendering platform is ready.

## Observability

Actual native HTML/PDF/output boundaries use one helper to pair local
`netops.report.io.count` counters with structured logs. Aggregate labels are
only closed `boundary`/`outcome`; correlation remains log-only and defaults to
`none` for standalone native calls. Host A02 observations supply actual admitted
operation/context identity. Finite nonnegative duration has a safe reporting
clock fallback. Reporting/sink failures, including interrupting sinks, cannot
discard returned HTML, original exceptions or factual publication.
Pure preview does not enter the observation helper.
