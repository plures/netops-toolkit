# `netops.report` — Reporting & Scheduling

HTML/PDF report generation, health dashboard, email delivery, and
report scheduling.

---

## `netops.report.generator`

Generate HTML (and optionally PDF) health reports from check results.

`netops.report.generator` exposes the native Python API and a saved-input CLI.
Build a report from structured check results, then render it:

```python
from netops.report import ReportGenerator

report = ReportGenerator()
data = report.build_report(title="Network Health", sections=[])
report.generate_html(data, output_path="report.html")
```

```console
netops report --input saved-sections.json --preview
netops report --input saved-sections.json --output report.html
netops report --input saved-outcome.json --format pdf --output report.pdf
```

Input is either `{"sections": [{"name": "...", "type": "...", "data": {}}]}`
or an exact versioned companion outcome. Preview validates loaded facts without
rendering, publishing, logging bootstrap or a report clock. Successful rendering
does not replace a source failure: a versioned source retains its exit
(`3` blocked, `4` partial, `5` failed, `6` unsupported, `130` cancelled).
Invalid inputs exit `2`; unavailable renderer extras exit `3`; rendering/output
failures exit `5`. No device I/O or implicit collection occurs.

Saved companion outcomes stay in the immutable public form admitted by the
JSON decoder through canonical outcome validation and projection. The CLI's
mutable classification view is not serializer input. A valid partial outcome
retains exit `4` in preview and HTML rendering; malformed or unadmitted values
remain rejected by the existing strict boundary.

Actual `.html.j2` values and generic JSON are HTML-escaped. Supported credential
material rejects; raw configuration/check payloads are omitted rather than
claimed perfectly redacted. PDF denies all resource fetching and validates real
PDF bytes. `probe_pdf()` runs the actual imported native renderer and returns
truthful readiness/guidance; it never installs dependencies or certifies a
platform tuple.

The native explicit-path API retains its legacy scope and now writes atomically
with symlink rejection. It is not an A02 protected-root/permission proof.
Companion output uses the separately admitted `ArtifactStore` only. Mandatory
empty-offline/failure-path A02 integration and independent native ACL/PDF/both-tier
qualification are not claimed complete by these source changes.
Current wheel/sdist declarations include the trusted built-in report template.
Earlier archives omitted it; those receipts describe historical packages, not
current source. Independent ordinary installed HTML proof exists for the earlier
sealed candidate, but each final source revision still requires a fresh build
and consuming proof. Real managed installation (I02), native PDF/platform
permissions and both-tier qualification (Q03) remain required. Installed preview
needs no renderer; a blocked dependency probe is not PDF qualification.
See [report architecture](https://github.com/plures/netops-toolkit/blob/main/documentation/report/report-architecture.md).

::: netops.report.generator

---

## `netops.report.health_dashboard`

Aggregate device health results into a summary dashboard view.

Supports table (terminal), JSON, and HTML output formats.

**CLI usage:**
```
python -m netops.report.health_dashboard --inventory inventory.yaml
python -m netops.report.health_dashboard --inventory inventory.yaml --format json
python -m netops.report.health_dashboard --inventory inventory.yaml --format html \
    --output dashboard.html
```

::: netops.report.health_dashboard

---

## `netops.report.mailer`

Send reports via email (SMTP with optional TLS/SSL).

::: netops.report.mailer

---

## `netops.report.scheduler`

Schedule recurring report generation and delivery.

Supports daily and weekly schedules with configurable delivery windows.

::: netops.report.scheduler
# Local output integration checkpoint (not acceptance)

Explicit empty offline report scope does not require invented controller
targets. Selected targets still require complete source coverage. The host
retains validated minimized source sections, errors and cleanup if later
preflight/rendering fails; no raw source native payload is copied as report data.
Local rendering does not qualify or depend on a later controller installation.

Package data and the sdist manifest now declare the actual trusted
`netops/report/templates/*.j2` resource. Older archives remain stale; a fresh
offline build and independent installed default-template rendering are still
required. No manually copied template or fake PDF driver counts as that proof.

