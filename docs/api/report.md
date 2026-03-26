# `netops.report` — Report Generation & Delivery

Generate HTML/PDF health reports, dashboards, email delivery, and scheduling.

---

## `netops.report.generator`

Report generator — produce HTML and PDF network health reports from check results.

Combines results from `netops.check.health`, `netops.check.bgp`,
`netops.check.vlan` (and any other check module) into formatted reports.

**Requirements:**
```
pip install netops-toolkit[report]       # HTML only
pip install netops-toolkit[report-pdf]   # HTML + PDF
```

**Usage:**
```python
from netops.check.health import build_health_report
from netops.check.bgp import build_bgp_report
from netops.report.generator import ReportGenerator

gen = ReportGenerator()
report_data = gen.build_report(
    title="Weekly Network Health",
    sections=[
        {"name": "Device Health", "type": "health",
         "data": build_health_report(health_results)},
        {"name": "BGP Health",    "type": "bgp",
         "data": build_bgp_report(bgp_results)},
    ],
)

html = gen.generate_html(report_data, output_path="report.html")
pdf  = gen.generate_pdf(report_data,  output_path="report.pdf")
```

### Classes

#### `ReportGenerator`

Generate HTML (and optionally PDF) network health reports.

**Parameters:**
- `template_path` — path to a custom Jinja2 HTML template; when `None` the bundled `default.html.j2` template is used
- `output_dir` — default directory for `generate_html` / `generate_pdf` when no explicit `output_path` is given; defaults to the current working directory

**Methods:**

##### `build_report(title: str = 'Network Health Report', sections: list[dict[str, Any]] | None = None, period: str | None = None) -> dict[str, Any]`
Assemble a report data structure ready for rendering.

**Parameters:**
- `title` — report title shown in the HTML header
- `sections` — list of section dicts, each with keys: `name` (heading),
  `type` (one of `"health"`, `"bgp"`, `"vlan"`; unknown types fall back to
  a raw JSON view), `data` (the dict returned by the corresponding
  `build_*_report()` function)
- `period` — optional description of the reporting period

Returns a dict with keys `title`, `generated_at`, `period`, `sections`, and
`overall_alert`.

##### `generate_html(report_data: dict[str, Any], output_path: str | None = None) -> str`
Render *report_data* as an HTML string.

**Parameters:**
- `report_data` — dict produced by `build_report`
- `output_path` — if given, the HTML is written to this file path in addition to being returned; relative paths are resolved against `output_dir`

Returns the rendered HTML string.

Raises `ImportError` when `jinja2` is not installed.

##### `generate_pdf(report_data: dict[str, Any], output_path: str | None = None) -> bytes`
Render *report_data* as a PDF document.

Internally renders HTML via `generate_html` then converts it to PDF using
`weasyprint`.

**Parameters:**
- `report_data` — dict produced by `build_report`
- `output_path` — if given, the PDF bytes are written to this file path in addition to being returned

Returns the PDF as a `bytes` object.

Raises `ImportError` when `weasyprint` is not installed.

##### `custom_template_path() -> str | None`
Return the custom template path, or `None` if using the built-in.

### Functions

#### `default_output_filename(prefix: str = 'netops-report', fmt: str = 'html') -> str`
Return a timestamped filename like `netops-report-20240324-120000.html`.

#### `generate_report(sections: list[dict[str, Any]], title: str = 'Network Health Report', period: str | None = None, output_dir: str | None = None, template_path: str | None = None, html_output: str | None = 'auto', pdf_output: str | None = None) -> dict[str, Any]`
High-level convenience wrapper: build report, render HTML (and PDF).

**Parameters:**
- `sections` — list of section dicts (`name`, `type`, `data`)
- `title` — report title
- `period` — optional reporting period description
- `output_dir` — directory for output files; defaults to the current directory
- `template_path` — custom Jinja2 template path (optional)
- `html_output` — path for HTML output; `"auto"` generates a timestamped filename; `None` skips writing
- `pdf_output` — path for PDF output; `"auto"` for a timestamped name; requires `weasyprint`

Returns the assembled `report_data` dict with an additional `html` key
containing the rendered HTML string.

---

## `netops.report.health_dashboard`

Unified multi-vendor health dashboard.

Aggregates health check results from all supported vendor checkers (Cisco
IOS/IOS-XE, Arista EOS, Juniper JunOS, Nokia SROS, Brocade, Palo Alto PAN-OS)
into a single normalised view and renders it as a terminal table, JSON document,
or self-contained HTML page.

**Common row schema:**
```python
{
    "device":    str,          # hostname / IP
    "vendor":    str,          # device_type string
    "site":      str | None,   # optional site tag
    "category":  str,          # "cpu", "memory", "interfaces", ...
    "status":    str,          # "ok", "warn", or "crit"
    "detail":    str,          # human-readable one-liner
    "timestamp": str,          # ISO-8601 UTC
}
```

**CLI usage:**
```
python -m netops.report.health_dashboard \
    --inventory inv.yaml --group core \
    --format table
python -m netops.report.health_dashboard \
    --inventory inv.yaml --vendor arista_eos \
    --format html --output dashboard.html
```

**Programmatic:**
```python
from netops.report.health_dashboard import aggregate_dashboard, format_table

results = [run_health_check(p) for p in device_params]
dashboard = aggregate_dashboard(results, vendor_tag="cisco_ios")
print(format_table(dashboard))
```

### Functions

#### `normalize_device_result(result: dict, vendor: str | None = None, site: str | None = None) -> list[dict]`
Convert a per-device health-check result to a list of normalised rows.

**Parameters:**
- `result` — a dict returned by any `run_*_health_check()` function
- `vendor` — vendor/platform tag to attach; if `None` the raw key from `result` is used when available
- `site` — optional site/location label

Returns a list of row dicts. Unreachable devices produce a single
`status="crit"` row with category `"reachability"`.

#### `aggregate_dashboard(device_results: list[dict], vendor_tag: str | None = None, site_tag: str | None = None, filter_vendor: str | None = None, filter_site: str | None = None, filter_severity: str | None = None) -> dict`
Aggregate health check results into a unified dashboard dict.

**Parameters:**
- `device_results` — list of per-device result dicts from any `run_*_health_check()`
- `vendor_tag` — vendor label to attach to every row when the result dicts do not already carry one
- `site_tag` — site label to attach to every row
- `filter_vendor` — when set, only include rows whose vendor contains this string (case-insensitive)
- `filter_site` — when set, only include rows matching this site label exactly
- `filter_severity` — `"warn"` excludes `"ok"` rows; `"crit"` also excludes `"warn"` rows

Returns a dashboard dict with keys: `generated_at`, `filters`, `entries`,
`summary`, `overall_status`.

#### `format_table(dashboard: dict, color: bool = True) -> str`
Render *dashboard* as a fixed-width terminal table string.

**Parameters:**
- `dashboard` — dict returned by `aggregate_dashboard`
- `color` — when `True` (default), status values are prefixed with emoji icons

Returns the formatted string (no trailing newline).

#### `render_html(dashboard: dict, output_path: str | None = None) -> str`
Render *dashboard* as a self-contained HTML string.

**Parameters:**
- `dashboard` — dict returned by `aggregate_dashboard`
- `output_path` — when given, the HTML is also written to this path

Raises `ImportError` when `jinja2` is not installed.

#### `main() -> None`
CLI entry point: `python -m netops.report.health_dashboard`.

---

## `netops.report.mailer`

Email delivery for network health reports.

Sends HTML (and optional PDF attachment) reports via SMTP using Python's
built-in `smtplib` and `email` modules — no extra dependencies required.

**Usage:**
```python
from netops.report.mailer import ReportMailer

mailer = ReportMailer(
    host="smtp.example.com",
    port=587,
    username="netops@example.com",
    password="secret",
    use_tls=True,
)
mailer.send(
    recipients=["ops-team@example.com"],
    subject="Daily Network Health Report",
    html_body=html_str,
    pdf_attachment=pdf_bytes,   # optional
)
```

### Classes

#### `ReportMailer`

Send HTML reports via SMTP.

**Parameters:**
- `host` — SMTP server hostname or IP address
- `port` — SMTP port (default: `587` for STARTTLS)
- `username` — SMTP authentication username; when `None` no authentication is attempted
- `password` — SMTP authentication password
- `use_tls` — when `True` (default) upgrade the connection with STARTTLS
- `use_ssl` — when `True` open a direct SSL/TLS connection (typically port 465); mutually exclusive with `use_tls` — `use_ssl` takes precedence
- `from_addr` — envelope *From* address; defaults to `username` when not given
- `timeout` — socket timeout in seconds (default: `30`)

**Methods:**

##### `send(recipients: list[str], subject: str, html_body: str, pdf_attachment: Optional[bytes] = None, pdf_filename: str = 'report.pdf', plain_text: Optional[str] = None) -> None`
Send a report email to *recipients*.

**Parameters:**
- `recipients` — list of recipient email addresses
- `subject` — email subject line
- `html_body` — HTML content for the email body
- `pdf_attachment` — optional PDF bytes to attach to the message
- `pdf_filename` — filename for the PDF attachment (default: `"report.pdf"`)
- `plain_text` — optional plain-text alternative body; when omitted a minimal plain-text version is generated automatically

---

## `netops.report.scheduler`

Scheduled network health report generation.

Supports daily and weekly schedules using Python's built-in `threading`
module — no external scheduler library required.

**Usage:**
```python
from netops.report.scheduler import ReportScheduler
from netops.report.generator import ReportGenerator
from netops.report.mailer import ReportMailer

gen  = ReportGenerator(output_dir="/var/reports")
mail = ReportMailer(host="smtp.example.com", username="netops@example.com",
                    password="secret")

def collect() -> list[dict]:
    return [{"name": "Device Health", "type": "health", "data": ...}]

scheduler = ReportScheduler(generator=gen, mailer=mail)
scheduler.schedule_daily(
    collect_fn=collect,
    time_of_day="06:00",
    recipients=["ops@example.com"],
    subject="Daily Network Health Report",
    pdf=True,
)
scheduler.start()   # blocks; call scheduler.stop() from another thread
```

### Classes

#### `ScheduledReport`

Descriptor for a single scheduled report job.

**Methods:**

##### `next_run(now: Optional[datetime] = None) -> datetime`
Return the next UTC run datetime for this schedule.

---

#### `ReportScheduler`

Schedule and run periodic network health reports.

**Parameters:**
- `generator` — `ReportGenerator` instance used to render HTML (and optionally PDF) output; when `None` a default generator is created
- `mailer` — optional `ReportMailer` instance for email delivery; when `None` reports are only written to disk

**Methods:**

##### `schedule_daily(collect_fn: Callable[[], list[dict]], time_of_day: str = '00:00', title: str = 'Daily Network Health Report', output_dir: Optional[str] = None, recipients: Optional[list[str]] = None, subject: Optional[str] = None, pdf: bool = False) -> None`
Register a daily report.

**Parameters:**
- `collect_fn` — zero-argument callable that returns a list of section dicts; called at report time to gather fresh check results
- `time_of_day` — UTC time to run in `HH:MM` format (default: `"00:00"`)
- `title` — report title
- `output_dir` — directory where generated files are saved
- `recipients` — email recipients; requires `mailer` to be set on the scheduler
- `subject` — email subject; defaults to `title`
- `pdf` — when `True` also generate and attach a PDF; requires `weasyprint`

##### `schedule_weekly(collect_fn: Callable[[], list[dict]], day_of_week: str = 'monday', time_of_day: str = '00:00', title: str = 'Weekly Network Health Report', output_dir: Optional[str] = None, recipients: Optional[list[str]] = None, subject: Optional[str] = None, pdf: bool = False) -> None`
Register a weekly report.

**Parameters:**
- `collect_fn` — zero-argument callable returning section dicts
- `day_of_week` — day to run (`"monday"` – `"sunday"`, default: `"monday"`)
- `time_of_day` — UTC time in `HH:MM` format (default: `"00:00"`)
- `title`, `output_dir`, `recipients`, `subject`, `pdf` — same as `schedule_daily`

##### `start(blocking: bool = True) -> None`
Start the scheduler.

**Parameters:**
- `blocking` — when `True` (default) this call blocks until `stop` is called from another thread; when `False` the scheduler runs in a background daemon thread

##### `stop() -> None`
Signal the scheduler to stop after the current sleep cycle.
