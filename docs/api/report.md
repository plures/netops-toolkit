# `netops.report` — Reporting & Scheduling

HTML/PDF report generation, health dashboard, email delivery, and
report scheduling.

---

## `netops.report.generator`

Generate HTML (and optionally PDF) health reports from check results.

`netops.report.generator` is a Python API; it does not define a command-line
interface. Build a report from structured check results, then render it:

```python
from netops.report import ReportGenerator

report = ReportGenerator()
data = report.build_report(title="Network Health", sections=[])
report.generate_html(data, output_path="report.html")
```

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
