# `netops.report` — Reporting & Scheduling

HTML/PDF report generation, health dashboard, email delivery, and
report scheduling.

---

## `netops.report.generator`

Generate HTML (and optionally PDF) health reports from check results.

**CLI usage:**
```
python -m netops.report.generator --results results.json --output report.html
python -m netops.report.generator --results results.json --output report.pdf --pdf
```

::: netops.report.generator

---

## `netops.report.health_dashboard`

Aggregate device health results into a summary dashboard view.

Supports table (terminal), JSON, and HTML output formats.

**CLI usage:**
```
python -m netops.report.health_dashboard --results results.json
python -m netops.report.health_dashboard --results results.json --format json
python -m netops.report.health_dashboard --results results.json --format html \
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
