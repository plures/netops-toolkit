"""
Report generator — produce HTML and PDF network health reports from check results.

Combines results from :mod:`netops.check.health`, :mod:`netops.check.bgp`,
:mod:`netops.check.vlan` (and any other check module) into formatted reports.

Requires the optional ``report`` extra::

    pip install netops-toolkit[report]          # HTML only
    pip install netops-toolkit[report-pdf]      # HTML + PDF

Usage::

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
    pdf  = gen.generate_pdf(report_data,  output_path="report.pdf")   # needs [report-pdf]
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

logger = logging.getLogger(__name__)

# Path to the built-in template shipped with the package
_BUILTIN_TEMPLATE = Path(__file__).parent / "templates" / "default.html.j2"


class ReportSection(TypedDict):
    """A single section within a report, grouping data by type."""

    name: str
    type: str
    data: dict[str, object]


class ReportData(TypedDict):
    """Assembled report data structure produced by :meth:`ReportGenerator.build_report`."""

    title: str
    generated_at: str
    period: str | None
    sections: list[ReportSection]
    overall_alert: bool


class ReportDataWithHtml(ReportData, total=False):
    """Extension of :class:`ReportData` that includes the rendered HTML string.

    Produced by the :func:`generate_report` convenience function.
    """

    html: str


class ReportGenerator:
    """Generate HTML (and optionally PDF) network health reports.

    Parameters
    ----------
    template_path:
        Path to a custom Jinja2 HTML template.  When *None* the bundled
        ``default.html.j2`` template is used.
    output_dir:
        Default directory for :meth:`generate_html` / :meth:`generate_pdf`
        when no explicit *output_path* is given.  Defaults to the current
        working directory.
    """

    def __init__(
        self,
        template_path: str | None = None,
        output_dir: str | None = None,
    ) -> None:
        """Initialise the generator with an optional template path and output directory."""
        self._template_path = Path(template_path) if template_path else _BUILTIN_TEMPLATE
        self._output_dir = Path(output_dir) if output_dir else Path.cwd()

    # ------------------------------------------------------------------
    # Report data builder
    # ------------------------------------------------------------------

    def build_report(
        self,
        title: str = "Network Health Report",
        sections: list[ReportSection] | None = None,
        period: str | None = None,
    ) -> ReportData:
        """Assemble a report data structure ready for rendering.

        Parameters
        ----------
        title:
            Report title shown in the HTML header.
        sections:
            List of section dicts, each with keys:

            * ``name``  – human-readable section heading
            * ``type``  – one of ``"health"``, ``"bgp"``, ``"vlan"`` (or any
                          string; unknown types fall back to a raw JSON view)
            * ``data``  – the dict returned by the corresponding
                          ``build_*_report()`` function

        period:
            Optional description of the reporting period, e.g.
            ``"2024-03-23 to 2024-03-24"``.

        Returns a dict with keys ``title``, ``generated_at``, ``period``,
        ``sections``, and ``overall_alert``.
        """
        sections = sections or []
        overall_alert = any(s.get("data", {}).get("overall_alert") for s in sections)
        return {
            "title": title,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "period": period,
            "sections": sections,
            "overall_alert": overall_alert,
        }

    # ------------------------------------------------------------------
    # HTML rendering
    # ------------------------------------------------------------------

    def generate_html(
        self,
        report_data: ReportData,
        output_path: str | None = None,
    ) -> str:
        """Render *report_data* as an HTML string.

        Parameters
        ----------
        report_data:
            Dict produced by :meth:`build_report`.
        output_path:
            If given, the HTML is written to this file path in addition to
            being returned.  Relative paths are resolved against
            *output_dir*.

        Returns the rendered HTML string.

        Raises
        ------
        ImportError
            When ``jinja2`` is not installed (``pip install
            netops-toolkit[report]``).
        """
        try:
            import jinja2  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "HTML report generation requires jinja2.  "
                "Install it with: pip install netops-toolkit[report]"
            ) from exc

        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self._template_path.parent)),
            autoescape=jinja2.select_autoescape(["html"]),
            undefined=jinja2.Undefined,
        )
        # Expose json serialisation to the template
        env.filters["tojson"] = lambda v, indent=None: json.dumps(v, indent=indent, default=str)

        template = env.get_template(self._template_path.name)
        html = template.render(**report_data)

        if output_path:
            dest = self._resolve_path(output_path, ".html")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(html, encoding="utf-8")
            logger.info("HTML report written to %s", dest)

        return html

    # ------------------------------------------------------------------
    # PDF rendering
    # ------------------------------------------------------------------

    def generate_pdf(
        self,
        report_data: ReportData,
        output_path: str | None = None,
    ) -> bytes:
        """Render *report_data* as a PDF document.

        Internally renders HTML via :meth:`generate_html` then converts it
        to PDF using ``weasyprint``.

        Parameters
        ----------
        report_data:
            Dict produced by :meth:`build_report`.
        output_path:
            If given, the PDF bytes are written to this file path in
            addition to being returned.

        Returns the PDF as a :class:`bytes` object.

        Raises
        ------
        ImportError
            When ``weasyprint`` is not installed (``pip install
            netops-toolkit[report-pdf]``).
        """
        try:
            from weasyprint import HTML as WeasyprintHTML  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "PDF generation requires weasyprint.  "
                "Install it with: pip install netops-toolkit[report-pdf]"
            ) from exc

        html_str = self.generate_html(report_data)
        pdf_bytes: bytes = WeasyprintHTML(string=html_str).write_pdf()

        if output_path:
            dest = self._resolve_path(output_path, ".pdf")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(pdf_bytes)
            logger.info("PDF report written to %s", dest)

        return pdf_bytes

    # ------------------------------------------------------------------
    # Public property
    # ------------------------------------------------------------------

    @property
    def custom_template_path(self) -> str | None:
        """Return the custom template path, or *None* if using the built-in."""
        if self._template_path == _BUILTIN_TEMPLATE:
            return None
        return str(self._template_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_path(self, path: str, default_suffix: str) -> Path:
        """Resolve *path* relative to *output_dir*; add suffix when missing."""
        p = Path(path)
        if not p.is_absolute():
            p = self._output_dir / p
        if not p.suffix:
            p = p.with_suffix(default_suffix)
        return p


# ---------------------------------------------------------------------------
# Convenience helper: auto-name output files
# ---------------------------------------------------------------------------


def default_output_filename(prefix: str = "netops-report", fmt: str = "html") -> str:
    """Return a timestamped filename like ``netops-report-20240324-120000.html``."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{ts}.{fmt}"


def generate_report(
    sections: list[ReportSection],
    title: str = "Network Health Report",
    period: str | None = None,
    output_dir: str | None = None,
    template_path: str | None = None,
    html_output: str | None = "auto",
    pdf_output: str | None = None,
) -> ReportDataWithHtml:
    """High-level convenience wrapper: build report, render HTML (and PDF).

    Parameters
    ----------
    sections:
        List of section dicts (``name``, ``type``, ``data``).
    title:
        Report title.
    period:
        Optional reporting period description.
    output_dir:
        Directory for output files.  Defaults to the current directory.
    template_path:
        Custom Jinja2 template path (optional).
    html_output:
        Path for the HTML output file.  Use ``"auto"`` to generate a
        timestamped filename in *output_dir*.  Use ``None`` to skip writing.
    pdf_output:
        Path for the PDF output file.  Use ``"auto"`` for a timestamped name.
        Requires ``weasyprint`` (``pip install netops-toolkit[report-pdf]``).

    Returns the assembled ``report_data`` dict (``sections``, ``title``,
    ``overall_alert``, etc.) with an additional ``html`` key containing the
    rendered HTML string.
    """
    gen = ReportGenerator(template_path=template_path, output_dir=output_dir)
    base = gen.build_report(title=title, sections=sections, period=period)

    out_dir = Path(output_dir) if output_dir else Path.cwd()

    html_path: str | None = None
    if html_output == "auto":
        html_path = str(out_dir / default_output_filename("netops-report", "html"))
    elif html_output:
        html_path = html_output

    html_str = gen.generate_html(base, output_path=html_path)

    result: ReportDataWithHtml = {**base, "html": html_str}

    if pdf_output is not None:
        pdf_path: str | None = None
        if pdf_output == "auto":
            pdf_path = str(out_dir / default_output_filename("netops-report", "pdf"))
        else:
            pdf_path = pdf_output
        gen.generate_pdf(base, output_path=pdf_path)

    return result
