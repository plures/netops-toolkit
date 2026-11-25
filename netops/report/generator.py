"""Report generator — produce HTML and PDF network health reports from check results.

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

import argparse
import logging
import math
import os
import stat
import sys
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import TypedDict, cast
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# Path to the built-in template shipped with the package
_BUILTIN_TEMPLATE = Path(__file__).parent / "templates" / "default.html.j2"
_METRIC = "netops.report.io.count"
_UNHANDLED = "Unhandled"
_BOUNDARIES = frozenset(("html", "pdf", "output", "input", _UNHANDLED))
_COUNTS: Counter[tuple[str, str]] = Counter()
_COUNTER_LOCK = threading.RLock()
_NEXT_ACTION = "Inspect the selected source, trusted renderer and exact output before replanning."


def _time() -> float:
    try:
        value = time.monotonic()
        return value if math.isfinite(value) and value >= 0 else 0.0
    except BaseException:
        return 0.0


def _record(boundary: str, outcome: str, duration: float) -> None:
    """Own matching bounded metric/log dimensions and isolate reporting failures."""
    try:
        with _COUNTER_LOCK:
            _COUNTS[(boundary, outcome)] += 1
        dimensions = {"boundary": boundary, "outcome": outcome}
        logger.info("report.io", extra={
            "metric": _METRIC, "metric_value": 1, "metric_dimensions": dimensions,
            **dimensions, "duration": duration, "operation_id": "none",
            "stage": boundary,
            "target_id": "none", "step_id": boundary, "context_id": "none",
            "mode": "output", "status": outcome,
            "error_category": "rendering" if outcome == "failed" else "none",
            "reason": "render-failed" if outcome == "failed" else "none",
            "retryable": False, "next_action": _NEXT_ACTION if outcome == "failed" else "none",
        })
    except BaseException:
        pass


@contextmanager
def _observe(boundary: str) -> Iterator[None]:
    if boundary not in _BOUNDARIES:
        raise ValueError("unknown-report-boundary")
    started = _time()
    _record(boundary, "started", 0.0)
    outcome = "failed"
    try:
        yield
        outcome = "succeeded"
    finally:
        _record(boundary, outcome, max(0.0, _time() - started))


def _minimized(value: object) -> object:
    """Omit raw device/config payloads, never claim arbitrary redaction is complete."""
    if isinstance(value, dict):
        return {
            key: _minimized(item) for key, item in value.items()
            if key not in ("raw", "config", "configuration", "before_text", "after_text")
        }
    if isinstance(value, list):
        return [_minimized(item) for item in value]
    return value


def _safe_section(section: ReportSection) -> ReportSection:
    import json

    from netops.ansible.contracts import canonical_bytes, public_object

    if (
        type(section) is not dict or set(section) != {"name", "type", "data"}
        or type(section["name"]) is not str or type(section["type"]) is not str
        or type(section["data"]) is not dict
    ):
        raise ValueError("input-binding-invalid")
    return cast(ReportSection, json.loads(canonical_bytes(public_object(_minimized(section)))))


def _read_input(path: str) -> bytes:
    from netops.ansible.contracts import MAX_CONTENT_BYTES

    with Path(path).open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("input-binding-invalid")
        return stream.read(MAX_CONTENT_BYTES + 1)


class _PdfResources(HTMLParser):
    """Reject resource references before a native library can log supplied URLs."""

    def __init__(self) -> None:
        super().__init__()
        self._style = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "iframe", "img", "link", "object", "embed", "base"):
            raise ValueError("report-resource-fetch-denied")
        if any(name in ("src", "srcset") for name, value in attrs):
            raise ValueError("report-resource-fetch-denied")
        for name, value in attrs:
            if name == "href" and value is not None and not value.startswith("#"):
                parsed = urlsplit(value)
                if (
                    parsed.scheme not in ("https", "http") or not parsed.netloc
                    or parsed.username is not None or parsed.password is not None
                ):
                    raise ValueError("output-rejected")
            if name == "style" and value is not None and (
                "url(" in value.lower().replace(" ", "") or "@import" in value.lower()
            ):
                raise ValueError("report-resource-fetch-denied")
        self._style = tag == "style"

    def handle_endtag(self, tag: str) -> None:
        if tag == "style":
            self._style = False

    def handle_data(self, data: str) -> None:
        if self._style and (
            "url(" in data.lower().replace(" ", "") or "@import" in data.lower()
        ):
            raise ValueError("report-resource-fetch-denied")


def _source_failed(value: object) -> bool:
    if isinstance(value, dict):
        if value.get("success") is False or value.get("overall_alert") is True:
            return True
        if value.get("status") in ("failed", "partial", "blocked", "unsupported", "cancelled"):
            return True
        if value.get("source_status") in ("failed", "partial", "blocked", "unsupported", "cancelled"):
            return True
        return any(_source_failed(item) for item in value.values())
    return isinstance(value, list) and any(_source_failed(item) for item in value)


def _write_output(dest: Path, content: bytes) -> None:
    """Native explicit output: atomic bytes, no symlink destination or path logging.

    Companion publication never enters this helper: its host must use the
    separately admitted protected ArtifactStore and integrity descriptors.
    """
    if any(parent.is_symlink() for parent in (dest,) + tuple(dest.parents)):
        raise ValueError("output-rejected")
    dest.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".netops-report-", dir=dest.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if dest.is_symlink():
            raise ValueError("output-rejected")
        os.replace(temporary, dest)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


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

        Returns
        -------
        ReportData
            Dict with keys ``title``, ``generated_at``, ``period``,
            ``sections``, and ``overall_alert``.

        """
        from netops.ansible.contracts import public_value

        public_value(title)
        public_value(period)
        if type(title) is not str or (period is not None and type(period) is not str):
            raise ValueError("input-binding-invalid")
        checked: list[ReportSection] = []
        for section in sections or []:
            if section.get("type") == "companion":
                import json

                from netops.ansible.contracts import canonical_bytes, public_value
                from netops.report.companion import project_outcome

                # The accepted native renderer passes a complete versioned
                # source outcome. It may not render native raw payloads.
                projected = project_outcome(public_value(section["data"]))
                section = {
                    "name": section["name"], "type": "companion",
                    "data": json.loads(canonical_bytes(projected)),
                }
            checked.append(_safe_section(section))
        sections = checked
        overall_alert = any(_source_failed(section["data"]) for section in sections)
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

        Returns
        -------
        str
            Rendered HTML string.

        Raises
        ------
        ImportError
            When ``jinja2`` is not installed (``pip install
            netops-toolkit[report]``).

        """
        with _observe("html"):
            return self._generate_html(report_data, output_path)

    def _generate_html(self, report_data: ReportData, output_path: str | None) -> str:
        try:
            import jinja2  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "HTML report generation requires jinja2.  "
                "Install it with: pip install netops-toolkit[report]"
            ) from exc

        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self._template_path.parent)),
            # select_autoescape(["html"]) does NOT match default.html.j2.
            autoescape=True,
            undefined=jinja2.Undefined,
        )
        template = env.get_template(self._template_path.name)
        # Do not override Jinja's HTML-safe tojson filter with raw JSON.
        safe_data: dict[str, object] = {
            "title": report_data["title"], "generated_at": report_data["generated_at"],
            "period": report_data["period"], "sections": report_data["sections"],
            "overall_alert": report_data["overall_alert"],
        }
        from netops.ansible.contracts import public_value

        public_value(report_data["title"])
        public_value(report_data["period"])
        public_value(report_data["generated_at"])
        safe_data["sections"] = [_safe_section(section) for section in report_data["sections"]]
        html = template.render(**safe_data)
        _PdfResources().feed(html)

        if output_path:
            dest = self._resolve_path(output_path, ".html")
            with _observe("output"):
                _write_output(dest, html.encode("utf-8"))

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

        Returns
        -------
        bytes
            PDF document bytes.

        Raises
        ------
        ImportError
            When ``weasyprint`` is not installed (``pip install
            netops-toolkit[report-pdf]``).

        """
        with _observe("pdf"):
            return self._generate_pdf(report_data, output_path)

    def _generate_pdf(self, report_data: ReportData, output_path: str | None) -> bytes:
        try:
            from weasyprint import HTML as WeasyprintHTML  # noqa: PLC0415
        except (ImportError, OSError) as exc:
            raise ImportError(
                "PDF generation requires weasyprint.  "
                "Install it with: pip install netops-toolkit[report-pdf]"
            ) from exc

        html_str = self.generate_html(report_data)
        _PdfResources().feed(html_str)
        attempted_fetch = False

        def deny_fetch(url: str, *args: object, **kwargs: object) -> dict[str, object]:
            nonlocal attempted_fetch
            attempted_fetch = True
            raise ValueError("report-resource-fetch-denied")

        pdf_bytes: bytes = WeasyprintHTML(
            string=html_str, url_fetcher=deny_fetch,
        ).write_pdf()
        # WeasyPrint may catch resource errors. A caught denied fetch still
        # rejects the document, rather than certifying an incomplete report.
        if attempted_fetch:
            raise ValueError("report-resource-fetch-denied")
        if (
            type(pdf_bytes) is not bytes or not pdf_bytes.startswith(b"%PDF-")
            or b"%%EOF" not in pdf_bytes[-1024:]
        ):
            raise ValueError("render-failed")

        if output_path:
            dest = self._resolve_path(output_path, ".pdf")
            with _observe("output"):
                _write_output(dest, pdf_bytes)

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


def probe_pdf() -> dict[str, object]:
    """Explicit consuming-context probe: render real native PDF bytes, never install.

    A positive result describes only this invocation in this Python/native
    library tuple. It is not a platform or product qualification receipt.
    """
    try:
        generator = ReportGenerator()
        content = generator.generate_pdf(generator.build_report())
        return {"ready": True, "media_type": "application/pdf", "size": len(content)}
    except ImportError:
        return {
            "ready": False, "reason": "dependency-not-ready",
            "next_action": "Install the selected report-pdf extra and native libraries in the approved consuming environment, then probe again.",
        }
    except Exception:
        return {
            "ready": False, "reason": "render-failed",
            "next_action": "Repair the qualified native PDF renderer before requesting PDF output.",
        }


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

    Returns
    -------
    ReportDataWithHtml
        Assembled report data dict with an additional ``html`` key containing
        the rendered HTML string.

    """
    gen = ReportGenerator(template_path=template_path, output_dir=output_dir)
    base = gen.build_report(title=title, sections=sections, period=period)

    html_path: str | None = None
    if html_output == "auto":
        html_path = default_output_filename("netops-report", "html")
    elif html_output:
        html_path = html_output

    html_str = gen.generate_html(base, output_path=html_path)

    result: ReportDataWithHtml = {**base, "html": html_str}

    if pdf_output is not None:
        pdf_path: str | None = None
        if pdf_output == "auto":
            pdf_path = default_output_filename("netops-report", "pdf")
        else:
            pdf_path = pdf_output
        gen.generate_pdf(base, output_path=pdf_path)

    return result


def main(argv: list[str] | None = None) -> int:
    """Render loaded sections via the actual native API; no device connection."""
    import json

    parser = argparse.ArgumentParser(description="Render saved network report sections.")
    parser.add_argument("--input", required=True, help="JSON object containing sections")
    parser.add_argument("--title", default="Network Health Report")
    parser.add_argument("--period")
    parser.add_argument("--format", choices=("html", "pdf"), default="html")
    parser.add_argument("--output", help="Explicit native output file")
    parser.add_argument("--preview", action="store_true", help="Validate without rendering/writing")
    args = parser.parse_args(argv)
    phase = "input"
    try:
        from netops.ansible.contracts import canonical_bytes, decode_json, wire
        from netops.report.companion import project_outcome

        if args.preview:
            content = _read_input(args.input)
        else:
            with _observe("input"):
                content = _read_input(args.input)
        admitted = decode_json(content)
        value = wire(admitted)
        if not isinstance(value, dict):
            raise ValueError("input-binding-invalid")
        if "operation_id" in value and "schema_version" in value:
            projected = project_outcome(admitted)
            sections = [{
                "name": "Selected outcomes", "type": "outcomes",
                "data": json.loads(canonical_bytes(projected)),
            }]
            source_exit = cast(int, projected["source_exit_code"])
        elif set(value) == {"sections"}:
            sections = value["sections"]
            source_exit = 0
        else:
            raise ValueError("input-binding-invalid")
        if not isinstance(sections, list):
            raise ValueError("input-binding-invalid")
        checked = [_safe_section(cast(ReportSection, section)) for section in sections]
        if source_exit == 0 and any(_source_failed(section["data"]) for section in checked):
            source_exit = 5
        if args.preview:
            print(json.dumps({
                "execution_performed": False, "sections": len(checked),
                "format": args.format, "output_requested": args.output is not None,
                "source_exit": source_exit,
            }, sort_keys=True))
            return source_exit
        phase = "render"
        generator = ReportGenerator()
        report = generator.build_report(args.title, checked, args.period)
        if args.format == "html":
            html = generator.generate_html(report, args.output)
            if args.output is None:
                print(html)
        else:
            if args.output is None:
                raise ValueError("output-rejected")
            generator.generate_pdf(report, args.output)
        return source_exit
    except ImportError:
        print("dependency-not-ready: install the selected report/report-pdf extra in the consuming environment.", file=sys.stderr)
        return 3
    except OSError:
        print("render-failed: check the selected input/output and native PDF libraries.", file=sys.stderr)
        return 5
    except (ValueError, TypeError, KeyError, RecursionError):
        print("input-binding-invalid or render-failed: validate saved sections and explicit output.", file=sys.stderr)
        return 2 if phase == "input" else 5
    except Exception:
        if not args.preview:
            _record(_UNHANDLED, "failed", 0.0)
        print("render-failed: inspect the trusted template and selected renderer.", file=sys.stderr)
        return 5


if __name__ == "__main__":
    sys.exit(main())
