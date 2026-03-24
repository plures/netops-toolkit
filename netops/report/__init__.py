"""
netops.report — HTML/PDF network health report generation.

Quick start::

    from netops.report import ReportGenerator, ReportMailer, ReportScheduler

Requires optional dependencies::

    pip install netops-toolkit[report]          # HTML only
    pip install netops-toolkit[report-pdf]      # HTML + PDF
"""

from netops.report.generator import ReportGenerator, default_output_filename, generate_report
from netops.report.mailer import ReportMailer
from netops.report.scheduler import ReportScheduler

__all__ = [
    "ReportGenerator",
    "ReportMailer",
    "ReportScheduler",
    "generate_report",
    "default_output_filename",
]
