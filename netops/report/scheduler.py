"""
Scheduled network health report generation.

Supports daily and weekly schedules using Python's built-in
:mod:`threading` module — no external scheduler library required.

Usage::

    from netops.report.scheduler import ReportScheduler
    from netops.report.generator import ReportGenerator
    from netops.report.mailer import ReportMailer

    gen  = ReportGenerator(output_dir="/var/reports")
    mail = ReportMailer(host="smtp.example.com", username="netops@example.com",
                        password="secret")

    def collect() -> list[dict]:
        # Build section list from live checks
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
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from netops.report.generator import ReportGenerator, generate_report

logger = logging.getLogger(__name__)

# Day-of-week name → weekday number (Monday = 0)
_WEEKDAYS: dict[str, int] = {
    "monday": 0,
    "tuesday": 1,
    "wednesday": 2,
    "thursday": 3,
    "friday": 4,
    "saturday": 5,
    "sunday": 6,
}


class ScheduledReport:
    """Descriptor for a single scheduled report job."""

    def __init__(
        self,
        collect_fn: Callable[[], list[dict]],
        frequency: str,  # "daily" or "weekly"
        time_of_day: str,  # "HH:MM" in UTC
        day_of_week: Optional[str],  # for "weekly" frequency
        title: str,
        output_dir: Optional[str],
        recipients: Optional[list[str]],
        subject: Optional[str],
        pdf: bool,
    ) -> None:
        """Initialise a scheduled report descriptor with timing and delivery settings."""
        self.collect_fn = collect_fn
        self.frequency = frequency
        self.time_of_day = time_of_day
        self.day_of_week = day_of_week.lower() if day_of_week else None
        self.title = title
        self.output_dir = output_dir
        self.recipients = recipients or []
        self.subject = subject or title
        self.pdf = pdf

    def next_run(self, now: Optional[datetime] = None) -> datetime:
        """Return the next UTC run datetime for this schedule."""
        now = now or datetime.now(timezone.utc)
        hour, minute = _parse_time(self.time_of_day)

        # Candidate run time today
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)

        if self.frequency == "daily":
            if candidate <= now:
                candidate += timedelta(days=1)
            return candidate

        # Weekly
        target_weekday = _WEEKDAYS.get(self.day_of_week or "monday", 0)
        days_ahead = (target_weekday - candidate.weekday()) % 7
        candidate += timedelta(days=days_ahead)
        if candidate <= now:
            candidate += timedelta(weeks=1)
        return candidate


class ReportScheduler:
    """Schedule and run periodic network health reports.

    Parameters
    ----------
    generator:
        :class:`~netops.report.generator.ReportGenerator` instance used to
        render HTML (and optionally PDF) output.  When *None* a default
        generator is created.
    mailer:
        Optional :class:`~netops.report.mailer.ReportMailer` instance for
        email delivery.  When *None* reports are only written to disk.
    """

    def __init__(
        self,
        generator: Optional[ReportGenerator] = None,
        mailer: Optional[object] = None,
    ) -> None:
        """Initialise the scheduler with optional generator and mailer instances."""
        self._generator = generator or ReportGenerator()
        self._mailer = mailer
        self._jobs: list[ScheduledReport] = []
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Schedule registration
    # ------------------------------------------------------------------

    def schedule_daily(
        self,
        collect_fn: Callable[[], list[dict]],
        time_of_day: str = "00:00",
        title: str = "Daily Network Health Report",
        output_dir: Optional[str] = None,
        recipients: Optional[list[str]] = None,
        subject: Optional[str] = None,
        pdf: bool = False,
    ) -> None:
        """Register a daily report.

        Parameters
        ----------
        collect_fn:
            Zero-argument callable that returns a list of section dicts
            (``{"name": ..., "type": ..., "data": ...}``).  Called at
            report time to gather fresh check results.
        time_of_day:
            UTC time to run the report in ``HH:MM`` format (default: ``"00:00"``).
        title:
            Report title.
        output_dir:
            Directory where generated files are saved.
        recipients:
            Email recipients.  Requires *mailer* to be set on the scheduler.
        subject:
            Email subject.  Defaults to *title*.
        pdf:
            When ``True`` also generate and attach a PDF.  Requires
            ``weasyprint`` (``pip install netops-toolkit[report-pdf]``).
        """
        job = ScheduledReport(
            collect_fn=collect_fn,
            frequency="daily",
            time_of_day=time_of_day,
            day_of_week=None,
            title=title,
            output_dir=output_dir,
            recipients=recipients,
            subject=subject,
            pdf=pdf,
        )
        self._jobs.append(job)
        logger.info("Scheduled daily report '%s' at %s UTC", title, time_of_day)

    def schedule_weekly(
        self,
        collect_fn: Callable[[], list[dict]],
        day_of_week: str = "monday",
        time_of_day: str = "00:00",
        title: str = "Weekly Network Health Report",
        output_dir: Optional[str] = None,
        recipients: Optional[list[str]] = None,
        subject: Optional[str] = None,
        pdf: bool = False,
    ) -> None:
        """Register a weekly report.

        Parameters
        ----------
        collect_fn:
            Zero-argument callable returning section dicts.
        day_of_week:
            Day to run (``"monday"`` – ``"sunday"``, default: ``"monday"``).
        time_of_day:
            UTC time in ``HH:MM`` format (default: ``"00:00"``).
        title:
            Report title.
        output_dir, recipients, subject, pdf:
            Same as :meth:`schedule_daily`.
        """
        dow = day_of_week.lower()
        if dow not in _WEEKDAYS:
            raise ValueError(
                f"Invalid day_of_week {day_of_week!r}. "
                f"Must be one of: {', '.join(_WEEKDAYS)}"
            )
        job = ScheduledReport(
            collect_fn=collect_fn,
            frequency="weekly",
            time_of_day=time_of_day,
            day_of_week=dow,
            title=title,
            output_dir=output_dir,
            recipients=recipients,
            subject=subject,
            pdf=pdf,
        )
        self._jobs.append(job)
        logger.info(
            "Scheduled weekly report '%s' on %s at %s UTC",
            title, day_of_week, time_of_day,
        )

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------

    def start(self, blocking: bool = True) -> None:
        """Start the scheduler.

        Parameters
        ----------
        blocking:
            When ``True`` (default) this call blocks until :meth:`stop` is
            called from another thread.  When ``False`` the scheduler runs
            in a background daemon thread and this call returns immediately.
        """
        if not self._jobs:
            logger.warning("ReportScheduler started with no scheduled jobs")

        self._stop_event.clear()

        if blocking:
            self._run_loop()
        else:
            self._thread = threading.Thread(
                target=self._run_loop, daemon=True, name="ReportScheduler"
            )
            self._thread.start()
            logger.info("ReportScheduler started in background thread")

    def stop(self) -> None:
        """Signal the scheduler to stop after the current sleep cycle."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("ReportScheduler stopped")

    # ------------------------------------------------------------------
    # Internal: run loop
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        """Main scheduler loop — sleep until the next job, then fire it."""
        while not self._stop_event.is_set():
            now = datetime.now(timezone.utc)
            if not self._jobs:
                self._stop_event.wait(timeout=60)
                continue

            # Find the soonest job
            next_times = [(job.next_run(now), job) for job in self._jobs]
            next_times.sort(key=lambda x: x[0])
            fire_at, job = next_times[0]

            wait_secs = (fire_at - now).total_seconds()
            logger.debug("Next report '%s' in %.0f s", job.title, wait_secs)

            # Sleep in short increments so we can honour stop()
            self._sleep_until(fire_at)
            if self._stop_event.is_set():
                break

            self._run_job(job)

    def _sleep_until(self, target: datetime) -> None:
        """Sleep until *target* UTC, waking every second to check stop event."""
        while not self._stop_event.is_set():
            remaining = (target - datetime.now(timezone.utc)).total_seconds()
            if remaining <= 0:
                break
            self._stop_event.wait(timeout=min(remaining, 1.0))

    def _run_job(self, job: ScheduledReport) -> None:
        """Execute a single report job: collect → render → (email)."""
        logger.info("Running scheduled report: %s", job.title)
        try:
            sections = job.collect_fn()
            report_data = generate_report(
                sections=sections,
                title=job.title,
                output_dir=job.output_dir,
                template_path=self._generator.custom_template_path,
                html_output="auto",
                pdf_output="auto" if job.pdf else None,
            )

            if job.recipients and self._mailer:
                pdf_bytes = None
                if job.pdf:
                    try:
                        pdf_bytes = self._generator.generate_pdf(report_data)
                    except ImportError:
                        logger.warning("PDF generation skipped — weasyprint not installed")

                self._mailer.send(  # type: ignore[attr-defined]
                    recipients=job.recipients,
                    subject=job.subject,
                    html_body=report_data["html"],
                    pdf_attachment=pdf_bytes,
                )

            logger.info("Scheduled report '%s' completed", job.title)
        except Exception as exc:  # noqa: BLE001
            logger.error("Scheduled report '%s' failed: %s", job.title, exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_time(time_str: str) -> tuple[int, int]:
    """Parse ``HH:MM`` into ``(hour, minute)``."""
    parts = time_str.split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid time format {time_str!r} — expected HH:MM")
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError as exc:
        raise ValueError(f"Invalid time format {time_str!r} — expected HH:MM") from exc
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(
            f"Invalid time {time_str!r} — hour must be 0-23, minute 0-59"
        )
    return hour, minute
