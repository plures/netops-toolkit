"""
Email delivery for network health reports.

Sends HTML (and optional PDF attachment) reports via SMTP using Python's
built-in :mod:`smtplib` and :mod:`email` modules — no extra dependencies
required.

Usage::

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
"""

from __future__ import annotations

import logging
import re
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

logger = logging.getLogger(__name__)


class ReportMailer:
    """Send HTML reports via SMTP.

    Parameters
    ----------
    host:
        SMTP server hostname or IP address.
    port:
        SMTP port (default: 587 for STARTTLS).
    username:
        SMTP authentication username.  When *None* no authentication is
        attempted.
    password:
        SMTP authentication password.
    use_tls:
        When ``True`` (default) upgrade the connection with STARTTLS.
    use_ssl:
        When ``True`` open a direct SSL/TLS connection (typically port 465).
        Mutually exclusive with *use_tls* — *use_ssl* takes precedence.
    from_addr:
        Envelope *From* address.  Defaults to *username* when not given.
    timeout:
        Socket timeout in seconds (default: 30).
    """

    def __init__(
        self,
        host: str,
        port: int = 587,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: bool = True,
        use_ssl: bool = False,
        from_addr: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.use_ssl = use_ssl
        self.from_addr = from_addr or username or "netops@localhost"
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send(
        self,
        recipients: list[str],
        subject: str,
        html_body: str,
        pdf_attachment: Optional[bytes] = None,
        pdf_filename: str = "report.pdf",
        plain_text: Optional[str] = None,
    ) -> None:
        """Send a report email to *recipients*.

        Parameters
        ----------
        recipients:
            List of recipient email addresses.
        subject:
            Email subject line.
        html_body:
            HTML content for the email body.
        pdf_attachment:
            Optional PDF bytes to attach to the message.
        pdf_filename:
            Filename for the PDF attachment (default: ``"report.pdf"``).
        plain_text:
            Optional plain-text alternative body.  When omitted a minimal
            plain-text version is generated automatically.
        """
        if not recipients:
            raise ValueError("recipients must not be empty")

        msg = self._build_message(
            recipients=recipients,
            subject=subject,
            html_body=html_body,
            pdf_attachment=pdf_attachment,
            pdf_filename=pdf_filename,
            plain_text=plain_text,
        )

        try:
            self._deliver(msg, recipients)
        except smtplib.SMTPException as exc:
            logger.error("Failed to send report email: %s", exc)
            raise

        logger.info(
            "Report email sent to %s via %s:%d",
            ", ".join(recipients),
            self.host,
            self.port,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_message(
        self,
        recipients: list[str],
        subject: str,
        html_body: str,
        pdf_attachment: Optional[bytes],
        pdf_filename: str,
        plain_text: Optional[str],
    ) -> MIMEMultipart:
        """Assemble the MIME message."""
        if pdf_attachment:
            root = MIMEMultipart("mixed")
            body_part = MIMEMultipart("alternative")
            root.attach(body_part)
        else:
            root = MIMEMultipart("alternative")
            body_part = root

        root["Subject"] = subject
        root["From"] = self.from_addr
        root["To"] = ", ".join(recipients)

        # Plain text fallback
        text = plain_text or _html_to_plain(html_body)
        body_part.attach(MIMEText(text, "plain", "utf-8"))
        body_part.attach(MIMEText(html_body, "html", "utf-8"))

        # PDF attachment
        if pdf_attachment:
            part = MIMEBase("application", "pdf")
            part.set_payload(pdf_attachment)
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                "attachment",
                filename=pdf_filename,
            )
            root.attach(part)

        return root

    def _deliver(self, msg: MIMEMultipart, recipients: list[str]) -> None:
        """Open an SMTP connection and send *msg*."""
        if self.use_ssl:
            smtp_cls = smtplib.SMTP_SSL
        else:
            smtp_cls = smtplib.SMTP

        with smtp_cls(self.host, self.port, timeout=self.timeout) as smtp:
            if self.use_tls and not self.use_ssl:
                smtp.starttls()
            if self.username:
                smtp.login(self.username, self.password or "")
            smtp.sendmail(self.from_addr, recipients, msg.as_string())


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _html_to_plain(html: str) -> str:
    """Very lightweight HTML → plain text conversion (strip tags only)."""
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
