"""
Minimal SMTP email service — admin-backend only needs this for error alert
emails. Donor invite / password reset emails are art-connect-backend's
concern; this is a deliberate, small, adapted copy, not a shared import
(these are two separately deployed codebases).
"""

import json
import logging
import smtplib
import urllib.error
import urllib.request
from email.message import EmailMessage
from datetime import datetime
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)


BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


def is_email_configured() -> bool:
    return bool(settings.BREVO_API_KEY or (settings.SMTP_HOST and settings.SMTP_USERNAME))


def _send_via_brevo_api(to: str, subject: str, html_body: str, text_body: Optional[str]) -> None:
    """Send through Brevo's HTTPS API. Used on hosts that block outbound SMTP ports (Railway)."""
    payload = {
        "sender": {"name": settings.SMTP_FROM_NAME, "email": settings.SMTP_FROM_EMAIL or settings.ALERT_EMAIL},
        "to": [{"email": to}],
        "subject": subject,
        "htmlContent": html_body,
        "textContent": text_body or "This email is best viewed in an HTML-capable client.",
    }
    request = urllib.request.Request(
        BREVO_API_URL, data=json.dumps(payload).encode(), method="POST",
        headers={"api-key": settings.BREVO_API_KEY, "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20):
            pass
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Brevo API {e.code}: {e.read().decode(errors='replace')[:300]}") from None


def send_email(to: str, subject: str, html_body: str, text_body: Optional[str] = None) -> bool:
    """Send a single email. Returns True on success, False when skipped or failed."""
    if not is_email_configured():
        logger.warning("Email not configured; skipping email to %s (%s)", to, subject)
        return False

    if settings.BREVO_API_KEY:
        try:
            _send_via_brevo_api(to, subject, html_body, text_body)
            logger.info("Email sent to %s (%s)", to, subject)
            return True
        except Exception as e:
            logger.error("Failed to send email to %s (%s): %s", to, subject, e)
            return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL or settings.SMTP_USERNAME}>"
    message["To"] = to
    message.set_content(text_body or "This email is best viewed in an HTML-capable client.")
    message.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.send_message(message)
        logger.info("Email sent to %s (%s)", to, subject)
        return True
    except Exception as e:
        logger.error("Failed to send email to %s (%s): %s", to, subject, e)
        return False


def _layout(title: str, body_html: str) -> str:
    return f"""\
<div style="font-family: Arial, Helvetica, sans-serif; max-width: 560px; margin: 0 auto; color: #494F55;">
  <div style="background: #193A57; padding: 20px 28px; border-radius: 8px 8px 0 0;">
    <span style="color: #FAFEFF; font-size: 20px; font-weight: bold;">VeriART</span>
  </div>
  <div style="border: 1px solid #E8DDD2; border-top: none; border-radius: 0 0 8px 8px; padding: 28px;">
    <h2 style="margin-top: 0; color: #193A57;">{title}</h2>
    {body_html}
    <p style="font-size: 12px; color: #8a9099; margin-top: 32px;">
      This is an automated message from VeriART. If you were not expecting it, you can safely ignore this email.
    </p>
  </div>
</div>"""


def send_error_alert_email(
    source: str, message: str, occurrence_count: int,
    first_seen_at: datetime, last_seen_at: datetime, error_log_id: str,
) -> bool:
    subject = f"[VeriART Alert] {source}: {(message or '')[:80]}"
    admin_link = f"{settings.ADMIN_PANEL_URL.rstrip('/')}/error-logs?id={error_log_id}" if settings.ADMIN_PANEL_URL else None
    body = f"""\
    <p><strong>Source:</strong> {source}</p>
    <p><strong>Message:</strong> {message}</p>
    <p><strong>Occurrences:</strong> {occurrence_count}</p>
    <p><strong>First seen:</strong> {first_seen_at}</p>
    <p><strong>Last seen:</strong> {last_seen_at}</p>
    {f'<p style="margin: 24px 0;"><a href="{admin_link}" style="background: #193A57; color: #FAFEFF; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold;">View in admin panel</a></p>' if admin_link else ''}"""
    return send_email(settings.ALERT_EMAIL, subject, _layout("Error alert", body))
