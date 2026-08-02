"""
Centralized error logging: dedups recurring errors by fingerprint and sends
a cooldown-gated alert email so the same bug firing repeatedly doesn't flood
the error_logs table or spam the inbox.
"""
import re
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from database import SessionLocal
from models import ErrorLog

logger = logging.getLogger(__name__)

_DYNAMIC_TOKEN_RE = re.compile(r"[0-9a-fA-F-]{8,}|\d+")
DEDUP_WINDOW_HOURS = 24
ALERT_COOLDOWN_MINUTES = 30


def _fingerprint(source: str, exc_type: str, path: str, message: str) -> str:
    normalized = _DYNAMIC_TOKEN_RE.sub("#", message or "")[:120]
    raw = f"{source}|{exc_type}|{path or ''}|{normalized}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def log_error(
    source: str,
    level: str,
    message: str,
    exc_type: str = "Error",
    path: Optional[str] = None,
    method: Optional[str] = None,
    status_code: Optional[int] = None,
    traceback_str: Optional[str] = None,
    user_type: Optional[str] = None,
    user_id: Optional[str] = None,
    cooldown_minutes: int = ALERT_COOLDOWN_MINUTES,
) -> None:
    """Record an error (dedup by fingerprint) and send a cooldown-gated alert
    email. Never raises — logging must not itself break the request."""
    db = SessionLocal()
    try:
        fp = _fingerprint(source, exc_type, path or "", message)
        now = datetime.now(timezone.utc)
        existing = (
            db.query(ErrorLog)
            .filter(
                ErrorLog.fingerprint == fp,
                ErrorLog.last_seen_at >= now - timedelta(hours=DEDUP_WINDOW_HOURS),
            )
            .order_by(ErrorLog.last_seen_at.desc())
            .first()
        )

        should_alert = False
        if existing:
            existing.occurrence_count += 1
            existing.last_seen_at = now
            if traceback_str:
                existing.traceback = traceback_str
            if existing.email_sent_at is None or (now - existing.email_sent_at) > timedelta(minutes=cooldown_minutes):
                should_alert = True
                existing.email_sent_at = now
            row = existing
        else:
            row = ErrorLog(
                source=source, level=level, message=(message or "")[:2000], fingerprint=fp,
                path=path, method=method, status_code=status_code, traceback=traceback_str,
                user_type=user_type, user_id=user_id, occurrence_count=1,
                first_seen_at=now, last_seen_at=now, email_sent_at=now,
            )
            db.add(row)
            should_alert = True

        db.commit()

        if should_alert:
            occurrence_count = row.occurrence_count
            first_seen_at = row.first_seen_at
            last_seen_at = row.last_seen_at
            row_id = row.id
            try:
                from utils.email import is_email_configured, send_error_alert_email
                if is_email_configured():
                    send_error_alert_email(
                        source=source, message=message, occurrence_count=occurrence_count,
                        first_seen_at=first_seen_at, last_seen_at=last_seen_at, error_log_id=row_id,
                    )
            except Exception:
                logger.exception("Failed to send error alert email")
    except Exception:
        logger.exception("Failed to record error log (source=%s)", source)
        db.rollback()
    finally:
        db.close()
