"""Public (unauthenticated) admin-backend endpoints — reachable even when an
admin's own session is dead (e.g. reporting a crash from admin-frontend's
error boundary). Kept separate from routes.py, where every other endpoint
under /api/admin implies "requires admin auth"."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


class FrontendErrorReport(BaseModel):
    message: str
    stack: Optional[str] = None
    path: Optional[str] = None


@router.post("/log-frontend-error")
@limiter.limit("20/minute")
async def log_frontend_error(request: Request, body: FrontendErrorReport):
    """source is hardcoded, not client-supplied — a public endpoint can't trust it."""
    from utils.error_logging import log_error
    exc_type = (body.message or "Error").split(":")[0].strip()[:50]
    log_error(
        source="admin-frontend", level="error", message=(body.message or "")[:2000],
        exc_type=exc_type, path=body.path, traceback_str=(body.stack or "")[:5000] or None,
    )
    return {"logged": True}
