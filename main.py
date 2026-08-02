"""
Admin Portal Backend - Standalone FastAPI Application
Connects to the main ArtPriv database
"""
import os
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from slowapi.errors import RateLimitExceeded

from config import settings
from database import engine, Base
from routes import router, limiter
from public_routes import router as public_router
from models import Admin, ActivityLog

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create admin tables if they don't exist
    Base.metadata.create_all(bind=engine)
    logger.info("Starting %s v%s", settings.APP_NAME, settings.APP_VERSION)
    yield
    logger.info("Shutting down %s", settings.APP_NAME)


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan
)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please try again later."},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    import traceback
    from utils.error_logging import log_error

    tb_str = traceback.format_exc()
    logger.error("Unhandled exception on %s %s", request.method, request.url.path, exc_info=exc)
    try:
        log_error(
            source="admin-backend", level="error", message=str(exc),
            exc_type=type(exc).__name__, path=request.url.path, method=request.method,
            status_code=500, traceback_str=tb_str,
        )
    except Exception:
        logger.exception("Failed to log unhandled exception")

    return JSONResponse(status_code=500, content={"detail": "An unexpected error occurred. Please try again later."})

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins_list,
    # Railway-hosted frontends stay unblocked even before ALLOWED_ORIGINS is
    # configured; scope is limited to Railway-owned hostnames.
    allow_origin_regex=r"https://.*\.(up\.railway\.app|veriart-tec\.in)",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

# Include admin routes
app.include_router(router, prefix="/api/admin", tags=["Admin"])
app.include_router(public_router, prefix="/api/public", tags=["Public"])


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running"
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
