"""
Admin Portal Backend - Standalone FastAPI Application
Connects to the main ArtPriv database
"""
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import traceback

from config import settings
from database import engine, Base
from routes import router
from models import Admin, ActivityLog



@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    
    # Test database connection and create tables if possible
    try:
        # Test connection first
        with engine.connect() as connection:
            print(f"✓ Database connected successfully")
        
        # Try to create tables
        Base.metadata.create_all(bind=engine)
        print(f"✓ Database tables initialized")
    except Exception as e:
        print(f"⚠ Warning: Database connection issue: {e}")
        print(f"  Application will start but database operations will fail")
        print(f"  Please check your DATABASE_URL environment variable")
    
    yield
    print(f"Shutting down {settings.APP_NAME}")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan
)

# CORS - allow all origins and routes for now
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=False,  # Must be False when allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"Global exception: {exc}")
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error", "error": str(exc)},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*",
        }
    )

# Include admin routes
app.include_router(router, prefix="/api/admin", tags=["Admin"])


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
