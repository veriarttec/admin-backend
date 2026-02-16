"""
Admin Portal Backend - Standalone FastAPI Application
Connects to the main ArtPriv database
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from config import settings
from database import engine, Base
from routes import router
from models import Admin, ActivityLog


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create admin tables if they don't exist (skip if connection fails)
    try:
        Base.metadata.create_all(bind=engine)
        print(f"✓ Database tables initialized")
    except Exception as e:
        print(f"⚠ Warning: Could not initialize database tables: {e}")
        print(f"  Tables may need to be created manually")
    
    print(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    print(f"Database: {settings.DATABASE_URL.split('@')[1] if '@' in settings.DATABASE_URL else 'configured'}")
    yield
    print(f"Shutting down {settings.APP_NAME}")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan
)

# CORS - allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
