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

# CORS - allow configured origins or all for development
# For production, set ALLOWED_ORIGINS in Railway env vars
origins = settings.origins_list if settings.ALLOWED_ORIGINS != "http://localhost:3000,http://localhost:3001" else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
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
