"""
Admin Portal Backend Configuration
All settings are configurable via environment variables
"""
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # Supabase Configuration
    SUPABASE_URL: str = "https://your-project.supabase.co"
    SUPABASE_KEY: str = "your-anon-key"
    SUPABASE_SERVICE_KEY: str = "your-service-key"
    
    # Database - PostgreSQL connection string
    # For Supabase: postgresql://postgres.[project-ref]:[password]@[host]:5432/postgres
    DATABASE_URL: str = "postgresql://user:password@localhost:5432/artpriv"
    
    # JWT Configuration - should match main application for token compatibility
    SECRET_KEY: str = "change-this-secret-key"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # App Configuration
    APP_NAME: str = "ArtPriv Admin Portal"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # CORS - comma-separated list of allowed origins
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:3001"
    
    # File Upload
    MAX_FILE_SIZE: int = 10485760  # 10MB
    
    # Supabase Storage Buckets
    BUCKET_CERTIFICATIONS: str = "certification-documents"
    BUCKET_CONSENT_FORMS: str = "consent-forms"
    BUCKET_TEST_REPORTS: str = "test-reports"
    BUCKET_COUNSELING_REPORTS: str = "counseling-reports"
    
    class Config:
        # Make .env file optional - Railway uses environment variables directly
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"
        
    @property
    def origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",")]


settings = Settings()
