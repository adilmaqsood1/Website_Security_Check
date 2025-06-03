from typing import Optional
from pydantic_settings import BaseSettings

class DatabaseConfig(BaseSettings):
    """Database configuration settings"""
    # Static database configuration
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/security_scanner"
    DATABASE_URL_UNPOOLED: str = "postgresql://postgres:postgres@localhost:5432/security_scanner"
    
    # Connection pool settings
    POOL_SIZE: int = 5
    MAX_OVERFLOW: int = 10
    POOL_RECYCLE: int = 3600  # 1 hour
    
    # PostgreSQL connection parameters
    PGHOST: str = "localhost"
    PGHOST_UNPOOLED: str = "localhost"
    PGUSER: str = "postgres"
    PGDATABASE: str = "security_scanner"
    PGPASSWORD: str = "postgres"
    
    # Vercel Postgres parameters - these are causing validation errors, so we'll make them optional
    POSTGRES_URL: Optional[str] = None
    POSTGRES_URL_NON_POOLING: Optional[str] = None
    POSTGRES_USER: Optional[str] = None
    POSTGRES_HOST: Optional[str] = None
    POSTGRES_PASSWORD: Optional[str] = None
    POSTGRES_DATABASE: Optional[str] = None
    POSTGRES_URL_NO_SSL: Optional[str] = None
    POSTGRES_PRISMA_URL: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"  # Allow extra fields in environment variables

# Create a singleton instance
db_config = DatabaseConfig()