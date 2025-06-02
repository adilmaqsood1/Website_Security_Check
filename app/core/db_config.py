from typing import Optional
import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class DatabaseConfig(BaseSettings):
    """Database configuration settings"""
    # Main connection URL - Railway will provide DATABASE_URL environment variable
    DATABASE_URL: Optional[str] = None
    DATABASE_URL_UNPOOLED: Optional[str] = None
    
    # Connection pool settings
    POOL_SIZE: int = 5
    MAX_OVERFLOW: int = 10
    POOL_RECYCLE: int = 3600  # 1 hour
    
    # PostgreSQL connection parameters
    PGHOST: Optional[str] = None
    PGHOST_UNPOOLED: Optional[str] = None
    PGUSER: Optional[str] = None
    PGDATABASE: Optional[str] = None
    PGPASSWORD: Optional[str] = None
    
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