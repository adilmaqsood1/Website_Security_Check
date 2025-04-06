from pydantic_settings import BaseSettings
from typing import List
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings(BaseSettings):
    """Application settings"""
    # API settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Website Security Scanner"
    
    # CORS settings
    CORS_ORIGINS: List[str] = ["*"]
    
    # Database settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgres://neondb_owner:npg_nRh1KyAo7jcW@ep-summer-rice-a59w093p-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require")
    
    # API Keys
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    
    # File paths
    SECURITY_REPORTS_DIR: str = os.getenv("SECURITY_REPORTS_DIR", "data/security_reports")
    REPORTS_DIR: str = os.getenv("REPORTS_DIR", "data/reports")
    RULES_DIR: str = os.getenv("RULES_DIR", "data/rules")
    LOGS_DIR: str = os.getenv("LOGS_DIR", "data/logs")
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Create settings instance
settings = Settings()