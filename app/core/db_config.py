from typing import Optional
import os

class DatabaseConfig:
    """Database configuration settings"""
    # Main connection URL
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgres://neondb_owner:npg_nRh1KyAo7jcW@ep-summer-rice-a59w093p-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require")
    DATABASE_URL_UNPOOLED: str = os.getenv("DATABASE_URL_UNPOOLED", "postgresql://neondb_owner:npg_nRh1KyAo7jcW@ep-summer-rice-a59w093p.us-east-2.aws.neon.tech/neondb?sslmode=require")
    
    # Connection pool settings
    POOL_SIZE: int = int(os.getenv("POOL_SIZE", "5"))
    MAX_OVERFLOW: int = int(os.getenv("MAX_OVERFLOW", "10"))
    POOL_RECYCLE: int = int(os.getenv("POOL_RECYCLE", "3600"))  # 1 hour
    
    # PostgreSQL connection parameters
    PGHOST: str = os.getenv("PGHOST", "ep-summer-rice-a59w093p-pooler.us-east-2.aws.neon.tech")
    PGHOST_UNPOOLED: str = os.getenv("PGHOST_UNPOOLED", "ep-summer-rice-a59w093p.us-east-2.aws.neon.tech")
    PGUSER: str = os.getenv("PGUSER", "neondb_owner")
    PGDATABASE: str = os.getenv("PGDATABASE", "neondb")
    PGPASSWORD: str = os.getenv("PGPASSWORD", "npg_nRh1KyAo7jcW")
    
    # Vercel Postgres parameters
    POSTGRES_URL: str = os.getenv("POSTGRES_URL", "postgres://neondb_owner:npg_nRh1KyAo7jcW@ep-summer-rice-a59w093p-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require")
    POSTGRES_URL_NON_POOLING: str = os.getenv("POSTGRES_URL_NON_POOLING", "postgres://neondb_owner:npg_nRh1KyAo7jcW@ep-summer-rice-a59w093p.us-east-2.aws.neon.tech/neondb?sslmode=require")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "neondb_owner")
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "ep-summer-rice-a59w093p-pooler.us-east-2.aws.neon.tech")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "npg_nRh1KyAo7jcW")
    POSTGRES_DATABASE: str = os.getenv("POSTGRES_DATABASE", "neondb")
    POSTGRES_URL_NO_SSL: str = os.getenv("POSTGRES_URL_NO_SSL", "postgres://neondb_owner:npg_nRh1KyAo7jcW@ep-summer-rice-a59w093p-pooler.us-east-2.aws.neon.tech/neondb")
    POSTGRES_PRISMA_URL: str = os.getenv("POSTGRES_PRISMA_URL", "postgres://neondb_owner:npg_nRh1KyAo7jcW@ep-summer-rice-a59w093p-pooler.us-east-2.aws.neon.tech/neondb?connect_timeout=15&sslmode=require")

# Create a singleton instance
db_config = DatabaseConfig()