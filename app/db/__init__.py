# Database initialization
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.core.db_config import db_config

# Create SQLAlchemy engine with PostgreSQL-specific configuration
# Handle case when DATABASE_URL is None
database_url = db_config.DATABASE_URL
if database_url is None:
    # Try to construct URL from individual components if available
    if db_config.PGHOST and db_config.PGUSER and db_config.PGPASSWORD and db_config.PGDATABASE:
        database_url = f"postgresql://{db_config.PGUSER}:{db_config.PGPASSWORD}@{db_config.PGHOST}/{db_config.PGDATABASE}"
    # Try Vercel Postgres URL if available
    elif db_config.POSTGRES_URL:
        database_url = db_config.POSTGRES_URL
    else:
        # Fallback to SQLite for development if no database URL is provided
        database_url = "sqlite:///./test.db"
        print("WARNING: No database URL provided, using SQLite for development")

# Convert postgres: to postgresql: if needed
if database_url and database_url.startswith('postgres:'):
    database_url = database_url.replace('postgres:', 'postgresql:')

engine = create_engine(
    database_url,
    pool_pre_ping=True,  # Verify connections before using them
    pool_size=db_config.POOL_SIZE,        # Connection pool size
    max_overflow=db_config.MAX_OVERFLOW,     # Maximum overflow connections
    pool_recycle=db_config.POOL_RECYCLE    # Recycle connections after 1 hour
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create base class for models
Base = declarative_base()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()