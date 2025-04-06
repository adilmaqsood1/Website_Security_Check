from sqlalchemy.orm import Session
from app.db import Base, engine
from app.db.models_security import SecurityScan, Vulnerability

def init_db():
    """Initialize database tables"""
    # Create all tables
    Base.metadata.create_all(bind=engine)

# Run initialization if this script is executed directly
if __name__ == "__main__":
    init_db()
    print("Database tables created successfully.")