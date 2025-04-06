from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.db import Base
from app.schemas.security_scan import ScanStatus, VulnerabilitySeverity


def generate_uuid():
    """Generate a unique UUID for database records"""
    return str(uuid.uuid4())


class SecurityScan(Base):
    """Model for website security scans"""
    __tablename__ = "security_scans"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    url = Column(String, nullable=False, index=True)
    scan_type = Column(String, nullable=False, default="full")
    status = Column(String, nullable=False, default=ScanStatus.PENDING)
    options = Column(JSON, default=dict)
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    summary = Column(JSON, nullable=True)
    report_path = Column(String, nullable=True)
    
    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="scan")
    
    def __repr__(self):
        return f"<SecurityScan {self.url}>"


class Vulnerability(Base):
    """Model for detected vulnerabilities"""
    __tablename__ = "vulnerabilities"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String, nullable=False, index=True)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False, default=VulnerabilitySeverity.MEDIUM)
    location = Column(String, nullable=False)
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    cwe_id = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    
    # Relationships
    scan_id = Column(String, ForeignKey("security_scans.id"))
    scan = relationship("SecurityScan", back_populates="vulnerabilities")
    
    def __repr__(self):
        return f"<Vulnerability {self.name}>"