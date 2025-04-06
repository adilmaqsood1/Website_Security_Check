from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum

class ScanStatus(str, Enum):
    """Status of a security scan"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

class VulnerabilitySeverity(str, Enum):
    """Severity levels for vulnerabilities"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityScanBase(BaseModel):
    """Base class for website security scans"""
    url: Union[HttpUrl, List[HttpUrl]] = Field(..., description="URL or list of URLs of the website(s) to scan")
    scan_type: str = Field("full", description="Type of scan to perform (full, quick, custom)")
    options: Dict[str, Any] = Field(default={}, description="Additional scan options")

class SecurityScanCreate(SecurityScanBase):
    """Schema for creating a new security scan"""
    pass

class Vulnerability(BaseModel):
    """Schema for a detected vulnerability"""
    name: str = Field(..., description="Name of the vulnerability")
    description: str = Field(..., description="Description of the vulnerability")
    severity: VulnerabilitySeverity = Field(..., description="Severity level")
    location: str = Field(..., description="Where the vulnerability was found (URL path, header, etc.)")
    evidence: Optional[str] = Field(None, description="Evidence of the vulnerability")
    remediation: Optional[str] = Field(None, description="Suggested remediation steps")
    cwe_id: Optional[str] = Field(None, description="Common Weakness Enumeration ID")
    cvss_score: Optional[float] = Field(None, description="CVSS score if applicable")

class SecurityScan(SecurityScanBase):
    """Schema for a complete security scan with results"""
    id: str = Field(..., description="Unique identifier for the scan")
    status: ScanStatus = Field(default=ScanStatus.PENDING, description="Current status of the scan")
    start_time: Optional[datetime] = Field(None, description="When the scan started")
    end_time: Optional[datetime] = Field(None, description="When the scan completed")
    vulnerabilities: List[Vulnerability] = Field(default=[], description="Detected vulnerabilities")
    summary: Optional[Dict[str, Any]] = Field(None, description="Summary of scan results")
    created_at: datetime = Field(default_factory=datetime.now, description="When the scan was created")
    report_path: Optional[str] = Field(None, description="Path to the generated report file")
    
    class Config:
        orm_mode = True

class SecurityScanUpdate(BaseModel):
    """Schema for updating a security scan"""
    status: Optional[ScanStatus] = None
    vulnerabilities: Optional[List[Vulnerability]] = None
    summary: Optional[Dict[str, Any]] = None
    report_path: Optional[str] = None