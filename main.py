from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
import uuid
import sqlite3
import os

# Create the FastAPI app
app = FastAPI(
    title="Website Security Scanner",
    description="A system to scan websites for security vulnerabilities",
    version="0.1.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development - restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure the database directory exists
os.makedirs("data", exist_ok=True)

# Initialize SQLite database
conn = sqlite3.connect("security_scanner.db")
cursor = conn.cursor()

# Create tables if they don't exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS security_scans (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL,
    options TEXT,
    start_time TEXT,
    end_time TEXT,
    created_at TEXT NOT NULL,
    summary TEXT,
    report_path TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    location TEXT,
    details TEXT,
    remediation TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES security_scans (id)
)
""")

conn.commit()
conn.close()

# Pydantic models
class ScanOptions(BaseModel):
    depth: Optional[int] = 2
    timeout: Optional[int] = 30
    user_agent: Optional[str] = "SecurityScanner/1.0"

class ScanRequest(BaseModel):
    url: str
    scan_type: str = "quick"  # quick, full, custom
    options: Optional[Dict[str, Any]] = {}

class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

class ScanSummary(BaseModel):
    total_vulnerabilities: int = 0
    severity_counts: SeverityCounts = SeverityCounts()

class Scan(BaseModel):
    id: str
    url: str
    scan_type: str
    status: str
    options: Optional[Dict[str, Any]] = {}
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    created_at: str
    summary: Optional[ScanSummary] = None
    report_path: Optional[str] = None

class Vulnerability(BaseModel):
    id: str
    scan_id: str
    name: str
    description: Optional[str] = None
    severity: str  # critical, high, medium, low, info
    location: Optional[str] = None
    details: Optional[Dict[str, Any]] = {}
    remediation: Optional[str] = None
    created_at: str

# Helper functions
def get_db_connection():
    conn = sqlite3.connect("security_scanner.db")
    conn.row_factory = sqlite3.Row
    return conn

def dict_to_json_str(d):
    import json
    return json.dumps(d)

def json_str_to_dict(s):
    import json
    if not s:
        return {}
    return json.loads(s)

# API Routes
@app.get("/")
def read_root():
    return {"message": "Welcome to the Website Security Scanner API"}

@app.post("/api/security/scan", response_model=Scan)
async def create_security_scan(scan_request: ScanRequest):
    scan_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    INSERT INTO security_scans 
    (id, url, scan_type, status, options, created_at) 
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        scan_id, 
        scan_request.url, 
        scan_request.scan_type, 
        "pending", 
        dict_to_json_str(scan_request.options), 
        now
    ))
    
    conn.commit()
    conn.close()
    
    # In a real application, you would start the scan in a background task
    # For this example, we'll simulate it by updating the status
    
    # Simulate starting the scan
    conn = get_db_connection()
    cursor = conn.cursor()
    start_time = datetime.now().isoformat()
    cursor.execute("""
    UPDATE security_scans 
    SET status = ?, start_time = ? 
    WHERE id = ?
    """, ("in_progress", start_time, scan_id))
    conn.commit()
    conn.close()
    
    # Return the created scan
    return Scan(
        id=scan_id,
        url=scan_request.url,
        scan_type=scan_request.scan_type,
        status="in_progress",
        options=scan_request.options,
        start_time=start_time,
        created_at=now
    )

@app.get("/api/security/scans", response_model=List[Scan])
async def get_security_scans():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM security_scans ORDER BY created_at DESC")
    rows = cursor.fetchall()
    
    scans = []
    for row in rows:
        summary = json_str_to_dict(row['summary']) if row['summary'] else None
        options = json_str_to_dict(row['options']) if row['options'] else {}
        
        scan = Scan(
            id=row['id'],
            url=row['url'],
            scan_type=row['scan_type'],
            status=row['status'],
            options=options,
            start_time=row['start_time'],
            end_time=row['end_time'],
            created_at=row['created_at'],
            summary=ScanSummary(**summary) if summary else None,
            report_path=row['report_path']
        )
        scans.append(scan)
    
    conn.close()
    return scans

@app.get("/api/security/scan/{scan_id}", response_model=Scan)
async def get_security_scan(scan_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM security_scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Scan not found")
    
    summary = json_str_to_dict(row['summary']) if row['summary'] else None
    options = json_str_to_dict(row['options']) if row['options'] else {}
    
    scan = Scan(
        id=row['id'],
        url=row['url'],
        scan_type=row['scan_type'],
        status=row['status'],
        options=options,
        start_time=row['start_time'],
        end_time=row['end_time'],
        created_at=row['created_at'],
        summary=ScanSummary(**summary) if summary else None,
        report_path=row['report_path']
    )
    
    conn.close()
    return scan

@app.get("/api/security/scan/{scan_id}/vulnerabilities", response_model=List[Vulnerability])
async def get_scan_vulnerabilities(scan_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
    rows = cursor.fetchall()
    
    vulnerabilities = []
    for row in rows:
        details = json_str_to_dict(row['details']) if row['details'] else {}
        
        vulnerability = Vulnerability(
            id=row['id'],
            scan_id=row['scan_id'],
            name=row['name'],
            description=row['description'],
            severity=row['severity'],
            location=row['location'],
            details=details,
            remediation=row['remediation'],
            created_at=row['created_at']
        )
        vulnerabilities.append(vulnerability)
    
    conn.close()
    return vulnerabilities

@app.post("/api/security/scan/{scan_id}/cancel")
async def cancel_security_scan(scan_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT status FROM security_scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if row['status'] not in ["pending", "in_progress"]:
        conn.close()
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Scan cannot be cancelled")
    
    cursor.execute("""
    UPDATE security_scans 
    SET status = 'cancelled', end_time = ? 
    WHERE id = ?
    """, (datetime.now().isoformat(), scan_id))
    
    conn.commit()
    conn.close()
    
    return {"message": "Scan cancelled successfully"}

# Run the application
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)