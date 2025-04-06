from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status, Response
from fastapi.responses import FileResponse
from typing import List, Optional, Dict, Any, Union
from sqlalchemy.orm import Session
import os
import json
import uuid
from datetime import datetime
import httpx

from app.core.config import settings
from app.schemas.security_scan import SecurityScanCreate, SecurityScan, SecurityScanUpdate, Vulnerability
from app.db import get_db
from app.db.models_security import SecurityScan as SecurityScanModel, Vulnerability as VulnerabilityModel
from app.core.scanner.security_scanner import SecurityScanner

# Create security router
security_router = APIRouter(prefix="/security", tags=["security"])

# Background task for running security scans
async def run_security_scan(scan_id: str, url: Union[str, List[str]], scan_type: str, options: Dict[str, Any], db: Session):
    """Run a security scan in the background"""
    try:
        # Get scan from database
        db_scan = db.query(SecurityScanModel).filter(SecurityScanModel.id == scan_id).first()
        if not db_scan:
            return
        
        # Update scan status
        db_scan.status = "in_progress"
        db_scan.start_time = datetime.now()
        db.commit()
        
        # Handle multiple URLs
        if isinstance(url, list):
            # Create a combined results dictionary
            combined_results = {
                "vulnerabilities": [],
                "summary": {
                    "total_vulnerabilities": 0,
                    "severity_counts": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "info": 0
                    },
                    "scan_duration": 0,
                    "pages_scanned": 0
                }
            }
            
            # Scan each URL
            for single_url in url:
                scanner = SecurityScanner(url=str(single_url), scan_type=scan_type, options=options)
                url_results = await scanner.scan()
                
                # Merge results
                combined_results["vulnerabilities"].extend(url_results["vulnerabilities"])
                combined_results["summary"]["total_vulnerabilities"] += url_results["summary"]["total_vulnerabilities"]
                combined_results["summary"]["pages_scanned"] += url_results["summary"]["pages_scanned"]
                
                # Merge severity counts
                for severity, count in url_results["summary"]["severity_counts"].items():
                    combined_results["summary"]["severity_counts"][severity] += count
                
                # Add scan duration
                combined_results["summary"]["scan_duration"] += url_results["summary"]["scan_duration"]
            
            results = combined_results
        else:
            # Run the scan for a single URL
            scanner = SecurityScanner(url=str(url), scan_type=scan_type, options=options)
            results = await scanner.scan()
        
        # Update scan with results
        db_scan.status = "completed"
        db_scan.end_time = datetime.now()
        db_scan.summary = results["summary"]
        db.commit()
        
        # Create vulnerability entries
        for vuln_data in results["vulnerabilities"]:
            vulnerability = VulnerabilityModel(
                name=vuln_data["name"],
                description=vuln_data["description"],
                severity=vuln_data["severity"],
                location=vuln_data["location"],
                evidence=vuln_data.get("evidence"),
                remediation=vuln_data.get("remediation"),
                cwe_id=vuln_data.get("cwe_id"),
                cvss_score=vuln_data.get("cvss_score"),
                scan_id=scan_id
            )
            db.add(vulnerability)
        
        db.commit()
        
        # Generate report file
        os.makedirs("data/security_reports", exist_ok=True)
        report_path = f"data/security_reports/{scan_id}.json"
        
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        
        # Update scan with report path
        db_scan.report_path = report_path
        db.commit()
        
    except Exception as e:
        # Update scan status on error
        db_scan = db.query(SecurityScanModel).filter(SecurityScanModel.id == scan_id).first()
        if db_scan:
            db_scan.status = "failed"
            db_scan.end_time = datetime.now()
            db_scan.summary = {"error": str(e)}
            db.commit()

@security_router.post("/scan", response_model=SecurityScan, status_code=status.HTTP_201_CREATED)
async def create_security_scan(scan: SecurityScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Create a new security scan for a website"""
    # Handle both single URL and list of URLs
    # For database storage, we'll use the first URL or convert list to string
    if isinstance(scan.url, list):
        primary_url = str(scan.url[0]) if scan.url else ""
        url_for_db = primary_url
    else:
        url_for_db = str(scan.url)
    
    # Create scan entry in database
    db_scan = SecurityScanModel(
        url=url_for_db,
        scan_type=scan.scan_type,
        options=scan.options,
        status="pending"
    )
    
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    # Start scan in background
    background_tasks.add_task(
        run_security_scan,
        scan_id=db_scan.id,
        url=scan.url,  # Pass the original URL (single or list)
        scan_type=scan.scan_type,
        options=scan.options,
        db=db
    )
    
    return db_scan

@security_router.get("/scan/{scan_id}", response_model=SecurityScan)
async def get_security_scan(scan_id: str, db: Session = Depends(get_db)):
    """Get a security scan by ID"""
    scan = db.query(SecurityScanModel).filter(SecurityScanModel.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Security scan not found")
    
    return scan

@security_router.get("/scans", response_model=List[SecurityScan])
async def get_security_scans(db: Session = Depends(get_db)):
    """Get all security scans"""
    scans = db.query(SecurityScanModel).all()
    return scans

@security_router.get("/scan/{scan_id}/vulnerabilities", response_model=List[Vulnerability])
async def get_scan_vulnerabilities(scan_id: str, db: Session = Depends(get_db)):
    """Get vulnerabilities for a specific scan"""
    scan = db.query(SecurityScanModel).filter(SecurityScanModel.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Security scan not found")
    
    return scan.vulnerabilities

@security_router.get("/scan/{scan_id}/report")
async def download_scan_report(scan_id: str, db: Session = Depends(get_db)):
    """Download the security scan report"""
    scan = db.query(SecurityScanModel).filter(SecurityScanModel.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Security scan not found")
    
    if not scan.report_path or not os.path.exists(scan.report_path):
        raise HTTPException(status_code=404, detail="Report not found")
    
    return FileResponse(
        path=scan.report_path,
        filename=f"security_scan_{scan_id}.json",
        media_type="application/json"
    )

@security_router.post("/scan/{scan_id}/cancel", response_model=SecurityScan)
async def cancel_security_scan(scan_id: str, db: Session = Depends(get_db)):
    """Cancel a running security scan"""
    scan = db.query(SecurityScanModel).filter(SecurityScanModel.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Security scan not found")
    
    if scan.status != "in_progress" and scan.status != "pending":
        raise HTTPException(status_code=400, detail="Scan is not in progress or pending")
    
    scan.status = "failed"
    scan.end_time = datetime.now()
    scan.summary = {"error": "Scan was cancelled by user"}
    
    db.commit()
    db.refresh(scan)
    
    return scan