import sqlite3
import json
import uuid
from datetime import datetime, timedelta
import time
import random

def get_db_connection():
    conn = sqlite3.connect("security_scanner.db")
    conn.row_factory = sqlite3.Row
    return conn

def simulate_scan_completion():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Find in-progress scans
    cursor.execute("SELECT * FROM security_scans WHERE status = 'in_progress'")
    scans = cursor.fetchall()
    
    for scan in scans:
        # Check if the scan has been running for at least 5 seconds
        start_time = datetime.fromisoformat(scan['start_time'])
        if datetime.now() - start_time < timedelta(seconds=5):
            continue
        
        # Generate random vulnerabilities
        vulnerability_count = random.randint(0, 10)
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        # Create vulnerabilities
        for _ in range(vulnerability_count):
            severity = random.choice(["critical", "high", "medium", "low", "info"])
            severity_counts[severity] += 1
            
            vuln_id = str(uuid.uuid4())
            now = datetime.now().isoformat()
            
            cursor.execute("""
            INSERT INTO vulnerabilities 
            (id, scan_id, name, description, severity, location, details, remediation, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln_id,
                scan['id'],
                f"Sample Vulnerability {vuln_id[:8]}",
                "This is a sample vulnerability description",
                severity,
                f"{scan['url']}/sample-path",
                json.dumps({"sample": "details"}),
                "This is a sample remediation suggestion",
                now
            ))
        
        # Update scan with results
        summary = {
            "total_vulnerabilities": vulnerability_count,
            "severity_counts": severity_counts
        }
        
        end_time = datetime.now().isoformat()
        cursor.execute("""
        UPDATE security_scans 
        SET status = 'completed', end_time = ?, summary = ? 
        WHERE id = ?
        """, (end_time, json.dumps(summary), scan['id']))
    
    conn.commit()
    conn.close()

def main():
    print("Starting scan simulation service...")
    while True:
        try:
            simulate_scan_completion()
            time.sleep(2)  # Check every 2 seconds
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)  # Wait a bit longer if there's an error

if __name__ == "__main__":
    main()