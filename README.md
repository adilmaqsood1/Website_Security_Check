# Website Security Scanner

## Project Overview

The Website Security Scanner is a comprehensive tool designed to identify and report security vulnerabilities in websites. The system provides a robust API for scanning websites and generating detailed security reports.

## Key Features

1. **Security Scanning**: Scan websites for common security vulnerabilities including XSS, CSRF, SQL injection, and more.

2. **Comprehensive Reporting**: Generate detailed reports of identified vulnerabilities with severity ratings and remediation suggestions.

3. **Multiple Scan Types**: Support for quick scans, full scans, and custom scans with configurable options.

4. **API-First Design**: RESTful API for easy integration with other systems and applications.

## Project Structure

```
├── app/                    # Main application directory
│   ├── api/                # API endpoints
│   ├── core/               # Core functionality
│   │   ├── config/         # Application configuration
│   │   ├── scanner/        # Security scanning logic
│   ├── db/                 # Database models and connections
│   └── schemas/            # Pydantic schemas
├── data/                   # Data storage
│   └── security_reports/   # Generated security reports
├── static/                 # Static files (if any)
└── tests/                  # Test suite
```

## Getting Started

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the application: `uvicorn main:app --reload`
4. Access the API documentation at `http://localhost:8000/docs`

## API Endpoints

- `POST /api/security/scan`: Start a new security scan
- `GET /api/security/scan/{scan_id}`: Get scan details
- `GET /api/security/scans`: List all scans
- `GET /api/security/scan/{scan_id}/vulnerabilities`: Get vulnerabilities for a scan
- `GET /api/security/scan/{scan_id}/report`: Download scan report
- `POST /api/security/scan/{scan_id}/cancel`: Cancel a running scan