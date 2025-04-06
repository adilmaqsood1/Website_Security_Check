import httpx
import asyncio
import re
import json
import uuid
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import random
import time

from app.core.config import settings
from app.schemas.security_scan import Vulnerability, VulnerabilitySeverity


class SecurityScanner:
    """Website security scanner that checks for common vulnerabilities"""
    
    def __init__(self, url: str, scan_type: str = "full", options: Dict[str, Any] = None):
        self.url = url
        self.scan_type = scan_type
        self.options = options or {}
        self.results = {
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
        self.start_time = None
        self.end_time = None
        self.client = httpx.AsyncClient(follow_redirects=True, timeout=30.0)
        self.visited_urls = set()
        # Increase default max_pages to scan more of the website
        self.max_pages = self.options.get("max_pages", 100)
    
    async def scan(self) -> Dict[str, Any]:
        """Run the security scan on the target website"""
        self.start_time = datetime.now()
        
        try:
            # Basic connectivity check
            await self.check_connectivity()
            
            # Run security checks based on scan type
            if self.scan_type == "quick":
                await self.run_quick_scan()
            elif self.scan_type == "full":
                await self.run_full_scan()
            elif self.scan_type == "custom":
                await self.run_custom_scan()
            else:
                await self.run_quick_scan()  # Default to quick scan
                
            # Update summary statistics
            self.update_summary()
            
            return self.results
        finally:
            self.end_time = datetime.now()
            self.results["summary"]["scan_duration"] = (self.end_time - self.start_time).total_seconds()
            await self.client.aclose()
    
    async def check_connectivity(self) -> None:
        """Check if the target website is accessible"""
        try:
            response = await self.client.get(self.url)
            if response.status_code >= 400:
                self.add_vulnerability(
                    name="Website Inaccessible",
                    description=f"The website returned HTTP status code {response.status_code}",
                    severity=VulnerabilitySeverity.HIGH,
                    location=self.url,
                    evidence=f"HTTP {response.status_code}: {response.reason_phrase}"
                )
        except httpx.RequestError as e:
            self.add_vulnerability(
                name="Connection Failed",
                description="Could not establish a connection to the website",
                severity=VulnerabilitySeverity.CRITICAL,
                location=self.url,
                evidence=str(e)
            )
    
    async def run_quick_scan(self) -> None:
        """Run a quick security scan with basic checks"""
        # Scan the main page only
        await self.scan_page(self.url)
        
        # Run basic security checks
        await self.check_ssl_tls()
        await self.check_security_headers()
        await self.check_basic_xss()
    
    async def run_full_scan(self) -> None:
        """Run a comprehensive security scan"""
        # Start with quick scan
        await self.run_quick_scan()
        
        # Additional checks
        await self.crawl_and_scan_site()
        await self.check_csrf_protection()
        await self.check_sql_injection()
        await self.check_open_redirects()
        await self.check_information_disclosure()
    
    async def run_custom_scan(self) -> None:
        """Run a custom security scan based on provided options"""
        # Get enabled checks from options
        checks = self.options.get("checks", [])
        
        # Run selected checks
        if "ssl_tls" in checks:
            await self.check_ssl_tls()
        if "security_headers" in checks:
            await self.check_security_headers()
        if "xss" in checks:
            await self.check_basic_xss()
        if "csrf" in checks:
            await self.check_csrf_protection()
        if "sql_injection" in checks:
            await self.check_sql_injection()
        if "open_redirects" in checks:
            await self.check_open_redirects()
        if "information_disclosure" in checks:
            await self.check_information_disclosure()
        if "crawl" in checks:
            await self.crawl_and_scan_site()
    
    async def scan_page(self, url: str) -> None:
        """Scan a single page for vulnerabilities"""
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        self.results["summary"]["pages_scanned"] += 1
        
        try:
            response = await self.client.get(url)
            
            # Check for vulnerabilities in this page
            await self.check_page_vulnerabilities(url, response)
            
        except httpx.RequestError:
            # Skip pages that can't be accessed
            pass
    
    async def crawl_and_scan_site(self) -> None:
        """Crawl the website and scan each page"""
        to_visit = [self.url]
        
        while to_visit and len(self.visited_urls) < self.max_pages:
            url = to_visit.pop(0)
            
            if url in self.visited_urls:
                continue
                
            try:
                response = await self.client.get(url)
                
                # Extract links from the page before scanning to build a more complete queue
                if response.status_code == 200 and "text/html" in response.headers.get("content-type", ""):
                    soup = BeautifulSoup(response.text, "html.parser")
                    base_url = urlparse(url)
                    
                    for link in soup.find_all("a", href=True):
                        href = link["href"]
                        # Skip anchor links and javascript links
                        if href.startswith("#") or href.startswith("javascript:"):
                            continue
                            
                        # Handle relative URLs
                        if not href.startswith("http"):
                            href = urljoin(url, href)
                        
                        # Only add URLs from the same domain that haven't been visited or queued
                        parsed_href = urlparse(href)
                        if parsed_href.netloc == base_url.netloc and href not in self.visited_urls and href not in to_visit:
                            to_visit.append(href)
                
                # Now scan the page for vulnerabilities
                await self.scan_page(url)
                
                # Log progress
                if len(self.visited_urls) % 10 == 0:
                    print(f"Scanned {len(self.visited_urls)} pages, {len(to_visit)} pages in queue")
            
            except httpx.RequestError as e:
                # Skip pages that can't be accessed but log the error
                print(f"Error accessing {url}: {str(e)}")
                continue
    
    async def check_page_vulnerabilities(self, url: str, response: httpx.Response) -> None:
        """Check a page for various vulnerabilities"""
        # Check for sensitive information disclosure
        await self.check_page_information_disclosure(url, response)
        
        # Check for XSS vulnerabilities in forms
        if "text/html" in response.headers.get("content-type", ""):
            soup = BeautifulSoup(response.text, "html.parser")
            await self.check_page_xss_vulnerabilities(url, soup)
            await self.check_page_csrf_vulnerabilities(url, soup)
    
    async def check_ssl_tls(self) -> None:
        """Check SSL/TLS configuration"""
        parsed_url = urlparse(self.url)
        if parsed_url.scheme != "https":
            self.add_vulnerability(
                name="Insecure Protocol",
                description="The website is not using HTTPS",
                severity=VulnerabilitySeverity.HIGH,
                location=self.url,
                evidence="URL uses HTTP instead of HTTPS",
                remediation="Configure the web server to use HTTPS and redirect all HTTP traffic to HTTPS",
                cwe_id="CWE-319"
            )
    
    async def check_security_headers(self) -> None:
        """Check for important security headers"""
        try:
            from app.core.ai.groq_client import GroqClient
            
            response = await self.client.get(self.url)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                "Strict-Transport-Security": {
                    "severity": VulnerabilitySeverity.MEDIUM,
                    "description": "Missing HSTS header",
                    "remediation": "Add the Strict-Transport-Security header with appropriate values",
                    "cwe_id": "CWE-319"
                },
                "Content-Security-Policy": {
                    "severity": VulnerabilitySeverity.MEDIUM,
                    "description": "Missing Content Security Policy",
                    "remediation": "Implement a Content Security Policy to prevent XSS attacks",
                    "cwe_id": "CWE-1021"
                },
                "X-Content-Type-Options": {
                    "severity": VulnerabilitySeverity.LOW,
                    "description": "Missing X-Content-Type-Options header",
                    "remediation": "Add the X-Content-Type-Options header with 'nosniff' value",
                    "cwe_id": "CWE-693"
                },
                "X-Frame-Options": {
                    "severity": VulnerabilitySeverity.LOW,
                    "description": "Missing X-Frame-Options header",
                    "remediation": "Add the X-Frame-Options header to prevent clickjacking",
                    "cwe_id": "CWE-1021"
                },
                "X-XSS-Protection": {
                    "severity": VulnerabilitySeverity.LOW,
                    "description": "Missing X-XSS-Protection header",
                    "remediation": "Add the X-XSS-Protection header to enable browser XSS protection",
                    "cwe_id": "CWE-79"
                }
            }
            
            # Initialize Groq client for dynamic remediation generation
            groq_client = None
            try:
                groq_client = GroqClient()
            except ValueError as e:
                # Continue without dynamic remediation if API key is not set
                print(f"Warning: {str(e)}. Using default remediation guidance.")
            
            for header, info in security_headers.items():
                if header not in headers:
                    # Generate dynamic remediation if Groq client is available
                    remediation = info["remediation"]
                    if groq_client:
                        try:
                            dynamic_remediation = await self.generate_dynamic_remediation(
                                groq_client,
                                f"Missing {header} Header",
                                info["description"],
                                header,
                                info["cwe_id"]
                            )
                            if dynamic_remediation:
                                remediation = dynamic_remediation
                        except Exception as e:
                            # Fall back to default remediation if generation fails
                            print(f"Error generating remediation: {str(e)}")
                    
                    self.add_vulnerability(
                        name=f"Missing {header} Header",
                        description=info["description"],
                        severity=info["severity"],
                        location=self.url,
                        evidence=f"Header not present in response",
                        remediation=remediation,
                        cwe_id=info["cwe_id"]
                    )
        
        except httpx.RequestError as e:
            # Skip if we can't access the page
            pass
    
    async def generate_dynamic_remediation(self, 
                                         groq_client, 
                                         vulnerability_name: str, 
                                         vulnerability_description: str,
                                         header_name: str,
                                         cwe_id: str) -> str:
        """Generate dynamic remediation guidance using Groq API
        
        Args:
            groq_client: Initialized GroqClient instance
            vulnerability_name: Name of the vulnerability
            vulnerability_description: Description of the vulnerability
            header_name: Name of the security header
            cwe_id: Common Weakness Enumeration ID
            
        Returns:
            Detailed remediation guidance as a string
        """
        return await groq_client.generate_remediation(
            vulnerability_name,
            vulnerability_description,
            header_name,
            cwe_id
        )
    
    async def check_basic_xss(self) -> None:
        """Check for basic XSS vulnerabilities"""
        # This is a simplified check - in a real scanner, more sophisticated tests would be used
        try:
            # Test for reflected XSS by adding a parameter to the URL
            test_payload = "<script>alert(1)</script>"
            test_url = f"{self.url}?test={test_payload}"
            
            response = await self.client.get(test_url)
            
            if test_payload in response.text:
                # Default remediation message
                remediation = "Implement proper input validation and output encoding"
                
                # Initialize Groq client for dynamic remediation generation
                groq_client = None
                try:
                    from app.core.ai.groq_client import GroqClient
                    groq_client = GroqClient()
                except ValueError as e:
                    # Continue without dynamic remediation if API key is not set
                    print(f"Warning: {str(e)}. Using default remediation guidance.")
                except ImportError:
                    # Continue without dynamic remediation if module is not available
                    print("Warning: GroqClient not available. Using default remediation guidance.")
                
                # Generate dynamic remediation if Groq client is available
                if groq_client:
                    try:
                        dynamic_remediation = await self.generate_dynamic_remediation(
                            groq_client,
                            "Potential Reflected XSS",
                            "The application may be vulnerable to reflected Cross-Site Scripting",
                            None,  # No header name for this vulnerability
                            "CWE-79"
                        )
                        if dynamic_remediation:
                            remediation = dynamic_remediation
                    except Exception as e:
                        # Fall back to default remediation if generation fails
                        print(f"Error generating remediation: {str(e)}")
                
                self.add_vulnerability(
                    name="Potential Reflected XSS",
                    description="The application may be vulnerable to reflected Cross-Site Scripting",
                    severity=VulnerabilitySeverity.HIGH,
                    location=test_url,
                    evidence=f"Payload was reflected in the response",
                    remediation=remediation,
                    cwe_id="CWE-79"
                )
        
        except httpx.RequestError:
            # Skip if we can't access the page
            pass
    
    async def check_csrf_protection(self) -> None:
        """Check for CSRF protection in forms"""
        try:
            response = await self.client.get(self.url)
            
            if "text/html" in response.headers.get("content-type", ""):
                soup = BeautifulSoup(response.text, "html.parser")
                forms = soup.find_all("form", method=lambda m: m and m.lower() == "post")
                
                for form in forms:
                    # Check for CSRF tokens in the form
                    csrf_fields = form.find_all("input", attrs={
                        "name": re.compile(r"csrf|token|nonce", re.I)
                    })
                    
                    if not csrf_fields:
                        self.add_vulnerability(
                            name="Missing CSRF Protection",
                            description="A form was found without CSRF protection",
                            severity=VulnerabilitySeverity.MEDIUM,
                            location=f"{self.url}#{form.get('id', '')}",
                            evidence=str(form)[:100] + "...",
                            remediation="Implement CSRF tokens for all forms",
                            cwe_id="CWE-352"
                        )
        
        except httpx.RequestError:
            # Skip if we can't access the page
            pass
    
    async def check_sql_injection(self) -> None:
        """Check for SQL injection vulnerabilities"""
        # This is a simplified check - in a real scanner, more sophisticated tests would be used
        try:
            # Parse the URL to find parameters
            parsed_url = urlparse(self.url)
            if parsed_url.query:
                params = dict([param.split('=') for param in parsed_url.query.split('&') if '=' in param])
                
                # Test each parameter for SQL injection
                for param, value in params.items():
                    test_payloads = ["' OR '1'='1", "1' OR '1'='1", "1 OR 1=1"]
                    
                    for payload in test_payloads:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        # Construct the test URL
                        query_string = "&".join([f"{k}={v}" for k, v in test_params.items()])
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                        
                        # Send the request
                        response = await self.client.get(test_url)
                        
                        # Check for signs of SQL injection
                        # Look for database errors or unexpected behavior
                        sql_error_patterns = [
                            "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
                            "SQLite", "SQLSTATE", "syntax error", "unclosed quotation"
                        ]
                        
                        for pattern in sql_error_patterns:
                            if pattern.lower() in response.text.lower():
                                self.add_vulnerability(
                                    name="Potential SQL Injection",
                                    description=f"The parameter '{param}' may be vulnerable to SQL injection",
                                    severity=VulnerabilitySeverity.HIGH,
                                    location=test_url,
                                    evidence=f"SQL error pattern '{pattern}' found in response",
                                    remediation="Use parameterized queries or prepared statements",
                                    cwe_id="CWE-89"
                                )
                                break
        
        except httpx.RequestError:
            # Skip if we can't access the page
            pass
            
    async def check_open_redirects(self) -> None:
        """Check for open redirect vulnerabilities"""
        try:
            # Common redirect parameters
            redirect_params = ["redirect", "url", "next", "return", "returnUrl", "returnTo", "goto", "to"]
            malicious_urls = ["https://evil.com", "//evil.com", "https://attacker.example.com"]
            
            # Check for redirect parameters in the URL
            parsed_url = urlparse(self.url)
            if parsed_url.query:
                params = dict([param.split('=') for param in parsed_url.query.split('&') if '=' in param])
                
                for param_name in redirect_params:
                    if param_name in params:
                        # Test with malicious URLs
                        for malicious_url in malicious_urls:
                            test_params = params.copy()
                            test_params[param_name] = malicious_url
                            
                            query_string = "&".join([f"{k}={v}" for k, v in test_params.items()])
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                            
                            # Send the request and check for redirects
                            response = await self.client.get(test_url, follow_redirects=False)
                            
                            # Check if the response is a redirect to our malicious URL
                            if response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get("location", "")
                                if any(url in location for url in malicious_urls):
                                    self.add_vulnerability(
                                        name="Open Redirect Vulnerability",
                                        description=f"The parameter '{param_name}' allows for open redirects",
                                        severity=VulnerabilitySeverity.MEDIUM,
                                        location=test_url,
                                        evidence=f"Redirects to {location}",
                                        remediation="Implement a whitelist of allowed redirect URLs or use relative URLs",
                                        cwe_id="CWE-601"
                                    )
            
            # Also check forms with action attributes that might contain redirect parameters
            response = await self.client.get(self.url)
            if "text/html" in response.headers.get("content-type", ""):
                soup = BeautifulSoup(response.text, "html.parser")
                forms = soup.find_all("form")
                
                for form in forms:
                    action = form.get("action", "")
                    if any(param in action for param in redirect_params):
                        self.add_vulnerability(
                            name="Potential Open Redirect in Form",
                            description="A form was found with a potential redirect parameter in its action",
                            severity=VulnerabilitySeverity.LOW,
                            location=f"{self.url}#{form.get('id', '')}",
                            evidence=f"Form action: {action}",
                            remediation="Validate redirect destinations on the server side",
                            cwe_id="CWE-601"
                        )
        
        except httpx.RequestError:
            # Skip if we can't access the page
            pass
    
    async def check_information_disclosure(self) -> None:
        """Check for information disclosure vulnerabilities"""
        try:
            # Common paths that might contain sensitive information
            sensitive_paths = [
                "/robots.txt", "/sitemap.xml", "/.git/", "/.env", "/backup/", "/config/",
                "/phpinfo.php", "/info.php", "/server-status", "/server-info",
                "/wp-config.php", "/config.php", "/database.yml", "/credentials.txt"
            ]
            
            base_url = f"{urlparse(self.url).scheme}://{urlparse(self.url).netloc}"
            
            for path in sensitive_paths:
                test_url = urljoin(base_url, path)
                response = await self.client.get(test_url)
                
                # Check if the file exists and is accessible
                if response.status_code == 200:
                    # Default remediation message
                    remediation = "Restrict access to sensitive files and directories"
                    
                    # Initialize Groq client for dynamic remediation generation
                    groq_client = None
                    try:
                        from app.core.ai.groq_client import GroqClient
                        groq_client = GroqClient()
                    except ValueError as e:
                        # Continue without dynamic remediation if API key is not set
                        print(f"Warning: {str(e)}. Using default remediation guidance.")
                    except ImportError:
                        # Continue without dynamic remediation if module is not available
                        print("Warning: GroqClient not available. Using default remediation guidance.")
                    
                    # Generate dynamic remediation if Groq client is available
                    if groq_client:
                        try:
                            dynamic_remediation = await self.generate_dynamic_remediation(
                                groq_client,
                                "Potential Information Disclosure",
                                f"Sensitive file or directory is accessible: {path}",
                                None,  # No header name for this vulnerability
                                "CWE-200"
                            )
                            if dynamic_remediation:
                                remediation = dynamic_remediation
                        except Exception as e:
                            # Fall back to default remediation if generation fails
                            print(f"Error generating remediation: {str(e)}")
                    
                    # Check content for sensitive information
                    self.add_vulnerability(
                        name="Potential Information Disclosure",
                        description=f"Sensitive file or directory is accessible: {path}",
                        severity=VulnerabilitySeverity.MEDIUM,
                        location=test_url,
                        evidence=f"File accessible with status code 200",
                        remediation=remediation,
                        cwe_id="CWE-200"
                    )
            
            # Check for version information in HTTP headers
            response = await self.client.get(self.url)
            headers = response.headers
            
            version_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]
            for header in version_headers:
                if header in headers:
                    # Default remediation message
                    remediation = "Configure the server to not disclose version information"
                    
                    # Generate dynamic remediation if Groq client is available
                    if groq_client:
                        try:
                            dynamic_remediation = await self.generate_dynamic_remediation(
                                groq_client,
                                "Version Information Disclosure",
                                f"The server is disclosing version information through HTTP headers",
                                header,  # Include the specific header name
                                "CWE-200"
                            )
                            if dynamic_remediation:
                                remediation = dynamic_remediation
                        except Exception as e:
                            # Fall back to default remediation if generation fails
                            print(f"Error generating remediation: {str(e)}")
                    
                    self.add_vulnerability(
                        name="Version Information Disclosure",
                        description=f"The server is disclosing version information through HTTP headers",
                        severity=VulnerabilitySeverity.LOW,
                        location=self.url,
                        evidence=f"{header}: {headers[header]}",
                        remediation=remediation,
                        cwe_id="CWE-200"
                    )
        
        except httpx.RequestError:
            # Skip if we can't access the page
            pass
    
    async def check_page_information_disclosure(self, url: str, response: httpx.Response) -> None:
        """Check a page for information disclosure vulnerabilities"""
        # Check for comments that might contain sensitive information
        if "text/html" in response.headers.get("content-type", ""):
            html_content = response.text
            
            # Check for HTML comments that might contain sensitive information
            comment_pattern = re.compile(r'<!--(.+?)-->', re.DOTALL)
            comments = comment_pattern.findall(html_content)
            
            sensitive_patterns = [
                r'password', r'user', r'username', r'api[_\-]?key', r'secret',
                r'token', r'auth', r'todo', r'fix', r'bug', r'issue', r'admin',
                r'database', r'db', r'config', r'private', r'key'
            ]
            
            # Initialize Groq client for dynamic remediation generation
            groq_client = None
            try:
                from app.core.ai.groq_client import GroqClient
                groq_client = GroqClient()
            except ValueError as e:
                # Continue without dynamic remediation if API key is not set
                print(f"Warning: {str(e)}. Using default remediation guidance.")
            except ImportError:
                # Continue without dynamic remediation if module is not available
                print("Warning: GroqClient not available. Using default remediation guidance.")
            
            for comment in comments:
                for pattern in sensitive_patterns:
                    if re.search(pattern, comment, re.IGNORECASE):
                        # Default remediation message
                        remediation = "Remove sensitive information from HTML comments"
                        
                        # Generate dynamic remediation if Groq client is available
                        if groq_client:
                            try:
                                # Include the specific sensitive pattern found in the description
                                detailed_description = f"HTML comment contains potentially sensitive information related to '{pattern}'"
                                
                                dynamic_remediation = await self.generate_dynamic_remediation(
                                    groq_client,
                                    "Sensitive Information in HTML Comment",
                                    detailed_description,
                                    None,  # No header name for this vulnerability
                                    "CWE-200"
                                )
                                if dynamic_remediation:
                                    remediation = dynamic_remediation
                            except Exception as e:
                                # Fall back to default remediation if generation fails
                                print(f"Error generating remediation: {str(e)}")
                        
                        self.add_vulnerability(
                            name="Sensitive Information in HTML Comment",
                            description=f"HTML comment contains potentially sensitive information related to '{pattern}'",
                            severity=VulnerabilitySeverity.MEDIUM,
                            location=url,
                            evidence=comment[:100] + "..." if len(comment) > 100 else comment,
                            remediation=remediation,
                            cwe_id="CWE-200"
                        )
                        break
            
            # Check for JavaScript with sensitive information
            script_pattern = re.compile(r'<script[^>]*>(.+?)</script>', re.DOTALL)
            scripts = script_pattern.findall(html_content)
            
            js_sensitive_patterns = [
                r'api[_\-]?key\s*[=:]\s*["\']([^"\']*)["\']",',
                r'password\s*[=:]\s*["\']([^"\']*)["\']",',
                r'secret\s*[=:]\s*["\']([^"\']*)["\']",',
                r'token\s*[=:]\s*["\']([^"\']*)["\']",'
            ]
            
            for script in scripts:
                for pattern in js_sensitive_patterns:
                    match = re.search(pattern, script, re.IGNORECASE)
                    if match:
                        # Default remediation message
                        remediation = "Remove sensitive information from client-side code"
                        
                        # Generate dynamic remediation if Groq client is available
                        if groq_client:
                            try:
                                # Include the specific sensitive pattern found in the description
                                pattern_name = pattern.split(r'[_\-]?')[0]  # Extract the base pattern name (api, password, etc.)
                                detailed_description = f"JavaScript code contains potentially sensitive information related to '{pattern_name}'"
                                
                                dynamic_remediation = await self.generate_dynamic_remediation(
                                    groq_client,
                                    "Sensitive Information in JavaScript",
                                    detailed_description,
                                    None,  # No header name for this vulnerability
                                    "CWE-200"
                                )
                                if dynamic_remediation:
                                    remediation = dynamic_remediation
                            except Exception as e:
                                # Fall back to default remediation if generation fails
                                print(f"Error generating remediation: {str(e)}")
                        
                        self.add_vulnerability(
                            name="Sensitive Information in JavaScript",
                            description=f"JavaScript code contains potentially sensitive information related to '{pattern.split(r'[_\\-]?')[0]}'",
                            severity=VulnerabilitySeverity.HIGH,
                            location=url,
                            evidence=match.group(0)[:100] + "..." if len(match.group(0)) > 100 else match.group(0),
                            remediation=remediation,
                            cwe_id="CWE-200"
                        )
                        break
    
    async def check_page_xss_vulnerabilities(self, url: str, soup: BeautifulSoup) -> None:
        """Check a page for XSS vulnerabilities in forms"""
        forms = soup.find_all("form")
        
        for form in forms:
            # Check form inputs for potential XSS vulnerabilities
            inputs = form.find_all("input")
            for input_field in inputs:
                input_type = input_field.get("type", "").lower()
                
                # Focus on text-based inputs
                if input_type in ["text", "search", "url", "tel", "email", ""]:
                    input_name = input_field.get("name", "")
                    if input_name:
                        self.add_vulnerability(
                            name="Potential XSS Vector",
                            description=f"Form input '{input_name}' could be a vector for XSS attacks",
                            severity=VulnerabilitySeverity.LOW,
                            location=f"{url}#{form.get('id', '')}",
                            evidence=str(input_field)[:100] + "..." if len(str(input_field)) > 100 else str(input_field),
                            remediation="Implement input validation and output encoding",
                            cwe_id="CWE-79"
                        )
            
            # Check for absence of input validation attributes
            for input_field in inputs:
                if not input_field.has_attr("pattern") and not input_field.has_attr("maxlength"):
                    input_name = input_field.get("name", "")
                    if input_name:
                        self.add_vulnerability(
                            name="Missing Input Validation",
                            description=f"Form input '{input_name}' lacks client-side validation attributes",
                            severity=VulnerabilitySeverity.INFO,
                            location=f"{url}#{form.get('id', '')}",
                            evidence=str(input_field)[:100] + "..." if len(str(input_field)) > 100 else str(input_field),
                            remediation="Add pattern and maxlength attributes for client-side validation",
                            cwe_id="CWE-20"
                        )
    
    async def check_page_csrf_vulnerabilities(self, url: str, soup: BeautifulSoup) -> None:
        """Check a page for CSRF vulnerabilities in forms"""
        forms = soup.find_all("form", method=lambda m: m and m.lower() == "post")
        
        for form in forms:
            # Check for CSRF tokens in the form
            csrf_fields = form.find_all("input", attrs={
                "name": re.compile(r"csrf|token|nonce", re.I)
            })
            
            if not csrf_fields:
                self.add_vulnerability(
                    name="Missing CSRF Protection",
                    description="A form was found without CSRF protection",
                    severity=VulnerabilitySeverity.MEDIUM,
                    location=f"{url}#{form.get('id', '')}",
                    evidence=str(form)[:100] + "..." if len(str(form)) > 100 else str(form),
                    remediation="Implement CSRF tokens for all forms",
                    cwe_id="CWE-352"
                )
    
    def update_summary(self) -> None:
        """Update the summary statistics for the scan"""
        # Count total vulnerabilities
        total_vulnerabilities = len(self.results["vulnerabilities"])
        self.results["summary"]["total_vulnerabilities"] = total_vulnerabilities
        
        # Reset severity counts
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        # Count vulnerabilities by severity
        for vuln in self.results["vulnerabilities"]:
            severity = vuln["severity"].lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        self.results["summary"]["severity_counts"] = severity_counts
    
    def add_vulnerability(self, name: str, description: str, severity: VulnerabilitySeverity, 
                         location: str, evidence: Optional[str] = None, remediation: Optional[str] = None,
                         cwe_id: Optional[str] = None, cvss_score: Optional[float] = None) -> None:
        """Add a vulnerability to the results"""
        vulnerability = {
            "name": name,
            "description": description,
            "severity": severity,
            "location": location,
            "evidence": evidence,
            "remediation": remediation,
            "cwe_id": cwe_id,
            "cvss_score": cvss_score
        }
        
        # Add to vulnerabilities list
        self.results["vulnerabilities"].append(vulnerability)
        
        # Update severity count in summary
        severity_key = severity.lower()
        if severity_key in self.results["summary"]["severity_counts"]:
            self.results["summary"]["severity_counts"][severity_key] += 1
        
        # Update total count
        self.results["summary"]["total_vulnerabilities"] += 1