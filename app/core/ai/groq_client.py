import os
import httpx
from typing import Dict, Any, Optional
from app.core.config import settings

class GroqClient:
    """Client for interacting with Groq API to generate dynamic remediation guidance"""
    
    def __init__(self):
        self.api_key = settings.GROQ_API_KEY
        self.base_url = "https://api.groq.com/openai/v1"
        self.model = "qwen-2.5-32b"
        
        if not self.api_key:
            raise ValueError("GROQ_API_KEY is not set in environment variables")
    
    async def generate_remediation(self, 
                                vulnerability_name: str, 
                                vulnerability_description: str,
                                header_name: Optional[str] = None,
                                cwe_id: Optional[str] = None) -> str:
        """Generate dynamic remediation guidance for a security vulnerability
        
        Args:
            vulnerability_name: Name of the vulnerability
            vulnerability_description: Description of the vulnerability
            header_name: Name of the security header (if applicable)
            cwe_id: Common Weakness Enumeration ID (if available)
            
        Returns:
            Detailed remediation guidance as a string
        """
        try:
            # Construct the prompt for the LLM
            prompt = self._build_remediation_prompt(
                vulnerability_name, 
                vulnerability_description,
                header_name,
                cwe_id
            )
            
            # Make API request to Groq
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity expert specializing in web application security. Provide detailed, actionable remediation steps for security vulnerabilities."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.2,
                    "max_tokens": 1024
                }
                
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload
                )
                
                response.raise_for_status()
                result = response.json()
                
                # Extract the generated remediation guidance
                if "choices" in result and len(result["choices"]) > 0:
                    return result["choices"][0]["message"]["content"]
                else:
                    return "Unable to generate remediation guidance. Please consult security documentation for this vulnerability."
        
        except httpx.RequestError as e:
            # Handle API request errors
            return f"Error generating remediation guidance: {str(e)}"
    
    def _build_remediation_prompt(self, 
                               vulnerability_name: str, 
                               vulnerability_description: str,
                               header_name: Optional[str] = None,
                               cwe_id: Optional[str] = None) -> str:
        """Build a prompt for the LLM to generate remediation guidance
        
        Args:
            vulnerability_name: Name of the vulnerability
            vulnerability_description: Description of the vulnerability
            header_name: Name of the security header (if applicable)
            cwe_id: Common Weakness Enumeration ID (if available)
            
        Returns:
            Formatted prompt string
        """
        prompt = f"""I need detailed remediation guidance for the following web security vulnerability:

Vulnerability: {vulnerability_name}
Description: {vulnerability_description}
"""
        
        if header_name:
            prompt += f"\nSecurity Header: {header_name}"
        
        if cwe_id:
            prompt += f"\nCWE ID: {cwe_id}"
        
        prompt += """

Please provide:
1. A detailed explanation of why this vulnerability is important to fix
2. Step-by-step instructions on how to implement the fix
3. Code examples for different web servers (Apache, Nginx, IIS) and programming languages (PHP, Python, Node.js)
4. Best practices for implementing this security measure
5. Any potential side effects or considerations when implementing the fix

Format your response in a clear, structured way that a developer can easily follow.
"""
        
        return prompt