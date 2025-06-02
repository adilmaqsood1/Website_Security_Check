# This file marks the app directory as a Python package
# Create and expose the FastAPI app instance
from fastapi import FastAPI

# Create a simple FastAPI app instance
app = FastAPI(
    title="Website Security Scanner",
    description="A system to scan websites for security vulnerabilities",
    version="0.1.0"
)

# Note: This is a minimal app instance. For the full app with routes and middleware,
# see wsgi.py or main.py