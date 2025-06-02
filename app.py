# Alternative entry point for Railway deployment
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os
import sys

# Add the current directory to the path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Fix for Railway: Convert any postgres:// URLs to postgresql://
database_url = os.getenv('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    os.environ['DATABASE_URL'] = database_url.replace('postgres://', 'postgresql://')
    print(f"Converted DATABASE_URL from postgres:// to postgresql://")

# Also check other potential database URLs
for env_var in ['POSTGRES_URL', 'POSTGRES_URL_NON_POOLING', 'POSTGRES_URL_NO_SSL', 'POSTGRES_PRISMA_URL']:
    url = os.getenv(env_var)
    if url and url.startswith('postgres://'):
        os.environ[env_var] = url.replace('postgres://', 'postgresql://')
        print(f"Converted {env_var} from postgres:// to postgresql://")

# Import routes and settings
from app.api.security_routes import security_router
from app.core.config import settings

app = FastAPI(
    title="Website Security Scanner",
    description="A system to scan websites for security vulnerabilities",
    version="0.1.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(security_router, prefix="/api")

# Mount static files if directory exists
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def root():
    """Root endpoint that returns basic API information"""
    return {
        "message": "Welcome to the Website Security Scanner API",
        "docs": "/docs",
        "version": app.version
    }
    
if __name__ == "__main__":
    import uvicorn
    print("Python version:", sys.version)
    print("Starting FastAPI application...")
    # Get port from environment variable for Railway deployment
    port = int(os.getenv("PORT", 8000))
    print(f"Running on port: {port}")
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)