# This file helps Railway locate the FastAPI app
from app.main import app

if __name__ == "__main__":
    import uvicorn
    import os
    
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("wsgi:app", host="0.0.0.0", port=port, reload=False)