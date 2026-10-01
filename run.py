"""Run the API: python run.py  ->  http://localhost:8000

HOST/PORT environment variables are honoured so the same command serves
inside a container (deploy/docker-compose.yml sets HOST=0.0.0.0).
"""
import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run("src.api.main:app",
                host=os.environ.get("HOST", "127.0.0.1"),
                port=int(os.environ.get("PORT", "8000")),
                log_level="info")
