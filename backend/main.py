from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import sys
import os

# Add routes to path
sys.path.insert(0, os.path.dirname(__file__))

from routes.analysis import router as analysis_router
from routes.dashboard import router as dashboard_router

# Lifespan context
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n🚀 TrustSphere AI Backend Starting...")
    print("📡 API Server running on http://localhost:8000")
    print("📊 API Docs available at http://localhost:8000/docs")
    print("✅ Ready to analyze threats!\n")
    yield
    print("\n🛑 TrustSphere AI Backend Shutting Down...\n")

# Initialize FastAPI app
app = FastAPI(
    title="TrustSphere AI API",
    description="One Digital Trust & Safety Layer - Smart India Hackathon 2026",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(analysis_router, prefix="/api", tags=["Analysis"])
app.include_router(dashboard_router, prefix="/api", tags=["Dashboard"])

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "TrustSphere AI - Before You Click. Before You Trust.",
        "version": "1.0.0",
        "docs": "/docs",
        "status": "running"
    }

# Health check
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "trustsphere-ai-backend"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
