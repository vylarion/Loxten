"""
Loxten API — FastAPI Application
Main entry point with CORS, router mounting, and lifespan
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .routers import analyze, breach, health


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown events"""
    print(f"🛡️  Loxten API v{settings.VERSION} starting...")
    print(f"   Free scans/day: {settings.FREE_SCANS_PER_DAY}")
    print(f"   Debug: {settings.DEBUG}")
    yield
    print("🛡️  Loxten API shutting down...")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Web security analysis API for the Loxten browser extension",
    lifespan=lifespan,
)

# CORS — allow the extension and dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Extensions use chrome-extension:// origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routers
app.include_router(analyze.router)
app.include_router(breach.router)
app.include_router(health.router)


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
    }
