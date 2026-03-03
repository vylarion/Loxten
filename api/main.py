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
    try:
        print(f"[*] Loxten API v{settings.VERSION} starting...")
        print(f"    Free scans/day: {settings.FREE_SCANS_PER_DAY}")
        print(f"    Debug: {settings.DEBUG}")
        vt_status = "[OK] key set" if settings.VIRUSTOTAL_API_KEY else "[--] no key"
        gsb_status = "[OK] key set" if settings.GOOGLE_SAFE_BROWSING_API_KEY else "[--] no key"
        print(f"    VirusTotal:      {vt_status}")
        print(f"    Safe Browsing:   {gsb_status}")
    except Exception as e:
        print(f"Startup log error: {e}")
    yield
    print("[*] Loxten API shutting down...")


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
