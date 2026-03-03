"""
Loxten API — Health Check Router
GET /api/health — Server status + service availability
"""

from fastapi import APIRouter

from ..models import HealthResponse
from ..config import settings

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_endpoint():
    """Check server health and external service availability"""
    return HealthResponse(
        status="ok",
        version=settings.VERSION,
        virustotal="enabled" if settings.VIRUSTOTAL_API_KEY else "disabled",
        safebrowsing="enabled" if settings.GOOGLE_SAFE_BROWSING_API_KEY else "disabled",
    )
