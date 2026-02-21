"""
Loxten API — Health Check Router
GET /api/health — Server status
"""

from fastapi import APIRouter

from ..models import HealthResponse
from ..config import settings

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_endpoint():
    """Check server health"""
    return HealthResponse(
        status="ok",
        version=settings.VERSION,
    )
