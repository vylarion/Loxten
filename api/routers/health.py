"""
Loxten API — Health Check Router
GET /api/health — Server status and LLM connectivity
"""

from fastapi import APIRouter

from ..models import HealthResponse
from ..services.gemini import test_connection
from ..config import settings

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_endpoint():
    """Check server health and LLM provider connectivity"""
    connected = await test_connection()

    return HealthResponse(
        status="ok",
        version=settings.VERSION,
        llm_provider=settings.LLM_PROVIDER,
        llm_connected=connected,
    )
