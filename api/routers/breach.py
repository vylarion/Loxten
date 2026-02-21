"""
Loxten API — Breach Check Router
POST /api/breach — Check email against known data breaches
"""

import time
from collections import defaultdict
from fastapi import APIRouter, HTTPException

from ..models import BreachRequest, BreachResponse
from ..services.hibp import check_email_breaches
from ..config import settings

router = APIRouter(prefix="/api", tags=["breach"])

# Simple rate limiting
_daily_counts: dict[str, int] = defaultdict(int)
_day_key: str = ""


def _check_rate_limit(client_id: str = "default") -> bool:
    global _day_key
    today = time.strftime("%Y-%m-%d")
    if today != _day_key:
        _daily_counts.clear()
        _day_key = today
    return _daily_counts[client_id] < settings.FREE_BREACH_CHECKS_PER_DAY


@router.post("/breach", response_model=BreachResponse)
async def breach_endpoint(request: BreachRequest):
    """
    Check if an email address has appeared in known data breaches.
    Uses the Have I Been Pwned API with k-anonymity.
    """
    if not request.email or "@" not in request.email:
        raise HTTPException(status_code=400, detail="Invalid email address")

    if not _check_rate_limit():
        raise HTTPException(
            status_code=429,
            detail=f"Daily breach check limit reached ({settings.FREE_BREACH_CHECKS_PER_DAY}/day).",
        )

    _daily_counts["default"] += 1

    try:
        result = await check_email_breaches(request.email)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Breach check failed: {str(e)[:100]}")
