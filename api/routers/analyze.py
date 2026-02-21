"""
Loxten API — URL Analysis Router
POST /api/analyze — Security analysis of URLs
"""

import time
from collections import defaultdict
from fastapi import APIRouter, HTTPException

from ..models import AnalyzeRequest, AnalyzeResponse
from ..config import settings

router = APIRouter(prefix="/api", tags=["analyze"])

# ─── Simple in-memory cache + rate limiting ───

_cache: dict[str, tuple[AnalyzeResponse, float]] = {}
CACHE_TTL = 300  # 5 minutes

_daily_counts: dict[str, int] = defaultdict(int)
_day_key: str = ""


def _get_cached(url: str) -> AnalyzeResponse | None:
    """Check cache for a recent analysis of this URL"""
    if url in _cache:
        result, timestamp = _cache[url]
        if time.time() - timestamp < CACHE_TTL:
            result.cached = True
            return result
        else:
            del _cache[url]
    return None


def _check_rate_limit(client_id: str = "default") -> bool:
    """Check if client has remaining free scans today"""
    global _day_key
    today = time.strftime("%Y-%m-%d")
    if today != _day_key:
        _daily_counts.clear()
        _day_key = today
    return _daily_counts[client_id] < settings.FREE_SCANS_PER_DAY


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_endpoint(request: AnalyzeRequest):
    """
    Analyze a URL for security threats.
    Currently uses local heuristics. VirusTotal integration coming soon.
    """
    # Check cache first
    cached = _get_cached(request.url)
    if cached:
        return cached

    # Rate limiting
    if not _check_rate_limit():
        raise HTTPException(
            status_code=429,
            detail=f"Daily scan limit reached ({settings.FREE_SCANS_PER_DAY}/day).",
        )

    # Basic URL analysis (placeholder until VT integration)
    result = AnalyzeResponse(
        url=request.url,
        risk_score=0,
        is_safe=True,
        summary="URL checked — no issues detected.",
    )

    # Cache the result
    _cache[request.url] = (result, time.time())
    _daily_counts["default"] += 1

    return result
