"""
Loxten API — Page Analysis Router
POST /api/analyze — AI-powered security analysis of web pages
"""

import time
from collections import defaultdict
from fastapi import APIRouter, HTTPException

from ..models import PageData, AnalyzeResponse
from ..services.gemini import analyze_page
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
async def analyze_endpoint(page_data: PageData):
    """
    Analyze a web page for security threats using AI.
    
    Sends page content to the configured LLM (Gemini/Groq) which
    returns a structured security assessment including:
    - Risk score (0-100)
    - Phishing detection
    - Threat identification
    - Privacy concerns
    - Human-readable summary
    """
    # Check cache first
    cached = _get_cached(page_data.url)
    if cached:
        return cached

    # Rate limiting
    if not _check_rate_limit():
        raise HTTPException(
            status_code=429,
            detail=f"Daily scan limit reached ({settings.FREE_SCANS_PER_DAY}/day). Upgrade for unlimited scans.",
        )

    try:
        result = await analyze_page(page_data)

        # Cache the result
        _cache[page_data.url] = (result, time.time())
        _daily_counts["default"] += 1

        return result

    except Exception as e:
        # Don't crash — return safe fallback
        return AnalyzeResponse(
            url=page_data.url,
            risk_score=0,
            is_safe=True,
            ai_summary=f"Analysis temporarily unavailable: {str(e)[:100]}",
        )
