"""
Loxten API — URL Analysis Router
POST /api/analyze — Security analysis with VT + GSB enrichment
"""

import asyncio
import time
from collections import defaultdict
from fastapi import APIRouter, HTTPException

from ..models import AnalyzeRequest, AnalyzeResponse, ThreatItem
from ..config import settings
from ..services.virustotal import get_url_report
from ..services.safebrowsing import check_url as gsb_check_url

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


# ─── GSB threat-type → human-readable mapping ───

_GSB_LABELS: dict[str, tuple[str, str]] = {
    "MALWARE": ("malware", "Google Safe Browsing flagged this URL as distributing malware."),
    "SOCIAL_ENGINEERING": ("phishing", "Google Safe Browsing flagged this URL as a social-engineering / phishing site."),
    "UNWANTED_SOFTWARE": ("malware", "Google Safe Browsing flagged this URL for unwanted software."),
    "POTENTIALLY_HARMFUL_APPLICATION": ("malware", "Google Safe Browsing flagged this URL for a potentially harmful application."),
}


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_endpoint(request: AnalyzeRequest):
    """
    Analyze a URL for security threats.
    Runs local heuristics + VirusTotal + Google Safe Browsing concurrently.
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

    # ─── Run VT + GSB concurrently ───
    vt_result, gsb_result = await asyncio.gather(
        get_url_report(request.url),
        gsb_check_url(request.url),
    )

    # ─── Collect sources that actually ran ───
    sources: list[str] = ["heuristics"]
    if vt_result.available:
        sources.append("virustotal")
    if gsb_result.available:
        sources.append("safebrowsing")

    # ─── Build threats list from VT + GSB ───
    threats: list[ThreatItem] = []
    risk_score = 0

    # VT detections → threats + risk
    if vt_result.available and vt_result.detections > 0:
        ratio = vt_result.detections / max(vt_result.total_engines, 1)
        severity = "critical" if ratio > 0.3 else "high" if ratio > 0.1 else "medium"
        threats.append(ThreatItem(
            type="malware_domain",
            severity=severity,
            description=f"VirusTotal: {vt_result.detections}/{vt_result.total_engines} engines flagged this URL.",
        ))
        risk_score = max(risk_score, min(int(ratio * 100) + 20, 100))

    # GSB threats → threats + risk
    for gsb_type in gsb_result.threats:
        label, desc = _GSB_LABELS.get(gsb_type, ("malware", f"Google Safe Browsing: {gsb_type}"))
        threats.append(ThreatItem(
            type=label,
            severity="critical",
            description=desc,
        ))
        risk_score = max(risk_score, 80)

    is_safe = risk_score < 30
    summary = (
        "No issues detected."
        if is_safe
        else f"Threats detected — risk score {risk_score}/100."
    )

    result = AnalyzeResponse(
        url=request.url,
        risk_score=risk_score,
        is_safe=is_safe,
        threats=threats,
        summary=summary,
        vt_detections=vt_result.detections,
        vt_total_engines=vt_result.total_engines,
        vt_reputation=vt_result.reputation,
        gsb_threats=gsb_result.threats,
        sources_checked=sources,
    )

    # Cache the result
    _cache[request.url] = (result, time.time())
    _daily_counts["default"] += 1

    return result
