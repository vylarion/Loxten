"""
Loxten — VirusTotal Service
Checks URLs against 70+ antivirus engines via VT API v3
"""

import base64
import httpx

from ..config import settings

VT_API_BASE = "https://www.virustotal.com/api/v3"


class VTResult:
    """VirusTotal lookup result"""

    __slots__ = ("detections", "total_engines", "reputation", "categories", "flagged_engines", "available")

    def __init__(
        self,
        detections: int = 0,
        total_engines: int = 0,
        reputation: int = 0,
        categories: list[str] | None = None,
        flagged_engines: list[str] | None = None,
        available: bool = False,
    ):
        self.detections = detections
        self.total_engines = total_engines
        self.reputation = reputation
        self.categories = categories or []
        self.flagged_engines = flagged_engines or []
        self.available = available


def _url_id(url: str) -> str:
    """Encode URL to VT's base64 URL identifier (no padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def get_url_report(url: str) -> VTResult:
    """
    Look up an existing VT report for a URL (instant, no re-scan).
    Returns empty VTResult if no API key or on failure.
    """
    api_key = settings.VIRUSTOTAL_API_KEY
    if not api_key:
        return VTResult()

    try:
        url_id = _url_id(url)
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{VT_API_BASE}/urls/{url_id}",
                headers={"x-apikey": api_key, "Accept": "application/json"},
                timeout=10.0,
            )

            if resp.status_code == 404:
                # URL not yet scanned by VT — trigger a scan
                return await _submit_and_check(client, api_key, url)

            if resp.status_code != 200:
                return VTResult()

            return _parse_report(resp.json())

    except Exception as e:
        print(f"[VT] Error: {e}")
        return VTResult()


async def _submit_and_check(client: httpx.AsyncClient, api_key: str, url: str) -> VTResult:
    """Submit URL for scanning and return whatever initial data VT provides."""
    try:
        resp = await client.post(
            f"{VT_API_BASE}/urls",
            headers={"x-apikey": api_key, "Accept": "application/json"},
            data={"url": url},
            timeout=10.0,
        )
        if resp.status_code in (200, 201):
            # VT returns analysis metadata — extract the URL ID and re-fetch
            data = resp.json()
            analysis_url = data.get("data", {}).get("links", {}).get("self", "")
            if analysis_url:
                report = await client.get(
                    analysis_url,
                    headers={"x-apikey": api_key},
                    timeout=10.0,
                )
                if report.status_code == 200:
                    return _parse_analysis(report.json())
        return VTResult(available=True)  # Submitted but no results yet
    except Exception:
        return VTResult()


def _parse_report(data: dict) -> VTResult:
    """Parse a VT URL report response."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    detections = malicious + suspicious
    total = sum(stats.values()) if stats else 0

    flagged = [
        name
        for name, result in results.items()
        if result.get("category") in ("malicious", "suspicious")
    ]

    categories = list(attrs.get("categories", {}).values())

    return VTResult(
        detections=detections,
        total_engines=total,
        reputation=attrs.get("reputation", 0),
        categories=categories[:5],  # Cap at 5
        flagged_engines=flagged[:10],  # Cap at 10
        available=True,
    )


def _parse_analysis(data: dict) -> VTResult:
    """Parse a VT analysis (post-submission) response."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    return VTResult(
        detections=malicious + suspicious,
        total_engines=sum(stats.values()) if stats else 0,
        reputation=0,
        available=True,
    )
