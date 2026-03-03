"""
Loxten — Google Safe Browsing Service
Checks URLs against Google's threat lists via Lookup API v4
"""

import httpx

from ..config import settings

GSB_API_BASE = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Threat types to check
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

PLATFORM_TYPES = ["ANY_PLATFORM"]
THREAT_ENTRY_TYPES = ["URL"]


class GSBResult:
    """Google Safe Browsing lookup result"""

    __slots__ = ("threats", "available")

    def __init__(self, threats: list[str] | None = None, available: bool = False):
        self.threats = threats or []
        self.available = available


async def check_url(url: str) -> GSBResult:
    """
    Check a URL against Google Safe Browsing.
    Returns matched threat types (empty = clean).
    Returns unavailable GSBResult if no API key or on failure.
    """
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
    if not api_key:
        return GSBResult()

    body = {
        "client": {"clientId": "loxten-extension", "clientVersion": settings.VERSION},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": PLATFORM_TYPES,
            "threatEntryTypes": THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                GSB_API_BASE,
                params={"key": api_key},
                json=body,
                timeout=8.0,
            )

            if resp.status_code != 200:
                return GSBResult()

            data = resp.json()
            matches = data.get("matches", [])

            threat_types = list({m.get("threatType", "") for m in matches if m.get("threatType")})

            return GSBResult(threats=threat_types, available=True)

    except Exception as e:
        print(f"[GSB] Error: {e}")
        return GSBResult()
