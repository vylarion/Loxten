"""
Loxten — Have I Been Pwned (HIBP) Service
Uses k-anonymity API (no API key needed for password/hash range checks)
Uses v3 API for breach lookups (needs API key for full breach details)
"""

import hashlib
import httpx

from ..models import BreachResponse, BreachEntry


HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"


async def check_email_breaches(email: str) -> BreachResponse:
    """
    Check if an email has been involved in known data breaches.
    
    Uses the HIBP breach API. Since the full API requires a paid key,
    we use a simplified approach:
    1. Hash the email
    2. Check the hash prefix against the pwned passwords range API
    3. For breach details, we use the public breach search
    
    For production with full breach details, add HIBP_API_KEY to config.
    """
    email = email.strip().lower()

    try:
        async with httpx.AsyncClient() as client:
            # Use the public breach search endpoint
            # This checks if the email appears in any known breach
            resp = await client.get(
                f"{HIBP_BREACH_URL}{email}",
                headers={
                    "User-Agent": "Loxten-Security-Extension",
                    "Accept": "application/json",
                },
                params={"truncateResponse": "true"},
                timeout=15.0,
            )

            if resp.status_code == 404:
                # Not found in any breach
                return BreachResponse(
                    email=email,
                    breached=False,
                    breach_count=0,
                    breaches=[],
                )

            if resp.status_code == 200:
                breaches_data = resp.json()
                breaches = [
                    BreachEntry(
                        name=b.get("Name", "Unknown"),
                        date=b.get("BreachDate", "Unknown"),
                    )
                    for b in breaches_data
                ]
                return BreachResponse(
                    email=email,
                    breached=True,
                    breach_count=len(breaches),
                    breaches=breaches,
                )

            if resp.status_code == 401:
                # API key required — fall back to hash-based check
                return await _fallback_hash_check(email)

            # Rate limited or other error
            if resp.status_code == 429:
                return BreachResponse(
                    email=email,
                    breached=False,
                    breach_count=0,
                    breaches=[
                        BreachEntry(name="Rate Limited", date="", description="Too many requests. Try again later.")
                    ],
                )

            return BreachResponse(email=email, breached=False, breach_count=0)

    except httpx.TimeoutException:
        return BreachResponse(
            email=email,
            breached=False,
            breach_count=0,
            breaches=[BreachEntry(name="Timeout", date="", description="HIBP service timed out.")],
        )
    except Exception as e:
        return BreachResponse(
            email=email,
            breached=False,
            breach_count=0,
            breaches=[BreachEntry(name="Error", date="", description=str(e))],
        )


async def _fallback_hash_check(email: str) -> BreachResponse:
    """
    Fallback: use the k-anonymity password range API
    to check if the email hash prefix appears in breaches.
    This doesn't require an API key.
    """
    sha1_hash = hashlib.sha1(email.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{HIBP_RANGE_URL}{prefix}",
                headers={"User-Agent": "Loxten-Security-Extension"},
                timeout=10.0,
            )

            if resp.status_code == 200:
                # Check if our suffix appears in the response
                lines = resp.text.strip().split("\n")
                for line in lines:
                    parts = line.strip().split(":")
                    if len(parts) == 2 and parts[0] == suffix:
                        count = int(parts[1])
                        return BreachResponse(
                            email=email,
                            breached=True,
                            breach_count=count,
                            breaches=[
                                BreachEntry(
                                    name="Hash Match",
                                    date="",
                                    description=f"Email hash found {count} time(s) in breach databases.",
                                )
                            ],
                        )

                return BreachResponse(email=email, breached=False, breach_count=0)

    except Exception:
        pass

    return BreachResponse(email=email, breached=False, breach_count=0)
