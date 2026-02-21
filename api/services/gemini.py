"""
Loxten AI — Gemini / Groq LLM Service
Provides structured security analysis of web pages using LLM
"""

import json
import re
from typing import Optional

from ..config import settings
from ..models import AnalyzeResponse, ThreatItem, PageData


# ─── Security Analysis Prompt ───

SYSTEM_PROMPT = """You are Loxten, an elite cybersecurity AI that analyzes web pages for security threats. You protect users by examining page content, URLs, forms, scripts, and behavior patterns.

For every page you analyze, you MUST return a JSON object with EXACTLY this structure (no markdown, no extra text, just pure JSON):

{
  "risk_score": <0-100 integer>,
  "is_safe": <true/false>,
  "is_phishing": <true/false>,
  "phishing_confidence": <0.0-1.0>,
  "impersonating": <"BrandName" or null>,
  "ai_summary": "<1-2 sentence summary of security status>",
  "threats": [
    {
      "type": "<phishing|malware|tracker|suspicious_script|cryptomining|clickjacking|data_exfiltration|deceptive_ui>",
      "severity": "<low|medium|high|critical>",
      "description": "<specific, actionable description>",
      "confidence": <0.0-1.0>
    }
  ],
  "privacy_concerns": ["<concern1>", "<concern2>"]
}

ANALYSIS RULES:
1. Check if the URL domain matches the page content/branding (phishing indicator)
2. Flag password forms on non-HTTPS or suspicious domains
3. Identify trackers, analytics, and fingerprinting scripts
4. Detect urgency language ("Your account will be suspended", "Act now")
5. Check for hidden iframes, suspicious redirects, obfuscated scripts
6. Assess privacy: what data does this page collect?
7. Be precise — avoid false positives. Score safe sites LOW (0-15).
8. Known safe sites (google.com, github.com, stackoverflow.com, etc.) should score 0-10.
9. Return ONLY the JSON object, no markdown formatting, no code blocks."""


def _build_analysis_prompt(page_data: PageData) -> str:
    """Build the user prompt from page data"""
    parts = [f"Analyze this web page for security threats:\n"]
    parts.append(f"URL: {page_data.url}")
    parts.append(f"Title: {page_data.title}")

    if page_data.has_password_field:
        parts.append("⚠ PAGE HAS PASSWORD INPUT FIELD")

    if page_data.text_content:
        # Truncate to avoid token limits
        text = page_data.text_content[:3000]
        parts.append(f"\nPage Text (truncated):\n{text}")

    if page_data.forms:
        parts.append(f"\nForms Found: {json.dumps(page_data.forms[:10])}")

    if page_data.external_scripts:
        parts.append(f"\nExternal Scripts: {json.dumps(page_data.external_scripts[:20])}")

    if page_data.iframes:
        parts.append(f"\nIframes: {json.dumps(page_data.iframes[:10])}")

    if page_data.meta_tags:
        parts.append(f"\nMeta Tags: {json.dumps(page_data.meta_tags)}")

    return "\n".join(parts)


def _parse_llm_response(raw: str, url: str) -> AnalyzeResponse:
    """Parse the LLM JSON response into an AnalyzeResponse"""
    try:
        # Strip markdown code blocks if present
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)

        data = json.loads(cleaned)

        threats = [
            ThreatItem(
                type=t.get("type", "unknown"),
                severity=t.get("severity", "medium"),
                description=t.get("description", ""),
                confidence=float(t.get("confidence", 0.5)),
            )
            for t in data.get("threats", [])
        ]

        return AnalyzeResponse(
            url=url,
            risk_score=min(100, max(0, int(data.get("risk_score", 0)))),
            is_safe=data.get("is_safe", True),
            threats=threats,
            ai_summary=data.get("ai_summary", ""),
            privacy_concerns=data.get("privacy_concerns", []),
            is_phishing=data.get("is_phishing", False),
            phishing_confidence=float(data.get("phishing_confidence", 0.0)),
            impersonating=data.get("impersonating"),
        )
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        # Fallback if LLM returns garbage
        return AnalyzeResponse(
            url=url,
            risk_score=0,
            is_safe=True,
            ai_summary=f"Analysis could not be parsed. Raw: {raw[:200]}",
        )


# ─── Gemini Provider ───

async def _analyze_gemini(page_data: PageData) -> AnalyzeResponse:
    """Analyze page using Google Gemini"""
    from google import genai

    client = genai.Client(api_key=settings.GEMINI_API_KEY)

    prompt = _build_analysis_prompt(page_data)

    response = await client.aio.models.generate_content(
        model=settings.GEMINI_MODEL,
        contents=prompt,
        config=genai.types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.1,
            max_output_tokens=1024,
        ),
    )

    raw_text = response.text or ""
    return _parse_llm_response(raw_text, page_data.url)


# ─── Groq Provider ───

async def _analyze_groq(page_data: PageData) -> AnalyzeResponse:
    """Analyze page using Groq (Llama)"""
    import httpx

    prompt = _build_analysis_prompt(page_data)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.1,
                "max_tokens": 1024,
            },
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()

    raw_text = data["choices"][0]["message"]["content"]
    return _parse_llm_response(raw_text, page_data.url)


# ─── Public Interface ───

async def analyze_page(page_data: PageData) -> AnalyzeResponse:
    """
    Analyze a web page using the configured LLM provider.
    This is the main entry point — call this from the router.
    """
    provider = settings.LLM_PROVIDER.lower()

    if provider == "gemini":
        if not settings.GEMINI_API_KEY:
            return AnalyzeResponse(
                url=page_data.url,
                risk_score=0,
                is_safe=True,
                ai_summary="Gemini API key not configured. Set GEMINI_API_KEY in .env",
            )
        return await _analyze_gemini(page_data)

    elif provider == "groq":
        if not settings.GROQ_API_KEY:
            return AnalyzeResponse(
                url=page_data.url,
                risk_score=0,
                is_safe=True,
                ai_summary="Groq API key not configured. Set GROQ_API_KEY in .env",
            )
        return await _analyze_groq(page_data)

    else:
        return AnalyzeResponse(
            url=page_data.url,
            risk_score=0,
            is_safe=True,
            ai_summary=f"Unknown LLM provider: {provider}",
        )


async def test_connection() -> bool:
    """Test if the configured LLM provider is reachable"""
    try:
        provider = settings.LLM_PROVIDER.lower()
        if provider == "gemini" and settings.GEMINI_API_KEY:
            from google import genai
            client = genai.Client(api_key=settings.GEMINI_API_KEY)
            response = await client.aio.models.generate_content(
                model=settings.GEMINI_MODEL,
                contents="Reply with just the word OK",
                config=genai.types.GenerateContentConfig(max_output_tokens=10),
            )
            return bool(response.text)
        elif provider == "groq" and settings.GROQ_API_KEY:
            import httpx
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://api.groq.com/openai/v1/models",
                    headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
                    timeout=10.0,
                )
                return resp.status_code == 200
        return False
    except Exception:
        return False
