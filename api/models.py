"""
Loxten API — Pydantic Models
Request/Response schemas for all endpoints
"""

from pydantic import BaseModel, Field
from typing import Optional


# ─── Analyze Endpoint ───

class PageData(BaseModel):
    """Data extracted from a web page by the content script"""
    url: str = Field(..., description="Full URL of the page")
    title: str = Field("", description="Page title")
    text_content: str = Field("", description="Visible text content (truncated)")
    forms: list[dict] = Field(default_factory=list, description="Form actions and input types found on page")
    external_scripts: list[str] = Field(default_factory=list, description="External script source URLs")
    meta_tags: dict = Field(default_factory=dict, description="Meta tag key-value pairs")
    has_password_field: bool = Field(False, description="Whether page has a password input")
    iframes: list[str] = Field(default_factory=list, description="Iframe source URLs")


class ThreatItem(BaseModel):
    """A single threat identified by AI analysis"""
    type: str = Field(..., description="Threat type: phishing, malware, tracker, etc.")
    severity: str = Field("medium", description="low, medium, high, critical")
    description: str = Field(..., description="Human-readable description")
    confidence: float = Field(0.0, description="AI confidence 0.0 to 1.0")


class AnalyzeResponse(BaseModel):
    """Response from AI-powered page analysis"""
    url: str
    risk_score: int = Field(0, ge=0, le=100, description="Overall risk 0-100")
    is_safe: bool = Field(True)
    threats: list[ThreatItem] = Field(default_factory=list)
    ai_summary: str = Field("", description="AI-generated security summary")
    privacy_concerns: list[str] = Field(default_factory=list, description="Privacy issues found")
    is_phishing: bool = Field(False)
    phishing_confidence: float = Field(0.0)
    impersonating: Optional[str] = Field(None, description="Brand being impersonated, if phishing")
    cached: bool = Field(False, description="Whether this result was from cache")


# ─── Breach Endpoint ───

class BreachRequest(BaseModel):
    """Email to check against breach databases"""
    email: str = Field(..., description="Email address to check")


class BreachEntry(BaseModel):
    """A single breach record"""
    name: str
    date: str
    description: str = ""


class BreachResponse(BaseModel):
    """Result of breach check"""
    email: str
    breached: bool = False
    breach_count: int = 0
    breaches: list[BreachEntry] = Field(default_factory=list)


# ─── Health Endpoint ───

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    llm_provider: str = ""
    llm_connected: bool = False
