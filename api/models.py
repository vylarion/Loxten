"""
Loxten API — Pydantic Models
Request/Response schemas for all endpoints
"""

from pydantic import BaseModel, Field
from typing import Optional


# ─── Analyze Endpoint ───

class AnalyzeRequest(BaseModel):
    """URL to check"""
    url: str = Field(..., description="Full URL to analyze")


class ThreatItem(BaseModel):
    """A single threat identified"""
    type: str = Field(..., description="Threat type: phishing, malware, tracker, etc.")
    severity: str = Field("medium", description="low, medium, high, critical")
    description: str = Field(..., description="Human-readable description")


class AnalyzeResponse(BaseModel):
    """Response from page analysis"""
    url: str
    risk_score: int = Field(0, ge=0, le=100, description="Overall risk 0-100")
    is_safe: bool = Field(True)
    threats: list[ThreatItem] = Field(default_factory=list)
    summary: str = Field("", description="Security summary")
    cached: bool = Field(False, description="Whether this result was from cache")

    # ─── VT / GSB enrichment ───
    vt_detections: int = Field(0, description="Number of VT engines that flagged the URL")
    vt_total_engines: int = Field(0, description="Total VT engines that scanned the URL")
    vt_reputation: int = Field(0, description="VT community reputation score")
    gsb_threats: list[str] = Field(default_factory=list, description="Google Safe Browsing threat types")
    sources_checked: list[str] = Field(default_factory=list, description="Which sources ran (heuristics, virustotal, safebrowsing)")


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
    version: str = "2.0.0"
    virustotal: str = Field("disabled", description="VT service status")
    safebrowsing: str = Field("disabled", description="GSB service status")
