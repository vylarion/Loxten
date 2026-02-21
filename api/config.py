"""
Loxten API Configuration
Reads settings from environment variables / .env file
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from api directory
env_path = Path(__file__).parent / ".env"
load_dotenv(env_path)


class Settings:
    # --- LLM Configuration ---
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "gemini")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    # --- Rate Limiting (Freemium) ---
    FREE_SCANS_PER_DAY: int = int(os.getenv("FREE_SCANS_PER_DAY", "50"))
    FREE_BREACH_CHECKS_PER_DAY: int = int(os.getenv("FREE_BREACH_CHECKS_PER_DAY", "5"))

    # --- CORS ---
    ALLOWED_ORIGINS: list[str] = [
        "chrome-extension://*",
        "http://localhost:5173",
        "http://localhost:4173",
    ]

    # --- Server ---
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "true").lower() == "true"

    # --- API Info ---
    APP_NAME: str = "Loxten API"
    VERSION: str = "1.0.0"


settings = Settings()
