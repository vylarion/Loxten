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
    # --- Rate Limiting ---
    FREE_SCANS_PER_DAY: int = int(os.getenv("FREE_SCANS_PER_DAY", "500"))
    FREE_BREACH_CHECKS_PER_DAY: int = int(os.getenv("FREE_BREACH_CHECKS_PER_DAY", "10"))

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
    VERSION: str = "2.0.0"


settings = Settings()
