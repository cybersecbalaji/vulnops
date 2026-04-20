from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # ── App ──────────────────────────────────────────────────────────────────
    APP_NAME: str = "VulnOps Triage Console"
    APP_ENV: str = "development"
    DEBUG: bool = False
    API_V1_STR: str = "/api/v1"

    # ── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str

    # ── Redis ────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── JWT ──────────────────────────────────────────────────────────────────
    JWT_PRIVATE_KEY: str
    JWT_PUBLIC_KEY: str
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_ALGORITHM: str = "RS256"

    # ── Refresh Token ────────────────────────────────────────────────────────
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # ── Encryption ───────────────────────────────────────────────────────────
    # Fernet key (URL-safe base64-encoded 32-byte key).
    # Generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    MASTER_ENCRYPTION_KEY: str

    # ── External APIs ────────────────────────────────────────────────────────
    NVD_API_KEY: str = ""

    # ── CORS ─────────────────────────────────────────────────────────────────
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    # ── Rate Limiting ────────────────────────────────────────────────────────
    MAX_LOGIN_ATTEMPTS: int = 10
    LOCKOUT_MINUTES: int = 15

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str | List[str]) -> List[str]:
        if isinstance(v, str):
            stripped = v.strip()
            # Accept JSON array format: '["http://localhost:3000"]'
            if stripped.startswith("["):
                import json
                return json.loads(stripped)
            # Accept comma-separated format: "http://a.com,http://b.com"
            return [origin.strip() for origin in stripped.split(",") if origin.strip()]
        return v

    @field_validator("JWT_PRIVATE_KEY", "JWT_PUBLIC_KEY", mode="before")
    @classmethod
    def unescape_pem_newlines(cls, v: str) -> str:
        # Allow \n literals in .env files (dotenv does not expand them)
        return v.replace("\\n", "\n")


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
