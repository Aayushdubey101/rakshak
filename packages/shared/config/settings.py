from pydantic_settings import BaseSettings
from functools import lru_cache
from pydantic import Field

from typing import Optional

class Settings(BaseSettings):
    APP_NAME: str = "Agentic Honeypot"
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_API_KEYS: Optional[str] = None  # Comma separated keys
    
    # Support for individual key variables (matching .env naming without underscores)
    GEMINI_API_KEY1: Optional[str] = None
    GEMINI_API_KEY2: Optional[str] = None
    GEMINI_API_KEY3: Optional[str] = None
    GEMINI_API_KEY4: Optional[str] = None
    # --- LLM Gateway (phase 3) -------------------------------------------
    # Every provider is optional. An unconfigured one reports DISABLED and the
    # task router skips it; keys are read here and never leave the server.
    LLM_PROVIDER: Optional[str] = None          # forces a provider to the front
    LLM_TASK_ROUTES: Optional[str] = None       # JSON: {"reasoning": ["ollama"]}
    LLM_TIMEOUT_SECONDS: float = 20.0
    LLM_SEED: Optional[int] = None              # deterministic local runs

    OLLAMA_ENABLED: bool = False                # opt-in: usually absent in prod
    OLLAMA_BASE_URL: str = "http://localhost:11434/v1"
    OLLAMA_MODEL: str = "gemma3:4b"

    OPENAI_API_KEY: Optional[str] = None
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_MODEL: str = "gpt-4o-mini"

    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_BASE_URL: str = "https://api.anthropic.com"
    ANTHROPIC_MODEL: str = "claude-sonnet-5"

    GROQ_API_KEY: Optional[str] = None
    GROQ_BASE_URL: str = "https://api.groq.com/openai/v1"
    GROQ_MODEL: str = "llama-3.3-70b-versatile"

    OPENROUTER_API_KEY: Optional[str] = None
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    OPENROUTER_MODEL: str = "openrouter/auto"

    # --- Channel adapters (phase 5) ---------------------------------------
    # Without a secret, the matching webhook rejects every request: an
    # unauthenticated webhook is never acted on.
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_WEBHOOK_SECRET: Optional[str] = None
    TELEGRAM_API_BASE: str = "https://api.telegram.org"

    WHATSAPP_APP_SECRET: Optional[str] = None       # signs X-Hub-Signature-256
    WHATSAPP_ACCESS_TOKEN: Optional[str] = None
    WHATSAPP_VERIFY_TOKEN: Optional[str] = None     # GET subscription handshake
    WHATSAPP_PHONE_NUMBER_ID: Optional[str] = None
    WHATSAPP_GRAPH_BASE: str = "https://graph.facebook.com/v21.0"

    # --- Persistence (phase 7) ---------------------------------------------
    # Unset means "use the in-process/offline fallback" (sqlite / in-memory /
    # local-filesystem), same DISABLED-not-a-stub convention as the LLM
    # providers. A single process degrades gracefully; a second process
    # sharing state requires these configured.
    DATABASE_URL: Optional[str] = None          # postgresql+asyncpg://...
    REDIS_URL: Optional[str] = None              # redis://...
    S3_ENDPOINT_URL: Optional[str] = None        # MinIO/S3-compatible endpoint
    S3_ACCESS_KEY: Optional[str] = None
    S3_SECRET_KEY: Optional[str] = None
    S3_BUCKET: str = "rakshak-evidence"
    S3_REGION: str = "us-east-1"

    # Retention, in days, per data class. 0 = keep forever.
    RETENTION_DAYS_MESSAGES: int = 90
    RETENTION_DAYS_MEDIA: int = 90
    RETENTION_DAYS_REPORTS: int = 365
    RETENTION_DAYS_AUDIT_LOGS: int = 0

    # --- Risk fusion (phase 8) ----------------------------------------------
    # Same ratio as the hardcoded blend it replaces (pattern 0.5, ml 0.3,
    # llm 0.2) — see packages/domain/risk/fusion.py. A signal that never ran
    # is absent, not zero, so these are only ever divided among signals that
    # actually produced one.
    FUSION_WEIGHT_PATTERN: float = 0.5
    FUSION_WEIGHT_ML_TEXT: float = 0.3
    FUSION_WEIGHT_LLM: float = 0.2
    FUSION_WEIGHT_ML_VISION: float = 0.3
    FUSION_WEIGHT_ML_URL: float = 0.3
    FUSION_WEIGHT_THREAT_INTEL: float = 0.4

    # Decision threshold: fused risk_score at/above this is a scam verdict.
    FUSION_SCAM_THRESHOLD: float = 0.30

    API_SECRET_KEY: str = Field(..., description="API Secret Key is required")

    # Comma-separated origins allowed to call the API cross-origin -- the
    # Next.js dev server (apps/web) runs on a different port than the API.
    CORS_ALLOWED_ORIGINS: str = "http://localhost:3000"

    # --- Honeypot isolation (phase 11) --------------------------------------
    # Rule #8: a consumer request never enters the honeypot automatically.
    # Off by default; HONEYPOT_RESEARCHER_KEY is deliberately a separate
    # secret from API_SECRET_KEY so a consumer credential never doubles as a
    # researcher one. Interim stand-in for phase 14's real scoped API keys.
    HONEYPOT_ENABLED: bool = False
    HONEYPOT_RESEARCHER_KEY: Optional[str] = None
    STRICT_RESPONSE_MODE: bool = True  # 🔥 CHANGED: Enable strict mode by default
    DEPLOYMENT_MODE: str = "full" # Options: 'lite', 'full'. Default 'full' for backward compatibility.
    HF_LITE_MODE: bool = False # 🔥 NEW: Explicit flag to disable HF models

    # --- Runtime security (phase 14) ----------------------------------------
    # "development" (default) never blocks startup on a soft-missing secret --
    # the point of every DISABLED-not-a-stub seam in this codebase is that a
    # laptop with no Redis/Postgres/webhook secrets still runs. "production"
    # switches main.py's startup check from advisory to fail-loud, and adds
    # HSTS to responses that arrive over HTTPS (X-Forwarded-Proto from the
    # terminating load balancer -- this process itself never holds a TLS cert).
    ENVIRONMENT: str = "development"

    # --- Observability (phase 15) -------------------------------------------
    # Both unset means "off", same DISABLED-not-a-stub convention as every
    # other optional-infra seam here -- a laptop with neither still runs.
    OTEL_EXPORTER_OTLP_ENDPOINT: Optional[str] = None
    SENTRY_DSN: Optional[str] = None

    class Config:
        env_file = ".env"
        extra = "ignore"

@lru_cache()
def get_settings():
    return Settings()
