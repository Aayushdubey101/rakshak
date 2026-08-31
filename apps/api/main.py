import asyncio
import logging
import os
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from packages.shared.config.settings import get_settings
from apps.api.routers import auth, health, investigations, threat_intel
from apps.telegram_bot import router as telegram_router
from apps.whatsapp_bot import router as whatsapp_router
from packages.shared.db.engine import create_all
from packages.shared.redis_client import get_redis_client
from packages.shared.logging_config import configure_logging
from packages.shared.telemetry import configure_tracing
from apps.api.middleware.auth import APIKeyMiddleware
from apps.api.middleware.rate_limit import RateLimitMiddleware
from apps.api.middleware.security_headers import SecurityHeadersMiddleware

logger = logging.getLogger("uvicorn")


def _assert_production_security(settings) -> None:
    """Fail loudly at startup instead of silently running unsafe in
    production (task.md phase 14). Every condition here is a legitimate dev
    convenience when unset -- a real gap only once `ENVIRONMENT=production`
    says this is meant to be a live deployment."""
    if settings.ENVIRONMENT != "production":
        return

    problems = []
    if settings.HONEYPOT_ENABLED and not settings.HONEYPOT_RESEARCHER_KEY:
        problems.append(
            "HONEYPOT_ENABLED=true with no HONEYPOT_RESEARCHER_KEY -- "
            "honeypot isolation cannot verify a researcher credential"
        )
    if settings.TELEGRAM_BOT_TOKEN and not settings.TELEGRAM_WEBHOOK_SECRET:
        problems.append(
            "TELEGRAM_BOT_TOKEN set with no TELEGRAM_WEBHOOK_SECRET -- "
            "the telegram webhook cannot verify signatures"
        )
    if settings.WHATSAPP_ACCESS_TOKEN and not settings.WHATSAPP_APP_SECRET:
        problems.append(
            "WHATSAPP_ACCESS_TOKEN set with no WHATSAPP_APP_SECRET -- "
            "the whatsapp webhook cannot verify signatures"
        )
    if problems:
        raise RuntimeError(
            "Refusing to start in production with unsafe configuration:\n  - " + "\n  - ".join(problems)
        )


# -------------------------------------------------
# Load settings (safe: extra env vars ignored)
# -------------------------------------------------
settings = get_settings()
_assert_production_security(settings)

# -------------------------------------------------
# Error tracking (phase 15) -- no SENTRY_DSN means disabled, same
# DISABLED-not-a-stub convention as every other optional-infra seam here.
# -------------------------------------------------
if settings.SENTRY_DSN:
    import sentry_sdk

    sentry_sdk.init(dsn=settings.SENTRY_DSN, environment=settings.ENVIRONMENT)

# -------------------------------------------------
# Create FastAPI app
# -------------------------------------------------
app = FastAPI(
    title=settings.APP_NAME,
    description="Agentic Honeypot for Scam Detection",
    version="1.0.0"
)

# OpenTelemetry FastAPI instrumentation must attach before the app starts
# serving; the JSON log handler waits for `startup_event` below so it runs
# after (and therefore wins over) uvicorn's own logging setup.
configure_tracing(app)

@app.get("/")
async def root():
    return {"message": "Quantum Honeypot Active."}

# -------------------------------------------------
# Middleware
# -------------------------------------------------
app.add_middleware(RateLimitMiddleware, requests_per_minute=60, redis_client=get_redis_client())
app.add_middleware(APIKeyMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
# Added last -> outermost: a cross-origin preflight (OPTIONS) or a rejected
# request still needs CORS headers on its response, so this must wrap
# everything above it, not sit inside the auth/rate-limit gate.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.CORS_ALLOWED_ORIGINS.split(",") if origin.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------
# Routers
# -------------------------------------------------
app.include_router(health.router)
app.include_router(auth.router)
app.include_router(investigations.router)
app.include_router(threat_intel.router)
app.include_router(telegram_router.router)
app.include_router(whatsapp_router.router)

# -------------------------------------------------
# Startup events
# -------------------------------------------------
@app.on_event("startup")
async def startup_event():
    # Runs after uvicorn.run() has already installed its own default logging
    # config, so this call wins and every logger this codebase uses emits
    # structured JSON from here on.
    configure_logging()

    # Dev/test convenience: create tables if they don't exist yet. Real
    # deployments migrate with Alembic (`migrations/`) before this ever runs.
    await create_all()

    # Warm packages/ml/text/semantic.py's lazy singletons (MiniLM encoder +
    # classifier head) here, not on the first real request. The encoder's
    # first load fetches ~87MB from Hugging Face and takes 9-15s -- close to
    # or over orchestrator.py's 10s detection StageBudget, so an unwarmed
    # first request can time out the whole detection stage and silently
    # degrade a real scam to "likely_safe". A background thread so it never
    # blocks startup; failures here are logged, not fatal (same "absent, not
    # a stub" contract as the rest of packages/ml -- a slow/offline HF fetch
    # degrades detection to no-semantic-signal, exactly like today, instead
    # of failing the app to start).
    async def _warm_semantic_classifier() -> None:
        from packages.ml.text import semantic

        try:
            await asyncio.to_thread(semantic.predict, "warmup")
        except Exception as exc:  # noqa: BLE001 -- best-effort warmup, never fatal
            logger.warning(f"semantic classifier warmup failed: {exc}")

    asyncio.create_task(_warm_semantic_classifier())

    # Same reasoning for packages/ml/vision/ocr.py's EasyOCR reader --
    # first load downloads detection/recognition model weights and is the
    # slow part of an otherwise-fast local OCR path.
    async def _warm_local_ocr() -> None:
        from packages.ml.vision import ocr as local_ocr

        try:
            await asyncio.to_thread(local_ocr.available)
        except Exception as exc:  # noqa: BLE001 -- best-effort warmup, never fatal
            logger.warning(f"local OCR warmup failed: {exc}")

    asyncio.create_task(_warm_local_ocr())

# -------------------------------------------------
# ENTRYPOINT
# -------------------------------------------------
def run():
    """Serve the API. Called by `python main.py` at the repository root."""
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    run()
