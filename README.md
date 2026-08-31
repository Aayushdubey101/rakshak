<p align="center">
  <img src="assets/rakshak-banner.svg" alt="Rakshak — agentic honeypot + AI/ML scam detection" width="100%">
</p>

<p align="center"><em>Don't trust it. Check it.</em></p>

---

**Rakshak** is an agentic honeypot and AI + ML scam-detection platform. Submit a
suspicious message, link, image, or document; it runs through ML classifiers,
multi-LLM reasoning, cybersecurity checks, and threat-intelligence correlation,
and returns a risk score with a confidence level and a full report. Optional
WhatsApp / Telegram bots let people forward content without visiting the site. An
opt-in honeypot engages scammers with AI personas to gather campaign
intelligence.

## How an investigation runs

Every channel builds one `InvestigationRequest`, calls `investigate()`, and gets
one `CanonicalReport` back. The pipeline
(`packages/domain/investigations/orchestrator.py`) is a single readable
function with two rules:

- **A stage failure degrades the report; it never aborts the investigation.**
  Each stage runs under its own timeout; its result is recorded in
  `stage_status` as `ok` / `degraded` / `failed` / `skipped`. A dead model or a
  slow provider yields a partial report that says so — never a 500, never a
  confident "looks fine".
- **Every log line carries the investigation id**, so one identifier follows a
  request across the API, the worker, and the database.

| Stage | Does | Budget |
|-------|------|--------|
| `ingestion` | normalize text; OCR images; extract PDF/audio text; refang + resolve URLs; SSRF guard; size/type limits → `NormalizedContent` | 18s |
| `entities` | regex extraction — UPI IDs, phone numbers, bank accounts, URLs, amounts, organizations, keywords | 2s |
| `threat_intel` | hash indicators, persist, correlate against prior investigations, link shared indicators into one campaign row | 2s |
| `detection` | rule signals + ML classifiers + LLM reasoning, fused into one score (split into separate stages is a planned change) | 18s |
| `agent` | honeypot engagement — only if `authorize_engagement()` grants it | 8s |
| `protection` | protective-action recommendations | 1s |

Interactive callers use `POST /api/v1/investigations` (waits, 45s total
budget). `POST /api/v1/investigations/async` enqueues an arq job and returns
`pending`; `GET /api/v1/investigations/{id}` polls. With no `REDIS_URL`, the
async route degrades to running inline.

## Detection layers

`packages/domain/risk/detector.py` fuses several independent signals:

- **Rule-based risk signals** — weighted keyword categories (urgency, financial,
  authority lure, rewards, threats, …), English + transliterated Hindi.
- **Supervised classifier** — scikit-learn model in `ml-models/trained/`, runs
  by default, no heavy install (`packages/ml/text/supervised.py`).
- **Semantic classifier** — `sentence-transformers/all-MiniLM-L6-v2` embedding +
  head, opt-in via `--extra semantic`, warmed at startup
  (`packages/ml/text/semantic.py`).
- **HF pipelines** — zero-shot + SMS-spam transformers, opt-in via `--extra ml`
  and `DEPLOYMENT_MODE=full` (`packages/ml/inference/hf.py`).
- **URL lexical scoring** — offline ruleset over each extracted URL
  (`packages/ml/url/`).
- **LLM reasoning** — routed through the gateway; only runs when the request
  carries `consent_external_processing`.

Model ids, versions, and thresholds live in one place
(`packages/ml/model_registry.py`); `scripts/eval_detection.py` and the sets in
`ml-models/evaluation/` are what justify changing them.

## LLM gateway

`packages/llm/` — call sites ask for a **task**, never a model:

| Task | Default provider chain |
|------|------------------------|
| `reasoning` | gemini → anthropic → openai → openrouter → groq → ollama |
| `fast` | groq → gemini → ollama → openai → openrouter → anthropic |
| `vision` | gemini → anthropic → openai → openrouter |
| `structured` | gemini → openai → anthropic → groq → openrouter → ollama |

An unconfigured provider reports `DISABLED` and the router skips it — never a
stub, never a hard failure. Any `*_API_KEY` accepts a comma-separated list for
per-key failover. `LLM_PROVIDER` forces one provider to the front;
`LLM_TASK_ROUTES` (JSON) overrides a single chain.

## API

Base prefix `/api`. All non-auth routes require a scope.

| Method | Path | Scope |
|--------|------|-------|
| `POST` | `/v1/auth/token` | (valid API key) — exchange key for short-lived bearer token |
| `POST` | `/v1/auth/register` · `/login` · `/forgot-password` · `/reset-password` | none — end-user accounts |
| `POST` | `/v1/investigations` | `analyze` — submit `MediaRef` / text, wait for report |
| `POST` | `/v1/investigations/upload` | `analyze` — multipart image/PDF upload |
| `POST` | `/v1/investigations/async` | `analyze` — enqueue, return `pending` |
| `GET` | `/v1/investigations` | `read:investigations` — list (own, or all for `admin`) |
| `GET` | `/v1/investigations/{id}` | `read:investigations` — poll / fetch report |
| `GET` | `/v1/threat-intel/feed` | `read:threat_intel` — live "what's circulating" feed |
| `GET`/`POST`/`DELETE` | `/honeypot/session/*` · `/honeypot/evidence` · `/honeypot/config` | `research:honeypot` / `admin` |
| `GET` | `/health/live` · `/health/ready` | none — liveness / readiness (ALB) |
| `POST` | `/webhooks/telegram` · `/webhooks/whatsapp` | signature-verified |

**Auth model.** Scoped API keys are created out of band and traded for
short-lived signed tokens. A logged-in person is an `ApiKeyPrincipal` with
principal `user:<id>` and scopes `{analyze, read:investigations,
read:threat_intel}` — never `admin` or `research:honeypot`, so honeypot
isolation holds for free. Scopes: `analyze`, `read:investigations`,
`read:threat_intel`, `research:honeypot`, `admin`.

## Honeypot isolation

`packages/agents/honeypot/isolation.py`. The orchestrator calls
`authorize_engagement()` before invoking any engagement hook. All three must
hold:

1. `HONEYPOT_ENABLED=true`
2. a valid `X-Researcher-Key` header (separate secret from any consumer key)
3. `confirmed_scam` — and that comes from the pipeline's own detection output,
   not from anything in the request body

In `ENVIRONMENT=production`, startup fails loudly if the honeypot is enabled
without its key, or a bot token is set without its webhook secret.

## Stack

- **Python 3.11+**, **FastAPI**, **arq** worker, SQLAlchemy async + **Alembic**
- **PostgreSQL + pgvector**, **Redis**, **MinIO** (S3-compatible object storage)
- **Next.js 16** (App Router) — `apps/web`
- Multi-provider LLM gateway — Gemini by default; OpenAI / Anthropic / Groq / OpenRouter / Ollama optional
- **scikit-learn** classifiers; optional `torch` / `transformers` / `sentence-transformers` / EasyOCR (CPU-only wheels)
- **Docker Compose** + **Caddy** locally; **Terraform** (`infra/terraform/`) for AWS (VPC, ALB, ECS/ECR, RDS, ElastiCache, S3, CloudFront)

## Layout

```
apps/
  api/            FastAPI app — routers: auth, health, investigations, threat_intel
  worker/         arq background tasks (one job per investigation)
  web/            Next.js frontend
  telegram_bot/   Telegram webhook adapter
  whatsapp_bot/   WhatsApp (Meta Cloud API) webhook adapter
packages/
  agents/         honeypot, investigation, protection, incident_response
  domain/         entities, investigations (orchestrator), reports, risk, threat_intel
  ingestion/      text, url, image (OCR), pdf, audio
  llm/            gateway, router, providers, policies, prompts
  ml/             text / url / vision classifiers, inference, model registry
  reports/        generator, serializers
  threat_intel/   feeds, indicators, reputation, campaigns, correlation
  shared/         config, db, schemas, security, storage, telemetry
ml-models/        trained artifacts + evaluation sets
migrations/       Alembic migrations
scripts/          API-key management, dataset + model training/eval, retention purge
infra/            Docker (Caddy) + Terraform (AWS)
```

## Quickstart (Docker)

```bash
cp .env.example .env
# set GEMINI_API_KEY and API_SECRET_KEY — those two are all you need to boot
docker compose up -d
```

Brings up Postgres (pgvector), Redis, MinIO, the API, the worker, the web app,
and Caddy (`infra/docker/Caddyfile`) fronting web + API. For a hosted install
(domain, TLS, EC2 sizing) see [DEPLOYMENT.md](DEPLOYMENT.md).

## Local dev (no Docker)

Backend — needs Postgres + Redis + MinIO (`docker compose up -d postgres redis minio`):

```bash
uv sync
uv run alembic upgrade head
uv run main.py                                   # API on http://localhost:10000  (docs at /docs)
uv run arq apps.worker.settings.WorkerSettings   # background worker
```

Frontend:

```bash
cd apps/web
pnpm install
pnpm dev                                         # http://localhost:3000
```

`apps/web/.env.local` already points `NEXT_PUBLIC_API_URL` at `http://localhost:10000`.

Web routes: `/onboarding`, `/forgot-password`, and under the app shell
`/dashboard`, `/analyze` (+ `/analyze/investigating`), `/investigations`,
`/reports/[id]`, `/threat-intel` (+ `/campaigns/[id]`), `/channels`
(+ `/telegram`, `/whatsapp`), `/settings`, `/privacy`.

## Configuration

Only `GEMINI_API_KEY` and `API_SECRET_KEY` are required in development.
Everything else in `.env.example` is optional and self-documenting.

| Group | Notes |
|-------|-------|
| **LLM providers** | Fill only the keys you have. An unconfigured provider reports `DISABLED` and the router skips it. Any `*_API_KEY` accepts a comma-separated list for failover. |
| **Channels** | `TELEGRAM_BOT_TOKEN` + `TELEGRAM_WEBHOOK_SECRET`, or the `WHATSAPP_*` set. Without its secret, a webhook rejects every request. |
| **Honeypot** | `HONEYPOT_ENABLED` + `HONEYPOT_RESEARCHER_KEY`. In `ENVIRONMENT=production`, startup fails if the honeypot is enabled without its key. |
| **Persistence** | `DATABASE_URL`, `REDIS_URL`, `S3_*`. Unset → in-memory fallbacks; the async queue runs investigations inline. |
| **Deploy** | `NEXT_PUBLIC_API_URL` is baked into the web image at build time — set it before `docker compose build`, not after. Also `CORS_ALLOWED_ORIGINS`. |
| **Observability** | `OTEL_EXPORTER_OTLP_ENDPOINT`, `SENTRY_DSN` — unset means off. |

Scoped API keys are created out of band, never stored in `.env`:

```bash
uv run python scripts/manage_api_keys.py create --principal <name> --scopes <scope...>
```

## Optional ML extras

```bash
uv sync --extra ml         # torch + transformers — zero-shot / spam HF pipelines
uv sync --extra semantic   # sentence-transformers embedding classifier
uv sync --extra ocr        # EasyOCR local image text extraction
```

`torch` / `torchvision` are pinned to the CPU-only wheel index
(`[tool.uv.sources]`), so these stay small and GPU-free.

## Tests

```bash
uv run pytest                 # tests/: unit, integration, e2e, security
cd apps/web && pnpm lint
```
