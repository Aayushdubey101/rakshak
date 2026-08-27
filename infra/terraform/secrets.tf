# Secrets Manager (task.md phase 15; phase 14 already documented ".env in
# development, AWS Secrets Manager in production"). Terraform owns the
# container -- DATABASE_URL/REDIS_URL, computed from resources this module
# already provisioned, so they're never re-typed by hand and never appear in
# a task definition's plaintext environment. Every other secret
# (API_SECRET_KEY, LLM provider keys, HONEYPOT_RESEARCHER_KEY, webhook
# secrets) is a container ECS reads from at task-start; terraform creates
# the empty container so `aws secretsmanager put-secret-value` has
# somewhere to write, but never sets its value -- keeping real credentials
# out of state and out of this repository.

resource "aws_secretsmanager_secret" "database_url" {
  name = "rakshak/database-url"
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id = aws_secretsmanager_secret.database_url.id
  secret_string = "postgresql+asyncpg://${var.db_username}:${random_password.db.result}@${aws_db_instance.main.address}:5432/${var.db_name}"
}

resource "aws_secretsmanager_secret" "redis_url" {
  name = "rakshak/redis-url"
}

resource "aws_secretsmanager_secret_version" "redis_url" {
  secret_id     = aws_secretsmanager_secret.redis_url.id
  secret_string = "rediss://${aws_elasticache_replication_group.main.primary_endpoint_address}:6379/0"
}

resource "aws_secretsmanager_secret" "app_secrets" {
  for_each = toset([
    "api-secret-key",
    "honeypot-researcher-key",
    "gemini-api-key",
    "openai-api-key",
    "anthropic-api-key",
    "groq-api-key",
    "openrouter-api-key",
    "telegram-bot-token",
    "telegram-webhook-secret",
    "whatsapp-access-token",
    "whatsapp-app-secret",
    "whatsapp-verify-token",
    "sentry-dsn",
  ])
  name = "rakshak/${each.value}"
}
