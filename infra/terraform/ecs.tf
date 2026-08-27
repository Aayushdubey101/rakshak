# ECS/Fargate: one API service behind the ALB, one worker service with no
# listener (task.md phase 15's "one API process + one worker process from
# phase 13" -- Fargate tasks, not EC2, so there's no host to patch).

resource "aws_ecs_cluster" "main" {
  name = "rakshak"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/rakshak/api"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/rakshak/worker"
  retention_in_days = 30
}

locals {
  # Every provider/channel secret is optional at the application layer
  # (packages/shared/config/settings.py: `Optional[str] = None`, DISABLED
  # when absent) -- resolving to an empty string here if the operator hasn't
  # populated a given secret in Secrets Manager still boots the container,
  # same "no fake stubs, just DISABLED" rule the rest of this codebase uses.
  app_secret_env = {
    API_SECRET_KEY           = "api-secret-key"
    HONEYPOT_RESEARCHER_KEY  = "honeypot-researcher-key"
    GEMINI_API_KEY            = "gemini-api-key"
    OPENAI_API_KEY            = "openai-api-key"
    ANTHROPIC_API_KEY         = "anthropic-api-key"
    GROQ_API_KEY              = "groq-api-key"
    OPENROUTER_API_KEY        = "openrouter-api-key"
    TELEGRAM_BOT_TOKEN        = "telegram-bot-token"
    TELEGRAM_WEBHOOK_SECRET   = "telegram-webhook-secret"
    WHATSAPP_ACCESS_TOKEN     = "whatsapp-access-token"
    WHATSAPP_APP_SECRET       = "whatsapp-app-secret"
    WHATSAPP_VERIFY_TOKEN     = "whatsapp-verify-token"
    SENTRY_DSN                = "sentry-dsn"
  }

  common_secrets = concat(
    [
      { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.database_url.arn },
      { name = "REDIS_URL", valueFrom = aws_secretsmanager_secret.redis_url.arn },
    ],
    [for env_name, key in local.app_secret_env : {
      name      = env_name
      valueFrom = aws_secretsmanager_secret.app_secrets[key].arn
    }],
  )

  common_environment = [
    { name = "ENVIRONMENT", value = var.environment },
    { name = "S3_BUCKET", value = aws_s3_bucket.evidence.bucket },
    { name = "S3_REGION", value = var.aws_region },
  ]
}

resource "aws_ecs_task_definition" "api" {
  family                   = "rakshak-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.api_cpu
  memory                   = var.api_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn             = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "api"
    image     = var.api_image
    essential = true
    portMappings = [{ containerPort = var.container_port, protocol = "tcp" }]
    environment = concat(local.common_environment, [{ name = "PORT", value = tostring(var.container_port) }])
    secrets     = local.common_secrets
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.api.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "api"
      }
    }
  }])
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "rakshak-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn             = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name        = "worker"
    image       = var.worker_image
    essential   = true
    environment = local.common_environment
    secrets     = local.common_secrets
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.worker.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "worker"
      }
    }
  }])
}

resource "aws_ecs_service" "api" {
  name            = "rakshak-api"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.ecs.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = var.container_port
  }

  depends_on = [aws_lb_listener.https]
}

resource "aws_ecs_service" "worker" {
  name            = "rakshak-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.ecs.id]
  }
}
