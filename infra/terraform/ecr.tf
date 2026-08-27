# Image registries for infra/docker/Dockerfile.{api,worker}. `var.api_image`
# / `var.worker_image` (passed at apply time by CI after a push) are full
# `<repo_url>:<tag>` strings, not derived from these resources, so a
# first-time apply doesn't have a chicken/egg dependency on an image that
# hasn't been pushed yet.

resource "aws_ecr_repository" "api" {
  name                 = "rakshak-api"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "worker" {
  name                 = "rakshak-worker"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "api" {
  repository = aws_ecr_repository.api.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep last 20 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 20
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_ecr_lifecycle_policy" "worker" {
  repository = aws_ecr_repository.worker.name
  policy      = aws_ecr_lifecycle_policy.api.policy
}
