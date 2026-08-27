# Rakshak AWS deployment (task.md phase 15).
#
# Not applied against a live account in this repository -- same precedent as
# phase 7's Postgres/Redis/S3 clients: built against the real provider,
# verified for internal consistency (`terraform validate`/`plan` need real
# credentials + a configured backend this environment doesn't have), not
# run for real. Configure the S3 backend below before the first real apply.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # backend "s3" {
  #   bucket         = "rakshak-terraform-state"
  #   key            = "rakshak/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "rakshak-terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "rakshak"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
