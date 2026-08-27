variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "production"
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "availability_zones" {
  type    = list(string)
  default = ["us-east-1a", "us-east-1b"]
}

# --- Compute -----------------------------------------------------------
variable "api_image" {
  description = "Full ECR image URI:tag for the API service. Built from infra/docker/Dockerfile.api."
  type        = string
}

variable "worker_image" {
  description = "Full ECR image URI:tag for the worker service. Built from infra/docker/Dockerfile.worker."
  type        = string
}

variable "api_cpu" {
  type    = number
  default = 512
}

variable "api_memory" {
  type    = number
  default = 1024
}

variable "api_desired_count" {
  type    = number
  default = 2
}

variable "worker_cpu" {
  type    = number
  default = 512
}

variable "worker_memory" {
  type    = number
  default = 1024
}

variable "worker_desired_count" {
  type    = number
  default = 1
}

variable "container_port" {
  type    = number
  default = 10000
}

# --- Database ------------------------------------------------------------
variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "db_engine_version" {
  description = "Postgres version. 15.4+ ships pgvector as an RDS-supported extension."
  type        = string
  default     = "16.4"
}

variable "db_allocated_storage" {
  type    = number
  default = 50
}

variable "db_name" {
  type    = string
  default = "rakshak"
}

variable "db_username" {
  type    = string
  default = "rakshak"
}

variable "db_backup_retention_days" {
  description = "RDS automated backup retention. docs/deployment/runbook.md's restore drill relies on this."
  type        = number
  default     = 7
}

# --- Redis -----------------------------------------------------------------
variable "redis_node_type" {
  type    = string
  default = "cache.t4g.small"
}

# --- Object storage --------------------------------------------------------
variable "evidence_bucket_name" {
  type    = string
  default = "rakshak-evidence"
}

# --- Edge --------------------------------------------------------------
variable "acm_certificate_arn" {
  description = "ACM cert (us-east-1, matching the region CloudFront requires) for the ALB HTTPS listener."
  type        = string
}

variable "domain_name" {
  description = "Public hostname CloudFront serves, e.g. app.rakshak.example. Empty disables the alias/cert binding on the distribution."
  type        = string
  default     = ""
}
