-- Postgres runs every *.sql in /docker-entrypoint-initdb.d/ once, only on a
-- fresh data directory (docker-compose.yml mounts this file there for the
-- `postgres` service). Same requirement infra/terraform/rds.tf's RDS
-- instance needs run manually once (see docs/deployment/runbook.md) --
-- Terraform can provision the instance but can't issue SQL against it.
CREATE EXTENSION IF NOT EXISTS vector;
