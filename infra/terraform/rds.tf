# Postgres + pgvector (task.md phase 7's schema, phase 15's managed
# instance). `CREATE EXTENSION vector;` still has to run once against the
# database after provisioning -- RDS supports the extension, terraform can't
# issue arbitrary SQL against it -- documented in docs/deployment/runbook.md.

resource "aws_db_subnet_group" "main" {
  name       = "rakshak-db"
  subnet_ids = aws_subnet.private[*].id
  tags       = { Name = "rakshak-db-subnet-group" }
}

resource "random_password" "db" {
  length  = 32
  special = false
}

resource "aws_db_instance" "main" {
  identifier     = "rakshak-postgres"
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_allocated_storage * 4
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.db_name
  username = var.db_username
  password = random_password.db.result

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false

  backup_retention_period = var.db_backup_retention_days
  backup_window           = "03:00-04:00"
  maintenance_window      = "mon:04:30-mon:05:30"
  copy_tags_to_snapshot   = true

  multi_az                   = var.environment == "production"
  deletion_protection        = var.environment == "production"
  skip_final_snapshot        = var.environment != "production"
  final_snapshot_identifier  = var.environment == "production" ? "rakshak-postgres-final" : null
  auto_minor_version_upgrade = true

  tags = { Name = "rakshak-postgres" }
}
