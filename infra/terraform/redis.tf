# ElastiCache Redis (task.md phase 7's session state / rate limiting /
# webhook dedup / async queue broker, phase 15's managed instance).

resource "aws_elasticache_subnet_group" "main" {
  name       = "rakshak-redis"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id = "rakshak-redis"
  description           = "Rakshak session state, rate limiting, webhook dedup, arq broker"

  engine         = "redis"
  engine_version = "7.1"
  node_type      = var.redis_node_type
  port           = 6379

  num_cache_clusters        = var.environment == "production" ? 2 : 1
  automatic_failover_enabled = var.environment == "production"

  subnet_group_name = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  # No automated backup without this -- default snapshot_retention_limit is
  # 0. Session state/rate-limit data is disposable, but the arq queue broker
  # living here means an unplanned failover with zero retention loses
  # in-flight jobs, not just cache warmth.
  snapshot_retention_limit = var.environment == "production" ? 7 : 1
  snapshot_window          = "05:00-06:00"

  tags = { Name = "rakshak-redis" }
}
