# Evidence/report/media object storage (task.md phase 7's
# packages/shared/storage/object_store.py::S3ObjectStore). The database
# stores keys, never blobs -- this bucket is where the blobs actually live.

resource "aws_s3_bucket" "evidence" {
  bucket = var.evidence_bucket_name
  tags   = { Name = "rakshak-evidence" }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Retention (task.md phase 7's per-data-class retention policy) is enforced
# in application code (scripts/retention_purge.py); this lifecycle rule is a
# second, independent backstop against a purge job that silently stops
# running, not a duplicate of the same policy.
resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
