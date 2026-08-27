# CloudFront + WAF in front of the ALB (architecture doc's own edge:
# "Internet -> CloudFront / WAF -> ALB -> ECS/Fargate"). WAFv2 for
# CloudFront must live in us-east-1 regardless of `var.aws_region` -- a
# second provider alias, not a hardcoded region on the main provider.

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

resource "aws_wafv2_web_acl" "edge" {
  provider    = aws.us_east_1
  name        = "rakshak-edge"
  scope       = "CLOUDFRONT"
  description = "Managed rule baseline in front of the Rakshak API"

  default_action {
    allow {}
  }

  rule {
    name     = "aws-common-rule-set"
    priority = 0
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rakshak-common-rule-set"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rakshak-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "rakshak-edge"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudfront_distribution" "main" {
  enabled         = true
  is_ipv6_enabled = true
  web_acl_id      = aws_wafv2_web_acl.edge.arn
  aliases         = var.domain_name != "" ? [var.domain_name] : []

  origin {
    domain_name = aws_lb.main.dns_name
    origin_id   = "rakshak-alb"
    custom_origin_config {
      http_port              = 80
      https_port              = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods          = ["GET", "HEAD"]
    target_origin_id        = "rakshak-alb"
    viewer_protocol_policy  = "redirect-to-https"

    # API responses are per-caller and change every request -- caching them
    # would leak one investigator's report to another.
    forwarded_values {
      query_string = true
      headers      = ["Authorization", "X-Api-Key", "X-Researcher-Key"]
      cookies {
        forward = "none"
      }
    }
    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn            = var.domain_name != "" ? var.acm_certificate_arn : null
    ssl_support_method             = var.domain_name != "" ? "sni-only" : null
    minimum_protocol_version       = "TLSv1.2_2021"
    cloudfront_default_certificate = var.domain_name == ""
  }

  tags = { Name = "rakshak-cdn" }
}
