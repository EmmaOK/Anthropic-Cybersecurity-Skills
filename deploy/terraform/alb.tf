# ---------------------------------------------------------------------------
# ALB in front of the API service (+ optional WAF). Webhooks (GuardDuty via
# EventBridge API Destination, PhishingBox) hit the same ALB with a service
# token; lock var.allowed_cidrs down and rely on the app's token/RBAC + WAF.
# For SSO on the browser UI, add an authenticate-oidc action to the HTTPS
# listener (needs your IdP details) — the app-layer RBAC still applies underneath.
# ---------------------------------------------------------------------------
resource "aws_lb" "api" {
  name               = "${var.name}-api"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.vpc.public_subnets
}

resource "aws_lb_target_group" "api" {
  name        = "${var.name}-api"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = module.vpc.vpc_id
  target_type = "ip"   # required for Fargate
  health_check {
    path                = "/api/queue/health"
    matcher             = "200,401,403" # authed endpoint: any of these means "app is up"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

# HTTPS when a cert is provided, else HTTP (dev only).
resource "aws_lb_listener" "https" {
  count             = var.certificate_arn == "" ? 0 : 1
  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.api.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    # redirect to HTTPS if a cert exists, else forward (dev)
    type             = var.certificate_arn == "" ? "forward" : "redirect"
    target_group_arn = var.certificate_arn == "" ? aws_lb_target_group.api.arn : null
    dynamic "redirect" {
      for_each = var.certificate_arn == "" ? [] : [1]
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }
}

# --- WAF (AWS managed rules) ---
resource "aws_wafv2_web_acl" "api" {
  count       = var.enable_waf ? 1 : 0
  name        = "${var.name}-waf"
  scope       = "REGIONAL"
  default_action { allow {} }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-waf"
    sampled_requests_enabled   = true
  }
  rule {
    name     = "common"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_wafv2_web_acl_association" "api" {
  count        = var.enable_waf ? 1 : 0
  resource_arn = aws_lb.api.arn
  web_acl_arn  = aws_wafv2_web_acl.api[0].arn
}
