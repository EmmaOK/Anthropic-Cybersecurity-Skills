# Overriding the previous Phantom deployment

You previously deployed Phantom via **`infra/phantom-mcp/`**. That stack is two things
in one:
- an **MCP server** (ECS Fargate service + ALB, Bedrock-backed), and
- a **Kali EC2** offensive backend (with its SSH key in Secrets Manager).

The new **`deploy/terraform/`** stack is the full Phantom **application** — the API +
worker + queue + Postgres/Redis/S3 control plane (this repo's `phantom/` code).

**Decision (chosen): the new app stack becomes the canonical Phantom; keep the Kali
box as the isolated offensive plane; retire only the old MCP-server compute.**

The two stacks use different name prefixes (`phantom` vs `phantom-mcp`) and the new
stack creates its own VPC, so **they do not collide** — "override" is a deliberate
cutover, done in this order.

```
        BEFORE                              AFTER
  infra/phantom-mcp:                  deploy/terraform  (canonical Phantom app)
    ├─ MCP server (ECS+ALB) ──►  retire (scale to 0, then tear down)
    └─ Kali EC2  ────────────────────►  KEEP (offensive plane; app calls it)
```

---

## Step 1 — Deploy the new app stack

Follow `deploy/terraform/README.md`. Bring it up and confirm it's healthy
(`terraform output alb_url`, then hit `/api/queue/health` with an admin token).

## Step 2 — Retire the old MCP-server compute (reversible first)

The MCP service has `ignore_changes = [desired_count]`, so scale it via the CLI, not
Terraform. This **stops the MCP app immediately, keeps everything else (including
Kali), and is fully reversible**:

```bash
# names come from `cd infra/phantom-mcp && terraform output` or the ECS console
aws ecs update-service \
  --cluster phantom-mcp-<env> \
  --service <mcp-service-name> \
  --desired-count 0
```

At this point the new stack is the live Phantom and the old MCP app is off. Verify
the new deployment for a few days before making the teardown permanent.

## Step 3 — Repoint integrations at the new stack

Update anything that pointed at the old MCP ALB:
- **GuardDuty** → EventBridge API Destination → the new `guardduty_webhook` output.
- **PhishingBox / email add-ins** → the new ALB `/api/webhook/...` URLs.
- **DNS / SSO** → the new ALB.

## Step 4 — Make the teardown permanent (when confident)

Targeted destroy of **only** the MCP-server resources. **Kali is never in the target
list, so it is provably untouched.** Always run `plan` first and read it.

```bash
cd infra/phantom-mcp
terraform plan -destroy \
  -target=aws_ecs_service.phantom_mcp \
  -target=aws_ecs_cluster_capacity_providers.phantom_mcp \
  -target=aws_ecs_cluster.phantom_mcp \
  -target=aws_ecs_task_definition.phantom_mcp \
  -target=aws_appautoscaling_policy.phantom_mcp_cpu \
  -target=aws_appautoscaling_target.phantom_mcp \
  -target=aws_cloudwatch_log_group.phantom_mcp \
  -target=aws_lb_listener.https \
  -target=aws_lb_listener.http_redirect \
  -target=aws_lb_target_group.phantom_mcp \
  -target=aws_lb.phantom_mcp \
  -target=aws_ecr_lifecycle_policy.phantom_mcp \
  -target=aws_ecr_repository.phantom_mcp
# review, then swap `plan -destroy` for `destroy` (same -targets) to apply
```

Leave the ALB/ECS **security groups** and the MCP **IAM roles/secrets** for a final
pass — the Kali SG may reference the ECS SG, so remove any such rule (or leave the
now-empty SGs as harmless orphans) rather than forcing a dependency error.

### KEEP — never destroy these (the Kali offensive plane)

```
aws_instance.kali            aws_security_group.kali
aws_key_pair.kali            aws_iam_role.kali
tls_private_key.kali         aws_iam_instance_profile.kali
aws_secretsmanager_secret.kali_ssh_key (+ version)
```

---

## Step 5 (follow-up) — Let the new app *use* the retained Kali box

Today the new app stack has no path to Kali. To wire the offensive plane in:

- **Networking** — the old stack put Kali in an **existing VPC** (`var.vpc_id`). Either
  deploy the new app into that **same VPC** (add an "existing VPC" option to
  `deploy/terraform/network.tf`), or **peer** the new app VPC to Kali's VPC.
- **Reachability** — allow the worker security group → Kali `:22`.
- **Credentials** — grant the worker task role read on `aws_secretsmanager_secret.kali_ssh_key`,
  and pass `KALI_HOST=<kali private ip>` + the key to the workers (see `phantom/kali.py`).

This is the "isolated offensive plane" from the deployment strategy. Tell me whether
you want **shared-VPC** or **VPC-peering** and I'll wire it.

---

## Safety

- `terraform plan` before every `apply`/`destroy`; read what changes.
- Step 2 (`desired-count 0`) is reversible — do it first, live on the new stack, then
  make teardown permanent.
- The Kali box, its SSH key, and its IAM are never targeted for destruction.
