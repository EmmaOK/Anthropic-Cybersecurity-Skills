# /api-design-review

Runs a STRIDE + ASVS design review for backend APIs and microservices.
Intended for: Backend teams, Integration teams, Platform API teams.

**Usage:** `/api-design-review $ARGUMENTS`

**Example:** `/api-design-review "Order management API — REST, JWT auth, PostgreSQL, consumed by mobile and web clients"`

---

You are a backend security architect reviewing the API described in $ARGUMENTS.

## Step 1 — Map the attack surface

Ask for (or infer from the description):
- Auth mechanism (JWT, OAuth2, API key, mTLS)
- Data stores (PostgreSQL, Redis, S3, etc.)
- External integrations (third-party APIs, webhooks)
- Consumers (mobile app, web frontend, other services, B2B partners)

## Step 2 — Run STRIDE threat model

Use `run_skill_agent`:
```
skill_name: performing-stride-threat-modeling
args: ["init", "--system", "<name>"]
```

Then analyze per component type (auth layer, data layer, API layer).

## Step 3 — OWASP API Security Top 10 check

Use `search_skills` with query `"API security OWASP"` and load:
- `testing-api-for-broken-object-level-authorization` — BOLA/IDOR check
- `testing-api-authentication-weaknesses` — auth design review
- `exploiting-api-injection-vulnerabilities` — injection surface review

For each, summarize which controls must be in the design (not just tests — design-time decisions).

## Step 4 — ASVS level assessment

```
skill_name: performing-asvs-compliance-assessment
args: ["init", "--app", "<name>", "--url", "<design-doc-url>", "--level", "2"]
```

Level guide: internal APIs = L1, customer-facing = L2, financial/health = L3.

## Step 5 — Output

Standard design review summary plus an **API risk checklist**:

### Pre-build security requirements
- [ ] Auth: token expiry, refresh rotation, revocation endpoint defined
- [ ] BOLA: every endpoint has object ownership check in design spec
- [ ] Input validation: schema defined for all request bodies
- [ ] Rate limiting: per-user limits specified in API spec
- [ ] Sensitive fields: PII fields flagged for masking in logs

Save to `security/api-design-review-<system>.md`.
