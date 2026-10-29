# API Reference

Base URL: `http://localhost:8000` (local) or your deployed agent URL.

All incident data is **org-scoped** and stored in cloud object storage (S3, MinIO, GCS, or Azure Blob).

---

## Authentication

| Endpoint group | Auth |
|----------------|------|
| `/health` | None (liveness probe) |
| `/audit`, `/orgs/{org_id}/config*`, `/orgs/{org_id}/docs*` | `Authorization: Bearer <token>`: `API_ADMIN_TOKEN` (any org) or the org's own token from `API_ORG_TOKENS`. See [Management API tokens](#management-api-tokens) |
| `/webhook/github` | `X-Hub-Signature-256` when `WEBHOOK_SECRET` is set |
| `/webhook/manual` | `X-Hub-Signature-256` **or** `X-Webhook-Signature` when `WEBHOOK_SECRET` is set |
| `/webhook/alertmanager`, `/webhook/grafana` | HMAC signature as above, **or** `Authorization: Bearer <WEBHOOK_SECRET>` (Alertmanager and Grafana cannot sign bodies) |
| `/slack/action` | `X-Slack-Signature` + `X-Slack-Request-Timestamp` when `SLACK_SIGNING_SECRET` is set (configured in Slack app settings) |

### Management API tokens

```bash
API_ADMIN_TOKEN=<long random string>                 # platform operator: every org
API_ORG_TOKENS=acme-corp=<token-a>,globex=<token-b>  # each token: only its own org
```

```bash
curl -H "Authorization: Bearer $API_TOKEN" http://localhost:8000/orgs/acme-corp/config/status
```

| Situation | Response |
|---|---|
| No `API_ADMIN_TOKEN` and no `API_ORG_TOKENS` configured | **503**: the API fails closed |
| Missing, malformed (not `Bearer`) or unknown token | **401** with `WWW-Authenticate: Bearer` |
| Valid org token used for a different org | **403** |
| Admin token, or the org's own token | Handled normally |

`API_AUTH_DISABLED=true` turns these checks off for local development (a warning is logged at
startup). For `/audit` the org is `org_id` from the query string, or `ORG_ID` when omitted.
Tokens are compared in constant time. The MCP server's network transports are not covered by these
tokens yet (see issue #116).

`X-Org-ID` is **not** authentication — it only selects the organization (see
[Org scoping](#org-scoping)) and is optional on every webhook.

### Webhook signatures

When `WEBHOOK_SECRET` is set, signed webhook endpoints require a hex HMAC-SHA256 of the
**raw request body**, keyed with `WEBHOOK_SECRET` and prefixed `sha256=`:

```bash
BODY='{"type":"k8s","namespace":"production"}'
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $2}')"

curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: $SIG" \
  -d "$BODY"
```

- A missing, malformed, or mismatched signature is rejected with **401** `{"detail": "Invalid signature"}`.
- `/webhook/manual` and `/webhook/alertmanager` accept either header, but `X-Hub-Signature-256`
  **takes precedence**: if it is present and invalid, `X-Webhook-Signature` is not consulted and the
  request is rejected. `/webhook/github` accepts only `X-Hub-Signature-256`.
- `/webhook/alertmanager` and `/webhook/grafana` also accept `Authorization: Bearer <WEBHOOK_SECRET>`,
  compared in constant time. A valid bearer token is accepted even if a signature header is also present.
- When `WEBHOOK_SECRET` is unset or empty, signature verification is skipped entirely and unsigned
  requests are accepted. Leave it unset only for local testing.

`/slack/action` uses Slack's own scheme instead (`v0=` HMAC-SHA256 over
`v0:{timestamp}:{body}` keyed with `SLACK_SIGNING_SECRET`, rejecting timestamps more than
5 minutes from the server clock), and returns **401** `{"detail": "Invalid Slack signature"}`
on failure.

---

## Org scoping

Set the organization in one of three ways (priority order):

1. `X-Org-ID` request header
2. `org_id` field in webhook JSON body
3. `ORG_ID` environment variable on the server (default: `default`)

All storage paths are prefixed with `{org_id}/`:

```text
{org_id}/audit/...
{org_id}/logs/...
{org_id}/docs/...
{org_id}/queue/...
{org_id}/checkpoints/...
```

---

## Endpoints

### `GET /health`

Health check and runtime status.

**Response 200:**

```json
{
  "status": "ok",
  "auto_apply": "false",
  "storage_provider": "memory",
  "org_id": "acme-corp",
  "queue_worker": true
}
```

---

### `GET /audit`

Returns org-scoped incident audit history from cloud storage.

**Query parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `org_id` | string | `ORG_ID` env | Organization to query |
| `limit` | int | `50` | Max events returned |

**Response 200:**

```json
{
  "org_id": "acme-corp",
  "events": [
    {
      "id": "INC-20260617120000-a1b2c3",
      "org_id": "acme-corp",
      "timestamp": "2026-06-17T12:00:00+00:00",
      "incident": { "type": "k8s", "namespace": "default" },
      "diagnosis": "Evidence: get_k8s_context showed OOMKilled...",
      "actions_taken": [{ "tool": "get_k8s_context", "result": {} }],
      "resolved": true,
      "grounding": { "grounded": true, "has_tool_evidence": true },
      "steps": 3,
      "escalated": false,
      "escalation_reasons": [],
      "duration_minutes": 4.2
    }
  ],
  "total": 1
}
```

When the agent cannot resolve an incident, audit entries include escalation metadata:

```json
{
  "escalated": true,
  "escalation_reasons": ["timeout_unresolved", "unresolved", "database_issue"],
  "duration_minutes": 12.5,
  "escalation": {
    "channels": {
      "slack": { "sent": true },
      "email": { "sent": true },
      "jira": { "created": true, "key": "OPS-456", "url": "https://..." },
      "zoho": { "created": true, "id": "12345" }
    }
  }
}
```

See [ESCALATION.md](ESCALATION.md) for configuration.

---

## Organization documentation

Org docs (runbooks, policies, playbooks) are loaded into the agent context during incidents.

**Allowed file extensions:** `.md`, `.txt`, `.yaml`, `.yml`, `.json`, `.rst`

### `POST /orgs/{org_id}/docs`

Upload documentation as JSON.

**Request body:**

```json
{
  "path": "runbooks/k8s-oom.md",
  "content": "# OOM Runbook\n1. Check pod logs\n2. Increase memory limits"
}
```

**Response 200:**

```json
{
  "status": "uploaded",
  "org_id": "acme-corp",
  "path": "runbooks/k8s-oom.md",
  "storage_key": "acme-corp/docs/runbooks/k8s-oom.md"
}
```

**Response 400:** Invalid path or unsupported extension.

---

### `POST /orgs/{org_id}/docs/upload`

Upload documentation from a file (multipart form).

**Query parameters:**

| Param | Required | Description |
|-------|----------|-------------|
| `path` | Yes | Storage path, e.g. `runbooks/k8s-oom.md` |

**Form field:**

| Field | Type | Description |
|-------|------|-------------|
| `file` | file | Document content |

**Example:**

```bash
curl -H "Authorization: Bearer $API_TOKEN" -X POST "http://localhost:8000/orgs/acme-corp/docs/upload?path=runbooks/k8s-oom.md" \
  -F "file=@./runbooks/k8s-oom.md"
```

---

### `GET /orgs/{org_id}/docs`

List documentation files.

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `prefix` | string | Filter by path prefix (optional) |

**Response 200:**

```json
{
  "org_id": "acme-corp",
  "docs": [
    { "path": "runbooks/k8s-oom.md", "key": "acme-corp/docs/runbooks/k8s-oom.md" }
  ]
}
```

---

### `GET /orgs/{org_id}/docs/{doc_path}`

Retrieve a single document.

**Response 200:**

```json
{
  "org_id": "acme-corp",
  "path": "runbooks/k8s-oom.md",
  "content": "# OOM Runbook\n..."
}
```

**Response 404:** Document not found.

---

### `DELETE /orgs/{org_id}/docs/{doc_path}`

Delete a document.

**Response 200:**

```json
{
  "status": "deleted",
  "org_id": "acme-corp",
  "path": "runbooks/k8s-oom.md"
}
```

---

## Webhooks

All webhooks **enqueue** incidents asynchronously. The response is immediate; processing happens in the background queue worker.

Poll `GET /audit` after ~10–60 seconds to see results.

### `POST /webhook/manual`

Manually trigger an incident.

**Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes | `application/json` |
| `X-Hub-Signature-256` or `X-Webhook-Signature` | If `WEBHOOK_SECRET` set | HMAC SHA-256 signature of the raw body (see [Webhook signatures](#webhook-signatures)) |
| `X-Org-ID` | No | Organization ID |

**Request body:**

| Field | Required | Description |
|-------|----------|-------------|
| `type` | **Yes** | `k8s`, `cicd`, `server`, `dockerfile`, `argocd`, `helm`, `terraform`, `cloud_aws`, `cloud_gcp`, `cloud_azure` |
| `namespace` | No | K8s namespace |
| `pod` | No | Pod name |
| `repo` | No | GitHub repo (`owner/repo`) |
| `run_id` | No | CI/CD run ID |
| `app_name` | No | ArgoCD application name |
| `description` | No | Human-readable description |
| `raw_logs` | No | Pre-collected logs |

**Example — K8s:**

```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: acme-corp" \
  -d '{
    "type": "k8s",
    "namespace": "production",
    "pod": "api-7d4f8b9c-xk2lp",
    "description": "Pod CrashLoopBackOff"
  }'
```

This unsigned example is accepted only while `WEBHOOK_SECRET` is unset; otherwise add a
signature header as shown under [Webhook signatures](#webhook-signatures).

**Response 200:**

```json
{
  "status": "queued",
  "incident_id": "INC-20260617120000-a1b2c3",
  "context": { "type": "k8s", "org_id": "acme-corp", ... }
}
```

**Response 400:** Missing `type` field.

**Response 401:** Missing or invalid webhook signature (when `WEBHOOK_SECRET` is set).

---

### `POST /webhook/grafana`

Receive Grafana Alerting notifications (webhook contact point). Same payload shape as Alertmanager,
plus Grafana fields.

**Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes | `application/json` |
| `Authorization` | If `WEBHOOK_SECRET` set (or sign instead) | `Bearer <WEBHOOK_SECRET>` — contact point → Optional settings → Authorization Header |
| `X-Hub-Signature-256` or `X-Webhook-Signature` | Alternative to `Authorization` | HMAC SHA-256 of the raw body |
| `X-Org-ID` | No | Organization ID (Grafana's numeric `orgId` is not used) |

Each `firing` alert is queued with `source: "grafana"`, the labels/annotations fields used for
Alertmanager, and `dashboard_url`, `panel_url`, `runbook_url`, `alert_values`, `starts_at`.

**Logs:** when `GRAFANA_URL` + `GRAFANA_LOKI_DATASOURCE_UID` (or `LOKI_URL`) are set, the agent attaches
`alert_logs` to the incident before diagnosis: up to 100 error-like lines from Loki, from 15 minutes
before `startsAt` (capped at 24 hours). The stream selector comes from the alert's `namespace`+`pod`,
`namespace`+`container`, `namespace`+`app`, `job`, `app`, `service_name`, `service` or `host` labels, in
that order; a `logql` annotation overrides it. The agent can run further LogQL with the read-only
`query_logs` tool.

**Response 200:** `{"status": "queued", "incident_ids": ["..."]}`

**Response 401:** Missing or invalid bearer token / signature (when `WEBHOOK_SECRET` is set).

---

### `POST /webhook/alertmanager`

Receive Prometheus Alertmanager alerts.

**Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes | `application/json` |
| `Authorization` | If `WEBHOOK_SECRET` set (or sign instead) | `Bearer <WEBHOOK_SECRET>` — set via `http_config.authorization` in `alertmanager.yml` |
| `X-Hub-Signature-256` or `X-Webhook-Signature` | Alternative to `Authorization` | HMAC SHA-256 signature of the raw body (see [Webhook signatures](#webhook-signatures)) |
| `X-Org-ID` | No | Organization ID |

**Request body:** Standard Alertmanager webhook JSON. Only `firing` alerts are queued. An alert
annotation `logql` (or `loki_query`) sets the Loki query used to attach logs; see `POST /webhook/grafana`.

**Example:**

```bash
curl -X POST http://localhost:8000/webhook/alertmanager \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: acme-corp" \
  -d '{
    "alerts": [{
      "status": "firing",
      "labels": {
        "alertname": "PodCrashLooping",
        "namespace": "production",
        "pod": "api-xyz"
      },
      "annotations": {
        "summary": "Pod is crash looping"
      }
    }]
  }'
```

**Response 200:**

```json
{
  "status": "queued",
  "incident_ids": ["INC-20260617120000-a1b2c3"]
}
```

**Response 401:** Missing or invalid webhook signature (when `WEBHOOK_SECRET` is set).

---

### `POST /webhook/github`

Receive GitHub Actions webhooks.

**Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `X-GitHub-Event` | Yes | Must be `workflow_run` |
| `X-Hub-Signature-256` | If `WEBHOOK_SECRET` set | HMAC SHA-256 signature |
| `X-Org-ID` | No | Organization ID |

Only processes `workflow_run` events where `conclusion` is `failure`.

**Response 200 (queued):**

```json
{
  "status": "queued",
  "type": "cicd",
  "incident_id": "INC-20260617120000-a1b2c3"
}
```

**Response 200 (ignored):**

```json
{
  "status": "ignored",
  "event": "push"
}
```

**Response 401:** Invalid webhook signature.

---

### `POST /slack/action`

Slack interactive button callback for approval workflow.

Approval buttons retain the organisation that requested the action. Execution
uses that organisation's credentials and restores the shared clients afterwards,
including when execution fails or is cancelled. Buttons created before this
organisation context was added must be requested again; callbacks without it
return HTTP 400 instead of selecting an organisation implicitly.

**Who can approve:** set `SLACK_APPROVER_IDS` to a comma-separated list of Slack user IDs (globally, or
per org with `PUT /orgs/{org_id}/config`; the org's value wins). A click from anyone else gets an
ephemeral "not an approver" reply and nothing runs. Without the setting, any channel member can approve
and a warning is logged. Every approval, rejection and refusal is stored as an
`approval-<timestamp>-<decision>.json` incident log with the Slack user ID and name and the command,
and the confirmation message names the approver.

**Content-Type:** `application/x-www-form-urlencoded`

**Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `X-Slack-Signature` | If `SLACK_SIGNING_SECRET` set | Slack `v0=` request signature |
| `X-Slack-Request-Timestamp` | If `SLACK_SIGNING_SECRET` set | Unix seconds; rejected if more than 5 minutes from the server clock |

**Form field:** `payload` — JSON string from Slack.

Normally configured in your Slack app as the Interactivity Request URL. Slack sends both
headers on interactive payloads; set `SLACK_SIGNING_SECRET` to the app's signing secret to
have them verified.

**Response 401:** Missing, stale, or invalid Slack signature (when `SLACK_SIGNING_SECRET` is set).
When the secret is unset, verification is skipped entirely.

---

## Incident types

| `type` value | Use case |
|--------------|----------|
| `k8s` | Pod crashes, OOM, ImagePullBackOff |
| `cicd` | Pipeline/build failures |
| `server` | CPU, memory, disk, nginx/systemd |
| `dockerfile` | Docker build failures |
| `argocd` | GitOps sync/health issues |
| `cloud_aws` | AWS resource issues |
| `cloud_gcp` | GCP resource issues |
| `cloud_azure` | Azure resource issues |

---

## Async processing model

```text
Webhook received
       │
       ▼
Enqueue to {org_id}/queue/pending/
       │
       ▼
Background worker claims incident
       │
       ▼
Agent runs (with checkpoint resume)
       │
       ├── Logs → {org_id}/logs/{year}/{month}/{incident_id}/
       ├── Audit → {org_id}/audit/{year}/{month}/{incident_id}.json
       └── Slack notification
```

**Queue worker settings** (`.env`):

```bash
QUEUE_POLL_INTERVAL_SEC=5
ORG_ID=acme-corp
ORG_IDS=acme-corp,beta-corp   # multi-tenant worker
```

---

## Storage configuration

```bash
STORAGE_PROVIDER=memory   # dev: memory | s3 | minio | gcs | azure
STORAGE_BUCKET=devops-agent
ORG_ID=acme-corp
AUDIT_RETENTION_DAYS=90
```

See `.env.example` for provider-specific settings — including the MinIO
(`STORAGE_ENDPOINT_URL`, `STORAGE_ACCESS_KEY`, `STORAGE_SECRET_KEY`) and Azure
(`AZURE_STORAGE_CONNECTION_STRING`, `AZURE_STORAGE_ACCOUNT_URL`) credentials.
It lists every variable the server reads, and
`tests/test_env_example_coverage.py` keeps it that way.

---

## Related docs

- [API Testing Guide](API_TESTING.md) — Postman and curl test procedures
- [Postman collection](../postman/DevOps-AI-Agent.postman_collection.json)
- [Getting Started](GETTING_STARTED.md)
