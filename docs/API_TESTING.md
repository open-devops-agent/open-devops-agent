# API Testing Guide

How to test all DevOps AI Agent APIs using **Postman** or **curl**.

---

## Prerequisites

1. Agent running locally:

```bash
cp .env.example .env
# Set ANTHROPIC_API_KEY, SLACK_WEBHOOK_URL (optional for testing), ORG_ID

uvicorn api.server:app --reload --port 8000
```

2. For durable storage (optional):

```bash
# Local with MinIO
docker compose up -d

# Or use in-memory (default, data lost on restart)
STORAGE_PROVIDER=memory
```

---

## Postman setup

### 1. Import collection and environment

1. Open Postman → **Import**
2. Import both files:
   - `postman/DevOps-AI-Agent.postman_collection.json`
   - `postman/DevOps-AI-Agent-Local.postman_environment.json`
3. Select **DevOps AI Agent — Local** environment (top-right dropdown)

### 2. Configure variables

| Variable | Default | Description |
|----------|---------|-------------|
| `baseUrl` | `http://localhost:8000` | Agent URL |
| `orgId` | `acme-corp` | Your organization ID |
| `docPath` | `runbooks/k8s-oom.md` | Doc path for file upload tests |
| `incidentId` | *(auto-set)* | Set by webhook test scripts |

### 3. Run the end-to-end flow

Use the **End-to-End Test Flow** folder — run requests **in order**:

| Step | Request | Expected |
|------|---------|----------|
| 1 | Health Check | `status: ok`, `queue_worker: true` |
| 2 | Upload Runbook | `status: uploaded` |
| 3 | Trigger K8s Incident | `status: queued`, saves `incidentId` |
| 4 | Poll Audit | Incident appears after ~30–60s (re-run if needed) |

> **Tip:** Use Postman **Collection Runner** on the "End-to-End Test Flow" folder. Add a 30s delay before step 4, or run step 4 manually after waiting.

### 4. Run individual folders

| Folder | What it tests |
|--------|---------------|
| Health, status & audit | `/health`, `/status`, `/audit` |
| Organization Documentation | CRUD for org runbooks |
| Webhooks | Manual, Alertmanager, GitHub triggers |
| Slack Integration | Approval callbacks (normally Slack-only) |

---

## curl test procedures

### Test 1: Health check

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

Expected:

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

### Test 2: Upload org runbook

```bash
curl -H "Authorization: Bearer $API_TOKEN" -s -X POST http://localhost:8000/orgs/acme-corp/docs \
  -H "Content-Type: application/json" \
  -d '{
    "path": "runbooks/k8s-oom.md",
    "content": "# OOM Runbook\n1. Run get_k8s_context\n2. Increase memory to 512Mi\nEvidence: cite exact log lines."
  }' | python3 -m json.tool
```

Verify listed:

```bash
curl -H "Authorization: Bearer $API_TOKEN" -s "http://localhost:8000/orgs/acme-corp/docs?prefix=runbooks" | python3 -m json.tool
```

Verify content:

```bash
curl -H "Authorization: Bearer $API_TOKEN" -s http://localhost:8000/orgs/acme-corp/docs/runbooks/k8s-oom.md | python3 -m json.tool
```

---

### Test 3: Upload doc from file

```bash
echo "# Server Runbook\nCheck disk with df -h" > /tmp/server-runbook.md

curl -H "Authorization: Bearer $API_TOKEN" -s -X POST "http://localhost:8000/orgs/acme-corp/docs/upload?path=runbooks/server-disk.md" \
  -F "file=@/tmp/server-runbook.md" | python3 -m json.tool
```

---

### Test 4: Trigger manual K8s incident

```bash
RESPONSE=$(curl -s -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: acme-corp" \
  -d '{
    "type": "k8s",
    "namespace": "default",
    "pod": "test-pod",
    "description": "E2E test incident"
  }')

echo "$RESPONSE" | python3 -m json.tool
INCIDENT_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['incident_id'])")
echo "Incident ID: $INCIDENT_ID"
```

Expected: `"status": "queued"`

---

### Test 5: Trigger Alertmanager webhook

```bash
curl -s -X POST http://localhost:8000/webhook/alertmanager \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: acme-corp" \
  -d '{
    "alerts": [{
      "status": "firing",
      "labels": {
        "alertname": "HighMemory",
        "severity": "warning",
        "namespace": "staging"
      },
      "annotations": {
        "summary": "Memory usage above 85%"
      }
    }]
  }' | python3 -m json.tool
```

---

### Test 6: Poll audit log

Wait 30–60 seconds for the queue worker, then:

```bash
curl -H "Authorization: Bearer $API_TOKEN" -s "http://localhost:8000/audit?org_id=acme-corp&limit=10" | python3 -m json.tool
```

Look for your `incident_id` in the `events` array. Each entry includes:

- `diagnosis` — agent conclusion with Evidence section
- `grounding.grounded` — `true` if backed by tool evidence
- `actions_taken` — tools called and results
- `resolved` — whether incident was grounded and resolved

---

### Test 7: CI/CD manual trigger

```bash
curl -s -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: acme-corp" \
  -d '{
    "type": "cicd",
    "repo": "acme-corp/api-service",
    "run_id": 12345678,
    "description": "Build failed on main"
  }' | python3 -m json.tool
```

---

### Test 8: Delete org doc

```bash
curl -H "Authorization: Bearer $API_TOKEN" -s -X DELETE http://localhost:8000/orgs/acme-corp/docs/runbooks/server-disk.md | python3 -m json.tool
```

---

## Automated test script

Run the included simulation script:

```bash
# Start agent first, then:
python3 scripts/test_api_flow.sh
```

Or use pytest for service-layer tests:

```bash
python3 -m pytest tests/test_services.py -v
```

---

## Testing with MinIO storage

```bash
docker compose up -d

# In .env:
STORAGE_PROVIDER=minio
STORAGE_ENDPOINT_URL=http://localhost:9000
STORAGE_ACCESS_KEY=minioadmin
STORAGE_SECRET_KEY=minioadmin
STORAGE_BUCKET=devops-agent
ORG_ID=acme-corp
```

MinIO console: http://localhost:9001 (login: `minioadmin` / `minioadmin`)

After triggering an incident, verify objects in bucket:

```text
acme-corp/queue/pending/
acme-corp/audit/2026/06/INC-...
acme-corp/logs/2026/06/INC-.../
acme-corp/docs/runbooks/
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `status: queued` but no audit entry | Wait longer; check agent logs for queue worker errors |
| `queue_worker: false` in /status | Server still starting — wait a few seconds |
| `resolved: false`, `grounded: false` | Expected without real infra — agent requires tool evidence |
| `401` on GitHub webhook | Set `WEBHOOK_SECRET` and sign payload, or unset secret for local testing |
| Empty audit for wrong org | Pass matching `org_id` query param or `X-Org-ID` header |
| Anthropic API errors | Verify `ANTHROPIC_API_KEY` in `.env` |

---

## Production testing checklist

- [ ] `GET /health` returns `{"status": "ok"}` and `GET /status` (with a token) returns `queue_worker: true`
- [ ] Upload runbook via `POST /orgs/{org}/docs`
- [ ] Trigger test incident via `POST /webhook/manual`
- [ ] Audit entry appears in `GET /audit?org_id=...`
- [ ] Slack notification received (if configured)
- [ ] Objects visible in cloud storage bucket
- [ ] PII scrubbed in audit (no raw emails/tokens)
- [ ] Restart agent — pending queue items resume processing

---

## Related

- [API Reference](API_REFERENCE.md) — full endpoint documentation
- [Postman collection](../postman/DevOps-AI-Agent.postman_collection.json)
- [Getting Started](GETTING_STARTED.md)
