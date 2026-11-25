# Org credentials: validation, rotation and revocation

Each org stores its own keys (Anthropic or another LLM provider, Slack, GitHub, cloud, …) with
`PUT`/`PATCH /orgs/{org_id}/config`. They are encrypted at rest when `ENCRYPT_CREDENTIALS=true` with a `CREDENTIALS_MASTER_KEY`
and are only ever returned as key names, never values.

## Endpoints (admin role for the org, or the platform admin token)

| Method | Path | What it does |
|---|---|---|
| `PUT` | `/orgs/{org}/config` | Replace the whole stored set |
| `PATCH` | `/orgs/{org}/config` | Set or rotate the given keys; `null` or `""` removes a key; others are kept |
| `DELETE` | `/orgs/{org}/config` | Revoke everything stored for the org |
| `DELETE` | `/orgs/{org}/config?keys=GITHUB_TOKEN,SLACK_BOT_TOKEN` | Revoke only those keys |
| `GET` | `/orgs/{org}/config/status` | Keys set, source (org/env), `updated_at`, `updated_by`, `age_days`, `stale` (viewer) |
| `GET` | `/orgs/{org}/config/audit` | Change history: who, when, keys added/changed/removed |

MCP: `configure_org_credentials` (with `merge: true` to behave like `PATCH`) and
`revoke_org_credentials`, both registered only where credential writes are allowed.

## Validation

Values are checked when saved, so a wrong paste fails at once with **422** instead of during an
incident. The response lists the keys and reasons, never the values:

```json
{"detail": {"errors": {"GITHUB_TOKEN": "is not a GitHub token (ghp_, ...)"}}}
```

Checks: no line breaks or control characters, at most 8 KB, secrets at least 8 characters with no
whitespace, `*_URL`/`*_ENDPOINT` must be http(s) URLs, `SLACK_WEBHOOK_URL` must be
`https://hooks.slack.com/…`, `ANTHROPIC_API_KEY` starts `sk-ant-`, `OPENAI_API_KEY` starts `sk-`,
`SLACK_BOT_TOKEN` starts `xoxb-`, `GITHUB_TOKEN` is a `ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`/`github_pat_` or
40-hex classic token, `AWS_ACCESS_KEY_ID` is `AKIA…`/`ASIA…`, `EMAIL_SMTP_PORT` is a port,
`AUTO_APPLY` is true/false and `LLM_PROVIDER` is a supported provider.

If a vendor changes its token format before this list is updated, set `CREDENTIAL_VALIDATION=warn`
(log only) or `off`.

## Audit trail

Every change writes an event under `{org}/credential_audit/<year>/<month>/` in storage:

```json
{"action": "credentials_updated", "org_id": "acme", "actor": "api:admin:3f9a1c2b7d10",
 "timestamp": "2026-11-25T10:02:11+00:00", "added": [], "changed": ["GITHUB_TOKEN"], "removed": []}
```

`actor` is the role plus the first 12 hex characters of the SHA-256 of the API token used (or `mcp`),
so you can tell which token made a change without the token appearing anywhere. Credential events are
not removed by `AUDIT_RETENTION_DAYS`.

## Rotation runbook

1. **Find what's due.** `GET /orgs/{org}/config/status` lists secrets older than
   `CREDENTIAL_MAX_AGE_DAYS` (default 90) under `stale`.
2. **Create the new credential at the provider** (GitHub, Slack, cloud IAM, …) while the old one still
   works.
3. **Swap it in** with `PATCH`, which leaves the other keys alone:

   ```bash
   curl -X PATCH https://agent.example.com/orgs/acme/config \
     -H "Authorization: Bearer $ACME_ADMIN_TOKEN" -H "Content-Type: application/json" \
     -d '{"credentials": {"GITHUB_TOKEN": "github_pat_..."}}'
   ```

   The next incident or tool call for the org uses the new value; nothing needs restarting.
4. **Check** with `GET /orgs/{org}/config/status` (`age_days` is 0) and a read-only call, for example
   `POST /webhook/manual` with a test incident.
5. **Revoke the old credential at the provider.**
6. **Confirm** the change appears in `GET /orgs/{org}/config/audit`.

## After a leak

1. Revoke at the provider first: that is what actually stops the key working.
2. `DELETE /orgs/{org}/config?keys=<leaked keys>` (or without `keys` to drop everything). The stored blob
   is overwritten before it is deleted. **Versioned buckets** (S3 versioning, GCS object versioning)
   still keep older versions of `{org}/config/credentials.json`: delete those versions too, or rely on
   encryption at rest and rotate `CREDENTIALS_MASTER_KEY`.
3. Store the replacement with `PATCH` and review `GET /orgs/{org}/config/audit` and `GET /audit` for
   anything done with the leaked key.
