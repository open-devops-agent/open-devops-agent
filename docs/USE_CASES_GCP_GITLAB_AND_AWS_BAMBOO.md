# Use Cases: GCP + GitLab, and AWS + Bitbucket + Bamboo

This guide shows how to run the DevOps AI Agent in two real environments: what it can **fix**, how to **configure** it, and how to **trigger** it day to day.

## Does the agent actually fix issues?

**Yes — for the remediations listed below.** It is not only a notifier.

| Stack | Auto / tool-driven fixes |
|-------|---------------------------|
| **GCP + GitLab** | GitLab: fetch logs → **retry pipeline** or open **MR with config fix**. GKE: diagnose → **restart/rollback/apply manifest** (dry-run first). GCE: **restart VM**, disk journal/log cleanup, nginx/certs, security patches. |
| **AWS + Bitbucket + Bamboo** | Bamboo: logs → **queue/retry**, **version check/bump**, Specs fix as **Bitbucket PR**. Bitbucket: **code review comments**. EKS: same K8s fixes as GKE. EC2: restart + server cleanup. S3: **diagnose only** (never delete). |

Fixes apply when tools succeed and either `AUTO_APPLY=true` or a human approves. With `AUTO_APPLY=false` (recommended at first), the agent still gathers evidence and posts Slack/`suggest_fix` / dry-run plans.

Keep `AUTO_APPLY=false` until you trust the agent. Prefer dry-run, Slack approval, and org runbooks.

---

## Shared principles (both use cases)

| Principle | Behavior |
|-----------|----------|
| Safety first | No delete/destroy of clusters, DBs, or production data |
| Evidence before fix | Agent must fetch logs/status via tools before claiming a root cause |
| Dry-run default | Manifests, cert renew, log cleanup, code review post start as dry-run |
| Escalate when stuck | Slack / Jira / PagerDuty when the agent cannot safely fix |
| BYOK | Each org can supply its own cloud and CI credentials |

**Typical flow**

```text
Alert / webhook / manual trigger
        ↓
  Incident queued (FastAPI)
        ↓
  Collect evidence (logs, kubectl, cloud APIs)
        ↓
  Propose or apply safe fix (if AUTO_APPLY / approved)
        ↓
  Verify + notify Slack
```

---

# Use case 1 — GCP + GitLab → GKE + VMs (+ optional AWS)

## Stack

| Layer | Your stack | Agent support |
|-------|------------|---------------|
| Source / CI | GitLab | Pipeline logs, retry, MRs with fixes, MR code review |
| Runtime | GKE | Pod CrashLoop/OOM/ImagePull, rollout restart/rollback, apply manifests (dry-run first) |
| Compute | GCE VMs | Diagnose, restart instance, disk/nginx/journal cleanup, security patches |
| Cloud APIs | GCP (+ AWS if used) | `get_gcp_resource`, restart/scale safe services; same for AWS |
| GitOps (optional) | ArgoCD / Helm | Sync/rollback (dry-run first) |

## What the agent can fix

### GitLab CI
- Failed pipeline: fetch job logs → root cause → retry transient failures
- Config/YAML bugs: open a **merge request** with the fix (`create_cicd_pr` / GitLab MR)
- MR review: webhook or manual `code_review` on GitLab MRs

### GKE
- CrashLoopBackOff / OOMKilled / ImagePullBackOff / failed rollouts
- `kubectl` restart, scale (not to zero without approval), rollback
- Apply corrected manifests with `dry_run=true` first
- Never `kubectl delete` namespaces/PVs

### GCE VMs
- High disk: inspect → vacuum journals + aged rotated `/var/log` only (protected paths alerted, not deleted)
- Nginx: `nginx -t` → apply config under `/etc/nginx/` → reload; refuse restart while `-t` fails
- TLS: `certbot renew` (DNS-01 if `CERTBOT_DNS_PLUGIN` set)
- Unattended security updates only (no reboot, no dist-upgrade)

### GCP cloud resources
- Read status/logs for GCE, GKE, Cloud Run, Cloud Functions, Cloud SQL (DB detail needs `ENABLE_DATABASE_COLLECTION=true`)
- Safe restart of VMs / Cloud Run; scale up (scale-down needs approval)

### If you also use AWS in this org
- Same agent can hold AWS credentials and handle EC2/EKS/ECS/S3 diagnostics and safe restarts in parallel

## What it will not do (escalate instead)
- Drop databases, delete GKE clusters, or wipe disks
- `terraform apply` / destroy (plan/validate only)
- Auto-reboot VMs after kernel patches
- Merge MRs without humans

## Configure (`.env`)

```bash
# Core
ANTHROPIC_API_KEY=sk-ant-...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
AUTO_APPLY=false
ORG_ID=gcp-gitlab-prod

# GitLab
GITLAB_TOKEN=glpat-...
GITLAB_URL=https://gitlab.com   # or https://gitlab.yourcompany.com

# GCP
GCP_PROJECT_ID=my-gcp-project
GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
# Prefer Workload Identity / attached SA on the agent host in production

# GKE (agent host needs cluster access)
KUBECONFIG=/path/to/gke-kubeconfig
ALLOWED_NAMESPACES=default,staging,production

# Optional: VMs via SSH from central agent
SSH_REMOTE_USER=ubuntu
SSH_STRICT_HOST_KEY_CHECKING=true

# Optional AWS (same org, second cloud)
AWS_REGION=us-east-1
# AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or instance role

# Code review posting (leave false until trusted)
CODE_REVIEW_AUTO_POST=false
```

**GCP service account roles (minimum useful set)**  
`roles/container.developer` (or tighter custom), `roles/compute.instanceAdmin.v1` (or restart-only custom), `roles/logging.viewer`, `roles/monitoring.viewer`. Avoid Owner.

## Wire webhooks

### GitLab pipeline failures + MR review
Project → Settings → Webhooks → URL:

`https://YOUR-AGENT/webhook/gitlab`

- Events: **Pipeline events**, **Merge request events** (for code review)
- Secret token: same value as agent `WEBHOOK_SECRET` (GitLab sends `X-Gitlab-Token`)

### Alertmanager → GKE / VM alerts
Route firing alerts to:

`https://YOUR-AGENT/webhook/alertmanager`

Useful alert labels: `namespace`, `pod`, `node`, `severity`, and for cloud `cloud_provider=gcp`.

### Manual tests

**GitLab pipeline failure**

```bash
curl -X POST https://YOUR-AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: gcp-gitlab-prod" \
  -d '{
    "type": "cicd",
    "source": "gitlab_ci",
    "project_id": "12345",
    "pipeline_id": 987654,
    "labels": {"cicd_platform": "gitlab"}
  }'
```

**GKE pod crash**

```bash
curl -X POST https://YOUR-AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: gcp-gitlab-prod" \
  -d '{
    "type": "k8s",
    "namespace": "production",
    "pod": "api-7d9f8c-abc12",
    "description": "CrashLoopBackOff"
  }'
```

**GCE VM / disk / nginx**

```bash
curl -X POST https://YOUR-AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: gcp-gitlab-prod" \
  -d '{
    "type": "server",
    "host": "10.0.1.20",
    "description": "Disk almost full / nginx failing"
  }'
```

**GCP resource**

```bash
curl -X POST https://YOUR-AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cloud_gcp",
    "resource_type": "gce",
    "resource_id": "web-1",
    "params": {"zone": "us-central1-a"}
  }'
```

**GitLab MR code review**

```bash
curl -X POST https://YOUR-AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "code_review",
    "scm_platform": "gitlab",
    "repo": "mygroup/myapp",
    "change_id": "42"
  }'
```

## Day-2 operations checklist (GCP + GitLab)

1. Deploy agent (Docker/K8s) with GitLab + GCP credentials  
2. Point GitLab webhooks + Alertmanager at the agent  
3. Upload runbooks: `POST /orgs/gcp-gitlab-prod/docs` (GKE OOM, disk full, GitLab runner)  
4. Fire a staging CrashLoop → confirm Slack diagnosis  
5. Only then set `AUTO_APPLY=true` for non-prod namespaces  
6. Keep production on approval (`REQUIRE_APPROVAL_FOR=rollback,scale_down,delete,exec`)

---

# Use case 2 — AWS + Bitbucket + Bamboo → EC2 + EKS + S3

## Stack

| Layer | Your stack | Agent support |
|-------|------------|---------------|
| Source | Bitbucket | PR code review (`/webhook/bitbucket`), comment on PRs |
| CI / CD | Bamboo | Build logs, queue/retry, version check + patch bump, Specs PR via SCM |
| Compute | EC2 | Disk/nginx/certs/security updates, restart instance |
| Kubernetes | EKS | Same K8s tools as GKE (CrashLoop, rollback, apply dry-run) |
| Storage / others | S3 (+ optional ECS/Lambda) | Describe/list diagnostics; no bucket wipe |

## What the agent can fix

### Bitbucket
- Review open PRs: secrets, risky shell/SQL, missing tests → post review comments  
- Wire Bitbucket webhook → `POST /webhook/bitbucket`  
- Does **not** merge PRs

### Bamboo
- Failed plan: collect logs → `retry_cicd_pipeline` (queue new build)  
- Release numbering: `bamboo_check_version` then `bamboo_increment_version` / `patch_bamboo_plan` (plan variable + queue)  
- Specs changes: `create_cicd_pr` with `platform=bamboo` opens a **Bitbucket PR** when  
  `BAMBOO_SCM_PROVIDER=bitbucket` and `BAMBOO_SPECS_REPO=workspace/repo_slug`  
  (also supports github / gitlab / azure_devops as SCM)

### EC2
- Disk full (safe log/journal cleanup only)  
- Nginx/TLS/certbot  
- Unattended security updates (no reboot)  
- Cloud: restart EC2 via AWS API when appropriate  

### EKS
- Same as GKE: diagnose pods, restart/rollback/scale, apply fixed YAML dry-run first  
- Agent needs `KUBECONFIG` (or in-cluster) for the EKS cluster  

### S3 / AWS platform
- Inspect buckets/objects metadata, CloudWatch-related context via collectors  
- Restart/scale ECS/EC2 where safe  
- **Never** delete buckets, force-delete objects, or terminate fleets  

## What it will not do (escalate instead)
- Empty or delete S3 buckets  
- Terminate EC2 fleets or delete EKS clusters  
- Auto-failover RDS / restore from snapshot (snapshot **create/list** only when DB collection enabled; restore always blocked)  
- Merge Bitbucket PRs or Bamboo Specs without review  

## Configure (`.env`)

```bash
# Core
ANTHROPIC_API_KEY=sk-ant-...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
AUTO_APPLY=false
ORG_ID=aws-bamboo-prod

# Bitbucket Cloud
BITBUCKET_USERNAME=your-bot
BITBUCKET_APP_PASSWORD=...          # or BITBUCKET_TOKEN=
BITBUCKET_API_URL=https://api.bitbucket.org/2.0
CODE_REVIEW_AUTO_POST=false         # set true only after dry-runs look good

# Bamboo
BAMBOO_URL=https://bamboo.yourcompany.com
BAMBOO_USERNAME=svc-devops-agent
BAMBOO_PASSWORD=...
BAMBOO_VERSION_VARIABLE=version
# Specs live in Bitbucket — agent opens fix PRs here
BAMBOO_SCM_PROVIDER=bitbucket
BAMBOO_SPECS_REPO=myworkspace/bamboo-specs

# AWS
AWS_REGION=eu-west-1
# Prefer IAM role on the agent EC2/ECS task:
# AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY only if no role

# EKS
KUBECONFIG=/home/agent/.kube/eks-prod.yaml
ALLOWED_NAMESPACES=default,staging,production

# EC2 SSH (central agent → app instances)
SSH_REMOTE_USER=ec2-user
SSH_STRICT_HOST_KEY_CHECKING=true
```

**IAM ideas (tighten for your account)**  
`AmazonEC2ReadOnlyAccess` + custom restart, `AmazonEKSClusterPolicy` / kubectl via IRSA, `AmazonS3ReadOnlyAccess`, CloudWatch read. No `s3:Delete*`, no unrestricted `ec2:TerminateInstances`.

## Wire webhooks

### Bitbucket PR review
Repository → Settings → Webhooks →  
URL: `https://YOUR-AGENT/webhook/bitbucket`  
Triggers: Pull request created / updated.

### Bamboo build failures
Add a final script task or notification that calls the agent:

```bash
curl -X POST https://YOUR-AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: aws-bamboo-prod" \
  -d "{
    \"type\": \"cicd\",
    \"source\": \"bamboo\",
    \"plan_key\": \"APP-PLAN\",
    \"build_number\": ${bamboo.buildNumber},
    \"labels\": {\"cicd_platform\": \"bamboo\"}
  }"
```

### Alertmanager / CloudWatch → agent
Forward EKS/EC2/S3 alarms to `POST /webhook/alertmanager` with labels such as `cloud_provider=aws`, `namespace`, `pod`, or `host`.

### Manual tests

**Bamboo failure**

```bash
curl -X POST https://YOUR-AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cicd",
    "source": "bamboo",
    "plan_key": "APP-PLAN",
    "build_number": 120,
    "labels": {"cicd_platform": "bamboo"}
  }'
```

**Bamboo version check / patch bump** (agent tools: `bamboo_check_version`, `bamboo_increment_version`)

```bash
curl -X POST https://YOUR-AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cicd",
    "source": "bamboo",
    "plan_key": "APP-PLAN",
    "labels": {"cicd_platform": "bamboo", "action": "increment_version"}
  }'
```

**Bitbucket PR review**

```bash
curl -X POST https://YOUR-AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "code_review",
    "scm_platform": "bitbucket",
    "repo": "myworkspace/myapp",
    "change_id": "15"
  }'
```

**EKS pod**

```bash
curl -X POST https://YOUR-AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "k8s",
    "namespace": "production",
    "pod": "payments-abc",
    "description": "OOMKilled"
  }'
```

**EC2 / disk**

```bash
curl -X POST https://YOUR-AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "server",
    "host": "i-0abc123",
    "description": "DiskFull on /var"
  }'
```

**AWS resource (EC2 / S3 / EKS)**

```bash
curl -X POST https://YOUR-AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cloud_aws",
    "resource_type": "ec2",
    "resource_id": "i-0abc123"
  }'
```

```bash
curl -X POST https://YOUR-AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cloud_aws",
    "resource_type": "s3",
    "resource_id": "my-app-artifacts"
  }'
```

## Day-2 operations checklist (AWS + Bitbucket + Bamboo)

1. Deploy agent on EC2/ECS with IAM role + EKS kubeconfig  
2. Add Bitbucket webhook for PRs; Bamboo failure notification → manual webhook  
3. Upload runbooks (EKS OOM, Bamboo version variable, EC2 disk)  
4. Dry-run code review on a staging PR; dry-run Bamboo retry on a non-prod plan  
5. Enable `CODE_REVIEW_AUTO_POST` only after comments look correct  
6. Keep `AUTO_APPLY=false` in production until approval gates are proven  

---

## Side-by-side: which tools matter

| Concern | Use case 1 (GCP + GitLab) | Use case 2 (AWS + Bitbucket + Bamboo) |
|---------|---------------------------|----------------------------------------|
| CI logs / retry | GitLab collector + `retry_cicd_pipeline` | Bamboo collector + queue/retry |
| Config fix PR/MR | GitLab MR | Bamboo Specs → **Bitbucket PR** (`BAMBOO_SCM_PROVIDER=bitbucket`) |
| Code review | `/webhook/gitlab` | `/webhook/bitbucket` |
| Kubernetes | GKE + `KUBECONFIG` | EKS + `KUBECONFIG` |
| VMs | GCE restart + SSH server tools | EC2 restart + SSH server tools |
| Object storage | GCS via GCP collector (as configured) | S3 describe (no delete) |
| Version bump | N/A (unless you add it) | `bamboo_check_version` / `bamboo_increment_version` |

---

## Running the agent (both)

```bash
cp .env.example .env
# fill credentials for the use case
pip install -r requirements.txt
devops-agent serve
# or: uvicorn api.server:app --host 0.0.0.0 --port 8000
```

Health: `GET /health`  
Audit: org-scoped audit/logs in configured storage (S3/MinIO/GCS/Azure/memory).

---

## Recommended rollout

| Phase | Action |
|-------|--------|
| 1 | Agent in Slack-only mode (`AUTO_APPLY=false`) |
| 2 | Staging: GitLab/Bamboo failures + one K8s namespace |
| 3 | Code review dry-run on Bitbucket/GitLab |
| 4 | Enable auto-apply for staging only |
| 5 | Production with approval gates + emergency stop `AGENT_EMERGENCY_STOP` |

---

## Related docs

- [MULTI_PLATFORM_GUIDE.md](./MULTI_PLATFORM_GUIDE.md) — platforms, Bamboo version API, code review  
- [PLATFORM_SUPPORT.md](./PLATFORM_SUPPORT.md) — collectors and capabilities  
- [COVERAGE_GAPS.md](./COVERAGE_GAPS.md) — what to escalate or extend  
- [SECURITY_GUARANTEES.md](../SECURITY_GUARANTEES.md) — safety model  
- [CENTRALIZED_DEPLOYMENT.md](./CENTRALIZED_DEPLOYMENT.md) — one agent, many remote targets  
