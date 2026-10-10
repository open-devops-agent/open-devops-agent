# Multi-Platform Support Guide

This guide explains how to configure and use the DevOps AI Agent with multiple CI/CD platforms, cloud providers, and ArgoCD.

## Table of Contents

1. [CI/CD Platforms](#cicd-platforms)
2. [Cloud Providers](#cloud-providers)
3. [ArgoCD Integration](#argocd-integration)
4. [Configuration](#configuration)
5. [Webhook Setup](#webhook-setup)
6. [Example Scenarios](#example-scenarios)

---

## Code review (any git host)

The agent can review pull/merge requests on **GitHub, GitLab, Bitbucket Cloud, Azure DevOps**, or a **local git clone** (`platform=git`).

| Tool | Purpose |
|------|---------|
| `fetch_code_change` | Load PR/MR metadata, file list, unified diff, heuristic secret/risk findings |
| `post_code_review` | Post summary (+ optional inline comments). Never merges. Default `COMMENT` |
| `list_open_code_changes` | List open PRs/MRs |

**Webhooks:** `POST /webhook/github` (`pull_request`), `POST /webhook/gitlab` (merge request), `POST /webhook/bitbucket` (pullrequest). Or manual:

```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "code_review",
    "scm_platform": "github",
    "repo": "acme/app",
    "change_id": "42"
  }'
```

Local / any repo without a PR API:

```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "code_review",
    "scm_platform": "git",
    "workspace_path": "/path/to/clone",
    "base_ref": "origin/main",
    "head_ref": "HEAD"
  }'
```

Posting is dry-run unless `CODE_REVIEW_AUTO_POST=true` (or `AUTO_APPLY=true`) and `dry_run=false`. Approvals require `CODE_REVIEW_ALLOW_APPROVE=true`.

---

## CI/CD Platforms

The agent now supports **5 CI/CD platforms**:

### Supported Platforms

| Platform | Webhook Support | Log Collection | PR/MR Creation | Pipeline Retry | Version bump |
|----------|----------------|----------------|----------------|----------------|--------------|
| **GitHub Actions** | ✅ | ✅ | ✅ | ✅ Rerun failed jobs | ❌ |
| **GitLab CI** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Jenkins** | Manual | ✅ | ✅ SCM PR (Jenkinsfile repo) | ✅ | ❌ |
| **Bamboo** | Manual | ✅ | ✅ SCM PR (bamboo-specs repo) | ✅ | ✅ Plan variable + latest result |
| **Azure DevOps** | ✅ | ✅ | ✅ Git push + PR | ✅ | ❌ |

### Configuration

Add these to your `.env` file:

```bash
# GitLab
GITLAB_TOKEN=glpat-xxxxxxxxxxxxx
GITLAB_URL=https://gitlab.com  # or your self-hosted URL

# Jenkins
JENKINS_URL=https://jenkins.yourcompany.com
JENKINS_USERNAME=admin
JENKINS_API_TOKEN=1234567890abcdef
JENKINS_SCM_PROVIDER=github
JENKINS_SCM_REPO=your-org/app

# Bamboo
BAMBOO_URL=https://bamboo.yourcompany.com
BAMBOO_USERNAME=admin
BAMBOO_PASSWORD=your-password
BAMBOO_VERSION_VARIABLE=version  # plan variable to bump (patch +1)
BAMBOO_SCM_PROVIDER=github
BAMBOO_SPECS_REPO=your-org/bamboo-specs

# Azure DevOps
AZURE_DEVOPS_ORG=your-org
AZURE_DEVOPS_PAT=xxxxxxxxxxxxx
AZURE_DEVOPS_PROJECT=your-project

# Wildcard TLS / DNS-01
CERTBOT_DNS_PLUGIN=cloudflare
CERTBOT_DNS_CREDENTIALS=/etc/letsencrypt/cloudflare.ini
CERTBOT_WILDCARD_DOMAINS=*.example.com,example.com
```

### Manual Trigger Examples

#### GitHub Actions Failure
```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cicd",
    "source": "github_actions",
    "repo": "myorg/myrepo",
    "run_id": 1234567890,
    "workflow_name": "Deploy",
    "branch": "main"
  }'
```

#### GitLab CI Failure
```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cicd",
    "source": "gitlab_ci",
    "project_id": "12345",
    "pipeline_id": 987654,
    "labels": {"cicd_platform": "gitlab"}
  }'
```

#### Jenkins Build Failure
```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cicd",
    "source": "jenkins",
    "job_name": "my-app-build",
    "build_number": 42,
    "labels": {"cicd_platform": "jenkins"}
  }'
```

#### Bamboo Build Failure
```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cicd",
    "source": "bamboo",
    "plan_key": "PROJ-PLAN",
    "build_number": 123,
    "labels": {"cicd_platform": "bamboo"}
  }'
```

### Bamboo version check and patch increment

Bamboo has no dedicated “version” REST type. The agent **checks** both the plan variable and the latest build result, then can bump the variable.

This matches [PlanResource](https://docs.atlassian.com/atlassian-bamboo/11.0.8/com/atlassian/bamboo/plugins/rest/build/PlanResource.html), ResultResource, and [QueueResource](https://docs.atlassian.com/bamboo/REST/5.0-SNAPSHOT/#d2e927):

| Step | Atlassian method | HTTP |
|------|------------------|------|
| Version check | `getPlanVariable` + latest result | `GET /rest/api/latest/plan/{PROJECT}-{PLAN}/variables/{name}` and `GET /rest/api/latest/result/{PROJECT}-{PLAN}-latest` |
| Persist bump | `editPlanVariable` (`RestVariable` `{name, value}`) | `PUT /rest/api/latest/plan/{PROJECT}-{PLAN}/variables/{name}` |
| Queue with override | `QueueResource` | `POST /rest/api/latest/queue/{PROJECT}-{PLAN}?bamboo.variable.{name}=1.4.1` |
| Specs PR | SCM (GitHub/GitLab/Azure) | `create_cicd_pr` platform=`bamboo` against `BAMBOO_SPECS_REPO` |

Agent tools:

- `bamboo_check_version` — plan variable + latest ResultResource build number
- `bamboo_increment_version` — read, patch-bump, PUT, optionally queue
- `patch_bamboo_plan` — same, then always queue (`increment_version=false` queues only)
- `create_cicd_pr` platform=`bamboo` — PR on the Specs Git repo

Atlassian documents the queue override as `bamboo.variable.myVariable=value` ([resetting variables via REST](https://support.atlassian.com/bamboo/kb/resetting-variables-via-a-rest-api-call-and-dynamic-release-versioning/)). That query param applies to **that build only**; the PUT is what updates the stored plan variable for later builds.

```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cicd",
    "source": "bamboo",
    "plan_key": "PROJ-PLAN",
    "labels": {"cicd_platform": "bamboo", "action": "increment_version"}
  }'
```

#### Azure DevOps Pipeline Failure
```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cicd",
    "source": "azure_devops",
    "project": "MyProject",
    "pipeline_id": 42,
    "run_id": 1234,
    "labels": {"cicd_platform": "azure_devops"}
  }'
```

---

## Cloud Providers

The agent supports **3 cloud providers** with safe monitoring and remediation operations.

### Supported Cloud Services

#### AWS
- **EC2 Instances** - Reboot, diagnostics, console logs
- **ECS Services** - Restart, scale, task diagnostics
- **Lambda Functions** - Error logs, configuration check
- **RDS Instances** - Status, events, connectivity
- **CloudWatch Logs** - Recent error logs

#### GCP
- **GCE Instances** - Reset, serial port logs
- **GKE Clusters** - Cluster info (delegates to K8s for pods)
- **Cloud Run** - Service restart, logs
- **Cloud Functions** - Error logs, status
- **Cloud SQL** - Instance status, configuration

#### Azure
- **Virtual Machines** - Restart, diagnostics, activity logs
- **AKS Clusters** - Cluster info (delegates to K8s for pods)
- **App Services** - Restart, scale, logs
- **Azure Functions** - Restart, function list
- **Azure SQL** - Server/database status

### Configuration

#### AWS Setup
```bash
# Option 1: Environment variables
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXX
export AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxx
export AWS_REGION=us-east-1

# Option 2: Use IAM roles (recommended for production)
# No credentials needed if running on EC2/ECS/Lambda with IAM role
```

Install AWS dependencies:
```bash
pip install boto3 botocore
```

#### GCP Setup
```bash
# Option 1: Service account file
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
export GCP_PROJECT_ID=my-project-id

# Option 2: Use attached service account (recommended for GCE/GKE)
# No credentials file needed
```

Install GCP dependencies:
```bash
pip install google-cloud-compute google-cloud-container \
            google-cloud-run google-cloud-functions \
            google-cloud-logging google-cloud-sql
```

#### Azure Setup
```bash
# Option 1: Service principal
export AZURE_SUBSCRIPTION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxx

# Option 2: Use managed identity (recommended for Azure VMs/AKS)
# No credentials needed
```

Install Azure dependencies:
```bash
pip install azure-identity azure-mgmt-compute \
            azure-mgmt-containerservice azure-mgmt-web \
            azure-mgmt-sql azure-mgmt-monitor
```

### Manual Trigger Examples

#### AWS EC2 Issue
```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cloud_aws",
    "resource_type": "ec2",
    "resource_id": "i-0123456789abcdef0",
    "description": "EC2 instance not responding"
  }'
```

#### GCP Cloud Run Issue
```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cloud_gcp",
    "resource_type": "cloud_run",
    "resource_id": "my-service",
    "params": {"region": "us-central1"}
  }'
```

#### Azure App Service Issue
```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cloud_azure",
    "resource_type": "app_service",
    "resource_id": "my-app",
    "params": {"resource_group": "my-rg"}
  }'
```

---

## ArgoCD Integration

The agent can monitor and remediate ArgoCD applications with safe GitOps operations.

### Features

- **Application Status** - Health, sync status, resource inventory
- **Sync Operations** - Trigger syncs with dry-run first
- **Rollback** - Rollback to previous revisions
- **Deployment History** - View past deployments

### Configuration

```bash
# ArgoCD Server
ARGOCD_SERVER_URL=https://argocd.yourcompany.com
ARGOCD_AUTH_TOKEN=xxxxxxxxxxxxx
```

Get an ArgoCD token:
```bash
# Login to ArgoCD
argocd login argocd.yourcompany.com

# Generate token (never expires)
argocd account generate-token

# Or create a service account with specific permissions
argocd proj role create-token myproject ci-role
```

### Manual Trigger Examples

#### OutOfSync Application
```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "argocd",
    "app_name": "my-app",
    "description": "Application OutOfSync"
  }'
```

#### Degraded Health
```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "argocd",
    "app_name": "my-app",
    "description": "Application health degraded"
  }'
```

---

## Webhook Setup

### GitLab Webhooks

1. Go to your GitLab project → **Settings** → **Webhooks**
2. Add webhook URL: `https://your-agent.com/webhook/gitlab` (you'll need to add this endpoint)
3. Select trigger: **Pipeline events**
4. Add secret token (optional but recommended)

### Azure DevOps Webhooks

1. Go to your project → **Project Settings** → **Service Hooks**
2. Add a new **Web Hooks** subscription
3. Select trigger: **Build completed**
4. Set URL: `https://your-agent.com/webhook/azure_devops`
5. Configure filters for failed builds

---

## Example Scenarios

### Scenario 1: GitLab CI Pipeline Fails

**What happens:**
1. GitLab sends webhook to agent
2. Agent fetches pipeline logs via GitLab API
3. Claude analyzes the failure (e.g., missing dependency)
4. Agent creates a merge request with the fix
5. Slack notification sent with MR link

**Agent Actions:**
- ✅ Fetch logs from GitLab CI
- ✅ Diagnose root cause
- ✅ Create MR with fix
- ✅ Notify team on Slack

### Scenario 2: AWS ECS Task Keeps Crashing

**What happens:**
1. CloudWatch alert triggers webhook
2. Agent fetches ECS task details and logs
3. Claude identifies OOMKilled issue
4. Agent suggests scaling ECS service or increasing memory
5. If `AUTO_APPLY=true`, scales service automatically
6. Notifies team with before/after metrics

**Agent Actions:**
- ✅ Fetch ECS task status and logs
- ✅ Analyze CloudWatch logs
- ✅ Scale ECS service (if auto-approved)
- ⚠️ Request approval if `AUTO_APPLY=false`

### Scenario 3: ArgoCD App OutOfSync

**What happens:**
1. Prometheus/Alertmanager sends ArgoCD alert
2. Agent fetches app status from ArgoCD API
3. Claude identifies config drift
4. Agent performs dry-run sync first
5. If safe, triggers actual sync (with approval if needed)
6. Monitors health post-sync

**Agent Actions:**
- ✅ Get ArgoCD app status
- ✅ Check unhealthy resources
- ✅ Sync with dry-run first
- ✅ Sync for real (with approval gate)
- ✅ Verify health after sync

### Scenario 4: Azure App Service Down

**What happens:**
1. Azure Monitor alert received
2. Agent fetches App Service diagnostics
3. Claude checks activity logs and status
4. Agent restarts the App Service
5. Monitors for successful restart
6. Escalates if restart doesn't help

**Agent Actions:**
- ✅ Fetch App Service status
- ✅ Check activity logs
- ✅ Restart service
- ✅ Verify service is running
- ⚠️ Escalate if issue persists

---

## Safety Features

### Built-in Safety Gates

1. **Dry-Run First** - All apply operations default to dry-run
2. **Approval Required** - `AUTO_APPLY=false` by default
3. **Read-Only by Default** - Most cloud operations are diagnostic
4. **No Destructive Commands** - Delete, terminate blocked by executor
5. **Audit Trail** - All actions logged to `/audit` endpoint

### Safe Operations

✅ **Always Allowed:**
- Fetch logs and diagnostics
- Describe resources
- Check status
- Dry-run syncs/applies

⚠️ **Require Approval (AUTO_APPLY=false):**
- Restart services
- Scale services
- Apply K8s manifests
- Sync ArgoCD apps
- Rollback deployments

🚫 **Always Blocked:**
- Delete resources
- Drop databases
- Terminate instances
- Force operations without approval

---

## Troubleshooting

### Issue: "Platform not configured"

**Solution:** Check that the required environment variables are set:
```bash
# For GitLab
echo $GITLAB_TOKEN

# For AWS
echo $AWS_REGION

# For ArgoCD
echo $ARGOCD_SERVER_URL
```

### Issue: Cloud SDK not installed

**Solution:** Install the required cloud provider SDK:
```bash
# For AWS issues
pip install boto3

# For GCP issues
pip install google-cloud-compute

# For Azure issues
pip install azure-identity azure-mgmt-compute
```

### Issue: "Authentication failed"

**Solution:** Verify credentials:
```bash
# Test GitLab token
curl -H "PRIVATE-TOKEN: $GITLAB_TOKEN" https://gitlab.com/api/v4/user

# Test ArgoCD token
curl -H "Authorization: Bearer $ARGOCD_AUTH_TOKEN" \
  https://argocd.yourcompany.com/api/v1/applications

# Test AWS credentials
aws sts get-caller-identity
```

---

## Next Steps

1. **Configure platforms** - Add credentials to `.env`
2. **Install dependencies** - Run `pip install -r requirements.txt` plus cloud SDKs
3. **Test manually** - Use `/webhook/manual` endpoint with examples above
4. **Set up webhooks** - Configure webhooks in GitLab, Azure DevOps, etc.
5. **Monitor** - Check `/audit` endpoint for incident history
6. **Graduate to AUTO_APPLY** - After testing, set `AUTO_APPLY=true` for autonomous mode

---

## Support Matrix

| Feature | GitHub | GitLab | Jenkins | Bamboo | Azure DevOps | ArgoCD | AWS | GCP | Azure |
|---------|--------|--------|---------|--------|--------------|--------|-----|-----|-------|
| Log Collection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Retry Pipeline | ✅ | ✅ | ✅ | ✅ | ✅ | N/A | N/A | N/A | N/A |
| Version increment | ❌ | ❌ | ❌ | ✅ | ❌ | N/A | N/A | N/A | N/A |
| Create PR/MR | ✅ | ✅ | ✅ SCM | ✅ SCM | ✅ | N/A | N/A | N/A | N/A |
| Restart Service | N/A | N/A | N/A | N/A | N/A | ✅ | ✅ | ✅ | ✅ |
| Scale Service | N/A | N/A | N/A | N/A | N/A | N/A | ✅ | ✅ | ✅ |
| Rollback | N/A | N/A | N/A | N/A | N/A | ✅ | N/A | N/A | N/A |

✅ Fully Supported | ⚠️ Limited Support | ❌ Not Supported | N/A Not Applicable
