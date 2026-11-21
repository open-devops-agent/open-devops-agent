# Getting started

Set up the agent locally, configure the integrations you need, and verify the API before sending an incident.

## Overview

The DevOps AI Agent is an autonomous system that:
- Monitors your infrastructure for issues
- Automatically diagnoses problems
- Suggests and applies fixes (with approval)
- Notifies your team

## Quick Start (Local Development)

### 1. Prerequisites

Ensure you have:
- Python 3.10 or higher
- `pip` and `venv`
- Git

```bash
# Check Python version
python --version  # Should be 3.10+

# Check pip
pip --version
```

### 2. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/open-devops-agent/open-devops-agent.git
cd open-devops-agent

# Create virtual environment
python -m venv venv

# Activate virtual environment
source venv/bin/activate  # On macOS/Linux
# OR
venv\Scripts\activate     # On Windows

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure API Keys

```bash
# Copy example environment file
cp .env.example .env

# Edit with your credentials
nano .env  # or use your favorite editor
```

**Minimum required configuration:**

```bash
# Required: an AI provider key. Claude by default:
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
# ...or another provider, for example Google Gemini (see AI_PROVIDERS.md):
# LLM_PROVIDER=gemini
# LLM_MODEL=<gemini model>
# GEMINI_API_KEY=AIza...

# Required: Slack notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
SLACK_APPROVAL_CHANNEL=devops-approvals

# Required: GitHub integration
GITHUB_TOKEN=ghp_your_github_token_here

# Organization & storage (recommended)
ORG_ID=acme-corp
STORAGE_PROVIDER=memory   # use minio/s3/gcs/azure in production

# Safety: Start with manual approval
AUTO_APPLY=false
```

**Where to get API keys:**

- **AI provider key** (one of): Anthropic https://console.anthropic.com/ · OpenAI https://platform.openai.com/api-keys · Google Gemini https://aistudio.google.com/apikey · Azure OpenAI (your Azure resource) · Ollama (none). See [AI providers](AI_PROVIDERS.md).
- **Slack Webhook**: https://api.slack.com/messaging/webhooks
- **GitHub Token**: https://github.com/settings/tokens (needs `repo` scope)

### 4. Start the Agent

```bash
# Start the API server
uvicorn api.server:app --reload --port 8000

# You should see:
# INFO:     Uvicorn running on http://127.0.0.1:8000
# INFO:     Application startup complete.
```

### 5. Test the Agent

Open a new terminal and test the health endpoint:

```bash
# Test health check
curl http://localhost:8000/health

# Expected response:
# {"status":"ok","auto_apply":"false","storage_provider":"memory","org_id":"acme-corp","queue_worker":true}
```

Upload an org runbook (loaded into agent context during incidents):

```bash
curl -H "Authorization: Bearer $API_TOKEN" -X POST http://localhost:8000/orgs/acme-corp/docs \
  -H "Content-Type: application/json" \
  -d '{
    "path": "runbooks/k8s-oom.md",
    "content": "# OOM Runbook\n1. Check pod logs\n2. Increase memory limits"
  }'
```

Test with a dummy incident (queued — processed async by background worker):

```bash
# Simulate a Kubernetes incident
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: acme-corp" \
  -d '{
    "type": "k8s",
    "namespace": "default",
    "pod": "test-pod",
    "description": "CrashLoopBackOff test"
  }'

# Response: {"status":"queued","incident_id":"INC-..."}
# Wait ~30s, then check audit log (see step 6)
```

**Or use Postman:** Import `postman/DevOps-AI-Agent.postman_collection.json` and run the **End-to-End Test Flow** folder. See [`docs/API_TESTING.md`](API_TESTING.md).

### 6. View Results

```bash
# View org-scoped audit log (poll after queuing — processing is async)
curl -H "Authorization: Bearer $API_TOKEN" "http://localhost:8000/audit?org_id=acme-corp" | python3 -m json.tool

# Or run the automated test script
./scripts/test_api_flow.sh
```

### 7. Escalation (auto-ticketing)

If the agent cannot resolve an incident within **10 minutes** (configurable), hits a **database issue**, or lacks evidence to act safely, it automatically:

- Sends a **Slack** escalation message
- Sends an **email** to the team
- Creates a **Jira** or **Zoho Desk** ticket (if configured)

```bash
# Configure in .env
ESCALATION_ENABLED=true
ESCALATION_TIMEOUT_MINUTES=10
ESCALATION_CHANNELS=slack,email,jira

# Test a DB incident (always escalates)
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: acme-corp" \
  -d '{
    "type": "cloud_aws",
    "resource_type": "rds",
    "resource_id": "prod-db-01",
    "description": "RDS connection timeout"
  }'
```

See [`docs/ESCALATION.md`](ESCALATION.md) for full setup.

### 8. Full E2E test: EC2 + Docker crash loop

For a real-world test (EC2 → Docker → broken container → agent fixes it), see:

**[`docs/E2E_EC2_DOCKER_TEST.md`](E2E_EC2_DOCKER_TEST.md)**

Quick summary:
1. Launch EC2 (t3.small, Ubuntu, ports 22 + 8000)
2. Run `scripts/ec2-docker-test-setup.sh` on EC2
3. Deploy agent on same EC2 with `AUTO_APPLY=true`
4. Trigger: `POST /webhook/manual` with `type: server`
5. Poll `GET /audit?org_id=acme-corp`

After the health check succeeds, continue with the platform-specific setup below.

---

## Next Steps

### Connect to Your Infrastructure

#### Kubernetes

If you have a Kubernetes cluster:

```bash
# Ensure kubectl is configured
kubectl get nodes

# The agent will use your local kubeconfig automatically
# Test with a real pod name:
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "k8s",
    "namespace": "default",
    "pod_name": "actual-pod-name"
  }'
```

#### GitHub Actions

Set up webhook in your repository:

1. Go to **Settings** → **Webhooks** → **Add webhook**
2. **Payload URL**: `http://your-public-url:8000/webhook/github`
3. **Content type**: `application/json`
4. **Events**: Select "Workflow runs"
5. **Active**: Check this box
6. Click **Add webhook**

For local testing, use [ngrok](https://ngrok.com/):

```bash
# In a new terminal
ngrok http 8000

# Use the ngrok URL (e.g., https://abc123.ngrok.io) as your webhook URL
```

#### Cloud Providers (AWS, GCP, Azure)

Add credentials to `.env`:

```bash
# AWS
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1

# GCP (requires service account JSON)
GCP_PROJECT_ID=your-project-id
# Also set: GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# Azure
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
```

Then install cloud SDKs:

```bash
# Install cloud providers (optional)
pip install boto3                    # AWS
pip install google-cloud-compute     # GCP
pip install azure-mgmt-compute       # Azure
```

---

## Production Deployment

Once you've tested locally, deploy to production:

### Option 1: Kubernetes (Recommended)

```bash
# See DEPLOYMENT.md for full instructions

# Quick deploy:
kubectl create namespace devops-agent
kubectl create secret generic agent-secrets \
  --from-literal=ANTHROPIC_API_KEY='your-key' \
  --from-literal=GITHUB_TOKEN='your-token' \
  -n devops-agent

kubectl apply -f k8s/ -n devops-agent
```

### Option 2: Docker

```bash
# See DEPLOYMENT.md for full instructions

docker-compose up -d
```

### Option 3: Cloud Platform

See [DEPLOYMENT.md](DEPLOYMENT.md) for:
- AWS ECS
- Google Cloud Run
- Azure Container Instances

---

## Understanding the Agent

### How It Works

```
1. Alert Received (webhook or manual trigger)
   ↓
2. Context Collection (logs, configs, metrics)
   ↓
3. AI Analysis (Claude identifies root cause)
   ↓
4. Action Planning (safe, dry-run first)
   ↓
5. Approval (if AUTO_APPLY=false)
   ↓
6. Execution (apply fix)
   ↓
7. Verification (confirm fix worked)
   ↓
8. Notification (Slack with summary)
```

### Safety Features

The agent is **safe by default**:

- **Dry-run first**: All destructive actions are simulated before execution
- **Approval gates**: With `AUTO_APPLY=false`, human approval required
- **Command whitelist**: Only safe commands allowed
- **Audit trail**: Every action logged with full reasoning
- **Step limits**: Prevents runaway loops

### Example Scenarios

#### Scenario 1: K8s Pod CrashLoopBackOff

```
Alert → Fetch pod logs → Identify missing ConfigMap → 
Create ConfigMap → Restart pod → Verify running → Notify
```

#### Scenario 2: CI/CD Pipeline Failure

```
Alert → Fetch build logs → Detect linting error → 
Create PR with fix → Retry build → Confirm success → Notify
```

#### Scenario 3: AWS EC2 High CPU

```
Alert → Fetch CloudWatch metrics → Identify memory leak → 
Restart service → Monitor recovery → Escalate if needed
```

---

## Configuration Options

### Environment Variables

`.env.example` is the complete list of every variable the agent reads, with its
default and what it controls — `tests/test_env_example_coverage.py` fails the
build if code starts reading a variable that is not listed there. The excerpt
below is only the handful you are most likely to change.

Key configuration options in `.env`:

```bash
# Safety
AUTO_APPLY=false           # Require approval for destructive actions
MAX_AGENT_STEPS=10         # Limit AI iterations to prevent loops

# Kubernetes
ALLOWED_NAMESPACES=default,staging  # Restrict which namespaces agent can modify
KUBECONFIG=/path/to/config          # Custom kubeconfig path

# CI/CD Platforms
GITLAB_TOKEN=glpat-xyz              # GitLab personal access token
JENKINS_URL=https://jenkins.company.com
JENKINS_USERNAME=agent
JENKINS_API_TOKEN=token

# Cloud Providers
# See .env.example for full list

# Logging
LOG_LEVEL=INFO             # DEBUG, INFO, WARNING, ERROR

# Notifications
PAGERDUTY_TOKEN=xyz        # Optional PagerDuty integration
```

### Advanced Configuration

See [MULTI_PLATFORM_GUIDE.md](MULTI_PLATFORM_GUIDE.md) for:
- Platform-specific configuration
- Webhook setup for each platform
- Custom collectors and tools
- Troubleshooting guides

---

## Common Issues

### Issue: Agent won't start

**Error:** `ModuleNotFoundError: No module named 'anthropic'`

**Solution:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue: API key invalid

**Error:** `Authentication failed: Invalid API key`

**Solution:**
- Double-check your API key in `.env`
- Ensure no extra spaces or quotes
- Verify key is active in Anthropic console

### Issue: Kubernetes permission denied

**Error:** `Forbidden: User cannot list pods in namespace`

**Solution:**
```bash
# Check your kubeconfig
kubectl auth can-i get pods --all-namespaces

# If using in-cluster, verify RBAC:
kubectl get clusterrolebinding | grep devops-agent
```

### Issue: No Slack notifications

**Solution:**
- Test webhook URL manually:
  ```bash
  curl -X POST YOUR_SLACK_WEBHOOK_URL \
    -H "Content-Type: application/json" \
    -d '{"text":"Test message"}'
  ```
- Verify webhook URL in `.env`
- Check Slack app permissions

---

## Testing

### Run Unit Tests

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v

# Run with coverage
pytest --cov=. tests/
```

### Simulate Incidents

```bash
# Use the simulation script
python scripts/simulate_incident.py --type k8s
python scripts/simulate_incident.py --type cicd --platform gitlab
python scripts/simulate_incident.py --type argocd
```

---

## Learning More

### Documentation

- [README.md](README.md) - Project overview and features
- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute
- [DEPLOYMENT.md](DEPLOYMENT.md) - Production deployment
- [MULTI_PLATFORM_GUIDE.md](MULTI_PLATFORM_GUIDE.md) - Platform configs

### Examples

Check `tests/` directory for examples of:
- Testing collectors
- Testing tools
- Mocking external services

### Community

- **Issues**: Report bugs or request features
- **Discussions**: Ask questions or share ideas
- **Pull Requests**: Contribute code or docs

---

## Gradual Rollout Plan

We recommend this rollout strategy:

### Week 1: Observation Mode
```bash
AUTO_APPLY=false
```
- Agent suggests actions but doesn't execute
- Review all suggestions in Slack
- Build confidence in agent decisions

### Week 2: Limited Auto-Apply
```bash
AUTO_APPLY=false
ALLOWED_NAMESPACES=staging
```
- Enable auto-apply for staging environments only
- Monitor closely
- Review audit logs daily

### Week 3: Production (Read-Only)
```bash
AUTO_APPLY=false
ALLOWED_NAMESPACES=staging,production
```
- Agent can read production but still requires approval
- Faster incident response with suggestions
- Team gets comfortable with agent in production

### Week 4+: Full Autonomous Mode (Optional)
```bash
AUTO_APPLY=true  # Only for simple, safe operations
ALLOWED_NAMESPACES=staging,production
```
- Agent can auto-fix simple issues (pod restarts, config updates)
- Still requires approval for destructive actions
- Review audit logs weekly

---

## Getting Help

If you're stuck:

1. Check the [Common Issues](#common-issues) section above
2. Review [TROUBLESHOOTING.md](DEPLOYMENT.md#troubleshooting)
3. Search [existing issues](https://github.com/open-devops-agent/open-devops-agent/issues)
4. Open a new issue with:
   - Your environment (OS, Python version, deployment method)
   - Steps to reproduce
   - Error messages and logs

---

## Next Steps

Now that your agent is running:

1. Review the [DEPLOYMENT.md](DEPLOYMENT.md) for production setup
2. Read [MULTI_PLATFORM_GUIDE.md](MULTI_PLATFORM_GUIDE.md) for platform-specific config
3. Check out [CONTRIBUTING.md](CONTRIBUTING.md) to add custom platforms
4. Join our community to share experiences

Use the audit log to review outcomes and record any configuration changes needed for your environment.
