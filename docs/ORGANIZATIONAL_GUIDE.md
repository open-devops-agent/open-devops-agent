# Organizational Deployment Guide

## Using the DevOps AI Agent in Your Organization

This guide explains how to effectively deploy and use the DevOps AI Agent across your organization for DevOps, SRE, and DevSecOps practices.

## Table of Contents

1. [Platform Support](#platform-support)
2. [Deployment Models](#deployment-models)
3. [Team Integration](#team-integration)
4. [Workflow Integration](#workflow-integration)
5. [Verification and Testing](#verification-and-testing)
6. [Documentation and Knowledge Management](#documentation-and-knowledge-management)
7. [Security and Compliance](#security-and-compliance)
8. [Best Practices](#best-practices)

---

## Platform Support

### Cloud Providers

The agent supports all major cloud providers:

**Amazon Web Services (AWS)**
- EC2 instances
- ECS containers
- Lambda functions
- RDS databases
- CloudWatch logs
- Collector: `collectors/aws.py`

**Google Cloud Platform (GCP)**
- Compute Engine VMs
- Cloud Run services
- Cloud Functions
- Cloud SQL
- Cloud Logging
- Collector: `collectors/gcp.py`

**Microsoft Azure**
- Virtual Machines
- Azure Container Instances
- Azure Functions
- Azure SQL Database
- Azure Monitor
- Collector: `collectors/azure.py`

### Operating Systems

**Linux (All Distributions)**
- Ubuntu
- Debian
- CentOS
- Amazon Linux
- Collector: `collectors/server.py`

**Red Hat Enterprise Linux (RHEL)**
- RHEL 7, 8, 9
- CentOS
- Rocky Linux
- AlmaLinux
- Special handling for: SELinux, firewalld, yum/dnf
- Collector: `collectors/server.py`

**Windows Server**
- Windows Server 2016, 2019, 2022
- PowerShell-based diagnostics
- Event Log monitoring
- Service management
- Collector: `collectors/server.py`

### CI/CD Platforms

- GitHub Actions
- GitLab CI/CD
- Jenkins
- Bamboo
- Azure DevOps
- ArgoCD (GitOps)

### Container Orchestration

- Kubernetes (all distributions)
- Docker
- OpenShift
- EKS (AWS)
- GKE (Google Cloud)
- AKS (Azure)

---

## Deployment Models

### 1. Centralized Deployment

Deploy a single agent instance that handles all incidents.

**Architecture:**
```
┌──────────────────────────────────────┐
│     Monitoring Systems               │
│  (Prometheus, Datadog, etc.)         │
└────────────┬─────────────────────────┘
             │ Alerts
             ▼
┌──────────────────────────────────────┐
│    DevOps AI Agent (Central)         │
│  - FastAPI server                    │
│  - Webhook endpoints                 │
│  - Claude integration                │
└────────────┬─────────────────────────┘
             │ Actions
             ▼
┌──────────────────────────────────────┐
│  Infrastructure                      │
│  - K8s clusters                      │
│  - Cloud resources                   │
│  - CI/CD pipelines                   │
└──────────────────────────────────────┘
```

**Best For:**
- Small to medium organizations
- Centralized DevOps teams
- Unified incident management

**Setup:**
```bash
# Deploy on Kubernetes
kubectl apply -f k8s/deployment.yaml

# Or use Docker
docker run -d \
  -p 8000:8000 \
  -e ANTHROPIC_API_KEY=your-key \
  -e EMAIL_ENABLED=true \
  devops-ai-agent:latest
```

### 2. Multi-Region Deployment

Deploy agent instances in each region for low latency.

**Architecture:**
```
Region US-East          Region EU-West          Region APAC
┌─────────────┐        ┌─────────────┐        ┌─────────────┐
│ AI Agent    │        │ AI Agent    │        │ AI Agent    │
│ Instance    │        │ Instance    │        │ Instance    │
└─────────────┘        └─────────────┘        └─────────────┘
      │                      │                      │
      └──────────────────────┴──────────────────────┘
                             │
                    ┌────────▼────────┐
                    │ Central Logging │
                    │ & Documentation │
                    └─────────────────┘
```

**Best For:**
- Global organizations
- Multi-region infrastructure
- Low-latency requirements

**Setup:**
```bash
# Deploy in each region
# Region 1
kubectl apply -f k8s/deployment.yaml -n us-east-1

# Region 2
kubectl apply -f k8s/deployment.yaml -n eu-west-1

# Configure regional routing
kubectl apply -f k8s/regional-ingress.yaml
```

### 3. Team-Based Deployment

Deploy separate agent instances per team or service.

**Architecture:**
```
Team A (Platform)       Team B (Backend)       Team C (Frontend)
┌─────────────┐        ┌─────────────┐        ┌─────────────┐
│ AI Agent    │        │ AI Agent    │        │ AI Agent    │
│ (Platform)  │        │ (Backend)   │        │ (Frontend)  │
└─────────────┘        └─────────────┘        └─────────────┘
      │                      │                      │
      └──────────────────────┴──────────────────────┘
                             │
                    ┌────────▼────────┐
                    │ Shared Services │
                    │ - Docs          │
                    │ - Audit logs    │
                    └─────────────────┘
```

**Best For:**
- Large organizations
- Team autonomy
- Service-specific requirements

**Configuration:**
```yaml
# Team A config
team: platform
namespaces:
  - infra
  - monitoring
alert_routing:
  - prometheus-infra

# Team B config
team: backend
namespaces:
  - api
  - services
alert_routing:
  - prometheus-backend
```

---

## Team Integration

### 1. DevOps Team Integration

**Responsibilities:**
- Deploy and maintain the agent
- Configure alert routing
- Review automation decisions
- Update runbooks

**Workflow:**
```bash
# 1. Deploy agent
kubectl apply -f k8s/

# 2. Configure webhooks
curl -X POST https://agent.company.com/webhook \
  -H "Content-Type: application/json" \
  -d '{"alert": "HighCPU", "namespace": "production"}'

# 3. Monitor agent activity
kubectl logs -f deployment/devops-ai-agent -n devops
```

### 2. SRE Team Integration

**Responsibilities:**
- Define incident response procedures
- Set safety policies
- Review postmortems
- Improve runbooks

**Configuration:**
```python
# sre_policies.py
SAFETY_POLICIES = {
    "never_delete": ["databases", "persistent-volumes"],
    "require_approval": ["scaling-down", "config-changes"],
    "auto_fix": ["pod-restarts", "cache-clears"],
}
```

### 3. Security Team Integration

**Responsibilities:**
- Configure security scanning
- Review compliance checks
- Manage RBAC policies
- Audit agent actions

**Setup:**
```bash
# Enable security features
export ENABLE_SECURITY_SCANNING=true
export ENABLE_COMPLIANCE_CHECKS=true

# Configure RBAC
kubectl apply -f k8s/rbac.yaml

# Review audit logs
tail -f logs/audit.log
```

### 4. Development Team Integration

**Responsibilities:**
- Understand agent capabilities
- Report issues
- Contribute to runbooks
- Review documentation

**Usage:**
```bash
# Developers can trigger agent via CI/CD
- name: Notify DevOps Agent
  run: |
    curl -X POST $AGENT_URL/webhook \
      -d '{"pipeline": "failed", "job": "$CI_JOB_NAME"}'
```

---

## Workflow Integration

### 1. Incident Response Workflow

```
1. Alert Triggered
   ↓
2. Agent Receives Alert
   ↓
3. Agent Classifies Incident
   ↓
4. Agent Collects Context
   ↓
5. Agent Analyzes with Claude
   ↓
6. Safety Check (CRITICAL)
   │
   ├─ Safe → Auto-fix
   │          ↓
   │       7. Apply Fix
   │          ↓
   │       8. Verify Fix
   │          ↓
   │       9. Generate Documentation
   │
   └─ Dangerous → Email SRE
                  ↓
               10. SRE Manually Fixes
                  ↓
               11. Agent Documents Fix
```

### 2. CI/CD Pipeline Integration

**GitHub Actions Example:**

```yaml
name: Deploy with AI Agent Monitoring

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: kubectl apply -f deployment.yaml
      
      - name: Notify Agent
        if: always()
        run: |
          curl -X POST $AGENT_URL/cicd-event \
            -H "Content-Type: application/json" \
            -d '{
              "event": "deployment",
              "status": "${{ job.status }}",
              "repo": "${{ github.repository }}",
              "commit": "${{ github.sha }}"
            }'
      
      - name: Verify Deployment
        run: |
          # Agent can verify deployment
          curl $AGENT_URL/verify-deployment?app=myapp
```

### 3. Monitoring Integration

**Prometheus AlertManager:**

```yaml
# alertmanager.yml
receivers:
  - name: 'devops-ai-agent'
    webhook_configs:
      - url: 'https://agent.company.com/webhook'
        send_resolved: true

route:
  group_by: ['alertname', 'cluster', 'service']
  receiver: 'devops-ai-agent'
  routes:
    - match:
        severity: critical
      receiver: 'devops-ai-agent'
      continue: true
```

**Datadog:**

```json
{
  "name": "High CPU Alert",
  "message": "@webhook-devops-ai-agent CPU usage above 80%",
  "query": "avg(last_5m):avg:system.cpu.user{*} > 80"
}
```

### 4. ChatOps Integration

**Slack Integration:**

```python
# tools/slack_notifier.py
from slack_sdk import WebClient

client = WebClient(token=os.getenv('SLACK_TOKEN'))

def notify_incident(channel, incident):
    client.chat_postMessage(
        channel=channel,
        text=f"🚨 Incident: {incident['type']}\n"
             f"Status: {incident['status']}\n"
             f"Action: {incident['action']}"
    )
```

---

## Verification and Testing

### How to Verify if a Fix Worked

The agent includes automated fix verification:

#### 1. Automatic Verification

The agent automatically verifies fixes in two stages:

**Immediate Verification:**
- Checks that the fix was applied correctly
- Verifies expected state is reached
- Runs in < 30 seconds

**Stability Monitoring:**
- Monitors system for 5 minutes (configurable)
- Checks every 30 seconds
- Ensures fix is stable

**Example:**
```python
from tools.fix_verifier import FixVerifier

verifier = FixVerifier()
result = await verifier.verify_fix(
    incident_type="k8s",
    fix_applied="Restarted pod",
    expected_state={
        "pod_name": "api-service",
        "namespace": "production",
        "pod_status": "Running"
    },
    monitoring_duration=300  # 5 minutes
)

if result["verified"]:
    print("✓ Fix verified and stable")
else:
    print(f"✗ Fix failed: {result['reason']}")
```

#### 2. Manual Verification Steps

For manual fixes, follow these steps:

**Step 1: Check Immediate Status**
```bash
# Kubernetes
kubectl get pods -n production -w

# Server
systemctl status service-name

# Cloud (AWS)
aws ecs describe-services --cluster prod --services api
```

**Step 2: Check Logs**
```bash
# Kubernetes
kubectl logs -f pod-name -n production

# Server
journalctl -u service-name -f

# Cloud (GCP)
gcloud logging read "resource.type=container"
```

**Step 3: Check Metrics**
```bash
# Use monitoring system
# Prometheus, Datadog, CloudWatch, etc.

# Verify:
# - CPU usage returned to normal
# - Memory usage stable
# - Error rate decreased
# - Response time improved
```

**Step 4: Run Health Checks**
```bash
# Application endpoint
curl https://api.company.com/health

# Kubernetes
kubectl exec -it pod-name -- /health-check.sh

# Server
/opt/app/scripts/health-check.sh
```

#### 3. Verification Report

The agent generates a verification report:

```
FIX VERIFICATION REPORT
======================

Status: SUCCESS - success
Timestamp: 2026-06-12 13:00:00
Incident Type: k8s

Fix Applied:
Restarted pod and updated configmap

Verification Results:
- Verified: YES
- Monitoring Duration: 300s

Checks Performed:

1. immediate_verification
   Status: PASSED
   Details: Pod is in Running state

2. stability_monitoring
   Status: PASSED
   Details: System stable for 5 minutes
   Success Rate: 100%

Next Steps:
- Fix is verified and stable
- Update documentation
- Close incident ticket
```

---

## Documentation and Knowledge Management

### Automatic Documentation Generation

After every fix (manual or automatic), the agent generates:

#### 1. Runbook

Step-by-step guide to fix the issue:
- Problem statement
- Root cause
- Prerequisites
- Fix steps
- Verification steps
- Rollback plan

**Location:** `logs/<year>/<month>/<incident_id>/runbook.md` in incident storage

**Example:**
```markdown
# Runbook: K8S - Pod CrashLoopBackOff

## Problem Statement
Pod in production namespace stuck in CrashLoopBackOff

## Root Cause
Missing environment variable in deployment configuration

## Steps to Fix

### 1. Verify the Issue
kubectl get pods -n production

### 2. Apply the Fix
kubectl edit deployment api-service -n production
# Add missing ENV var

### 3. Verify the Fix
- [ ] Check pod status is Running
- [ ] Verify application logs show no errors
- [ ] Test application endpoint
```

#### 2. Postmortem

Detailed incident report:
- Timeline
- Root cause analysis
- Impact assessment
- Action items
- Lessons learned

**Location:** `logs/<year>/<month>/<incident_id>/postmortem.md` in incident storage

#### 3. Knowledge Base Article

Searchable KB entry:
- Problem symptoms
- Solution
- Prevention tips
- Related issues
- Tags for search

**Location:** `logs/<year>/<month>/<incident_id>/kb.md` in incident storage

### Using the Documentation Generator

**Automatic (for manual fixes):**

When you manually fix an issue, the agent automatically detects it and generates documentation:

```python
# The agent watches for manual interventions
# and automatically documents them

# Example: After you manually restart a pod
kubectl rollout restart deployment/api-service -n production

# Agent detects this and generates:
# 1. Runbook
# 2. Postmortem
# 3. KB article
```

**Manual trigger:**

```python
# Automatic: with AUTO_DOCUMENTATION=true (default) every completed incident gets
# postmortem.md, runbook.md and kb.md under logs/<year>/<month>/<incident_id>/
# in your storage backend (PII-scrubbed, same retention as the incident's logs).
from tools.documentation_generator import render_incident_docs

docs = render_incident_docs(incident_id, context, result)
# {"postmortem.md": "...", "runbook.md": "...", "kb.md": "..."}
```

### Searching Documentation

```bash
# Documents live next to each incident's logs: <org>/logs/<year>/<month>/<incident_id>/
# (STORAGE_PROVIDER=s3 shown; the default memory backend does not survive restarts)
aws s3 ls "s3://$STORAGE_BUCKET/<org>/logs/" --recursive | grep postmortem.md
aws s3 cp "s3://$STORAGE_BUCKET/<org>/logs/2026/11/<incident_id>/runbook.md" -
```

---

## Security and Compliance

### Safety Guarantees

The agent follows strict safety principles:

**NEVER DELETE. NEVER DESTROY. NOTIFY INSTEAD.**

**Permanently Blocked Operations:**
- rm -rf / or any recursive delete
- format, mkfs (filesystem format)
- dd (disk operations)
- DROP DATABASE, TRUNCATE TABLE
- kubectl delete namespace
- Deleting production resources

**Email Notification Triggers:**
- Any dangerous command detected
- Security vulnerabilities found
- Compliance violations
- Critical incidents

### Compliance Features

**Built-in Compliance Checks:**
- CIS Benchmarks
- SOC2 requirements
- PCI-DSS standards
- HIPAA controls
- GDPR data protection

**Audit Trail:**
All actions are logged:
```json
{
  "timestamp": "2026-06-12T13:00:00Z",
  "incident_id": "INC-001",
  "action": "restart_pod",
  "resource": "api-service",
  "namespace": "production",
  "approved_by": "auto",
  "verification": "passed"
}
```

### RBAC Configuration

```yaml
# k8s/rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: devops-ai-agent
  namespace: production
rules:
  # Read-only by default
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  
  # Limited write permissions
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "patch"]  # patch for restarts only
```

---

## Best Practices

### 1. Start Conservative

**Phase 1: Read-Only Mode (Week 1-2)**
- Enable monitoring only
- No automated fixes
- Generate documentation
- Review agent decisions

**Phase 2: Safe Actions (Week 3-4)**
- Enable pod restarts
- Enable cache clears
- Enable scaling up (not down)
- Still require approval for risky actions

**Phase 3: Full Automation (Month 2+)**
- Enable all safe actions
- Keep dangerous operations blocked
- Maintain email notifications

### 2. Team Training

**Training Program:**
1. Week 1: Introduction to agent capabilities
2. Week 2: Understanding safety policies
3. Week 3: Reviewing agent decisions
4. Week 4: Customizing for your environment

**Documentation:**
- Share this guide with all teams
- Create team-specific runbooks
- Document your policies
- Share success stories

### 3. Monitoring and Metrics

**Track These Metrics:**
- Incidents detected
- Incidents auto-fixed
- Incidents requiring human intervention
- Average time to fix
- Verification success rate
- Documentation generated

**Dashboard Example:**
```
DevOps AI Agent Dashboard
========================

This Month:
- Incidents: 145
- Auto-fixed: 112 (77%)
- Manual: 33 (23%)
- Avg Fix Time: 2.3 minutes
- Verification: 98% success

Documentation Generated:
- Runbooks: 33
- Postmortems: 33
- KB Articles: 33

Top Issues:
1. Pod CrashLoopBackOff (42)
2. High CPU usage (28)
3. CI/CD failures (23)
```

### 4. Continuous Improvement

**Monthly Reviews:**
- Review all incidents
- Update runbooks
- Refine safety policies
- Add new integrations
- Train the team on new features

**Feedback Loop:**
1. Agent suggests fix
2. SRE reviews
3. If correct → Add to auto-fix list
4. If incorrect → Update agent logic
5. Document in runbook

### 5. Integration Checklist

Before going live, verify:

- [ ] Agent deployed and accessible
- [ ] Monitoring systems integrated
- [ ] Email notifications configured
- [ ] RBAC permissions set
- [ ] Safety policies defined
- [ ] Team trained
- [ ] Documentation location configured
- [ ] Audit logging enabled
- [ ] Backup procedures in place
- [ ] Rollback procedures tested

---

## Support and Troubleshooting

### Common Issues

**Issue: Agent not receiving alerts**
```bash
# Check webhook configuration
curl -X POST https://agent.company.com/webhook/test

# Check agent logs
kubectl logs deployment/devops-ai-agent -n devops
```

**Issue: Fix verification failing**
```bash
# Check agent has necessary permissions
kubectl auth can-i get pods --as=system:serviceaccount:devops:ai-agent

# Check network connectivity
kubectl exec deployment/devops-ai-agent -- curl https://api.company.com
```

**Issue: Documentation not generated**
```bash
# Is it enabled? (default true; code-review runs are never documented)
kubectl exec deployment/devops-ai-agent -- printenv AUTO_DOCUMENTATION

# Did saving fail? (storage errors are logged, never fatal)
kubectl logs deployment/devops-ai-agent | grep incident_docs_failed
```

### Getting Help

1. Check logs: `kubectl logs -f deployment/devops-ai-agent`
2. Review incident documents: `<org>/logs/<year>/<month>/<incident_id>/postmortem.md` in storage
3. Check health endpoint: `curl https://agent.company.com/health`
4. Review audit logs: `tail -f logs/audit.log`

---

## Conclusion

The DevOps AI Agent is designed to be a force multiplier for your organization, handling routine incidents while ensuring safety through strict policies and human oversight.

**Key Benefits:**
- Reduces MTTR (Mean Time To Recovery)
- Generates comprehensive documentation
- Ensures compliance and security
- Scales with your organization
- Learns from every incident

**Remember:**
- Start conservative
- Train your teams
- Review regularly
- Contribute improvements
- Share knowledge

For questions or contributions, see CONTRIBUTING.md
