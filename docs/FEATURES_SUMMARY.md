# Features Summary

Quick reference for all agent capabilities.

## Core Features

### 1. Multi-Platform Monitoring

**Supports:**
- 3 Major Cloud Providers (AWS, GCP, Azure)
- 3 Operating Systems (Linux, Windows, RHEL)
- 6 CI/CD Platforms (GitHub Actions, GitLab CI, Jenkins, Bamboo, Azure DevOps, ArgoCD)
- Kubernetes + Docker
- Custom servers

**Files:**
- `collectors/aws.py` - AWS monitoring
- `collectors/gcp.py` - GCP monitoring
- `collectors/azure.py` - Azure monitoring
- `collectors/server.py` - Multi-OS server monitoring
- `collectors/k8s.py` - Kubernetes monitoring
- `collectors/github.py`, `gitlab.py`, `jenkins.py`, etc. - CI/CD monitoring

---

### 2. Automatic Fix Verification

**Capabilities:**
- Immediate verification (< 30 seconds)
- Stability monitoring (5 minutes default)
- Multiple health checks
- Success rate calculation
- Detailed verification reports

**Usage:**
```python
from tools.fix_verifier import FixVerifier

verifier = FixVerifier()
result = await verifier.verify_fix(
    incident_type="k8s",
    fix_applied="Restarted pod",
    expected_state={"pod_status": "Running"},
    monitoring_duration=300
)

print(result["verified"])  # True/False
print(result["status"])     # "success", "failed", "unstable"
```

**File:** `tools/fix_verifier.py`

---

### 3. Automatic Documentation Generation

**Generates:**
1. **Runbooks** - Step-by-step fix procedures
2. **Postmortems** - Detailed incident reports
3. **Knowledge Base Articles** - Searchable documentation

**Features:**
- Automatic after every fix (manual or automatic)
- Searchable with tags
- Stored with the incident's logs, same retention
- Markdown format

**Usage:**
```python
# Automatic: with AUTO_DOCUMENTATION=true (default) every completed incident gets
# postmortem.md, runbook.md and kb.md under logs/<year>/<month>/<incident_id>/
# in your storage backend (PII-scrubbed, same retention as the incident's logs).
from tools.documentation_generator import render_incident_docs

docs = render_incident_docs(incident_id, context, result)
# {"postmortem.md": "...", "runbook.md": "...", "kb.md": "..."}
```

**File:** `tools/documentation_generator.py`

---

### 4. Enhanced Server Monitoring

**Operating Systems:**
- Linux (Ubuntu, Debian, CentOS, Amazon Linux)
- RHEL (7, 8, 9, CentOS, Rocky, AlmaLinux)
- Windows Server (2016, 2019, 2022)

**Auto-Detection:**
- Automatically detects OS type
- Runs appropriate commands
- Platform-specific diagnostics

**Collected Data:**
- CPU usage and load
- Memory usage (detailed)
- Disk usage and I/O
- Network connections
- Running services
- System logs
- Failed services
- Top processes

**Special Features:**
- **RHEL**: SELinux status, firewalld, yum updates
- **Windows**: PowerShell diagnostics, Event Logs, Services

**File:** `collectors/server.py`

---

### 5. Safety-First Execution

**Principles:**
- NEVER DELETE
- NEVER DESTROY
- NOTIFY INSTEAD

**Features:**
- Command blacklist (destructive operations blocked)
- Email notifications for dangerous commands
- Dry-run mode
- Approval gates
- Comprehensive audit trail

**Blocked Operations:**
- `rm -rf /`
- `format`, `mkfs`
- `DROP DATABASE`
- `kubectl delete namespace`
- All recursive deletes

**File:** `tools/executor.py`

---

### 6. DevSecOps Features

**Security:**
- Vulnerability scanning
- Secrets detection
- Container security checks
- Network security validation

**Compliance:**
- CIS Benchmarks
- SOC2 requirements
- PCI-DSS standards
- HIPAA controls
- GDPR compliance

**File:** `collectors/security_scanner.py`

---

### 7. Email Notifications

**Triggers:**
- Dangerous operations detected
- Security vulnerabilities found
- Compliance violations
- Critical incidents
- Manual intervention required

**Configuration:**
```bash
EMAIL_ENABLED=true
EMAIL_SMTP_HOST=smtp.company.com
EMAIL_SMTP_PORT=587
EMAIL_FROM=devops-agent@company.com
EMAIL_TO=sre-team@company.com
EMAIL_USERNAME=agent
EMAIL_PASSWORD=secret
```

**File:** `tools/email_notifier.py`

---

### 8. Multi-Cloud Support

**AWS:**
- EC2 instance diagnostics
- ECS task analysis
- Lambda function errors
- RDS database health
- CloudWatch log queries

**GCP:**
- Compute Engine VM diagnostics
- Cloud Run service analysis
- Cloud Functions debugging
- Cloud SQL health
- Cloud Logging queries

**Azure:**
- Virtual Machine diagnostics
- Container Instances analysis
- Function App debugging
- SQL Database health
- Azure Monitor queries

**Files:** `collectors/aws.py`, `collectors/gcp.py`, `collectors/azure.py`

---

### 9. CI/CD Integration

**Platforms:**
- GitHub Actions
- GitLab CI/CD
- Jenkins
- Bamboo
- Azure DevOps
- ArgoCD

**Capabilities:**
- Webhook integration
- Pipeline failure detection
- Build log analysis
- Deployment tracking
- Rollback automation

**Files:** `collectors/github.py`, `gitlab.py`, `jenkins.py`, `bamboo.py`, `azure_devops.py`, `argocd.py`

---

### 10. Kubernetes Expertise

**Issues Handled:**
- CrashLoopBackOff
- ImagePullBackOff
- OOMKilled
- Pending pods
- ConfigMap/Secret errors
- Resource constraints
- Network issues

**Data Collected:**
- Pod status and events
- Container logs
- Resource usage
- Node conditions
- Service endpoints

**File:** `collectors/k8s.py`

---

## API Endpoints

### Webhook Endpoint

```bash
POST /webhook
Content-Type: application/json

{
  "alert": "HighCPU",
  "labels": {
    "namespace": "production",
    "severity": "critical"
  }
}
```

### Health Check

```bash
GET /health

Response:
{
  "status": "healthy",
  "version": "1.0.0",
  "collectors": ["k8s", "aws", "gcp", "azure"],
  "uptime": "5 days"
}
```

### Audit Log

```bash
GET /audit

Response:
[
  {
    "timestamp": "2026-06-12T13:00:00Z",
    "incident_id": "INC-001",
    "action": "restart_pod",
    "result": "success"
  }
]
```

### Fix Verification

```bash
POST /verify-fix
Content-Type: application/json

{
  "incident_type": "k8s",
  "fix_applied": "Restarted pod",
  "expected_state": {"pod_status": "Running"}
}
```

---

## Configuration

### Environment Variables

**Core:**
- `ANTHROPIC_API_KEY` - Claude API key (required)
- `LOG_LEVEL` - Logging level (default: INFO)
- `DRY_RUN` - Test mode (default: false)

**Email:**
- `EMAIL_ENABLED` - Enable email notifications
- `EMAIL_SMTP_HOST` - SMTP server
- `EMAIL_TO` - Alert recipient

**Security:**
- `ENABLE_SECURITY_SCANNING` - Enable security checks
- `ENABLE_COMPLIANCE_CHECKS` - Enable compliance validation
- `AGENT_EMERGENCY_STOP` - Emergency shutdown flag

**Cloud:**
- `AWS_REGION` - AWS region
- `GCP_PROJECT_ID` - GCP project
- `AZURE_SUBSCRIPTION_ID` - Azure subscription

**File:** `.env.example`

---

## Deployment Options

### Kubernetes

```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/service.yaml
```

### Docker

```bash
docker build -t devops-ai-agent .
docker run -d -p 8000:8000 \
  -e ANTHROPIC_API_KEY=sk-... \
  devops-ai-agent
```

### Cloud

- AWS: ECS Fargate
- GCP: Cloud Run
- Azure: Container Instances

**File:** `DEPLOYMENT.md`

---

## Testing

### Unit Tests

```bash
pytest tests/test_basic.py -v
```

### Integration Tests

```bash
pytest tests/integration/ -v
```

### CI/CD

```bash
# GitHub Actions
.github/workflows/ci.yml
```

---

## Documentation

| Document | Description |
|----------|-------------|
| `README.md` | Main project documentation |
| `ORGANIZATIONAL_GUIDE.md` | How to use in your organization |
| `PLATFORM_SUPPORT.md` | Detailed platform support matrix |
| `SECURITY_POLICY.md` | Safety and security policies |
| `DEVSECOPS_GUIDE.md` | DevSecOps features and best practices |
| `DEPLOYMENT.md` | Deployment guides for all platforms |
| `ARCHITECTURE.md` | System architecture and design |
| `CONTRIBUTING.md` | How to contribute |

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/open-devops-agent/open-devops-agent.git
cd devops-ai-agent
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your settings
```

### 3. Run

```bash
python agent/main.py
```

### 4. Test

```bash
curl -X POST http://localhost:8000/webhook \
  -H "Content-Type: application/json" \
  -d '{"alert": "test", "labels": {}}'
```

---

## Support

- GitHub Issues: Report bugs or request features
- Documentation: Read the guides above
- Contributing: See CONTRIBUTING.md

---

## Statistics

**Lines of Code:**
- Total: ~3,500+
- Collectors: ~1,200
- Tools: ~800
- Tests: ~500
- Documentation: ~2,000

**Platforms Supported:**
- Cloud Providers: 3 (AWS, GCP, Azure)
- Operating Systems: 3 (Linux, Windows, RHEL)
- CI/CD Platforms: 6
- Total Integration Points: 13+

**Test Coverage:**
- Unit Tests: Comprehensive
- Integration Tests: Core flows
- CI/CD: GitHub Actions with 5 jobs

---

Last Updated: June 12, 2026
