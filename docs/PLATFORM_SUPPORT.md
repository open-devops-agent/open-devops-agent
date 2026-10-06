# Platform Support Matrix

Complete list of supported platforms, operating systems, and integrations.

## Cloud Providers

| Provider | Supported | Collector | Services |
|----------|-----------|-----------|----------|
| Amazon Web Services (AWS) | Yes | `collectors/aws.py` | EC2, EKS, ECS/Fargate, ECR, Lambda, RDS, ElastiCache, DynamoDB, ALB/ELB, VPC, S3, SQS, SNS, Auto Scaling, Elastic Beanstalk, App Runner, Batch, CloudWatch |
| Google Cloud Platform (GCP) | Yes | `collectors/gcp.py` | GCE VMs, GKE, Cloud Run, Cloud Functions, Cloud SQL, Artifact Registry, Cloud Storage, Load Balancers, Memorystore, Pub/Sub, Cloud Composer, Instance Groups, Firestore |
| Microsoft Azure | Yes | `collectors/azure.py` | VMs, VMSS, AKS, ACI, Container Apps, ACR, App Service, Functions, SQL*, Cosmos DB*, Redis*, Load Balancers, Storage, Service Bus, Batch |

\* **Database/cache services optional** — disabled unless `ENABLE_DATABASE_COLLECTION=true` (default: false)

**Full service registry:** `collectors/cloud_registry.py`  
**Database policy:** `collectors/database_policy.py`

### AWS Details

**Supported Services:**

| Category | Resource Types |
|----------|----------------|
| **VMs** | `ec2` |
| **Kubernetes** | `eks`, `eks_nodegroup` |
| **Containers** | `ecs`, `fargate`, `ecr`, `apprunner`, `batch` |
| **Serverless** | `lambda` |
| **Databases** | `rds`, `elasticache`, `dynamodb` |
| **Networking** | `alb`, `elb`, `vpc` |
| **Storage/Messaging** | `s3`, `sqs`, `sns` |
| **Scaling** | `autoscaling`, `elasticbeanstalk` |
| **Monitoring** | `cloudwatch` |

**Example — EKS cluster:**
```python
from collectors.aws import AWSCollector

collector = AWSCollector()
data = await collector.collect("eks", "my-production-cluster")
```

**Example — EC2 VM:**
```python
data = await collector.collect("ec2", "i-1234567890abcdef")
```

**Example — ECS/Fargate task:**
```python
data = await collector.collect("ecs", "arn:aws:ecs:...", cluster="prod-cluster")
```

### GCP Details

**Supported Services:**

| Category | Resource Types |
|----------|----------------|
| **VMs** | `gce`, `compute` (alias) |
| **Kubernetes** | `gke`, `gke_nodepool` |
| **Containers** | `cloud_run`, `artifact_registry` |
| **Serverless** | `cloud_function` |
| **Databases** | `cloud_sql`, `firestore`, `memorystore` |
| **Networking** | `load_balancer` |
| **Storage/Messaging** | `cloud_storage`, `pubsub` |
| **Orchestration** | `cloud_composer`, `instance_group` |

**Example — GKE cluster:**
```python
from collectors.gcp import GCPCollector

collector = GCPCollector()
data = await collector.collect(
    "gke", "my-cluster",
    cluster="my-cluster", zone="us-central1-a"
)
```

**Example — GCE VM:**
```python
data = await collector.collect("gce", "web-server-01", zone="us-central1-a")
```

### Azure Details

**Supported Services:**

| Category | Resource Types |
|----------|----------------|
| **VMs** | `vm`, `vmss` |
| **Kubernetes** | `aks` |
| **Containers** | `aci`, `container_instance`, `container_apps`, `acr` |
| **App Hosting** | `app_service`, `function` |
| **Databases** | `sql`, `cosmosdb`, `redis` |
| **Networking** | `load_balancer`, `application_gateway` |
| **Storage/Messaging** | `storage`, `service_bus` |
| **Batch** | `batch` |

**Example — AKS cluster:**
```python
from collectors.azure import AzureCollector

collector = AzureCollector()
data = await collector.collect(
    "aks", "prod-aks",
    resource_group="production-rg"
)
```

**Example — Azure VM:**
```python
data = await collector.collect("vm", "web-vm-01", resource_group="production-rg")
```

**Example — Azure Container Instances:**
```python
data = await collector.collect("aci", "api-container-group", resource_group="production-rg")
```

---

## Operating Systems

| OS | Versions | Collector | Features |
|----|----------|-----------|----------|
| Linux (Ubuntu/Debian) | All | `collectors/server_enhanced.py` | Full diagnostics, systemd, apt |
| RHEL/CentOS | 7, 8, 9 | `collectors/server_enhanced.py` | Full diagnostics, systemd, yum/dnf, SELinux |
| Amazon Linux | 1, 2, 2023 | `collectors/server_enhanced.py` | Full diagnostics, systemd |
| Windows Server | 2016, 2019, 2022 | `collectors/server_enhanced.py` | PowerShell diagnostics, Event Logs |

### Linux (Ubuntu/Debian) Support

**Diagnostics Collected:**
- OS info: `uname`, distribution, kernel version
- CPU: Usage, load average, core count
- Memory: Usage, swap, cache, buffers
- Disk: Usage, I/O stats, inode usage
- Network: Connections, listening ports, interfaces
- Processes: Top CPU/memory consumers
- Services: systemd units, failed services
- Logs: journalctl errors, kernel errors

**Commands Run:**
```bash
uname -a
free -h
df -h
ps aux --sort=-%cpu
systemctl list-units --state=failed
journalctl -p err -n 50
ss -tlnp
ip addr show
```

### RHEL/CentOS Support

**Additional Features:**
- SELinux status and denials
- firewalld configuration
- yum/dnf update checks
- Red Hat subscription status

**Commands Run:**
```bash
cat /etc/redhat-release
sestatus
systemctl status firewalld
yum check-update
```

### Windows Server Support

**Diagnostics Collected:**
- OS info: Version, build, uptime
- CPU: Usage, processor info
- Memory: Total, available, committed
- Disk: Logical disks, free space
- Processes: Top memory consumers
- Services: Running and stopped services
- Network: Connections, listening ports
- Event Logs: System/Application errors and warnings
- Firewall: Status across all profiles
- Scheduled tasks: Status

**Commands Run:**
```powershell
systeminfo
wmic cpu get name,numberofcores
Get-Process | Sort-Object WorkingSet -Descending
Get-Service | Where-Object {$_.Status -eq 'Running'}
Get-EventLog -LogName System -EntryType Error -Newest 20
netstat -ano | findstr LISTENING
ipconfig /all
```

---

## CI/CD Platforms

| Platform | Supported | Collector | Features |
|----------|-----------|-----------|----------|
| GitHub Actions | Yes | `collectors/github.py` | Workflow failures, check runs, deployment status |
| GitLab CI/CD | Yes | `collectors/gitlab.py` | Pipeline failures, job logs, runner issues |
| Jenkins | Yes | `collectors/jenkins.py` | Build failures, console logs, plugin issues |
| Bamboo | Yes | `collectors/bamboo.py` | Build failures, version check/increment, Specs PRs |
| Azure DevOps | Yes | `collectors/azure_devops.py` | Pipeline failures, release issues |
| ArgoCD | Yes | `collectors/argocd.py` | Sync failures, health status, rollbacks |

### GitHub Actions

**Capabilities:**
- Webhook integration for workflow events
- Fetch workflow run logs
- Check run status analysis
- Deployment status tracking
- Re-run failed jobs (`POST /repos/{owner}/{repo}/actions/runs/{id}/rerun-failed-jobs`)

**Setup:**
```yaml
# .github/workflows/notify-agent.yml
- name: Notify Agent on Failure
  if: failure()
  run: |
    curl -X POST $AGENT_URL/webhook \
      -d '{"platform": "github", "event": "${{ github.event_name }}"}'
```

### GitLab CI/CD

**Capabilities:**
- Webhook integration for pipeline events
- Fetch job logs and traces
- Pipeline failure analysis
- Deployment tracking

**Setup:**
```yaml
# .gitlab-ci.yml
after_script:
  - |
    if [ "$CI_JOB_STATUS" = "failed" ]; then
      curl -X POST $AGENT_URL/webhook \
        -d '{"platform": "gitlab", "pipeline_id": "$CI_PIPELINE_ID"}'
    fi
```

### Jenkins

**Capabilities:**
- Webhook integration via notification plugin
- Console log parsing
- Build failure analysis
- Plugin issue detection
- PR of Jenkinsfile on `JENKINS_SCM_REPO` (GitHub/GitLab/Azure)

**Setup:**
```groovy
// Jenkinsfile
post {
  failure {
    sh "curl -X POST $AGENT_URL/webhook -d '{\"platform\": \"jenkins\"}'"
  }
}
```

### Bamboo

**Capabilities:**
- Manual incident trigger and build-log collection
- Queue a new build (`POST /rest/api/latest/queue/{PROJECT}-{PLAN}`)
- Version check: plan variable + latest ResultResource (`GET .../result/{PROJECT}-{PLAN}-latest`)
- Patch increment: bump `version` (or `BAMBOO_VERSION_VARIABLE`), PUT, then queue
- PR against `BAMBOO_SPECS_REPO` (Bamboo has no native PR API)

**REST (PlanResource / ResultResource / QueueResource):**
```
GET  /rest/api/latest/plan/{PROJECT}-{PLAN}/variables/{name}
GET  /rest/api/latest/result/{PROJECT}-{PLAN}-latest
PUT  /rest/api/latest/plan/{PROJECT}-{PLAN}/variables/{name}   body: {"name":"...","value":"..."}
POST /rest/api/latest/queue/{PROJECT}-{PLAN}?bamboo.variable.{name}=1.4.1
```

Fallback version check if `/variables/{name}` is unavailable:

```
GET /rest/api/latest/plan/{PROJECT}-{PLAN}?expand=variableContext
```

**Setup:**
```bash
# .env
BAMBOO_URL=https://bamboo.yourcompany.com
BAMBOO_USERNAME=admin
BAMBOO_PASSWORD=...
BAMBOO_VERSION_VARIABLE=version
BAMBOO_SCM_PROVIDER=github
BAMBOO_SPECS_REPO=your-org/bamboo-specs
```

```bash
curl -X POST $AGENT_URL/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{"type":"cicd","source":"bamboo","plan_key":"PROJ-PLAN"}'
```

### ArgoCD

**Capabilities:**
- Application health monitoring
- Sync status tracking
- Resource health analysis
- Automatic rollback on failures

**Setup:**
```yaml
# argocd application
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: myapp
  annotations:
    notifications.argoproj.io/subscribe.on-sync-failed.webhook: devops-ai-agent
```

---

## Container Orchestration

| Platform | Supported | Collector | Features |
|----------|-----------|-----------|----------|
| Kubernetes | Yes | `collectors/k8s.py` | Pod issues, events, logs, resource metrics |
| Docker | Yes | `collectors/docker.py` | Container health, image issues, network |
| OpenShift | Yes | Via K8s collector | Full K8s support + OpenShift-specific resources |
| EKS (AWS) | Yes | Via K8s + AWS collectors | Cluster issues, node problems |
| GKE (GCP) | Yes | Via K8s + GCP collectors | Cluster issues, node pools |
| AKS (Azure) | Yes | Via K8s + Azure collectors | Cluster issues, node problems |

### Kubernetes

**Issues Detected:**
- CrashLoopBackOff: Container crashes repeatedly
- ImagePullBackOff: Cannot pull container image
- OOMKilled: Out of memory
- Pending: Cannot schedule pod
- ConfigMap/Secret errors: Missing or invalid configuration
- Resource limits: CPU/memory constraints
- Network issues: Service unavailable

**Data Collected:**
- Pod status and events
- Container logs (last 100 lines)
- Resource usage (CPU, memory)
- ConfigMaps and Secrets (metadata only)
- Service endpoints
- Deployment/StatefulSet status
- Node conditions

**Example:**
```python
from collectors.k8s import K8sCollector

collector = K8sCollector()
data = await collector.collect({
    "namespace": "production",
    "pod_name": "api-service-xyz"
})
```

### Docker

**Capabilities:**
- Container health checks
- Image pull issues
- Volume problems
- Network connectivity
- Resource usage

---

## Monitoring Integration

| System | Integration Method | Setup Difficulty |
|--------|-------------------|------------------|
| Prometheus/AlertManager | Webhook receiver | Easy |
| Datadog | Webhook integration | Easy |
| AWS CloudWatch | EventBridge + Lambda | Medium |
| Azure Monitor | Action Group webhook | Easy |
| PagerDuty | Webhook integration | Easy |
| Grafana | Alert notification channel | Easy |

### Prometheus/AlertManager

**Configuration:**
```yaml
# alertmanager.yml
receivers:
  - name: 'devops-ai-agent'
    webhook_configs:
      - url: 'https://agent.company.com/webhook'
        send_resolved: true

route:
  receiver: 'devops-ai-agent'
```

### Datadog

**Configuration:**
```json
{
  "name": "DevOps AI Agent",
  "message": "@webhook-devops-ai-agent {{alert_title}}",
  "query": "avg(last_5m):..."
}
```

---

## DevOps Tool Integration

| Category | Tools | Integration |
|----------|-------|-------------|
| **Version Control** | GitHub, GitLab, Bitbucket | Webhook, API |
| **CI/CD** | Jenkins, GitHub Actions, GitLab CI, Azure DevOps, Bamboo | Webhook, API |
| **Container Registry** | Docker Hub, ECR, GCR, ACR | API access |
| **Infrastructure as Code** | Terraform, CloudFormation, ARM templates | CLI integration |
| **Configuration Management** | Ansible, Chef, Puppet | CLI integration |
| **Service Mesh** | Istio, Linkerd | K8s API |
| **API Gateway** | Kong, Ambassador, Nginx | Config analysis |
| **Secrets Management** | Vault, AWS Secrets Manager, Azure Key Vault | API access |

---

## Requirements by Platform

### Minimum Requirements

**For All Platforms:**
- Python 3.9+
- 2GB RAM
- Network access to monitored systems

**For Kubernetes:**
- `kubectl` configured
- RBAC permissions (read pods, logs, events)
- kubeconfig file

**For AWS:**
- AWS credentials configured
- IAM permissions (read-only)
- AWS CLI (optional)

**For GCP:**
- GCP credentials configured
- IAM permissions (read-only)
- gcloud CLI (optional)

**For Azure:**
- Azure credentials configured
- RBAC permissions (reader)
- Azure CLI (optional)

**For Windows:**
- PowerShell 5.1+
- Administrator privileges for service management

---

## Adding New Platforms

To add support for a new platform:

1. **Create Collector** (`collectors/new_platform.py`):
```python
class NewPlatformCollector:
    async def collect(self, incident_data: dict) -> dict:
        # Collect diagnostics
        return {"status": "...", "logs": "..."}
```

2. **Register in Classifier** (`agent/classifier.py`):
```python
def classify_issue(alertname, labels):
    if "newplatform" in alertname.lower():
        return "newplatform"
```

3. **Add Tools** (`tools/new_platform_tools.py`):
```python
def fix_newplatform_issue(issue_type):
    # Implement fix
    pass
```

4. **Update Documentation**:
- Add to this file
- Update README.md
- Create examples

**See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guide.**

---

## Platform-Specific Notes

### Multi-Cloud Considerations

- Agent can monitor multiple clouds simultaneously
- Credentials must be configured for each cloud
- Cross-cloud incident correlation supported
- Unified documentation across clouds

### Hybrid Environments

- Mix of on-premise and cloud supported
- VPN/bastion configuration may be needed
- Network connectivity is critical
- Consider agent per environment

### Air-Gapped Environments

- Deploy agent within air-gapped network
- Configure internal image registries
- Use internal documentation storage
- Email may need internal SMTP server

---

## Feature Comparison

| Feature | AWS | GCP | Azure | K8s | Linux | Windows | RHEL |
|---------|-----|-----|-------|-----|-------|---------|------|
| Health Checks | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Log Collection | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Metrics | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Auto-Remediation | Yes | Yes | Yes | Yes | Yes | Partial | Yes |
| Compliance Checks | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Security Scanning | Yes | Yes | Yes | Yes | Yes | Yes | Yes |

---

## Testing Platform Support

Each collector has unit tests:

```bash
# Test all collectors
pytest tests/test_basic.py -v

# Test specific platform
pytest tests/test_basic.py::TestK8sCollector -v

# Test with real credentials (careful!)
pytest tests/integration/ -v
```

---

## Roadmap

**Coming Soon:**
- VMware vSphere support
- Oracle Cloud Infrastructure
- Alibaba Cloud
- DigitalOcean
- Heroku
- IBM Cloud

**Want a platform added?** Open an issue or submit a PR!

---

For questions or issues with platform support, see [CONTRIBUTING.md](CONTRIBUTING.md).
