# Deployment Guide

This guide covers deploying the DevOps AI Agent in various environments.

## Table of Contents

- [Kubernetes Deployment](#kubernetes-deployment)
- [Docker Deployment](#docker-deployment)
- [Cloud Platforms](#cloud-platforms)
- [CI/CD Integration](#cicd-integration)
- [Monitoring Setup](#monitoring-setup)

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (v1.20+)
- `kubectl` configured
- Cluster admin access (for RBAC setup)

### Quick Deploy

```bash
# 1. Create namespace
kubectl create namespace devops-agent

# 2. Create secrets
kubectl create secret generic agent-secrets \
  --from-literal=ANTHROPIC_API_KEY='your-claude-api-key' \
  --from-literal=GITHUB_TOKEN='your-github-token' \
  --from-literal=SLACK_WEBHOOK_URL='your-slack-webhook' \
  --from-literal=SLACK_APPROVAL_CHANNEL='devops-approvals' \
  -n devops-agent

# 3. Deploy all resources
kubectl apply -f k8s/ -n devops-agent

# 4. Verify deployment
kubectl get pods -n devops-agent
kubectl logs -f deployment/devops-agent -n devops-agent
```

### Custom Configuration

Edit `k8s/configmap.yaml` for custom settings:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: agent-config
  namespace: devops-agent
data:
  AUTO_APPLY: "false"
  MAX_AGENT_STEPS: "10"
  ALLOWED_NAMESPACES: "default,staging,production"
  LOG_LEVEL: "INFO"
```

### RBAC Configuration

The agent requires specific Kubernetes permissions. Review `k8s/rbac.yaml`:

```yaml
# Minimum permissions for read-only operations
- apiGroups: [""]
  resources: ["pods", "pods/log", "events", "configmaps"]
  verbs: ["get", "list", "watch"]

# For auto-remediation (optional)
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "patch", "update"]
```

**Production Recommendation:** Start with read-only, add write permissions after 1 week of observation.

### Ingress Setup

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: devops-agent-ingress
  namespace: devops-agent
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - devops-agent.yourdomain.com
    secretName: devops-agent-tls
  rules:
  - host: devops-agent.yourdomain.com
    http:
      paths:
      - path: /webhook
        pathType: Prefix
        backend:
          service:
            name: devops-agent
            port:
              number: 8000
```

### Health Checks

```bash
# Check pod health
kubectl get pods -n devops-agent

# View logs
kubectl logs -f deployment/devops-agent -n devops-agent

# Check service
kubectl get svc -n devops-agent

# Test health endpoint
kubectl port-forward -n devops-agent svc/devops-agent 8000:8000
curl http://localhost:8000/health
```

### Scaling

```bash
# Scale replicas
kubectl scale deployment devops-agent --replicas=3 -n devops-agent

# Horizontal Pod Autoscaler (optional)
kubectl autoscale deployment devops-agent \
  --cpu-percent=70 \
  --min=2 \
  --max=10 \
  -n devops-agent
```

---

## Docker Deployment

### Docker Compose (Quick Start)

```bash
# 1. Update environment in docker-compose.yml or create .env
cp .env.example .env
nano .env

# 2. Start services
docker-compose up -d

# 3. View logs
docker-compose logs -f devops-agent

# 4. Stop services
docker-compose down
```

### Standalone Docker

```bash
# Build image
docker build -t devops-ai-agent:latest -f docker/Dockerfile .

# Run container
docker run -d \
  --name devops-agent \
  -p 8000:8000 \
  -e ANTHROPIC_API_KEY='your-key' \
  -e GITHUB_TOKEN='your-token' \
  -e SLACK_WEBHOOK_URL='your-webhook' \
  -e AUTO_APPLY='false' \
  -v $(pwd)/audit_log.json:/app/audit_log.json \
  devops-ai-agent:latest

# View logs
docker logs -f devops-agent

# Stop container
docker stop devops-agent
docker rm devops-agent
```

### Docker with External Kubernetes

```bash
# Mount kubeconfig
docker run -d \
  --name devops-agent \
  -p 8000:8000 \
  -v ~/.kube/config:/root/.kube/config:ro \
  -e ANTHROPIC_API_KEY='your-key' \
  -e GITHUB_TOKEN='your-token' \
  devops-ai-agent:latest
```

---

## Cloud Platforms

### AWS ECS

#### Prerequisites

- AWS CLI configured
- ECS cluster created
- ECR repository for image

#### Deploy to ECS

```bash
# 1. Build and push image
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com

docker build -t devops-ai-agent:latest -f docker/Dockerfile .
docker tag devops-ai-agent:latest YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/devops-ai-agent:latest
docker push YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/devops-ai-agent:latest

# 2. Create task definition
aws ecs register-task-definition --cli-input-json file://ecs-task-definition.json

# 3. Create service
aws ecs create-service \
  --cluster your-cluster \
  --service-name devops-agent \
  --task-definition devops-agent:1 \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx]}"
```

**ECS Task Definition Example:**

```json
{
  "family": "devops-agent",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "containerDefinitions": [
    {
      "name": "devops-agent",
      "image": "YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/devops-ai-agent:latest",
      "portMappings": [{"containerPort": 8000, "protocol": "tcp"}],
      "secrets": [
        {"name": "ANTHROPIC_API_KEY", "valueFrom": "arn:aws:secretsmanager:..."},
        {"name": "GITHUB_TOKEN", "valueFrom": "arn:aws:secretsmanager:..."}
      ],
      "environment": [
        {"name": "AUTO_APPLY", "value": "false"}
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/devops-agent",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Google Cloud Run

```bash
# 1. Build and push to GCR
gcloud builds submit --tag gcr.io/YOUR_PROJECT/devops-agent

# 2. Deploy to Cloud Run
gcloud run deploy devops-agent \
  --image gcr.io/YOUR_PROJECT/devops-agent \
  --platform managed \
  --region us-central1 \
  --set-env-vars AUTO_APPLY=false \
  --set-secrets ANTHROPIC_API_KEY=anthropic-key:latest,GITHUB_TOKEN=github-token:latest \
  --allow-unauthenticated \
  --port 8000

# 3. Get service URL
gcloud run services describe devops-agent --region us-central1 --format 'value(status.url)'
```

### Azure Container Instances

```bash
# 1. Build and push to ACR
az acr build --registry yourregistry --image devops-agent:latest -f docker/Dockerfile .

# 2. Deploy to ACI
az container create \
  --resource-group your-rg \
  --name devops-agent \
  --image yourregistry.azurecr.io/devops-agent:latest \
  --registry-username YOUR_USERNAME \
  --registry-password YOUR_PASSWORD \
  --dns-name-label devops-agent \
  --ports 8000 \
  --environment-variables \
    AUTO_APPLY=false \
  --secure-environment-variables \
    ANTHROPIC_API_KEY=your-key \
    GITHUB_TOKEN=your-token

# 3. Get FQDN
az container show --resource-group your-rg --name devops-agent --query ipAddress.fqdn
```

---

## CI/CD Integration

### GitHub Actions Webhook

```yaml
# .github/workflows/notify-agent.yml
name: Notify Agent on Failure

on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  notify-agent:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'failure' }}
    steps:
      - name: Notify DevOps Agent
        run: |
          curl -X POST https://devops-agent.yourdomain.com/webhook/github \
            -H "Content-Type: application/json" \
            -H "X-GitHub-Event: workflow_run" \
            -d '{"action": "completed", "workflow_run": {"id": "${{ github.event.workflow_run.id }}", "conclusion": "failure"}}'
```

### GitLab CI Webhook

```yaml
# .gitlab-ci.yml
after_script:
  - |
    if [ "$CI_JOB_STATUS" == "failed" ]; then
      curl -X POST https://devops-agent.yourdomain.com/webhook/gitlab \
        -H "Content-Type: application/json" \
        -H "X-Gitlab-Token: $WEBHOOK_TOKEN" \
        -d "{\"object_kind\": \"pipeline\", \"project\": {\"id\": $CI_PROJECT_ID}, \"object_attributes\": {\"id\": $CI_PIPELINE_ID, \"status\": \"failed\"}}"
    fi
```

### Prometheus Alertmanager

```yaml
# alertmanager.yml
route:
  receiver: 'devops-agent'
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h

receivers:
  - name: 'devops-agent'
    webhook_configs:
      - url: 'https://devops-agent.yourdomain.com/webhook/alertmanager'
        send_resolved: true
        http_config:
          bearer_token: 'your-webhook-token'
```

---

## Monitoring Setup

### Prometheus Metrics

The agent exposes metrics at `/metrics`:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'devops-agent'
    static_configs:
      - targets: ['devops-agent:8000']
    metrics_path: '/metrics'
```

### Key Metrics

- `agent_incidents_total` - Total incidents processed
- `agent_incidents_resolved_total` - Successfully resolved incidents
- `agent_tool_calls_total` - Tool execution count
- `agent_approval_requests_total` - Approval requests sent
- `agent_errors_total` - Errors encountered

### Grafana Dashboard

Import the provided dashboard: `monitoring/grafana-dashboard.json`

### Logging

#### ELK Stack

```yaml
# filebeat.yml
filebeat.inputs:
- type: container
  paths:
    - '/var/lib/docker/containers/*/*.log'
  processors:
    - add_kubernetes_metadata:
        host: ${NODE_NAME}
        matchers:
        - logs_path:
            logs_path: "/var/lib/docker/containers/"

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "devops-agent-%{+yyyy.MM.dd}"
```

#### CloudWatch (AWS)

```bash
# Install CloudWatch agent
aws logs create-log-group --log-group-name /devops-agent

# Agent logs to CloudWatch automatically if running on ECS/EC2 with proper IAM role
```

### Alerting

```yaml
# Alert on agent failures
groups:
  - name: devops-agent
    rules:
      - alert: AgentHighErrorRate
        expr: rate(agent_errors_total[5m]) > 0.1
        for: 5m
        annotations:
          summary: "DevOps Agent error rate is high"
          
      - alert: AgentDown
        expr: up{job="devops-agent"} == 0
        for: 2m
        annotations:
          summary: "DevOps Agent is down"
```

---

## Security Best Practices

### Secrets Management

**Kubernetes:**
```bash
# Use sealed secrets or external secrets operator
kubectl create secret generic agent-secrets \
  --from-literal=ANTHROPIC_API_KEY='...' \
  --dry-run=client -o yaml | kubeseal -o yaml > sealed-secret.yaml
```

**AWS:**
```bash
# Use AWS Secrets Manager
aws secretsmanager create-secret \
  --name devops-agent/anthropic-api-key \
  --secret-string 'your-key'
```

**GCP:**
```bash
# Use Secret Manager
gcloud secrets create anthropic-api-key --data-file=-
```

### Network Security

- Use TLS/HTTPS for all webhook endpoints
- Implement webhook signature verification
- Use network policies in Kubernetes
- Restrict egress traffic to required APIs only

### RBAC

- Follow principle of least privilege
- Start with read-only permissions
- Audit permission usage regularly
- Use namespace-scoped roles when possible

---

## Troubleshooting

### Agent Not Starting

```bash
# Check logs
kubectl logs -n devops-agent deployment/devops-agent --tail=100

# Common issues:
# 1. Missing API keys - check secrets
# 2. Invalid kubeconfig - verify RBAC
# 3. Network issues - check network policies
```

### Webhooks Not Working

```bash
# Test webhook manually
curl -X POST https://your-agent.com/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{"type": "k8s", "namespace": "default", "pod_name": "test"}'

# Check firewall rules
# Verify DNS resolution
# Check ingress/load balancer configuration
```

### Agent Not Taking Actions

```bash
# Check AUTO_APPLY setting
kubectl get configmap agent-config -n devops-agent -o yaml

# Review audit log
curl -H "Authorization: Bearer $API_TOKEN" https://your-agent.com/audit

# Check approval channel in Slack
```

---

## Performance Tuning

### Resource Limits

```yaml
resources:
  requests:
    memory: "512Mi"
    cpu: "250m"
  limits:
    memory: "1Gi"
    cpu: "1000m"
```

### Concurrency

```python
# api/server.py
app = FastAPI()

# Adjust worker count based on load: only with shared storage
# (STORAGE_PROVIDER=s3|gcs|azure|minio). With in-memory storage keep one worker;
# a second process refuses to start because it couldn't see the queue or approvals.
# WEB_CONCURRENCY=4 uvicorn api.server:app --workers 4
```

### Caching

Consider caching for:
- GitHub API responses
- Kubernetes resource lookups
- Cloud provider API calls

---

## Backup and Recovery

### Audit Log Backup

```bash
# Kubernetes persistent volume for audit log
kubectl apply -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: agent-audit-log
  namespace: devops-agent
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
EOF
```

### Configuration Backup

```bash
# Backup all agent resources
kubectl get all,secrets,configmaps -n devops-agent -o yaml > agent-backup.yaml
```

---

## Upgrading

```bash
# 1. Backup current configuration
kubectl get all,secrets,configmaps -n devops-agent -o yaml > backup-$(date +%Y%m%d).yaml

# 2. Pull latest changes
git pull origin main

# 3. Build new image
docker build -t devops-ai-agent:v2 -f docker/Dockerfile .

# 4. Update deployment
kubectl set image deployment/devops-agent devops-agent=devops-ai-agent:v2 -n devops-agent

# 5. Monitor rollout
kubectl rollout status deployment/devops-agent -n devops-agent

# 6. Rollback if needed
kubectl rollout undo deployment/devops-agent -n devops-agent
```

---

## Support

- Documentation: [README.md](README.md)
- Issues: [GitHub Issues](https://github.com/open-devops-agent/open-devops-agent/issues)
- Discussions: [GitHub Discussions](https://github.com/open-devops-agent/open-devops-agent/discussions)
