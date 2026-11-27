# Build and Usage — Python Package and Docker Image

How to build, install, and run the DevOps AI Agent as a **Python package** or **Docker image**.

---

## Table of Contents

1. [Python Package](#python-package)
   - [Build](#build-the-python-package)
   - [Install](#install-the-python-package)
   - [Usage](#usage-python-package)
   - [Publish to PyPI](#publish-to-pypi-optional)
2. [Docker Image](#docker-image)
   - [Build](#build-the-docker-image)
   - [Run](#run-the-docker-image)
   - [Usage](#usage-docker-image)
   - [Docker Compose](#docker-compose)
3. [Configuration (Both)](#configuration-both)
4. [Verify](#verify-both)

---

## Python Package

### Build the Python package

**Requirements:** Python 3.10+, `pip`, `build`

```bash
git clone https://github.com/open-devops-agent/open-devops-agent.git
cd open-devops-agent

# Option A: use the build script
chmod +x scripts/build_package.sh
./scripts/build_package.sh

# Option B: manual build
python3 -m pip install --upgrade build wheel
python3 -m build
```

**Output:**
```
dist/
  devops_ai_agent-1.0.0-py3-none-any.whl   # wheel (recommended for install)
  devops_ai_agent-1.0.0.tar.gz             # source distribution
```

---

### Install the Python package

**From local wheel (after build):**

```bash
pip install dist/devops_ai_agent-1.0.0-py3-none-any.whl
```

**From source (development):**

```bash
pip install -e ".[dev]"           # editable install + dev tools
pip install -e ".[aws,gcp,azure]" # editable + all cloud SDKs
```

**With optional cloud SDKs:**

```bash
# AWS only
pip install "dist/devops_ai_agent-1.0.0-py3-none-any.whl[aws]"

# GCP only
pip install "dist/devops_ai_agent-1.0.0-py3-none-any.whl[gcp]"

# Azure only
pip install "dist/devops_ai_agent-1.0.0-py3-none-any.whl[azure]"

# All clouds
pip install "dist/devops_ai_agent-1.0.0-py3-none-any.whl[cloud]"
```

**From PyPI (after you publish):**

```bash
pip install devops-ai-agent
pip install "devops-ai-agent[aws,gcp,azure]"
```

---

### Usage (Python package)

**1. Configure environment**

```bash
cp .env.example .env
# Edit .env — minimum: ANTHROPIC_API_KEY, EMAIL_*, SLACK_*
nano .env
```

**2. Start the agent**

```bash
# Production (one worker; more workers need shared storage, see below)
devops-agent serve

# Custom port
devops-agent serve --port 8080

# Development (auto-reload)
devops-agent serve --reload --port 8000

# Check version
devops-agent version
```

**Alternative (without CLI — same server):**

```bash
uvicorn api.server:app --host 0.0.0.0 --port 8000 --workers 1
```

> **More than one worker or replica needs shared storage** (`STORAGE_PROVIDER=s3|gcs|azure|minio`).
> With the default in-memory storage each process keeps its own queue, approvals and org config,
> so the agent refuses to start a second worker instead of silently losing incidents.

**3. Test**

```bash
curl http://localhost:8000/health

curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{"type": "server", "labels": {"alertname": "TestAlert", "severity": "warning"}}'
```

**4. Run as a systemd service (Linux/RHEL)**

```ini
# /etc/systemd/system/devops-ai-agent.service
[Unit]
Description=DevOps AI Agent
After=network.target

[Service]
Type=simple
User=devops
WorkingDirectory=/opt/devops-ai-agent
EnvironmentFile=/opt/devops-ai-agent/.env
ExecStart=/opt/devops-ai-agent/venv/bin/devops-agent serve --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable devops-ai-agent
sudo systemctl start devops-ai-agent
sudo systemctl status devops-ai-agent
```

---

### Publish to PyPI (optional)

```bash
# Build
./scripts/build_package.sh

# Upload (requires PyPI account + API token)
pip install twine
twine upload dist/*

# Install from PyPI
pip install devops-ai-agent
```

---

## Docker Image

### Build the Docker image

**Requirements:** Docker 20+

```bash
git clone https://github.com/open-devops-agent/open-devops-agent.git
cd open-devops-agent

# Option A: use the build script
chmod +x scripts/build_docker.sh
./scripts/build_docker.sh

# Option B: manual build
docker build -t devops-ai-agent:latest -f docker/Dockerfile .

# Custom name/tag
IMAGE_NAME=myregistry/devops-ai-agent IMAGE_TAG=v1.0.0 ./scripts/build_docker.sh
```

**Multi-platform build (optional):**

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t devops-ai-agent:latest \
  -f docker/Dockerfile \
  --push .
```

---

### Run the Docker image

**1. Create config file**

```bash
cp .env.example .env
nano .env
```

**2. Run container**

```bash
docker run -d \
  --name devops-ai-agent \
  -p 8000:8000 \
  --env-file .env \
  -v "$(pwd)/documentation:/app/documentation" \
  devops-ai-agent:latest
```

**With Kubernetes access (mount kubeconfig):**

```bash
docker run -d \
  --name devops-ai-agent \
  -p 8000:8000 \
  --env-file .env \
  -v "$HOME/.kube:/home/appuser/.kube:ro" \
  -v "$(pwd)/documentation:/app/documentation" \
  devops-ai-agent:latest
```

**With AWS credentials:**

```bash
docker run -d \
  --name devops-ai-agent \
  -p 8000:8000 \
  --env-file .env \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_REGION \
  devops-ai-agent:latest
```

---

### Usage (Docker image)

**Check logs:**

```bash
docker logs -f devops-ai-agent
```

**Health check:**

```bash
curl http://localhost:8000/health
```

**Send test incident:**

```bash
curl -X POST http://localhost:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: acme-corp" \
  -d '{
    "type": "k8s",
    "namespace": "default",
    "pod": "test-pod",
    "description": "Test incident"
  }'
# Response: {"status":"queued","incident_id":"INC-..."}
```

**View audit log** (poll after ~30s — processing is async):

```bash
curl -H "Authorization: Bearer $API_TOKEN" "http://localhost:8000/audit?org_id=acme-corp"
```

**API docs & Postman:** See [API_REFERENCE.md](API_REFERENCE.md), [API_TESTING.md](API_TESTING.md), and `postman/` folder.

**Stop / restart:**

```bash
docker stop devops-ai-agent
docker start devops-ai-agent
docker restart devops-ai-agent
```

**Update to new image:**

```bash
docker stop devops-ai-agent
docker rm devops-ai-agent
./scripts/build_docker.sh
docker run -d --name devops-ai-agent -p 8000:8000 --env-file .env devops-ai-agent:latest
```

**Push to a registry:**

```bash
docker tag devops-ai-agent:latest myregistry.io/devops/devops-ai-agent:v1.0.0
docker push myregistry.io/devops/devops-ai-agent:v1.0.0
```

---

### Docker Compose

```bash
cp .env.example .env
nano .env

docker compose up -d        # start
docker compose logs -f      # logs
docker compose ps           # status
docker compose down         # stop
```

**docker-compose.yml** (included in repo):

```yaml
services:
  agent:
    build:
      context: .
      dockerfile: docker/Dockerfile
    ports:
      - "8000:8000"
    env_file:
      - .env
    volumes:
      - ~/.kube:/home/appuser/.kube:ro
      - ./documentation:/app/documentation
    restart: unless-stopped
```

---

## Configuration (Both)

Same `.env` file works for Python package and Docker.

**Minimum required:**

```bash
ANTHROPIC_API_KEY=sk-ant-...
EMAIL_ENABLED=true
EMAIL_SMTP_HOST=smtp.yourcompany.com
EMAIL_TO=sre-team@yourcompany.com
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Safety defaults
AUTO_APPLY=false
ENABLE_DATABASE_COLLECTION=false
ENABLE_SECURITY_SCANNING=true
```

See `.env.example` for all options.

---

## Verify (Both)

```bash
# Health
curl http://localhost:8000/health

# Setup check (Python package only)
./scripts/verify_setup.sh

# Run tests (Python package dev install)
pip install -e ".[dev]"
pytest tests/ -v
```

---

## Quick Comparison

| | Python Package | Docker Image |
|---|----------------|--------------|
| **Best for** | VMs, bare metal, systemd, dev | Production, K8s, ECS, Cloud Run |
| **Install** | `pip install dist/*.whl` | `docker build` |
| **Start** | `devops-agent serve` | `docker run` or `docker compose up` |
| **CLI** | `devops-agent` command | `docker exec` |
| **Cloud extras** | `pip install .[aws,gcp,azure]` | Add to Dockerfile or mount creds |
| **Updates** | `pip install --upgrade` | Rebuild + redeploy image |

---

## Related Docs

- [usage-readme.md](../usage-readme.md) — installation from source + automated fixes
- [docs/DEPLOYMENT.md](DEPLOYMENT.md) — Kubernetes and cloud deployment
- [SECURITY_GUARANTEES.md](../SECURITY_GUARANTEES.md) — security and safety

---

Last updated: June 2026
