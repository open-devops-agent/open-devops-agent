# Contributing to DevOps AI Agent

Thank you for considering contributing to the DevOps AI Agent! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Adding New Platforms](#adding-new-platforms)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. Please be respectful and constructive in all interactions.

### Our Standards

- Use welcoming and inclusive language
- Be respectful of differing viewpoints
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

---

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git
- Basic understanding of DevOps concepts
- Familiarity with async Python and FastAPI (for API contributions)

### First Contribution

Look for issues labeled with:
- `good-first-issue` - Easy issues for newcomers
- `help-wanted` - Issues where we need community help
- `documentation` - Documentation improvements

---

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/open-devops-agent/open-devops-agent.git
cd devops-ai-agent

# Add upstream remote
git remote add upstream https://github.com/open-devops-agent/open-devops-agent.git
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate it
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows
```

### 3. Install Dependencies

```bash
# Install core dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt

# Or install everything
pip install pytest pytest-cov pytest-mock black flake8 mypy pylint
```

### 4. Set Up Pre-commit Hooks (Optional)

```bash
pip install pre-commit
pre-commit install
```

### 5. Create Test Environment

```bash
# Copy example environment
cp .env.example .env.test

# Edit with dummy values for testing
nano .env.test
```

### 6. Verify Setup

```bash
# Run tests
pytest tests/ -v

# Start the server
uvicorn api.server:app --reload --port 8000

# In another terminal, test health endpoint
curl http://localhost:8000/health
```

---

### Dependencies (hashed lock files)

`requirements.txt` (and `middleware/requirements.txt`) hold the version **ranges** you edit. The
Docker images install from `requirements.lock`, which pins every package, including transitive ones,
to one version and records its sha256 hashes. A package swapped or re-published on PyPI then fails
the build instead of shipping (#121).

- **Adding or changing a dependency:** edit `requirements.txt`, then run `scripts/lock.sh` and commit
  both files. Existing pins are kept; only what you changed is resolved.
- **Upgrading everything:** `scripts/lock.sh --upgrade`. The *Refresh dependency locks* workflow does
  this weekly and opens a PR.
- Use uv 0.11.28, the version CI uses (`pipx run uv==0.11.28 …` or `pip install uv==0.11.28`), so the
  lock format matches.
- CI's *Dependency Lock* job fails if a lock doesn't match `requirements.txt`, installs it with
  `--require-hashes`, runs the tests against it, and runs `pip-audit` on both locks.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce**
- **Expected behavior**
- **Actual behavior**
- **Environment details** (OS, Python version, etc.)
- **Logs or error messages**

**Bug Report Template:**

```markdown
**Description:**
Brief description of the bug

**Steps to Reproduce:**
1. Step one
2. Step two
3. Step three

**Expected Behavior:**
What should happen

**Actual Behavior:**
What actually happens

**Environment:**
- OS: 
- Python Version:
- Agent Version:

**Logs:**
```
Paste relevant logs here
```
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. Include:

- **Clear title and description**
- **Use case** - Why is this enhancement needed?
- **Proposed solution** - How should it work?
- **Alternatives considered**
- **Additional context**

### Pull Requests

1. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes**
   - Follow coding standards (see below)
   - Add tests for new functionality
   - Update documentation

3. **Test your changes**
   ```bash
   # Run all tests
   pytest tests/ -v
   
   # Run with coverage
   pytest --cov=. tests/
   
   # Run linting
   black .
   flake8 .
   mypy .
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add support for CircleCI"
   ```
   
   Use [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation changes
   - `test:` - Test additions or changes
   - `refactor:` - Code refactoring
   - `chore:` - Maintenance tasks

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create Pull Request**
   - Go to your fork on GitHub
   - Click "New Pull Request"
   - Fill out the PR template
   - Link any related issues

---

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://pep8.org/) with some modifications:

#### Formatting

- **Line length**: 100 characters (not 79)
- **Indentation**: 4 spaces (no tabs)
- **Quotes**: Double quotes for strings (except where single quotes improve readability)
- **Imports**: Organized in three groups (stdlib, third-party, local)

```python
# Standard library
import os
import sys
from typing import Dict, List, Optional

# Third-party
import anthropic
from fastapi import FastAPI

# Local
from agent.core import DevOpsAgent
from collectors.k8s import K8sCollector
```

#### Naming Conventions

- **Classes**: `PascalCase` (e.g., `K8sCollector`, `DevOpsAgent`)
- **Functions/Methods**: `snake_case` (e.g., `collect_logs`, `apply_manifest`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `MAX_RETRIES`, `DEFAULT_TIMEOUT`)
- **Private methods**: `_leading_underscore` (e.g., `_internal_helper`)

#### Type Hints

Always use type hints for function signatures:

```python
def collect_logs(
    pod_name: str,
    namespace: str = "default",
    tail_lines: Optional[int] = None
) -> Dict[str, any]:
    """
    Collects logs from a Kubernetes pod.
    
    Args:
        pod_name: Name of the pod
        namespace: Kubernetes namespace (default: "default")
        tail_lines: Number of lines to retrieve (optional)
    
    Returns:
        Dictionary containing logs and metadata
    
    Raises:
        K8sException: If pod not found or access denied
    """
    pass
```

#### Documentation

- **Module docstrings**: Describe what the module does
- **Class docstrings**: Describe the class purpose and usage
- **Function docstrings**: Use Google-style docstrings

```python
"""
collectors/gitlab.py

GitLab CI/CD collector for fetching pipeline logs and status.
"""

class GitLabCollector:
    """
    Collects logs and metadata from GitLab CI/CD pipelines.
    
    This collector interfaces with the GitLab API to fetch pipeline
    information, job logs, and failure details.
    
    Attributes:
        client: GitLab API client
        base_url: GitLab instance URL
    """
    
    def collect_pipeline_logs(self, project_id: int, pipeline_id: int) -> Dict[str, any]:
        """
        Fetches logs from a GitLab pipeline.
        
        Args:
            project_id: GitLab project ID
            pipeline_id: Pipeline ID
        
        Returns:
            Dictionary containing:
                - logs: List of job logs
                - status: Pipeline status
                - failed_jobs: List of failed job names
        
        Raises:
            GitLabAPIException: If API request fails
        """
        pass
```

### Error Handling

- Use specific exception types
- Always include helpful error messages
- Log errors appropriately

```python
try:
    result = api_client.get_data()
except requests.exceptions.Timeout:
    logger.error(f"Timeout connecting to {api_url}")
    raise CollectorException("Failed to fetch data: timeout")
except requests.exceptions.HTTPError as e:
    if e.response.status_code == 404:
        raise CollectorException(f"Resource not found: {resource_id}")
    raise
```

### Logging

Use structured logging:

```python
import logging

logger = logging.getLogger(__name__)

logger.info(f"Collecting logs for pod {pod_name} in namespace {namespace}")
logger.warning(f"Pod {pod_name} has been restarting frequently")
logger.error(f"Failed to apply manifest: {error_message}")
```

### Security

- **Never hardcode credentials**
- **Use environment variables** for secrets
- **Validate all inputs** (especially user-provided data)
- **Use parameterized queries** for any database operations
- **Sanitize shell commands** in executor

```python
# Bad
os.system(f"kubectl get pod {pod_name}")  # Shell injection risk!

# Good
subprocess.run(
    ["kubectl", "get", "pod", pod_name],
    capture_output=True,
    check=True
)
```

---

## Testing

### Test Structure

```
tests/
├── test_agent.py          # Agent core tests
├── test_collectors/
│   ├── test_k8s.py
│   ├── test_github.py
│   └── test_gitlab.py
├── test_tools/
│   ├── test_executor.py
│   ├── test_k8s_tools.py
│   └── test_github_tools.py
└── fixtures/
    ├── k8s_pod.yaml
    └── github_workflow_log.txt
```

### Writing Tests

```python
import pytest
from unittest.mock import Mock, patch

def test_k8s_collector_fetches_logs():
    """Test that K8s collector successfully fetches pod logs"""
    # Arrange
    collector = K8sCollector()
    mock_k8s = Mock()
    mock_k8s.read_namespaced_pod_log.return_value = "test log output"
    
    # Act
    with patch('collectors.k8s.client.CoreV1Api', return_value=mock_k8s):
        result = collector.collect({"pod_name": "test-pod", "namespace": "default"})
    
    # Assert
    assert "logs" in result
    assert "test log output" in result["logs"]

def test_safe_executor_blocks_dangerous_commands():
    """Test that executor blocks non-whitelisted commands"""
    executor = SafeExecutor(allowed_commands=["echo", "ls"])
    
    result = executor.run_command("rm -rf /", dry_run=False)
    
    assert result["status"] == "blocked"
    assert "not allowed" in result["message"]
```

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_agent.py

# Run with coverage
pytest --cov=. --cov-report=html

# Run only tests matching pattern
pytest -k "k8s"
```

### Test Requirements

- All new features must include tests
- Maintain or improve code coverage
- Mock external API calls (don't make real API requests in tests)
- Test both success and failure cases
- Test edge cases and error conditions

---

## Pull Request Process

### PR Checklist

Before submitting, ensure:

- [ ] Code follows style guidelines
- [ ] All tests pass locally
- [ ] New tests added for new functionality
- [ ] Documentation updated (README, docstrings, etc.)
- [ ] Commit messages follow conventional commits
- [ ] PR description clearly explains changes
- [ ] Related issues are linked

### PR Template

```markdown
## Description
Brief description of changes

Fixes #(issue number)

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests pass locally

## Screenshots (if applicable)

## Additional Notes
```

### Review Process

1. **Automated Checks**: CI pipeline must pass
2. **Code Review**: At least one maintainer approval required
3. **Testing**: Changes tested in development environment
4. **Merge**: Squash and merge (unless commit history is valuable)

---

## Adding New Platforms

### Collector Plugin Template

```python
"""
collectors/my_platform.py

Collector for MyPlatform monitoring/CI/CD system.
"""

import logging
from typing import Dict, Optional, List

logger = logging.getLogger(__name__)

class MyPlatformCollector:
    """
    Collects logs and diagnostic data from MyPlatform.
    """
    
    def __init__(self, api_token: Optional[str] = None, base_url: Optional[str] = None):
        """
        Initialize MyPlatform collector.
        
        Args:
            api_token: MyPlatform API token
            base_url: Base URL of MyPlatform instance
        """
        self.api_token = api_token or os.getenv('MYPLATFORM_TOKEN')
        self.base_url = base_url or os.getenv('MYPLATFORM_URL', 'https://api.myplatform.com')
        
        if not self.api_token:
            raise ValueError("MyPlatform API token required")
        
        # Initialize API client
        self.client = MyPlatformClient(token=self.api_token, base_url=self.base_url)
    
    def collect(self, incident_data: Dict) -> Dict:
        """
        Collect logs and context for an incident.
        
        Args:
            incident_data: Dictionary containing:
                - resource_id: ID of the resource
                - timestamp: Time of incident
                - (other platform-specific fields)
        
        Returns:
            Dictionary containing:
                - logs: List of log entries
                - metadata: Platform-specific metadata
                - recent_changes: Recent deployments/changes
                - status: Current status
        """
        resource_id = incident_data.get('resource_id')
        
        logger.info(f"Collecting MyPlatform data for resource {resource_id}")
        
        try:
            # Fetch logs
            logs = self._fetch_logs(resource_id)
            
            # Fetch metadata
            metadata = self._fetch_metadata(resource_id)
            
            # Fetch recent changes
            recent_changes = self._fetch_recent_changes(resource_id)
            
            return {
                "logs": logs,
                "metadata": metadata,
                "recent_changes": recent_changes,
                "status": metadata.get("status", "unknown"),
                "timestamp": incident_data.get("timestamp"),
            }
        
        except Exception as e:
            logger.error(f"Failed to collect MyPlatform data: {e}")
            return {
                "error": str(e),
                "logs": [],
                "metadata": {},
            }
    
    def _fetch_logs(self, resource_id: str) -> List[str]:
        """Fetch logs from MyPlatform"""
        response = self.client.get_logs(resource_id)
        return response.get('logs', [])
    
    def _fetch_metadata(self, resource_id: str) -> Dict:
        """Fetch resource metadata"""
        return self.client.get_resource(resource_id)
    
    def _fetch_recent_changes(self, resource_id: str) -> List[Dict]:
        """Fetch recent changes/deployments"""
        return self.client.get_changes(resource_id, limit=5)
```

### Tool Plugin Template

```python
"""
tools/my_platform_tools.py

Tools for interacting with MyPlatform.
"""

import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

def restart_myplatform_service(
    service_id: str,
    dry_run: bool = True,
    wait_for_healthy: bool = True
) -> Dict:
    """
    Restart a service in MyPlatform.
    
    Args:
        service_id: Service identifier
        dry_run: If True, only simulate the action
        wait_for_healthy: Wait for service to become healthy
    
    Returns:
        Dictionary containing:
            - status: "success" or "failed"
            - message: Human-readable message
            - dry_run: Whether this was a dry-run
            - service_id: Service that was restarted
    """
    if dry_run:
        logger.info(f"[DRY-RUN] Would restart service {service_id}")
        return {
            "status": "success",
            "message": f"Would restart service {service_id}",
            "dry_run": True,
            "service_id": service_id,
        }
    
    logger.info(f"Restarting MyPlatform service {service_id}")
    
    try:
        client = MyPlatformClient()
        client.restart_service(service_id)
        
        if wait_for_healthy:
            status = client.wait_until_healthy(service_id, timeout=300)
            if not status:
                return {
                    "status": "failed",
                    "message": f"Service {service_id} did not become healthy",
                    "dry_run": False,
                }
        
        return {
            "status": "success",
            "message": f"Successfully restarted service {service_id}",
            "dry_run": False,
            "service_id": service_id,
        }
    
    except Exception as e:
        logger.error(f"Failed to restart service: {e}")
        return {
            "status": "failed",
            "message": f"Failed to restart: {str(e)}",
            "dry_run": False,
        }
```

### Register in Agent Core

```python
# agent/core.py

from collectors.my_platform import MyPlatformCollector
from tools.my_platform_tools import restart_myplatform_service

class DevOpsAgent:
    def __init__(self):
        # ... existing initialization ...
        
        # Register collector
        self.collectors['my_platform'] = MyPlatformCollector()
        
        # Register tool
        self.tools.append({
            "name": "restart_myplatform_service",
            "description": "Restarts a service in MyPlatform",
            "input_schema": {
                "type": "object",
                "properties": {
                    "service_id": {
                        "type": "string",
                        "description": "Service identifier"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, only simulate the action",
                        "default": True
                    }
                },
                "required": ["service_id"]
            }
        })
```

### Update Documentation

Don't forget to update:
- `README.md` - Add to supported platforms
- `MULTI_PLATFORM_GUIDE.md` - Add configuration section
- `.env.example` - Add required environment variables
- `requirements.txt` - Add any new dependencies

---

## Questions?

- **GitHub Discussions**: For general questions
- **GitHub Issues**: For bug reports and feature requests
- **Slack**: [Join our community](https://your-slack-link)

---

Thank you for contributing! 🎉
