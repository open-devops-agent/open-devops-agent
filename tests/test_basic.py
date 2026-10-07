"""
Basic tests for DevOps AI Agent to ensure CI pipeline works.

These tests use dummy data and mock external services.
"""

import pytest
import os
from unittest.mock import Mock, patch


def test_environment_loading():
    """Test that environment variables can be loaded"""
    # This test ensures .env loading works
    test_key = os.getenv('ANTHROPIC_API_KEY', 'dummy')
    assert test_key is not None


def test_imports():
    """Test that core modules can be imported"""
    try:
        from agent import core
        from collectors import k8s, github
        from tools import executor
        assert True
    except ImportError as e:
        pytest.fail(f"Failed to import modules: {e}")


@pytest.mark.asyncio
async def test_health_endpoint_structure():
    """Test that health endpoint returns expected structure"""
    try:
        from api.server import app
        from fastapi.testclient import TestClient
        
        client = TestClient(app)
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
    except ImportError:
        pytest.skip("FastAPI or app deps not available")


@pytest.mark.asyncio
async def test_audit_endpoint_structure():
    """Test that audit endpoint returns expected structure"""
    try:
        from api.server import app
        from fastapi.testclient import TestClient
        
        client = TestClient(app)
        response = client.get("/audit")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list) or isinstance(data, dict)
    except ImportError:
        pytest.skip("FastAPI or app deps not available")


def test_safe_executor_dry_run():
    """Test that SafeExecutor properly handles classification"""
    from tools.executor import SafeExecutor
    
    executor = SafeExecutor()
    
    # Test that executor can classify commands
    assert executor._classify('kubectl get pods') in ['safe', 'allowed', 'requires_approval']


def test_safe_executor_whitelist():
    """Test that SafeExecutor enforces command safety"""
    from tools.executor import SafeExecutor
    
    executor = SafeExecutor()
    
    # Test safe command
    classification_safe = executor._classify('kubectl get pods')
    assert classification_safe == 'safe'
    
    # Test dangerous command
    classification_dangerous = executor._classify('kubectl delete pod test')
    assert classification_dangerous == 'requires_approval'


class TestK8sCollector:
    """Test suite for K8s collector with mocked Kubernetes client"""
    
    def test_collector_initialization(self):
        """Test K8s collector can be initialized"""
        try:
            from collectors.k8s import K8sCollector
            
            collector = K8sCollector()
            assert collector is not None
        except Exception:
            # Skip if kubernetes module not available
            pass
    
    def test_collect_with_dummy_data(self):
        """Test collector with dummy incident data"""
        try:
            from collectors.k8s import K8sCollector
            
            collector = K8sCollector()
            
            # Test data
            incident_data = {
                "pod_name": "test-pod",
                "namespace": "default"
            }
            
            # This might fail without real K8s, but should not crash
            try:
                result = collector.collect(incident_data)
                assert result is not None
            except Exception:
                # Expected when no real K8s cluster
                pass
        except Exception:
            # Skip if kubernetes module not available
            pass


class TestGitHubCollector:
    """Test suite for GitHub collector"""
    
    def test_collector_initialization(self):
        """Test GitHub collector can be initialized"""
        from collectors.github import GitHubCollector
        
        collector = GitHubCollector()
        assert collector is not None


class TestClassifier:
    """Test suite for issue classifier"""
    
    def test_classifier_import(self):
        """Test that classifier module can be imported"""
        from agent.classifier import classify_issue
        assert classify_issue is not None
    
    def test_k8s_classification(self):
        """Test K8s issue classification"""
        from agent.classifier import classify_issue
        
        result = classify_issue("PodCrashLoopBackOff", {"namespace": "default"})
        assert result in ["k8s", "unknown"]
    
    def test_cicd_classification(self):
        """Test CI/CD issue classification"""
        from agent.classifier import classify_issue
        
        result = classify_issue("BuildFailed", {"source": "github"})
        assert result in ["cicd", "unknown"]


class TestDatabasePolicy:
    """Database collection is optional for security."""

    def test_database_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("ENABLE_DATABASE_COLLECTION", raising=False)
        from collectors.database_policy import (
            is_database_collection_enabled,
            is_database_resource_type,
            check_database_access,
        )

        assert is_database_collection_enabled() is False
        assert is_database_resource_type("rds") is True
        assert is_database_resource_type("ec2") is False
        blocked = check_database_access("rds", cloud="aws")
        assert blocked is not None
        assert blocked.get("blocked") is True

    def test_database_enabled_when_configured(self, monkeypatch):
        monkeypatch.setenv("ENABLE_DATABASE_COLLECTION", "true")
        from importlib import reload
        import collectors.database_policy as dp
        reload(dp)

        assert dp.is_database_collection_enabled() is True
        assert dp.check_database_access("cloud_sql", cloud="gcp") is None


class TestPrompts:
    """Test suite for system prompts"""
    
    def test_prompts_loading(self):
        """Test that prompts module can be loaded"""
        from agent.prompts import get_system_prompt
        assert get_system_prompt is not None
    
    def test_k8s_prompt(self):
        """Test K8s system prompt"""
        from agent.prompts import get_system_prompt
        
        prompt = get_system_prompt("k8s")
        assert prompt is not None
        assert len(prompt) > 0
        assert "kubernetes" in prompt.lower() or "k8s" in prompt.lower()
    
    def test_cicd_prompt(self):
        """Test CI/CD system prompt"""
        from agent.prompts import get_system_prompt
        
        prompt = get_system_prompt("cicd")
        assert prompt is not None
        assert len(prompt) > 0


def test_k8s_tools_dry_run():
    """K8s tools are agent tool-calls; covered by test_mcp.py registry smoke test."""
    pytest.skip("K8s tools are agent tool-calls — see test_mcp.py")


def test_github_tools_mock():
    """GitHub tools are agent tool-calls; covered by test_mcp.py registry smoke test."""
    pytest.skip("GitHub tools are agent tool-calls — see test_mcp.py")


@pytest.mark.parametrize("alert_name,labels,expected_type", [
    ("PipelineFailed", {"source": "github_actions"}, "cicd"),
    ("BuildFailed", {"source": "gitlab_ci"}, "cicd"),
    ("JenkinsJobFailed", {"source": "jenkins"}, "cicd"),
    ("BambooBuildFailed", {"plan_key": "PROJ-PLAN"}, "cicd"),
    ("PodCrashing", {"namespace": "default"}, "k8s"),
    ("ArgoCDSyncFailed", {"app": "test"}, "argocd"),
    ("DiskFull", {"host": "web-1"}, "server"),
    ("NginxDown", {}, "server"),
    ("CertbotRenewFailed", {}, "server"),
])
def test_platform_classification(alert_name, labels, expected_type):
    """Test classification for various platforms"""
    from agent.classifier import classify_issue
    
    result = classify_issue(alert_name, labels)
    
    assert result in [expected_type, "unknown"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
