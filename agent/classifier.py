"""
Issue type classifier — maps alert names and labels to issue types.
Supports multiple CI/CD platforms, cloud providers, and ArgoCD.
"""


def classify_issue(alertname: str, labels: dict) -> str:
    """
    Classify incident type based on alert name and labels.
    
    Returns:
        - k8s: Kubernetes/container issues
        - cicd: CI/CD pipeline issues (GitHub, GitLab, Jenkins, Bamboo, Azure DevOps)
        - server: Server/VM issues
        - cloud_aws: AWS resource issues
        - cloud_gcp: GCP resource issues
        - cloud_azure: Azure resource issues
        - argocd: ArgoCD deployment issues
        - helm: Helm chart/release issues
        - terraform: Terraform/IaC drift and validation (read-only)
        - observability: SLO, metrics, traces, synthetics, on-call, status page
        - data: databases, snapshots/DR, Kafka, Elasticsearch, Redis
        - code_review: pull/merge request review on GitHub/GitLab/Bitbucket/Azure/local git
    """
    name = alertname.lower()

    # CI/CD specific keywords (check first to avoid conflicts with k8s "deployment")
    cicd_keywords = ["pipeline", "build", "ci", "release", "workflow", "job",
                     "jenkins", "gitlab", "bamboo", "azure-pipeline", "github-actions",
                     "buildfailed", "pipelinefailed", "pipelineerror", "deploymentfailed"]
    
    k8s_keywords = ["pod", "container", "crash", "oom", "image", "evict",
                    "pending", "replicaset", "statefulset", "daemonset",
                    "nodepool", "crashloop"]
    
    server_keywords = [
        "cpu", "memory", "disk", "diskfull", "inode", "load", "nginx", "apache",
        "service", "host", "node", "network", "ssh", "systemd", "journal",
        "certbot", "letsencrypt", "wildcard", "certificate", "ssl", "filesystem",
    ]
    
    argocd_keywords = ["argocd", "argo", "gitops", "sync"]

    helm_keywords = ["helm", "chart", "helmrelease", "release failed"]

    terraform_keywords = ["terraform", "tfstate", "tf plan", "iac drift", "infrastructure drift"]

    observability_keywords = [
        "slo", "errorbudget", "error-budget", "error budget", "apdex", "prometheus",
        "grafana", "datadog", "newrelic", "new relic", "synthetic", "blackbox",
        "jaeger", "tempo", "traceid", "oncall", "on-call", "statuspage", "status page",
        "latency", "p99", "burnrate", "burn-rate",
    ]

    data_keywords = [
        "kafka", "elasticsearch", "opensearch", "consumerlag", "consumer-lag",
        "snapshot", "backup", "restore", "failover", "wal", "replication slot",
    ]

    code_review_keywords = [
        "code review", "codereview", "pull_request", "pull request", "merge_request",
        "merge request", "pr opened", "pr updated", "mr opened", "bitbucket pr",
    ]
    
    aws_keywords = [
        "ec2", "ecs", "eks", "fargate", "lambda", "rds", "aws", "cloudwatch",
        "elb", "alb", "ecr", "elasticache", "dynamodb", "sqs", "sns", "s3",
        "autoscaling", "elasticbeanstalk", "apprunner", "batch",
    ]

    gcp_keywords = [
        "gce", "gke", "cloud-run", "cloud-function", "gcp", "google-cloud",
        "compute-engine", "artifact-registry", "cloud-sql", "memorystore",
        "pubsub", "cloud-storage", "load-balancer", "cloud-composer",
    ]

    azure_keywords = [
        "azure-vm", "aks", "app-service", "azure-function", "azure-sql",
        "aci", "container-instance", "container-apps", "acr", "vmss",
        "cosmosdb", "redis", "application-gateway", "service-bus",
    ]

    # Check ArgoCD / Helm / Terraform (specific GitOps & IaC)
    if any(k in name for k in argocd_keywords):
        return "argocd"
    if any(k in name for k in helm_keywords):
        return "helm"
    if any(k in name for k in terraform_keywords):
        return "terraform"
    if any(k in name for k in observability_keywords):
        return "observability"
    if any(k in name for k in data_keywords):
        return "data"
    if any(k in name for k in code_review_keywords):
        return "code_review"
    
    # Check CI/CD before K8s (to catch "deployment" in CICD context)
    if any(k in name for k in cicd_keywords):
        return "cicd"
    
    # Check cloud providers
    if any(k in name for k in aws_keywords):
        return "cloud_aws"
    if any(k in name for k in gcp_keywords):
        return "cloud_gcp"
    if any(k in name for k in azure_keywords):
        return "cloud_azure"
    
    # Check K8s
    if any(k in name for k in k8s_keywords):
        return "k8s"
    
    # Check server
    if any(k in name for k in server_keywords):
        return "server"

    # Fallback: check labels
    if labels.get("namespace") or labels.get("pod"):
        return "k8s"
    if labels.get("cluster") and labels.get("cloud_provider"):
        cloud = labels["cloud_provider"].lower()
        if cloud in ("aws", "eks"):
            return "cloud_aws"
        if cloud in ("gcp", "gke", "google"):
            return "cloud_gcp"
        if cloud in ("azure", "aks"):
            return "cloud_azure"
    if labels.get("pipeline") or labels.get("job"):
        return "cicd"
    if labels.get("argocd_app"):
        return "argocd"
    if labels.get("helm_release") or labels.get("chart"):
        return "helm"
    if labels.get("terraform_workspace") or labels.get("tf_workspace"):
        return "terraform"
    if labels.get("slo") or labels.get("prometheus") or labels.get("statuspage"):
        return "observability"
    if labels.get("kafka") or labels.get("elasticsearch") or labels.get("snapshot_id"):
        return "data"
    if (
        labels.get("pull_request")
        or labels.get("merge_request")
        or labels.get("pr_number")
        or labels.get("mr_iid")
        or labels.get("code_review")
    ):
        return "code_review"
    if labels.get("cloud_provider"):
        cloud = labels["cloud_provider"].lower()
        if "aws" in cloud:
            return "cloud_aws"
        elif "gcp" in cloud or "google" in cloud:
            return "cloud_gcp"
        elif "azure" in cloud:
            return "cloud_azure"

    return "server"


def get_cicd_platform(labels: dict, context: dict) -> str:
    """
    Determine the specific CI/CD platform from labels and context.
    
    Returns: 'github', 'gitlab', 'jenkins', 'bamboo', 'azure_devops', or 'unknown'
    """
    # Check labels first
    if labels.get("cicd_platform"):
        return labels["cicd_platform"].lower()
    
    # Check context/source
    source = context.get("source", "").lower()
    if "github" in source:
        return "github"
    elif "gitlab" in source:
        return "gitlab"
    elif "jenkins" in source:
        return "jenkins"
    elif "bamboo" in source:
        return "bamboo"
    elif "azure" in source or "azuredevops" in source:
        return "azure_devops"
    
    # Check repo or job URL
    repo_url = context.get("repo", "") or labels.get("repo_url", "")
    if "github.com" in repo_url:
        return "github"
    elif "gitlab" in repo_url:
        return "gitlab"
    if "bamboo" in repo_url or labels.get("plan_key") or context.get("plan_key"):
        return "bamboo"

    return "unknown"
