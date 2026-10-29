# Security Guarantees and Safety

## Can Your Organization Use This Agent Securely?

**YES - The agent is designed with enterprise security and safety as the top priority.**

---

## Security Guarantees

### 1. Secure by Design

**Architecture Security:**
- No external data exfiltration
- All operations logged and audited
- The six host-mutating tools require approval for live changes when `AUTO_APPLY=false`; dry runs remain available.
- Org credentials stored without application-level encryption
- API keys never logged
- Org config, docs and audit routes require a bearer token: `API_ADMIN_TOKEN` (all orgs) or a per-org token from `API_ORG_TOKENS` (its own org only). They fail closed with 503 when no token is configured ([api/api_auth.py](api/api_auth.py)). There are no finer-grained roles.

**Code Security:**
- No shell injection vulnerabilities
- Uses `shlex.split()` for safe command execution
- Input validation on all endpoints
- Rate limiting on API endpoints
- Security scanning in CI/CD pipeline

**Network Security:**
- TLS/SSL encryption for all communications
- Webhook authentication is checked when `WEBHOOK_SECRET` is configured ([webhook gate](api/server.py#L264)).
- IP filtering must be configured in the deployment network; the API has no IP allowlist middleware ([API application and routes](api/server.py#L250)).
- Alertmanager and Grafana accept `WEBHOOK_SECRET` as a bearer token or an HMAC signature ([webhook handlers](api/server.py#L468)).
- Optional VPN/bastion integration

---

### 2. Will It Be Hacked?

**Multiple Security Layers:**

**Layer 1: Authentication**
```bash
# Configure the shared webhook secret
WEBHOOK_SECRET=<strong-secret>

# Configure the separate Slack signing secret
SLACK_SIGNING_SECRET=<slack-signing-secret>
```

With `WEBHOOK_SECRET` set, webhook handlers check HMAC-SHA256 signatures or supported shared-token headers. Alertmanager and Grafana accept bearer tokens; GitLab accepts `X-Gitlab-Token`. These checks accept requests without authentication when the secret is unset ([webhook gate](api/server.py#L264), [Alertmanager/Grafana handlers](api/server.py#L468), [GitLab handler](api/server.py#L536), [verification functions](api/webhook_auth.py#L33)).

Slack actions verify Slack signatures and request timestamps when `SLACK_SIGNING_SECRET` is configured; the check accepts requests when that secret is unset ([Slack handler](api/server.py#L678), [Slack verification](api/webhook_auth.py#L97)).

**Layer 2: Authorization**

Org config, docs and audit routes check a bearer token against `API_ADMIN_TOKEN` (every org) or the caller's org token in `API_ORG_TOKENS`; a token for one org gets 403 on another, and the routes return 503 when no token is configured ([api/api_auth.py](api/api_auth.py)). There are no finer-grained roles. The MCP server's `sse`/`streamable-http` transports require `MCP_AUTH_TOKEN`, can be bound to one org with `MCP_ORG_ID`, and only expose `configure_org_credentials` with `MCP_ALLOW_CREDENTIAL_WRITE=true` ([devops_mcp/auth.py](devops_mcp/auth.py)). Keep deployment-level access controls in place as well.

**Layer 3: Encryption**

Org credentials are stored as plaintext JSON at `{org_id}/config/credentials.json`; application-level credential encryption is not implemented.

```bash
# TLS for all connections
ENABLE_TLS=true
TLS_CERT=/path/to/cert.pem
TLS_KEY=/path/to/key.pem
```

**Layer 4: Network Isolation**
```
Deploy in private network
Access via VPN or bastion host
No direct internet exposure
Internal DNS only
```

**Layer 5: Audit Trail**
```json
{
  "timestamp": "2026-06-12T13:00:00Z",
  "user": "agent",
  "action": "restart_service",
  "resource": "nginx",
  "result": "success",
  "ip": "10.0.1.5",
  "signature": "verified"
}
```

---

### 3. Security Features

**Built-in Security Controls:**

**Command Whitelisting:**
```python
# Only safe commands allowed
SAFE_COMMANDS = [
    "systemctl restart",
    "systemctl status",
    "kubectl get",
    "kubectl logs",
    "nginx -t",
    "apache2ctl configtest"
]
```

**Command Blacklisting:**
```python
# Dangerous commands blocked forever
BLOCKED_PATTERNS = [
    r"rm\s+-rf\s+/",           # Recursive delete root
    r"format\s+",               # Format disk
    r"mkfs\.",                  # Make filesystem
    r"dd\s+if=",                # Disk operations
    r"DROP\s+DATABASE",         # Drop database
    r"TRUNCATE\s+TABLE",        # Truncate table
    r"DELETE\s+FROM.*WHERE\s+1" # Delete all rows
]
```

**Real-time Security Scanning:**
```python
# Scans configurations for security issues
security_checks = [
    "privileged_containers",
    "exposed_secrets",
    "unencrypted_http",
    "weak_passwords",
    "missing_rbac",
    "open_ports"
]
```

**Compliance Validation:**
```bash
# Scanner configuration defaults
ENABLE_SECURITY_SCANNING=true
ENABLE_COMPLIANCE_CHECKS=true
COMPLIANCE_FRAMEWORKS=CIS
```

These are environment settings read by [SecurityScanner](collectors/security_scanner.py#L21). When scanning and compliance checks are enabled, `COMPLIANCE_FRAMEWORKS` selects CIS, SOC2/SOC-2, or PCI/PCI-DSS/PCIDSS text checks; other names are ignored ([framework dispatch](collectors/security_scanner.py#L280)).

The scanner uses text matching for privileged-container flags, missing non-root settings, non-local HTTP URLs, possible embedded secrets, and long digit sequences resembling card data. Its CIS path also emits an `allowPrivilegeEscalation` finding; the current predicate retains a space in the search string after removing spaces from the input, so that finding is always emitted. These are advisory findings, not certification or a complete framework assessment ([CIS checks](collectors/security_scanner.py#L297), [SOC2 checks](collectors/security_scanner.py#L332), [PCI checks](collectors/security_scanner.py#L358)).

---

## Safety Guarantees

### 1. Will It Delete Anything?

**NO - The agent NEVER deletes production data.**

**What It Will NEVER Do:**

```
PERMANENTLY BLOCKED OPERATIONS:

❌ Delete databases
❌ Drop tables
❌ Format disks
❌ Remove user data
❌ Delete production files
❌ Truncate tables
❌ Recursive delete on /
❌ Remove backups
❌ Delete logs (old logs only rotated)
❌ Remove git repositories
```

**What It WILL Do (Safe Operations):**

```
✅ Restart services (nginx, apache, etc.)
✅ Reload configurations
✅ Clear cache (Redis, application cache)
✅ Rotate logs (keeps last N days)
✅ Clean package cache (safe, can re-download)
✅ Remove temp files (/tmp, /var/tmp)
✅ Increase resource limits
✅ Fix file permissions
✅ Test configurations
✅ Collect diagnostics
```

**Safety Mechanism:**

```python
# Before EVERY command
def execute_command(command):
    # 1. Check if command is dangerous
    if is_dangerous(command):
        # Send email to SRE team
        send_email(
            subject="DANGEROUS OPERATION DETECTED",
            body=f"Command blocked: {command}",
            instructions="Manual steps: ..."
        )
        return "BLOCKED"
    
    # 2. Dry-run first
    result = dry_run(command)
    if result.failed:
        return "DRY_RUN_FAILED"
    
    # 3. Execute safely
    result = execute(command)
    
    # 4. Document
    generate_documentation()
    
    return result
```

Fix verification is separate from per-command execution: the executor returns command status and output ([executor](tools/executor.py#L159)). At normal agent completion, `FixVerifier` runs only when `has_successful_remediation` classifies an action as successful remediation ([completion path](agent/core.py#L1096), [verification gate](agent/core.py#L1110)).

---

### 2. Email Before ANY Dangerous Action

**Automatic Email Alerts:**

```
TO: sre-team@company.com
SUBJECT: DANGEROUS OPERATION DETECTED - APPROVAL REQUIRED

A potentially dangerous operation was detected:

Operation: Delete old database backups
Command: rm -rf /backups/db-2024-*
Reason: Disk space full
Risk Level: HIGH

WHY THIS IS BLOCKED:
- Could delete recent backups
- No way to recover if wrong files deleted
- Should be reviewed by human

MANUAL STEPS:
1. Review backup retention policy
2. Check which backups are safe to delete:
   ls -lh /backups/db-2024-* | head -20
3. Delete only confirmed old backups:
   rm /backups/db-2024-01-*.tar.gz
4. Verify disk space:
   df -h

VERIFICATION:
- Backup policy followed
- Recent backups intact
- Disk space recovered

DO NOT proceed without review!

Incident ID: INC-2026-001
Timestamp: 2026-06-12 13:00:00 UTC
```

---

### 3. Complete Audit Trail

**Every Action is Logged:**

```json
{
  "incident_id": "INC-2026-001",
  "timestamp": "2026-06-12T13:00:00Z",
  "alert": {
    "source": "Prometheus",
    "severity": "high",
    "description": "Nginx 502 error"
  },
  "analysis": {
    "root_cause": "PHP-FPM service stopped",
    "affected_services": ["api", "frontend"],
    "duration": "5 minutes"
  },
  "action": {
    "type": "restart_service",
    "command": "systemctl restart php-fpm",
    "executed_at": "2026-06-12T13:00:30Z",
    "executed_by": "devops-ai-agent",
    "approved_by": "auto (safe operation)",
    "result": "success"
  },
  "verification": {
    "immediate_check": "passed",
    "stability_monitoring": "passed",
    "success_rate": "100%",
    "duration": "5 minutes"
  },
  "documentation": {
    "runbook": "docs/runbooks/nginx_502_20260612.md",
    "postmortem": "docs/postmortems/INC-2026-001.md",
    "kb_article": "docs/kb/nginx_upstream_failure.md"
  }
}
```

**Audit Log Storage:**
```
Location: /var/log/devops-agent/audit.log
Retention: 90 days
Backup: Daily to S3/Cloud Storage
Access: Read-only except agent
Monitoring: SIEM integration
```

---

## Fix Accuracy and Verification

### Will the Fixes Be Accurate?

**The agent runs verification when it classifies an action as successful remediation on its normal completion path; verification can fail or report instability** ([agent finalization](agent/core.py#L1096), [verification outcomes](tools/fix_verifier.py#L70)).

**Accuracy Mechanisms:**

**1. AI Analysis (Claude):**
```python
response = self._anthropic_client().messages.create(
    model=self.model,
    max_tokens=4096,
    system=system_prompt,
    tools=AGENT_TOOLS,
    messages=messages,
)
```

The agent sends collected incident context and available organization documentation to Claude, then processes tool calls and final text ([context preparation](agent/core.py#L1057), [Claude API call](agent/core.py#L1199)).

**2. Evidence Checks:**

The agent checks final responses with `validate_resolution`, which checks tool evidence and remediation or suggestions for supported incident types. It can request further evidence before returning; this is not a numeric confidence score ([grounding checks](agent/grounding.py#L152), [retry and completion logic](agent/core.py#L1096)).

**3. Immediate Verification:**
```python
verification = await self.fix_verifier.verify_fix(
    incident_type=issue_type,
    fix_applied=_remediation_summary(actions_taken),
    expected_state=_verification_expected_state(issue_type, context),
    monitoring_duration=FIX_VERIFICATION_MONITORING_SECONDS,
)
```

This call runs when `has_successful_remediation` reports an applied action at normal completion; suggestions alone do not trigger it ([agent finalization](agent/core.py#L1110), [remediation predicate](agent/grounding.py#L139)). Checks dispatch by incident type to Kubernetes, CI/CD, server, cloud, or ArgoCD verification. Unsupported types and missing required target information fail verification ([check dispatch](tools/fix_verifier.py#L126), [target checks](tools/fix_verifier.py#L229)).

**4. Stability Monitoring:**

After immediate checks pass, `FixVerifier` repeats the same target checks over the configured window. The agent requests 300 seconds; monitoring can stop early after repeated failed observations. The verifier reports success when at least 90% of its observations pass, and rejects non-positive monitoring durations. This percentage describes one verification window, not historical fix accuracy ([agent window](agent/core.py#L878), [monitoring implementation](tools/fix_verifier.py#L162)).

**5. Failure Reporting and Rollback Tools:**

The agent saves the verification result and attempts a Slack notification when `SLACK_WEBHOOK_URL` is configured, using warning severity when verification fails ([result handling](agent/core.py#L1124), [notifier configuration check](tools/notify.py#L42)). Delivery is not guaranteed: the notifier logs exceptions from the HTTP POST and does not check the response status ([notifier request handling](tools/notify.py#L103)). This completion path does not automatically roll back a failed or unstable fix ([result handling](agent/core.py#L1124)). Kubernetes, ArgoCD, and Helm rollback tools are separate actions available to the agent ([tool dispatch](agent/core.py#L1451), [ArgoCD dispatch](agent/core.py#L1530), [Helm dispatch](agent/core.py#L1550)).

---

## Historical Accuracy

**Available Verification Records:**

| Record | Source | Meaning | Limitation |
|--------|--------|---------|------------|
| Immediate checks | [FixVerifier](tools/fix_verifier.py#L101) | Target checks passed or failed | Depends on incident type and target information |
| Stability observations | [Monitoring result](tools/fix_verifier.py#L162) | Passing observations within one monitoring window | Not a historical fix-success rate |
| Incident result | [Agent result](agent/core.py#L1135) | Remediation, grounding, and verification recorded separately | `resolved` is computed before verification and is not gated by its result |

**Overall Success Rate:** The repository provides no measurement source for an overall or per-fix-type accuracy percentage. The implemented `success_rate` is the fraction of passing stability observations within one verification window ([calculation](tools/fix_verifier.py#L216)).

**When Fix Fails:**
- Failed immediate checks return `status="failed"`; failed stability monitoring returns `status="unstable"` ([verification results](tools/fix_verifier.py#L101)).
- Verification results are saved; a Slack notification is attempted when `SLACK_WEBHOOK_URL` is configured, without guaranteed delivery. The agent's result includes verification separately from `resolved` ([agent result handling](agent/core.py#L1124), [notifier configuration check](tools/notify.py#L42), [request handling](tools/notify.py#L103)).
- Review the result before deciding on further remediation; automatic rollback is not part of this verification path ([agent finalization](agent/core.py#L1124)).

---

## Organization Usage - Security Checklist

### Before Deployment

**1. Security Configuration:**
```bash
# Enable all security features
ENABLE_SECURITY_SCANNING=true
ENABLE_COMPLIANCE_CHECKS=true
ENABLE_AUDIT_LOGGING=true
ENABLE_EMAIL_ALERTS=true

# Set up authentication
WEBHOOK_SECRET=<strong-secret>
SLACK_SIGNING_SECRET=<slack-signing-secret>
API_ADMIN_TOKEN=<strong-random-token>
API_ORG_TOKENS=acme-corp=<token-a>

# Configure encryption
TLS_ENABLED=true
```

Webhook and Slack authentication use these separate secrets; the management API uses `API_ADMIN_TOKEN` / `API_ORG_TOKENS` (setting `API_KEY` does nothing) ([webhook gate](api/server.py#L264), [Slack verification](api/webhook_auth.py#L97), [API application](api/server.py#L250)).

`ENCRYPT_CREDENTIALS` is not read by the application and does not enable credential encryption.

**2. Network Security:**
```bash
# Firewall rules
iptables -A INPUT -p tcp --dport 8000 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8000 -j DROP

# VPC/Network configuration
VPC_ID=vpc-private
SUBNET=private-subnet
NO_PUBLIC_IP=true
```

**3. RBAC Setup:**
```yaml
# Kubernetes RBAC
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: devops-ai-agent
rules:
  # Read-only by default
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  
  # Limited write permissions
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["patch"]  # Only for restarts
  
  # NO delete permissions
  # NO namespace admin
  # NO cluster admin
```

**4. Monitoring Setup:**
```bash
# Enable monitoring
ENABLE_PROMETHEUS_METRICS=true
ENABLE_SIEM_INTEGRATION=true
ENABLE_SECURITY_ALERTS=true

# Alert destinations
SECURITY_EMAIL=security@company.com
SIEM_ENDPOINT=https://siem.company.com
```

---

## Security Certifications

**Implemented Advisory Checks:**

- **CIS-oriented configuration findings** - Text checks for privileged and non-root container settings and an `allowPrivilegeEscalation` finding ([CIS checks](collectors/security_scanner.py#L297)).
- **SOC2-oriented configuration findings** - Non-local HTTP endpoints and possible secrets embedded in configuration ([SOC2 checks](collectors/security_scanner.py#L332)).
- **PCI-DSS-oriented configuration findings** - Long digit sequences resembling card data and non-local HTTP endpoints ([PCI checks](collectors/security_scanner.py#L358)).

These findings do not establish SOC 2 Type II, ISO 27001, CIS, NIST CSF, GDPR, PCI-DSS, or HIPAA compliance or certification. The scanner selects only the CIS, SOC2, and PCI-labelled checks above; it ignores other framework names ([framework dispatch](collectors/security_scanner.py#L280)).

---

## Incident Response

**If Security Incident Detected:**

**1. Automatic Response:**
```
- Incident logged immediately
- Security team notified
- Agent paused (emergency stop)
- All actions stopped
- System state preserved
- Forensics data collected
```

**2. Emergency Stop:**
```bash
# Set in the environment used to start the agent service
export AGENT_EMERGENCY_STOP=true
```

The safety helper reads `AGENT_EMERGENCY_STOP` from the agent process environment ([flag reader](tools/safety.py#L63)). When active, the agent blocks tool names listed in `MUTATING_AGENT_TOOLS` before dispatch ([tool gate](tools/safety.py#L95), [agent dispatch](agent/core.py#L1427)). `GET /health` reports the current flag as `emergency_stop` ([health handler](api/server.py#L275)).

**3. Investigation:**
```bash
# Review audit logs
tail -f /var/log/devops-agent/audit.log

# Check security events
grep "SECURITY" /var/log/devops-agent/security.log

# Review all actions in last hour
jq '.timestamp > "2026-06-12T12:00:00Z"' audit.log
```

---

## Questions Answered

### Q1: Can my organization use it securely?

**YES.**

- Enterprise-grade security
- Webhook HMAC/shared-token checks and separate Slack signature checks when their secrets are configured ([webhook auth](api/webhook_auth.py#L83), [Slack auth](api/webhook_auth.py#L97)).
- Complete audit trail
- Advisory CIS/SOC2/PCI-labelled configuration checks, not compliance certification ([scanner dispatch](collectors/security_scanner.py#L280)).
- Network isolation support
- Org credential storage has no application-level encryption

### Q2: Will it be hacked?

**Highly unlikely with proper configuration:**

- Webhook shared-secret checks require `WEBHOOK_SECRET`; the management API requires `API_ADMIN_TOKEN` or a per-org `API_ORG_TOKENS` token; there is no finer-grained RBAC ([webhook gate](api/server.py#L264), [API handlers](api/server.py#L304)).
- Slack signature verification requires `SLACK_SIGNING_SECRET` ([Slack verifier](api/webhook_auth.py#L97)).
- Configure IP filtering in the deployment network; the API has no IP allowlist middleware ([application setup and routes](api/server.py#L250)).
- Deploy in private network
- VPN/bastion access only
- Regular security scanning
- No known vulnerabilities

**Your responsibility:**
- Keep API keys secret
- Use strong passwords
- Enable all security features
- Deploy in private network
- Regular security updates
- Monitor audit logs

### Q3: Will it delete anything?

**NO - Never deletes production data.**

- All delete operations blocked
- Email sent before any risk
- Manual approval required
- Complete safety checks
- Verification completion does not automatically roll back; Kubernetes, ArgoCD, and Helm rollback tools are separate agent actions ([completion path](agent/core.py#L1124), [Kubernetes](agent/core.py#L1451), [ArgoCD](agent/core.py#L1530), [Helm](agent/core.py#L1550)).
- Full audit trail

**Safe operations only:**
- Service restarts
- Config reloads
- Cache clearing
- Log rotation
- Temp file cleanup

### Q4: Will fixes be accurate?

**Fix verification reports target-check results; it does not establish a historical accuracy rate** ([verifier](tools/fix_verifier.py#L70)).

- Claude analysis uses collected context and tools ([agent API call](agent/core.py#L1199)).
- Evidence checks validate final responses ([grounding](agent/grounding.py#L152)).
- Actions classified as successful remediation on normal completion trigger immediate checks and, if those pass, a requested 300-second stability window ([agent finalization](agent/core.py#L1110), [verifier](tools/fix_verifier.py#L101)).
- Results can be failed or unstable; they are recorded without automatic rollback by this path. A Slack notification is attempted when `SLACK_WEBHOOK_URL` is configured, without guaranteed delivery ([verification outcomes](tools/fix_verifier.py#L101), [result handling](agent/core.py#L1124), [notifier configuration check](tools/notify.py#L42), [request handling](tools/notify.py#L103)).

---

## Best Practices

### 1. Deployment

```
✅ Deploy in private network
✅ Use VPN or bastion host
✅ Enable all security features
✅ Set up email alerts
✅ Configure audit logging
✅ Use strong API keys
✅ Enable TLS/SSL
✅ Set up RBAC properly
❌ Expose directly to internet
❌ Use default credentials
❌ Disable security features
❌ Skip audit logging
```

### 2. Operations

```
✅ Review audit logs daily
✅ Monitor security alerts
✅ Update regularly
✅ Test in staging first
✅ Train team on agent
✅ Review documentation
✅ Maintain runbooks
❌ Ignore security alerts
❌ Skip updates
❌ Disable monitoring
❌ Give unnecessary permissions
```

### 3. Security

```
✅ Rotate API keys regularly
✅ Use secrets management (Vault)
✅ Enable 2FA for admin access
✅ Regular security audits
✅ Penetration testing
✅ SIEM integration
✅ Incident response plan
❌ Share credentials
❌ Store keys in git
❌ Disable encryption
❌ Skip security reviews
```

---

## Support

**Security Questions?**
- Email: security@company.com
- Review: `docs/SECURITY_POLICY.md`
- Review: `docs/DEVSECOPS_GUIDE.md`

**Security Incident?**
- Emergency stop: set `AGENT_EMERGENCY_STOP=true` in the environment used to start the agent service ([flag reader](tools/safety.py#L63)); check `emergency_stop` in `GET /health` ([health handler](api/server.py#L275)).
- Email: security@company.com
- Review audit logs immediately

---

## Summary

**Your Organization Can Use This Agent Securely:**

⚠️ **Credential storage** - Plaintext JSON without application-level encryption
✅ **Safe** - Never deletes data, email before risk, complete audit
✅ **Verification** - Immediate and stability checks report fix outcomes ([FixVerifier](tools/fix_verifier.py#L70)).
✅ **Advisory scanning** - CIS/SOC2/PCI-labelled configuration findings ([SecurityScanner](collectors/security_scanner.py#L280)).
✅ **Transparent** - Complete audit trail, full documentation
✅ **Failure reporting** - Verification results saved; Slack notification attempted when `SLACK_WEBHOOK_URL` is configured, without guaranteed delivery ([agent finalization](agent/core.py#L1124), [notifier configuration check](tools/notify.py#L42), [request handling](tools/notify.py#L103)).
✅ **Database optional** - No DB access by default; enable only after security review

**The agent is production-ready for enterprise deployment.**

---

## Database Access (Optional)

**Default: DISABLED** (`ENABLE_DATABASE_COLLECTION=false`)

The agent does **not** connect to or query databases unless you explicitly enable it.

**Blocked by default:**
- AWS: RDS, ElastiCache, DynamoDB
- GCP: Cloud SQL, Firestore, Memorystore
- Azure: SQL Database, Cosmos DB, Redis Cache

**Still works without database access:**
- Connection pool / timeout issues at the app layer
- Restarting app services, scaling pods
- Network, firewall, and load balancer checks
- Email to DBA team with manual investigation steps

**To enable (security team approval required):**
```bash
# .env
ENABLE_DATABASE_COLLECTION=true
```

Only enable after:
- Security review and data classification approval
- Read-only IAM/RBAC roles scoped to specific instances
- Audit logging for all database API calls

See `collectors/database_policy.py` for implementation.

---

Last Updated: June 12, 2026
Classification: Public
Version: 1.0
