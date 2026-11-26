# Runbook templates

Templates for incident types the agent has **no built-in collector or tool** for (see the
[platform coverage status](../PLATFORM_SUPPORT.md#coverage-status)). Fill in the `<…>` placeholders
for your environment and upload them as org docs. The agent then reads them on every incident for
that org:

```bash
curl -X POST "https://agent.example.com/orgs/acme/docs/upload?path=runbooks/dns.md" \
  -H "Authorization: Bearer $ACME_ADMIN_TOKEN" -F "file=@dns-route53-cloudflare.md"
```

| Template | For |
|---|---|
| [ci-circleci-bitbucket-pipelines.md](ci-circleci-bitbucket-pipelines.md) | CircleCI and Bitbucket Pipelines failures |
| [dns-route53-cloudflare.md](dns-route53-cloudflare.md) | DNS resolution, propagation and record errors |
| [tls-certificate-renewal.md](tls-certificate-renewal.md) | Certificates the built-in `renew_certificates` tool can't handle (ACM, Cloudflare, cert-manager) |
| [vault-secret-rotation.md](vault-secret-rotation.md) | Vault / secrets-manager rotation and expired credentials |

Then send incidents for these with `POST /webhook/manual` (`type` plus `raw_logs` and `description`),
or route their alerts through Alertmanager, Grafana or PagerDuty. Each template ends with the
checklist the agent uses to decide between `suggest_fix` and escalation. Uploaded runbooks are
instructions to the agent, so keep them in reviewed source control and only upload from there.
