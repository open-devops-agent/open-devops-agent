# Security Policy

Open DevOps Agent runs with access to clusters, CI systems, cloud accounts and
chat. We take vulnerabilities in it seriously and appreciate responsible
disclosure.

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a
vulnerability.**

Report it privately through GitHub:
**[Report a vulnerability](https://github.com/open-devops-agent/open-devops-agent/security/advisories/new)**
(Security tab → Advisories → "Report a vulnerability").

Please include:

- the affected component (API, webhook, MCP server, edge middleware, a tool, CI)
  and commit or version
- steps to reproduce or a proof of concept
- the impact you think it has (for example credential exposure, cross-tenant
  access, command execution, approval bypass)
- any configuration it depends on (`AUTO_APPLY`, auth tokens, transports)

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment and severity | within 7 days |
| Fix or mitigation for high/critical issues | as fast as possible, usually within 30 days |
| Public advisory | after a fix is released, crediting you unless you prefer otherwise |

We will keep you updated through the advisory thread and may ask you to verify
the fix.

## Scope

In scope: everything in this repository, including the API server, webhook
handlers, MCP server, edge middleware (`middleware/`), agent tools, Docker
images built from this repo, and CI workflows.

Especially interesting: authentication or authorization bypass, cross-org
(tenant) data or credential access, approval or `AUTO_APPLY` bypass, command or
shell injection, SSRF, prompt injection that leads to a tool action, and secret
leakage in logs, reports or audit records.

Out of scope: vulnerabilities in third-party services we integrate with (report
those to the vendor), issues that require an already-compromised host or admin
token, missing hardening on a deployment you control (for example exposing the
API without TLS), and denial of service through volumetric traffic.

## Supported versions

Security fixes go to the `main` branch. Please reproduce against current
`main` before reporting.

## Safe harbor

We will not pursue action against good-faith research that follows this
policy, avoids privacy violations and service disruption, and gives us
reasonable time to fix the issue before disclosure. Test only against your own
deployments.

## Related

- How the agent limits what it can do: [SECURITY_GUARANTEES.md](SECURITY_GUARANTEES.md)
- Operational safety rules: [docs/SECURITY_POLICY.md](docs/SECURITY_POLICY.md)
