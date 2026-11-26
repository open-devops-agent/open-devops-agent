# Runbook: DNS (Route 53 / Cloudflare)

> Template (#17). There are no DNS tools built in (tracked in #75). The agent investigates with the
> evidence you send and read-only commands, and suggests changes for a human to apply.

## How incidents arrive
- Synthetic or blackbox alerts (`probe_dns_lookup_time_seconds`, `probe_success == 0`) through Alertmanager or Grafana, labelled `category="dns"`.
- Or `/webhook/manual` with `{"type": "server", "description": "DNS: <name> fails to resolve", "raw_logs": "<dig output>"}`.

## Environment facts (fill in)
- Hosted zones and who owns them: `<example.com → Route 53 zone Z123, owned by platform>`
- Cloudflare-proxied records: `<…>`
- TTL policy and the change process (PR to `<infra repo>`, Terraform `<path>`): `<…>`

## Diagnosis order
1. `dig +short <name> @1.1.1.1` and `@8.8.8.8`, compared with the authoritative answer: `dig <name> @<ns from dig NS>`.
2. NXDOMAIN or wrong IP? Check the record in the zone (`aws route53 list-resource-record-sets` or the Cloudflare API, read-only) and recent changes (CloudTrail `ChangeResourceRecordSets`, Cloudflare audit log).
3. Correct record but stale answers: TTL or a resolver cache. Give the expected time to clear.
4. Domain expiry or a delegation problem: `whois`, and the parent zone's NS records.
5. DNSSEC failures (`SERVFAIL` only on validating resolvers): `dig +dnssec`, DS record vs DNSKEY.

## Allowed actions
- `suggest_fix` with the exact record change (Terraform diff preferred) and how to roll it back.
- **Never** change DNS records directly. A DNS mistake can take everything down at once.

## Escalate when
- Apex or NS records are involved, the domain is near expiry, or more than one zone is affected.
