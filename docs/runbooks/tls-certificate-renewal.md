# Runbook: TLS certificate expiry and renewal

> Template (#17). **certbot on servers is built in**: `renew_certificates` (dry run first, DNS-01 and
> wildcard through `CERTBOT_DNS_PLUGIN`). Use this runbook for everything else: AWS ACM, Cloudflare
> edge certificates, Kubernetes cert-manager, load-balancer certificates and appliances.

## How incidents arrive
- `probe_ssl_earliest_cert_expiry - time() < 14 * 86400` (blackbox exporter) through Alertmanager.
- cert-manager `CertificateNotReady`, or ACM `DaysToExpiry` from EventBridge to `/webhook/manual`.

## Environment facts (fill in)
- Which certificates are issued where: `<*.example.com: ACM in us-east-1 (CloudFront); api.example.com: cert-manager ClusterIssuer letsencrypt-prod>`
- DNS validation records live in: `<Route 53 zone / Cloudflare>`

## Diagnosis order
1. What's actually served: `openssl s_client -connect <host>:443 -servername <host> </dev/null | openssl x509 -noout -dates -issuer -subject`.
2. **certbot host:** use `renew_certificates` with `dry_run=true`, then follow the built-in flow.
3. **cert-manager:** `kubectl describe certificate <name> -n <ns>`, then the `CertificateRequest`, `Order` and `Challenge` objects, and the HTTP-01 or DNS-01 solver error.
4. **ACM:** `aws acm describe-certificate`. Check `RenewalSummary` and whether the DNS validation CNAME still exists.
5. Renewed but still the old certificate is served: the load balancer or CDN hasn't picked it up, or a pod needs a reload.

## Allowed actions
- `renew_certificates` (certbot, dry run first) and nginx reload through the built-in tools.
- `suggest_fix` for cert-manager, ACM and Cloudflare: the exact command or manifest change.

## Escalate when
- Less than 72h to expiry with no renewal path, or a production certificate is already expired.
