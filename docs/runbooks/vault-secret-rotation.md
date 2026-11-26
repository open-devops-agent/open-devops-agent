# Runbook: Vault / secrets rotation and expired credentials

> Template (#17). There's no Vault integration (tracked in #77). The agent recognises credential
> failures in logs and guides rotation; it never reads or writes secret values. For **the agent's
> own** org credentials, see [Credential rotation](../CREDENTIAL_ROTATION.md).

## How incidents arrive
- App errors such as `permission denied`, `invalid token`, `lease expired`, `403 from vault` through logs or Loki alerts.
- Vault telemetry alerts (`vault.expire.num_leases`, token TTL) through Alertmanager.
- `/webhook/manual` with `{"type": "server", "description": "Vault lease expired for <app>", "raw_logs": "…"}`.

## Environment facts (fill in)
- Vault address, auth methods per app (Kubernetes auth role `<…>`, AppRole `<…>`): `<…>`
- Dynamic vs static secrets per app; rotation owners: `<…>`
- Other stores (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault): `<…>`

## Diagnosis order
1. Which identity failed, and when it last worked (first error timestamp).
2. Dynamic secret: has the lease expired, or did the app stop renewing it? Check the Vault agent or sidecar logs, and the pod restart history.
3. Static secret: was it rotated recently without the app being restarted or reloaded? Check the rotation job and the secret version timestamps (metadata only).
4. Auth broken for everything? Check whether the Vault seal status, auth method or Kubernetes service account token reviewer changed.

## Allowed actions
- Read-only checks. `suggest_fix` with the exact rotation or restart steps.
- **Never** read secret values. Approval-gated reads redact them anyway (#191).
- If a credential leaked, use the containment tools (`disable_access_key`) through approval, and see the leak response in the credential rotation guide.

## Escalate when
- Production auth is failing for more than one app, Vault is sealed, or a leak is suspected.
