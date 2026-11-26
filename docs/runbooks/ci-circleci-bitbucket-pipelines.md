# Runbook: CircleCI / Bitbucket Pipelines failure

> Template (#17). The agent has no CircleCI or Bitbucket Pipelines API client (tracked in #76).
> It diagnoses from the logs you send and suggests fixes; it can't retry or read builds itself.

## How incidents arrive
- Your pipeline's failure step posts to `/webhook/manual`:
  `{"type": "cicd", "platform": "<circleci|bitbucket>", "repo": "<org/repo>", "run_id": "<build number>", "raw_logs": "<last 200 lines>", "description": "<job> failed on <branch>"}`
- CircleCI: add an `on_fail` step or a webhook-to-script bridge. Bitbucket: an `after-script` that runs when `BITBUCKET_EXIT_CODE != 0`.

## Environment facts (fill in)
- Default branch and protected branches: `<main>`
- Where secrets live (CircleCI contexts / Bitbucket repository variables): `<…>`
- Docker images, caches and runners in use: `<…>`
- Owner and on-call channel: `<team, #channel>`

## Diagnosis order
1. The **first** error in `raw_logs`, not the last line. Check whether it's a dependency resolution, test, lint or deploy step.
2. Does the same job pass on the default branch? If yes, the change is the cause; if no, check the environment (images, caches, expired secrets).
3. Is it flaky (timeouts, network)? Check the job's recent history in the UI or API.
4. Secret or permission errors (`401`, `403`, `permission denied`): check for an expired token or a rotated context variable.

## Allowed actions
- `suggest_fix` with the exact diff or config change and how to verify it.
- Open a PR with the fix (`create_cicd_pr`) only for config files in this repo.
- **Never** re-run deploy jobs or change pipeline secrets: a human does that.

## Escalate when
- A credential is expired or missing, the failure is in a deploy to production, or the same job failed 3+ times on the default branch.
