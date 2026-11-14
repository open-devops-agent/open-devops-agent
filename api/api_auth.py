"""
Bearer-token authorization for the management API (org config, docs, audit).

- ``API_ADMIN_TOKEN``: platform operator token, valid for every org (role=admin).
- ``API_ORG_TOKENS``: per-org tokens:
    ``org-a=token-a``                 → admin for org-a (backward compatible)
    ``org-a:viewer=token-v``          → viewer
    ``org-a:approver=token-p``        → approver
    ``org-a:admin=token-a``           → admin
- Fails closed: with neither configured, protected routes return 503 unless
  ``API_AUTH_DISABLED=true`` is set explicitly (local development only).

Role hierarchy: admin > approver > viewer.

Webhooks keep their own signature checks (``api.webhook_auth``) and ``/health``
stays open for liveness probes.
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

from fastapi import HTTPException

from api.webhook_auth import _signatures_equal, bearer_token

ROLE_RANK = {"viewer": 1, "approver": 2, "admin": 3}
VALID_ROLES = frozenset(ROLE_RANK)


def api_auth_disabled() -> bool:
    return os.getenv("API_AUTH_DISABLED", "false").strip().lower() in ("true", "1", "yes")


def _admin_token() -> str:
    return os.getenv("API_ADMIN_TOKEN", "").strip()


def _parse_org_token_entry(pair: str) -> Optional[Tuple[str, str, str]]:
    """Return (org_id, role, token) or None."""
    left, sep, token = pair.partition("=")
    if not sep or not left.strip() or not token.strip():
        return None
    org_part = left.strip()
    if ":" in org_part:
        org_id, role = org_part.rsplit(":", 1)
        org_id, role = org_id.strip(), role.strip().lower()
        if role not in VALID_ROLES:
            return None
        if not org_id:
            return None
        return org_id, role, token.strip()
    return org_part, "admin", token.strip()


def _org_token_entries() -> List[Tuple[str, str, str]]:
    """Parse API_ORG_TOKENS into (org, role, token) triples."""
    entries: List[Tuple[str, str, str]] = []
    for pair in os.getenv("API_ORG_TOKENS", "").split(","):
        parsed = _parse_org_token_entry(pair)
        if parsed:
            entries.append(parsed)
    return entries


def _org_tokens() -> Dict[str, str]:
    """Backward-compatible map org → first admin token (tests / status)."""
    tokens: Dict[str, str] = {}
    for org, role, token in _org_token_entries():
        if role == "admin" and org not in tokens:
            tokens[org] = token
    return tokens


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"}
    )


def _role_sufficient(have: str, need: str) -> bool:
    return ROLE_RANK.get(have, 0) >= ROLE_RANK.get(need, 99)


def resolve_access(
    org_id: str, authorization: Optional[str]
) -> Optional[Tuple[str, str]]:
    """
    Return (scope, role) where scope is ``admin`` or the org_id.
    None if unauthenticated / disabled path handled by caller.
    """
    if api_auth_disabled():
        return ("*", "admin")

    admin = _admin_token()
    entries = _org_token_entries()
    if not admin and not entries:
        raise HTTPException(
            status_code=503,
            detail=(
                "API authentication is not configured. Set API_ADMIN_TOKEN or "
                "API_ORG_TOKENS (or API_AUTH_DISABLED=true for local development)."
            ),
        )

    token = bearer_token(authorization)
    if not token:
        raise _unauthorized("Bearer token required")

    if admin and _signatures_equal(admin, token):
        return ("*", "admin")

    matched = [
        (org, role)
        for org, role, expected in entries
        if _signatures_equal(expected, token)
    ]
    for org, role in matched:
        if org == org_id:
            return (org, role)
    if matched:
        raise HTTPException(
            status_code=403, detail="Token is not valid for this organization"
        )
    raise _unauthorized("Invalid token")


def require_org_access(
    org_id: str,
    authorization: Optional[str],
    min_role: str = "viewer",
) -> str:
    """Allow the request when the token covers ``org_id`` with at least ``min_role``.

    Returns the granted role name.
    Raises 503 when no tokens are configured, 401 for a missing or unknown
    token, 403 for wrong org or insufficient role.
    """
    need = (min_role or "viewer").lower()
    if need not in VALID_ROLES:
        need = "viewer"

    access = resolve_access(org_id, authorization)
    assert access is not None
    _scope, role = access
    if not _role_sufficient(role, need):
        raise HTTPException(
            status_code=403,
            detail=f"Role '{role}' is insufficient; requires '{need}' or higher",
        )
    return role
