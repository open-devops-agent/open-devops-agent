"""
Webhook and Slack request signature verification.
"""
import hashlib
import hmac
import os
import time
from typing import Optional


def _signatures_equal(expected: str, provided: str) -> bool:
    """Compare signatures in constant time, failing closed on malformed input.

    ``hmac.compare_digest`` raises ``TypeError`` when a ``str`` argument holds
    non-ASCII characters (or when only one argument is a ``str``). Header values reach us
    latin-1-decoded, so an unauthenticated caller can trigger that with a
    malformed signature header. Treat anything the primitive refuses to compare
    as a mismatch instead of letting it escape as a 500.

    Only a byte-for-byte match returns ``True``: the provided signature is never
    sanitised, re-encoded lossily or truncated to make it comparable. Nothing
    about the secret leaks here either — ``compare_digest`` validates its
    arguments before comparing, so the timing of the ``TypeError`` depends only
    on the caller's own input.
    """
    try:
        return hmac.compare_digest(expected, provided)
    except TypeError:
        return False


def verify_hmac_sha256_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not secret or not signature:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return _signatures_equal(expected, signature)


def get_webhook_secret() -> str:
    return os.getenv("WEBHOOK_SECRET", "")


def verify_webhook_request(payload: bytes, signature: Optional[str]) -> bool:
    """Verify webhook using WEBHOOK_SECRET and X-Hub-Signature-256 / X-Webhook-Signature."""
    secret = get_webhook_secret()
    if not secret:
        return True
    if not signature:
        return False
    return verify_hmac_sha256_signature(payload, signature, secret)


def verify_static_webhook_token(token: Optional[str], secret: Optional[str] = None) -> bool:
    """GitLab-style shared secret (X-Gitlab-Token), compared in constant time."""
    expected = secret if secret is not None else get_webhook_secret()
    if not expected:
        return True
    if not token:
        return False
    return _signatures_equal(expected, token)


def verify_webhook_auth(
    payload: bytes,
    signature: Optional[str] = None,
    static_token: Optional[str] = None,
) -> bool:
    """Accept HMAC signature or a static token (GitLab Secret token)."""
    secret = get_webhook_secret()
    if not secret:
        return True
    if signature and verify_hmac_sha256_signature(payload, signature, secret):
        return True
    if static_token and verify_static_webhook_token(static_token, secret):
        return True
    return False


def get_slack_signing_secret() -> str:
    return os.getenv("SLACK_SIGNING_SECRET", "")


def verify_slack_signature(
    body: bytes,
    timestamp: Optional[str],
    signature: Optional[str],
    signing_secret: Optional[str] = None,
    max_age_seconds: int = 300,
) -> bool:
    secret = signing_secret or get_slack_signing_secret()
    if not secret:
        return True
    if not timestamp or not signature:
        return False
    try:
        if abs(time.time() - int(timestamp)) > max_age_seconds:
            return False
    except (TypeError, ValueError):
        return False

    try:
        decoded_body = body.decode()
    except UnicodeDecodeError:
        # Slack signs the UTF-8 request body, so a body that is not UTF-8 cannot
        # carry a signature we would accept. Fail closed rather than decoding
        # with errors="replace"/"ignore", which would change the base string —
        # and therefore the computed signature — for legitimate traffic too.
        return False

    basestring = f"v0:{timestamp}:{decoded_body}"
    expected = "v0=" + hmac.new(
        secret.encode(), basestring.encode(), hashlib.sha256
    ).hexdigest()
    return _signatures_equal(expected, signature)
