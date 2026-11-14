"""
Envelope encryption for org credentials at rest (#60).

When ENCRYPT_CREDENTIALS=true, OrgConfig stores Fernet ciphertext instead of
plaintext JSON. Key: CREDENTIALS_MASTER_KEY (url-safe base64 Fernet key) or
CREDENTIALS_MASTER_KEY_FILE.

Generate a key:
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""
from __future__ import annotations

import os
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken

ENCRYPTED_MARKER = "_encrypted"
CIPHERTEXT_KEY = "ciphertext"


def encryption_enabled() -> bool:
    return os.getenv("ENCRYPT_CREDENTIALS", "false").strip().lower() in (
        "true",
        "1",
        "yes",
    )


def _load_key() -> Optional[bytes]:
    raw = os.getenv("CREDENTIALS_MASTER_KEY", "").strip()
    if not raw:
        path = os.getenv("CREDENTIALS_MASTER_KEY_FILE", "").strip()
        if path:
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read().strip()
    if not raw:
        return None
    return raw.encode() if isinstance(raw, str) else raw


def get_fernet() -> Fernet:
    key = _load_key()
    if not key:
        raise RuntimeError(
            "ENCRYPT_CREDENTIALS is enabled but CREDENTIALS_MASTER_KEY "
            "(or CREDENTIALS_MASTER_KEY_FILE) is not set."
        )
    return Fernet(key)


def wrap_for_storage(credentials: dict) -> dict:
    """Return a storage document (plaintext or encrypted wrapper)."""
    if not encryption_enabled():
        return credentials
    token = get_fernet().encrypt(_stable_json(credentials).encode("utf-8"))
    return {ENCRYPTED_MARKER: True, CIPHERTEXT_KEY: token.decode("ascii")}


def unwrap_from_storage(data: Optional[dict]) -> dict:
    """Decrypt if needed; plaintext blobs pass through unchanged."""
    if not data:
        return {}
    if not data.get(ENCRYPTED_MARKER):
        return dict(data)
    ciphertext = data.get(CIPHERTEXT_KEY)
    if not isinstance(ciphertext, str) or not ciphertext:
        raise ValueError("Encrypted credentials blob is missing ciphertext")
    try:
        plain = get_fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError(
            "Failed to decrypt org credentials — check CREDENTIALS_MASTER_KEY"
        ) from exc
    import json

    parsed: Any = json.loads(plain)
    if not isinstance(parsed, dict):
        raise ValueError("Decrypted credentials are not a JSON object")
    return parsed


def _stable_json(credentials: dict) -> str:
    import json

    return json.dumps(credentials, sort_keys=True, separators=(",", ":"))
