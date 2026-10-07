"""
Classify filesystem paths before any cleanup.

Protected / production / in-use paths are never deleted. The agent must alert
instead of guessing.
"""
from __future__ import annotations

import os
from pathlib import PurePosixPath

PROTECTED_PREFIXES = (
    "/etc",
    "/home",
    "/root",
    "/boot",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/opt",
    "/srv",
    "/data",
    "/mnt",
    "/media",
    "/var/www",
    "/var/lib/mysql",
    "/var/lib/postgresql",
    "/var/lib/pgsql",
    "/var/lib/mongodb",
    "/var/lib/redis",
    "/var/lib/docker/volumes",
    "/var/lib/kubelet",
    "/var/lib/rancher",
    "/var/lib/containerd",
    "/var/lib/etcd",
    "/app",
    "/apps",
    "/prod",
    "/production",
)

PROTECTED_NAME_MARKERS = (
    ".env",
    "id_rsa",
    "id_ed25519",
    ".pem",
    ".key",
    "credentials",
    "secrets",
    "prod",
    "production",
    "customer",
    "backup.sql",
    "dump.sql",
    "wal",
)

# Rotated / compressed logs under /var/log are the only files cleanup may delete.
SAFE_LOG_SUFFIXES = (".gz", ".xz", ".bz2", ".1", ".old", ".rotated")


def extra_protected_prefixes() -> tuple[str, ...]:
    raw = os.getenv("CLEANUP_PROTECTED_PATHS", "")
    extras = [p.strip() for p in raw.split(",") if p.strip()]
    return tuple(extras)


def normalize_path(path: str) -> str:
    cleaned = (path or "").strip()
    if not cleaned:
        return ""
    posix = PurePosixPath(cleaned)
    if posix.is_absolute():
        resolved = posix
    else:
        resolved = PurePosixPath("/") / posix
    parts = []
    for part in resolved.parts:
        if part == "..":
            if parts:
                parts.pop()
            continue
        if part in (".",):
            continue
        parts.append(part)
    if not parts:
        return "/"
    return str(PurePosixPath(*parts)) if parts[0] == "/" else "/" + str(PurePosixPath(*parts))


def _is_under(path: str, prefix: str) -> bool:
    path = path.rstrip("/") or "/"
    prefix = prefix.rstrip("/") or "/"
    return path == prefix or path.startswith(prefix + "/")


def is_protected_path(path: str) -> bool:
    """True when the path is production, in-use, or otherwise must not be deleted."""
    normalized = normalize_path(path)
    if not normalized or normalized == "/":
        return True
    for prefix in PROTECTED_PREFIXES + extra_protected_prefixes():
        if _is_under(normalized, prefix):
            return True
    lower = normalized.lower()
    name = PurePosixPath(normalized).name.lower()
    if any(marker in name or marker in lower for marker in PROTECTED_NAME_MARKERS):
        return True
    return False


def is_safe_stale_log(path: str) -> bool:
    """Rotated/compressed logs under /var/log only — never live app or prod files."""
    normalized = normalize_path(path)
    if not normalized.startswith("/var/log/") and normalized != "/var/log":
        return False
    if is_protected_path(normalized):
        return False
    name = PurePosixPath(normalized).name
    return name.endswith(SAFE_LOG_SUFFIXES)


def classify_cleanup_target(path: str) -> dict:
    """
    Return a classification for a candidate delete path.

    status:
      - safe: rotated stale log under /var/log
      - protected: must not delete; alert instead
      - rejected: not a recognized cleanup target
    """
    normalized = normalize_path(path)
    if not normalized:
        return {"path": path, "status": "rejected", "reason": "empty path"}
    if is_protected_path(normalized):
        return {
            "path": normalized,
            "status": "protected",
            "reason": "production, in-use, or sensitive path — will not delete",
            "alert": True,
        }
    if is_safe_stale_log(normalized):
        return {
            "path": normalized,
            "status": "safe",
            "reason": "rotated/compressed log under /var/log",
            "alert": False,
        }
    return {
        "path": normalized,
        "status": "rejected",
        "reason": "not a rotated log under /var/log — refuse to delete unknown data",
        "alert": True,
    }
