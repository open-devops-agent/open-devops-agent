"""
Simple in-process rate limiting for webhook and credential endpoints (#64).

Configure with:
  RATE_LIMIT_ENABLED=true
  RATE_LIMIT_REQUESTS=60          # max requests
  RATE_LIMIT_WINDOW_SEC=60       # per window
  RATE_LIMIT_PATHS=/webhook,/orgs  # prefix match (comma-separated)

For multi-worker / multi-host deploys, also rate-limit at the load balancer.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Deque, Dict, Optional, Tuple


def rate_limit_enabled() -> bool:
    return os.getenv("RATE_LIMIT_ENABLED", "false").strip().lower() in (
        "true",
        "1",
        "yes",
    )


def _limits() -> Tuple[int, float]:
    try:
        max_requests = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
    except ValueError:
        max_requests = 60
    try:
        window = float(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))
    except ValueError:
        window = 60.0
    return max(1, max_requests), max(1.0, window)


def _path_prefixes() -> Tuple[str, ...]:
    raw = os.getenv("RATE_LIMIT_PATHS", "/webhook,/orgs")
    return tuple(p.strip() for p in raw.split(",") if p.strip())


def path_is_limited(path: str) -> bool:
    prefixes = _path_prefixes()
    return any(path == p or path.startswith(p.rstrip("/") + "/") or path.startswith(p) for p in prefixes)


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> Tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        max_requests, window = _limits()
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            cutoff = now - window
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= max_requests:
                retry = int(window - (now - q[0])) + 1
                return False, max(1, retry)
            q.append(now)
            return True, 0


_limiter = SlidingWindowLimiter()


def check_rate_limit(client_key: str, path: str) -> Optional[int]:
    """
    If the request should be blocked, return retry-after seconds.
    Otherwise return None.
    """
    if not rate_limit_enabled() or not path_is_limited(path):
        return None
    allowed, retry_after = _limiter.allow(f"{client_key}:{path.split('/')[1] if path.startswith('/') else path}")
    return None if allowed else retry_after
