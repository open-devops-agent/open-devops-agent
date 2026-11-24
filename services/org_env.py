"""
Context-local view of os.environ for per-org credentials (#63).

An org's credentials used to be written into the process-wide os.environ for
the duration of a request, so a concurrent request for another org could read
them. Instead, the credentials are held in a ContextVar overlay: each asyncio
task (and each thread started with asyncio.to_thread / contextvars.copy_context)
sees only the overlay of the org scope it runs in.

os.environ itself is switched to a subclass whose reads consult the overlay
first, so every existing ``os.getenv("GITHUB_TOKEN")`` call, and libraries that
read the environment (boto3, the Kubernetes client), resolve to the current
org's value with no change at the call site. Writes still go to the real
process environment. Child processes do not see the overlay automatically:
pass ``env=subprocess_env()`` when starting them.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Dict, Generator, Iterator, Mapping, Optional

_overlay: ContextVar[Optional[Dict[str, str]]] = ContextVar("org_env_overlay", default=None)

_BaseEnviron = type(os.environ)


class OrgScopedEnviron(_BaseEnviron):  # type: ignore[misc, valid-type]
    """os.environ whose reads see the current org's credential overlay."""

    def __getitem__(self, key: str) -> str:
        layer = _overlay.get()
        if layer is not None and key in layer:
            return layer[key]
        return super().__getitem__(key)

    def __contains__(self, key: object) -> bool:
        layer = _overlay.get()
        if layer is not None and key in layer:
            return True
        return super().__contains__(key)

    def __iter__(self) -> Iterator[str]:
        layer = _overlay.get()
        seen = set()
        for key in super().__iter__():
            seen.add(key)
            yield key
        if layer:
            for key in layer:
                if key not in seen:
                    yield key

    def __len__(self) -> int:
        layer = _overlay.get()
        if not layer:
            return super().__len__()
        return sum(1 for _ in self)

    def copy(self) -> Dict[str, str]:
        return dict(self)


def install() -> None:
    """Make os.environ overlay-aware (idempotent; keeps the same object)."""
    if not isinstance(os.environ, OrgScopedEnviron):
        os.environ.__class__ = OrgScopedEnviron


@contextmanager
def env_overlay(values: Mapping[str, object]) -> Generator[None, None, None]:
    """Overlay ``values`` on os.environ for the current context only."""
    install()
    merged = dict(_overlay.get() or {})
    merged.update({k: str(v) for k, v in values.items()})
    token = _overlay.set(merged)
    try:
        yield
    finally:
        _overlay.reset(token)


def active_overlay() -> Dict[str, str]:
    return dict(_overlay.get() or {})


def subprocess_env() -> Optional[Dict[str, str]]:
    """Environment for a child process: the real env plus the current org overlay.

    None (inherit the process environment) when no org scope is active.
    """
    if not _overlay.get():
        return None
    return dict(os.environ)


install()
