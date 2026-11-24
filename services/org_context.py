"""
Per-org credential scopes (#63).

Two layers keep one org's credentials away from another org's work when they
run concurrently in the same process:

1. ``org_credentials`` overlays the org's keys on a context-local view of
   os.environ (services/org_env.py). The process environment is never mutated,
   so a request running for org B cannot read org A's keys, whatever it awaits.

2. ``org_agent_credentials`` also guards the agent's cached clients (GitHub,
   cloud SDKs, the LLM client), which are shared attributes of one agent object.
   An ``OrgGate`` admits any number of scopes for the same org at once, but a
   scope for a different org waits until they have all left. Clients are
   refreshed when the first scope of an org enters and restored when the last
   one leaves, never while another scope is still using them.
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from typing import AsyncGenerator, Generator, List, Optional

import structlog

from services.org_config import OrgConfig, resolve_org_credentials
from services.org_env import env_overlay

log = structlog.get_logger()
_active_org: ContextVar[Optional[str]] = ContextVar("active_org", default=None)


def current_org_id() -> str:
    """Organisation for metadata carried into deferred work such as approvals."""
    return _active_org.get() or os.getenv("ORG_ID", "default")


@contextmanager
def org_credentials(org_id: str, org_config: Optional[OrgConfig] = None) -> Generator[dict, None, None]:
    """
    Make the org's credentials visible through os.getenv for the current
    context only. Yields the credential key names (never values).
    """
    org_config = org_config or OrgConfig()
    creds = resolve_org_credentials(org_id, org_config)
    org_token = _active_org.set(org_id)
    try:
        with env_overlay(creds):
            yield {k: True for k in creds}
    finally:
        _active_org.reset(org_token)


_CREDENTIAL_CLIENTS = (
    "github_collector",
    "gitlab_collector",
    "jenkins_collector",
    "bamboo_collector",
    "azure_devops_collector",
    "argocd_collector",
    "aws_collector",
    "gcp_collector",
    "azure_collector",
    "github_tools",
    "cicd_tools",
    "cloud_tools",
    "argocd_tools",
    "k8s_collector",
    "k8s_tools",
    "helm_tools",
)


def _refresh_client(client: object) -> None:
    refresh = getattr(client, "refresh_credentials", None)
    if callable(refresh):
        refresh()
        return
    reset = getattr(client, "reset", None)
    if callable(reset):
        reset()


def refresh_agent_credentials(agent: object) -> None:
    """Re-read env-backed clients for the org scope that is current."""
    if hasattr(agent, "client"):
        agent.client = None
    for name in _CREDENTIAL_CLIENTS:
        client = getattr(agent, name, None)
        if client is not None:
            _refresh_client(client)


class OrgGate:
    """Lets one org at a time use a shared agent; same-org scopes run together.

    A task already inside the gate may open a scope for another org (a nested
    switch) once no other task is inside; the outer org's clients come back when
    the nested scope exits. Release is synchronous so a cancelled task can never
    leave the gate locked.
    """

    def __init__(self) -> None:
        self.org: Optional[str] = None
        self.holders = 0
        # (outer org, holders before the switch) for each nested switch
        self._stack: List[tuple] = []
        self._cond: Optional[asyncio.Condition] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.held: ContextVar[int] = ContextVar(f"org_gate_held_{id(self)}", default=0)

    def _condition(self) -> asyncio.Condition:
        loop = asyncio.get_running_loop()
        if self._cond is None or self._loop is not loop:
            # A new event loop (tests, a restarted server) starts with a fresh gate.
            self._cond, self._loop = asyncio.Condition(), loop
            self.org, self.holders, self._stack = None, 0, []
        return self._cond

    async def acquire(self, org_id: str) -> bool:
        """Enter for ``org_id``. Returns True when the caller must refresh clients."""
        cond = self._condition()
        held = self.held.get()
        waited = False
        async with cond:
            while True:
                if self.holders == 0:
                    self.org, self.holders, self._stack = org_id, 1, []
                    return True
                if self.org == org_id and (held or not self._stack):
                    self.holders += 1
                    return False
                if held and self.holders == held:
                    # Nested switch by the only task inside the gate.
                    self._stack.append((self.org, self.holders))
                    self.org = org_id
                    self.holders += 1
                    return True
                if not waited:
                    log.info("org_scope_waiting", org_id=org_id, active_org=self.org)
                    waited = True
                await cond.wait()

    def release(self) -> Optional[str]:
        """Leave. Returns the org whose clients to restore: "" for platform, None for no change."""
        self.holders -= 1
        restore: Optional[str] = None
        if self._stack and self.holders == self._stack[-1][1]:
            self.org = self._stack.pop()[0]
            restore = self.org
        elif self.holders <= 0:
            self.org, self.holders, self._stack = None, 0, []
            restore = ""
        if self._loop is not None and not self._loop.is_closed():
            self._loop.create_task(self._wake())
        return restore

    async def _wake(self) -> None:
        cond = self._cond
        if cond is not None:
            async with cond:
                cond.notify_all()


_gates: "dict[int, OrgGate]" = {}


def _gate_for(agent: object) -> OrgGate:
    gate = _gates.get(id(agent))
    if gate is None or getattr(agent, "_org_gate", None) is not gate:
        gate = OrgGate()
        _gates[id(agent)] = gate
        try:
            setattr(agent, "_org_gate", gate)
        except Exception:  # objects that refuse attributes still get a gate by id
            pass
    return gate


@asynccontextmanager
async def org_agent_credentials(
    org_id: str,
    agent: object,
    escalation_service: Optional[object] = None,
) -> AsyncGenerator[dict, None]:
    """Run with ``org_id``'s credentials and with the agent's clients built for that org.

    Concurrent scopes for other orgs wait (see OrgGate); scopes for the same
    org share the clients. Clients are restored when the last scope leaves.
    The escalation service (used only by the serial queue worker) is refreshed
    on every entry and exit.
    """
    gate = _gate_for(agent)
    must_refresh = await gate.acquire(org_id)
    held_token = gate.held.set(gate.held.get() + 1)
    try:
        with org_credentials(org_id) as credentials:
            if must_refresh:
                refresh_agent_credentials(agent)
            if escalation_service is not None:
                escalation_service.refresh_credentials()
            yield credentials
    finally:
        gate.held.reset(held_token)
        restore = gate.release()
        if restore == "":
            refresh_agent_credentials(agent)
        elif restore:
            with org_credentials(restore):
                refresh_agent_credentials(agent)
        if escalation_service is not None:
            escalation_service.refresh_credentials()
