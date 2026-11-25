from typing import Protocol

from .schemas import AgentContext


class IdentityService[RequestT, AgentT](Protocol):
    """Request and registry record types are supplied by the integration layer."""

    async def verify_request(self, request: RequestT) -> AgentContext: ...

    async def get_agent(self, agent_id: str) -> AgentT: ...

    async def is_active(self, agent_id: str, key_id: str | None = None) -> bool: ...
