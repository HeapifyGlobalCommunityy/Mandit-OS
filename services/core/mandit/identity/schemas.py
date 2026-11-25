from dataclasses import dataclass
from datetime import datetime


class IdentityError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class AgentContext:
    """Produced only after the complete request-verification pipeline succeeds."""

    agent_id: str
    operator_id: str
    key_id: str
    key_thumbprint: str
    scopes: frozenset[str]
    credential_id: str
    verified_at: datetime
