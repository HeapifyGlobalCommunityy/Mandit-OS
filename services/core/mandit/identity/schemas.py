"""Identity data types.

`IdentityError` and `AgentContext` are the published interface (modules/01 section 3); other
teams import them from here. The registry records, the caller `Principal` and the registration
request models below are used inside the identity module and by its HTTP layer.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator


class IdentityError(Exception):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


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


# --- Registry records (rows of operators, agents and agent_keys; migration 0001) -------------

OperatorStatus = Literal["PENDING", "VERIFIED", "SUSPENDED"]
AgentStatus = Literal["ACTIVE", "REVOKED"]
AgentKeyStatus = Literal["ACTIVE", "RETIRED", "REVOKED"]


@dataclass(frozen=True)
class OperatorRecord:
    operator_id: str
    legal_name: str
    domain: str
    contact_email: str
    status: OperatorStatus
    verified_at: datetime | None
    created_at: datetime


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    operator_id: str
    name: str
    version: str
    model_declared: str | None
    scopes: tuple[str, ...]
    status: AgentStatus
    created_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: str | None = None


@dataclass(frozen=True)
class AgentKeyRecord:
    key_id: str
    agent_id: str
    jwk: dict[str, str]
    thumbprint: str
    status: AgentKeyStatus
    created_at: datetime
    retired_at: datetime | None = None


@dataclass(frozen=True)
class AgentView:
    agent: AgentRecord
    keys: tuple[AgentKeyRecord, ...]


# --- Caller identity ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Principal:
    """The authenticated caller of a registry endpoint, supplied by the console or service auth.

    `mandit_admin` callers manage operators. Operator admins act only for the operators in
    `operator_ids`. SERVICE principals may read agents but never change the registry.
    """

    kind: Literal["USER", "SERVICE"]
    id: str
    mandit_admin: bool = False
    operator_ids: frozenset[str] = field(default_factory=frozenset)

    def acts_for(self, operator_id: str) -> bool:
        return self.mandit_admin or operator_id in self.operator_ids


# --- Registration requests (modules/01 sections 6.1 and 6.2) --------------------------------

# RFC 2606 and RFC 6761 reserved names. The programme uses synthetic data only (REFERENCE 1.2),
# and Phase 1 verification is manual, so registering a real company's domain is refused.
SYNTHETIC_TLDS = ("example", "test", "invalid", "localhost")
SYNTHETIC_DOMAINS = ("example.com", "example.net", "example.org")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_EMAIL_LOCAL = re.compile(r"[A-Za-z0-9._%+-]{1,64}")
# Printable ASCII with no leading or trailing space; rejects control and bidi characters.
_DISPLAY = r"^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$"

ID_PATTERN = {
    "op": re.compile(r"op_[0-9A-Za-z]{1,64}"),
    "agt": re.compile(r"agt_[0-9A-Za-z]{1,64}"),
}

LegalName = Annotated[str, StringConstraints(min_length=1, max_length=200, pattern=_DISPLAY)]
AgentName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
Version = Annotated[str, StringConstraints(pattern=r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,31}$")]
ModelName = Annotated[str, StringConstraints(max_length=64, pattern=_DISPLAY)]
ScopeName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z_]*:[a-z][a-z_]*$")]
OperatorId = Annotated[str, StringConstraints(pattern=r"^op_[0-9A-Za-z]{1,64}$")]


def synthetic_domain(value: str) -> str:
    """Return the lowercase domain, or raise ValueError if it is invalid or not synthetic."""
    domain = value.lower()
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or not all(_LABEL.fullmatch(lb) for lb in labels):
        raise ValueError("must be a valid DNS hostname")
    if labels[-1] not in SYNTHETIC_TLDS and not any(
        domain == d or domain.endswith("." + d) for d in SYNTHETIC_DOMAINS
    ):
        raise ValueError("must be a reserved synthetic domain (RFC 2606), e.g. acme.example")
    return domain


class OperatorRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    legal_name: LegalName
    domain: Annotated[str, StringConstraints(max_length=253)]
    contact_email: Annotated[str, StringConstraints(max_length=254)]

    @field_validator("domain")
    @classmethod
    def _domain(cls, value: str) -> str:
        return synthetic_domain(value)

    @field_validator("contact_email")
    @classmethod
    def _email(cls, value: str) -> str:
        local, sep, domain = value.rpartition("@")
        if not sep or not _EMAIL_LOCAL.fullmatch(local):
            raise ValueError("must be an email address")
        return f"{local}@{synthetic_domain(domain)}"


class AgentRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    operator_id: OperatorId
    name: AgentName
    version: Version
    model_declared: ModelName | None = None
    # Validated as an Ed25519 JWK by keys.public_key_from_jwk; only the shape is bounded here.
    public_key: Annotated[dict[str, Any], Field(min_length=1, max_length=16)]
    requested_scopes: Annotated[list[ScopeName], Field(min_length=1, max_length=16)]
