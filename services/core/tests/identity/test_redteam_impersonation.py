"""Replays the T2 impersonation corpus cases against the identity module.

Each case in redteam/corpus/impersonation/ names a `credential_attack`. This module builds that
attack against the real issuer, verifier, key-validation and registration code and asserts that
it is rejected with one of the case's expected reason codes. The gateway-level steps in the same
files run once the gateway and the red-team harness exist; this test is the regression gate until
then.
"""

import json
from collections.abc import Callable
from pathlib import Path

import jwt
import pytest
import yaml
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from identity_support import (
    ADMIN,
    MemoryDatabase,
    MemoryUnitOfWork,
    agent_request,
    operator_admin,
    run,
)

from mandit.identity.keys import base64url, jwk_thumbprint, public_key_from_jwk
from mandit.identity.kya_jwt import issue_kya_jwt, verify_kya_jwt
from mandit.identity.schemas import AgentRegistration, IdentityError, OperatorRegistration
from mandit.identity.service import RegistrationService

CORPUS = Path(__file__).resolve().parents[4] / "redteam" / "corpus" / "impersonation"
CASES = sorted(CORPUS.glob("ATK-IMP-*.yaml"))

MANDIT_KID = "mandit-kya-2026-11"
ISSUER_KEY = Ed25519PrivateKey.generate()
ISSUER_KEYS = {MANDIT_KID: ISSUER_KEY.public_key()}


def _jwk(private_key: Ed25519PrivateKey) -> dict[str, str]:
    raw = private_key.public_key().public_bytes_raw()
    return {"kty": "OKP", "crv": "Ed25519", "x": base64url(raw)}


VICTIM_KEY = Ed25519PrivateKey.generate()
ATTACKER_KEY = Ed25519PrivateKey.generate()
VICTIM_THUMB = jwk_thumbprint(_jwk(VICTIM_KEY))
ATTACKER_THUMB = jwk_thumbprint(_jwk(ATTACKER_KEY))


def _genuine_victim_token() -> str:
    return issue_kya_jwt(
        ISSUER_KEY,
        kid=MANDIT_KID,
        agent_id="agt_victim",
        operator_id="op_victim",
        key_thumbprint=VICTIM_THUMB,
        scopes=["purchase:execute"],
    )


def _claims() -> dict[str, object]:
    return jwt.decode(_genuine_victim_token(), options={"verify_signature": False})


def _b64json(obj: dict[str, object]) -> str:
    return base64url(json.dumps(obj, separators=(",", ":")).encode())


def _verify_as_victim(token: str) -> None:
    verify_kya_jwt(token, issuer_keys=ISSUER_KEYS, expected_thumbprint=VICTIM_THUMB)


def alg_none() -> None:
    header = {"alg": "none", "typ": "kya+jwt", "kid": MANDIT_KID}
    _verify_as_victim(f"{_b64json(header)}.{_b64json(_claims())}.")


def alg_confusion_hs256() -> None:
    header = {"alg": "HS256", "typ": "kya+jwt", "kid": MANDIT_KID}
    signing_input = f"{_b64json(header)}.{_b64json(_claims())}".encode()
    mac = hmac.HMAC(ISSUER_KEY.public_key().public_bytes_raw(), hashes.SHA256())
    mac.update(signing_input)
    _verify_as_victim(f"{signing_input.decode()}.{base64url(mac.finalize())}")


def foreign_kid() -> None:
    token = jwt.encode(
        _claims(), ATTACKER_KEY, algorithm="EdDSA", headers={"typ": "kya+jwt", "kid": "attacker"}
    )
    _verify_as_victim(token)


def forged_signature() -> None:
    token = jwt.encode(
        _claims(), ATTACKER_KEY, algorithm="EdDSA", headers={"typ": "kya+jwt", "kid": MANDIT_KID}
    )
    _verify_as_victim(token)


def stolen_jwt_wrong_key() -> None:
    # The gateway resolves the thumbprint from the key that signed the request: the attacker's.
    verify_kya_jwt(
        _genuine_victim_token(), issuer_keys=ISSUER_KEYS, expected_thumbprint=ATTACKER_THUMB
    )


def small_order_public_key() -> None:
    identity_point = bytes([1]) + bytes(31)
    public_key_from_jwk({"kty": "OKP", "crv": "Ed25519", "x": base64url(identity_point)})


def _registry() -> RegistrationService:
    db = MemoryDatabase()
    return RegistrationService(lambda: MemoryUnitOfWork(db))


async def _operator(service: RegistrationService, *, verify: bool) -> str:
    request = OperatorRegistration.model_validate(
        {"legal_name": "Mallory Ltd (synthetic)", "domain": "mallory.example",
         "contact_email": "ops@mallory.example"}
    )  # fmt: skip
    operator = await service.register_operator(ADMIN, request)
    if verify:
        await service.verify_operator(ADMIN, operator.operator_id)
    return operator.operator_id


def unverified_operator_registration() -> None:
    async def attack() -> None:
        service = _registry()
        operator_id = await _operator(service, verify=False)
        request = AgentRegistration.model_validate(agent_request(operator_id))
        await service.register_agent(operator_admin(operator_id), request)

    run(attack())


def duplicate_key_registration() -> None:
    async def attack() -> None:
        service = _registry()
        victim_operator = await _operator(service, verify=True)
        victim_jwk = _jwk(VICTIM_KEY)
        victim = AgentRegistration.model_validate(
            agent_request(victim_operator, public_key=victim_jwk)
        )
        await service.register_agent(operator_admin(victim_operator), victim)

        attacker_operator = await _operator(service, verify=True)
        stolen = {**victim_jwk, "kid": "mallory-key-1"}  # a new label does not make a new key
        attacker = AgentRegistration.model_validate(
            agent_request(attacker_operator, name="mallory-shopper", public_key=stolen)
        )
        await service.register_agent(operator_admin(attacker_operator), attacker)

    run(attack())


ATTACKS: dict[str, Callable[[], None]] = {
    fn.__name__: fn
    for fn in (
        alg_none,
        alg_confusion_hs256,
        foreign_kid,
        forged_signature,
        stolen_jwt_wrong_key,
        small_order_public_key,
        unverified_operator_registration,
        duplicate_key_registration,
    )
}


def _load(path: Path) -> dict[str, object]:
    case = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(case, dict)
    return case


def test_corpus_is_present_and_unique():
    ids = [_load(path)["id"] for path in CASES]
    assert len(ids) >= len(ATTACKS)
    assert len(ids) == len(set(ids))
    assert all(path.stem == case_id for path, case_id in zip(CASES, ids, strict=True))


def test_every_attack_has_a_corpus_case():
    assert {_load(path)["credential_attack"] for path in CASES} == set(ATTACKS)


def test_genuine_credential_still_verifies():
    """Control: the defences must not block the legitimate victim."""
    _verify_as_victim(_genuine_victim_token())


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_impersonation_case_is_rejected(path):
    case = _load(path)
    assert case["threat_class"] == "T2_AGENT_IMPERSONATION"
    expected = case["expected"]
    assert isinstance(expected, dict)
    with pytest.raises(IdentityError) as err:
        ATTACKS[str(case["credential_attack"])]()
    assert err.value.code in expected["reason_codes_include_any"]
