import json
import re
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mandit.identity.challenge import challenge_message, verify_challenge
from mandit.identity.ids import new_id
from mandit.identity.keys import base64url, jwk_thumbprint, public_key_from_jwk
from mandit.identity.kya_jwt import AUDIENCE, ISSUER, REQUIRED, issue_kya_jwt, verify_kya_jwt
from mandit.identity.schemas import IdentityError

JWK = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
THUMB = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def test_rfc8037_appendix_a3():
    assert jwk_thumbprint(dict(JWK, kid="ignored")) == THUMB


@pytest.mark.parametrize(
    "change",
    [
        {"kty": "RSA"},
        {"crv": "Ed448"},
        {"d": None},
        {"x": "!" * 43},
        {"x": JWK["x"] + "="},
        {"x": JWK["x"][:-1] + "p"},
        {"x": base64url(bytes(31))},
        {"x": base64url(bytes(33))},
        {"x": base64url(bytes(32))},
    ],
)
def test_invalid_jwk(change):
    with pytest.raises(IdentityError) as err:
        public_key_from_jwk(JWK | change)
    assert err.value.code == "VALIDATION_ERROR"


@pytest.mark.parametrize("prefix", ["agt", "op", "akey", "chl", "kya"])
def test_ids(prefix):
    assert re.fullmatch(prefix + r"_[0-7][0-9A-HJKMNP-TV-Z]{25}", new_id(prefix))


@pytest.mark.parametrize("change", [None, "nonce", "agent_id", "key", "signature", "encoding"])
def test_challenge(change):
    signer = Ed25519PrivateKey.generate()
    message = b"mandit-kya-challenge:nonce_1:agt_1"
    assert challenge_message("nonce_1", "agt_1") == message
    args = dict(nonce="nonce_1", agent_id="agt_1", signature=base64url(signer.sign(message)))
    public = signer.public_key()
    if change is None:
        verify_challenge(public, **args)
        return
    if change == "key":
        public = Ed25519PrivateKey.generate().public_key()
    elif change == "signature":
        args[change] = base64url(bytes(64))
    elif change == "encoding":
        args["signature"] += "="
    else:
        args[change] += "2"
    with pytest.raises(IdentityError) as err:
        verify_challenge(public, **args)
    assert err.value.code == "CHALLENGE_INVALID"


@pytest.fixture
def issuer_key():
    return Ed25519PrivateKey.generate()


def verify(token, key, thumb=THUMB):
    return verify_kya_jwt(
        token, issuer_keys={"issuer": key.public_key()}, expected_thumbprint=thumb
    )


def issue(key):
    return issue_kya_jwt(
        key,
        kid="issuer",
        agent_id="agt_example",
        operator_id="op_example",
        scopes=["purchase:read"],
        key_thumbprint=THUMB,
    )


def sign(key, claims, **headers):
    return jwt.encode(
        claims, key, algorithm="EdDSA", headers={"typ": "kya+jwt", "kid": "issuer"} | headers
    )


def test_roundtrip(issuer_key):
    token = issue(issuer_key)
    assert jwt.get_unverified_header(token) == {"alg": "EdDSA", "kid": "issuer", "typ": "kya+jwt"}
    claims = verify(token, issuer_key)
    assert claims == {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "agt_example",
        "op": "op_example",
        "scope": "purchase:read",
        "cnf": {"jkt": THUMB},
        "iat": claims["iat"],
        "nbf": claims["iat"],
        "exp": claims["iat"] + 900,
        "jti": claims["jti"],
    }
    assert claims["jti"].startswith("kya_")


@pytest.mark.parametrize("field", REQUIRED)
def test_required_claims(issuer_key, field):
    claims = verify(issue(issuer_key), issuer_key)
    del claims[field]
    with pytest.raises(IdentityError) as err:
        verify(sign(issuer_key, claims), issuer_key)
    assert err.value.code == "KYA_TOKEN_INVALID"


@pytest.mark.parametrize(
    "change",
    [
        {"iss": "other"},
        {"aud": "other"},
        {"cnf": {}},
        {"scope": []},
        {"op": None},
        {"exp": "never"},
        {"exp": 9999999999},
    ],
)
def test_invalid_claim(issuer_key, change):
    claims = verify(issue(issuer_key), issuer_key)
    with pytest.raises(IdentityError) as err:
        verify(sign(issuer_key, claims | change), issuer_key)
    assert err.value.code == "KYA_TOKEN_INVALID"


@pytest.mark.parametrize("offset,allowed", [(-961, False), (-930, True), (30, True), (65, False)])
def test_leeway(issuer_key, offset, allowed):
    claims = verify(issue(issuer_key), issuer_key)
    start = int(time.time()) + offset
    token = sign(issuer_key, claims | {"iat": start, "nbf": start, "exp": start + 900})
    if allowed:
        assert verify(token, issuer_key)["iat"] == start
    else:
        with pytest.raises(IdentityError) as err:
            verify(token, issuer_key)
        assert err.value.code == "KYA_TOKEN_EXPIRED"


@pytest.mark.parametrize("header", [{"kid": "unknown"}, {"typ": "JWT"}])
def test_header_policy(issuer_key, header):
    claims = verify(issue(issuer_key), issuer_key)
    token = sign(issuer_key, claims, **header)
    with pytest.raises(IdentityError) as err:
        verify(token, issuer_key)
    assert err.value.code == "KYA_TOKEN_INVALID"


@pytest.mark.parametrize("algorithm", ["none", "HS256"])
def test_header_algorithm_rejected_before_decode(issuer_key, monkeypatch, algorithm):
    token = issue(issuer_key)
    _, payload, signature = token.split(".")
    altered = base64url(json.dumps(jwt.get_unverified_header(token) | {"alg": algorithm}).encode())
    monkeypatch.setattr(jwt, "decode", lambda *args, **kwargs: pytest.fail("Unexpected JWT decode"))
    with pytest.raises(IdentityError) as err:
        verify(".".join([altered, payload, signature]), issuer_key)
    assert err.value.code == "KYA_TOKEN_INVALID"


def test_ignores_remote_key_hints(issuer_key):
    claims = verify(issue(issuer_key), issuer_key)
    headers = {"jku": "https://unused.invalid/keys", "x5u": "https://unused.invalid/cert"}
    assert verify(sign(issuer_key, claims, **headers), issuer_key) == claims
    with pytest.raises(IdentityError) as err:
        verify(sign(Ed25519PrivateKey.generate(), claims, **headers), issuer_key)
    assert err.value.code == "KYA_TOKEN_INVALID"


def test_tampered_payload(issuer_key):
    token = issue(issuer_key)
    header, _, signature = token.split(".")
    payload = base64url(json.dumps(verify(token, issuer_key) | {"op": "different"}).encode())
    with pytest.raises(IdentityError) as err:
        verify(".".join([header, payload, signature]), issuer_key)
    assert err.value.code == "KYA_TOKEN_INVALID"


def test_binding(issuer_key):
    with pytest.raises(IdentityError) as err:
        verify(issue(issuer_key), issuer_key, base64url(bytes(32)))
    assert err.value.code == "KEY_NOT_BOUND"


def test_encoded_size_boundary(issuer_key):
    scope = "s" * 11919
    args = dict(
        kid="issuer", agent_id="agt_example", operator_id="op_example", key_thumbprint=THUMB
    )
    token = issue_kya_jwt(issuer_key, **args, scopes=[scope])
    assert len(token) == 16384
    claims = verify(token, issuer_key)
    assert claims["scope"] == scope

    larger_scope = scope + "s"
    oversized = sign(issuer_key, claims | {"scope": larger_scope})
    assert len(oversized) == 16385
    with pytest.raises(IdentityError) as err:
        verify(oversized, issuer_key)
    assert err.value.code == "KYA_TOKEN_INVALID"
    with pytest.raises(IdentityError) as err:
        issue_kya_jwt(issuer_key, **args, scopes=[larger_scope])
    assert err.value.code == "VALIDATION_ERROR"


# --- Error paths: every IdentityError code each function can raise is exercised below. ---


def test_ids_reject_unknown_prefix():
    with pytest.raises(ValueError):
        new_id("usr")


@pytest.mark.parametrize(
    "nonce,agent_id",
    [
        ("nonce:1", "agt_1"),  # a ':' would let two different pairs share one signed message
        ("nonce_1", "agt:1"),
        ("", "agt_1"),
        ("nonce_1", ""),
        (None, "agt_1"),
        ("nonce_1", "agt_1\n"),
    ],
)
def test_challenge_rejects_ambiguous_components(nonce, agent_id):
    signer = Ed25519PrivateKey.generate()
    with pytest.raises(IdentityError) as err:
        verify_challenge(
            signer.public_key(), nonce=nonce, agent_id=agent_id, signature=base64url(bytes(64))
        )
    assert err.value.code == "CHALLENGE_INVALID"


@pytest.mark.parametrize(
    "change",
    [
        {"kid": ""},
        {"agent_id": " "},
        {"operator_id": None},
        {"issuer": ""},
        {"scopes": "purchase:read"},  # a bare string would be split into one-letter scopes
        {"scopes": ["purchase read"]},
        {"scopes": ['purchase"read']},
        {"scopes": [7]},
        {"key_thumbprint": "short"},
        {"key_thumbprint": THUMB + "="},
    ],
)
def test_issue_rejects_invalid_input(issuer_key, change):
    args = dict(
        kid="issuer",
        agent_id="agt_example",
        operator_id="op_example",
        scopes=["purchase:read"],
        key_thumbprint=THUMB,
    )
    with pytest.raises(IdentityError) as err:
        issue_kya_jwt(issuer_key, **(args | change))
    assert err.value.code == "VALIDATION_ERROR"


@pytest.mark.parametrize("token", [None, 123, b"a.b.c", "", "a.b", "not-a-jwt", "a.b.c"])
def test_verify_rejects_malformed_token(issuer_key, token):
    with pytest.raises(IdentityError) as err:
        verify(token, issuer_key)
    assert err.value.code == "KYA_TOKEN_INVALID"


def test_crit_header_rejected(issuer_key):
    claims = verify(issue(issuer_key), issuer_key)
    with pytest.raises(IdentityError) as err:
        verify(sign(issuer_key, claims, crit=["exp"]), issuer_key)
    assert err.value.code == "KYA_TOKEN_INVALID"


def test_non_ed25519_issuer_key_rejected(issuer_key):
    from cryptography.hazmat.primitives.asymmetric import ec

    wrong_type = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(IdentityError) as err:
        verify_kya_jwt(
            issue(issuer_key), issuer_keys={"issuer": wrong_type}, expected_thumbprint=THUMB
        )
    assert err.value.code == "KYA_TOKEN_INVALID"


@pytest.mark.parametrize(
    "change",
    [
        lambda c: {"iat": True},  # bool is an int subclass; must not pass as a NumericDate
        lambda c: {"exp": c["exp"] - 0.5},
        lambda c: {"sub": ""},
        lambda c: {"op": "   "},
        lambda c: {"jti": 7},
        lambda c: {"scope": 'purchase"read'},
        lambda c: {"scope": "purchase:read  merchant:read"},
        lambda c: {"cnf": "jkt"},
        lambda c: {"cnf": {"jkt": "short"}},
    ],
)
def test_invalid_claim_values(issuer_key, change):
    claims = verify(issue(issuer_key), issuer_key)
    with pytest.raises(IdentityError) as err:
        verify(sign(issuer_key, claims | change(claims)), issuer_key)
    assert err.value.code == "KYA_TOKEN_INVALID"


def test_error_does_not_echo_credential(issuer_key):
    token = issue(issuer_key)
    with pytest.raises(IdentityError) as err:
        verify(token, Ed25519PrivateKey.generate())
    assert token not in str(err.value) and token not in err.value.message
