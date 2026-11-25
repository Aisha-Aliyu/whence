"""Health checks, the error format and token checks. Only readyz needs Postgres."""

import time
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from tests.conftest import ISSUER, SIGNING_KEY, make_token


def test_healthz_answers_without_a_database(offline_client: TestClient) -> None:
    response = offline_client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_reports_a_database_it_cannot_reach(offline_client: TestClient) -> None:
    response = offline_client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


def test_readyz_passes_with_a_database(client: TestClient) -> None:
    assert client.get("/readyz").status_code == 200


def test_unknown_routes_use_the_error_format(offline_client: TestClient) -> None:
    response = offline_client.get("/nope")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_a_request_without_a_token_is_refused(offline_client: TestClient) -> None:
    response = offline_client.get("/v1/workspaces")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "missing_token"
    assert response.headers["www-authenticate"] == "Bearer"


def test_tokens_that_fail_a_check_are_refused(offline_client: TestClient) -> None:
    user = uuid4()
    now = int(time.time())
    other_key = ec.generate_private_key(ec.SECP256R1())
    bad_tokens = {
        "garbage": "not-a-token",
        "expired": make_token(user, exp=now - 120, iat=now - 720),
        "wrong audience": make_token(user, aud="anon"),
        "wrong issuer": make_token(user, iss="https://evil.example/auth/v1"),
        "another key": make_token(user, key=other_key),
        "not a user ID": make_token(user, sub="admin"),
        "shared secret": make_token(user, key="secret" * 8, algorithm="HS256"),
        "no signature": jwt.encode(
            {
                "sub": str(user),
                "aud": "authenticated",
                "iss": ISSUER,
                "iat": now,
                "exp": now + 600,
            },
            "",
            algorithm="none",
        ),
    }
    for name, token in bad_tokens.items():
        response = offline_client.get(
            "/v1/workspaces", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401, name
        assert response.json()["error"]["code"] == "invalid_token", name


def test_a_token_missing_a_required_claim_is_refused(
    offline_client: TestClient,
) -> None:
    now = int(time.time())
    token = jwt.encode(
        {"sub": str(uuid4()), "aud": "authenticated", "iss": ISSUER, "exp": now + 600},
        SIGNING_KEY,
        algorithm="ES256",
    )
    response = offline_client.get(
        "/v1/workspaces", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401
