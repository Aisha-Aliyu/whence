"""Shared test setup.

Tests that need Postgres read TEST_DATABASE_URL (a database the tests may wipe)
and are skipped without it. Tokens are signed with a key made for the test run,
so no test calls Supabase.
"""

import os
import time
from collections.abc import Callable, Iterator
from typing import Any
from uuid import UUID, uuid4

import jwt
import psycopg
import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app.auth import TokenVerifier
from app.main import create_app
from app.settings import Settings

SUPABASE_URL = "https://test.supabase.co"
ISSUER = f"{SUPABASE_URL}/auth/v1"
SIGNING_KEY = ec.generate_private_key(ec.SECP256R1())
UNREACHABLE_DB = "postgresql://nobody:nothing@127.0.0.1:1/none"


class LocalVerifier(TokenVerifier):
    """Checks tokens against the test key instead of Supabase's key set."""

    def signing_key(self, token: str) -> Any:
        return SIGNING_KEY.public_key()


def make_token(
    user: UUID, key: Any = SIGNING_KEY, algorithm: str = "ES256", **claims: Any
) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user),
        "aud": "authenticated",
        "iss": ISSUER,
        "iat": now,
        "exp": now + 600,
    }
    payload.update(claims)
    return jwt.encode(payload, key, algorithm=algorithm, headers={"kid": "test"})


def make_client(database_url: str) -> TestClient:
    settings = Settings(
        database_url=database_url, supabase_url=SUPABASE_URL, db_timeout_seconds=2
    )
    verifier = LocalVerifier(
        settings.jwks_url, settings.jwt_issuer, settings.jwt_audience
    )
    return TestClient(create_app(settings, verifier))


@pytest.fixture(scope="session")
def database_url() -> Iterator[str]:
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is not set")
    os.environ["DATABASE_URL"] = url
    config = Config("alembic.ini")
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    yield url


@pytest.fixture
def client(database_url: str) -> Iterator[TestClient]:
    with psycopg.connect(database_url, autocommit=True) as conn:
        conn.execute("TRUNCATE whence.workspaces CASCADE")
    with make_client(database_url) as test_client:
        yield test_client


@pytest.fixture
def offline_client() -> Iterator[TestClient]:
    """An app whose database cannot be reached."""
    with make_client(UNREACHABLE_DB) as test_client:
        yield test_client


Headers = Callable[[UUID], dict[str, str]]


@pytest.fixture
def auth() -> Headers:
    return lambda user: {"Authorization": f"Bearer {make_token(user)}"}


@pytest.fixture
def users() -> tuple[UUID, UUID]:
    return uuid4(), uuid4()
