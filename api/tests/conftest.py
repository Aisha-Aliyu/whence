"""Shared test setup.

Tests that need Postgres read TEST_DATABASE_URL (a database the tests may wipe)
and are skipped without it. Tokens are signed with a key made for the test run,
so no test calls Supabase.
"""

import os
import time
from collections.abc import Callable, Iterator, Sequence
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
from app.embeddings import DIMENSIONS, EmbeddingError
from app.main import create_app
from app.settings import Settings
from app.workers_ai import WorkersAIError

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


def make_pdf(pages: list[str]) -> bytes:
    """A minimal PDF with one line of text on each page."""
    kids = " ".join(f"{4 + 2 * i} 0 R" for i in range(len(pages)))
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    for i, text in enumerate(pages):
        stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET"
        objects.append(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]"
            f" /Resources << /Font << /F1 3 0 R >> >> /Contents {5 + 2 * i} 0 R >>"
        )
        objects.append(f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream")
    pdf = "%PDF-1.4\n"
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += f"{number} 0 obj\n{body}\nendobj\n"
    table = "".join(f"{offset:010d} 00000 n \n" for offset in offsets)
    pdf += (
        f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n{table}"
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{len(pdf)}\n%%EOF\n"
    )
    return pdf.encode("ascii")


class FakeEmbedder:
    """Made-up vectors, so no test calls Cloudflare. Set fail to simulate an outage."""

    def __init__(self) -> None:
        self.fail = False

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if self.fail:
            raise EmbeddingError("Workers AI is down")
        return [[len(text) % 7 + 1.0] * DIMENSIONS for text in texts]


class FakeChat:
    """Replies with a script, so no test calls Cloudflare. Keeps every prompt."""

    def __init__(self) -> None:
        self.reply = ["Refunds take five days [P1]."]
        self.prompts: list[list[dict[str, str]]] = []
        self.fail = False

    def stream(self, messages: list[dict[str, str]]) -> Iterator[str]:
        self.prompts.append(messages)
        if self.fail:
            raise WorkersAIError("Workers AI is down")
        yield from self.reply


def make_client(
    database_url: str,
    embedder: FakeEmbedder | None = None,
    chat: FakeChat | None = None,
    **settings: Any,
) -> TestClient:
    config = Settings(
        database_url=database_url,
        supabase_url=SUPABASE_URL,
        db_timeout_seconds=2,
        **settings,
    )
    verifier = LocalVerifier(config.jwks_url, config.jwt_issuer, config.jwt_audience)
    app = create_app(config, verifier, embedder or FakeEmbedder(), chat or FakeChat())
    return TestClient(app)


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
def embedder() -> FakeEmbedder:
    return FakeEmbedder()


@pytest.fixture
def chat() -> FakeChat:
    return FakeChat()


@pytest.fixture
def client(
    database_url: str, embedder: FakeEmbedder, chat: FakeChat
) -> Iterator[TestClient]:
    with psycopg.connect(database_url, autocommit=True) as conn:
        conn.execute("TRUNCATE whence.workspaces CASCADE")
    with make_client(database_url, embedder, chat) as test_client:
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
