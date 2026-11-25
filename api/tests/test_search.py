"""Hybrid search runs inside one workspace, over documents that are ready."""

from uuid import UUID

from fastapi.testclient import TestClient

from app.db import open_pool
from app.search import searcher
from tests.conftest import FakeEmbedder, Headers
from tests.test_documents import upload
from tests.test_workspaces import create

HANDBOOK = (
    b"# Refunds\nRefunds take five days.\n\n# Office\nThe office opens at nine.\n"
)


def test_search_ranks_matching_passages_first_within_the_workspace(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID], database_url: str
) -> None:
    alice, bob = users
    mine = create(client, auth, alice)
    upload(client, auth, alice, mine, HANDBOOK, "handbook.md")
    theirs = create(client, auth, bob, "Bob's team")
    upload(client, auth, bob, theirs, b"Refunds take ten days here.", "bob.txt")
    with open_pool(database_url, 1, 5) as pool:
        hits = searcher(pool, alice, UUID(mine), FakeEmbedder())("refunds")
        assert [h.section for h in hits] == ["Refunds", "Office"]
        assert {h.document for h in hits} == {"handbook.md"}
        # Bob asking about Alice's workspace finds nothing, even by its ID.
        assert searcher(pool, bob, UUID(mine), FakeEmbedder())("refunds") == []


def test_documents_that_are_not_ready_are_left_out(
    client: TestClient,
    auth: Headers,
    users: tuple[UUID, UUID],
    database_url: str,
    embedder: FakeEmbedder,
) -> None:
    alice, _ = users
    workspace = create(client, auth, alice)
    upload(client, auth, alice, workspace, HANDBOOK, "handbook.md")
    embedder.fail = True
    upload(client, auth, alice, workspace, b"Refunds are instant.", "draft.txt")
    with open_pool(database_url, 1, 5) as pool:
        hits = searcher(pool, alice, UUID(workspace), FakeEmbedder())("refunds")
    assert {h.document for h in hits} == {"handbook.md"}
