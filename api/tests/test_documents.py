"""Documents through the API, and the database policies underneath them.

The isolation tests prove that a user in workspace A can neither read nor change
documents or passages in workspace B, through the API and in the database.
"""

from uuid import UUID

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient

from tests.conftest import FakeEmbedder, Headers, make_client, make_pdf
from tests.test_workspaces import add_member, as_app, create

PDF = make_pdf(["Refunds take five days.", "Shipping is free on every order."])


def upload(
    client: TestClient,
    auth: Headers,
    user: UUID,
    workspace: str,
    data: bytes = PDF,
    name: str = "policy.pdf",
) -> httpx.Response:
    response: httpx.Response = client.post(
        f"/v1/workspaces/{workspace}/documents",
        params={"name": name},
        content=data,
        headers=auth(user),
    )
    return response


def test_an_upload_becomes_embedded_passages_with_page_numbers(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID], database_url: str
) -> None:
    alice, _ = users
    workspace = create(client, auth, alice)
    response = upload(client, auth, alice, workspace, name="C:\\Users\\a\\policy.pdf")
    assert response.status_code == 202
    document = response.json()
    assert (document["name"], document["kind"]) == ("policy.pdf", "pdf")
    assert (document["pages"], document["passages"]) == (2, 2)
    # TestClient finishes the background embedding before it returns.
    url = f"/v1/workspaces/{workspace}/documents/{document['id']}"
    assert client.get(url, headers=auth(alice)).json()["status"] == "ready"
    with psycopg.connect(database_url) as conn:
        rows = conn.execute(
            "SELECT page, embedding IS NOT NULL FROM whence.passages"
            " WHERE document_id = %s ORDER BY ordinal",
            (document["id"],),
        ).fetchall()
    assert rows == [(1, True), (2, True)]


def test_the_same_file_twice_is_one_document(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID]
) -> None:
    alice, _ = users
    workspace = create(client, auth, alice)
    first = upload(client, auth, alice, workspace).json()
    again = upload(client, auth, alice, workspace, name="copy.pdf")
    assert again.status_code == 200
    assert again.json()["id"] == first["id"]
    listed = client.get(f"/v1/workspaces/{workspace}/documents", headers=auth(alice))
    assert [d["id"] for d in listed.json()] == [first["id"]]


def test_a_failed_embedding_marks_the_document_failed(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID], embedder: FakeEmbedder
) -> None:
    alice, _ = users
    workspace = create(client, auth, alice)
    embedder.fail = True
    document = upload(client, auth, alice, workspace).json()
    url = f"/v1/workspaces/{workspace}/documents/{document['id']}"
    assert client.get(url, headers=auth(alice)).json()["status"] == "failed"


def test_members_read_documents_and_only_owners_and_admins_change_them(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID], database_url: str
) -> None:
    alice, bob = users
    workspace = create(client, auth, alice)
    add_member(database_url, workspace, bob, "member")
    document = upload(client, auth, alice, workspace).json()
    url = f"/v1/workspaces/{workspace}/documents/{document['id']}"
    assert client.get(url, headers=auth(bob)).status_code == 200
    assert (
        upload(client, auth, bob, workspace, b"Notes", "notes.txt").status_code == 403
    )
    assert client.delete(url, headers=auth(bob)).status_code == 403
    with psycopg.connect(database_url, autocommit=True) as conn:
        conn.execute(
            "UPDATE whence.memberships SET role = 'admin' WHERE user_id = %s", (bob,)
        )
    assert client.delete(url, headers=auth(bob)).status_code == 204
    assert client.get(url, headers=auth(alice)).status_code == 404


def test_another_workspace_can_neither_see_nor_change_documents(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID]
) -> None:
    alice, bob = users
    workspace = create(client, auth, alice)
    document = upload(client, auth, alice, workspace).json()["id"]
    bobs = create(client, auth, bob, "Bob's team")
    for base in (f"/v1/workspaces/{workspace}", f"/v1/workspaces/{bobs}"):
        url = f"{base}/documents/{document}"
        assert client.get(url, headers=auth(bob)).status_code == 404
        assert client.delete(url, headers=auth(bob)).status_code == 404
    documents = f"/v1/workspaces/{workspace}/documents"
    assert client.get(documents, headers=auth(bob)).status_code == 404
    assert upload(client, auth, bob, workspace).status_code == 404
    url = f"{documents}/{document}"
    assert client.get(url, headers=auth(alice)).json()["status"] == "ready"


def test_the_database_hides_other_workspaces_documents_even_from_a_bad_query(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID], database_url: str
) -> None:
    alice, bob = users
    workspace = create(client, auth, alice)
    document = upload(client, auth, alice, workspace).json()["id"]
    bobs = create(client, auth, bob, "Bob's team")
    with psycopg.connect(database_url, autocommit=True) as conn:
        as_app(conn, bob)
        # No WHERE clause: the policies alone decide.
        assert conn.execute("SELECT * FROM whence.documents").fetchall() == []
        assert conn.execute("SELECT * FROM whence.passages").fetchall() == []
        for change in (
            "UPDATE whence.passages SET embedding = NULL RETURNING id",
            "UPDATE whence.documents SET status = 'failed' RETURNING id",
            "DELETE FROM whence.documents RETURNING id",
        ):
            assert conn.execute(change).fetchall() == []
        planted = (
            "INSERT INTO whence.passages (document_id, workspace_id, ordinal, text)"
            " VALUES (%s, %s, 99, 'planted')"
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(planted, (document, workspace))
        # Bob owns his workspace, but a passage must match its document's.
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            conn.execute(planted, (document, bobs))
    url = f"/v1/workspaces/{workspace}/documents/{document}"
    assert client.get(url, headers=auth(alice)).json()["passages"] == 2


def test_uploads_must_be_allowed_types_within_the_limits(
    database_url: str, auth: Headers, users: tuple[UUID, UUID]
) -> None:
    alice, _ = users
    with make_client(database_url, max_upload_bytes=1000, workspace_bytes=1500) as app:
        workspace = create(app, auth, alice)

        def error(data: bytes, name: str) -> str:
            response = upload(app, auth, alice, workspace, data, name)
            return str(response.json()["error"]["code"])

        assert error(b"x" * 1001, "big.txt") == "file_too_large"
        assert error(b"", "empty.txt") == "empty_file"
        assert error(b"\x89PNG\r\n", "photo.png") == "unsupported_type"
        assert (
            upload(app, auth, alice, workspace, b"a" * 900, "a.txt").status_code == 202
        )
        assert error(b"b" * 900, "b.txt") == "workspace_full"
