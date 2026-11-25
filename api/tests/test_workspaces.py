"""Workspaces through the API, and the database policies underneath them.

The isolation tests prove that a user in workspace A can neither read nor change
anything in workspace B, through the API and directly in the database.
"""

from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from tests.conftest import Headers


def create(
    client: TestClient, auth: Headers, user: UUID, name: str = "Acme Ops"
) -> str:
    response = client.post("/v1/workspaces", json={"name": name}, headers=auth(user))
    assert response.status_code == 201
    workspace_id: str = response.json()["id"]
    return workspace_id


def add_member(database_url: str, workspace_id: str, user: UUID, role: str) -> None:
    with psycopg.connect(
        database_url, autocommit=True
    ) as conn:  # as the owner, like an invite
        conn.execute(
            "INSERT INTO whence.memberships (workspace_id, user_id, role)"
            " VALUES (%s, %s, %s)",
            (workspace_id, user, role),
        )


def test_the_creator_owns_a_new_workspace(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID]
) -> None:
    alice, _ = users
    response = client.post(
        "/v1/workspaces", json={"name": "  Acme Ops  "}, headers=auth(alice)
    )
    assert response.status_code == 201
    created = response.json()
    assert (created["name"], created["role"]) == ("Acme Ops", "owner")
    assert client.get("/v1/workspaces", headers=auth(alice)).json() == [created]
    assert (
        client.get(f"/v1/workspaces/{created['id']}", headers=auth(alice)).json()
        == created
    )


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"name": ""},
        {"name": "   "},
        {"name": "x" * 101},
        {"name": "Ops", "created_by": "x"},
    ],
)
def test_invalid_workspaces_are_refused(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID], body: dict[str, str]
) -> None:
    response = client.post("/v1/workspaces", json=body, headers=auth(users[0]))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"


def test_another_user_can_neither_see_nor_change_a_workspace(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID]
) -> None:
    alice, bob = users
    workspace = create(client, auth, alice)
    url = f"/v1/workspaces/{workspace}"
    assert client.get("/v1/workspaces", headers=auth(bob)).json() == []
    assert client.get(url, headers=auth(bob)).status_code == 404
    assert (
        client.patch(url, json={"name": "Mine now"}, headers=auth(bob)).status_code
        == 404
    )
    assert client.delete(url, headers=auth(bob)).status_code == 404
    assert client.get(url, headers=auth(alice)).json()["name"] == "Acme Ops"


def test_roles_decide_who_renames_and_deletes(
    client: TestClient, auth: Headers, database_url: str
) -> None:
    owner, admin, member = uuid4(), uuid4(), uuid4()
    workspace = create(client, auth, owner)
    add_member(database_url, workspace, admin, "admin")
    add_member(database_url, workspace, member, "member")
    url = f"/v1/workspaces/{workspace}"

    assert client.get(url, headers=auth(member)).json()["role"] == "member"
    assert (
        client.patch(url, json={"name": "Renamed"}, headers=auth(member)).status_code
        == 403
    )
    assert (
        client.patch(url, json={"name": "Renamed"}, headers=auth(admin)).status_code
        == 200
    )
    assert client.delete(url, headers=auth(admin)).status_code == 403
    assert client.delete(url, headers=auth(owner)).status_code == 204
    assert client.get(url, headers=auth(owner)).status_code == 404


def as_app(conn: psycopg.Connection[tuple[object, ...]], user: UUID | None) -> None:
    conn.execute("SET ROLE whence_app")
    if user is not None:
        conn.execute("SELECT set_config('app.user_id', %s, false)", (str(user),))


def test_the_database_hides_other_workspaces_even_from_a_bad_query(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID], database_url: str
) -> None:
    alice, bob = users
    workspace = create(client, auth, alice)
    with psycopg.connect(database_url, autocommit=True) as conn:
        as_app(conn, bob)
        # No WHERE clause and no join: the policies alone decide.
        assert conn.execute("SELECT * FROM whence.workspaces").fetchall() == []
        assert conn.execute("SELECT * FROM whence.memberships").fetchall() == []
        updated = conn.execute(
            "UPDATE whence.workspaces SET name = 'Mine now' RETURNING id"
        )
        assert updated.fetchall() == []
        assert (
            conn.execute("DELETE FROM whence.workspaces RETURNING id").fetchall() == []
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "INSERT INTO whence.memberships (workspace_id, user_id, role)"
                " VALUES (%s, %s, 'owner')",
                (workspace, bob),
            )
    with psycopg.connect(database_url, autocommit=True) as conn:
        as_app(conn, None)  # no signed-in user: nothing at all
        assert conn.execute("SELECT * FROM whence.workspaces").fetchall() == []
    assert (
        client.get(f"/v1/workspaces/{workspace}", headers=auth(alice)).json()["name"]
        == "Acme Ops"
    )


def test_the_app_role_cannot_change_who_created_a_workspace(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID], database_url: str
) -> None:
    alice, bob = users
    create(client, auth, alice)
    with psycopg.connect(database_url, autocommit=True) as conn:
        as_app(conn, alice)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE whence.workspaces SET created_by = %s", (bob,))
