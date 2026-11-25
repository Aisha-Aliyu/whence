"""Workspaces: create, list, read, rename and delete.

Every query runs through db.as_user, so row-level security limits it to the
signed-in user's workspaces. The role checks here give clear 403 messages; the
policies enforce the same rules again in the database.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Response
from psycopg import Connection
from psycopg.rows import DictRow
from pydantic import BaseModel, ConfigDict, Field

from app.auth import CurrentUser
from app.db import DbPool, as_user
from app.errors import ApiError

Role = Literal["owner", "admin", "member"]

router = APIRouter(prefix="/v1/workspaces", tags=["workspaces"])

SELECT_MINE = """
    SELECT w.id, w.name, w.created_at, m.role
    FROM whence.workspaces w
    JOIN whence.memberships m ON m.workspace_id = w.id AND m.user_id = %(user)s
"""


class WorkspaceIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=100)


class Workspace(BaseModel):
    id: UUID
    name: str
    role: Role
    created_at: datetime


@router.post("", status_code=201)
def create_workspace(body: WorkspaceIn, user: CurrentUser, pool: DbPool) -> Workspace:
    with as_user(pool, user) as conn:
        row = conn.execute(
            "INSERT INTO whence.workspaces (name, created_by) VALUES (%s, %s)"
            " RETURNING id, name, created_at",
            (body.name, user),
        ).fetchone()
        assert row is not None
        conn.execute(
            "INSERT INTO whence.memberships (workspace_id, user_id, role)"
            " VALUES (%s, %s, 'owner')",
            (row["id"], user),
        )
    return Workspace(**row, role="owner")


@router.get("")
def list_workspaces(user: CurrentUser, pool: DbPool) -> list[Workspace]:
    with as_user(pool, user) as conn:
        rows = conn.execute(SELECT_MINE + " ORDER BY w.created_at", {"user": user})
        return [Workspace(**row) for row in rows]


@router.get("/{workspace_id}")
def get_workspace(workspace_id: UUID, user: CurrentUser, pool: DbPool) -> Workspace:
    with as_user(pool, user) as conn:
        return find(conn, workspace_id, user)


@router.patch("/{workspace_id}")
def rename_workspace(
    workspace_id: UUID, body: WorkspaceIn, user: CurrentUser, pool: DbPool
) -> Workspace:
    with as_user(pool, user) as conn:
        workspace = find(conn, workspace_id, user)
        if workspace.role not in ("owner", "admin"):
            raise ApiError(
                403, "forbidden", "Only owners and admins can rename a workspace."
            )
        conn.execute(
            "UPDATE whence.workspaces SET name = %s WHERE id = %s",
            (body.name, workspace_id),
        )
        return workspace.model_copy(update={"name": body.name})


@router.delete("/{workspace_id}", status_code=204)
def delete_workspace(workspace_id: UUID, user: CurrentUser, pool: DbPool) -> Response:
    with as_user(pool, user) as conn:
        if find(conn, workspace_id, user).role != "owner":
            raise ApiError(403, "forbidden", "Only the owner can delete a workspace.")
        conn.execute("DELETE FROM whence.workspaces WHERE id = %s", (workspace_id,))
    return Response(status_code=204)


def find(conn: Connection[DictRow], workspace_id: UUID, user: UUID) -> Workspace:
    row = conn.execute(
        SELECT_MINE + " WHERE w.id = %(id)s", {"user": user, "id": workspace_id}
    ).fetchone()
    if row is None:  # another team's workspace looks exactly like a missing one
        raise ApiError(404, "not_found", "Workspace not found.")
    return Workspace(**row)
