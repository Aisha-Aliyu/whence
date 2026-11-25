"""Documents: upload, list, read and delete.

An upload is checked, read and split into passages during the request, so a bad
file gets a clear error at once. Embedding calls an outside service, so it runs
after the response, and the document's status says when it is ready. Only the
extracted text is kept, never the uploaded file.
"""

import hashlib
import logging
import re
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from psycopg import Connection
from psycopg.rows import DictRow
from pydantic import BaseModel

from app.auth import CurrentUser
from app.db import DbPool, Pool, as_user
from app.embeddings import Embedder, as_vector
from app.errors import ApiError
from app.extract import extract, kind_of
from app.workspaces import find

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/workspaces/{workspace_id}/documents", tags=["documents"])

LIST = """
    SELECT d.id, d.name, d.kind, d.size_bytes, d.pages, d.status, d.created_at,
        (SELECT count(*) FROM whence.passages p WHERE p.document_id = d.id)
            AS passages
    FROM whence.documents d
    WHERE d.workspace_id = %s
    ORDER BY d.created_at DESC
    LIMIT 500
"""

ONE = """
    SELECT d.id, d.name, d.kind, d.size_bytes, d.pages, d.status, d.created_at,
        (SELECT count(*) FROM whence.passages p WHERE p.document_id = d.id)
            AS passages
    FROM whence.documents d
    WHERE d.workspace_id = %s AND d.id = %s
"""


class Document(BaseModel):
    id: UUID
    name: str
    kind: Literal["pdf", "markdown", "text"]
    size_bytes: int
    pages: int | None
    passages: int
    status: Literal["processing", "ready", "failed"]
    created_at: datetime


@router.post("", status_code=202)
async def upload_document(
    workspace_id: UUID,
    name: Annotated[str, Query(min_length=1, max_length=200)],
    request: Request,
    response: Response,
    background: BackgroundTasks,
    user: CurrentUser,
    pool: DbPool,
) -> Document:
    """The request body is the file itself. Owners and admins only."""
    request.app.state.upload_limiter.hit(str(user))
    settings = request.app.state.settings
    name = clean(name)
    kind_of(name)  # refuse an unsupported type before reading the file
    await run_in_threadpool(check_editor, pool, user, workspace_id)
    data = await read_body(request, settings.max_upload_bytes)
    document, created = await run_in_threadpool(
        save, pool, user, workspace_id, name, data, settings.workspace_bytes
    )
    if created:
        embedder = request.app.state.embedder
        background.add_task(embed_document, pool, embedder, user, document.id)
    else:  # the same file again: answer with the document we already have
        response.status_code = 200
    return document


@router.get("")
def list_documents(
    workspace_id: UUID, user: CurrentUser, pool: DbPool
) -> list[Document]:
    with as_user(pool, user) as conn:
        find(conn, workspace_id, user)
        return [Document(**row) for row in conn.execute(LIST, (workspace_id,))]


@router.get("/{document_id}")
def get_document(
    workspace_id: UUID, document_id: UUID, user: CurrentUser, pool: DbPool
) -> Document:
    with as_user(pool, user) as conn:
        find(conn, workspace_id, user)
        return fetch(conn, workspace_id, document_id)


@router.delete("/{document_id}", status_code=204)
def delete_document(
    workspace_id: UUID, document_id: UUID, user: CurrentUser, pool: DbPool
) -> Response:
    with as_user(pool, user) as conn:
        require_editor(conn, workspace_id, user)
        fetch(conn, workspace_id, document_id)
        conn.execute(
            "DELETE FROM whence.documents WHERE workspace_id = %s AND id = %s",
            (workspace_id, document_id),
        )
    return Response(status_code=204)


def clean(name: str) -> str:
    """Keeps a display name only: no folders and no control characters."""
    name = re.sub(r"[\x00-\x1f\x7f]", "", re.split(r"[\\/]", name)[-1]).strip()
    if not name:
        raise ApiError(422, "invalid_request", "The file name is not valid.")
    return name


async def read_body(request: Request, limit: int) -> bytes:
    """Reads the upload, stopping as soon as it passes the size limit."""
    too_large = ApiError(
        413, "file_too_large", f"Files can be up to {limit / 1_000_000:g} MB."
    )
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise too_large
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise too_large
    if not body:
        raise ApiError(422, "empty_file", "The file is empty.")
    return bytes(body)


def check_editor(pool: Pool, user: UUID, workspace_id: UUID) -> None:
    with as_user(pool, user) as conn:
        require_editor(conn, workspace_id, user)


def save(
    pool: Pool, user: UUID, workspace_id: UUID, name: str, data: bytes, quota: int
) -> tuple[Document, bool]:
    """Stores the document and its passages. False when it already existed."""
    digest = hashlib.sha256(data).hexdigest()
    with as_user(pool, user) as conn:  # quick checks before the slow part
        existing = find_by_hash(conn, workspace_id, digest)
        if existing:
            return existing, False
        check_quota(conn, workspace_id, len(data), quota)
    extracted = extract(data, name)  # outside any transaction: parsing can be slow
    with as_user(pool, user) as conn:
        # One upload per workspace at a time from here, so two uploads cannot
        # both pass the quota check or both add the same file.
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (str(workspace_id),),
        )
        existing = find_by_hash(conn, workspace_id, digest)
        if existing:
            return existing, False
        check_quota(conn, workspace_id, len(data), quota)
        row = conn.execute(
            "INSERT INTO whence.documents"
            " (workspace_id, name, kind, size_bytes, sha256, pages, uploaded_by)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (
                workspace_id,
                name,
                extracted.kind,
                len(data),
                digest,
                extracted.pages,
                user,
            ),
        ).fetchone()
        assert row is not None
        with conn.cursor() as cursor:
            cursor.executemany(
                "INSERT INTO whence.passages"
                " (document_id, workspace_id, ordinal, page, section, text)"
                " VALUES (%s, %s, %s, %s, %s, %s)",
                [
                    (row["id"], workspace_id, ordinal, p.page, p.section, p.text)
                    for ordinal, p in enumerate(extracted.passages)
                ],
            )
        return fetch(conn, workspace_id, row["id"]), True


def embed_document(
    pool: Pool, embedder: Embedder, user: UUID, document_id: UUID
) -> None:
    """Runs after the upload response. Any failure marks the document failed."""
    try:
        with as_user(pool, user) as conn:
            rows = conn.execute(
                "SELECT id, text FROM whence.passages WHERE document_id = %s"
                " ORDER BY ordinal",
                (document_id,),
            ).fetchall()
        vectors = embedder.embed([row["text"] for row in rows])
        with as_user(pool, user) as conn, conn.cursor() as cursor:
            cursor.executemany(
                "UPDATE whence.passages SET embedding = %s::extensions.vector"
                " WHERE id = %s",
                [
                    (as_vector(vector), row["id"])
                    for row, vector in zip(rows, vectors, strict=True)
                ],
            )
            cursor.execute(
                "UPDATE whence.documents SET status = 'ready' WHERE id = %s",
                (document_id,),
            )
    except Exception:
        log.exception("Could not embed document %s", document_id)
        with as_user(pool, user) as conn:
            conn.execute(
                "UPDATE whence.documents SET status = 'failed' WHERE id = %s",
                (document_id,),
            )


def require_editor(conn: Connection[DictRow], workspace_id: UUID, user: UUID) -> None:
    if find(conn, workspace_id, user).role not in ("owner", "admin"):
        raise ApiError(
            403, "forbidden", "Only owners and admins can add or delete documents."
        )


def check_quota(
    conn: Connection[DictRow], workspace_id: UUID, size: int, quota: int
) -> None:
    row = conn.execute(
        "SELECT coalesce(sum(size_bytes), 0) AS used FROM whence.documents"
        " WHERE workspace_id = %s",
        (workspace_id,),
    ).fetchone()
    assert row is not None
    if int(row["used"]) + size > quota:
        raise ApiError(
            413, "workspace_full", "This workspace is full. Delete some documents."
        )


def find_by_hash(
    conn: Connection[DictRow], workspace_id: UUID, digest: str
) -> Document | None:
    row = conn.execute(
        "SELECT id FROM whence.documents WHERE workspace_id = %s AND sha256 = %s",
        (workspace_id, digest),
    ).fetchone()
    return fetch(conn, workspace_id, row["id"]) if row else None


def fetch(conn: Connection[DictRow], workspace_id: UUID, document_id: UUID) -> Document:
    row = conn.execute(ONE, (workspace_id, document_id)).fetchone()
    if row is None:  # another team's document looks exactly like a missing one
        raise ApiError(404, "not_found", "Document not found.")
    return Document(**row)
