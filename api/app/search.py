"""Hybrid search: vectors and full text, merged with reciprocal rank fusion.

Vectors find passages that mean the same thing in other words. Full text finds
exact names, codes and acronyms that vectors miss. Each method ranks its top 20,
and a passage scores 1 / (60 + rank) from each list it appears in.

The vector search is exact, with no index: a workspace holds a few thousand
passages, which Postgres scans in milliseconds.
"""

from collections.abc import Callable
from uuid import UUID

from psycopg import Connection
from psycopg.rows import DictRow
from pydantic import BaseModel

from app.db import Pool, as_user
from app.embeddings import QUERY_PREFIX, Embedder, as_vector

SEARCH = """
WITH question AS (
    -- Any word of the question may match, and passages that hold more of them
    -- rank higher. Requiring every word would miss most questions.
    SELECT %(vector)s::extensions.vector AS vector,
        replace(plainto_tsquery('english', %(text)s)::text, ' & ', ' | ')::tsquery
            AS query
),
ready AS (
    SELECT p.id, p.embedding, p.search
    FROM whence.passages p
    JOIN whence.documents d ON d.id = p.document_id AND d.status = 'ready'
    WHERE p.workspace_id = %(workspace)s
),
semantic AS (
    SELECT r.id, row_number() OVER (
        ORDER BY r.embedding OPERATOR(extensions.<=>) q.vector, r.id
    ) AS rank
    FROM ready r, question q
    ORDER BY rank
    LIMIT 20
),
keyword AS (
    SELECT r.id, row_number() OVER (
        ORDER BY ts_rank_cd(r.search, q.query) DESC, r.id
    ) AS rank
    FROM ready r, question q
    WHERE r.search @@ q.query
    ORDER BY rank
    LIMIT 20
),
fused AS (
    SELECT id, sum(1.0 / (60 + rank)) AS score
    FROM (SELECT id, rank FROM semantic UNION ALL SELECT id, rank FROM keyword) r
    GROUP BY id
)
SELECT p.id, p.document_id, d.name AS document, p.page, p.section, p.text,
    f.score
FROM fused f
JOIN whence.passages p ON p.id = f.id
JOIN whence.documents d ON d.id = p.document_id
ORDER BY f.score DESC, p.id
LIMIT %(limit)s
"""


class Hit(BaseModel):
    id: UUID
    document_id: UUID
    document: str
    page: int | None
    section: str | None
    text: str
    score: float


def search(
    conn: Connection[DictRow],
    workspace_id: UUID,
    text: str,
    vector: list[float],
    limit: int = 8,
) -> list[Hit]:
    params = {
        "workspace": workspace_id,
        "text": text,
        "vector": as_vector(vector),
        "limit": limit,
    }
    return [Hit(**row) for row in conn.execute(SEARCH, params)]


def searcher(
    pool: Pool, user: UUID, workspace_id: UUID, embedder: Embedder
) -> Callable[[str], list[Hit]]:
    """Search one workspace as one user. The embedding call happens outside
    the database transaction, so a slow provider never holds a connection."""

    def run(question: str) -> list[Hit]:
        vector = embedder.embed([QUERY_PREFIX + question])[0]
        with as_user(pool, user) as conn:
            return search(conn, workspace_id, question, vector)

    return run
