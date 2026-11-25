"""Database access.

Each request runs in one transaction as the whence_app role, which cannot
bypass row-level security, with the signed-in user's ID set for that
transaction only. The policies in the migrations then decide which rows the
request can see or change, so a bug in a query cannot reach another workspace.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from psycopg import Connection
from psycopg.rows import DictRow, dict_row
from psycopg_pool import ConnectionPool

Pool = ConnectionPool[Connection[DictRow]]


def open_pool(url: str, size: int, timeout: float) -> Pool:
    return ConnectionPool(
        url,
        connection_class=Connection[DictRow],
        kwargs={"row_factory": dict_row, "connect_timeout": max(1, round(timeout))},
        min_size=1,
        max_size=size,
        timeout=timeout,
        open=True,
    )


def get_pool(request: Request) -> Pool:
    pool: Pool = request.app.state.pool
    return pool


DbPool = Annotated[Pool, Depends(get_pool)]


@contextmanager
def as_user(pool: Pool, user_id: UUID) -> Iterator[Connection[DictRow]]:
    """A transaction that runs as whence_app on behalf of one signed-in user."""
    with pool.connection() as conn, conn.transaction():
        conn.execute("SET LOCAL ROLE whence_app")
        conn.execute("SET LOCAL statement_timeout = '5s'")
        conn.execute("SELECT set_config('app.user_id', %s, true)", (str(user_id),))
        yield conn
