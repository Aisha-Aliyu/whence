"""Runs migrations against DATABASE_URL, as the database owner, never as the API."""

import os

from alembic import context
from sqlalchemy import create_engine, pool


def database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise SystemExit("Set DATABASE_URL to the database to migrate.")
    return url.replace("postgresql://", "postgresql+psycopg://", 1)


def run() -> None:
    engine = create_engine(database_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        # Alembic's own version table lives in our schema too, out of the Data API.
        connection.exec_driver_sql("CREATE SCHEMA IF NOT EXISTS whence")
        connection.commit()
        context.configure(connection=connection, version_table_schema="whence")
        with context.begin_transaction():
            context.run_migrations()


run()
