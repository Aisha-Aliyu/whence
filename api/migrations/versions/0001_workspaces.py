"""Workspaces and memberships, with row-level security.

Revision ID: 0001
Revises:
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

UPGRADE = """
-- Our tables live in their own schema. Supabase exposes the public schema
-- through its Data API, and nothing of ours should be reachable that way.
CREATE SCHEMA IF NOT EXISTS whence;

-- The API runs every request as this role. It cannot log in, owns nothing and
-- cannot bypass row-level security.
DO $$ BEGIN
    CREATE ROLE whence_app NOLOGIN NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
GRANT whence_app TO CURRENT_USER;

CREATE TYPE whence.workspace_role AS ENUM ('owner', 'admin', 'member');

CREATE TABLE whence.workspaces (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE whence.memberships (
    workspace_id uuid NOT NULL REFERENCES whence.workspaces (id) ON DELETE CASCADE,
    user_id uuid NOT NULL,
    role whence.workspace_role NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX memberships_user_id ON whence.memberships (user_id);

-- The signed-in user for this transaction, set by the API. NULL when unset, so
-- every policy below matches nothing.
CREATE FUNCTION whence.current_user_id() RETURNS uuid
LANGUAGE sql STABLE
AS $$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;

ALTER TABLE whence.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE whence.workspaces FORCE ROW LEVEL SECURITY;
ALTER TABLE whence.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE whence.memberships FORCE ROW LEVEL SECURITY;

-- People see their own memberships.
CREATE POLICY memberships_select ON whence.memberships FOR SELECT TO whence_app
    USING (user_id = whence.current_user_id());

-- The creator of a workspace adds themselves as its owner.
CREATE POLICY memberships_insert_owner ON whence.memberships FOR INSERT TO whence_app
    WITH CHECK (
        user_id = whence.current_user_id()
        AND role = 'owner'
        AND EXISTS (
            SELECT 1 FROM whence.workspaces w
            WHERE w.id = workspace_id AND w.created_by = whence.current_user_id()
        )
    );

-- Members see their workspaces. The creator also sees theirs, so the owner
-- membership can be added right after the workspace is created.
CREATE POLICY workspaces_select ON whence.workspaces FOR SELECT TO whence_app
    USING (
        created_by = whence.current_user_id()
        OR EXISTS (
            SELECT 1 FROM whence.memberships m
            WHERE m.workspace_id = id AND m.user_id = whence.current_user_id()
        )
    );

CREATE POLICY workspaces_insert ON whence.workspaces FOR INSERT TO whence_app
    WITH CHECK (created_by = whence.current_user_id());

CREATE POLICY workspaces_update ON whence.workspaces FOR UPDATE TO whence_app
    USING (
        EXISTS (
            SELECT 1 FROM whence.memberships m
            WHERE m.workspace_id = id AND m.user_id = whence.current_user_id()
              AND m.role IN ('owner', 'admin')
        )
    );

CREATE POLICY workspaces_delete ON whence.workspaces FOR DELETE TO whence_app
    USING (
        EXISTS (
            SELECT 1 FROM whence.memberships m
            WHERE m.workspace_id = id AND m.user_id = whence.current_user_id()
              AND m.role = 'owner'
        )
    );

GRANT USAGE ON SCHEMA whence TO whence_app;
GRANT EXECUTE ON FUNCTION whence.current_user_id() TO whence_app;
GRANT SELECT, INSERT, DELETE ON whence.workspaces TO whence_app;
GRANT UPDATE (name) ON whence.workspaces TO whence_app;
GRANT SELECT, INSERT ON whence.memberships TO whence_app;
"""

DOWNGRADE = """
-- One statement: each table's policies refer to the other table.
DROP TABLE whence.memberships, whence.workspaces;
DROP TYPE whence.workspace_role;
DROP FUNCTION whence.current_user_id();
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
