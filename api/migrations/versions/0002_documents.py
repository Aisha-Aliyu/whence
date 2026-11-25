"""Documents and their passages, with row-level security.

Revision ID: 0002
Revises: 0001
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

UPGRADE = """
-- pgvector stores the embeddings. Supabase keeps extensions in this schema.
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA extensions;

CREATE TYPE whence.document_status AS ENUM ('processing', 'ready', 'failed');

CREATE TABLE whence.documents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL REFERENCES whence.workspaces (id) ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    kind text NOT NULL CHECK (kind IN ('pdf', 'markdown', 'text')),
    size_bytes integer NOT NULL CHECK (size_bytes > 0),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    pages integer CHECK (pages > 0),
    status whence.document_status NOT NULL DEFAULT 'processing',
    uploaded_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- The same file uploaded twice is one document.
    UNIQUE (workspace_id, sha256),
    -- Lets each passage name its document and workspace together.
    UNIQUE (id, workspace_id)
);

CREATE TABLE whence.passages (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    page integer CHECK (page > 0),
    section text,
    text text NOT NULL CHECK (char_length(text) BETWEEN 1 AND 4000),
    embedding extensions.vector(384),
    search tsvector GENERATED ALWAYS AS (to_tsvector('english', text)) STORED,
    UNIQUE (document_id, ordinal),
    -- A passage can never claim a workspace other than its document's.
    FOREIGN KEY (document_id, workspace_id)
        REFERENCES whence.documents (id, workspace_id) ON DELETE CASCADE
);
CREATE INDEX passages_workspace_id ON whence.passages (workspace_id);
CREATE INDEX passages_search ON whence.passages USING gin (search);

-- True when the signed-in user holds one of these roles in the workspace.
CREATE FUNCTION whence.has_role(workspace uuid, roles whence.workspace_role[])
RETURNS boolean
LANGUAGE sql STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM whence.memberships m
        WHERE m.workspace_id = workspace AND m.user_id = whence.current_user_id()
          AND m.role = ANY (roles)
    )
$$;

ALTER TABLE whence.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE whence.documents FORCE ROW LEVEL SECURITY;
ALTER TABLE whence.passages ENABLE ROW LEVEL SECURITY;
ALTER TABLE whence.passages FORCE ROW LEVEL SECURITY;

-- Every member reads a workspace's documents and passages.
CREATE POLICY documents_select ON whence.documents FOR SELECT TO whence_app
    USING (whence.has_role(workspace_id, '{owner,admin,member}'));
CREATE POLICY passages_select ON whence.passages FOR SELECT TO whence_app
    USING (whence.has_role(workspace_id, '{owner,admin,member}'));

-- Only owners and admins add, process and delete them.
CREATE POLICY documents_insert ON whence.documents FOR INSERT TO whence_app
    WITH CHECK (
        uploaded_by = whence.current_user_id()
        AND whence.has_role(workspace_id, '{owner,admin}')
    );
CREATE POLICY documents_update ON whence.documents FOR UPDATE TO whence_app
    USING (whence.has_role(workspace_id, '{owner,admin}'));
CREATE POLICY documents_delete ON whence.documents FOR DELETE TO whence_app
    USING (whence.has_role(workspace_id, '{owner,admin}'));
CREATE POLICY passages_insert ON whence.passages FOR INSERT TO whence_app
    WITH CHECK (whence.has_role(workspace_id, '{owner,admin}'));
CREATE POLICY passages_update ON whence.passages FOR UPDATE TO whence_app
    USING (whence.has_role(workspace_id, '{owner,admin}'));

GRANT USAGE ON SCHEMA extensions TO whence_app;
GRANT EXECUTE ON FUNCTION whence.has_role(uuid, whence.workspace_role[])
    TO whence_app;
GRANT SELECT, INSERT, DELETE ON whence.documents TO whence_app;
GRANT UPDATE (status) ON whence.documents TO whence_app;
GRANT SELECT, INSERT ON whence.passages TO whence_app;
GRANT UPDATE (embedding) ON whence.passages TO whence_app;
"""

# The vector extension stays: other database objects may use it, and Supabase
# manages its extensions schema.
DOWNGRADE = """
DROP TABLE whence.passages, whence.documents;
DROP FUNCTION whence.has_role(uuid, whence.workspace_role[]);
DROP TYPE whence.document_status;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
