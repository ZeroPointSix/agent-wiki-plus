"""indexed MCP token fingerprints

Existing bcrypt-only rows are backfilled lazily after their next successful
authentication because their raw tokens cannot be reconstructed.

Revision ID: c4e8a1b2d3f6
Revises: b3d7f1a2c4e5
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "c4e8a1b2d3f6"
down_revision: str | None = "b3d7f1a2c4e5"
branch_labels: str | None = None
depends_on: str | None = None

_TABLE = "mcp_tokens"
_COLUMN = "token_fingerprint"
_INDEX = "idx_mcp_tokens_fingerprint"


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns(_TABLE)}
    if _COLUMN not in columns:
        op.add_column(_TABLE, sa.Column(_COLUMN, sa.Text(), nullable=True))

    inspector = sa.inspect(op.get_bind())
    indexes = {index["name"] for index in inspector.get_indexes(_TABLE)}
    if _INDEX not in indexes:
        op.create_index(
            _INDEX,
            _TABLE,
            [_COLUMN],
            unique=True,
            postgresql_where=sa.text("token_fingerprint IS NOT NULL"),
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    indexes = {index["name"] for index in inspector.get_indexes(_TABLE)}
    if _INDEX in indexes:
        op.drop_index(_INDEX, table_name=_TABLE)
    columns = {column["name"] for column in inspector.get_columns(_TABLE)}
    if _COLUMN in columns:
        op.drop_column(_TABLE, _COLUMN)
