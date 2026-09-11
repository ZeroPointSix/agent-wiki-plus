"""Alembic migration chain integrity.

CI only ever builds a schema through ``init_db`` (``alembic upgrade head``, on
top of ``0001``'s ``create_all``), so a stray ``down_revision`` that forks the
history or a migration that can't be re-run is invisible to it. These assert one
head (no divergence) and that the provenance migrations survive a real
down-then-up round trip, which nothing else exercises.
"""

from __future__ import annotations

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

from app.db.session import _alembic_config, get_engine

# The write-side migration. Its down_revision is the point we roll back to.
_PROVENANCE_LEDGER = "c7a1f0e3b2d9"
_PROVENANCE_TABLES = ("provenance_ledger", "source_ranges")


def _current_revision() -> str | None:
    with get_engine().connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def _has_table(name: str) -> bool:
    return sa.inspect(get_engine()).has_table(name)


def test_single_head_revision():
    """Exactly one head. A forked or dangling down_revision shows up here."""
    heads = ScriptDirectory.from_config(_alembic_config()).get_heads()
    assert len(heads) == 1, f"diverged migration history, expected one head, got {heads}"


def test_provenance_migrations_round_trip(tmp_db):
    """Downgrade past the provenance migrations then upgrade back to head.

    The fixture leaves the schema at head. Rolling back drops the source-range
    and ledger tables and re-running the chain recreates them, so a broken
    downgrade or a create that no longer matches the model fails here rather
    than only on a real production upgrade.
    """
    cfg = _alembic_config()
    script = ScriptDirectory.from_config(cfg)
    head = script.get_heads()[0]
    before_provenance = script.get_revision(_PROVENANCE_LEDGER).down_revision
    assert isinstance(before_provenance, str)  # linear parent, not a merge point

    assert _current_revision() == head
    assert all(_has_table(t) for t in _PROVENANCE_TABLES)

    command.downgrade(cfg, before_provenance)
    assert _current_revision() == before_provenance
    assert not any(_has_table(t) for t in _PROVENANCE_TABLES)

    command.upgrade(cfg, "head")
    assert _current_revision() == head
    assert all(_has_table(t) for t in _PROVENANCE_TABLES)


# The topic map. Its upgrade() short-circuits when the tables already exist, because ``0001``
# builds fresh databases from the models — so CI never runs the body, and only a rewind does.
_TOPIC_MAP = "a4d92e1c7f38"
_TOPIC_MAP_TABLES = ("need_maps", "topics", "aspects", "aspect_pages")


def test_topic_map_migration_round_trips(tmp_db):
    """Downgrade past the topic map then upgrade back, and check the shape it rebuilds.

    Two things this catches that nothing else does. The guard means ``upgrade()`` is dead code on
    a fresh database, so a create that drifted from the model would never surface; and the
    downgrade has to drop the tables in dependency order, which broke twice while these tables
    were gaining foreign keys.
    """
    cfg = _alembic_config()
    script = ScriptDirectory.from_config(cfg)
    head = script.get_heads()[0]
    parent = script.get_revision(_TOPIC_MAP).down_revision
    assert isinstance(parent, str)  # linear parent, not a merge point

    assert all(_has_table(t) for t in _TOPIC_MAP_TABLES)

    command.downgrade(cfg, parent)
    assert not any(_has_table(t) for t in _TOPIC_MAP_TABLES)

    command.upgrade(cfg, "head")
    assert _current_revision() == head
    assert all(_has_table(t) for t in _TOPIC_MAP_TABLES)

    inspector = sa.inspect(get_engine())
    # The columns the schema argues for: an aspect belongs to one topic, and the join to a need
    # carries no copy of it.
    assert {c["name"] for c in inspector.get_columns("aspects")} == {
        "id", "need_map_id", "topic_id", "name", "description",
    }
    assert {c["name"] for c in inspector.get_columns("aspect_pages")} == {
        "aspect_id", "doc_id", "need_name",
    }
    assert inspector.get_pk_constraint("aspect_pages")["constrained_columns"] == [
        "aspect_id", "doc_id", "need_name",
    ]
    assert "topic_aspects" not in inspector.get_table_names()


# Fingerprint index. ``0001`` create_all already materializes the column, so
# CI never executes the upgrade body unless we rewind past this revision.
_MCP_FINGERPRINT = "c4e8a1b2d3f6"


def test_mcp_token_fingerprint_migration_round_trips(tmp_db):
    """Downgrade past the fingerprint migration then upgrade, and check the shape.

    Fresh databases skip ``upgrade()`` because the column already exists. A
    rewind is the only way to run add-column / create-index and to prove
    multiple NULL fingerprints remain legal afterwards (legacy bcrypt-only
    rows).
    """
    from sqlalchemy.exc import IntegrityError

    from app.db.models import McpToken
    from app.db.session import session

    from tests._seed import seed_user

    cfg = _alembic_config()
    script = ScriptDirectory.from_config(cfg)
    head = script.get_heads()[0]
    parent = script.get_revision(_MCP_FINGERPRINT).down_revision
    assert isinstance(parent, str)

    inspector = sa.inspect(get_engine())
    assert "token_fingerprint" in {c["name"] for c in inspector.get_columns("mcp_tokens")}
    assert "idx_mcp_tokens_fingerprint" in {
        i["name"] for i in inspector.get_indexes("mcp_tokens")
    }

    command.downgrade(cfg, parent)
    inspector = sa.inspect(get_engine())
    inspector.clear_cache()
    assert "token_fingerprint" not in {
        c["name"] for c in inspector.get_columns("mcp_tokens")
    }
    assert "idx_mcp_tokens_fingerprint" not in {
        i["name"] for i in inspector.get_indexes("mcp_tokens")
    }

    command.upgrade(cfg, "head")
    assert _current_revision() == head
    inspector = sa.inspect(get_engine())
    inspector.clear_cache()
    columns = {c["name"]: c for c in inspector.get_columns("mcp_tokens")}
    assert "token_fingerprint" in columns
    assert columns["token_fingerprint"]["nullable"] is True
    indexes = {i["name"]: i for i in inspector.get_indexes("mcp_tokens")}
    fingerprint_idx = indexes["idx_mcp_tokens_fingerprint"]
    assert fingerprint_idx["unique"] is True
    assert fingerprint_idx["column_names"] == ["token_fingerprint"]

    uid = seed_user(uid="u1", email="u1@x.com")
    with session() as s:
        s.add(
            McpToken(
                id="mtk_legacy_a",
                user_id=uid,
                name="legacy-a",
                token_hash="hash-a",
                token_fingerprint=None,
            )
        )
        s.add(
            McpToken(
                id="mtk_legacy_b",
                user_id=uid,
                name="legacy-b",
                token_hash="hash-b",
                token_fingerprint=None,
            )
        )

    with pytest.raises(IntegrityError):
        with session() as s:
            s.add(
                McpToken(
                    id="mtk_dup_a",
                    user_id=uid,
                    name="dup-a",
                    token_hash="hash-dup-a",
                    token_fingerprint="abc" * 8 + "a",
                )
            )
            s.add(
                McpToken(
                    id="mtk_dup_b",
                    user_id=uid,
                    name="dup-b",
                    token_hash="hash-dup-b",
                    token_fingerprint="abc" * 8 + "a",
                )
            )
