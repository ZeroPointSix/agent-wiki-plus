"""MCP-token repo — SQLAlchemy ORM. Free functions over ``McpToken``.

Tokens are personal API keys an MCP client (Claude Code, Cursor, Codex,
…) presents in an ``Authorization: Bearer mcp_<token>`` header to talk
to the inbound MCP server.

The raw token is shown to the user **once** at creation; the DB stores a
bcrypt verifier plus a SHA-256 lookup fingerprint. The fingerprint is safe to
index because raw tokens carry 192 bits of entropy, while bcrypt remains the
authority for verification. Legacy rows are backfilled after their first
successful verification.

See ``local_data/wiki/mcp-server/mcp-server.md`` for the full design.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from app.auth import User
from app.auth.passwords import hash_password, verify_password
from app.db.models import McpToken, User as UserRow
from app.db.session import session

log = logging.getLogger(__name__)

TOKEN_PREFIX = "mcp_"
"""Distinguishable prefix so leaked tokens are obvious in logs and so the
token can't be confused with a session cookie or another credential."""

_TOKEN_BYTES = 24
"""24 bytes → 32 base64url chars after stripping padding. Plenty of
entropy; short enough to copy-paste without wrap."""


def _fingerprint(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class _Candidate:
    id: str
    user_id: str
    name: str
    token_hash: str


def _candidate(row: McpToken) -> _Candidate:
    return _Candidate(row.id, row.user_id, row.name, row.token_hash)


# --------------------------------------------------------------------------- #
# Read                                                                        #
# --------------------------------------------------------------------------- #


def _to_dict(t: McpToken) -> dict[str, Any]:
    return {
        "id": t.id,
        "user_id": t.user_id,
        "name": t.name,
        "created_at": t.created_at,
        "last_used_at": t.last_used_at,
    }


def list_for_user(user_id: str) -> list[dict[str, Any]]:
    """Tokens for a given user, newest first. Hashes are not returned."""
    with session() as s:
        rows = s.scalars(
            select(McpToken)
            .where(McpToken.user_id == user_id)
            .order_by(McpToken.created_at.desc())
        ).all()
        return [_to_dict(t) for t in rows]


# --------------------------------------------------------------------------- #
# Mutate                                                                      #
# --------------------------------------------------------------------------- #


def create(user_id: str, name: str) -> tuple[str, str]:
    """Mint a new token. Returns ``(token_id, raw_token)`` — the raw
    value is the only place the plaintext exists; the caller must show
    it to the user immediately and never persist it.

    Trims ``name`` and rejects empty values. Names don't have to be
    unique (the user may want two tokens both labelled "laptop" while
    rotating); ``id`` is the addressable handle.
    """
    name = name.strip()
    if not name:
        raise ValueError("name is required")

    raw = TOKEN_PREFIX + secrets.token_urlsafe(_TOKEN_BYTES)
    token_id = "mtk_" + uuid.uuid4().hex[:12]

    fingerprint = _fingerprint(raw)
    with session() as s:
        s.add(
            McpToken(
                id=token_id,
                user_id=user_id,
                name=name,
                token_hash=hash_password(raw),
                token_fingerprint=fingerprint,
            )
        )
    log.info("mcp token created id=%s user_id=%s name=%s", token_id, user_id, name)
    return token_id, raw


def revoke(token_id: str, user_id: str) -> bool:
    """Revoke a token. Returns ``True`` if a row was deleted, ``False``
    if no token with that id exists for this user (used so the API can
    return 404 vs 204 cleanly).
    """
    with session() as s:
        t = s.get(McpToken, token_id)
        if t is None or t.user_id != user_id:
            return False
        s.delete(t)
    log.info("mcp token revoked id=%s user_id=%s", token_id, user_id)
    return True


# --------------------------------------------------------------------------- #
# Verify                                                                      #
# --------------------------------------------------------------------------- #


def verify(raw_token: str) -> tuple[User, str] | None:
    """Resolve a raw bearer token to ``(User, agent_name)``, or ``None``.

    Indexed tokens require one bcrypt check. Legacy rows without a fingerprint
    are scanned once, then lazily backfilled. Candidate hashes are detached
    before bcrypt so CPU-bound verification never occupies a pooled DB
    connection. A second transaction confirms the token still exists before
    returning, preserving immediate revocation semantics.

    On success, also bumps ``last_used_at`` so the UI can show "last
    used 3 minutes ago" without an extra audit trail.
    """
    if not raw_token or not raw_token.startswith(TOKEN_PREFIX):
        return None

    fingerprint = _fingerprint(raw_token)
    lookup_started = time.perf_counter()
    with session() as s:
        exact = s.scalar(
            select(McpToken).where(McpToken.token_fingerprint == fingerprint)
        )
        legacy = (
            []
            if exact is not None
            else [
                _candidate(row)
                for row in s.scalars(
                    select(McpToken).where(McpToken.token_fingerprint.is_(None))
                ).all()
            ]
        )
        candidates = [_candidate(exact)] if exact is not None else legacy
    lookup_ms = (time.perf_counter() - lookup_started) * 1000

    bcrypt_started = time.perf_counter()
    match = next(
        (
            candidate
            for candidate in candidates
            if verify_password(raw_token, candidate.token_hash)
        ),
        None,
    )
    bcrypt_ms = (time.perf_counter() - bcrypt_started) * 1000
    if match is None:
        log.debug(
            "mcp auth miss lookup_ms=%.1f bcrypt_ms=%.1f candidates=%d legacy=%s",
            lookup_ms,
            bcrypt_ms,
            len(candidates),
            exact is None,
        )
        return None

    finalize_started = time.perf_counter()
    with session() as s:
        current = s.get(McpToken, match.id)
        if current is None:
            return None
        if current.token_fingerprint not in (None, fingerprint):
            return None
        if current.token_fingerprint is None:
            current.token_fingerprint = fingerprint

        user = s.get(UserRow, current.user_id)
        if user is None:
            log.warning(
                "mcp token %s resolved to missing user %s; treating as invalid",
                current.id,
                current.user_id,
            )
            return None

        current.last_used_at = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        result = (
            User(
                id=user.id,
                email=user.email,
                name=user.name,
                is_admin=bool(user.is_admin),
            ),
            current.name,
        )
    log.debug(
        "mcp auth success lookup_ms=%.1f bcrypt_ms=%.1f finalize_ms=%.1f "
        "candidates=%d legacy=%s",
        lookup_ms,
        bcrypt_ms,
        (time.perf_counter() - finalize_started) * 1000,
        len(candidates),
        exact is None,
    )
    return result
