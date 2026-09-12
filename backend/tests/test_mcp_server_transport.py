"""Tests for the inbound MCP transport — bearer auth, session
handshake, JSON-RPC dispatch."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError, TimeoutError as SqlAlchemyTimeoutError

from app.auth import mcp_tokens as tokens_repo
from app.auth.mcp_tokens import TOKEN_PREFIX
from app.db import models as orm
from app.db.session import session as db_session
from app.main import create_app
from app.mcp_server import session as mcp_session
from app.mcp_server import transport as mcp_transport

from tests._seed import seed_user


@pytest.fixture
def client(tmp_db):
    mcp_session.reset_for_tests()
    yield TestClient(create_app())
    mcp_session.reset_for_tests()


def _mint_token(uid: str, name: str = "k") -> str:
    _, raw = tokens_repo.create(uid, name)
    return raw


def _initialize_request(req_id: int = 1) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "0"},
        },
    }


# --------------------------------------------------------------------------- #
# Bearer auth                                                                 #
# --------------------------------------------------------------------------- #


def test_no_auth_header_is_401(client):
    res = client.post("/api/mcp", json=_initialize_request())
    assert res.status_code == 401
    assert res.json()["error"]


def test_non_bearer_scheme_is_401(client):
    res = client.post(
        "/api/mcp",
        json=_initialize_request(),
        headers={"Authorization": "Basic abc:def"},
    )
    assert res.status_code == 401


def test_unknown_token_is_401(client):
    seed_user(uid="u1", email="u1@x.com")
    res = client.post(
        "/api/mcp",
        json=_initialize_request(),
        headers={"Authorization": f"Bearer {TOKEN_PREFIX}{'z' * 32}"},
    )
    assert res.status_code == 401


def test_revoked_token_is_401(client):
    uid = seed_user(uid="u1", email="u1@x.com")
    token_id, raw = tokens_repo.create(uid, "k")
    assert tokens_repo.revoke(token_id, uid)

    res = client.post(
        "/api/mcp",
        json=_initialize_request(),
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert res.status_code == 401


def test_auth_pool_timeout_is_attributable_503(client, monkeypatch):
    def fail(_raw: str):
        raise SqlAlchemyTimeoutError("pool exhausted")

    monkeypatch.setattr(tokens_repo, "verify", fail)
    res = client.post(
        "/api/mcp",
        json=_initialize_request(),
        headers={"Authorization": f"Bearer {TOKEN_PREFIX}{'z' * 32}"},
    )

    assert res.status_code == 503
    assert res.json()["code"] == "database_pool_timeout"


def test_auth_operational_error_is_attributable_503(client, monkeypatch):
    def fail(_raw: str):
        raise OperationalError("SELECT 1", {}, Exception("could not connect"))

    monkeypatch.setattr(tokens_repo, "verify", fail)
    res = client.post(
        "/api/mcp",
        json=_initialize_request(),
        headers={"Authorization": f"Bearer {TOKEN_PREFIX}{'z' * 32}"},
    )

    assert res.status_code == 503
    assert res.json()["code"] == "database_unavailable"


def test_database_jsonrpc_codes_avoid_mcp_sdk_registry():
    reserved = {-32000, -32001, -32002, -32020, -32021, -32022, -32042}
    assert mcp_transport.DATABASE_POOL_TIMEOUT == -32010
    assert mcp_transport.DATABASE_UNAVAILABLE == -32011
    assert mcp_transport.DATABASE_POOL_TIMEOUT not in reserved
    assert mcp_transport.DATABASE_UNAVAILABLE not in reserved


# --------------------------------------------------------------------------- #
# initialize handshake                                                        #
# --------------------------------------------------------------------------- #


def test_initialize_returns_capabilities_and_session_id(client):
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)

    res = client.post(
        "/api/mcp",
        json=_initialize_request(req_id=42),
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert res.status_code == 200

    body = res.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 42
    assert "result" in body
    assert body["result"]["protocolVersion"] == "2025-03-26"
    assert body["result"]["serverInfo"]["name"] == "agent-wiki"

    caps = body["result"]["capabilities"]
    assert "tools" in caps
    assert caps["resources"]["subscribe"] is True

    sess_id = res.headers.get("Mcp-Session-Id")
    assert sess_id is not None
    assert sess_id.startswith("mcps_")


def test_initialize_creates_session_for_token_user(client):
    """Side-effect proof that the bearer user is threaded through
    correctly: the session in the registry must be tied to the bearer
    token's owner."""
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)

    res = client.post(
        "/api/mcp",
        json=_initialize_request(),
        headers={"Authorization": f"Bearer {raw}"},
    )
    sess_id = res.headers["Mcp-Session-Id"]

    sess = mcp_session.get(sess_id)
    assert sess is not None
    assert sess.user_id == uid
    assert sess.initialized is False  # client must ack via notifications/initialized


def test_cached_session_observes_initialization_from_another_worker(client, monkeypatch):
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)
    auth = {"Authorization": f"Bearer {raw}"}

    init_res = client.post("/api/mcp", json=_initialize_request(), headers=auth)
    sess_id = init_res.headers["Mcp-Session-Id"]
    cached = mcp_session.get(sess_id)
    assert cached is not None and cached.initialized is False

    # Simulate notifications/initialized being handled by another worker.
    with db_session() as s:
        row = s.get(orm.McpSession, sess_id)
        assert row is not None
        row.initialized = True

    list_res = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": 7, "method": "tools/list"},
        headers={**auth, "Mcp-Session-Id": sess_id},
    )

    assert list_res.status_code == 200
    assert "result" in list_res.json()

    def fail_db_session():
        raise AssertionError("initialized session should have been written back to the local cache")

    with monkeypatch.context() as cache_only:
        cache_only.setattr(mcp_session, "db_session", fail_db_session)
        refreshed = mcp_session.get(sess_id)
    assert refreshed is not None and refreshed.initialized is True

    monkeypatch.setattr(
        mcp_session, "_now", lambda: datetime(2100, 1, 1, tzinfo=timezone.utc)
    )
    assert mcp_session.get(sess_id) is None
    assert sess_id not in mcp_session.all_session_ids()


# --------------------------------------------------------------------------- #
# Post-initialize flow                                                        #
# --------------------------------------------------------------------------- #


def test_full_handshake_then_tools_list(client):
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)
    auth = {"Authorization": f"Bearer {raw}"}

    res = client.post("/api/mcp", json=_initialize_request(), headers=auth)
    sess_id = res.headers["Mcp-Session-Id"]

    res = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers={**auth, "Mcp-Session-Id": sess_id},
    )
    assert res.status_code == 202
    assert res.content == b""

    sess = mcp_session.get(sess_id)
    assert sess is not None and sess.initialized is True

    res = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": 7, "method": "tools/list"},
        headers={**auth, "Mcp-Session-Id": sess_id},
    )
    body = res.json()
    assert body["id"] == 7
    assert isinstance(body["result"]["tools"], list)
    assert all("name" in t and "inputSchema" in t for t in body["result"]["tools"])


def test_ping_returns_empty_result(client):
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)
    auth = {"Authorization": f"Bearer {raw}"}

    res = client.post("/api/mcp", json=_initialize_request(), headers=auth)
    sess_id = res.headers["Mcp-Session-Id"]
    client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers={**auth, "Mcp-Session-Id": sess_id},
    )

    res = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": 99, "method": "ping"},
        headers={**auth, "Mcp-Session-Id": sess_id},
    )
    assert res.json() == {"jsonrpc": "2.0", "id": 99, "result": {}}


# --------------------------------------------------------------------------- #
# Protocol errors                                                             #
# --------------------------------------------------------------------------- #


def test_request_without_session_id_is_protocol_error(client):
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)

    res = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {raw}"},
    )
    body = res.json()
    assert "error" in body
    # JSON-RPC 2.0 "Invalid Request"
    assert body["error"]["code"] == -32600
    assert "Mcp-Session-Id" in body["error"]["message"]


def test_unknown_session_id_request_is_404(client):
    # A request bearing an Mcp-Session-Id the server doesn't recognize
    # (e.g. the session died on a backend restart) must return HTTP 404 so
    # the client re-initializes, per the MCP Streamable HTTP spec.
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)

    res = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": 7, "method": "tools/list"},
        headers={
            "Authorization": f"Bearer {raw}",
            "Mcp-Session-Id": "mcps_does-not-exist",
        },
    )
    assert res.status_code == 404
    assert res.json()["error"]["code"] == -32600


def test_unknown_session_id_sse_is_404(client):
    # Same rule on the SSE GET stream — a stale session id reconnecting
    # gets 404, not 400, so the client knows to start a fresh session.
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)

    res = client.get(
        "/api/mcp",
        headers={
            "Authorization": f"Bearer {raw}",
            "Mcp-Session-Id": "mcps_does-not-exist",
        },
    )
    assert res.status_code == 404


def test_uninitialized_session_sse_is_400(client):
    # A *known* session that simply hasn't sent notifications/initialized
    # yet is a protocol-ordering error (400), distinct from an unknown id.
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)
    auth = {"Authorization": f"Bearer {raw}"}

    res = client.post("/api/mcp", json=_initialize_request(), headers=auth)
    sess_id = res.headers["Mcp-Session-Id"]

    res = client.get("/api/mcp", headers={**auth, "Mcp-Session-Id": sess_id})
    assert res.status_code == 400


def test_method_before_initialized_ack_is_error(client):
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)
    auth = {"Authorization": f"Bearer {raw}"}

    res = client.post("/api/mcp", json=_initialize_request(), headers=auth)
    sess_id = res.headers["Mcp-Session-Id"]

    # tools/list without sending notifications/initialized first
    res = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        headers={**auth, "Mcp-Session-Id": sess_id},
    )
    body = res.json()
    assert body["error"]["code"] == -32600
    assert "not initialized" in body["error"]["message"]


def test_unknown_method_is_method_not_found(client):
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)
    auth = {"Authorization": f"Bearer {raw}"}

    res = client.post("/api/mcp", json=_initialize_request(), headers=auth)
    sess_id = res.headers["Mcp-Session-Id"]
    client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers={**auth, "Mcp-Session-Id": sess_id},
    )

    res = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": 3, "method": "nonsense/totally-fake"},
        headers={**auth, "Mcp-Session-Id": sess_id},
    )
    body = res.json()
    assert body["error"]["code"] == -32601


def test_dispatch_pool_timeout_has_stable_jsonrpc_code(client, monkeypatch):
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)
    auth = {"Authorization": f"Bearer {raw}"}
    res = client.post("/api/mcp", json=_initialize_request(), headers=auth)
    sess_id = res.headers["Mcp-Session-Id"]

    def fail(_session_id: str):
        raise SqlAlchemyTimeoutError("pool exhausted")

    monkeypatch.setattr(mcp_session, "get", fail)
    res = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
        headers={**auth, "Mcp-Session-Id": sess_id},
    )

    assert res.status_code == 200
    assert res.json()["error"]["code"] == -32010


def test_dispatch_operational_error_has_stable_jsonrpc_code(client, monkeypatch):
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)
    auth = {"Authorization": f"Bearer {raw}"}
    res = client.post("/api/mcp", json=_initialize_request(), headers=auth)
    sess_id = res.headers["Mcp-Session-Id"]

    def fail(_session_id: str):
        raise OperationalError("SELECT 1", {}, Exception("could not connect"))

    monkeypatch.setattr(mcp_session, "get", fail)
    res = client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
        headers={**auth, "Mcp-Session-Id": sess_id},
    )

    assert res.status_code == 200
    assert res.json()["error"]["code"] == -32011


def test_missing_jsonrpc_field_is_invalid_request(client):
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)

    res = client.post(
        "/api/mcp",
        json={"id": 1, "method": "initialize", "params": {}},
        headers={"Authorization": f"Bearer {raw}"},
    )
    body = res.json()
    assert body["error"]["code"] == -32600


def test_non_dict_body_is_400(client):
    uid = seed_user(uid="u1", email="u1@x.com")
    raw = _mint_token(uid)

    res = client.post(
        "/api/mcp",
        json=["not", "an", "object"],
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert res.status_code == 400
