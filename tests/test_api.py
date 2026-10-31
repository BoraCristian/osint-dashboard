import json

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from conftest import make_ctx, routes

HTTP_MOCKS = {
    "api.github.com/users/": {"login": "neo", "name": "Neo"},
    "api.chess.com/": {"name": "Neo"},
}


@pytest.fixture
def client():
    app = create_app(Settings(rate_limit=0), context=make_ctx(routes(HTTP_MOCKS)))
    with TestClient(app) as c:
        yield c


def parse_sse(text: str):
    events = []
    for chunk in text.strip().split("\n\n"):
        lines = dict(line.split(": ", 1) for line in chunk.splitlines())
        events.append((lines["event"], json.loads(lines["data"])))
    return events


def test_index_and_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "OSINT Dashboard" in r.text
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert client.get("/static/app.js").status_code == 200
    # Swagger UI needs its CDN scripts, so /docs is the one page without the strict CSP
    docs = client.get("/docs")
    assert docs.status_code == 200 and "content-security-policy" not in docs.headers


def test_modules_endpoint_reports_keys(client):
    mods = {m["id"]: m for m in client.get("/api/modules").json()}
    assert mods["dns"]["enabled"] is True and mods["dns"]["needs_key"] is False
    assert mods["breaches"]["enabled"] is False and mods["breaches"]["needs_key"] is True


def test_lookup_json(client):
    r = client.get("/api/lookup", params={"q": "@neo"})
    assert r.status_code == 200
    body = r.json()
    assert body["target"] == {"raw": "@neo", "kind": "username", "value": "neo", "domain": None}
    (accounts,) = body["modules"]
    assert accounts["id"] == "accounts" and accounts["status"] == "ok"
    assert {f["site"] for f in accounts["data"]["found"]} == {"GitHub", "Chess.com"}
    assert body["summary"]["info"] == 1


def test_stream_sends_start_modules_done(client):
    r = client.get("/api/stream", params={"q": "neo", "type": "username"})
    assert r.headers["content-type"].startswith("text/event-stream")
    events = parse_sse(r.text)
    assert [e for e, _ in events] == ["start", "module", "done"]
    assert events[0][1]["modules"] == [{"id": "accounts", "title": "Accounts with this username"}]


@pytest.mark.parametrize("params, message", [
    ({"q": "10.0.0.1"}, "private or reserved"),
    ({"q": "169.254.169.254"}, "private or reserved"),
    ({"q": "not valid!"}, "Could not tell what that is"),
    ({"q": "x", "type": "spaceship"}, "Unknown target type"),
    ({"q": "nope", "type": "ip"}, "not a valid IP address"),
])
def test_bad_requests(client, params, message):
    r = client.get("/api/lookup", params=params)
    assert r.status_code == 400 and message in r.json()["error"]
    assert client.get("/api/stream", params=params).status_code == 400


def test_error_messages_never_echo_the_input(client):
    for q, kind in [("<script>alert(1)</script>", None), ("evil<b>@@x", "email"), ("<img src=x>", "domain")]:
        params = {"q": q, **({"type": kind} if kind else {})}
        error = client.get("/api/lookup", params=params).json()["error"]
        assert "<" not in error and q not in error


def test_module_crash_details_stay_on_the_server(monkeypatch):
    from app.core import MODULES, Module

    async def broken(target, ctx):
        raise RuntimeError("secret internal detail: /srv/app/keys.txt")

    monkeypatch.setitem(MODULES, "accounts", Module("accounts", "Accounts", frozenset({"username"}), broken))
    app = create_app(Settings(rate_limit=0), context=make_ctx(routes(HTTP_MOCKS)))
    with TestClient(app) as c:
        (report,) = c.get("/api/lookup", params={"q": "neo"}).json()["modules"]
    assert report["status"] == "error"
    assert "secret" not in report["summary"] and "RuntimeError" not in report["summary"]


def test_rate_limit():
    app = create_app(Settings(rate_limit=2), context=make_ctx(routes(HTTP_MOCKS)))
    with TestClient(app) as c:
        codes = [c.get("/api/lookup", params={"q": "neo"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
