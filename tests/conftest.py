"""Test helpers: a fake DNS resolver and a mock HTTP transport, so tests never touch the network."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from collections.abc import Callable

import dns.resolver
import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Settings  # noqa: E402
from app.core import Context  # noqa: E402


class FakeRdata:
    def __init__(self, text: str):
        self.text = text
        self.strings = [text.encode()]

    def to_text(self) -> str:
        return self.text


class FakeResolver:
    """``records`` maps (name, type) -> list of answers. Names not present at all are NXDOMAIN."""

    def __init__(self, records: dict[tuple[str, str], list[str]]):
        self.records = records
        self.names = {name for name, _ in records}

    async def resolve(self, name: str, rtype: str):
        name = name.rstrip(".")
        if (name, rtype) in self.records:
            return [FakeRdata(t) for t in self.records[(name, rtype)]]
        if name in self.names:
            raise dns.resolver.NoAnswer()
        raise dns.resolver.NXDOMAIN()


Handler = Callable[[httpx.Request], httpx.Response]


def routes(table: dict[str, object]) -> Handler:
    """Mock transport handler: match on 'host/path' prefix, value is JSON data, an int status, or a Response."""

    def handler(request: httpx.Request) -> httpx.Response:
        key = request.url.host + request.url.path
        for prefix, value in sorted(table.items(), key=lambda kv: -len(kv[0])):
            if key.startswith(prefix):
                if isinstance(value, httpx.Response):
                    return value
                if isinstance(value, int):
                    return httpx.Response(value, json={"error": "mock"})
                return httpx.Response(200, content=json.dumps(value).encode(),
                                      headers={"content-type": "application/json"})
        return httpx.Response(404, json={"error": f"no mock for {key}"})

    return handler


def make_ctx(handler: Handler | None = None, records=None, **settings) -> Context:
    transport = httpx.MockTransport(handler or routes({}))
    return Context(
        http=httpx.AsyncClient(transport=transport, follow_redirects=True),
        settings=Settings(**{"rate_limit": 0, **settings}),
        resolver=FakeResolver(records or {}),
    )


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def ctx_factory():
    return make_ctx
