"""FastAPI application: JSON API, a Server-Sent Events stream and the static dashboard."""

from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import dns.asyncresolver
import httpx
from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from . import modules as _modules  # noqa: F401  (registers the lookup modules)
from .config import ROOT, Settings
from .core import MODULES, SEVERITIES, Context, TTLCache, modules_for, run_all, sort_findings
from .netguard import is_public
from .targets import MESSAGES, InvalidTarget, Target, parse_target

STATIC = ROOT / "static"


def make_context(settings: Settings) -> Context:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6.0
    http = httpx.AsyncClient(
        headers={"User-Agent": settings.user_agent, "Accept": "application/json, */*"},
        timeout=httpx.Timeout(15.0),
        follow_redirects=True,
        limits=httpx.Limits(max_connections=50),
    )
    return Context(http=http, settings=settings, resolver=resolver)


class RateLimiter:
    """Sliding window: at most ``limit`` lookups per client per minute (0 disables it)."""

    def __init__(self, limit: int, window: float = 60.0):
        self.limit, self.window = limit, window
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, client: str) -> bool:
        if self.limit <= 0:
            return True
        now = time.monotonic()
        q = self.hits[client]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


def create_app(settings: Settings | None = None, context: Context | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.ctx = context or make_context(settings)
        yield
        if context is None:
            await app.state.ctx.http.aclose()

    app = FastAPI(title="OSINT Dashboard", version=__version__, lifespan=lifespan)
    cache = TTLCache(settings.cache_ttl)
    limiter = RateLimiter(settings.rate_limit)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        # FastAPI's /docs page loads Swagger UI from a CDN with inline scripts, so it keeps its own defaults
        if not request.url.path.startswith(("/docs", "/redoc")):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' https: data:; style-src 'self'; "
                "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        response.headers.update({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
        })
        return response

    def error(status: int, message: str) -> JSONResponse:
        return JSONResponse({"error": message}, status_code=status)

    def prepare(request: Request, q: str, kind: str | None) -> Target | JSONResponse:
        try:
            target = parse_target(q, kind)
        except InvalidTarget as exc:
            # fixed text looked up by reason code: the exception object itself never reaches the client
            return error(400, MESSAGES.get(exc.reason, MESSAGES["unrecognised"]))
        if target.kind == "ip" and not is_public(target.value):
            return error(400, f"{target.value} is a private or reserved address - there is nothing public to look up")
        if not limiter.allow(request.client.host if request.client else "unknown"):
            return error(429, f"rate limit: {settings.rate_limit} lookups per minute")
        return target

    def parse_only(modules: str | None) -> set[str] | None:
        return {m.strip() for m in modules.split(",") if m.strip()} if modules else None

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/modules")
    async def list_modules():
        return [
            {"id": m.id, "title": m.title, "kinds": sorted(m.kinds), "description": m.description,
             "needs_key": m.key_setting is not None,
             "enabled": m.key_setting is None or bool(getattr(settings, m.key_setting))}
            for m in MODULES.values()
        ]

    @app.get("/api/lookup")
    async def lookup(request: Request, q: str = Query(..., max_length=300), type: str | None = None,
                     modules: str | None = None):
        """Run every module and return one JSON document (handy for curl / scripts)."""
        target = prepare(request, q, type)
        if isinstance(target, JSONResponse):
            return target
        started = time.perf_counter()
        reports = [r async for r in run_all(target, request.app.state.ctx, cache, parse_only(modules))]
        order = [m.id for m in modules_for(target.kind)]
        reports.sort(key=lambda r: order.index(r.id))
        findings = sort_findings([f for r in reports for f in r.findings])
        return {
            "target": target.to_dict(),
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "summary": {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES},
            "findings": [f.__dict__ for f in findings],
            "modules": [r.to_dict() for r in reports],
        }

    @app.get("/api/stream")
    async def stream(request: Request, q: str = Query(..., max_length=300), type: str | None = None,
                     modules: str | None = None):
        """Server-Sent Events: one event per module as soon as it finishes."""
        target = prepare(request, q, type)
        if isinstance(target, JSONResponse):
            return target
        only = parse_only(modules)
        planned = [{"id": m.id, "title": m.title} for m in modules_for(target.kind) if only is None or m.id in only]

        def sse(event: str, payload: dict) -> str:
            return f"event: {event}\ndata: {json.dumps(payload, default=str)}\n\n"

        async def events():
            started = time.perf_counter()
            yield sse("start", {"target": target.to_dict(), "modules": planned})
            async for report in run_all(target, request.app.state.ctx, cache, only):
                if await request.is_disconnected():
                    break
                yield sse("module", report.to_dict())
            yield sse("done", {"duration_ms": int((time.perf_counter() - started) * 1000)})

        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


app = create_app()
