"""Module framework: registry, result types, caching and the concurrent runner."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import asdict, dataclass, field, replace
from typing import Any
from collections.abc import AsyncIterator, Awaitable, Callable

import dns.asyncresolver
import httpx

from .config import Settings
from .targets import Target

SEVERITIES = ("critical", "high", "medium", "low", "info")
log = logging.getLogger(__name__)


@dataclass
class Finding:
    severity: str  # one of SEVERITIES
    title: str
    detail: str = ""
    module: str = ""


@dataclass
class Result:
    """What a module returns. ``data`` is rendered generically by the frontend."""

    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    links: dict[str, str] = field(default_factory=dict)  # label -> URL for "open in source"


class Skip(Exception):
    """Raise from a module when it cannot run (missing API key, not applicable...)."""


class NoData(Exception):
    """Raise from a module when the lookup worked but found nothing."""


@dataclass
class ModuleReport:
    id: str
    title: str
    status: str  # ok | empty | skipped | error
    summary: str
    data: dict[str, Any]
    findings: list[Finding]
    links: dict[str, str]
    duration_ms: int
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Context:
    http: httpx.AsyncClient
    settings: Settings
    resolver: dns.asyncresolver.Resolver


ModuleFn = Callable[[Target, Context], Awaitable[Result]]


@dataclass(frozen=True)
class Module:
    id: str
    title: str
    kinds: frozenset[str]
    fn: ModuleFn
    key_setting: str | None = None  # Settings attribute holding a required API key
    description: str = ""


MODULES: dict[str, Module] = {}


def module(id: str, title: str, kinds: set[str], key: str | None = None, description: str = ""):
    def register(fn: ModuleFn) -> ModuleFn:
        MODULES[id] = Module(id, title, frozenset(kinds), fn, key, description or (fn.__doc__ or "").strip())
        return fn

    return register


def modules_for(kind: str) -> list[Module]:
    return [m for m in MODULES.values() if kind in m.kinds]


class TTLCache:
    def __init__(self, ttl: int):
        self.ttl = ttl
        self._data: dict[tuple, tuple[float, ModuleReport]] = {}

    def get(self, key: tuple) -> ModuleReport | None:
        hit = self._data.get(key)
        if hit and time.monotonic() - hit[0] < self.ttl:
            return hit[1]
        self._data.pop(key, None)
        return None

    def set(self, key: tuple, value: ModuleReport) -> None:
        if len(self._data) > 2000:  # crude bound so a long-running server does not grow forever
            self._data.clear()
        self._data[key] = (time.monotonic(), value)


async def run_module(mod: Module, target: Target, ctx: Context, cache: TTLCache | None = None) -> ModuleReport:
    key = (mod.id, target.kind, target.value)
    if cache and (hit := cache.get(key)):
        return replace(hit, cached=True)

    start = time.perf_counter()
    status, data, findings, links = "ok", {}, [], {}
    try:
        if mod.key_setting and not getattr(ctx.settings, mod.key_setting):
            raise Skip(f"needs an API key ({mod.key_setting.upper().replace('_KEY', '_API_KEY')} in .env)")
        result = await asyncio.wait_for(mod.fn(target, ctx), timeout=ctx.settings.module_timeout)
        summary, data, findings, links = result.summary, result.data, result.findings, result.links
    except Skip as exc:
        status, summary = "skipped", str(exc)
    except NoData as exc:
        status, summary = "empty", str(exc) or "nothing found"
    except asyncio.TimeoutError:
        status, summary = "error", f"timed out after {ctx.settings.module_timeout:.0f}s"
    except httpx.HTTPStatusError as exc:
        status, summary = "error", f"{exc.request.url.host} answered HTTP {exc.response.status_code}"
    except httpx.HTTPError as exc:
        status, summary = "error", f"network error: {type(exc).__name__}"
    except Exception:  # a bug in one module must not break the whole lookup
        # details go to the server log only; clients never see exception text
        log.exception("module %s failed for %s target", mod.id, target.kind)
        status, summary = "error", "internal error in this module (details are in the server log)"

    for f in findings:
        f.module = mod.id
    report = ModuleReport(mod.id, mod.title, status, summary, data, findings, links,
                          int((time.perf_counter() - start) * 1000))
    # cache successes and "nothing found", not errors, so a transient failure can be retried
    if cache and status in ("ok", "empty"):
        cache.set(key, report)
    return report


async def run_all(target: Target, ctx: Context, cache: TTLCache | None = None,
                  only: set[str] | None = None) -> AsyncIterator[ModuleReport]:
    """Run every applicable module concurrently and yield reports as they finish."""
    mods = [m for m in modules_for(target.kind) if only is None or m.id in only]
    tasks = [asyncio.create_task(run_module(m, target, ctx, cache)) for m in mods]
    try:
        for next_done in asyncio.as_completed(tasks):
            yield await next_done
    finally:
        for t in tasks:
            t.cancel()


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITIES.index(f.severity))
