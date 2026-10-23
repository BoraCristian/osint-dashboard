"""Settings read from environment variables (and an optional .env file next to the app)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_dotenv(path: Path = ROOT / ".env") -> None:
    """Minimal .env reader: KEY=value lines, # comments. Real environment variables win."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


@dataclass(frozen=True)
class Settings:
    abuseipdb_key: str | None = None
    hibp_key: str | None = None
    virustotal_key: str | None = None
    module_timeout: float = 25.0
    cache_ttl: int = 600  # seconds
    rate_limit: int = 20  # lookups per client per minute
    user_agent: str = "osint-dashboard/0.1 (+https://github.com/BoraCristian/cybersec-portfolio)"

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv()

        def key(name: str) -> str | None:
            return os.environ.get(name) or None

        return cls(
            abuseipdb_key=key("ABUSEIPDB_API_KEY"),
            hibp_key=key("HIBP_API_KEY"),
            virustotal_key=key("VIRUSTOTAL_API_KEY"),
            module_timeout=float(os.environ.get("OSINT_MODULE_TIMEOUT", cls.module_timeout)),
            cache_ttl=int(os.environ.get("OSINT_CACHE_TTL", cls.cache_ttl)),
            rate_limit=int(os.environ.get("OSINT_RATE_LIMIT", cls.rate_limit)),
        )
