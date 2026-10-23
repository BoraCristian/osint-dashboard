"""Work out what the user typed: an IP, a domain, an email address or a username."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

KINDS = ("ip", "domain", "email", "username")

LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
DOMAIN_RE = re.compile(rf"^(?:{LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{2,59}})$")
EMAIL_RE = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@(?P<domain>[^@\s]+)$", re.I)
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,38}$", re.I)


class InvalidTarget(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    raw: str
    kind: str  # one of KINDS
    value: str  # normalised form used for lookups

    @property
    def domain(self) -> str | None:
        if self.kind == "domain":
            return self.value
        if self.kind == "email":
            return self.value.rsplit("@", 1)[1]
        return None

    def to_dict(self) -> dict:
        return {"raw": self.raw, "kind": self.kind, "value": self.value, "domain": self.domain}


def _normalise_domain(text: str) -> str | None:
    text = text.strip().lower().rstrip(".")
    try:
        text = text.encode("idna").decode("ascii")  # bücher.de -> xn--bcher-kva.de
    except UnicodeError:
        return None
    return text if len(text) <= 253 and DOMAIN_RE.match(text) else None


def parse_target(text: str, kind: str | None = None) -> Target:
    raw = (text or "").strip()
    if not raw:
        raise InvalidTarget("enter a domain, IP address, email address or username")
    if len(raw) > 300:
        raise InvalidTarget("input is too long")
    if kind not in (None, "", "auto") and kind not in KINDS:
        raise InvalidTarget(f"unknown type {kind!r}")
    kind = None if kind in (None, "", "auto") else kind

    value = raw
    # accept pasted URLs: https://www.example.com/path -> www.example.com
    if "://" in value:
        value = urlsplit(value).hostname or ""
    if value.startswith("@") and kind in (None, "username"):
        value = value[1:]

    if kind in (None, "ip"):
        try:
            return Target(raw, "ip", str(ipaddress.ip_address(value.strip("[]"))))
        except ValueError:
            if kind == "ip":
                raise InvalidTarget(f"{raw!r} is not a valid IP address") from None

    if kind in (None, "email") and "@" in value:
        m = EMAIL_RE.match(value)
        domain = _normalise_domain(m["domain"]) if m else None
        if m and domain:
            return Target(raw, "email", f"{value.rsplit('@', 1)[0]}@{domain}")
        raise InvalidTarget(f"{raw!r} is not a valid email address")
    if kind == "email":
        raise InvalidTarget(f"{raw!r} is not a valid email address")

    if kind in (None, "domain"):
        domain = _normalise_domain(value)
        if domain:
            return Target(raw, "domain", domain)
        if kind == "domain":
            raise InvalidTarget(f"{raw!r} is not a valid domain name")

    if USERNAME_RE.match(value):
        return Target(raw, "username", value)
    raise InvalidTarget(f"could not tell what {raw!r} is - pick a type explicitly")
