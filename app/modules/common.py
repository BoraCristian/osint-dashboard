"""Helpers shared by several modules."""

from __future__ import annotations

from datetime import datetime, timezone

import dns.asyncresolver
import dns.exception
import dns.resolver


async def dns_query(resolver: dns.asyncresolver.Resolver, name: str, rtype: str) -> list[str]:
    """Return the records as text, or [] when there are none. NXDOMAIN is re-raised."""
    try:
        answer = await resolver.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        raise
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    out = []
    for r in answer:
        if rtype == "TXT":
            out.append(b"".join(r.strings).decode("utf-8", errors="replace"))
        else:
            out.append(r.to_text().rstrip("."))
    return out


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def now() -> datetime:
    return datetime.now(timezone.utc)


def days_until(ts: datetime) -> int:
    return (ts - now()).days


def vcard_field(entity: dict, name: str) -> str | None:
    """Pull one field (fn, email, org...) out of an RDAP entity's jCard."""
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2):
        return None
    for prop in vcard[1]:
        if prop and prop[0] == name:
            value = prop[-1]
            return " ".join(value) if isinstance(value, list) else str(value)
    return None


def rdap_events(obj: dict) -> dict[str, str]:
    return {e["eventAction"]: e["eventDate"] for e in obj.get("events", []) if "eventAction" in e and "eventDate" in e}


def rdap_entities(obj: dict, role: str) -> list[dict]:
    """Entities with ``role``, searching nested entities too (registrars often nest the abuse contact)."""
    found = []
    for ent in obj.get("entities", []) or []:
        if role in (ent.get("roles") or []):
            found.append(ent)
        found.extend(rdap_entities(ent, role))
    return found
