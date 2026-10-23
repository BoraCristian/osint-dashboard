"""Identity modules: username presence across sites, and email address intelligence."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote

import dns.resolver
import httpx

from ..core import Context, Finding, NoData, Result, module
from ..targets import Target
from .common import dns_query

# ---------------------------------------------------------------------------
# Username presence
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Site:
    name: str
    api: str  # URL checked, {u} = username
    profile: str  # public profile URL shown to the user
    exists: Callable[[httpx.Response], bool | None]  # True / False / None = could not tell
    details: Callable[[dict], dict] = lambda d: {}


def by_status(r: httpx.Response) -> bool | None:
    if r.status_code == 200:
        return True
    if r.status_code in (404, 410):
        return False
    return None


def by_json(test: Callable[[object], bool]) -> Callable[[httpx.Response], bool | None]:
    def check(r: httpx.Response) -> bool | None:
        if r.status_code != 200:
            return False if r.status_code == 404 else None
        try:
            return test(r.json())
        except ValueError:
            return None
    return check


def pick(*keys: str) -> Callable[[dict], dict]:
    return lambda d: {k: d.get(k) for k in keys if isinstance(d, dict) and d.get(k) not in (None, "", [])}


SITES = [
    Site("GitHub", "https://api.github.com/users/{u}", "https://github.com/{u}", by_status,
         pick("name", "company", "blog", "location", "bio", "public_repos", "followers", "created_at")),
    Site("GitLab", "https://gitlab.com/api/v4/users?username={u}", "https://gitlab.com/{u}",
         by_json(lambda d: bool(d)), lambda d: pick("name", "state")(d[0]) if d else {}),
    Site("Codeberg", "https://codeberg.org/api/v1/users/{u}", "https://codeberg.org/{u}", by_status,
         pick("full_name", "location", "website", "created")),
    Site("Docker Hub", "https://hub.docker.com/v2/users/{u}/", "https://hub.docker.com/u/{u}", by_status,
         pick("full_name", "company", "location", "date_joined")),
    Site("DEV", "https://dev.to/api/users/by_username?url={u}", "https://dev.to/{u}", by_status,
         pick("name", "summary", "location", "joined_at", "github_username", "twitter_username")),
    Site("Hacker News", "https://hacker-news.firebaseio.com/v0/user/{u}.json", "https://news.ycombinator.com/user?id={u}",
         by_json(lambda d: d is not None), pick("karma", "created")),
    Site("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", "https://keybase.io/{u}",
         by_json(lambda d: bool(d.get("them")) and d["them"][0] is not None),
         lambda d: pick("full_name", "location", "bio")((d["them"][0].get("profile") or {}))),
    Site("Mastodon (mastodon.social)", "https://mastodon.social/api/v1/accounts/lookup?acct={u}",
         "https://mastodon.social/@{u}", by_status, pick("display_name", "created_at", "followers_count")),
    Site("Chess.com", "https://api.chess.com/pub/player/{u_lower}", "https://www.chess.com/member/{u}", by_status,
         pick("name", "location", "joined")),
    Site("Lichess", "https://lichess.org/api/user/{u}", "https://lichess.org/@/{u}", by_status,
         pick("createdAt", "playTime")),
]


@module("accounts", "Accounts with this username", {"username"})
async def accounts(target: Target, ctx: Context) -> Result:
    """Checks public APIs of popular sites for an account with this exact name."""
    u = target.value

    async def check(site: Site) -> tuple[Site, bool | None, dict]:
        url = site.api.format(u=quote(u), u_lower=quote(u.lower()))
        try:
            r = await ctx.http.get(url, timeout=12)
        except httpx.HTTPError:
            return site, None, {}
        found = site.exists(r)
        details = {}
        if found:
            try:
                details = site.details(r.json())
            except (ValueError, KeyError, IndexError, TypeError, AttributeError):
                details = {}
        return site, found, details

    results = await asyncio.gather(*(check(s) for s in SITES))
    found = [{"site": s.name, "url": s.profile.format(u=u), **({"details": d} if d else {})}
             for s, ok, d in results if ok]
    data = {
        "found": found,
        "not_found": [s.name for s, ok, _ in results if ok is False],
        "could_not_check": [s.name for s, ok, _ in results if ok is None],
    }
    if not found:
        raise NoData(f"no account named '{u}' on the {len(SITES)} sites checked")
    return Result(f"Found on {len(found)} of {len(SITES)} sites", data, [Finding(
        "info", "Matching names are not proof of one owner",
        "Different people can use the same username; compare profile details before linking accounts.")])


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

FREE_PROVIDERS = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
                  "yahoo.co.uk", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net",
                  "yandex.ru", "yandex.com", "mail.ru", "zoho.com", "tutanota.com", "tuta.io", "fastmail.com"}
DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org", "yopmail.com",
              "trashmail.com", "getnada.com", "sharklasers.com", "dispostable.com", "maildrop.cc", "throwawaymail.com",
              "fakeinbox.com", "mintemail.com", "mohmal.com", "emailondeck.com", "tempail.com", "burnermail.io"}
MX_PROVIDERS = {"google.com": "Google", "googlemail.com": "Google",
                "outlook.com": "Microsoft 365", "protection.outlook.com": "Microsoft 365",
                "pphosted.com": "Proofpoint", "mimecast.com": "Mimecast", "zoho.com": "Zoho Mail",
                "protonmail.ch": "Proton Mail", "yahoodns.net": "Yahoo", "icloud.com": "iCloud",
                "messagingengine.com": "Fastmail", "secureserver.net": "GoDaddy", "ovh.net": "OVH", "yandex.net": "Yandex"}


@module("email_domain", "Email domain", {"email"})
async def email_domain(target: Target, ctx: Context) -> Result:
    """Whether the domain can receive mail, who runs it, and whether it is disposable."""
    domain = target.domain
    try:
        mx = await dns_query(ctx.resolver, domain, "MX")
    except dns.resolver.NXDOMAIN:
        return Result("Domain does not exist", {"domain": domain, "mx": []},
                      [Finding("high", "Email domain does not exist", "This address cannot receive mail.")])
    hosts = [m.split()[-1].lower() for m in sorted(mx, key=lambda m: int(m.split()[0]) if m.split()[0].isdigit() else 99)]
    provider = next((name for h in hosts for suffix, name in MX_PROVIDERS.items() if h.endswith(suffix)), None)
    findings = []
    if not hosts:
        findings.append(Finding("medium", "Domain has no MX record", "The address probably cannot receive mail."))
    if domain in DISPOSABLE:
        findings.append(Finding("medium", "Disposable email provider", "Throwaway inboxes are common in fraud and spam sign-ups."))
    kind = "disposable" if domain in DISPOSABLE else "free webmail" if domain in FREE_PROVIDERS else "custom / corporate"
    data = {"domain": domain, "type": kind, "mail_provider": provider, "mx": hosts}
    return Result(f"{kind.capitalize()} domain" + (f", mail by {provider}" if provider else ""), data, findings)


@module("gravatar", "Public profile (Gravatar)", {"email"})
async def gravatar(target: Target, ctx: Context) -> Result:
    """Gravatar profiles are keyed by the email hash and often list a name, bio and linked accounts."""
    digest = hashlib.md5(target.value.lower().encode()).hexdigest()
    r = await ctx.http.get(f"https://en.gravatar.com/{digest}.json")
    if r.status_code == 404 or not r.content.strip():
        raise NoData("no public Gravatar profile")
    r.raise_for_status()
    try:
        entry = r.json()["entry"][0]
    except (ValueError, KeyError, IndexError):
        raise NoData("no public Gravatar profile") from None
    data = {
        "display_name": entry.get("displayName"),
        "profile": entry.get("profileUrl"),
        "location": entry.get("currentLocation"),
        "about": entry.get("aboutMe"),
        "job": " @ ".join(filter(None, [entry.get("job_title"), entry.get("company")])) or None,
        "linked_accounts": [a.get("url") for a in entry.get("accounts", []) if a.get("url")],
        "websites": [u.get("value") for u in entry.get("urls", []) if u.get("value")],
        "avatar": entry.get("thumbnailUrl"),
    }
    data = {k: v for k, v in data.items() if v}
    return Result(f"Profile: {data.get('display_name') or 'unnamed'}", data,
                  [Finding("info", "Email address has a public Gravatar profile",
                           "Anyone who knows the address can find this profile and the accounts it links to.")],
                  {"Gravatar": entry.get("profileUrl") or f"https://gravatar.com/{digest}"})


@module("breaches", "Data breaches (Have I Been Pwned)", {"email"}, key="hibp_key")
async def breaches(target: Target, ctx: Context) -> Result:
    """Known data breaches that included this address."""
    r = await ctx.http.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(target.value)}",
                           params={"truncateResponse": "false"}, headers={"hibp-api-key": ctx.settings.hibp_key})
    if r.status_code == 404:
        raise NoData("not found in any known breach")
    r.raise_for_status()
    found = sorted(r.json(), key=lambda b: b.get("BreachDate", ""), reverse=True)
    rows = [{"name": b["Name"], "date": b.get("BreachDate"), "data": b.get("DataClasses", [])} for b in found]
    with_passwords = [b["name"] for b in rows if "Passwords" in b["data"]]
    findings = [Finding("high" if with_passwords else "medium", f"Appears in {len(rows)} data breach(es)",
                        ("Passwords leaked in: " + ", ".join(with_passwords[:8]) + ". Any reused password should be changed.")
                        if with_passwords else "No passwords exposed, but personal data was.")]
    return Result(f"{len(rows)} breaches, most recent {rows[0]['date']}", {"breaches": rows}, findings,
                  {"Have I Been Pwned": "https://haveibeenpwned.com/"})
