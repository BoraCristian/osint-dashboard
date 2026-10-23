"""Domain modules: DNS, email security, registration, certificates, subdomains, web headers, history."""

from __future__ import annotations

import asyncio
import re
import ssl
from datetime import datetime, timezone

import dns.resolver
import httpx

from ..core import Context, Finding, NoData, Result, Skip, module
from ..netguard import BlockedAddress, resolve_public
from ..targets import Target
from .common import days_until, dns_query, now, parse_time, rdap_entities, rdap_events, vcard_field

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA")


@module("dns", "DNS records", {"domain"})
async def dns_records(target: Target, ctx: Context) -> Result:
    """A, AAAA, MX, NS, TXT, CAA and SOA records."""
    try:
        answers = await asyncio.gather(*(dns_query(ctx.resolver, target.domain, t) for t in RECORD_TYPES))
    except dns.resolver.NXDOMAIN:
        raise NoData(f"{target.domain} does not exist (NXDOMAIN)") from None
    records = {t: a for t, a in zip(RECORD_TYPES, answers) if a}
    if not records:
        raise NoData("the domain exists but has no records")

    findings = []
    if not records.get("CAA"):
        findings.append(Finding("info", "No CAA record",
                                "Any certificate authority may issue certificates for this domain."))
    if not records.get("A") and not records.get("AAAA"):
        findings.append(Finding("info", "No A/AAAA record", "The bare domain does not point at a server."))
    total = sum(len(v) for v in records.values())
    return Result(f"{total} records across {len(records)} types", {"records": records}, findings)


# ---------------------------------------------------------------------------
# SPF / DMARC / DKIM
# ---------------------------------------------------------------------------

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "mandrill",
                  "smtp", "everlytickey1", "mxvault", "protonmail")


def analyse_spf(records: list[str], has_mx: bool) -> tuple[dict, list[Finding]]:
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    findings = []
    if not spf:
        sev = "medium" if has_mx else "low"
        hint = "" if has_mx else ' For a domain that sends no mail, publish "v=spf1 -all".'
        return {"record": None}, [Finding(sev, "No SPF record", "Anyone can send mail claiming to be from this domain "
                                          "and receivers have no policy to check it against." + hint)]
    if len(spf) > 1:
        findings.append(Finding("medium", "Multiple SPF records",
                                "More than one v=spf1 record is a permanent error (RFC 7208): SPF is ignored."))
    record = spf[0]
    terms = record.split()[1:]
    all_term = next((t for t in terms if t.lstrip("+-~?").lower() == "all"), None)
    qualifier = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}.get(all_term[0], "pass") if all_term else None
    lookups = sum(1 for t in terms if re.match(r"^[+\-~?]?(include|a|mx|ptr|exists|redirect)\b", t, re.I))
    if qualifier == "pass":
        findings.append(Finding("high", "SPF allows any sender (+all)",
                                "The record ends in +all, which authorises every server on the internet."))
    elif qualifier == "neutral":
        findings.append(Finding("medium", "SPF is neutral (?all)", "Mail from unlisted servers is neither accepted nor rejected."))
    elif qualifier is None and not any(t.lower().startswith("redirect=") for t in terms):
        findings.append(Finding("low", "SPF has no 'all' mechanism", "Unlisted senders fall through to a neutral result."))
    if lookups > 10:
        findings.append(Finding("medium", "SPF exceeds 10 DNS lookups",
                                f"{lookups} lookup mechanisms; receivers will treat SPF as a permanent error."))
    return {"record": record, "all": qualifier, "dns_lookups": lookups}, findings


def analyse_dmarc(records: list[str]) -> tuple[dict, list[Finding]]:
    dmarc = [r for r in records if r.upper().startswith("V=DMARC1")]
    if not dmarc:
        return {"record": None}, [Finding("medium", "No DMARC record",
                                          "Receivers are not told to reject or quarantine spoofed mail, "
                                          "and the owner gets no reports about it.")]
    record = dmarc[0]
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    policy = tags.get("p", "").lower()
    findings = []
    if policy == "none":
        findings.append(Finding("low", "DMARC policy is p=none",
                                "Monitoring only: spoofed mail is still delivered."))
    elif policy not in ("quarantine", "reject"):
        findings.append(Finding("medium", "DMARC policy missing or invalid", f"p={policy or '(empty)'}"))
    if tags.get("pct") and tags["pct"] != "100" and policy in ("quarantine", "reject"):
        findings.append(Finding("low", f"DMARC applies to only {tags['pct']}% of mail", "The rest is treated as p=none."))
    if "rua" not in tags:
        findings.append(Finding("info", "DMARC has no aggregate report address (rua)", "The owner gets no visibility into abuse."))
    return {"record": record, "policy": policy, "subdomain_policy": tags.get("sp"), "reports_to": tags.get("rua")}, findings


@module("email_security", "Email security (SPF / DMARC / DKIM)", {"domain", "email"})
async def email_security(target: Target, ctx: Context) -> Result:
    """Checks whether the domain can be spoofed in email."""
    domain = target.domain
    try:
        txt, mx = await asyncio.gather(dns_query(ctx.resolver, domain, "TXT"), dns_query(ctx.resolver, domain, "MX"))
    except dns.resolver.NXDOMAIN:
        raise NoData(f"{domain} does not exist") from None
    try:
        dmarc_txt = await dns_query(ctx.resolver, f"_dmarc.{domain}", "TXT")
    except dns.resolver.NXDOMAIN:
        dmarc_txt = []

    async def dkim(selector: str) -> str | None:
        try:
            recs = await dns_query(ctx.resolver, f"{selector}._domainkey.{domain}", "TXT")
        except dns.resolver.NXDOMAIN:
            return None
        return selector if any("p=" in r for r in recs) else None

    selectors = [s for s in await asyncio.gather(*(dkim(s) for s in DKIM_SELECTORS)) if s]

    spf, spf_findings = analyse_spf(txt, bool(mx))
    dmarc, dmarc_findings = analyse_dmarc(dmarc_txt)
    findings = spf_findings + dmarc_findings
    if mx and not selectors:
        findings.append(Finding("info", "No DKIM key found on common selectors",
                                "DKIM may still be configured with a custom selector name."))

    spoofable = not spf["record"] or spf.get("all") in ("pass", "neutral") or dmarc.get("policy") in (None, "none")
    summary = ("Spoofing protection is weak" if spoofable else "SPF and DMARC are enforced")
    return Result(summary, {"spf": spf, "dmarc": dmarc, "dkim_selectors_found": selectors,
                            "spoofable": spoofable}, findings)


# ---------------------------------------------------------------------------
# Registration (RDAP, the modern replacement for WHOIS)
# ---------------------------------------------------------------------------


@module("whois", "Registration (RDAP / WHOIS)", {"domain"})
async def registration(target: Target, ctx: Context) -> Result:
    """Registrar, dates and status from RDAP."""
    r = await ctx.http.get(f"https://rdap.org/domain/{target.domain}")
    if r.status_code == 404:
        raise NoData("not found in RDAP: the domain is unregistered, a subdomain, or its TLD has no RDAP service")
    r.raise_for_status()
    doc = r.json()
    events = rdap_events(doc)
    created, expires = parse_time(events.get("registration")), parse_time(events.get("expiration"))
    registrar = next((vcard_field(e, "fn") for e in rdap_entities(doc, "registrar")), None)
    abuse = next((vcard_field(e, "email") for e in rdap_entities(doc, "abuse")), None)
    status = doc.get("status", [])

    findings = []
    if created:
        age = (now() - created).days
        if age < 30:
            findings.append(Finding("medium", f"Newly registered domain ({age} days old)",
                                    "Most phishing and malware domains are used within weeks of registration."))
    if expires:
        left = days_until(expires)
        if left < 0:
            findings.append(Finding("high", "Registration has expired", f"Expired {-left} days ago."))
        elif left < 30:
            findings.append(Finding("high", f"Registration expires in {left} days",
                                    "If it lapses, anyone can register it and take over its email and web traffic."))
    if any("pending delete" in s or "redemption" in s for s in status):
        findings.append(Finding("high", "Domain is being deleted", ", ".join(status)))
    elif status and not any("transfer prohibited" in s for s in status):
        findings.append(Finding("low", "No transfer lock", "clientTransferProhibited is not set, so the domain is easier to hijack."))

    data = {
        "registrar": registrar,
        "created": created.date().isoformat() if created else None,
        "updated": events.get("last changed", "")[:10] or None,
        "expires": expires.date().isoformat() if expires else None,
        "age_days": (now() - created).days if created else None,
        "status": status,
        "nameservers": sorted(ns.get("ldhName", "").lower() for ns in doc.get("nameservers", [])),
        "dnssec": (doc.get("secureDNS") or {}).get("delegationSigned"),
        "abuse_contact": abuse,
    }
    summary = f"Registered via {registrar or 'unknown registrar'}" + (f" on {data['created']}" if created else "")
    return Result(summary, data, findings, {"RDAP": f"https://rdap.org/domain/{target.domain}"})


# ---------------------------------------------------------------------------
# Subdomains from Certificate Transparency
# ---------------------------------------------------------------------------

INTERESTING = re.compile(r"(^|[.-])(dev|develop|staging|stage|stg|test|uat|qa|preprod|admin|internal|intranet|vpn|"
                         r"jenkins|gitlab|git|jira|confluence|grafana|kibana|prometheus|old|backup|beta|sandbox|"
                         r"api-dev|debug|phpmyadmin|portal|remote|citrix|owa|webmail)([.-]|$)")


@module("subdomains", "Subdomains (Certificate Transparency)", {"domain"})
async def subdomains(target: Target, ctx: Context) -> Result:
    """Hostnames that appeared in public TLS certificates (crt.sh)."""
    domain = target.domain
    r = await ctx.http.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                           timeout=ctx.settings.module_timeout)
    r.raise_for_status()
    entries = r.json() if r.content.strip() else []
    names: set[str] = set()
    first_seen: str | None = None
    for e in entries:
        for name in str(e.get("name_value", "")).lower().split("\n"):
            name = name.strip().lstrip("*.")
            if name.endswith("." + domain) or name == domain:
                names.add(name)
        nb = e.get("not_before")
        if nb and (first_seen is None or nb < first_seen):
            first_seen = nb
    names.discard(domain)
    if not names:
        raise NoData("no subdomains found in certificate transparency logs")

    ordered = sorted(names, key=lambda n: (n.count("."), n))
    interesting = [n for n in ordered if INTERESTING.search(n[: -len(domain) - 1])]
    findings = []
    if interesting:
        findings.append(Finding("low", f"{len(interesting)} potentially sensitive subdomains are public",
                                "Names like dev/staging/admin/vpn in CT logs point attackers at less-hardened "
                                "systems: " + ", ".join(interesting[:8]) + (" ..." if len(interesting) > 8 else "")))
    data = {"count": len(ordered), "certificates": len(entries), "first_certificate": (first_seen or "")[:10] or None,
            "interesting": interesting[:50], "subdomains": ordered[:300]}
    if len(ordered) > 300:
        data["note"] = f"showing 300 of {len(ordered)}"
    return Result(f"{len(ordered)} unique subdomains in {len(entries)} certificates", data, findings,
                  {"crt.sh": f"https://crt.sh/?q=%25.{domain}"})


# ---------------------------------------------------------------------------
# TLS certificate (connects to the target)
# ---------------------------------------------------------------------------


def _name(rdn_seq) -> dict[str, str]:
    return {k: v for rdn in rdn_seq for k, v in rdn}


@module("tls", "TLS certificate", {"domain"},
        description="Connects to port 443 and reads the certificate (one normal HTTPS handshake).")
async def tls_certificate(target: Target, ctx: Context) -> Result:
    domain = target.domain
    try:
        addrs = await resolve_public(domain, 443)
    except BlockedAddress as exc:
        raise Skip(str(exc)) from None

    async def handshake(context: ssl.SSLContext):
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(addrs[0], 443, ssl=context, server_hostname=domain), timeout=10)
        try:
            sslobj = writer.get_extra_info("ssl_object")
            return sslobj.getpeercert(), sslobj.version(), sslobj.cipher()
        finally:
            writer.close()

    try:
        cert, version, cipher = await handshake(ssl.create_default_context())
    except ssl.SSLCertVerificationError as exc:
        return Result("Certificate is NOT trusted", {"verification_error": exc.verify_message, "address": addrs[0]},
                      [Finding("high", "TLS certificate fails validation",
                               f"{exc.verify_message}. Browsers will show a security warning.")])
    except (OSError, asyncio.TimeoutError) as exc:
        raise NoData(f"nothing answering on {domain}:443 ({type(exc).__name__})") from None

    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    issuer, subject = _name(cert.get("issuer", ())), _name(cert.get("subject", ()))
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    left = days_until(not_after)

    findings = []
    if left < 14:
        findings.append(Finding("medium", f"Certificate expires in {left} days", f"Valid until {not_after:%Y-%m-%d}."))
    if version in ("TLSv1", "TLSv1.1"):
        findings.append(Finding("medium", f"Server negotiated {version}", "TLS 1.0/1.1 are deprecated."))

    data = {
        "subject": subject.get("commonName"),
        "issuer": " / ".join(filter(None, [issuer.get("organizationName"), issuer.get("commonName")])),
        "valid_from": f"{not_before:%Y-%m-%d}",
        "valid_until": f"{not_after:%Y-%m-%d}",
        "days_left": left,
        "protocol": version,
        "cipher": cipher[0] if cipher else None,
        "alt_names": sans[:100],
        "address": addrs[0],
    }
    return Result(f"{data['issuer'] or 'Unknown CA'}, valid for {left} more days ({version})", data, findings)


# ---------------------------------------------------------------------------
# HTTP security headers (connects to the target)
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    # header: (severity if missing, why it matters)
    "strict-transport-security": ("medium", "browsers may be downgraded to plain HTTP (SSL stripping)"),
    "content-security-policy": ("medium", "no second line of defence against XSS and injected scripts"),
    "x-content-type-options": ("low", "browsers may MIME-sniff responses into executable content"),
    "x-frame-options": ("low", "the site can be framed for clickjacking"),
    "referrer-policy": ("info", "full URLs may leak to third parties in the Referer header"),
    "permissions-policy": ("info", "no restriction on powerful browser features (camera, geolocation...)"),
}
WEIGHTS = {"high": 25, "medium": 15, "low": 7, "info": 2}


async def _fetch(ctx: Context, url: str, max_hops: int = 5) -> tuple[httpx.Response, list[str]]:
    """GET with manual redirects so that every hop goes through the SSRF check."""
    chain = []
    for _ in range(max_hops + 1):
        host = httpx.URL(url).host
        await resolve_public(host, httpx.URL(url).port or (443 if url.startswith("https") else 80))
        resp = await ctx.http.get(url, follow_redirects=False, timeout=10)
        chain.append(f"{resp.status_code} {url}")
        if resp.is_redirect and "location" in resp.headers:
            url = str(resp.url.join(resp.headers["location"]))
            continue
        return resp, chain
    raise NoData("too many redirects")


def grade(score: int) -> str:
    return next(g for limit, g in ((90, "A"), (75, "B"), (60, "C"), (45, "D"), (0, "F")) if score >= limit)


@module("http_headers", "Web server & security headers", {"domain"},
        description="Requests the home page over HTTPS and HTTP and checks the security headers.")
async def http_headers(target: Target, ctx: Context) -> Result:
    domain = target.domain
    try:
        try:
            resp, chain = await _fetch(ctx, f"https://{domain}/")
        except httpx.TransportError:
            resp, chain = await _fetch(ctx, f"http://{domain}/")
    except BlockedAddress as exc:
        raise Skip(str(exc)) from None
    except httpx.TransportError as exc:
        raise NoData(f"no web server answered ({type(exc).__name__})") from None

    headers = resp.headers
    https = resp.url.scheme == "https"
    findings: list[Finding] = []
    present, missing = {}, []
    for name, (sev, why) in SECURITY_HEADERS.items():
        value = headers.get(name)
        if name == "x-frame-options" and not value and "frame-ancestors" in headers.get("content-security-policy", ""):
            value = "(via CSP frame-ancestors)"
        if name == "strict-transport-security" and not https:
            continue
        if value:
            present[name] = value
        else:
            missing.append(name)
            findings.append(Finding(sev, f"Missing {name}", why[0].upper() + why[1:] + "."))

    hsts = headers.get("strict-transport-security", "")
    m = re.search(r"max-age=(\d+)", hsts)
    if m and int(m.group(1)) < 15552000:
        findings.append(Finding("low", "Short HSTS max-age", f"max-age={m.group(1)} (less than 180 days)."))

    disclosure = {h: headers[h] for h in ("server", "x-powered-by", "x-aspnet-version", "x-generator") if h in headers}
    if any(re.search(r"\d+\.\d+", v) for v in disclosure.values()):
        findings.append(Finding("low", "Software version disclosed",
                                "; ".join(f"{k}: {v}" for k, v in disclosure.items()) +
                                ". Exact versions make it easy to match known CVEs."))

    weak_cookies = []
    for cookie in headers.get_list("set-cookie"):
        flags = cookie.lower()
        if (https and "secure" not in flags) or "httponly" not in flags:
            weak_cookies.append(cookie.split("=", 1)[0])
    if weak_cookies:
        findings.append(Finding("low", "Cookies without Secure/HttpOnly", ", ".join(weak_cookies[:5])))

    redirects_to_https = None
    if https:
        try:
            plain, _ = await _fetch(ctx, f"http://{domain}/", max_hops=3)
            redirects_to_https = plain.url.scheme == "https"
        except (httpx.HTTPError, BlockedAddress, NoData):
            redirects_to_https = None  # port 80 closed is fine
        if redirects_to_https is False:
            findings.append(Finding("medium", "HTTP does not redirect to HTTPS", "Visitors typing the bare domain stay on plain HTTP."))
    else:
        findings.append(Finding("high", "No HTTPS", "The site is only served over plain HTTP."))

    score = max(0, 100 - sum(WEIGHTS.get(f.severity, 0) for f in findings))
    data = {
        "final_url": str(resp.url),
        "status": resp.status_code,
        "redirect_chain": chain,
        "http_redirects_to_https": redirects_to_https,
        "grade": grade(score),
        "score": score,
        "security_headers_present": present,
        "security_headers_missing": missing,
        "technology": disclosure,
    }
    return Result(f"Grade {data['grade']} ({score}/100), HTTP {resp.status_code}", data, findings)


# ---------------------------------------------------------------------------
# Wayback Machine history
# ---------------------------------------------------------------------------


@module("wayback", "Web history (Wayback Machine)", {"domain"})
async def wayback(target: Target, ctx: Context) -> Result:
    """First and latest snapshots in the Internet Archive."""
    url = "https://web.archive.org/cdx/search/cdx"
    params = {"url": target.domain, "output": "json", "fl": "timestamp,original,statuscode"}

    async def one(limit: int):
        r = await ctx.http.get(url, params={**params, "limit": limit})
        r.raise_for_status()
        rows = r.json() if r.content.strip() else []
        return rows[1] if len(rows) > 1 else None

    first, last = await asyncio.gather(one(1), one(-1))
    if not first:
        raise NoData("never archived")

    def fmt(row):
        ts = row[0]
        return {"date": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}", "url": row[1], "status": row[2],
                "snapshot": f"https://web.archive.org/web/{ts}/{row[1]}"}

    data = {"first_snapshot": fmt(first), "latest_snapshot": fmt(last) if last else None}
    return Result(f"Archived since {data['first_snapshot']['date']}", data, [],
                  {"Wayback Machine": f"https://web.archive.org/web/*/{target.domain}"})
