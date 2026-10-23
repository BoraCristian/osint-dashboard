"""IP modules: geolocation/ASN, network owner, reverse DNS, exposed services, reputation."""

from __future__ import annotations

import asyncio
import ipaddress

import dns.exception
import dns.resolver
import dns.reversename

from ..core import Context, Finding, NoData, Result, module
from ..targets import Target
from .common import dns_query, rdap_entities, rdap_events, vcard_field

# ---------------------------------------------------------------------------
# Geolocation / ASN
# ---------------------------------------------------------------------------


async def _ipinfo(ctx: Context, ip: str) -> dict:
    r = await ctx.http.get(f"https://ipinfo.io/{ip}/json")
    r.raise_for_status()
    return r.json()


def _geo(info: dict) -> dict:
    asn, _, org = (info.get("org") or "").partition(" ")
    return {
        "hostname": info.get("hostname"),
        "organisation": org or None,
        "asn": asn or None,
        "city": info.get("city"),
        "region": info.get("region"),
        "country": info.get("country"),
        "coordinates": info.get("loc"),
        "timezone": info.get("timezone"),
        "anycast": info.get("anycast", False),
    }


@module("geo", "Location & network (ipinfo)", {"ip"})
async def geolocation(target: Target, ctx: Context) -> Result:
    """Approximate location, ASN and hosting provider."""
    info = await _ipinfo(ctx, target.value)
    if info.get("bogon"):
        raise NoData("reserved / private address")
    data = _geo(info)
    where = ", ".join(filter(None, [data["city"], data["country"]]))
    return Result(f"{data['organisation'] or 'Unknown network'} - {where or 'unknown location'}", data, [],
                  {"ipinfo": f"https://ipinfo.io/{target.value}"})


@module("hosting", "Hosting", {"domain"})
async def hosting(target: Target, ctx: Context) -> Result:
    """Who hosts the addresses the domain points to."""
    try:
        ips = (await dns_query(ctx.resolver, target.domain, "A"))[:4]
    except dns.resolver.NXDOMAIN:
        raise NoData("domain does not exist") from None
    if not ips:
        raise NoData("no A records")
    infos = await asyncio.gather(*(_ipinfo(ctx, ip) for ip in ips))
    hosts = [{"ip": ip, **{k: v for k, v in _geo(i).items() if k in ("organisation", "asn", "city", "country")}}
             for ip, i in zip(ips, infos)]
    orgs = sorted({h["organisation"] for h in hosts if h["organisation"]})
    return Result(f"Hosted by {', '.join(orgs) or 'unknown'}", {"addresses": hosts}, [])


# ---------------------------------------------------------------------------
# Network owner (RDAP)
# ---------------------------------------------------------------------------


@module("ip_rdap", "Network owner (RDAP)", {"ip"})
async def ip_rdap(target: Target, ctx: Context) -> Result:
    """Which organisation the address block is registered to, and its abuse contact."""
    r = await ctx.http.get(f"https://rdap.org/ip/{target.value}")
    if r.status_code == 404:
        raise NoData("no RDAP record")
    r.raise_for_status()
    doc = r.json()
    cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in doc.get("cidr0_cidrs", [])]
    owner = next((vcard_field(e, "fn") for e in rdap_entities(doc, "registrant")), None)
    abuse = next((vcard_field(e, "email") for e in rdap_entities(doc, "abuse")), None)
    events = rdap_events(doc)
    data = {
        "network_name": doc.get("name"),
        "handle": doc.get("handle"),
        "range": f"{doc.get('startAddress')} - {doc.get('endAddress')}",
        "cidr": cidrs,
        "type": doc.get("type"),
        "country": doc.get("country"),
        "owner": owner,
        "abuse_contact": abuse,
        "registered": (events.get("registration") or "")[:10] or None,
        "updated": (events.get("last changed") or "")[:10] or None,
        "registry": (doc.get("port43") or "").replace("whois.", "") or None,
    }
    return Result(f"{owner or doc.get('name') or 'Unknown owner'} ({', '.join(cidrs) or data['range']})", data, [],
                  {"RDAP": f"https://rdap.org/ip/{target.value}"})


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------


@module("reverse_dns", "Reverse DNS", {"ip"})
async def reverse_dns(target: Target, ctx: Context) -> Result:
    """PTR record, checked against the forward lookup (FCrDNS)."""
    name = dns.reversename.from_address(target.value).to_text()
    try:
        ptrs = await dns_query(ctx.resolver, name, "PTR")
    except dns.resolver.NXDOMAIN:
        ptrs = []
    if not ptrs:
        raise NoData("no PTR record")
    rtype = "AAAA" if ipaddress.ip_address(target.value).version == 6 else "A"
    confirmed = {}
    for ptr in ptrs[:5]:
        try:
            forward = await dns_query(ctx.resolver, ptr, rtype)
        except (dns.resolver.NXDOMAIN, dns.exception.DNSException):
            forward = []
        confirmed[ptr] = target.value in forward
    findings = []
    if not any(confirmed.values()):
        findings.append(Finding("info", "Reverse DNS is not forward-confirmed",
                                "The PTR name does not resolve back to this IP; mail servers may distrust it."))
    return Result(", ".join(ptrs), {"ptr": ptrs, "forward_confirmed": confirmed}, findings)


# ---------------------------------------------------------------------------
# Exposed services (Shodan InternetDB - free, no key)
# ---------------------------------------------------------------------------

RISKY_PORTS = {
    21: ("medium", "FTP"), 23: ("high", "Telnet"), 25: ("info", "SMTP"), 69: ("medium", "TFTP"),
    111: ("medium", "RPCbind"), 135: ("high", "MS RPC"), 139: ("high", "NetBIOS"), 445: ("high", "SMB"),
    1433: ("high", "MS SQL"), 1521: ("high", "Oracle DB"), 2049: ("medium", "NFS"), 2375: ("critical", "Docker API (no TLS)"),
    3306: ("high", "MySQL"), 3389: ("high", "RDP"), 5432: ("high", "PostgreSQL"), 5900: ("high", "VNC"),
    5985: ("medium", "WinRM"), 6379: ("high", "Redis"), 9200: ("high", "Elasticsearch"), 11211: ("high", "Memcached"),
    27017: ("high", "MongoDB"), 161: ("medium", "SNMP"), 1883: ("medium", "MQTT"), 502: ("high", "Modbus (ICS)"),
}
TAG_SEVERITY = {"compromised": "critical", "malware": "critical", "doublepulsar": "critical", "c2": "critical",
                "tor": "medium", "eol-os": "medium", "eol-product": "medium", "self-signed": "low", "honeypot": "info",
                "vpn": "info", "proxy": "info", "cloud": "info", "cdn": "info", "database": "info", "starttls": "info"}


@module("exposure", "Open ports & known CVEs (Shodan InternetDB)", {"ip"})
async def exposure(target: Target, ctx: Context) -> Result:
    """What Shodan's scanners saw on this address: open ports, software, tags and CVEs."""
    r = await ctx.http.get(f"https://internetdb.shodan.io/{target.value}")
    if r.status_code == 404:
        raise NoData("Shodan has not seen anything on this address")
    r.raise_for_status()
    doc = r.json()
    ports, vulns, tags = sorted(doc.get("ports", [])), sorted(doc.get("vulns", [])), doc.get("tags", [])
    if not (ports or vulns or tags or doc.get("hostnames")):
        raise NoData("no open ports recorded")

    findings = []
    for port in ports:
        if port in RISKY_PORTS:
            sev, name = RISKY_PORTS[port]
            if sev != "info":
                findings.append(Finding(sev, f"{name} exposed to the internet (port {port})",
                                        "This service should normally sit behind a VPN or firewall."))
    if vulns:
        kev_hint = ", ".join(vulns[:10]) + (f" and {len(vulns) - 10} more" if len(vulns) > 10 else "")
        findings.append(Finding("high", f"{len(vulns)} known CVEs match the software seen",
                                f"Based on version banners (may include false positives): {kev_hint}."))
    for tag in tags:
        sev = TAG_SEVERITY.get(tag, "info")
        if sev != "info":
            findings.append(Finding(sev, f"Tagged '{tag}' by Shodan", ""))

    data = {"ports": ports, "hostnames": doc.get("hostnames", []), "software": doc.get("cpes", []),
            "tags": tags, "vulns": vulns}
    summary = f"{len(ports)} open port(s)" + (f", {len(vulns)} CVEs" if vulns else "")
    return Result(summary, data, findings, {"Shodan": f"https://www.shodan.io/host/{target.value}"})


# ---------------------------------------------------------------------------
# Reputation (optional API keys)
# ---------------------------------------------------------------------------


@module("abuseipdb", "Abuse reports (AbuseIPDB)", {"ip"}, key="abuseipdb_key")
async def abuseipdb(target: Target, ctx: Context) -> Result:
    """Community reports of attacks from this IP over the last 90 days."""
    r = await ctx.http.get("https://api.abuseipdb.com/api/v2/check",
                           params={"ipAddress": target.value, "maxAgeInDays": 90},
                           headers={"Key": ctx.settings.abuseipdb_key, "Accept": "application/json"})
    r.raise_for_status()
    d = r.json()["data"]
    score = d.get("abuseConfidenceScore", 0)
    findings = []
    if score >= 75:
        findings.append(Finding("high", f"AbuseIPDB confidence {score}%", f"{d.get('totalReports')} reports in 90 days."))
    elif score >= 25:
        findings.append(Finding("medium", f"AbuseIPDB confidence {score}%", f"{d.get('totalReports')} reports in 90 days."))
    elif d.get("totalReports"):
        findings.append(Finding("low", f"{d['totalReports']} abuse report(s)", f"Confidence score {score}%."))
    if d.get("isTor"):
        findings.append(Finding("medium", "Tor exit node", ""))
    data = {k: d.get(k) for k in ("abuseConfidenceScore", "totalReports", "numDistinctUsers", "lastReportedAt",
                                  "usageType", "isp", "domain", "isTor", "isWhitelisted")}
    return Result(f"Abuse confidence {score}% ({d.get('totalReports', 0)} reports)", data, findings,
                  {"AbuseIPDB": f"https://www.abuseipdb.com/check/{target.value}"})


@module("virustotal", "Reputation (VirusTotal)", {"ip", "domain"}, key="virustotal_key")
async def virustotal(target: Target, ctx: Context) -> Result:
    """How many antivirus / blocklist engines flag the IP or domain."""
    kind = "ip_addresses" if target.kind == "ip" else "domains"
    value = target.value if target.kind == "ip" else target.domain
    r = await ctx.http.get(f"https://www.virustotal.com/api/v3/{kind}/{value}",
                           headers={"x-apikey": ctx.settings.virustotal_key})
    if r.status_code == 404:
        raise NoData("unknown to VirusTotal")
    r.raise_for_status()
    attrs = r.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
    findings = []
    if malicious >= 3:
        findings.append(Finding("high", f"Flagged malicious by {malicious} engines", ""))
    elif malicious or suspicious:
        findings.append(Finding("medium", f"Flagged by {malicious + suspicious} engine(s)",
                                f"{malicious} malicious, {suspicious} suspicious."))
    data = {"stats": stats, "reputation": attrs.get("reputation"), "categories": attrs.get("categories"),
            "tags": attrs.get("tags")}
    gui = "ip-address" if target.kind == "ip" else "domain"
    return Result(f"{malicious} malicious / {sum(stats.values()) or 0} engines", data, findings,
                  {"VirusTotal": f"https://www.virustotal.com/gui/{gui}/{value}"})
