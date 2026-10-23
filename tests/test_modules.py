from datetime import datetime, timedelta, timezone

import httpx
import pytest

import app.modules  # noqa: F401  (registers modules)
from app.core import MODULES, run_module
from app.modules import domain as domain_mod
from app.modules.domain import analyse_dmarc, analyse_spf, grade
from app.targets import parse_target
from conftest import make_ctx, routes, run


def module_run(module_id, target, ctx):
    return run(run_module(MODULES[module_id], parse_target(target), ctx))


def severities(report):
    return {f.title: f.severity for f in report.findings}


# ---------------------------------------------------------------------------
# SPF / DMARC analysis
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("record, expected_sev", [
    ("v=spf1 include:_spf.google.com -all", None),
    ("v=spf1 include:_spf.google.com ~all", None),
    ("v=spf1 +all", "high"),
    ("v=spf1 a mx ?all", "medium"),
    ("v=spf1 a mx", "low"),
])
def test_spf_all_qualifier(record, expected_sev):
    _, findings = analyse_spf([record], has_mx=True)
    assert (findings[0].severity if findings else None) == expected_sev


def test_spf_missing_and_duplicates():
    _, findings = analyse_spf(["google-site-verification=abc"], has_mx=True)
    assert findings[0].title == "No SPF record" and findings[0].severity == "medium"
    _, findings = analyse_spf([], has_mx=False)
    assert "v=spf1 -all" in findings[0].detail  # advice for domains that send no mail
    _, findings = analyse_spf(["v=spf1 -all", "v=spf1 mx -all"], has_mx=True)
    assert any(f.title == "Multiple SPF records" for f in findings)


def test_spf_too_many_lookups():
    record = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(11)) + " -all"
    data, findings = analyse_spf([record], has_mx=True)
    assert data["dns_lookups"] == 11
    assert any("10 DNS lookups" in f.title for f in findings)


def test_dmarc_policies():
    data, findings = analyse_dmarc(["v=DMARC1; p=reject; rua=mailto:d@example.com"])
    assert data["policy"] == "reject" and findings == []
    _, findings = analyse_dmarc(["v=DMARC1; p=none; rua=mailto:d@example.com"])
    assert [f.severity for f in findings] == ["low"]
    _, findings = analyse_dmarc([])
    assert findings[0].title == "No DMARC record"
    _, findings = analyse_dmarc(["v=DMARC1; p=quarantine; pct=20"])
    assert {f.title for f in findings} >= {"DMARC applies to only 20% of mail"}


def test_email_security_module_with_fake_dns():
    records = {
        ("example.com", "TXT"): ["v=spf1 mx -all"],
        ("example.com", "MX"): ["10 mail.example.com"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:x@example.com"],
        ("selector1._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa; p=MIGf..."],
    }
    report = module_run("email_security", "example.com", make_ctx(records=records))
    assert report.status == "ok"
    assert report.data["spoofable"] is False
    assert report.data["dkim_selectors_found"] == ["selector1"]
    assert report.findings == []


def test_dns_module_nxdomain():
    report = module_run("dns", "nope.example", make_ctx(records={}))
    assert report.status == "empty" and "NXDOMAIN" in report.summary


def test_dns_module_lists_records():
    records = {("example.com", "A"): ["93.184.215.14"], ("example.com", "NS"): ["a.iana-servers.net"]}
    report = module_run("dns", "example.com", make_ctx(records=records))
    assert report.data["records"] == {"A": ["93.184.215.14"], "NS": ["a.iana-servers.net"]}
    assert "No CAA record" in severities(report)


# ---------------------------------------------------------------------------
# RDAP registration
# ---------------------------------------------------------------------------


def rdap_domain(created: datetime, expires: datetime, status=("client transfer prohibited",)):
    return {
        "events": [{"eventAction": "registration", "eventDate": created.isoformat()},
                   {"eventAction": "expiration", "eventDate": expires.isoformat()}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                      "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@reg.example"]]]}]}],
        "status": list(status),
        "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
    }


def test_whois_parses_rdap():
    now = datetime.now(timezone.utc)
    doc = rdap_domain(now - timedelta(days=4000), now + timedelta(days=300))
    report = module_run("whois", "example.com", make_ctx(routes({"rdap.org/domain/": doc})))
    assert report.data["registrar"] == "Example Registrar"
    assert report.data["abuse_contact"] == "abuse@reg.example"
    assert report.data["nameservers"] == ["ns1.example.com"]
    assert report.findings == []


def test_whois_flags_new_and_expiring_domains():
    now = datetime.now(timezone.utc)
    doc = rdap_domain(now - timedelta(days=3), now + timedelta(days=10), status=["active"])
    report = module_run("whois", "example.com", make_ctx(routes({"rdap.org/domain/": doc})))
    sev = severities(report)
    assert sev["Newly registered domain (3 days old)"] == "medium"
    assert any(t.startswith("Registration expires in") and s == "high" for t, s in sev.items())
    assert sev["No transfer lock"] == "low"


def test_whois_not_found():
    report = module_run("whois", "example.com", make_ctx(routes({"rdap.org/domain/": 404})))
    assert report.status == "empty"


# ---------------------------------------------------------------------------
# Certificate transparency
# ---------------------------------------------------------------------------


def test_subdomains_dedupes_and_flags_interesting_names():
    entries = [
        {"name_value": "example.com\nwww.example.com", "not_before": "2020-01-01T00:00:00"},
        {"name_value": "*.example.com\nstaging.example.com\nWWW.example.com", "not_before": "2018-05-01T00:00:00"},
        {"name_value": "vpn.example.com\nevil.com", "not_before": "2021-01-01T00:00:00"},
    ]
    report = module_run("subdomains", "example.com", make_ctx(routes({"crt.sh/": entries})))
    assert sorted(report.data["subdomains"]) == ["staging.example.com", "vpn.example.com", "www.example.com"]
    assert report.data["first_certificate"] == "2018-05-01"
    assert sorted(report.data["interesting"]) == ["staging.example.com", "vpn.example.com"]
    assert "evil.com" not in report.data["subdomains"]


# ---------------------------------------------------------------------------
# HTTP headers (SSRF guard stubbed to allow the mock host)
# ---------------------------------------------------------------------------


@pytest.fixture
def allow_resolution(monkeypatch):
    async def fake_resolve(host, port=443):
        return ["93.184.215.14"]
    monkeypatch.setattr(domain_mod, "resolve_public", fake_resolve)


def test_http_headers_grade_and_findings(allow_resolution):
    def handler(request: httpx.Request):
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"location": f"https://{request.url.host}/"})
        return httpx.Response(200, headers={
            "strict-transport-security": "max-age=63072000; includeSubDomains",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin",
            "permissions-policy": "camera=()",
            "server": "nginx",
        })

    report = module_run("http_headers", "example.com", make_ctx(handler))
    assert report.status == "ok", report.summary
    assert report.data["grade"] == "A"
    assert report.data["http_redirects_to_https"] is True
    assert report.data["security_headers_present"]["x-frame-options"] == "(via CSP frame-ancestors)"
    assert report.findings == []


def test_http_headers_weak_site(allow_resolution):
    def handler(request: httpx.Request):
        return httpx.Response(200, headers={"server": "Apache/2.4.49 (Unix)", "x-powered-by": "PHP/7.2.1",
                                            "set-cookie": "PHPSESSID=abc; path=/"})

    report = module_run("http_headers", "example.com", make_ctx(handler))
    sev = severities(report)
    assert sev["Missing strict-transport-security"] == "medium"
    assert sev["Software version disclosed"] == "low"
    assert sev["Cookies without Secure/HttpOnly"] == "low"
    assert sev["HTTP does not redirect to HTTPS"] == "medium"
    assert report.data["grade"] in ("D", "F")


def test_http_headers_refuses_redirect_to_internal_address(monkeypatch):
    async def fake_resolve(host, port=443):
        if host == "internal.example.com":
            raise domain_mod.BlockedAddress("internal.example.com resolves to a non-public address (10.0.0.5)")
        return ["93.184.215.14"]
    monkeypatch.setattr(domain_mod, "resolve_public", fake_resolve)

    def handler(request: httpx.Request):
        return httpx.Response(302, headers={"location": "http://internal.example.com/admin"})

    report = module_run("http_headers", "example.com", make_ctx(handler))
    assert report.status == "skipped"
    assert "non-public" in report.summary


def test_grade_boundaries():
    assert [grade(s) for s in (100, 90, 89, 75, 60, 45, 44, 0)] == ["A", "A", "B", "B", "C", "D", "F", "F"]


# ---------------------------------------------------------------------------
# IP modules
# ---------------------------------------------------------------------------


def test_exposure_flags_risky_ports_cves_and_tags():
    doc = {"ip": "203.0.113.5", "ports": [22, 443, 3389, 6379], "hostnames": ["host.example"],
           "cpes": ["cpe:/a:openbsd:openssh"], "tags": ["compromised", "cloud"], "vulns": ["CVE-2023-0001", "CVE-2024-0002"]}
    report = module_run("exposure", "8.8.4.4", make_ctx(routes({"internetdb.shodan.io/": doc})))
    sev = severities(report)
    assert sev["RDP exposed to the internet (port 3389)"] == "high"
    assert sev["Redis exposed to the internet (port 6379)"] == "high"
    assert sev["2 known CVEs match the software seen"] == "high"
    assert sev["Tagged 'compromised' by Shodan"] == "critical"
    assert "Tagged 'cloud' by Shodan" not in sev
    assert report.data["ports"] == [22, 443, 3389, 6379]


def test_exposure_nothing_seen():
    report = module_run("exposure", "8.8.4.4", make_ctx(routes({"internetdb.shodan.io/": 404})))
    assert report.status == "empty"


def test_geo_and_rdap():
    ipinfo = {"ip": "8.8.8.8", "hostname": "dns.google", "city": "Mountain View", "country": "US",
              "org": "AS15169 Google LLC", "anycast": True}
    rdap = {"name": "GOGL", "handle": "NET-8-8-8-0-2", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
            "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}], "country": "US",
            "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
                          "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@google.com"]]]}]}]}
    ctx = make_ctx(routes({"ipinfo.io/": ipinfo, "rdap.org/ip/": rdap}))
    geo = module_run("geo", "8.8.8.8", ctx)
    assert (geo.data["asn"], geo.data["organisation"]) == ("AS15169", "Google LLC")
    owner = module_run("ip_rdap", "8.8.8.8", ctx)
    assert owner.data["cidr"] == ["8.8.8.0/24"]
    assert owner.data["abuse_contact"] == "abuse@google.com"
    assert owner.summary.startswith("Google LLC")


def test_keyed_modules_skip_without_key():
    report = module_run("abuseipdb", "8.8.8.8", make_ctx())
    assert report.status == "skipped" and "ABUSEIPDB_API_KEY" in report.summary


def test_abuseipdb_with_key():
    payload = {"data": {"abuseConfidenceScore": 100, "totalReports": 812, "isTor": False, "usageType": "Data Center"}}
    ctx = make_ctx(routes({"api.abuseipdb.com/": payload}), abuseipdb_key="test-key")
    report = module_run("abuseipdb", "8.8.8.8", ctx)
    assert severities(report) == {"AbuseIPDB confidence 100%": "high"}


# ---------------------------------------------------------------------------
# Identity modules
# ---------------------------------------------------------------------------


def test_accounts_found_missing_and_unknown():
    table = {
        "api.github.com/users/": {"login": "neo", "name": "Thomas Anderson", "public_repos": 3},
        "gitlab.com/api/v4/users": [],
        "hacker-news.firebaseio.com/": None,  # HN answers JSON null for unknown users
        "keybase.io/": {"them": [None]},
        "dev.to/": 404,
        "hub.docker.com/": 404,
        "codeberg.org/": 404,
        "mastodon.social/": 503,  # cannot tell
        "api.chess.com/": {"name": "Neo"},
        "lichess.org/": 404,
    }
    report = module_run("accounts", "neo", make_ctx(routes(table)))
    found = {f["site"]: f for f in report.data["found"]}
    assert set(found) == {"GitHub", "Chess.com"}
    assert found["GitHub"]["details"] == {"name": "Thomas Anderson", "public_repos": 3}
    assert found["GitHub"]["url"] == "https://github.com/neo"
    assert "Hacker News" in report.data["not_found"] and "Keybase" in report.data["not_found"]
    assert report.data["could_not_check"] == ["Mastodon (mastodon.social)"]


def test_accounts_none_found():
    report = module_run("accounts", "nobody", make_ctx(routes({})))
    assert report.status == "empty"


def test_email_domain_disposable_and_missing_mx():
    report = module_run("email_domain", "x@mailinator.com",
                        make_ctx(records={("mailinator.com", "MX"): ["10 mail.mailinator.com"]}))
    assert report.data["type"] == "disposable"
    assert "Disposable email provider" in severities(report)

    report = module_run("email_domain", "x@example.org", make_ctx(records={("example.org", "A"): ["1.2.3.4"]}))
    assert severities(report)["Domain has no MX record"] == "medium"


def test_email_domain_provider_detection():
    records = {("corp.example", "MX"): ["20 backup.example.net", "10 corp-example.mail.protection.outlook.com"]}
    report = module_run("email_domain", "ceo@corp.example", make_ctx(records=records))
    assert report.data["mail_provider"] == "Microsoft 365"
    assert report.data["mx"][0].endswith("outlook.com")  # sorted by priority


def test_gravatar_profile():
    doc = {"entry": [{"displayName": "Jane", "profileUrl": "https://gravatar.com/jane",
                      "accounts": [{"url": "https://github.com/jane"}], "urls": []}]}
    report = module_run("gravatar", "jane@example.com", make_ctx(routes({"en.gravatar.com/": doc})))
    assert report.data["display_name"] == "Jane"
    assert report.data["linked_accounts"] == ["https://github.com/jane"]


def test_breaches_with_key():
    breaches = [{"Name": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Email addresses", "Passwords"]},
                {"Name": "Canva", "BreachDate": "2019-05-24", "DataClasses": ["Email addresses", "Names"]}]
    ctx = make_ctx(routes({"haveibeenpwned.com/": breaches}), hibp_key="k")
    report = module_run("breaches", "a@example.com", ctx)
    assert report.data["breaches"][0]["name"] == "Canva"  # most recent first
    assert severities(report) == {"Appears in 2 data breach(es)": "high"}


# ---------------------------------------------------------------------------
# framework behaviour
# ---------------------------------------------------------------------------


def test_module_errors_are_contained():
    report = module_run("whois", "example.com", make_ctx(routes({"rdap.org/domain/": 500})))
    assert report.status == "error" and "HTTP 500" in report.summary


def test_cache_returns_copy_marked_cached():
    from app.core import TTLCache
    cache = TTLCache(60)
    ctx = make_ctx(routes({"internetdb.shodan.io/": {"ports": [443], "vulns": [], "tags": [], "cpes": [], "hostnames": []}}))
    target = parse_target("8.8.4.4")
    first = run(run_module(MODULES["exposure"], target, ctx, cache))
    second = run(run_module(MODULES["exposure"], target, ctx, cache))
    assert (first.cached, second.cached) == (False, True)
    assert second.data == first.data
