import pytest

from app.netguard import BlockedAddress, is_public, resolve_public
from app.targets import InvalidTarget, parse_target
from conftest import run


@pytest.mark.parametrize("text, kind, value", [
    ("example.com", "domain", "example.com"),
    ("  WWW.Example.COM. ", "domain", "www.example.com"),
    ("https://sub.example.co.uk/login?x=1", "domain", "sub.example.co.uk"),
    ("bücher.de", "domain", "xn--bcher-kva.de"),
    ("8.8.8.8", "ip", "8.8.8.8"),
    ("2001:4860:4860::8888", "ip", "2001:4860:4860::8888"),
    ("[2001:db8::1]", "ip", "2001:db8::1"),
    ("Alice.Smith+tag@Example.org", "email", "Alice.Smith+tag@example.org"),
    ("octocat", "username", "octocat"),
    ("@octocat", "username", "octocat"),
    ("john_doe-99", "username", "john_doe-99"),
])
def test_auto_detection(text, kind, value):
    t = parse_target(text)
    assert (t.kind, t.value) == (kind, value)


def test_email_exposes_domain():
    assert parse_target("a@b.example.com").domain == "b.example.com"
    assert parse_target("8.8.8.8").domain is None


def test_explicit_type_overrides_detection():
    # "github.com" would be a domain, but someone may really mean the username
    assert parse_target("example", "username").kind == "username"
    with pytest.raises(InvalidTarget):
        parse_target("not-an-ip", "ip")
    with pytest.raises(InvalidTarget):
        parse_target("example.com", "email")


@pytest.mark.parametrize("bad", ["", "   ", "a b c", "<script>", "x" * 301, "two@@at.com", "user@nodot", "-bad.com"])
def test_invalid_input(bad):
    with pytest.raises(InvalidTarget):
        parse_target(bad)


@pytest.mark.parametrize("ip, public", [
    ("8.8.8.8", True), ("1.1.1.1", True), ("2606:4700::1111", True),
    ("127.0.0.1", False), ("10.1.2.3", False), ("192.168.1.1", False), ("172.16.0.1", False),
    ("169.254.169.254", False), ("100.64.0.1", False), ("0.0.0.0", False), ("::1", False),
    ("fc00::1", False), ("::ffff:127.0.0.1", False), ("224.0.0.1", False),
])
def test_is_public(ip, public):
    assert is_public(ip) is public


def test_resolve_public_blocks_internal_targets():
    with pytest.raises(BlockedAddress):
        run(resolve_public("127.0.0.1"))
    with pytest.raises(BlockedAddress):
        run(resolve_public("169.254.169.254"))
    with pytest.raises(BlockedAddress):
        run(resolve_public("localhost"))  # resolves to loopback without any network access
    assert run(resolve_public("8.8.8.8")) == ["8.8.8.8"]
