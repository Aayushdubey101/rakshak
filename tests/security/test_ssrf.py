"""SSRF guards. Phase 4's security gate.

Resolving a URL from a message means our server makes a request an attacker
chose. These tests are the proof it cannot be pointed inward — at localhost, at
RFC1918, or at a cloud metadata endpoint — whether the address arrives as a
literal, through DNS, or on the second hop of a redirect.
"""

import socket

import httpx
import pytest
import respx

from packages.ingestion import ingest
from packages.ingestion.limits import IngestionLimits
from packages.ingestion.url import classify_target, resolve_url
from packages.shared.schemas import InvestigationRequest, Platform, RejectionReason

PUBLIC_IP = "93.184.216.34"


@pytest.fixture
def dns(monkeypatch):
    """Point every hostname at chosen addresses, without touching a resolver."""
    def _install(*addresses: str):
        def _getaddrinfo(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port or 80))
                for address in addresses
            ]

        monkeypatch.setattr("packages.ingestion.url.socket.getaddrinfo", _getaddrinfo)
    return _install


# --- literal addresses -------------------------------------------------------

@pytest.mark.parametrize(
    "url,fragment",
    [
        ("http://127.0.0.1/admin", "loopback"),
        ("http://10.0.0.5/internal", "private"),
        ("http://192.168.1.1/router", "private"),
        ("http://172.16.0.1/", "private"),
        ("http://169.254.169.254/latest/meta-data/", "link-local"),  # cloud metadata
        ("http://[::1]/", "loopback"),
        ("http://[fd00::1]/", "private"),
        ("http://0.0.0.0/", "reserved"),
        ("http://224.0.0.1/", "multicast"),
    ],
)
def test_internal_literals_are_refused(url, fragment):
    allowed, reason = classify_target(url)
    assert allowed is False
    assert fragment in reason


def test_public_literal_is_allowed():
    assert classify_target(f"http://{PUBLIC_IP}/") == (True, None)


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "gopher://evil.test/", "ftp://evil.test/x", "javascript:alert(1)"]
)
def test_only_http_schemes_are_allowed(url):
    allowed, reason = classify_target(url)
    assert allowed is False
    assert "scheme" in reason or "no host" in reason


# --- through DNS -------------------------------------------------------------

def test_hostname_resolving_to_metadata_is_refused(dns):
    """The literal is obvious; this is the version attackers actually use."""
    dns("169.254.169.254")
    allowed, reason = classify_target("http://harmless-looking.test/")
    assert allowed is False and "link-local" in reason


def test_one_internal_answer_poisons_the_whole_set(dns):
    """DNS rebinding returns a public and a private address together."""
    dns(PUBLIC_IP, "10.0.0.5")
    allowed, reason = classify_target("http://rebind.test/")
    assert allowed is False and "private" in reason


def test_unresolvable_host_is_refused(monkeypatch):
    def _boom(*args, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr("packages.ingestion.url.socket.getaddrinfo", _boom)
    allowed, reason = classify_target("http://nx.invalid/")
    assert allowed is False and "dns" in reason


# --- redirects ---------------------------------------------------------------

@respx.mock
async def test_redirect_to_an_internal_address_is_blocked(monkeypatch):
    """Hop one is public, hop two is the metadata service."""
    by_host = {"public.test": PUBLIC_IP, "metadata.test": "169.254.169.254"}

    def _getaddrinfo(host, port, *args, **kwargs):
        address = by_host.get(host, PUBLIC_IP)
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port or 80))]

    monkeypatch.setattr("packages.ingestion.url.socket.getaddrinfo", _getaddrinfo)
    respx.get("http://public.test/").mock(
        return_value=httpx.Response(302, headers={"location": "http://metadata.test/latest/"})
    )

    observation = await resolve_url("http://public.test/")

    assert observation.blocked is True
    assert "redirect to blocked target" in observation.block_reason
    assert observation.redirect_chain == ("http://metadata.test/latest/",)


@respx.mock
async def test_redirect_chain_is_capped(dns):
    dns(PUBLIC_IP)
    respx.get(url__regex=r"http://loop\.test/.*").mock(
        return_value=httpx.Response(302, headers={"location": "http://loop.test/next"})
    )

    observation = await resolve_url("http://loop.test/", limits=IngestionLimits(max_redirects=2))

    assert observation.blocked is True
    assert "exceeded 2 redirects" in observation.block_reason


@respx.mock
async def test_successful_resolution_records_the_final_url(dns):
    dns(PUBLIC_IP)
    respx.get("http://short.test/abc").mock(
        return_value=httpx.Response(301, headers={"location": "http://short.test/real"})
    )
    respx.get("http://short.test/real").mock(return_value=httpx.Response(200, text="ok"))

    observation = await resolve_url("http://short.test/abc")

    assert observation.blocked is False
    assert observation.final_url == "http://short.test/real"
    assert observation.status_code == 200


@respx.mock
async def test_timeout_is_reported_not_raised(dns):
    dns(PUBLIC_IP)
    respx.get("http://slow.test/").mock(side_effect=httpx.ConnectTimeout("too slow"))

    observation = await resolve_url("http://slow.test/")

    assert observation.blocked is True and observation.block_reason == "timed out"


@respx.mock
async def test_connection_failure_is_reported_not_raised(dns):
    dns(PUBLIC_IP)
    respx.get("http://down.test/").mock(side_effect=httpx.ConnectError("refused"))

    observation = await resolve_url("http://down.test/")

    assert observation.blocked is True and "request failed" in observation.block_reason


# --- through ingest ----------------------------------------------------------

async def test_ingest_never_resolves_unless_asked():
    """Parsing a message must not make an outbound request as a side effect."""
    with respx.mock(assert_all_called=False) as mock:
        content = await ingest(
            InvestigationRequest(platform=Platform.WEB, text="see http://127.0.0.1/admin")
        )
    assert len(mock.calls) == 0
    assert content.urls[0].blocked is False  # observed, not judged
    assert content.rejections == ()


async def test_blocked_urls_become_typed_rejections(dns):
    dns("10.0.0.5")
    content = await ingest(
        InvestigationRequest(platform=Platform.WEB, text="open http://internal.test/"),
        resolve_urls=True,
    )

    assert content.blocked_urls
    assert content.rejections[0].reason is RejectionReason.BLOCKED_TARGET
    assert "private" in content.rejections[0].detail
