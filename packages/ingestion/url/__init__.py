"""URL extraction, canonicalization, and guarded resolution.

Every URL here came from a stranger. Resolving one means our server makes a
request an attacker chose, which is the definition of SSRF — so the guards are
not optional and not configurable away:

* the destination must resolve to a public address, checked after DNS, so
  `evil.test` pointing at 169.254.169.254 is refused like a literal would be;
* every hop of a redirect chain is re-checked, because hop two is where the
  attacker actually puts the internal address;
* redirects are capped, the timeout is hard, and no body is streamed beyond the
  size cap.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit

import httpx

from packages.ingestion.limits import DEFAULT_LIMITS, IngestionLimits
from packages.shared.schemas.content import UrlObservation

_URL_PATTERN = re.compile(
    r"""(?xi)
    \b(
        (?:https?://|hxxps?://)            # scheme, plain or defanged
        (?:\[\.\]|[^\s<>"')\]])+           # `[.]` is part of the URL, not a bracket
        |
        [a-z0-9](?:[a-z0-9\-]*[a-z0-9])?   # host.tld/path, defanged or not
        (?:(?:\.|\[\.\])[a-z0-9\-]+)+
        (?:/(?:\[\.\]|[^\s<>"')\]])*)?
    )
    """
)

# A host is either dotted-and-TLD-shaped or a literal address.
_LOOKS_LIKE_HOST = re.compile(r"^[a-z0-9\-\.]+\.[a-z]{2,}$", re.IGNORECASE)


def _is_plausible_host(host: str) -> bool:
    if not host:
        return False
    if _LOOKS_LIKE_HOST.match(host):
        return True
    try:  # IP literals are URLs too, and are exactly what SSRF payloads use
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
_TRAILING_PUNCTUATION = ".,;:!?)]}'\""


def refang(url: str) -> str:
    """Undo the defanging analysts and messaging apps apply to unsafe links."""
    return (
        url.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("[://]", "://")
        .replace("hxxp", "http")
        .replace("hXXp", "http")
    )


def canonicalize(url: str) -> str:
    """A comparable form: scheme lowercased, default port dropped, no fragment."""
    candidate = refang(url).strip().rstrip(_TRAILING_PUNCTUATION)
    if "://" not in candidate:
        candidate = f"http://{candidate}"

    parts = urlsplit(candidate)
    host = (parts.hostname or "").lower()
    if parts.port and not (
        (parts.scheme == "http" and parts.port == 80)
        or (parts.scheme == "https" and parts.port == 443)
    ):
        host = f"{host}:{parts.port}"

    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), host, path, parts.query, ""))


def extract_urls(text: str, *, limits: IngestionLimits = DEFAULT_LIMITS) -> tuple[str, ...]:
    """Every URL in the text, defanged ones included, in order, deduplicated."""
    if not text:
        return ()

    found: list[str] = []
    for match in _URL_PATTERN.finditer(text):
        candidate = match.group(1).rstrip(_TRAILING_PUNCTUATION)
        refanged = refang(candidate)
        try:
            host = urlsplit(refanged if "://" in refanged else f"http://{refanged}").hostname or ""
        except ValueError:  # malformed brackets and the like: not a URL
            continue
        if not _is_plausible_host(host):
            continue
        if candidate not in found:
            found.append(candidate)
        if len(found) >= limits.max_urls:
            break
    return tuple(found)


def _address_is_public(address: str) -> tuple[bool, str | None]:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False, f"not an IP address: {address}"

    # Order matters: loopback, link-local and unspecified are *also* private, so
    # the specific category has to be named before the general one.
    if ip.is_loopback:
        return False, f"loopback address {ip}"
    if ip.is_link_local:
        return False, f"link-local address {ip}"     # 169.254.169.254 lives here
    if ip.is_multicast:
        return False, f"multicast address {ip}"
    if ip.is_unspecified:
        return False, f"reserved address {ip}"
    if ip.is_private:
        return False, f"private address {ip}"
    if ip.is_reserved:
        return False, f"reserved address {ip}"
    return True, None


def classify_target(url: str) -> tuple[bool, str | None]:
    """`(allowed, reason_if_blocked)` for one URL, after resolving its host."""
    parts = urlsplit(url)

    if parts.scheme not in ("http", "https"):
        return False, f"unsupported scheme '{parts.scheme}'"

    host = parts.hostname
    if not host:
        return False, "no host"

    try:  # a literal address never reaches DNS
        ipaddress.ip_address(host)
        return _address_is_public(host)
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, parts.port or 80, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return False, f"dns resolution failed: {exc}"

    if not infos:
        return False, "dns returned no addresses"

    # Every resolved address must be public: one internal answer is enough to
    # make the request unsafe (DNS rebinding returns several).
    for info in infos:
        allowed, reason = _address_is_public(info[4][0])
        if not allowed:
            return False, reason
    return True, None


async def resolve_url(url: str, *, limits: IngestionLimits = DEFAULT_LIMITS) -> UrlObservation:
    """Follow redirects by hand, re-checking the guard at every hop."""
    raw = url
    normalized = canonicalize(url)
    was_defanged = refang(url) != url

    def _observation(**overrides) -> UrlObservation:
        base = dict(
            raw=raw,
            normalized=normalized,
            host=urlsplit(normalized).hostname or "",
            was_defanged=was_defanged,
        )
        return UrlObservation(**{**base, **overrides})

    allowed, reason = classify_target(normalized)
    if not allowed:
        return _observation(blocked=True, block_reason=reason)

    current = normalized
    chain: list[str] = []

    try:
        async with httpx.AsyncClient(
            timeout=limits.request_timeout_seconds, follow_redirects=False
        ) as client:
            for _ in range(limits.max_redirects + 1):
                response = await client.get(current, headers={"Accept": "text/html"})

                if response.status_code not in (301, 302, 303, 307, 308):
                    return _observation(
                        final_url=current,
                        redirect_chain=tuple(chain),
                        status_code=response.status_code,
                    )

                location = response.headers.get("location")
                if not location:
                    return _observation(
                        final_url=current,
                        redirect_chain=tuple(chain),
                        status_code=response.status_code,
                    )

                current = canonicalize(str(httpx.URL(current).join(location)))
                chain.append(current)

                allowed, reason = classify_target(current)
                if not allowed:  # the interesting hop is never the first one
                    return _observation(
                        blocked=True,
                        block_reason=f"redirect to blocked target: {reason}",
                        redirect_chain=tuple(chain),
                    )

        return _observation(
            blocked=True,
            block_reason=f"exceeded {limits.max_redirects} redirects",
            redirect_chain=tuple(chain),
        )
    except httpx.TimeoutException:
        return _observation(blocked=True, block_reason="timed out", redirect_chain=tuple(chain))
    except httpx.HTTPError as exc:
        return _observation(
            blocked=True, block_reason=f"request failed: {exc}", redirect_chain=tuple(chain)
        )
