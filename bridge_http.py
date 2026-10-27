"""Bounded HTTP with destination checks on the addresses actually used to connect."""

import asyncio
import ipaddress
import re
import socket
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator, Mapping, Sequence

import aiohttp
from yarl import URL

from bridge_errors import CapabilityError as CapabilityError

V6_SPECIAL = tuple(
    ipaddress.IPv6Network(value)
    for value in (
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "2001::/23",
        "2002::/16",
    )
)
V4_SPECIAL = ipaddress.IPv4Network("192.0.0.0/24")
V4_ANYCAST = {ipaddress.IPv4Address("192.0.0.9"), ipaddress.IPv4Address("192.0.0.10")}


def public_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped:
            address = address.ipv4_mapped
        elif address.is_site_local or any(address in network for network in V6_SPECIAL):
            return False
    # Python 3.11 predates several non-global classifications fixed in 3.13.
    if (
        isinstance(address, ipaddress.IPv4Address)
        and address in V4_SPECIAL
        and address not in V4_ANYCAST
    ):
        return False
    return address.is_global and not address.is_multicast and not address.is_reserved


def checked_url(value: object, internal_origins: Sequence[str] = ()) -> URL:
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) <= 32 for c in value):
        raise CapabilityError("Invalid destination")
    try:
        url = URL(value)
        host = url.host
        origin = str(url.origin())
    except (ValueError, UnicodeError):
        raise CapabilityError("Invalid destination") from None
    if (
        url.scheme not in ("http", "https")
        or not host
        or "%" in host
        or url.user is not None
        or url.fragment
        or (url.scheme != "https" and origin not in internal_origins)
    ):
        raise CapabilityError("Destination denied")
    # aiohttp skips its resolver for numeric hosts, so validate them here as well.
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and origin not in internal_origins and not public_address(host):
        raise CapabilityError("Destination denied")
    return url


class GuardedResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, internal: bool = False) -> None:
        self.internal = internal
        self.delegate = aiohttp.resolver.ThreadedResolver()

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> list[aiohttp.abc.ResolveResult]:
        answers = await self.delegate.resolve(host, port, family)
        if not answers or (
            not self.internal and any(not public_address(answer["host"]) for answer in answers)
        ):
            raise CapabilityError("Destination denied")
        return answers

    async def close(self) -> None:
        await self.delegate.close()


class SafeHTTP:
    def __init__(
        self,
        *,
        internal_origins: Sequence[str] = (),
        max_bytes: int = 65536,
        seconds: float = 15,
        redirects: int = 3,
    ) -> None:
        self.internal_origins = tuple(internal_origins)
        self.max_bytes, self.seconds, self.redirects = max_bytes, seconds, redirects

    async def validate_browser_destination(self, destination: str) -> None:
        """Apply DNS admission before handing an authorization URL to a browser.

        The browser owns its subsequent resolution/redirects; this preflight cannot
        pin its socket like open() does for bridge-owned HTTP requests.
        """
        url = checked_url(destination, self.internal_origins)
        resolver = GuardedResolver(str(url.origin()) in self.internal_origins)
        try:
            async with asyncio.timeout(self.seconds):
                await resolver.resolve(str(url.host), url.port or 443, family=socket.AF_UNSPEC)
        finally:
            await resolver.close()

    @asynccontextmanager
    async def open(
        self,
        method: str,
        destination: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: object = None,
        form: Mapping[str, str] | None = None,
    ) -> AsyncIterator[aiohttp.ClientResponse]:
        if form is not None and body is not None:
            raise CapabilityError("Ambiguous request body")
        url = checked_url(destination, self.internal_origins)
        resolver = GuardedResolver(str(url.origin()) in self.internal_origins)
        connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False, force_close=True)
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                trust_env=False,
                cookie_jar=aiohttp.DummyCookieJar(),
                auto_decompress=False,
                timeout=aiohttp.ClientTimeout(total=self.seconds),
            ) as session:
                async with session.request(
                    method,
                    url,
                    headers={"Accept-Encoding": "identity", **(headers or {})},
                    json=body,
                    data=form,
                    allow_redirects=False,
                ) as response:
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise CapabilityError("Compressed response denied")
                    if (
                        response.content_length is not None
                        and response.content_length > self.max_bytes
                    ):
                        raise CapabilityError("Response too large")
                    yield response
        finally:
            await resolver.close()

    async def chunks(self, response: aiohttp.ClientResponse) -> AsyncIterator[bytes]:
        size = 0
        async for chunk in response.content.iter_chunked(4096):
            size += len(chunk)
            if size > self.max_bytes:
                raise CapabilityError("Response too large")
            yield chunk

    async def read(self, response: aiohttp.ClientResponse) -> str:
        data = b"".join([chunk async for chunk in self.chunks(response)])
        try:
            return data.decode("utf-8")
        except UnicodeError:
            raise CapabilityError("Invalid response encoding") from None

    async def lines(self, response: aiohttp.ClientResponse) -> AsyncIterator[str]:
        """Strict UTF-8 lines, including CRLF split across network chunks."""
        buffer = b""
        skip_lf = False
        try:
            async for chunk in self.chunks(response):
                if skip_lf:
                    if chunk.startswith(b"\n"):
                        chunk = chunk[1:]
                    skip_lf = False
                buffer += chunk
                while match := re.search(rb"\r\n|\r|\n", buffer):
                    # CR terminates immediately; a following LF is the same delimiter.
                    skip_lf = match.group() == b"\r" and match.end() == len(buffer)
                    yield buffer[: match.start()].decode("utf-8")
                    buffer = buffer[match.end() :]
            # Validate but do not dispatch an unterminated SSE line.
            buffer.decode("utf-8")
        except UnicodeError:
            raise CapabilityError("Invalid response encoding") from None

    async def page(self, destination: str) -> str:
        # One deadline covers DNS, all redirect hops and the final body.
        async with asyncio.timeout(self.seconds):
            hop = 0
            while True:
                async with self.open("GET", destination) as response:
                    if response.status in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location")
                        if not location or hop == self.redirects:
                            raise CapabilityError("Redirect limit reached")
                        destination = str(response.url.join(URL(location)))
                        hop += 1
                        continue
                    if response.status != 200:
                        raise CapabilityError("Web request failed")
                    if not (
                        response.content_type.startswith("text/")
                        or response.content_type == "application/json"
                    ):
                        raise CapabilityError("Unsupported page type")
                    return await self.read(response)
