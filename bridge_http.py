"""Bounded HTTP with destination checks on the addresses actually used to connect."""

import asyncio
import ipaddress
import socket
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator, Mapping, Sequence

import aiohttp
from yarl import URL


class CapabilityError(ValueError):
    """Static messages only: request data, credentials and server errors stay private."""


def public_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


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

    @asynccontextmanager
    async def open(
        self,
        method: str,
        destination: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: object = None,
    ) -> AsyncIterator[aiohttp.ClientResponse]:
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

    async def read(self, response: aiohttp.ClientResponse) -> str:
        data = bytearray()
        async for chunk in response.content.iter_chunked(4096):
            data.extend(chunk)
            if len(data) > self.max_bytes:
                raise CapabilityError("Response too large")
        try:
            return data.decode("utf-8")
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
