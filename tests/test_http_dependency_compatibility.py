"""Exercise the installed HTTP packages together over a real loopback connection."""

import asyncio

from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer
from multidict import MultiDict
from yarl import URL


def test_url_preserves_international_hostname_with_cached_properties():
    url = URL("https://fa\u00df.de/echo")
    assert url.host == "fa\u00df.de"
    assert url.raw_host == "xn--fa-hia.de"
    # Repeated reads and a derived URL exercise the installed property cache too.
    assert url.host == "fa\u00df.de"
    queried = url.with_query([("tag", "first"), ("tag", "second")])
    assert queried.raw_host == "xn--fa-hia.de"
    assert queried.query.getall("tag") == ["first", "second"]


def test_http_preserves_repeated_query_parameters_and_headers():
    async def scenario():
        async def echo(request):
            return web.json_response(
                {
                    "query": request.query.getall("tag"),
                    "headers": request.headers.getall("X-Tag"),
                }
            )

        app = web.Application()
        app.router.add_get("/echo", echo)
        async with TestServer(app, host="127.0.0.1") as server, ClientSession() as client:
            async with client.get(
                server.make_url("/echo"),
                params=MultiDict([("tag", "a & b"), ("tag", "second")]),
                headers=MultiDict([("X-Tag", "first"), ("X-Tag", "second")]),
            ) as response:
                assert response.status == 200
                assert await response.json() == {
                    "query": ["a & b", "second"],
                    "headers": ["first", "second"],
                }

    asyncio.run(scenario())
