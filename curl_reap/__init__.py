"""curl_reap: reap the web.

Three pillars in one library:
  1. Transport: a native TLS 1.3 client and built-in HTTP/2 that replay each
     impersonate target's captured ClientHello, HTTP/2 framing and headers
     (OpenSSL fallback for TLS-1.2-only servers), ordered HTTP/1.1, WebSocket,
     retries, profile and proxy rotation, cookies, caching, and async use.
  2. Parsing: a fast lxml selector with parsel-style css/xpath, self-healing
     selectors, and one-call structured extraction (jsonld, meta, links, images,
     tables, markdown).
  3. Orchestration: a small concurrent crawl engine with a continuous scheduler,
     per-domain AutoThrottle, robots.txt, depth/domain limits, dedup, retries,
     and item pipelines (jsonl/csv/sqlite).

Quick start:

    import curl_reap as reap

    page = reap.get("https://quotes.toscrape.com")
    print(page.css("span.text::text").getall())
    print(page.markdown())          # readable text
    print(page.jsonld())            # structured data

    class Quotes(reap.Spider):
        start_urls = ["https://quotes.toscrape.com"]
        def parse(self, page):
            for q in page.css("div.quote"):
                yield {"text": q.css_first("span.text::text"),
                       "author": q.css_first("small.author::text")}
            nxt = page.css_first("li.next a::attr(href)")
            if nxt:
                yield page.follow(nxt)

    items = reap.run(Quotes, concurrency=8)

Command line:

    reap get https://example.com --css "h1::text"
    reap crawl https://quotes.toscrape.com --css "span.text::text" -o out.jsonl
"""
from . import pipelines as pipelines
from .adaptive import relocate, save, signature, similarity
from .aio import AsyncSession, aget, apost
from .cache import DiskCache
from .engine import Reaper, run
from .geocode import Geocoder, geocode
from .http import (
    CookieJar,
    HTTPStatusError,
    Response,
    RetryPolicy,
    Session,
    TransportError,
    URLPolicyError,
    detect_encoding,
    download,
    fetch,
    get,
    post,
)
from .tls import FINGERPRINTS, PROFILES, Profile
from .websocket import AsyncWebSocket, WebSocket
from .parser import Selector, SelectorList
from .pipelines import (
    CsvPipeline,
    DedupPipeline,
    JsonLinesPipeline,
    Pipeline,
    SqlitePipeline,
)
from .render import BrowserSession, render, render_if_empty
from .spider import Request, SitemapSpider, Spider
from .throttle import AutoThrottle

# The native engines are loaded with the package, not lazily on first request.
# transport.py imports them inside functions; two threads making their first
# HTTP/2 request concurrently (or racing another hpack user) can deadlock
# Python 3.14's per-module import locks. Package import is serialized by the
# import system, so doing it here removes the race, and every later lazy
# ``from ._h2 import ...`` is a plain sys.modules lookup.
from . import _h2  # noqa: F401  (cryptography and hpack are required deps)
from . import _tls  # noqa: F401

__version__ = "2.0.0"

__all__ = [
    # transport
    "get", "post", "fetch", "download", "Session", "Response", "RetryPolicy",
    "HTTPStatusError", "TransportError", "URLPolicyError", "CookieJar",
    "PROFILES",
    "FINGERPRINTS", "Profile",
    "DiskCache",
    "detect_encoding",
    "AsyncSession", "aget", "apost",
    "WebSocket", "AsyncWebSocket",
    # rendering (optional playwright extra)
    "render", "render_if_empty", "BrowserSession",
    # parsing
    "Selector", "SelectorList",
    "signature", "similarity", "save", "relocate",
    # orchestration
    "Spider", "SitemapSpider", "Request", "Reaper", "run",
    "Pipeline", "DedupPipeline", "JsonLinesPipeline", "CsvPipeline",
    "SqlitePipeline", "pipelines", "AutoThrottle",
    # extras
    "Geocoder", "geocode",
    "__version__",
]
