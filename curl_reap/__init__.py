"""curl_reap: reap the web.

Three pillars in one library:
  1. Transport: ordered HTTP/1.1 over socket + ssl, with best-effort browser
     family TLS/header profiles, retries, proxy rotation, caching, and async use.
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
    detect_encoding,
    download,
    fetch,
    get,
    post,
)
from .tls import FINGERPRINTS, PROFILES, Profile
from .parser import Selector, SelectorList
from .pipelines import (
    CsvPipeline,
    DedupPipeline,
    JsonLinesPipeline,
    Pipeline,
    SqlitePipeline,
)
from .spider import Request, SitemapSpider, Spider
from .throttle import AutoThrottle


def render(url, **kwargs):
    """Fetch ``url`` in a real browser (optional Playwright extra)."""
    from .render import render as _render
    return _render(url, **kwargs)


def render_if_empty(response, **kwargs):
    """Render only when the plain-HTTP response looks hollow."""
    from .render import render_if_empty as _rie
    return _rie(response, **kwargs)


__version__ = "1.0.0"

__all__ = [
    # transport
    "get", "post", "fetch", "download", "Session", "Response", "RetryPolicy",
    "HTTPStatusError", "TransportError", "CookieJar", "PROFILES",
    "FINGERPRINTS", "Profile",
    "DiskCache",
    "detect_encoding",
    "AsyncSession", "aget", "apost",
    # rendering (optional playwright extra)
    "render", "render_if_empty",
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
