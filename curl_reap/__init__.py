"""curl_reap: reap the web.

Three pillars in one library:
  1. Transport: real browser TLS/JA3 impersonation (powered by curl_cffi) so your
     requests are not fingerprinted as a bot - now with smart retries/backoff,
     fingerprint + proxy rotation, a disk cache, and an async client.
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
from .adaptive import relocate, save, signature, similarity
from .aio import AsyncSession, aget, apost
from .cache import DiskCache
from .engine import Reaper, run
from .geocode import Geocoder, geocode
from .http import (
    FINGERPRINTS,
    NODEMAVEN_URL,
    HTTPStatusError,
    Response,
    RetryPolicy,
    Session,
    fetch,
    get,
    post,
)
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

__version__ = "0.2.2"

__all__ = [
    # transport
    "get", "post", "fetch", "Session", "Response", "RetryPolicy",
    "HTTPStatusError", "FINGERPRINTS", "DiskCache",
    "AsyncSession", "aget", "apost",
    # parsing
    "Selector", "SelectorList",
    "signature", "similarity", "save", "relocate",
    # orchestration
    "Spider", "SitemapSpider", "Request", "Reaper", "run",
    "Pipeline", "DedupPipeline", "JsonLinesPipeline", "CsvPipeline",
    "SqlitePipeline", "AutoThrottle",
    # extras
    "Geocoder", "geocode", "NODEMAVEN_URL",
    "__version__",
]
