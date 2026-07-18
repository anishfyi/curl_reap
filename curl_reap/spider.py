"""Spider and Request: the unit of work for the crawl engine."""
from __future__ import annotations

import hashlib
import json
import re


class Request:
    """A pending fetch plus the callback that parses its Response.

    priority: higher runs sooner. errback: called with the exception (or the
    failed Response) when the fetch ultimately fails. dont_filter skips dedup.
    """

    def __init__(self, url, callback=None, method="GET", meta=None, priority=0,
                 errback=None, dont_filter=False, **kw):
        self.url = url
        self.callback = callback
        self.method = method
        self.meta = meta or {}
        self.priority = priority
        self.errback = errback
        self.dont_filter = dont_filter
        self.kw = kw

    def fingerprint(self):
        body = self.kw.get("data") or self.kw.get("json") or self.kw.get("params")
        if body is None:
            return f"{self.method}:{self.url}"
        blob = json.dumps(body, sort_keys=True, default=str)
        return f"{self.method}:{self.url}:{hashlib.sha1(blob.encode()).hexdigest()[:12]}"

    def __repr__(self):
        return f"<Request {self.method} {self.url}>"


class Spider:
    """Subclass this: set start_urls and implement parse(self, page).

    Optional knobs:
      allowed_domains = ["example.com"]   confine the crawl (subdomains included)
      max_depth = 3                       stop following deeper than this
      custom_headers = {...}              extra headers for every request
    """

    name = "reap"
    start_urls = []
    allowed_domains = None
    max_depth = None
    custom_headers = None

    def start(self):
        for url in self.start_urls:
            yield Request(url, self.parse)

    def parse(self, page):
        raise NotImplementedError("Spider.parse must be implemented")


class SitemapSpider(Spider):
    """Crawl straight from sitemap.xml: point it at one or more sitemaps (or a
    site root - /sitemap.xml is assumed), filter urls with url_pattern, and
    implement parse(page) for each content page.

        class Products(reap.SitemapSpider):
            sitemap_urls = ["https://shop.example.com"]
            url_pattern = r"/product/"
            def parse(self, page): ...
    """

    sitemap_urls = []
    url_pattern = None

    _LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>")

    def start(self):
        for url in self.sitemap_urls:
            if not url.rstrip("/").endswith((".xml", ".xml.gz")):
                url = url.rstrip("/") + "/sitemap.xml"
            yield Request(url, self.parse_sitemap, dont_filter=True)

    def parse_sitemap(self, page):
        import gzip
        raw = page.content or b""
        # Gzipped sitemaps (.xml.gz, or gzip magic bytes) must be decompressed
        # before parsing; page.text would just be binary noise.
        if raw[:2] == b"\x1f\x8b" or (page.url or "").rstrip("/").endswith(".gz"):
            try:
                raw = gzip.decompress(raw)
            except (OSError, EOFError):
                raw = page.content or b""
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        pat = re.compile(self.url_pattern) if self.url_pattern else None
        for loc in self._LOC.findall(text):
            loc = loc.strip()
            if loc.rstrip("/").endswith((".xml", ".xml.gz")):
                yield Request(loc, self.parse_sitemap, dont_filter=True)
            elif pat is None or pat.search(loc):
                yield Request(loc, self.parse)
