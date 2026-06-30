"""Spider and Request: the unit of work for the crawl engine."""
from __future__ import annotations


class Request:
    """A pending fetch plus the callback that parses its Response."""

    def __init__(self, url, callback=None, method="GET", meta=None, **kw):
        self.url = url
        self.callback = callback
        self.method = method
        self.meta = meta or {}
        self.kw = kw

    def fingerprint(self):
        return f"{self.method}:{self.url}"

    def __repr__(self):
        return f"<Request {self.method} {self.url}>"


class Spider:
    """Subclass this: set start_urls and implement parse(self, page)."""

    name = "reap"
    start_urls = []

    def start(self):
        for url in self.start_urls:
            yield Request(url, self.parse)

    def parse(self, page):
        raise NotImplementedError("Spider.parse must be implemented")
