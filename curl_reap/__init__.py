"""curl_reap: reap the web.

Three pillars in one library:
  1. Transport: real browser TLS/JA3 impersonation (powered by curl_cffi) so your
     requests are not fingerprinted as a bot.
  2. Parsing: a fast lxml selector with parsel-style css/xpath plus self-healing
     selectors that survive markup changes.
  3. Orchestration: a small concurrent crawl engine with dedup, retries,
     AutoThrottle, and item pipelines.

Quick start:

    import curl_reap as reap

    page = reap.get("https://quotes.toscrape.com")
    print(page.css("span.text::text").getall())

    class Quotes(reap.Spider):
        start_urls = ["https://quotes.toscrape.com"]
        def parse(self, page):
            for q in page.css("div.quote"):
                yield {"text": q.css_first("span.text::text"),
                       "author": q.css_first("small.author::text")}
            nxt = page.css_first("li.next a::attr(href)")
            if nxt:
                yield reap.Request("https://quotes.toscrape.com" + nxt, self.parse)

    items = reap.run(Quotes, concurrency=8)
"""
from .adaptive import relocate, save, signature, similarity
from .engine import Reaper, run
from .http import Response, Session, fetch, get, post
from .parser import Selector, SelectorList
from .pipelines import CsvPipeline, DedupPipeline, JsonLinesPipeline, Pipeline
from .spider import Request, Spider
from .throttle import AutoThrottle

__version__ = "0.1.0"

__all__ = [
    "get", "post", "fetch", "Session", "Response",
    "Selector", "SelectorList",
    "Spider", "Request", "Reaper", "run",
    "Pipeline", "DedupPipeline", "JsonLinesPipeline", "CsvPipeline", "AutoThrottle",
    "signature", "similarity", "save", "relocate",
    "__version__",
]
