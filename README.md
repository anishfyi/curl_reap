<p align="center">
  <img src="https://raw.githubusercontent.com/anishfyi/curl_reap/main/assets/logo.png" alt="curl_reap" width="440" />
</p>

<p align="center"><b>Reap the web.</b> Browser-grade TLS impersonation, self-healing selectors, one-call structured extraction, and a concurrent crawl engine, in one small library.</p>

<p align="center">
  <code>pip install curl_reap</code>
</p>

<p align="center">
  <a href="https://anishfyi.github.io/curl_reap/"><b>Documentation</b></a>
  &nbsp;&middot;&nbsp; <a href="https://pypi.org/project/curl-reap/">PyPI</a>
  &nbsp;&middot;&nbsp; <a href="https://github.com/anishfyi/curl_reap">Source</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/curl-reap/"><img src="https://img.shields.io/pypi/v/curl-reap?color=C9871A&label=pypi" alt="PyPI version"></a>
  <img src="https://img.shields.io/pypi/pyversions/curl-reap?color=C9871A" alt="Python versions">
  <img src="https://img.shields.io/badge/license-MIT-2ea44f" alt="MIT license">
  <a href="https://anishfyi.github.io/curl_reap/"><img src="https://img.shields.io/badge/docs-curl__reap-C9871A" alt="Docs"></a>
</p>

---

<h3 align="center">Sponsors</h3>

<p align="center">
  <a href="https://go.nodemaven.com/curlreap" title="NodeMaven - residential and mobile proxies">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/anishfyi/curl_reap/main/assets/sponsors/nodemaven-dark.svg">
      <img src="https://raw.githubusercontent.com/anishfyi/curl_reap/main/assets/sponsors/nodemaven-light.svg" alt="NodeMaven" height="40">
    </picture>
  </a>
</p>

---

Full documentation with deep API reference and examples: **https://anishfyi.github.io/curl_reap/**

## Why

Modern scraping needs three things, and today you reach for three different tools:

1. **Get past the door.** Sites fingerprint your TLS handshake and block stock Python clients. `curl_cffi` solves this with real Chrome/Safari fingerprints.
2. **Survive markup changes.** Plain CSS and XPath break the moment a site renames a class. Scrapling pioneered self-healing selectors that re-find the element anyway.
3. **Crawl at scale.** Concurrency, throttling, retries, dedup, and pipelines. That is Scrapy.

`curl_reap` takes the best idea from each and puts them behind one friendly API.

| | curl_cffi | Scrapy | Scrapling | **curl_reap** |
|---|:---:|:---:|:---:|:---:|
| Real browser TLS / JA3 | yes | no | partial | **yes** |
| Parser built in | no | yes | yes | **yes** |
| Self-healing selectors | no | no | yes | **yes** |
| Structured extraction (jsonld/meta/tables/markdown) | no | no | partial | **yes** |
| Concurrent crawl engine | no | yes | no | **yes** |
| AutoThrottle, retries, pipelines | no | yes | no | **yes** |
| Fingerprint + proxy rotation | partial | no | no | **yes** |
| Async client | yes | no | partial | **yes** |
| Disk response cache | no | partial | no | **yes** |
| One small dependency set | yes | no | no | **yes** |

## New in 0.3.0

- **Encoding detection.** Pages decode cleanly even when the server omits or lies about the charset (BOM, Content-Type, `<meta charset>`, then charset-normalizer if it is installed). `Response.encoding` exposes the result.
- **Conditional cache revalidation.** A stale `DiskCache` entry revalidates with `If-None-Match` / `If-Modified-Since`; a `304 Not Modified` serves the cached body instead of re-downloading.
- **robots.txt Crawl-delay and Sitemap discovery.** The crawler floors its per-domain pace at the site's `Crawl-delay`, and surfaces declared sitemaps via `Reaper.discovered_sitemaps`.
- **Gzipped sitemaps.** `SitemapSpider` decompresses `.xml.gz` sitemaps and indexes before parsing.
- **Auto proxy rotation on a block.** On a 403/407/429 with a proxy pool configured, the session rotates onto a fresh proxy and retries.

## Install

```bash
pip install curl_reap
```

Requires Python 3.9+. Pulls in `curl_cffi`, `lxml`, and `cssselect`.

## Quick start

A one-shot fetch parses like parsel, but the request carries a genuine browser fingerprint:

```python
import curl_reap as reap

page = reap.get("https://quotes.toscrape.com", impersonate="chrome124")
print(page.css("span.text::text").getall())
print(page.css_first("small.author::text"))
```

## Structured extraction

The answers most scrapes actually want are one method call away, no selectors required:

```python
page = reap.get("https://example.com/product/42")

page.jsonld()      # all JSON-LD blocks as dicts (product/article/event data)
page.meta_tags()   # {title, description, og:*, twitter:*, canonical, ...}
page.links(internal_only=True)   # [{"url": ..., "text": ...}, ...] absolute urls
page.images()      # [{"url": ..., "alt": ...}] (handles lazy data-src)
page.tables()      # every <table> as list-of-rows
page.markdown()    # readable page content as markdown, great for LLMs
```

## Resilience: retries, rotation, cache, async

```python
# smart retries with exponential backoff + jitter, honoring Retry-After;
# retries 429/5xx automatically
s = reap.Session(retry_policy=reap.RetryPolicy(retries=4, backoff=0.5))

# rotate real browser fingerprints and proxies across requests
s = reap.Session(rotate="random",
                 proxy=["http://p1:8080", "http://p2:8080"])

# disk cache: repeat GETs come from disk (fast dev loops, fewer hits)
s = reap.Session(cache=reap.DiskCache(ttl=3600))
r = s.get(url); r2 = s.get(url)   # r2.from_cache is True

# async: the same impersonating fetch, awaitable
import asyncio
async def main():
    async with reap.AsyncSession() as a:
        pages = await asyncio.gather(*(a.get(u) for u in urls))
asyncio.run(main())
```

## Self-healing selectors

Save an element once. Later, even if the site renames the class or moves the node, `auto_match` relocates it by structural signature:

```python
page = reap.get("https://shop.example.com/item/42")
page.css_first("a.buy-btn").save("buy_button")     # remember its shape

# weeks later, the class is now "purchase-cta" and the old selector misses:
later = reap.get("https://shop.example.com/item/99")
btn = later.css_first("a.buy-btn", auto_match=True, identifier="buy_button")
print(btn.attr("href"))                            # found anyway
```

Other finders: `page.find_by_text("Sign in")` and `page.find_similar(some_element)`.

## Crawl at scale

A `Spider` yields items (dicts) and more `Request` objects. A continuous scheduler keeps every worker busy (one slow page never stalls the crawl), with per-domain AutoThrottle, retries, dedup, depth/domain limits, optional `robots.txt`, and pipelines:

```python
import curl_reap as reap
from curl_reap import JsonLinesPipeline

class Quotes(reap.Spider):
    start_urls = ["https://quotes.toscrape.com"]
    allowed_domains = ["quotes.toscrape.com"]   # confine the crawl
    max_depth = 5

    def parse(self, page):
        for q in page.css("div.quote"):
            yield {
                "text": q.css_first("span.text::text"),
                "author": q.css_first("small.author::text"),
            }
        nxt = page.css_first("li.next a::attr(href)")
        if nxt:
            yield page.follow(nxt)                # resolves relative urls for you

items = reap.run(
    Quotes,
    concurrency=8,
    throttle=True,             # per-domain AutoThrottle, backs off on 429/503
    respect_robots=True,       # opt-in robots.txt compliance
    pipelines=[JsonLinesPipeline("quotes.jsonl")],
)
print(len(items), "items reaped")
```

Crawl straight from a sitemap with `SitemapSpider`:

```python
class Products(reap.SitemapSpider):
    sitemap_urls = ["https://shop.example.com"]   # /sitemap.xml assumed
    url_pattern = r"/product/"
    def parse(self, page):
        yield page.jsonld()[0]
```

## Command line

Installing the package also installs a `reap` command:

```bash
reap get https://example.com                      # readable markdown
reap get https://example.com --css "h1::text"     # extract with a selector
reap get https://api.site.com/x --json            # pretty-print JSON
reap meta https://example.com                      # title + og/twitter + JSON-LD
reap links https://example.com --internal          # list same-domain links
reap crawl https://quotes.toscrape.com --css "span.text::text" \
     --max-pages 20 -o out.jsonl                    # crawl to a file (.jsonl/.csv/.db)
```

## API at a glance

- `reap.get(url, impersonate="chrome124", **kw)` and `reap.post(...)` return a `Response` you can `.css()` / `.xpath()` directly. `.status`, `.ok`, `.from_cache`, `.follow()`, `.raise_for_status()`.
- `reap.Session(impersonate=..., headers=..., retry_policy=..., rotate=..., proxy=..., cache=...)` for a reusable client; `reap.AsyncSession` / `reap.aget` for async.
- Structured extraction on any page: `.jsonld()`, `.meta_tags()`, `.links()`, `.images()`, `.tables()`, `.markdown()`.
- `Selector` / `SelectorList`: `.css`, `.css_first`, `.xpath`, `.find_by_text`, `.find_similar`, `.save`, `.re`, `.re_first`, `.text`, `.attr`.
- `reap.Spider`, `reap.SitemapSpider`, `reap.Request(url, priority=, errback=, dont_filter=)`, `reap.run(spider, ...)`, `reap.Reaper(...)`.
- Pipelines: `DedupPipeline`, `JsonLinesPipeline`, `CsvPipeline`, `SqlitePipeline`, or subclass `Pipeline`.
- `reap.Geocoder().geocode(name, area, city, country)`: turn a name or address into coordinates with a precision label (`name`, `district`, or `city`), cached and rate limited.

## Legal and acceptable use

`curl_reap` impersonates a real browser at the TLS level, which is what a normal browser does. It does **not** solve CAPTCHAs, bypass logins or paywalls, or defeat anti-bot services (Cloudflare, DataDome, PerimeterX, Akamai). If a site is actively blocking you, that block is the line to respect. You are responsible for checking robots.txt and each site's terms, not circumventing technical access controls, handling personal data lawfully (GDPR / CCPA), and respecting copyright. Provided under MIT, "as is", with no warranty.

Full notice and your responsibilities as a user: **[LEGAL.md](LEGAL.md)**.

## License

MIT. See [LICENSE](LICENSE).
