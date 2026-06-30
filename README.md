<p align="center">
  <img src="https://raw.githubusercontent.com/anishfyi/curl_reap/main/assets/logo.png" alt="curl_reap" width="440" />
</p>

<p align="center"><b>Reap the web.</b> Browser-grade TLS impersonation, self-healing selectors, and a concurrent crawl engine, in one small library.</p>

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

> Full documentation with deep API reference and examples: **https://anishfyi.github.io/curl_reap/**

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
| Concurrent crawl engine | no | yes | no | **yes** |
| AutoThrottle, retries, pipelines | no | yes | no | **yes** |
| One small dependency set | yes | no | no | **yes** |

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

A `Spider` yields items (dicts) and more `Request` objects. The engine handles concurrency, AutoThrottle, retries, dedup, and pipelines:

```python
import curl_reap as reap
from curl_reap import JsonLinesPipeline

class Quotes(reap.Spider):
    start_urls = ["https://quotes.toscrape.com"]

    def parse(self, page):
        for q in page.css("div.quote"):
            yield {
                "text": q.css_first("span.text::text"),
                "author": q.css_first("small.author::text"),
            }
        nxt = page.css_first("li.next a::attr(href)")
        if nxt:
            yield reap.Request("https://quotes.toscrape.com" + nxt, self.parse)

items = reap.run(
    Quotes,
    concurrency=8,
    throttle=True,                       # AutoThrottle adapts to server latency
    pipelines=[JsonLinesPipeline("quotes.jsonl")],
)
print(len(items), "items reaped")
```

## API at a glance

- `reap.get(url, impersonate="chrome124", **kw)` and `reap.post(...)` return a `Response` you can `.css()` / `.xpath()` directly.
- `reap.Session(impersonate=..., headers=..., retries=...)` for a reusable client.
- `Selector` / `SelectorList`: `.css`, `.css_first`, `.xpath`, `.find_by_text`, `.find_similar`, `.save`, `.re`, `.text`, `.attr`.
- `reap.Spider`, `reap.Request`, `reap.run(spider, ...)`, `reap.Reaper(...)`.
- Pipelines: `DedupPipeline`, `JsonLinesPipeline`, `CsvPipeline`, or subclass `Pipeline`.

## Responsible use

`curl_reap` impersonates a real browser at the TLS level, which is exactly what a normal browser does. It does **not** ship a challenge solver and it will not break CAPTCHAs or anti-bot walls (Cloudflare challenges, DataDome, PerimeterX, and similar). If a site has deliberately put up an access-control wall, that is a signal to stop. Respect robots.txt and each site's terms, throttle your crawls, and only collect data you are allowed to collect.

## License

MIT. See [LICENSE](LICENSE).
