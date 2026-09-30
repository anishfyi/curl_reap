# curl_reap

**Reap the web.** One Python library for scraping: a hardened HTTP transport, self-healing selectors, structured extraction, and a concurrent crawl engine.

[![CI](https://github.com/anishfyi/curl_reap/actions/workflows/ci.yml/badge.svg)](https://github.com/anishfyi/curl_reap/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/curl-reap)](https://pypi.org/project/curl-reap/)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f)](LICENSE)

**Documentation: [velofy.co/curl_reap](https://velofy.co/curl_reap/)**

## Install

```bash
pip install curl_reap
```

Python 3.9+. Two dependencies total: `lxml` and `cssselect`. No compiled curl binding, no downloads at runtime, pure standard-library transport.

> **Release status:** the latest release is 1.1.0, on GitHub. PyPI still serves 0.2.2, which predates the 1.0 rewrite described here, until 1.1.0 is uploaded there. Until then, install 1.1.0 from the GitHub release:
> `pip install "curl_reap @ https://github.com/anishfyi/curl_reap/releases/download/v1.1.0/curl_reap-1.1.0-py3-none-any.whl"`
> or from the git tag: `pip install "curl_reap @ git+https://github.com/anishfyi/curl_reap@v1.1.0"`

Optional extras when you want more:

```bash
pip install "curl-reap[h2]"   # HTTP/2 via hyper-h2 (Session(http2=True) / reap --http2 get URL)
pip install "curl-reap[js]"   # JavaScript rendering via Playwright (reap.render)
```

## Example

```python
import curl_reap as reap

page = reap.get("https://quotes.toscrape.com", profile="chrome")
# or curl_cffi-style versioned targets (38 of them, plus 4 aliases):
page = reap.get("https://quotes.toscrape.com", impersonate="chrome124")
print(page.css("span.text::text").getall())
print(page.jsonld())
```

---

<h3 align="center">Sponsors</h3>

<p align="center"><strong>Primary sponsor</strong></p>

<p align="center">
  <a href="https://go.nodemaven.com/curlreapGH" title="NodeMaven: best proxy for web scraping and automation">
    <img src="https://raw.githubusercontent.com/anishfyi/curl_reap/main/assets/sponsors/nodemaven-banner.jpg" alt="NodeMaven: best proxy for web scraping and automation with the highest quality IP" width="720">
  </a>
</p>

**[NodeMaven](https://go.nodemaven.com/curlreapGH)**: the most efficient proxy provider for web scraping and automation, with the highest quality IPs on the market.

Why [NodeMaven](https://go.nodemaven.com/curlreapGH)?

- ZIP targeting
- 99.9% uptime
- IP filtering: every proxy has a fraud score under 97%
- No KYC required
- Free tools: Proxy Bandwidth Checker, Meta Tag Checker, IP Lookup and more

Codes for curl_reap users: `CURLREAP35` for 35% off mobile and residential proxies, `CURLREAP40` for 40% off ISP (static) proxies.

---

## Why curl_reap

- **Get past the front door.** Stock Python clients are fingerprinted as bots in seconds. curl_reap ships its own HTTP/1.1 engine on `socket` + `ssl` with curated cipher orderings, ALPN, browser-family profiles (`chrome`, `firefox`, `safari`), and exact control over header order and casing. Rotation pools advance both profile and proxy across retries.
- **Survive markup changes.** Selectors heal themselves: when a site renames a class, `find_similar` and adaptive relocation re-find the element from a saved signature.
- **Skip the parsing boilerplate.** One call gives you JSON-LD, meta tags, links, images, tables, and readable markdown.
- **Crawl without wiring Scrapy-sized machinery.** Spiders, priorities, per-domain AutoThrottle, robots.txt with Crawl-delay, sitemap discovery, dedup, and jsonl/csv/sqlite pipelines behind one `reap.run()` call.
- **Stay light.** No compiled curl fork, no runtime binary downloads, no framework lock-in. If you outgrow it, every piece is importable standalone.

Honest limits: standard-library TLS cannot produce an exact browser ClientHello, so hard-blocked sites behind enterprise anti-bot may still distinguish it. curl_reap does not solve CAPTCHAs, bypass logins or paywalls, or defeat anti-bot services. Respect robots.txt, terms, and the law: [LEGAL.md](LEGAL.md).

## How it compares

What curl_reap puts in one install, and which of requests + bs4, httpx, curl_cffi, Scrapy and Scrapling also have it:

- **Browser-inspired TLS/header profiles:** curl_cffi; partial in Scrapling.
- **Byte-level header order control:** curl_cffi.
- **Parser built in (lxml):** Scrapy, Scrapling; requests + bs4 via bs4.
- **Self-healing selectors:** Scrapling.
- **Structured extraction (jsonld/meta/tables/markdown):** partial in Scrapy and Scrapling.
- **Concurrent crawl engine:** Scrapy.
- **AutoThrottle, retries, pipelines:** Scrapy; partial in httpx.
- **Fingerprint + proxy rotation:** partial in httpx and curl_cffi.
- **Async client:** httpx, curl_cffi; partial in Scrapling.
- **Disk response cache with 304 revalidation:** partial in Scrapy.
- **Zero heavy dependencies:** httpx.
- **One install does everything:** partial in Scrapy and Scrapling.

## Documentation

Full docs live at **[velofy.co/curl_reap](https://velofy.co/curl_reap/)**:

- [Installation](https://velofy.co/curl_reap/installation/) and [Quickstart](https://velofy.co/curl_reap/quickstart/)
- [Transport and impersonation profiles](https://velofy.co/curl_reap/transport-and-profiles/)
- [Sessions, retries, proxies and cookies](https://velofy.co/curl_reap/sessions/)
- [Caching and downloads](https://velofy.co/curl_reap/caching-and-downloads/)
- [Selectors and self-healing](https://velofy.co/curl_reap/selectors/)
- [Structured extraction](https://velofy.co/curl_reap/structured-extraction/)
- [Crawling](https://velofy.co/curl_reap/crawling/) and [Pipelines](https://velofy.co/curl_reap/pipelines/)
- [JavaScript rendering](https://velofy.co/curl_reap/javascript-rendering/) and [HTTP/2](https://velofy.co/curl_reap/http2/)
- [Command line](https://velofy.co/curl_reap/cli/) and [CLI reference](https://velofy.co/curl_reap/cli-reference/)
- [Python API reference](https://velofy.co/curl_reap/api-reference/) and [Impersonation targets](https://velofy.co/curl_reap/impersonation-targets/)
- [Geocoding](https://velofy.co/curl_reap/geocoding/)
- [Responsible use](https://velofy.co/curl_reap/responsible-use/) and [Changelog](https://velofy.co/curl_reap/changelog/)

## Contributing

Issues and pull requests are welcome at [github.com/anishfyi/curl_reap](https://github.com/anishfyi/curl_reap/issues). To run the test suite the way CI does:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -q
```

Install `.[dev,h2]` to include the HTTP/2 tests.

## Credits

With thanks to the projects whose ideas this builds on:

- **curl_cffi** by Yuriy Lexifi and contributors, for proving how far TLS impersonation can take a scraper. The 1.0 transport is written from scratch, but the inspiration is explicit.
- **Scrapy**, for the crawl-engine blueprint.
- **Scrapling** and **parsel**, for self-healing selectors and css/xpath ergonomics.
- **curl-impersonate** by lwthiker, the original browser-TLS-for-curl project.

Built with AI hands: co-developed with **ox-alpha**, an AI agent whose makers keep their name off the label (the mystery lab), alongside the claude-work and codex agents, fanned out and judged via **kestrel-cli**. Made with the help of AI, on Anish's machine, for a freer web.

## License

MIT. See [LICENSE](LICENSE).
