# curl_reap

**Reap the web.** One Python library for scraping: a hardened HTTP transport, self-healing selectors, structured extraction, and a concurrent crawl engine.

```bash
pip install curl_reap
```

```python
import curl_reap as reap

page = reap.get("https://quotes.toscrape.com", profile="chrome")
# or curl_cffi-style versioned targets (42 available):
page = reap.get("https://quotes.toscrape.com", impersonate="chrome124")
print(page.css("span.text::text").getall())
print(page.jsonld())
```

Python 3.9+. Two dependencies total: `lxml` and `cssselect`. No binaries, no downloads at runtime, pure standard-library transport.

## How it compares

| | requests + bs4 | httpx | curl_cffi | Scrapy | Scrapling | **curl_reap** |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Browser-inspired TLS/header profiles | no | no | yes | no | partial | **yes** |
| Byte-level header order control | no | no | yes | no | no | **yes** |
| Parser built in | bs4 only | no | no | yes | yes | **yes (lxml)** |
| Self-healing selectors | no | no | no | no | yes | **yes** |
| Structured extraction (jsonld/meta/tables/markdown) | no | no | no | partial | partial | **yes** |
| Concurrent crawl engine | no | no | no | yes | no | **yes** |
| AutoThrottle, retries, pipelines | no | partial | no | yes | no | **yes** |
| Fingerprint + proxy rotation | no | partial | partial | no | no | **yes** |
| Async client | no | yes | yes | no | partial | **yes** |
| Disk response cache with 304 revalidation | no | no | no | partial | no | **yes** |
| Zero heavy dependencies | no | yes | no | no | no | **yes** |
| One install does everything | no | no | no | partial | partial | **yes** |

## Why curl_reap

- **Get past the front door.** Stock Python clients are fingerprinted as bots in seconds. curl_reap ships its own HTTP/1.1 engine on `socket` + `ssl` with curated cipher orderings, ALPN, browser-family profiles (`chrome`, `firefox`, `safari`), and exact control over header order and casing. Rotation pools advance both profile and proxy across retries.
- **Survive markup changes.** Selectors heal themselves: when a site renames a class, `find_similar` and adaptive relocation re-find the element from a saved signature.
- **Skip the parsing boilerplate.** One call gives you JSON-LD, meta tags, links, images, tables, and readable markdown.
- **Crawl without wiring Scrapy-sized machinery.** Spiders, priorities, per-domain AutoThrottle, robots.txt with Crawl-delay, sitemap discovery, dedup, and jsonl/csv/sqlite pipelines behind one `reap.run()` call.
- **Stay light.** No compiled curl fork, no runtime binary downloads, no framework lock-in. If you outgrow it, every piece is importable standalone.

Honest limits: standard-library TLS cannot produce an exact browser ClientHello, so hard-blocked sites behind enterprise anti-bot may still distinguish it. curl_reap does not solve CAPTCHAs, bypass logins or paywalls, or defeat anti-bot services. Respect robots.txt, terms, and the law: [LEGAL.md](LEGAL.md).

## Credits

With thanks to the projects whose ideas this builds on:

- **curl_cffi** by Yuriy Lexifi and contributors, for proving how far TLS impersonation can take a scraper. The 1.0 transport is written from scratch, but the inspiration is explicit.
- **Scrapy**, for the crawl-engine blueprint.
- **Scrapling** and **parsel**, for self-healing selectors and css/xpath ergonomics.
- **curl-impersonate** by lwthiker, the original browser-TLS-for-curl project.

Built with AI hands: co-developed with **ox-alpha**, an AI agent whose makers keep their name off the label (the mystery lab), alongside the claude-work and codex agents, fanned out and judged via **kestrel-cli**. Made with the help of AI, on Anish's machine, for a freer web.

## License

MIT. See [LICENSE](LICENSE).
