<p align="center">
  <a href="https://velofy.co/curl_reap/"><picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/anishfyi/curl_reap/main/assets/tile-dark.svg">
    <img alt="curl_reap" src="https://raw.githubusercontent.com/anishfyi/curl_reap/main/assets/tile-light.svg" width="360">
  </picture></a>
</p>

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
pip install "curl-reap[js]"   # JavaScript rendering via Playwright (reap.render, BrowserSession)
pip install "curl-reap[server]"  # private job API + worker (reap serve / reap worker)
```

## Example

```python
import curl_reap as reap

page = reap.get("https://quotes.toscrape.com", profile="chrome")
# or curl_cffi-style versioned targets (38 of them, plus 4 aliases):
page = reap.get("https://quotes.toscrape.com", impersonate="chrome124")
print(page.css("span.text::text").getall())
print(page.jsonld())

# structured extraction in one call
print(page.extract({"quotes": "span.text::text",
                    "authors": "small.author::text"}, many=True))
print(page.markdown(main_only=True))

# reuse a real browser for ordinary JS pages (optional `js` extra)
with reap.BrowserSession(url_policy=lambda u: u.startswith(
        "https://quotes.toscrape.com")) as browser:
    rendered = browser.goto("https://quotes.toscrape.com/js/")
    rendered = browser.follow("/page/2")

# confine a session to an origin allowlist and spot bot-wall outcomes
session = reap.Session(
    url_policy=lambda u: u.startswith("https://quotes.toscrape.com"))
page = session.get("https://quotes.toscrape.com")
print(page.block_reason)   # None | rate_limited | proxy_auth_required |
                           # forbidden | challenge
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

## Hardened sessions and crawling

The transport keeps HTTP-level state correct so long crawls don't drift:

- **Cookies** are scoped by `(domain, path, name)`: host-only cookies never reach subdomains, `Domain` attributes are accepted only for the origin host or a parent (foreign and IP-literal domains are dropped), paths match on real boundaries (`/app` never leaks to `/apple`), `Max-Age=0` deletes the exact scope, and `CookieJar.get_dict()` is a documented lossy flattening for compatibility. Full public-suffix validation is not implemented.
- **Redirects** strip `Authorization`, explicit `Cookie`, `Proxy-Authorization` and `Host` whenever the origin (scheme + host + effective port) changes, so credentials cannot leak across hosts or an `https -> http` downgrade; `Response.history` exposes the redirect chain as Responses.
- **`Session(url_policy=callable)`** is consulted before every outgoing URL - the initial request (params applied, cache lookups included) and each redirect hop - before a socket is touched. A falsy return raises `URLPolicyError`. This is the origin-confinement seam the private service uses; it is not a complete egress firewall (see below).
- **`Session(sticky=True)`** pins one profile/proxy for the session's life; retries and 4xx signals never rotate a sticky route. `RetryPolicy(allowed_methods=...)` gates which methods replay - POST/PATCH are never retried unless you opt in - and `Retry-After` is honored verbatim rather than clamped to `max_backoff`.
- **`Response.block_reason`** reports `rate_limited` (429), `proxy_auth_required` (407), `forbidden` (403), or `challenge` when the body heuristically looks like an interstitial. `render_if_empty` only renders successful hollow pages - it does not execute or retry challenge interstitials. JS rendering via `reap.render` / `BrowserSession` is for ordinary JavaScript-heavy pages on sites you are allowed to fetch; it is not a challenge bypass, and the stdlib transport does not claim a better TLS fingerprint than curl_cffi.

`BrowserSession` (optional `js` extra) keeps one browser/context/page alive across `goto()` calls so cookies and storage persist, reports the real navigation status and final URL (never a fabricated 200), optionally attaches to an authorized remote browser via `cdp_url`, and can route-gate document and subresource requests through the same `url_policy`.

The `Reaper` engine grew the knobs large crawls need: `collect_items=False` streams items through pipelines/`on_item` without storing them, `per_domain_concurrency` caps in-flight requests per origin, `max_pending` bounds the in-memory frontier (overflow is dropped into `stats["queue_dropped"]` - the frontier is not durable and has no resumability), dedup happens at schedule time, the `max_pages` budget is reserved atomically before the network and counts failed fetches too, per-domain throttling reserves monotonic start slots, and 429/503 `Retry-After` becomes a real cooldown. Responses with `status >= 400` or a challenge-looking body go to the errback with the `Response`, never to `parse`.

## Private job service (optional `server` extra)

For a small private fleet, `pip install "curl-reap[server]"` adds a FastAPI service and a Redis-backed job queue (`curl_reap.service`, `curl_reap.jobs`).

Keep every secret out of history and config files - store them once with [smbk](https://github.com/anishfyi/smbk) and inject them at run time:

```bash
smbk add REAP_API_KEY        # shared secret for the x-reap-key header
smbk add REAP_REDIS_URL      # only when the URL carries a password
smbk add REAP_PROXY_URL      # optional single dashboard proxy for workers

# plain (non-secret) configuration stays in the environment:
export REAP_REDIS_URL="redis://127.0.0.1:6379/0"            # if it has no password
export REAP_ALLOWED_ORIGINS="https://example.com:443,http://internal:8080"

smbk run -k REAP_API_KEY -- reap serve --host 127.0.0.1 --port 8000
smbk run -k REAP_API_KEY -k REAP_REDIS_URL -k REAP_PROXY_URL -- reap worker
```

- `POST /jobs` takes `{url, css?, max_chars?}` for **one page** and returns `202 {id}`; `GET /jobs/{id}` reports `queued/running/succeeded/failed` with a capped result (`url`, `status`, `fields`, `markdown`, `meta`, `jsonld`, <= 1 MiB). The API is deliberately a single-page extraction endpoint: large multi-page crawls stay a library concern via `Reaper`; there is no crawl endpoint, and clients cannot supply proxies, headers, auth or scripts.

```bash
curl -sS -X POST http://127.0.0.1:8000/jobs \
    -H "x-reap-key: $REAP_API_KEY" -H 'content-type: application/json' \
    -d '{"url": "https://example.com/", "css": {"title": "h1::text"}}'
curl -sS http://127.0.0.1:8000/jobs/<id> -H "x-reap-key: $REAP_API_KEY"
```

- Delivery is **at-least-once** via Redis sorted-set leases with fencing tokens; crashed workers' jobs are re-claimed up to `max_attempts`. Pending jobs never expire (configure AOF persistence, e.g. `appendonly yes` + `appendfsync everysec`, and a `noeviction` policy for durability), terminal jobs expire after `result_ttl`.
- Workers fetch through `Session(sticky=True, retries=0)` confined by the exact `REAP_ALLOWED_ORIGINS` allowlist, respect robots.txt (fail-closed on redirect/403/429/5xx/challenge robots fetches, transient failures retried after a 5-minute cache), pace **every** outgoing hop (robots probe, page, each redirect) through a shared Redis reservation (default 1s per origin) plus a shared 429/`Retry-After` cooldown, and report `status`/final URL/`block_reason` on failure - never raw exceptions that could carry secrets. Replicas scale horizontally: run N `reap worker` processes with identical env against the same Redis.
- **Deployment limits:** keep the API on a private network behind TLS ingress (the `x-reap-key` shared secret is not an identity system); the origin allowlist is checked per URL but is *not* a complete egress firewall - add real egress rules at the network layer since an allowed hostname can still resolve elsewhere (DNS rebinding); set container/process resource limits; raw response bodies are buffered whole in memory, so cap `max_chars` and site size expectations accordingly; the crawl frontier is in-memory only (no durable/resumable queue).
- A `Dockerfile` builds a non-root image with the `server` extra installed:

```bash
docker build -t curl-reap .
docker run --rm -e REAP_ALLOWED_ORIGINS -p 8000:8000 \
    curl-reap serve --host 0.0.0.0 --port 8000   # container needs the explicit 0.0.0.0
smbk run -k REAP_API_KEY -k REAP_REDIS_URL -- \
    docker run --rm -e REAP_ALLOWED_ORIGINS \
    -e REAP_API_KEY -e REAP_REDIS_URL curl-reap worker
```

Secrets still come from the environment (smbk, Docker secrets, or your orchestrator's env injection); nothing is baked into the image.

- A provider-specific NodeMaven SDK (sticky residential sessions etc.) is intentionally *not* included in v1 of the service; generic `proxy=` support in `Session` works today, and the NodeMaven sticky-session concept maps onto `Session(sticky=True)` when such an SDK lands.

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

Install `.[dev,h2]` to include the HTTP/2 tests. Those tests spin a real
TLS server and expect a throwaway certificate at `/tmp/h2cert/{cert,key}.pem`;
generate one locally (e.g. `openssl req -x509 -newkey rsa:2048 -nodes
-keyout /tmp/h2cert/key.pem -out /tmp/h2cert/cert.pem -subj /CN=localhost
-days 7`) or those four tests skip/fail.

## Credits

With thanks to the projects whose ideas this builds on:

- **curl_cffi** by Yuriy Lexifi and contributors, for proving how far TLS impersonation can take a scraper. The 1.0 transport is written from scratch, but the inspiration is explicit.
- **Scrapy**, for the crawl-engine blueprint.
- **Scrapling** and **parsel**, for self-healing selectors and css/xpath ergonomics.
- **curl-impersonate** by lwthiker, the original browser-TLS-for-curl project.

Built with AI hands: co-developed with **ox-alpha**, an AI agent whose makers keep their name off the label (the mystery lab), alongside the claude-work and codex agents, fanned out and judged via **kestrel-cli**. Made with the help of AI, on Anish's machine, for a freer web.

## License

MIT. See [LICENSE](LICENSE).
