<p align="center">
  <a href="https://velofy.co/curl_reap/"><picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/anishfyi/curl_reap/main/assets/tile-dark.svg">
    <img alt="curl_reap" src="https://raw.githubusercontent.com/anishfyi/curl_reap/main/assets/tile-light.svg" width="360">
  </picture></a>
</p>

<p align="center"><strong>Reap the web.</strong></p>

<p align="center">
  <a href="https://pypi.org/project/curl-reap/"><img alt="PyPI" src="https://img.shields.io/pypi/v/curl-reap?label=pypi&color=12130f"></a>
  <a href="https://github.com/anishfyi/curl_reap/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/anishfyi/curl_reap/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/anishfyi/curl_reap/blob/main/LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-12130f"></a>
</p>

<p align="center">
  <a href="https://velofy.co/curl_reap/">Documentation</a> ·
  <a href="https://velofy.co/curl_reap/quickstart/">Quickstart</a> ·
  <a href="https://github.com/anishfyi/curl_reap/blob/main/CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/anishfyi/curl_reap/releases">Releases</a>
</p>

One Python library for scraping: a browser-exact HTTP/TLS/HTTP-2 transport, self-healing selectors, structured extraction, and a concurrent crawl engine.

## The wire is the fingerprint

On the modern web, the bytes of your TLS handshake and HTTP/2 preface decide
whether you get the page or a bot wall. curl_reap 2.0 reproduces a real
browser's bytes exactly, from its own TLS 1.3 engine: cipher order, extension
order and GREASE, post-quantum X25519MLKEM768 key shares, certificate
compression, ALPS, ECH GREASE, padding - and per-browser HTTP/2 SETTINGS,
priority and HPACK. Measured JA4, ja4_r, peetprint and Akamai h2 fingerprints
match the captured browsers for all 53 captured target names (38 browser
builds plus 15 aliases captured under their own names). Prove it on your own
machine:

```bash
reap doctor chrome     # or firefox147, safari2601, edge101, tor, ...
```

## Install

```bash
pip install curl_reap
```

Python 3.9+. Dependencies: `lxml`, `cssselect`, `cryptography`, `hpack`,
`brotli` - all shipping wheels for common platforms, no compiled curl binding,
no runtime downloads, and a readable pure-Python engine a maintainer can
adapt the day a browser changes its hello.

> **Versions:** 2.0.0 is the first PyPI release since 0.2.2, which was still
> built on curl_cffi. 1.0.0 and 1.1.0 were GitHub releases only. Check
> `curl_reap.__version__` after installing.

Optional extras when you want more:

```bash
pip install "curl-reap[zstd]"    # zstd bodies + certificate compression
pip install "curl-reap[js]"      # JavaScript rendering via Playwright (reap.render, BrowserSession)
pip install "curl-reap[server]"  # private job API + worker (reap serve / reap worker)
```

## Example

```python
import curl_reap as reap

page = reap.get("https://quotes.toscrape.com", profile="chrome")
# or versioned targets (79 names: 38 concrete captures, aliases, legacy):
page = reap.get("https://quotes.toscrape.com", impersonate="chrome124")
print(page.css("span.text::text").getall())
print(page.jsonld())

# HTTP/2 is negotiated by default; see what a connection used
print(page.infos["tls_backend"], page.http_version, page.infos["cipher"])

# WebSockets ride the same transport
with reap.WebSocket.connect("wss://echo.example/socket") as ws:
    ws.send("hello")
    print(ws.recv())

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
  <a href="https://go.nodemaven.com/curlreapreadmeoct" title="NodeMaven: best proxy for web scraping and automation">
    <img src="https://velofy.co/images/sponsors/nodemaven-banner.webp" alt="NodeMaven: best proxy for web scraping and automation with the highest quality IP" width="720">
  </a>
</p>

**[NodeMaven](https://go.nodemaven.com/curlreapreadmeoct)**: the most efficient proxy provider for web scraping and automation, with the highest quality IPs on the market.

Why [NodeMaven](https://go.nodemaven.com/curlreapreadmeoct)?

- ZIP targeting
- 99.9% uptime
- IP filtering: every proxy has a fraud score under 97%
- No KYC required
- Free tools: Proxy Bandwidth Checker, Meta Tag Checker, IP Lookup and more

Codes for curl_reap users: `CURLREAP35` for 35% off mobile and residential proxies, `CURLREAP40` for 40% off ISP (static) proxies.

---

## Why curl_reap

- **Get past the front door.** Stock Python clients are fingerprinted as bots in seconds. curl_reap 2.0 ships its own TLS 1.3 engine and HTTP/2 framing that reproduce a real browser's handshake bytes exactly - cipher order, extension order and GREASE, post-quantum key shares, per-browser SETTINGS and HPACK - for 38 captured browser builds behind 79 target names. Rotation pools advance both profile and proxy across retries.
- **Survive markup changes.** Selectors heal themselves: when a site renames a class, `find_similar` and adaptive relocation re-find the element from a saved signature.
- **Skip the parsing boilerplate.** One call gives you JSON-LD, meta tags, links, images, tables, and readable markdown.
- **Crawl without wiring framework-sized machinery.** Spiders, priorities, per-domain AutoThrottle, robots.txt with Crawl-delay, sitemap discovery, dedup, and jsonl/csv/sqlite pipelines behind one `reap.run()` call.
- **Stay light.** No compiled curl fork, no runtime binary downloads, no framework lock-in. If you outgrow it, every piece is importable standalone.

Honest limits: servers that only speak TLS 1.2 fall back to an OpenSSL-shaped hello (the response says so in `infos["tls_backend"]`), and that fallback cannot run through an `https://` proxy (SOCKS and `http://` proxies work); HTTP/3 (QUIC) is not implemented. curl_reap does not solve CAPTCHAs, bypass logins or paywalls, or defeat anti-bot services. Respect robots.txt, terms, and the law: [LEGAL.md](https://github.com/anishfyi/curl_reap/blob/main/LEGAL.md).

## What's in one install

- Browser-exact TLS 1.3 fingerprints (JA4/ja4_r/peetprint verified per target) with post-quantum key shares and PSK resumption
- Byte-exact HTTP/2 SETTINGS/HPACK per target, on by default, plus ordered HTTP/1.1
- WebSocket and async clients on the same transport
- An lxml parser with self-healing selectors and one-call structured extraction (jsonld/meta/links/images/tables/markdown)
- A concurrent crawl engine: priorities, AutoThrottle, robots.txt, dedup, jsonl/csv/sqlite pipelines
- Fingerprint + proxy rotation, retries with `Retry-After`, disk cache with 304 revalidation, streaming downloads
- `reap doctor` so you can verify every fingerprint claim on your own machine

## Performance

Local-loopback benchmark (Apple M3 Pro, Python 3.12; `bench/bench.py`, results in `bench/AFTER-2.0.md`), against a C-accelerated browser-impersonation client on the same machine: **1.3x** its throughput on HTTP/1.1 keep-alive, **1.8x** threaded, **1.2x** on TLS keep-alive, **1.2x** on 5 MB bodies (1.1.0 was 0.05x there), **0.75x** on HTTP/2 (with byte-exact framing), and **0.5x** on fresh TLS handshakes - the pure-Python engine costs about 1 ms per handshake, and PSK resumption takes over where servers accept tickets. The fingerprint table above is the point: bytes first, then speed.

## Hardened sessions and crawling

The transport keeps HTTP-level state correct so long crawls don't drift:

- **Cookies** are scoped by `(domain, path, name)`: host-only cookies never reach subdomains, `Domain` attributes are accepted only for the origin host or a parent (foreign and IP-literal domains are dropped), paths match on real boundaries (`/app` never leaks to `/apple`), `Max-Age=0` deletes the exact scope, and `CookieJar.get_dict()` is a documented lossy flattening for compatibility. Full public-suffix validation is not implemented.
- **Redirects** strip `Authorization`, explicit `Cookie`, `Proxy-Authorization` and `Host` whenever the origin (scheme + host + effective port) changes, so credentials cannot leak across hosts or an `https -> http` downgrade; `Response.history` exposes the redirect chain as Responses.
- **`Session(url_policy=callable)`** is consulted before every outgoing URL - the initial request (params applied, cache lookups included) and each redirect hop - before a socket is touched. A falsy return raises `URLPolicyError`. This is the origin-confinement seam the private service uses; it is not a complete egress firewall (see below).
- **`Session(sticky=True)`** pins one profile/proxy for the session's life; retries and 4xx signals never rotate a sticky route. `RetryPolicy(allowed_methods=...)` gates which methods replay - POST/PATCH are never retried unless you opt in - and `Retry-After` is honored rather than clamped to `max_backoff` (values above 24 hours are capped at 24 hours).
- **`Response.block_reason`** reports `rate_limited` (429), `proxy_auth_required` (407), `forbidden` (403), or `challenge` when the body heuristically looks like an interstitial. `render_if_empty` only renders successful hollow pages - it does not execute or retry challenge interstitials. JS rendering via `reap.render` / `BrowserSession` is for ordinary JavaScript-heavy pages on sites you are allowed to fetch; it is not a challenge bypass.

`BrowserSession` (optional `js` extra) keeps one browser/context/page alive across `goto()` calls so cookies and storage persist, reports the real navigation status and final URL (never a fabricated 200), optionally attaches to an authorized remote browser via `cdp_url`, and can route-gate document and subresource requests through the same `url_policy`.

The `Reaper` engine grew the knobs large crawls need: `collect_items=False` streams items through pipelines/`on_item` without storing them, `per_domain_concurrency` caps in-flight requests per origin, `max_pending` bounds the in-memory frontier (overflow is dropped into `stats["queue_dropped"]` - the frontier is not durable and has no resumability), dedup happens at schedule time, the `max_pages` budget is reserved atomically before the network and counts failed fetches too, per-domain throttling reserves monotonic start slots, and 429/503 `Retry-After` becomes a real cooldown. Responses with `status >= 400` or a challenge-looking body go to the errback with the `Response`, never to `parse`.

## Private job service (optional `server` extra)

For a small private fleet, `pip install "curl-reap[server]"` adds a FastAPI service and a Redis-backed job queue (`curl_reap.service`, `curl_reap.jobs`).

Keep every secret out of history and config files: store them once in a secrets vault and inject them at run time. The examples use `smbk`; any tool that sets environment variables for one command works the same way:

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
pip install -e ".[dev,server]"
python -m pytest tests/ -q
```

The HTTP/2 tests in `tests/test_http2.py` and `tests/test_h2_connection.py`
use hyper-h2 as the test server and skip without it: `pip install h2` to run
them (the `h2` extra is an empty alias since 2.0). `tests/test_http2.py` also
needs the `openssl` command, which it uses to mint a throwaway localhost
certificate chain. Live network checks run only with `REAP_LIVE_TESTS=1`.

## Credits

With thanks to the projects whose ideas this builds on:

- **curl_cffi** by lexiforest and contributors, for proving how far TLS impersonation can take a scraper. curl_reap's transport is written from scratch, but the inspiration is explicit: the 2.0 browser templates were captured from curl_cffi 0.16.3, and target names follow its naming.
- **Scrapy**, for the crawl-engine blueprint.
- **Scrapling** and **parsel**, for self-healing selectors and css/xpath ergonomics.
- **curl-impersonate** by lwthiker, the original browser-TLS-for-curl project.

Built with AI hands: co-developed with **ox-alpha**, an AI agent whose makers keep their name off the label (the mystery lab), alongside the claude-work and codex agents, fanned out and judged via **kestrel-cli**. Made with the help of AI, on Anish's machine, for a freer web.

## License

MIT. See [LICENSE](https://github.com/anishfyi/curl_reap/blob/main/LICENSE).
