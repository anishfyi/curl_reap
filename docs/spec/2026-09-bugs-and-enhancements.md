# curl_reap: bugs and enhancements, September 2026

Status: proposed. Written against `main` at `9d08b89` (version string 1.0.0,
PyPI still at 0.2.2). Two uncommitted fixes sit in the working tree: the
`cli.py` syntax repair and a generated-cert fixture for `tests/test_http2.py`.

## What curl_reap is for

One dependency-light library that replaces requests plus bs4, httpx, curl_cffi,
Scrapy and Scrapling for a Python scraper: a hand-rolled HTTP/1.1 transport
with byte-level header order, browser-family TLS profiles on the standard
library, a parser with self-healing selectors and structured extraction, and a
concurrent crawl engine with throttling, robots, caching and pipelines. The
README is careful to say stdlib TLS cannot reproduce a browser ClientHello.

Three things follow: the shipped entry points must import, the crawl engine
must deliver the politeness it claims, and the docs must describe the library
that exists after the 1.0 transport rewrite.

## Snapshot

| Item | Value |
|---|---|
| Version | pyproject and `__init__` say 1.0.0; `docs/llms.txt` says 0.3.0; PyPI latest is 0.2.2 |
| Source | `http.py` 1,429 lines, 15 modules |
| Tests | 14 files, ~60 tests, Ubuntu only, Python 3.9 to 3.13 |
| CLI tests | none |
| HTTP/2 tests | all skipped in CI (`h2` not in the dev extra) |
| TODO/FIXME in source | none |
| Stale branches | 13 `fanout/*` scratch branches, 7 merged feature branches |

## Bugs

Severity: P0 broken as shipped, P1 wrong results or a security issue, P2 robustness, P3 quality.

### P0

**B1. The committed CLI does not parse.** `git show HEAD:curl_reap/cli.py`
line 40 has two statements on one line:
`print(r.markdown(max_len=args.max_len))    return 0 if r.ok else 1`.
`pyproject.toml:38` registers `reap = "curl_reap.cli:main"`, so every `reap`
invocation fails at import. Introduced in `7a92398` (v0.2.0). No test imports
`curl_reap.cli`. The uncommitted working-tree edit fixes it. The committed
`dist/curl_reap-1.0.0-py3-none-any.whl` contains the broken file and lacks
`render.py` and `h2engine.py`.
Fix: commit the repair, add `python -c "import curl_reap.cli"` and
`reap --help` to CI, delete `dist/`, add a wheel-install smoke step.

**B2. HTTP/2 responses are never content-decoded.** The 1.1 path decodes at
`http.py:699`; the h2 path builds `_RawResponse` at `http.py:918-920` with no
`_decode_content` call. Every profile sends `Accept-Encoding: gzip, deflate`,
so `Session(http2=True)` against any compressing server returns raw gzip as
`.content` and mojibake as `.text`. The h2 tests use a local server that never
compresses. Fix: decode on both paths; add a gzip case to `test_http2.py`.

**B3. `docs/llms.txt` describes the pre-1.0 curl_cffi library.** It claims
version 0.3.0, "JA3 impersonation through curl_cffi" four times, and a
canonical page at `anishfyi.com/curl_reap/`. CI has a job that greps to prove
curl_cffi is gone. This file is what answer engines read. Fix: rewrite against
`__init__.py:85-105` and `tls.py:11-18`.

### P1

**B4. Domain-scoped cookies can never match.** `_response` strips the leading
dot from `Set-Cookie` domains (`http.py:722`); `CookieJar.header_for` only
matches subdomains when the stored domain starts with a dot (`http.py:476`).
Log in at `www.site.com`, receive `Domain=site.com`, and every later request is
anonymous. `tests/test_transport.py:141` passes a dotted domain the transport
can never produce, so the test is a false positive.

**B5. Cookies are keyed by name only.** `http.py:447`. One `Session` crawling
two hosts loses `sid`, `csrftoken`, `__cf_bm` on the first. `Reaper` shares one
session across all domains (`engine.py:142`). Key on `(domain, path, name)`.

**B6. Cookie tossing.** `absorb` (`http.py:436`) accepts any `Domain=`. A
response from `evil.test` with `Domain=bank.test` is stored and replayed to
`bank.test`. RFC 6265 section 5.3.6 requires a suffix check and a public-suffix
check. Reachable through any redirect chain.

**B7. `delay=` is ignored when `throttle=False`, and so is Crawl-delay.**
`engine.py:176-178` folds both into `AutoThrottle(enabled=...)`, and
`throttle.py:49` returns 0 when disabled. Measured: 16 requests with
`delay=1.0, throttle=False` complete in 0.00 s. `respect_robots=True,
throttle=False` therefore claims compliance and ignores Crawl-delay.

**B8. The per-domain delay is divided by concurrency.** `AutoThrottle.wait`
(`throttle.py:47-51`) sleeps per worker with no next-allowed timestamp.
Measured: `delay=1.0, concurrency=8` fires bursts of 8 every second. A site's
`Crawl-delay: 2` is honoured at 4 requests per second. Fix: a per-domain
next-allowed time under a lock; make `delay` independent of `throttle`.

**B9. `max_pages` overshoots by up to `concurrency`.** `_admit` checks
`stats["requests"]` (`engine.py:207`), which is incremented after the fetch
(`:247-248`). Measured: `max_pages=10, concurrency=8` yields 17 requests.
Reserve the budget in `_admit`.

**B10. `Selector` raises on empty and XML-declared bodies.** `parser.py:86`
calls `lxml.html.fromstring` unguarded. A 204 or empty 200 raises
`ParserError: Document is empty`; a body starting with `<?xml ... encoding=`
raises `ValueError`. Sitemaps, RSS and XML APIs are unusable through
`Response.css`. Fix: substitute an empty document for empty bodies and feed
bytes when a declaration is present.

**B11. `Authorization` leaks across hosts on redirect.** `http.py:957-958`
clears the computed auth but a user-supplied `Authorization` header in
`headers=` rides through every hop.

**B12. `render()` fabricates `status = 200`.** `render.py:61` discards the real
response, so a rendered 403 or 404 reports `.ok`. `browser_channel="chrome"`
(`render.py:51`) resolves `getattr(pw, "chrome")`, which does not exist, and
silently falls back to bundled Chromium. Authenticated proxy URLs lose their
credentials (`render.py:53` passes only `server`).

### P2

**B13. Retries re-send POST and PUT.** `http.py:1324-1329` retries any method
after a transport error. A request that reached the server and timed out on
the response is submitted twice. Restrict to idempotent methods, or require an
explicit opt-in.

**B14. Pool is unbounded, never reaped, never liveness-checked.**
`http.py:526-537`, `607-608`. One socket per `(scheme, host, port, proxy,
profile, verify)` forever; a server-closed keepalive surfaces as
`TransportError` when `retries=0`.

**B15. `timeout` is per socket operation, not a deadline.** `http.py:551-553`.
A server dribbling one byte per 29 s never times out; each redirect hop gets a
fresh budget, so `max_redirects=10, timeout=30` can block 300 s.

**B16. No response-size cap on HTTP/1.1.** `read_exact`, `read_to_close`,
`_read_chunked` (`http.py:271-276, 307, 759`) buffer any declared length in
memory. The h2 path caps at 64 MB (`h2engine.py:19`). Apply the same cap.

**B17. Sessions are never closed.** `Reaper` (`engine.py:142`), the module
default session (`http.py:1395-1405`), `cli._fetch` (`cli.py:20-22`) and
`Geocoder` (`geocode.py:55`) all create sessions with no close path.

**B18. Worker threads die silently.** `engine.py:279-284` has no try/except
around `_admit`, `_throttle_for` and `frontier.put`. Once every worker has
died, `run()` returns success with the queue unconsumed.

**B19. A failed request is permanently deduped.** `_admit` records the
fingerprint before the fetch (`engine.py:202-204`); `_fail` never re-queues.

**B20. h2 connection hygiene.** `_Connection.close()` never sends GOAWAY
(`http.py:328-335` vs `h2engine.py:44`); h2 exchanges are always marked
reusable (`http.py:840`); the read loop returns on the first `StreamEnded` of
any stream (`h2engine.py:105-130`); h2 downloads write redirect bodies to the
sink before the redirect is evaluated (`http.py:841-848` vs `:951-953`).

**B21. robots.txt thundering herd and wrong agent.** `_RobotsGate` releases
its lock before fetching (`engine.py:80-92`), so N workers fetch the same
robots file. `agent="*"` is hardcoded (`engine.py:70`) while the profile sends
a Chrome UA. Robots fetches bypass the throttle and stats.

**B22. `Geocoder` cache is unsynchronised and non-atomic.** `geocode.py:104-
105` mutates and rewrites the whole JSON outside the lock on every lookup; the
bare `except` at `:128` hides the resulting `RuntimeError`.

**B23. `DiskCache.set` writes the body in place.** `cache.py:87-88`. A reader
can pair fresh meta with a half-written body. Use the tmp-and-replace path the
meta file already uses.

### P3

**B24. `CaseInsensitiveHeaders` is half case-insensitive.** `http.py:84`
overrides reads but not `__setitem__`, `__delitem__`, `pop`, `update`, and
`Response.__init__` bypasses it with `dict.__init__`.

**B25. Sitemap `<loc>` is not XML-unescaped.** `spider.py:75`. `&amp;` stays
literal in fetched URLs, which affects nearly every parameterised sitemap.

**B26. `impersonate` and `profile` conflict differently in two places.** The
constructor silently prefers `impersonate` (`http.py:1191-1193`); `request`
raises (`:1263-1266`). `cli._fetch` always passes both.

**B27. Malformed selectors return `[]`.** `parser.py:98, 117` swallow every
exception, so a typo is indistinguishable from no match, and `auto_match` then
relocates something else.

**B28. Cookie path matching has no boundary.** `http.py:478`. `/foo` matches
`/foobar`.

**B29. `stats["elapsed"]` is missing on the empty-seed path.**
`engine.py:274-277`.

**B30. Dead code.** `tls.py:126-127` replaces a string with itself;
`h2engine.py:86` assigns an unused `end`; `http.py:22` imports five unused
typing names; `http.py:976-979` uses `__import__("re")` at module scope then
re-imports inside `detect_encoding`; `cli.py:118` defines `--markdown` and
never reads it. `Profile.alpn_protocols` (`tls.py:41`) is never consulted;
ALPN comes only from `self.http2` (`http.py:508-518`).

### Fingerprint tables

- `_CHROME_MAJORS` tops out at 133, Firefox at 135, Safari at 18.0
  (`tls.py:178-181`). The `chrome` and `edge` aliases resolve to 131 while
  133 exists (`tls.py:207-208`). Firefox and Safari aliases are current.
- `Accept-Encoding: gzip, deflate` (`tls.py:113, 145, 158`) matches no real
  browser; all send `br`, and Chromium adds `zstd`. This one header undermines
  the "faithful at the HTTP layer" claim. Either add brotli and zstd as
  optional decoders and advertise them when present, or document the tradeoff.
- Rotation draws from `PROFILES` (3 entries), not `FINGERPRINTS` (42), so
  `rotate="random"` varies across three fingerprints.

## Docs drift

- `docs/llms.txt`: see B3.
- `docs/index.html:573` promises a per-request `cookies=` kwarg. `request`
  raises `TypeError` on it (`http.py:1272-1274`).
- The site claims control of TLS "extension layout"; `tls.py:12-14` says the
  stdlib cannot control extension ordering.
- "No compiled extensions" (`docs/index.html:78, 504`, `README.md:21`). `lxml`
  is a mandatory C extension. Say "no compiled curl binding".
- "42 versioned targets" (`README.md:12`) is 38 versioned plus 4 aliases.
- The site never mentions `impersonate`, HTTP/2, `download`, `CookieJar`,
  `render`, `looks_like_challenge`, `detect_encoding`, `TransportError` or
  `RetryPolicy`. It is frozen at the transport rewrite.
- "Three profiles ship with 1.0.0" is true of `PROFILES` and false of the
  library.
- Signature drift: `find_by_text` has an undocumented `deepest` parameter;
  `reaper.stats` has three undocumented keys; `reap.run` docs omit
  `max_depth`, `session`, `cache`, `rotate`, `proxy`; `Selector.tables()`
  docstring describes header detection the code does not do;
  `render_if_empty` returns a tuple and says nothing about it and is missing
  from `render.__all__`.
- The `feat/nodemaven-proxy-hint` branch is built on the deleted curl_cffi
  transport and cannot merge. As designed it prints an advertisement to stderr
  from library code. Keep the sponsorship in the README and docs only, and
  delete the branch.

## Test gaps

- No test imports `curl_reap.cli` (B1).
- HTTP/2 is skipped in CI because `h2` is not in `[dev]`. Install `.[h2]` in
  the matrix.
- `render.py` and `aio.py` have no tests.
- Ubuntu only. `os.replace`, part files and socket behaviour differ on
  Windows and macOS.
- The cookie tests construct shapes the transport never produces (B4). No
  test for name collision across hosts (B5) or domain validation (B6).
- `test_throttle_floors_at_crawl_delay` asserts the configured floor, not the
  achieved rate (B7, B8).
- `max_pages` is tested only at a concurrency where the race cannot fire (B9).
- Nothing for empty or XML bodies, pool growth, stale connections, wall-clock
  timeout, cross-host `Authorization`, threaded pipelines, `DiskCache`
  concurrency, `Geocoder` threading, sitemap escaping.
- No coverage, lint, type check, or wheel-install smoke step.

## Enhancements

1. **E1. A real per-domain rate limiter** (B7, B8), with `delay` and
   `throttle` independent.
2. **E2. RFC 6265 cookies**: `(domain, path, name)` keys, suffix and
   public-suffix validation, path boundaries, `HttpOnly` and `SameSite`
   retention, `jar.save()` and `jar.load()`.
3. **E3. Streaming reads**: `Response.iter_content()` and `iter_lines()`, with
   the 64 MB cap applied to buffered reads.
4. **E4. Pool limits and eviction**: `max_connections`, per-host keepalive
   cap, idle TTL, liveness probe before reuse.
5. **E5. A wall-clock deadline**: `timeout=(connect, read, total)`.
6. **E6. Idempotency-aware retries.**
7. **E7. Render to transport handoff**: `render()` accepts and returns cookies
   and headers so a solved interstitial's clearance cookie flows back into the
   `Session`; persistent browser context instead of a fresh `sync_playwright`
   per call; an async variant.
8. **E8. SOCKS5 and HTTPS proxies.** `_connect` rejects everything but
   `http://` (`http.py:544-545`), which sits oddly next to a proxy sponsor.
9. **E9. HTTP cache semantics**: `Cache-Control`, `Vary`, `Expires`; key on
   auth so an authenticated response is never served anonymously
   (`cache.py:29-31`).
10. **E10. Engine-level retry with `dont_retry`, and a resumable frontier.**
11. **E11. Real async I/O**, or relabel `aio.py` as thread-backed. The README
    table lists "Async client: yes" beside httpx.
12. **E12. brotli and zstd** as optional decoders (see fingerprint tables).
13. **E13. Export `resolve_profile` and `create_ssl_context`** at the root and
    document custom `Profile` authoring.
14. **E14. `reap doctor <url>`**: fetch a fingerprint echo endpoint and report
    which signals match the claimed profile. The most useful feature for the
    library's premise.
15. **E15. XML-aware sitemap parsing** with `lastmod`, `priority`, namespaces.
16. **E16. Decide `Geocoder`'s fate.** A Nominatim hotel geocoder inside a
    scraping library, absent from the README. Split it out or make it a
    documented extra.

## Hygiene

- `Development Status :: 5 - Production/Stable` is not defensible with B1.
- Classifiers stop at 3.12 while CI tests 3.13. Add `3 :: Only` and
  `Typing :: Typed` once `py.typed` exists.
- `license = { text = "MIT" }` is the deprecated form.
- No `py.typed`; 15 modules import `annotations` from `__future__` and only
  `tls.py` has annotated signatures. Either annotate `http.py` or drop the
  ceremony.
- No ruff, black, mypy or pytest config. Ten `# noqa: BLE001` sites reference
  a linter that is not installed.
- `MANIFEST.in` is redundant with the hatch sdist config and disagrees with it.
- `dist/` is present with a broken wheel. `.reap_geocode.json` (17 KB of real
  geocoded listings) is tracked despite the ignore rule. `git rm --cached` it.
- No `CHANGELOG.md`. Four feature commits have landed since the 1.0.0 string
  with no bump and no release.
- Version is in `pyproject.toml`, `__init__.py`, `llms.txt` and the
  `geocode.py:39` user agent. Single-source it.
- Prune the 13 `fanout/*` and 7 merged feature branches.

## Sequencing

1. Commit the two working-tree fixes. CI: import the CLI, install `.[h2]`,
   wheel-install smoke. Delete `dist/`. Rewrite `llms.txt`. Release 1.0.0 to
   PyPI, or rename the string to 1.0.0rc1 until B2 and B4 to B6 land.
2. 1.0.1: B2, B4, B5, B6, B10, B11, B12, cookie and h2 tests.
3. 1.1.0: E1 rate limiter, B9, B17, B18, B19, B21, engine tests with timing
   assertions.
4. 1.2.0: E2 to E6 transport hardening, docs site reconciliation, CHANGELOG,
   lint and type config.
