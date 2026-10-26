# Changelog

Full history, including releases before 1.0.0: https://velofy.co/curl_reap/changelog/

## 2.0.0 (2026-10-26)

The transport is new from the TLS record layer up. curl_reap now speaks with
browser-exact bytes: a pure-Python TLS 1.3 client on `cryptography`
primitives renders each impersonate target's captured ClientHello byte for
byte (cipher order, extension order and GREASE, X25519MLKEM768 post-quantum
key shares, certificate compression, ALPS, ECH GREASE, padding), and the
built-in HTTP/2 framing reproduces each browser's SETTINGS, WINDOW_UPDATE,
priority and HPACK representations. Measured JA4, ja4_r, peetprint and Akamai
h2 fingerprints equal the captured browsers' for all 53 captured target names
(38 browser builds plus 15 aliases captured under their own names).

This is the first PyPI release since 0.2.2, which was still built on
curl_cffi; 1.0.0 and 1.1.0 were GitHub releases only. Read "Changed" before
upgrading.

### Added

- Native TLS 1.3 engine (`curl_reap._tls`): HelloRetryRequest, KeyUpdate,
  PSK resumption with a thread-safe session cache (tickets are drained on
  close so resumption survives short-lived connections), strict RFC 5280
  certificate verification through the `cryptography` policy API, and an
  automatic OpenSSL fallback for TLS-1.2-only servers or client
  certificates. `Session(tls="auto"|"native"|"openssl")`, and
  `Response.infos["tls_backend"]` reports what a connection used.
- Built-in HTTP/2 (`curl_reap._h2`): on by default, byte-exact per target,
  content-decoded bodies, streamed downloads, GOAWAY-aware retry
  classification, flow control on both windows. The `h2` extra is now an
  empty alias.
- 79 impersonate targets (38 concrete captures, 19 aliases, 22 legacy
  names) with the exact per-target HTTP/1.1 and HTTP/2 header sets.
- `reap doctor [target]`: fetch a fingerprint echo service as the target and
  compare ja4, ja4_r, ja3 (where the browser's JA3 is stable), the Akamai
  HTTP/2 fingerprint and the header order with the captured values
  (peetprint is printed). It accepts all 79 names; `reap doctor --list`
  prints them.
- WebSocket and AsyncWebSocket (`reap.WebSocket.connect`,
  `Session.ws_connect`, `AsyncSession.ws_connect`): RFC 6455 over the same
  transport, with masking, fragmentation, keepalive handling and close
  codes.
- Request keyword superset: `files`, `cookies`, `stream`, `proxies` (dict
  forms), `proxy_auth`, `cert`, `timeout=(connect, read)` tuples,
  `allow_redirects="safe"` (refuses private/loopback/link-local redirect
  targets), `interface`, `debug`, `ja3`/`akamai`/`extra_fp` custom
  fingerprints, and the compatibility no-op keywords accepted with one
  warning. `trust_env` honors `*_proxy`/`NO_PROXY`.
- `Headers` multi-dict (ordered, case-insensitive, multi-value) for requests
  and responses; RFC 6265bis cookie parser and jar (`curl_reap.cookies`)
  scoped by domain, path and name.
- Response upgrades: lazy `text`, settable `encoding`, `is_success`,
  `redirect_url`, `history`, `block_reason`, `elapsed` as timedelta with
  `elapsed_seconds`, endpoint and TLS infos,
  `iter_content`/`iter_lines`/`close` for streamed bodies, pickling support.
- Session controls: `url_policy=` (checked before every outgoing URL,
  including each redirect hop), `sticky=True` (one profile and proxy for
  the session's life) and `RetryPolicy(allowed_methods=...)`.
- Crawl engine controls: `collect_items=False`, `per_domain_concurrency`,
  `max_pending` (a bounded frontier), schedule-time dedup, a `max_pages`
  budget that counts failed fetches, and `Retry-After` cooldowns on 429 and
  503.
- `reap.BrowserSession` (`js` extra): one browser context reused across
  `goto()` calls, real navigation status, optional `cdp_url` attach and
  `url_policy` gating. `extract()` for named fields and
  `markdown(main_only=True)`.
- A private job service in a new `server` extra: `reap serve` (FastAPI) and
  `reap worker` (Redis queue with leases and fencing tokens) for single-page
  extraction jobs, plus a non-root `Dockerfile`.

### Fixed

- Every P1 defect and all but one P2 defect from the 2026-10-10 transport
  audit (see `docs/design/audit-2026-10-10.md` and `docs/STATE.md` for the
  itemized closure; the open one is under "Known limitations"):
  Partitioned/unknown cookie attributes, HTTP/2 bodies returned
  compressed, h2 request bodies above 16 KB, pooled connections after
  GOAWAY, download bodies on error statuses, multi-member gzip, UTF-8
  redirect targets, torn cache entries, pool liveness and bounds,
  whole-request deadlines, size caps, CONNECT host:port, and the rest.
- HTTP/2 responses are content-decoded; downloads stream to disk on every
  transport with constant memory (5 MB bodies went from 0.05x to 1.2x a
  C-based impersonation client's throughput on the reference machine).
- `Retry-After` values are clamped to 24 hours: `inf` no longer crashes and
  huge values no longer sleep for real.
- Redirects that change origin drop `Authorization`, `Cookie`,
  `Proxy-Authorization` and `Host`, including an `https` to `http`
  downgrade on the same host.

Fixed during the 2.0.0 release cycle, in 2.0 code that no earlier release
shipped (late commits in the 2.0 pull request #29, the follow-up pull
requests #30, #33 and #34, and the release branch):

- Pooled connections and TLS 1.3 resumption tickets are keyed by the full
  trust identity (`verify` value and client `cert`), so a ticket earned with
  `verify=False` can never resume a verified request. (#29)
- The native TLS and HTTP/2 engines load at package import, which avoids a
  Python 3.14 import-lock deadlock on the first concurrent HTTP/2 requests.
  (#29)
- A complete HTTP/2 response that arrives in the same read as an error
  GOAWAY is returned instead of discarded. (#29)
- `stream=True` over HTTP/1.1 returned no body (`content` was `None` and
  `iter_content()` yielded nothing). Streamed bodies now decode `gzip`,
  `deflate` and `br` as they arrive, report truncated compressed bodies,
  keep memory bounded by the read size and return the connection to the
  pool when drained; an encoding that cannot be streamed raises
  `ContentDecodingError`. (#30)
- `Response.infos["tls_backend"]` was never set, so reading it raised
  `KeyError`. It is now `"native"`, `"openssl"` or `"plain"` on every
  connection. (#30)
- `reap doctor` measured every target with Chrome traffic, failed on the
  JA3 row for Chromium targets, never compared headers, rejected aliases and
  legacy names, and ignored `--impersonate`. It now impersonates the named
  target and compares every comparable row. (#33)
- HTTP/2 requests sent the HTTP/1.1 header set lowercased instead of the
  target's captured HTTP/2 set, so Chrome 124+ and Safari 18.0+ targets sent
  no `priority` header over HTTP/2. (#34)
- Client certificates under `tls="auto"`: the native engine answered a
  CertificateRequest with an empty certificate. Requests with `cert=` now go
  through OpenSSL, `tls="native"` with `cert=` raises `ValueError`, the
  `(cert, key, password)` form works, and paths may be `os.PathLike`. (#34)
- Privacy: when the native handshake found a TLS-1.2-only server, the
  OpenSSL fallback re-dialed the server directly instead of through the
  configured proxy. Through a SOCKS proxy the request left from the
  machine's own address; through an HTTP proxy a direct connection was
  opened and dropped before the tunnelled one. The fallback now reconnects
  the same way as the first attempt. With an `https://` proxy, which the
  OpenSSL path cannot run through, it fails before dialing anything.
- A hand-built `Profile` (no HTTP/2 spec) offered `h2` in ALPN, so a server
  that picked HTTP/2 received an HTTP/1.1 request and the request failed.
  Such profiles now offer `http/1.1` only, as the `Profile` documentation
  says; built-in targets are unchanged.

### Changed

- HTTP/2 is negotiated by default (`Session(http2=False)` opts out). The CLI
  `--http2` flag is accepted and has no effect.
- `Response.ok` is True for 2xx and 3xx (use `is_success` for 2xx only).
- `RetryPolicy` retries only `GET`, `HEAD`, `OPTIONS`, `PUT` and `DELETE` by
  default; `POST` and `PATCH` need `allowed_methods`.
- `max_redirects` defaults to 30 (it was 10).
- The crawl engine sends responses with status 400 or higher, and
  challenge-looking responses, to the request's errback instead of `parse`.
- `cryptography>=42`, `hpack>=4` and `brotli>=1.1` are required;
  `zstandard` is an optional extra (`pip install "curl-reap[zstd]"`) for
  zstd bodies and certificate compression.
- Exceptions mirror the wider ecosystem's names and error codes while
  keeping `TransportError` and `OSError` roots. `HTTPStatusError` is now an
  alias of `HTTPError`, an `OSError` subclass (it was a plain `Exception`),
  and `Response.elapsed` is a `timedelta`.

### Known limitations

- No native TLS 1.2: TLS-1.2-only servers get an OpenSSL-shaped ClientHello.
  That fallback offers only the X25519 group (`Profile.curve`), so a
  TLS-1.2-only server with a P-256 ECDSA certificate fails the handshake;
  servers with RSA certificates work.
- An `https://` proxy works only on the native TLS path. The OpenSSL path
  (TLS-1.2-only servers, `cert=`, custom profiles without a template,
  `tls="openssl"`) fails through one; use an `http://` or SOCKS proxy there.
- A per-request header set to `None` removes a session header but not one
  that comes from the profile; use a custom `Profile` to send fewer headers.
- HTTP/3 (QUIC) is not implemented.

## 1.1.0 (2026-09-30)

### Fixed

- The `reap` command line tool works again. In 1.0.0 it failed at startup with a `SyntaxError` in `curl_reap/cli.py`, where two statements shared one line.

### Added

- Optional HTTP/2 transport through hyper-h2: `Session(http2=True)`, `reap --http2`, and a new `h2` extra. Falls back to HTTP/1.1 when the server or the environment does not support it. Response bodies over HTTP/2 are not content-decoded yet.
- `impersonate=` as an alias of `profile=`, with 38 versioned Chrome, Edge, Firefox and Safari targets plus four aliases in `reap.FINGERPRINTS`, and a CLI `--impersonate` option.
- `Session.cookies`, a `CookieJar` that stores cookies from responses and redirect hops and replays them. Exported as `reap.CookieJar`.
- Streaming downloads: `Session.download()`, `reap.download()` and `AsyncSession.download()`.
- `Response.looks_like_challenge`.
- `reap.render()` and `reap.render_if_empty()` through Playwright, in a new `js` extra.
- `reap.TransportError` exported at the package root.

### Tests and CI

- CLI tests: import, `--help`, and `reap get` against a local server.
- CI runs `reap --help` on every Python version.
- The CI check that `curl_cffi` is gone from the package can now fail. Before, a negated `grep` in a bash step could never fail the job.
- An adversarial transport test suite, and a CI matrix for Python 3.9 to 3.13.

### Other

- The Geocoder's default User-Agent now says `curl_reap/1.1`.
- Documentation moved to https://velofy.co/curl_reap/.

## 1.0.0 (2026-08-22)

The from-scratch, breaking release: curl_cffi removed, a standard-library HTTP/1.1 transport with browser TLS and header profiles, and `profile=` in place of `impersonate=`. GitHub release only; it was not uploaded to PyPI.
