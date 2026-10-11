# Changelog

Full history, including releases before 1.0.0: https://velofy.co/curl_reap/changelog/

## 2.0.0 (2026-10-11)

The transport is new from the TLS record layer up. curl_reap now speaks with
browser-exact bytes: a pure-Python TLS 1.3 client on `cryptography`
primitives renders each impersonate target's captured ClientHello byte for
byte (cipher order, extension order and GREASE, X25519MLKEM768 post-quantum
key shares, certificate compression, ALPS, ECH GREASE, padding), and the
built-in HTTP/2 framing reproduces each browser's SETTINGS, WINDOW_UPDATE,
priority and HPACK representations. Measured JA4, ja4_r, peetprint and Akamai
h2 fingerprints equal the captured browsers' for every one of the 53 targets.

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
- `reap doctor [target]`: fetch a fingerprint echo service and verify this
  machine's ja3/ja4/peetprint/Akamai/headers against the captured values.
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
  and responses; RFC 6265bis cookie parser and jar (`curl_reap.cookies`).
- Response upgrades: lazy `text`, settable `encoding`, `is_success`,
  `redirect_url`, `elapsed` as timedelta with `elapsed_seconds`, endpoint
  and TLS infos, `iter_content`/`iter_lines`/`close` for streamed bodies,
  pickling support.

### Fixed

- Every P1/P2 defect from the 2026-10-10 transport audit (see
  `docs/design/audit-2026-10-10.md` and `docs/STATE.md` for the itemized
  closure): Partitioned/unknown cookie attributes, HTTP/2 bodies returned
  compressed, h2 request bodies above 16 KB, pooled connections after
  GOAWAY, download bodies on error statuses, multi-member gzip, UTF-8
  redirect targets, torn cache entries, pool liveness and bounds,
  whole-request deadlines, size caps, CONNECT host:port, and the rest.
- HTTP/2 responses are content-decoded; downloads stream to disk on every
  transport with constant memory (5 MB bodies went from 0.05x to 1.2x a
  C-based impersonation client's throughput on the reference machine).
- `Retry-After` values are clamped (no more crashes on `inf`, no literal
  27-hour sleeps).

### Changed

- HTTP/2 is negotiated by default (`Session(http2=False)` opts out).
- `Response.ok` is True for 2xx and 3xx (use `is_success` for 2xx only).
- `cryptography>=42`, `hpack>=4` and `brotli>=1.1` are required;
  `zstandard` is an optional extra (`pip install "curl-reap[zstd]"`) for
  zstd bodies and certificate compression.
- Exceptions mirror the wider ecosystem's names and error codes while
  keeping `TransportError` and `OSError` roots.

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
