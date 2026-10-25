# curl_reap 2.0 state ledger

Living record of the 2.0 transport work: what shipped, what closed, what is
deliberately open. The design contract is `docs/design/beyond-curl-cffi.md`;
the audit is `docs/design/audit-2026-10-10.md`; the API parity study is
`docs/design/parity-2026-10-10.md`.

## Audit fix closure (2026-10-10 audit, closed in 2.0.0)

Every P1 finding and every P2 finding but one from the audit is closed. The
P2 header-removal row and the P3 items marked **open** below are tracked
deliberately.

| Finding | Class | Status | Where |
| --- | --- | --- | --- |
| F02 Partitioned cookies dropped; unknown attributes become phantom cookies | P1 | **closed** | `curl_reap/cookies.py` RFC 6265bis parser |
| F-B2 HTTP/2 bodies returned/saved undecoded | P1 | **closed** | `transport._h2_exchange` decodes; spill-file streaming |
| F04 h2 bodies >16 KB raise raw framing errors | P1 | **closed** | `_h2.H2Connection` chunks by frame size + both windows |
| GOAWAY leaves pooled h2 connection; next request dies raw | P1 | **closed** | retryable H2Error, connection closed on error |
| Server push stream body returned as the response | P1 | **closed** | `_h2` refuses pushes (RST REFUSED_STREAM) |
| download() over h2 buffers all; fails >64 MB | P1 | **closed** | on_data streams into the spill file |
| Multi-member gzip truncated to first member | P1 | **closed** | `_gunzip_all`, `_StreamDecoder` both decode every member |
| UTF-8 Location double-encoded | P1 | **closed** | `response._redirect_target` |
| DiskCache.set torn reads | P1 | **closed** | single-file entries, fsync + os.replace |
| download() replaces file with 503/404 body | P1 | **closed** | sink commits only for 2xx |
| CONNECT omits :443 | P1 | **closed** | `transport._connect_tunnel` always host:port |
| Pool liveness / unbounded pool / poisoned buffer | P2 | **closed** | bounded pool, select+poll liveness, empty-buffer rule |
| Timeout per socket op, not per request | P2 | **closed** | whole-request deadlines everywhere incl. redirects |
| No HTTP/1.1 size cap | P2 | **closed** | `max_body_bytes` (default 64 MiB) |
| TLS handshake failures escape raw | P2 | **closed** | wrapped in `SSLError`/`ConnectTimeout` in `_connect` |
| HEAD+303 rewritten to GET | P2 | **closed** | HEAD preserved on 303 |
| headers={name: None} cannot drop a profile header | P2 | **open** | `_merge_headers` honors None, but `Session` merges session and request headers before the profile is applied, so None drops a session header only (documented in the 2.0.0 changelog) |
| Retry-After: inf crashes; huge values sleep for real | P2 | **closed** | clamped to 24 h in `retry_after_seconds` |
| close() never sends GOAWAY | P2 | **closed** | `_Connection.close` → `H2Connection.close` |
| h2 download writes redirect body to sink | P2 | **closed** | sink gated to 2xx on both transports |
| 101 pooled as HTTP/1.1 | P2 | **closed** | 101 marked non-reusable (WebSocket takes the socket) |
| Lenient Content-Length (`1_0` accepted) | P2 | **closed** | strict digit check |
| Secure cookies accepted from http origins | P2 | **closed** | jar rejects (documented: no localhost carve-out) |
| B2/B14/B15/B16/B20/B24/B26/B28/B30 fingerprint-table items | P1/P2 | **closed** | new registry + native engines |
| P3 `_release/close` race; trailer injection; TE-without-chunked; Connection token lists; IDNA mismatches; h2 set-cookie multi; eager .text | P3 | **closed** | empty-buffer release rule; trailers consumed not merged; close-delimited TE; tokenised Connection; IDNA host keys; multi-value Set-Cookie kept; lazy text |
| P3 aio cancellation cannot stop the worker | P3 | **open** | documented: cancellation stops waiting, the timeout bounds the thread |
| OpenSSL fallback offers only X25519 (`Profile.curve`) | P2 | **open** | a TLS-1.2-only server with a P-256 ECDSA certificate fails the handshake; RSA-certificate servers work |
| Public-suffix validation for cookie domains | P3 | **open** | documented in jar docstring |

## Deliberate scope decisions

- TLS 1.2-only servers use the OpenSSL fallback and the response says so
  (`infos["tls_backend"] == "openssl"`); no native TLS 1.2. The fallback
  re-dials through the same proxy as the first attempt; it cannot run through
  an `https://` proxy (no TLS inside TLS on the stdlib `ssl` module) and
  fails before dialing anything there.
- HTTP/3 (QUIC) raises `NotImplementedError` (`http_version="v3"`).
- `perk=` is accepted and ignored with a warning (the hybrid post-quantum
  key share is automatic); the libcurl compatibility keywords are accepted
  and ignored with one warning per process.
- A-scenario HTTP/1.1 latency carries ~25% over 1.1.0 (deadline arming,
  liveness probes, multi-value header objects); 1.1.0 carried known
  correctness debt instead. The benchmark tables in `bench/` record both.
- The 1 ms pure-Python handshake cost on fresh connections is the design's
  accepted trade for readability and platform coverage; PSK resumption
  mitigates it where servers issue tickets.

## Fixed after the 2.0 merge, before the 2.0.0 release

- #30: `stream=True` over HTTP/1.1 returned no body; `infos["tls_backend"]`
  was never set.
- #33: `reap doctor` measured Chrome traffic for every target, failed the JA3
  row for Chromium, skipped headers, rejected aliases and legacy names.
- #34: HTTP/2 requests sent the HTTP/1.1 header set lowercased; client
  certificates were sent empty under `tls="auto"`.
- 2026-10-26: the TLS 1.2 OpenSSL fallback re-dialed the server directly,
  bypassing a SOCKS or HTTP proxy (`tests/test_tls12_fallback_proxy.py`).

## Verification snapshot (2026-10-26, release/2.0.0)

- Full offline suite: 1452 passed, 21 skipped (live-gated, optional h2,
  playwright, kyber-py and curl_cffi comparisons) on CPython 3.9.25, 3.12.12
  and 3.13.12; 1487 passed, 19 skipped on 3.12 with hyper-h2 installed.

## Verification snapshot (2026-10-11)

- Full offline suite: 1419 passed, 2 skipped (live-gated).
- Live verification (REAP_LIVE_TESTS=1): 14/14 - tls.peet.ws JA4/ja4_r/
  peetprint/Akamai per family, cloudflare/google/github/wiki/example fetch
  200 through the native stack, tickets cached.
- Benchmarks: `bench/AFTER-2.0.md` (vs `bench/BASELINE.md` for 1.1.0).
- Doctor: `reap doctor <target>` reproduces the parity check on any machine.
