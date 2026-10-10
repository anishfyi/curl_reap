# curl_reap 2.0: beyond curl_cffi

Status: design frozen on 2026-10-11 for the `feat/beyond-curl-cffi` branch. This document is the contract between the work packages; implementers follow it and record deviations in `docs/STATE.md`.

## Why

curl_cffi wins on one axis only: the bytes on the wire. Its patched BoringSSL emits the browser's exact TLS ClientHello and its nghttp2 emits the browser's HTTP/2 SETTINGS. Everything curl_reap sends today through the standard library `ssl` module is an OpenSSL-shaped hello (JA4 `t13d913h2_...` against Chrome's `t13d1516h2_8daaf6152771_806a8c22fdea`) and hyper-h2 default settings (`1:4096;2:1;...|00|0|m,s,a,p` against Chrome's `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`). The standard library cannot be configured to fix either: no extension order, no GREASE, no TLS 1.3 suite order, no supported-groups control, no ML-KEM key share.

Measured on 2026-10-10 (bench/BASELINE.md): curl_reap is already 1.6 to 2.5 times faster than curl_cffi on HTTP/1.1 keep-alive and threaded work, but 0.75x on fresh TLS handshakes, 0.7x on HTTP/2 (and its HTTP/2 bodies are never content-decoded), and 0.05x on 5 MB bodies because `.text` is decoded eagerly. The API also rejects 22 keywords a curl_cffi user passes every day (`cookies=`, `files=`, `stream=`, `proxies=`, timeout tuples) and has no WebSocket.

## What

A 2.0.0 release of curl_reap in which:

1. The TLS layer is a pure-Python TLS 1.3 client (`curl_reap/_tls/`) on the `cryptography` package's primitives that sends a byte-faithful ClientHello per impersonate target, including a real X25519MLKEM768 hybrid key share (ML-KEM-768 from `cryptography` when available, else the verified pure-Python implementation), compressed certificates, ALPS, ECH GREASE, HelloRetryRequest, KeyUpdate, and PSK resumption. Measured JA4 and peetprint equal curl_cffi's for every captured target.
2. The HTTP/2 layer is curl_reap's own framing (`curl_reap/_h2/`) over the `hpack` package's Huffman tables, emitting each browser's SETTINGS, WINDOW_UPDATE, HEADERS flags and priority, pseudo-header order and nghttp2-identical HPACK representations. Measured Akamai fingerprint equals curl_cffi's for every captured target. HTTP/2 is on by default.
3. Every curl_cffi 0.16.3 target name resolves (56 names plus curl_reap's older names as aliases), with exact header sets per target captured from curl_cffi, and the HTTP/1.1 request carries no `Upgrade: h2c` tell.
4. The request API is a superset of `curl_cffi.requests`: every keyword curl_cffi accepts is accepted with the same semantics (or raises `NotImplementedError` with a reason for HTTP/3 only), `Response` carries every curl_cffi attribute, exceptions mirror curl_cffi's hierarchy and codes, and `WebSocket`/`AsyncWebSocket` exist.
5. The transport defects found by the audit (`docs/STATE.md` lists them with their fix) are closed: lazy `.text`, HTTP/2 decoding and streaming, pool liveness and bounds, request deadlines, body caps, RFC 6265bis cookies, multi-member gzip, UTF-8 Location, atomic cache writes, download safety, CONNECT port, and the rest.
6. `reap doctor [target]` fetches a fingerprint echo and reports JA3, JA4, peetprint, Akamai and the HTTP header order against the expected values, so users can prove parity themselves.
7. Benchmarks against curl_cffi are published in `bench/` and the README states them with the exact command.

Not in scope: HTTP/3 (QUIC), CAPTCHA or anti-bot bypass, TLS 1.2 in the native engine (TLS 1.2-only servers fall back to the OpenSSL path and the response says so), constant-time cryptography.

## How

### Dependencies

Required: `lxml`, `cssselect`, `cryptography>=42` (x509 verification policy API), `hpack>=4`, `brotli>=1.1` (compressed certificates and `br` bodies). Optional extras: `zstd` (`zstandard`, used for `zstd` bodies and certificate compression on Python < 3.14; Python 3.14 uses `compression.zstd`), `js` (Playwright), `server` (FastAPI + Redis), `dev`. The `h2` extra becomes an empty alias for one release and is documented as removed. If `cryptography` cannot be imported the transport silently uses the OpenSSL path with the old best-effort profiles, and `Session.tls_backend` reports `"openssl"`.

### Module layout and ownership

| Path | Owner work package | Contents |
| --- | --- | --- |
| `curl_reap/exceptions.py` | WP-core | Exception hierarchy, no imports from the package |
| `curl_reap/headers.py` | WP-core | `Headers` multi-dict; `CaseInsensitiveHeaders = Headers` |
| `curl_reap/cookies.py` | WP-core | RFC 6265bis parser, `CookieJar`, `Cookies` facade |
| `curl_reap/multipart.py` | WP-core | `encode_multipart`, `Multipart` (`CurlMime` alias), per-family boundaries |
| `curl_reap/socks.py` | WP-core | SOCKS4, SOCKS4a, SOCKS5, SOCKS5h connect |
| `curl_reap/_tls/` | WP-tls | TLS 1.3 engine, templates loader, ML-KEM, certificate verification, drivers |
| `curl_reap/_h2/` | WP-h2 | HTTP/2 framing, HPACK encoder, H2Spec templates, connection |
| `curl_reap/fingerprint.py` | WP-fp | JA3/JA4/Akamai calculators, expected values, `check()` |
| `curl_reap/tls.py` | WP-registry | `Profile`, `FINGERPRINTS`, `PROFILES`, `resolve_profile`, `create_ssl_context` (OpenSSL fallback) |
| `curl_reap/_profiles_data.py` | WP-registry | Generated: header sets per target, template names, aliases |
| `curl_reap/_tls/templates_data.py` | WP-registry | Generated from `tools/hello_templates/*.json` |
| `curl_reap/_h2/templates_data.py` | WP-registry | Generated from `tools/h2_templates/*.json` |
| `curl_reap/transport.py` | WP-transport | `_Transport`: pool, connect (native TLS, OpenSSL fallback, proxies), HTTP/1.1 framing, HTTP/2 exchange, redirects, streaming |
| `curl_reap/response.py` | WP-transport | `Response`, `_RawResponse`, streaming body |
| `curl_reap/http.py` | WP-transport | `Session`, module functions, re-exports so `from curl_reap.http import X` keeps working |
| `curl_reap/websocket.py` | WP-ws | `WebSocket`, `AsyncWebSocket`, close codes, errors |
| `curl_reap/aio.py` | WP-ws | `AsyncSession` (thread-backed, with `max_clients`, `ws_connect`, streaming) |
| `curl_reap/cli.py` | WP-fp | `reap doctor`, method subcommands, `-o/--auth/--proxy` |
| `curl_reap/h2engine.py` | removed | hyper-h2 engine deleted |

### Interfaces

Every package below may import `curl_reap.exceptions` and nothing else from curl_reap except where stated.

`curl_reap/exceptions.py`:

```python
class RequestException(OSError):            # alias RequestsError
    code: int = 0                            # CurlECode-compatible number
    response = None
class TransportError(RequestException): ...  # base for everything below; existing name kept
class ConnectionError(TransportError): ...   # code 7
class DNSError(ConnectionError): ...         # code 6
class ProxyError(ConnectionError): ...       # code 5
class SSLError(ConnectionError): ...         # code 35
class CertificateVerifyError(SSLError): ...  # code 60
class Timeout(TransportError): ...           # code 28
class ConnectTimeout(Timeout, ConnectionError): ...
class ReadTimeout(Timeout): ...
class TooManyRedirects(TransportError): ...  # code 47, .response = last hop
class IncompleteRead(TransportError): ...    # code 18
class ChunkedEncodingError(TransportError): ...  # code 56
class ContentDecodingError(TransportError): ...  # code 61
class InvalidURL(RequestException, ValueError): ...   # code 3
class InvalidSchema(RequestException, ValueError): ... # code 1
class InvalidHeader(RequestException, ValueError): ...
class InterfaceError(ConnectionError): ...   # code 45
class ImpersonateError(RequestException): ...
class SessionClosed(RequestException): ...
class StreamConsumedError(RequestException): ...
class UnrewindableBodyError(RequestException): ...
class HTTPError(RequestException): ...       # alias HTTPStatusError; .response set
class URLPolicyError(ValueError): ...        # unchanged
class WebSocketError(RequestException): ...
class WebSocketClosed(WebSocketError): ...
class WebSocketTimeout(WebSocketError, Timeout): ...
class CurlECode(IntEnum): ...                # same numbers as curl_cffi
```

`curl_reap/headers.py`:

```python
class Headers(MutableMapping[str, str]):
    """Ordered, case-insensitive, multi-value. Constructor accepts Headers, Mapping, (name, value) pairs, or 'Name: value' lines."""
    def get_list(self, key, split_commas=False) -> list[str]
    def multi_items(self) -> list[tuple[str, str]]
    def raw(self) -> list[tuple[bytes, bytes]]
    def add(self, key, value) -> None       # append without replacing
    # __getitem__ joins duplicates with ', '; __setitem__ replaces all; pop/__delitem__/update case-insensitive
CaseInsensitiveHeaders = Headers
```

`curl_reap/cookies.py`:

```python
def parse_set_cookie(value: str) -> dict | None   # name, value, domain, path, secure, httponly, samesite, partitioned, max_age, expires; unknown attributes ignored
class CookieJar:                                   # existing semantics plus: set(name, value, domain=None, path='/', secure=False), get(name, default=None, domain=None, path=None) raising CookieConflict on ambiguity, delete(), __len__, __iter__ over cookie dicts, items(), to_cookiejar() -> http.cookiejar.CookieJar, update(cookies), save(path)/load(path) JSON, header_for(url, extra=None), absorb(url, specs) rejects Secure from http origins, hosts IDNA-normalized
class Cookies(MutableMapping[str, str]):           # curl_cffi facade over a CookieJar, .jar property
class CookieConflict(...)                          # re-exported from exceptions
```

`curl_reap/multipart.py`:

```python
def boundary_for(family: str) -> str      # chrome/edge/safari: '----WebKitFormBoundary' + 16 [A-Za-z0-9]; firefox: '-' * 27 + 20 digits; other: 32 hex
def encode_multipart(data=None, files=None, boundary=None) -> tuple[bytes, str]   # (body, content_type); data fields first then files; file spec: fileobj | (filename, content) | (filename, content, content_type) | (filename, content, content_type, headers)
class Multipart:                           # CurlMime-compatible: addpart(name, content_type=None, filename=None, local_path=None, data=None), from_list(), to_body(boundary) -> (bytes, content_type)
CurlMime = Multipart
```

`curl_reap/socks.py`:

```python
def socks_connect(proxy, host, port, timeout, source_address=None) -> socket.socket
# proxy: urlsplit result with scheme socks4|socks4a|socks5|socks5h, optional user:pass. socks4a and socks5h send the hostname (remote DNS); socks4 and socks5 resolve locally. Raises ProxyError.
```

`curl_reap/_tls/`:

```python
# __init__.py exports:
class TLSError(TransportError); class TLS12Negotiated(TLSError); class CertificateError(CertificateVerifyError, TLSError)
class HelloTemplate                       # dataclass built from a template dict (the tools/hello_templates JSON shape, loaded from _tls/templates_data.py). Fields: name, ciphers, extensions (ordered list of dicts), supported_groups, signature_algorithms, key_share_groups, alpn, alps_codepoint, alps_value, supported_versions, psk_modes, compress_certificate, ec_point_formats, record_size_limit, delegated_credentials, padding_rule, ech (dict|None), permute_extensions (bool), grease (bool), session_ticket (bool)
def template(name: str) -> HelloTemplate   # KeyError for unknown
def template_from_ja3(ja3: str, *, alpn=('h2','http/1.1')) -> HelloTemplate
def build_client_hello(template, server_name, *, alpn, key_shares, psk=None, random_bytes=None) -> bytes   # pure function, used by tests and fingerprint.py
class TLSClient:                           # sans-IO
    def __init__(self, server_name, template, *, verify=True, alpn=('h2','http/1.1'), resumption=None)
    def start(self) -> None                # queues the ClientHello
    def receive(self, data: bytes) -> list[Event]   # Event in {HandshakeDone, ApplicationData(data), Closed(reason), NewTicket(ticket)}
    def data_to_send(self) -> bytes
    def send(self, app_data: bytes) -> None
    def close(self) -> None                # queues close_notify
    def key_update(self) -> None
    handshake_complete: bool; alpn_selected: str|None; cipher: str; group: str; peer_chain: list[bytes]; version = 'TLSv1.3'
def wrap_socket(sock, server_name, template, *, verify=True, alpn=('h2','http/1.1'), timeout=None, deadline=None, session_cache=None) -> TLSSocket
class TLSSocket:                           # blocking socket-like over TLSClient
    sendall, recv(n) (b'' after close_notify or EOF), settimeout, gettimeout, close, shutdown, fileno, getpeername, getsockname
    selected_alpn_protocol() -> str|None; version() -> 'TLSv1.3'; cipher() -> (name, 'TLSv1.3', bits); getpeercert(binary_form=True) -> bytes; negotiated_group -> str
class AsyncTLSSocket                       # asyncio driver, same methods as coroutines (reader/writer based)
class SessionCache                         # thread-safe {server_name: list[ticket]} with max entries; used for PSK resumption
# verify: True (system store via ssl default context certs, then certifi), False, or a CA bundle path. Certificate verification uses cryptography.x509.verification with DNSName(server_name) or IPAddress.
# TLS12Negotiated is raised from wrap_socket when the ServerHello has no supported_versions extension; the caller falls back to ssl.
```

`curl_reap/_h2/`:

```python
class H2Spec                               # dataclass: settings: tuple[tuple[int,int],...], window_update: int, priority_frames: tuple[tuple[int,bool,int,int],...], headers_flags: int, headers_priority: tuple[bool,int,int]|None, pseudo_order: str ('masp'|'mpas'|'msap'|'mspa'), name
def spec(name: str) -> H2Spec; def spec_from_akamai(s: str) -> H2Spec; def akamai_string(spec) -> str
class H2Error(TransportError)
class H2Connection:
    def __init__(self, sock, spec: H2Spec, *, max_body=64 * 1024 * 1024, deadline=None)   # sends preface, SETTINGS in spec order, WINDOW_UPDATE, PRIORITY frames
    def request(self, method, scheme, authority, path, headers, body=b'', *, on_data=None, deadline=None) -> H2Response
        # headers: ordered list of (name, value) regular headers (already lowercase or not; lowercased here); pseudo headers emitted in spec.pseudo_order; HPACK representations mimic nghttp2: :method/:scheme indexed when in the static table, :authority literal-with-incremental-indexing with static name index, :path literal-without-indexing with static name, regular headers literal-with-incremental-indexing with static name index when the name is in the static table, Huffman only when shorter, cookie values never-indexed? (no: match nghttp2 capture, see tools/h2_templates/<t>.json 'headers' list). Request body chunked by min(peer max frame size, stream window, connection window), waits for WINDOW_UPDATE. on_data(chunk) streams DATA; otherwise body buffered up to max_body (H2Error beyond).
    class H2Response: status: int, headers: list[tuple[str,str]], body: bytes|None, trailers: list[tuple[str,str]], stream_id
    alive -> bool                           # False after GOAWAY, connection error, or close
    def close(self) -> None                 # GOAWAY last_stream_id, NO_ERROR, debug b'' then socket close
    def ping(self) -> float                 # round trip seconds (liveness probe)
# Handles: SETTINGS (ack, apply), WINDOW_UPDATE both windows, PING (ack), GOAWAY (mark dead; requests with stream_id > last_stream_id raise H2Error(retryable=True)), RST_STREAM, PUSH_PROMISE (RST_STREAM REFUSED_STREAM; ENABLE_PUSH is 0 for every browser), PRIORITY, CONTINUATION, trailers, 1xx informational HEADERS skipped, padding, max_body. Events are filtered by stream id. Flow control: send WINDOW_UPDATE on the stream and connection when consumed exceeds half the initial window, the way Chrome does (connection window = 65535 + spec.window_update).
```

`curl_reap/fingerprint.py`:

```python
def parse_client_hello(data: bytes) -> dict; def ja3(parsed) -> tuple[str, str]; def ja4(parsed, alpn='h2') -> str; def ja4_r(parsed) -> str; def peetprint(parsed) -> str
def akamai_from_frames(frames) -> str
EXPECTED: dict[str, dict]      # target -> {'ja4': ..., 'ja4_r': ..., 'akamai': ..., 'ja3_fixed': bool, 'ja3': str|None}
def check(target='chrome', url='https://tls.peet.ws/api/all', session=None) -> dict   # {'target', 'ja3', 'ja4', 'peetprint', 'akamai', 'expected', 'matches': {...}, 'headers': [...], 'http_version'}
```

`curl_reap/tls.py` (registry):

```python
@dataclass(frozen=True)
class Profile:
    name: str; family: str ('chrome'|'edge'|'firefox'|'safari'|'tor'|'custom'); version: str
    headers: HeaderTuple               # HTTP/1.1 header set in order (no Host, no Upgrade/HTTP2-Settings/Connection)
    h2_headers: HeaderTuple            # HTTP/2 header set in order (lowercase names), None means derive from headers
    tls_template: str | None           # key into _tls templates; None => OpenSSL path
    h2_spec: str | None                # key into _h2 specs; None => HTTP/1.1 only
    accept_encoding: str               # as sent in headers
    form_boundary: str                 # family rule name for multipart
    ciphers, alpn_protocols, curve, minimum_version   # kept for the OpenSSL fallback
FINGERPRINTS: dict[str, Profile]     # all 56 curl_cffi names, their aliases (chrome -> chrome150, edge -> edge101, firefox -> firefox147, safari -> safari2601, safari_ios -> safari260_ios, safari_beta -> safari2601, safari_ios_beta -> safari260_ios, chrome_android -> chrome131_android, edge_99/edge_101/safari15_3/safari15_5/safari17_0/safari17_2_ios/safari18_0/safari18_0_ios/safari18_4/safari18_4_ios as in curl_cffi), plus curl_reap 1.x names (chrome98, chrome126, chrome128, chrome129, chrome130, chrome133, edge126, edge128, edge129, edge130, edge131, edge133, firefox95, firefox102, firefox109, firefox117, firefox127, firefox128, firefox132, safari16_0, safari16_4, safari17_2) mapped to the nearest captured template with their own User-Agent version
PROFILES = {'chrome', 'firefox', 'safari'}; resolve_profile(name | Profile | curl_cffi Fingerprint dict) -> Profile
def create_ssl_context(profile, verify=True, alpn=...)   # unchanged OpenSSL fallback
```

Transport rules:

- `Session(http2=True)` is the default. ALPN offered is `h2, http/1.1` for every built-in profile. `http_version` accepts `'v1'`, `'v2'`, `'v2tls'`, `'v2_prior_knowledge'`, `'v3'`/`'v3only'` (raise `NotImplementedError`).
- `Session(tls='auto'|'native'|'openssl')`. `auto` uses native when `cryptography` imports and the profile has a template, and falls back to OpenSSL only on `TLS12Negotiated` or when `cert=` is given. `Response.tls_backend` and `Response.http_version` report what happened.
- Pool key: `(scheme, host, port, proxy, profile.name, verify, tls_backend, interface)`. Per-key cap 10 idle, idle TTL 60 s, liveness probe (`select` readable means dead; h2 `alive`) before reuse, reader buffer must be empty, `Connection: close` tokenised.
- Timeouts: `timeout` float is a whole-request deadline (connect plus transfer, every redirect hop included); `(connect, read)` sets a connect timeout and a per-read timeout plus a deadline of their sum; `None` disables. Deadline passed to every socket operation.
- Body cap: `Session(max_body_bytes=64 MiB)` for buffered bodies; sinks and `stream=True` are uncapped.
- `stream=True` returns after the response head; `iter_content(chunk_size)`, `iter_lines()`, `close()`; connection returned to the pool on exhaustion, closed on early `close()`.
- `download()` commits the file only for 2xx and never writes redirect or error bodies.
- Redirects: default `max_redirects=30`, `-1` unlimited, `TooManyRedirects` carries the last response; HEAD stays HEAD on 303; Location bytes decoded latin-1 then re-encoded UTF-8; `allow_redirects='safe'` rejects private, loopback, link-local destinations.
- Proxies: `proxy=` (string or list), `proxies=` dict with curl_cffi key order (`scheme://host`, `all://host`, `scheme`, `all`), `proxy_auth=`, schemes `http`, `https` (TLS to the proxy through the OpenSSL context), `socks4`, `socks4a`, `socks5`, `socks5h`; default port 1080 for socks and 8080 for http (document the difference from libcurl's 1080); CONNECT target always `host:port`; `trust_env=True` reads `*_proxy` and `no_proxy` when no proxy is given.
- Request keywords accepted: everything in curl_cffi 0.16.3's `request()` signature. `ja3=`, `akamai=`, `extra_fp=` build a custom `Profile` for the call. `perk=` is stored and ignored with a warning. `curl_options=`, `curl_infos=`, `thread=`, `curl=`, `use_thread_local_curl=`, `async_curl=`, `loop=` accepted and ignored with one warning per process. `debug=True` logs request and response heads at INFO on logger `curl_reap.transport`.
- Response: `status`, `status_code`, `reason`, `ok` (200 to 399, `is_success` for 2xx), `url`, `headers` (`Headers`), `cookies` (`Cookies`), `content`, lazy `text` with `encoding` setter, `charset`, `charset_encoding`, `default_encoding`, `elapsed` (`timedelta`; `elapsed_seconds` float), `history`, `redirect_count`, `redirect_url`, `is_redirect`, `primary_ip`, `primary_port`, `local_ip`, `local_port`, `http_version` (string, `http_version_int` curl constant), `request` snapshot, `infos` (dict with `tls_backend`, `cipher`, `group`, `alpn`, `request_size`, `response_size`), `json(**kw)` from bytes, `iter_content`, `iter_lines`, `close`, `raise_for_status`, `block_reason`, `looks_like_challenge`, selector passthroughs unchanged, `__getstate__` drops raw and selector.

### Verification

- Unit tests per module; the existing suites must keep passing (adjusted where the behaviour change is intended and documented).
- Offline fingerprint tests: build the ClientHello for every template and assert JA4/ja4_r/peetprint equal the captured expected values; build the HTTP/2 preface for every spec and assert the Akamai string.
- Local TLS 1.3 server tests (stdlib `ssl` server with a generated CA) for the native engine: handshake, AES-GCM and ChaCha20, HRR (server restricted to P-256), KeyUpdate, close_notify, hostname mismatch, untrusted CA, `verify=False`, resumption on the second connection.
- Local HTTP/2 server tests on hyper-h2 (test-only dependency) for the `_h2` client: flow control both directions, large bodies, push refusal, GOAWAY, RST_STREAM, trailers, 1xx.
- Live tests behind `REAP_LIVE_TESTS=1`: tls.peet.ws JA4, peetprint and Akamai per family equal curl_cffi's recorded values; cloudflare.com, google.com, github.com, wikipedia.org, example.com fetch 200 through the native stack including ML-KEM negotiation on hosts that select it.
- `bench/bench.py` rerun; the README table uses those numbers.
- Python 3.9 to 3.13 matrix in CI with `cryptography` and `brotli` installed, and a job that installs without `cryptography` to prove the OpenSSL fallback.

## Optimal way

Alternatives considered: (a) binding curl-impersonate like curl_cffi, rejected because it recreates the thing we compete with, needs a C toolchain per platform and locks fingerprints to binary releases; (b) `utls` through Go or Rust bindings, same problem; (c) staying on OpenSSL `ssl` and documenting the gap, rejected because the user's goal is parity; (d) a pure-Python TLS 1.3 client on `cryptography`, chosen: `cryptography` ships wheels for every platform curl_cffi lacks (win32, ppc64le, s390x, musl variants, PyPy), the engine is 2 to 3 thousand lines of readable Python a maintainer can adapt the day a browser changes its hello, the spike already matches Chrome's JA4 and peetprint byte for byte, CPU cost is about 1 ms per handshake, and templates are data so new targets need a capture, not a release.

For HTTP/2, driving hyper-h2 cannot produce the exact SETTINGS set (it always emits all six settings) or nghttp2's HPACK representations, so the framing is written in curl_reap on top of `hpack`'s Huffman tables; it is about 700 lines and gives async a sans-IO core for later.

## Work packages and order

Phase 1 (parallel, no shared files): WP-core, WP-tls, WP-h2, WP-fp, WP-registry, WP-transport (coded against the interfaces above with `_tls` and `_h2` imported lazily so it runs on the OpenSSL path until they land).
Phase 2 (sequential): WP-integrate wires transport to `_tls` and `_h2`, deletes `h2engine.py`, runs and fixes the whole suite, reruns the bench; then WP-ws adds WebSocket and the async facade on the integrated transport; then WP-fp finishes `reap doctor` on the live stack.
Phase 3: adversarial review per module, matrix run, live verification, docs, release.
