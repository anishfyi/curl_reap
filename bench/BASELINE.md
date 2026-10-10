# curl_reap baseline benchmark

Date: 2026-10-10. Machine: Apple M3 Pro (11 cores, macOS-26.3-arm64-arm-64bit). Python 3.12.12, OpenSSL 3.6.5 29 Sep 2026.

Libraries: curl_reap 1.1.0, curl_cffi 0.16.3 (libcurl libcurl/8.21.0-IMPERSONATE BoringSSL zlib/1.3.1 brotli/1.2.0 zstd/1.5.7 AppleIDN nghttp2/1.63.0 ngtcp2/1.20.0 nghttp3/1.15.0), h2 4.4.1, hpack 4.2.0, cryptography 50.0.2.

Method: every server runs in a thread of the benchmark process on 127.0.0.1; no external network. 20 warm-up requests, then 3 timed runs per scenario; the table shows the median of each metric across runs. TLS verification: self-signed ECDSA P-256 CA cert path. TLS session tickets on the server: True. HTML body 20480 bytes (4828 bytes gzip). Large body 5242880 bytes identity. curl_reap uses Session(retries=0, verify=...); curl_cffi uses requests.Session(verify=...) with its default thread-local curl handles; http.client uses one connection per thread with manual gzip decoding and is the floor reference. bad=N marks responses whose status or decoded length did not match.

Reproduce: `.venv/bin/python bench/bench.py --out bench/baseline.json --md bench/BASELINE.md`

| Scenario | Metric | curl_reap | curl_cffi | http.client | reap / cffi |
|---|---|---|---|---|---|
| A. HTTP/1.1 keep-alive, 1 connection, 2000 GET x 20 KB gzip HTML | req/s | 12,949 | 7,468 | 14,449 | 1.73x |
|  | p50 / p99 ms | 0.076 / 0.098 | 0.131 / 0.204 | 0.068 / 0.092 |  |
| B. HTTP/1.1 keep-alive, 16 threads x 300 GET, shared Session | req/s | 10,676 | 4,238 | 11,817 | 2.52x |
|  | p50 / p99 ms | 1.413 / 3.108 | 3.635 / 6.913 | 1.259 / 3.003 |  |
| C. HTTPS fresh connections, 300 x 1 GET (server sends Connection: close) | conn/s | 1,639 | 2,179 | 1,416 | 0.75x |
|  | p50 / p99 ms | 0.601 / 0.970 | 0.447 / 0.786 | 0.690 / 1.061 |  |
| D. HTTPS keep-alive, 1 connection, 2000 GET x 20 KB gzip HTML | req/s | 11,349 | 6,979 | 12,218 | 1.63x |
|  | p50 / p99 ms | 0.086 / 0.114 | 0.139 / 0.210 | 0.080 / 0.113 |  |
| E. HTTP/2 keep-alive (ALPN h2), 1 connection, 1000 GET x 20 KB gzip HTML | req/s | 3,079 (bad=1000) | 4,401 | n/a | 0.70x |
|  | p50 / p99 ms | 0.317 / 0.631 | 0.222 / 0.416 | n/a |  |
| F. HTTP/1.1 keep-alive, 50 GET x 5 MB identity body | MB/s | 121.3 | 2,468.9 | 11,214.9 | 0.05x |
|  | p50 / p99 ms | 41.246 / 42.211 | 2.042 / 2.571 | 0.406 / 0.826 |  |

## Baseline findings (2026-10-10)

Where curl_reap already leads curl_cffi 0.16.3 on this machine:

- A, D: HTTP/1.1 keep-alive over plain TCP and over TLS, curl_reap is 1.6x to 1.7x faster per request (0.076 ms vs 0.131 ms p50) and sits within 10 percent of the stdlib http.client floor.
- B: with 16 threads sharing one Session, curl_reap sustains 10.7k req/s while curl_cffi drops to 4.2k req/s, below its own sequential rate, so curl_cffi loses throughput under threads while curl_reap scales.

Where curl_cffi leads, and why:

- C (fresh TLS connections): 2,179 conn/s vs 1,639 conn/s. Running the server with OP_NO_TICKET gives the same ratio (2,303 vs 1,787), so curl_cffi is not winning through session resumption here; BoringSSL's handshake plus libcurl's connect path is simply cheaper than socket.create_connection (getaddrinfo every time) plus ssl.SSLContext.wrap_socket. curl_reap never resumes TLS sessions, which is the lever left to pull.
- E (HTTP/2): 4,401 vs 3,079 req/s, and every curl_reap response is flagged bad=1000: the HTTP/2 path (curl_reap/http.py _Transport._h2_exchange) returns the raw gzip body because it never calls _decode_content. This is a correctness bug, not only a speed gap; the gzip bytes also get decoded to garbage .text.
- F (5 MB body): 121 MB/s vs 2,469 MB/s, a 20x gap. 36.5 ms of the 41 ms per response is content.decode("utf-8", "replace") in _RawResponse.__init__, which eagerly builds .text for every body, binary ones included. The socket path itself moves the 5 MB in about 2 ms.

Profile notes: cProfile in Python 3.12 is built on sys.monitoring and samples every thread, so the in-process server's recv and sendall calls appear in the whole-process listings (that is why recv and sendall show about 2x the request count). The curl_reap-only sections are unaffected. Profiles live outside the repo (profile_A.txt, profile_C.txt, profile_D.txt, profile_F.txt in the scratchpad of the run that produced this file); regenerate with --profile-dir.

Hot spots in curl_reap's own code (A and D profiles, 2000 requests each), with one idea each:

1. http.py _RawResponse.__init__: eager .text decode of every body (95 percent of F). Make .text a lazy cached property on _RawResponse and Response and run _fix_garbled_text on first access only.
2. http.py _Transport._h2_exchange and h2engine.py H2Protocol.request: no Content-Encoding decode on HTTP/2; also one recv, receive_data, acknowledge_received_data and flush per frame. Call _decode_content in _h2_exchange; batch WINDOW_UPDATE acks until stream end; hoist the h2.events imports out of request.
3. http.py _Transport._response (largest own time, 57 percent of A cumulative): per header line two decode calls plus strip, then CaseInsensitiveHeaders._actual does a linear scan with str.lower on every key for each insert and each later .get (24,000 _actual calls and 186,000 str.lower calls per 2000 requests). Decode the head once, split, and keep a lowercase index dict inside CaseInsensitiveHeaders so lookups are O(1).
4. http.py _BufferedSocket._receive, read_until, read_exact (24 percent of A, 27 percent of D): recv into bytes, bytearray.extend, find, bytes(buffer[:end]), del, then the same again for the body, four copies of every byte. Fast path the common case where one recv holds head plus body by parsing the received bytes directly and slicing the body with memoryview; use recv_into with a reusable buffer and larger reads for Content-Length bodies.
5. http.py _merge_headers and _header_items (13 percent of A): the profile's static header block and the session headers are re-validated and re-merged on every request, including isinstance(headers, Mapping) through typing (8,000 slow ABC checks). Validate once at construction and cache the merged list and its rendered bytes per Session; merge only when the request carries its own headers.
6. http.py _Transport._single_request (5 percent own time): urlsplit plus three separate .hostname computations (urllib recomputes it each access, via _single_request, _origin and CookieJar.header_for), idna encode, two quote calls, and 18 per-line str.encode calls to render the head. Parse the URL once per request, pass the parts down, memoize (scheme, host, port, authority, target) per URL string, and render the head with a single join and encode.
7. http.py Session.request and Response.__init__: 15 kwargs.pop calls, _route under a lock even when nothing rotates, and Response copies the headers into a second CaseInsensitiveHeaders and rebuilds history. Add a no-override fast path, skip the lock when there is one profile and no proxy, and let Response adopt the raw headers object.
8. http.py CookieJar.header_for: takes the lock and splits the URL on every request even with an empty jar. Return "" before any work when _cookies is empty.
9. http.py _Transport._connect (C: 0.38 ms of the 0.60 ms per connection): getaddrinfo on every connect, no TCP_NODELAY, settimeout twice, and a full handshake every time (do_handshake is the top own-time item in C). Cache resolved addresses per host for a short TTL, set TCP_NODELAY as curl does, and keep the last SSLSocket.session per (host, port, profile) to pass session= into wrap_socket so repeat connections use a PSK handshake; curl_cffi gained nothing from tickets here, so this can overtake it on C.
10. zlib.decompress (8 percent of A) is unavoidable and identical to curl_cffi's libz cost; no change expected there.
