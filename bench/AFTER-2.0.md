# curl_reap 2.0 benchmark

Date: 2026-10-11. Machine: Apple M3 Pro (11 cores, macOS-26.3-arm64-arm-64bit). Python 3.12.12, OpenSSL 3.6.5 29 Sep 2026.

Libraries: curl_reap 2.0.0, curl_cffi 0.16.3 (libcurl libcurl/8.21.0-IMPERSONATE BoringSSL zlib/1.3.1 brotli/1.2.0 zstd/1.5.7 AppleIDN nghttp2/1.63.0 ngtcp2/1.20.0 nghttp3/1.15.0), h2 4.4.1, hpack 4.2.0, cryptography 50.0.2.

Method: every server runs in a thread of the benchmark process on 127.0.0.1; no external network. 20 warm-up requests, then 3 timed runs per scenario; the table shows the median of each metric across runs. TLS verification: self-signed ECDSA P-256 CA cert path. TLS session tickets on the server: True. HTML body 20480 bytes (4828 bytes gzip). Large body 5242880 bytes identity. curl_reap uses Session(retries=0, verify=...); curl_cffi uses requests.Session(verify=...) with its default thread-local curl handles; http.client uses one connection per thread with manual gzip decoding and is the floor reference. bad=N marks responses whose status or decoded length did not match.

Reproduce: `.venv/bin/python bench/bench.py --out bench/after-2.0.json --md bench/AFTER-2.0.md`

| Scenario | Metric | curl_reap | curl_cffi | http.client | reap / cffi |
|---|---|---|---|---|---|
| A. HTTP/1.1 keep-alive, 1 connection, 2000 GET x 20 KB gzip HTML | req/s | 9,795 | 7,389 | 14,184 | 1.33x |
|  | p50 / p99 ms | 0.099 / 0.144 | 0.132 / 0.206 | 0.069 / 0.097 |  |
| B. HTTP/1.1 keep-alive, 16 threads x 300 GET, shared Session | req/s | 7,594 | 4,271 | 11,758 | 1.78x |
|  | p50 / p99 ms | 2.061 / 3.617 | 3.634 / 6.729 | 1.272 / 2.953 |  |
| C. HTTPS fresh connections, 300 x 1 GET (server sends Connection: close) | conn/s | 1,011 | 2,085 | 1,311 | 0.48x |
|  | p50 / p99 ms | 0.958 / 1.460 | 0.452 / 0.843 | 0.731 / 1.294 |  |
| D. HTTPS keep-alive, 1 connection, 2000 GET x 20 KB gzip HTML | req/s | 8,034 | 6,944 | 12,215 | 1.16x |
|  | p50 / p99 ms | 0.120 / 0.182 | 0.139 / 0.211 | 0.081 / 0.105 |  |
| E. HTTP/2 keep-alive (ALPN h2), 1 connection, 1000 GET x 20 KB gzip HTML | req/s | 3,280 | 4,377 | n/a | 0.75x |
|  | p50 / p99 ms | 0.296 / 0.531 | 0.221 / 0.428 | n/a |  |
| F. HTTP/1.1 keep-alive, 50 GET x 5 MB identity body | MB/s | 3,554.5 | 2,967.4 | 12,154.0 | 1.20x |
|  | p50 / p99 ms | 1.333 / 1.971 | 1.589 / 2.759 | 0.368 / 0.875 |  |
