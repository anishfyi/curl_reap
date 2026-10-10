# curl_cffi HTTP/2 client templates

Captured 2026-10-10 18:31 UTC with curl_cffi 0.16.3 (libcurl/8.21.0-IMPERSONATE BoringSSL zlib/1.3.1 brotli/1.2.0 zstd/1.5.7 AppleIDN nghttp2/1.63.0 ngtcp2/1.20.0 nghttp3/1.15.0) by `tools/capture_h2.py`. Each target was fetched 2 times against a local TLS server (ALPN h2) and 2 times against a local plain HTTP/1.1 server. `peet` is the live `http2.akamai_fingerprint` reported by https://tls.peet.ws/api/all for the same target. Regenerate the index without touching the network with `python tools/capture_h2.py --index-only`.

## Per target

| target | akamai (local) | peet match | HEADERS flags | HEADERS priority | pseudo | stable |
|---|---|---|---|---|---|---|
| chrome | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome150 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome146 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome145 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome142 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome136 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome133a | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome131 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome124 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome123 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome120 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome119 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome116 | `1:65536;2:0;3:1000;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome110 | `1:65536;2:0;3:1000;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome107 | `1:65536;2:0;3:1000;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome104 | `1:65536;3:1000;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome101 | `1:65536;3:1000;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome100 | `1:65536;3:1000;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome99 | `1:65536;3:1000;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome_android | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome131_android | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| chrome99_android | `1:65536;3:1000;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| edge | `1:65536;3:1000;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| edge101 | `1:65536;3:1000;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| edge99 | `1:65536;3:1000;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=1 dep=0 w=256 | m,a,s,p | yes |
| firefox | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=42 | m,p,a,s | yes |
| firefox147 | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=42 | m,p,a,s | yes |
| firefox144 | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=42 | m,p,a,s | yes |
| firefox135 | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=256 | m,p,a,s | yes |
| firefox133 | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=256 | m,p,a,s | yes |
| tor | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | not fetched | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=42 | m,p,a,s | yes |
| tor145 | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=42 | m,p,a,s | yes |
| safari | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` | yes | END_STREAM\|END_HEADERS (0x05) | none | m,s,a,p | yes |
| safari2601 | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` | yes | END_STREAM\|END_HEADERS (0x05) | none | m,s,a,p | yes |
| safari260 | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` | yes | END_STREAM\|END_HEADERS (0x05) | none | m,s,a,p | yes |
| safari184 | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=256 | m,s,a,p | yes |
| safari180 | `2:0;3:100;4:2097152;8:1;9:1\|10420225\|0\|m,s,a,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=256 | m,s,a,p | yes |
| safari170 | `2:0;4:4194304;3:100\|10485760\|0\|m,s,p,a` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=255 | m,s,p,a | yes |
| safari155 | `4:4194304;3:100\|10485760\|0\|m,s,p,a` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=255 | m,s,p,a | yes |
| safari153 | `4:4194304;3:100\|10485760\|0\|m,s,p,a` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=255 | m,s,p,a | yes |
| safari_ios | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` | yes | END_STREAM\|END_HEADERS (0x05) | none | m,s,a,p | yes |
| safari260_ios | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` | yes | END_STREAM\|END_HEADERS (0x05) | none | m,s,a,p | yes |
| safari184_ios | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=256 | m,s,a,p | yes |
| safari180_ios | `2:0;3:100;4:2097152;8:1;9:1\|10420225\|0\|m,s,a,p` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=256 | m,s,a,p | yes |
| safari172_ios | `2:0;4:2097152;3:100\|10485760\|0\|m,s,p,a` | yes | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=255 | m,s,p,a | yes |
| safari_beta | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` | not fetched | END_STREAM\|END_HEADERS (0x05) | none | m,s,a,p | yes |
| safari_ios_beta | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` | not fetched | END_STREAM\|END_HEADERS (0x05) | none | m,s,a,p | yes |
| safari15_3 | `4:4194304;3:100\|10485760\|0\|m,s,p,a` | not fetched | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=255 | m,s,p,a | yes |
| safari15_5 | `4:4194304;3:100\|10485760\|0\|m,s,p,a` | not fetched | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=255 | m,s,p,a | yes |
| safari17_0 | `2:0;4:4194304;3:100\|10485760\|0\|m,s,p,a` | not fetched | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=255 | m,s,p,a | yes |
| safari17_2_ios | `2:0;4:2097152;3:100\|10485760\|0\|m,s,p,a` | not fetched | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=255 | m,s,p,a | yes |
| safari18_0 | `2:0;3:100;4:2097152;8:1;9:1\|10420225\|0\|m,s,a,p` | not fetched | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=256 | m,s,a,p | yes |
| safari18_0_ios | `2:0;3:100;4:2097152;8:1;9:1\|10420225\|0\|m,s,a,p` | not fetched | END_STREAM\|END_HEADERS\|PRIORITY (0x25) | E=0 dep=0 w=256 | m,s,a,p | yes |

## Header order per target

### chrome

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "macOS"` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "macOS"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_806a8c22fdea`, ja3_hash `20e3b453110dcda1edfa905b0b6d531b`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome150

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "macOS"` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "macOS"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_806a8c22fdea`, ja3_hash `6b74a7db9ec89ef0787a60e0fc1294aa`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome146

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "macOS"` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "macOS"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`, ja3_hash `e64f1f62360f31004eb31caba5ea8f59`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome145

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "macOS"` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "macOS"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`, ja3_hash `a07e41280f488ba692e2949a65bdc882`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome142

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "macOS"` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "macOS"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`, ja3_hash `cac5635c4590b05e05d4589f90440f84`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome136

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "macOS"` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "macOS"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`, ja3_hash `1abca34e28dfe52fe8175ff90291f877`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome133a

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "macOS"` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "macOS"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`, ja3_hash `e5aece86234b23b0d245d42f123421d6`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome131

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "macOS"` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "macOS"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_02713d6af862`, ja3_hash `3d277f0ba2138b1be85d11ffb4c38568`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome124

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "macOS"` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "macOS"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_02713d6af862`, ja3_hash `ece5d5447b4867f10c9189a1739f4688`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome123

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "macOS"` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "macOS"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_02713d6af862`, ja3_hash `68c6a927a938bc6167e0964d18872c5e`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome120

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "macOS"` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "macOS"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_02713d6af862`, ja3_hash `33b419b717d93313e59779a424392f79`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome119

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "macOS"` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "macOS"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_02713d6af862`, ja3_hash `3290f5c03c598471fd76d01a6a6002f7`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome116

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "Windows"` [literal-incremental, name literal, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAMAAAPoAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "Windows"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;3:1000;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_e5627efa2ab1`, ja3_hash `8249a04527b2d0bf55345a0c6c1c655b`, akamai `1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome110

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "Windows"` [literal-incremental, name literal, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAMAAAPoAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "Windows"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;3:1000;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_e5627efa2ab1`, ja3_hash `5dd1b9076a50ab687077650a5f5852d1`, akamai `1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome107

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "Windows"` [literal-incremental, name literal, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAMAAAPoAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "Windows"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;3:1000;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_e5627efa2ab1`, ja3_hash `cd08e31494f9531f560d64c695473da9`, akamai `1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome104

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "Windows"` [literal-incremental, name literal, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAMAAAPoAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "Windows"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;3:1000;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_e5627efa2ab1`, ja3_hash `cd08e31494f9531f560d64c695473da9`, akamai `1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome101

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="101", "Google Chrome";v="101"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "Windows"` [literal-incremental, name literal, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAMAAAPoAAQAYAAAAAYABAAA`
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="101", "Google Chrome";v="101"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "Windows"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;3:1000;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_e5627efa2ab1`, ja3_hash `cd08e31494f9531f560d64c695473da9`, akamai `1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome100

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "Windows"` [literal-incremental, name literal, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAMAAAPoAAQAYAAAAAYABAAA`
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "Windows"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;3:1000;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_e5627efa2ab1`, ja3_hash `cd08e31494f9531f560d64c695473da9`, akamai `1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome99

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "Windows"` [literal-incremental, name literal, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAMAAAPoAAQAYAAAAAYABAAA`
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "Windows"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;3:1000;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_e5627efa2ab1`, ja3_hash `cd08e31494f9531f560d64c695473da9`, akamai `1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome_android

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "Android"` [literal-incremental, name literal, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "Android"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_02713d6af862`, ja3_hash `bcb9c4a5b53934b11f637554cc6d8012`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome131_android

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: "Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "Android"` [literal-incremental, name literal, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA`
  - `sec-ch-ua: "Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "Android"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:6291456;6:262144
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_02713d6af862`, ja3_hash `896fe116cbba485b08fb471834e2a59b`, akamai `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`

### chrome99_android

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?1` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "Android"` [literal-incremental, name literal, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.58 Mobile Safari/537.36` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAMAAAPoAAQAYAAAAAYABAAA`
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"`
  - `sec-ch-ua-mobile: ?1`
  - `sec-ch-ua-platform: "Android"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.58 Mobile Safari/537.36`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;3:1000;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_e5627efa2ab1`, ja3_hash `cd08e31494f9531f560d64c695473da9`, akamai `1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`

### edge

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "Windows"` [literal-incremental, name literal, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAMAAAPoAAQAYAAAAAYABAAA`
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "Windows"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;3:1000;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_e5627efa2ab1`, ja3_hash `cd08e31494f9531f560d64c695473da9`, akamai `1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`

### edge101

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "Windows"` [literal-incremental, name literal, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAMAAAPoAAQAYAAAAAYABAAA`
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "Windows"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;3:1000;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_e5627efa2ab1`, ja3_hash `cd08e31494f9531f560d64c695473da9`, akamai `1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`

### edge99

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="99", "Microsoft Edge";v="99"` [literal-incremental, name literal, value huffman]
  - `sec-ch-ua-mobile: ?0` [literal-incremental, name literal, value plain]
  - `sec-ch-ua-platform: "Windows"` [literal-incremental, name literal, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.30` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAMAAAPoAAQAYAAAAAYABAAA`
  - `sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="99", "Microsoft Edge";v="99"`
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "Windows"`
  - `Upgrade-Insecure-Requests: 1`
  - `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.30`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-User: ?1`
  - `Sec-Fetch-Dest: document`
  - `Accept-Encoding: gzip, deflate, br`
  - `Accept-Language: en-US,en;q=0.9`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;3:1000;4:6291456;6:262144
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1516h2_8daaf6152771_e5627efa2ab1`, ja3_hash `cd08e31494f9531f560d64c695473da9`, akamai `1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`

### firefox

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `te: trailers` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAAgAAAAUAAEAA`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Accept-Language: en-US,en;q=0.9`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Upgrade-Insecure-Requests: 1`
  - `Sec-Fetch-Dest: document`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-User: ?1`
  - `Priority: u=0, i`
  - `Te: trailers`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:131072;5:16384
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1717h2_5b57614c22b0_3cbfd9057e0d`, ja3_hash `6f7889b9fb1a62a9577e685c1fcfa919`, akamai `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`

### firefox147

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `te: trailers` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAAgAAAAUAAEAA`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Accept-Language: en-US,en;q=0.9`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Upgrade-Insecure-Requests: 1`
  - `Sec-Fetch-Dest: document`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-User: ?1`
  - `Priority: u=0, i`
  - `Te: trailers`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:131072;5:16384
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1717h2_5b57614c22b0_3cbfd9057e0d`, ja3_hash `6f7889b9fb1a62a9577e685c1fcfa919`, akamai `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`

### firefox144

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `accept-language: en-US,en;q=0.5` [literal-incremental, name static-table #17, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `te: trailers` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAAgAAAAUAAEAA`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Accept-Language: en-US,en;q=0.5`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Upgrade-Insecure-Requests: 1`
  - `Sec-Fetch-Dest: document`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-User: ?1`
  - `Priority: u=0, i`
  - `Te: trailers`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:131072;5:16384
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1717h2_5b57614c22b0_3cbfd9057e0d`, ja3_hash `6f7889b9fb1a62a9577e685c1fcfa919`, akamai `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`

### firefox135

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `accept-language: en-US,en;q=0.5` [literal-incremental, name static-table #17, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `te: trailers` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAAgAAAAUAAEAA`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Accept-Language: en-US,en;q=0.5`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Upgrade-Insecure-Requests: 1`
  - `Sec-Fetch-Dest: document`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-User: ?1`
  - `Priority: u=0, i`
  - `Te: trailers`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:131072;5:16384
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1717h2_5b57614c22b0_3cbfd9057e0d`, ja3_hash `6f7889b9fb1a62a9577e685c1fcfa919`, akamai `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`

### firefox133

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `accept-language: en-US,en;q=0.5` [literal-incremental, name static-table #17, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `te: trailers` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAAgAAAAUAAEAA`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Accept-Language: en-US,en;q=0.5`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Upgrade-Insecure-Requests: 1`
  - `Sec-Fetch-Dest: document`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-User: ?1`
  - `Priority: u=0, i`
  - `Te: trailers`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:131072;5:16384
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1716h2_5b57614c22b0_eeeea6562960`, ja3_hash `2d692a4485ca2f5f2b10ecb2d2909ad3`, akamai `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`

### tor

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `accept-language: en-US,en;q=0.5` [literal-incremental, name static-table #17, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `sec-gpc: 1` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `te: trailers` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAAgAAAAUAAEAA`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Accept-Language: en-US,en;q=0.5`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Sec-GPC: 1`
  - `Upgrade-Insecure-Requests: 1`
  - `Sec-Fetch-Dest: document`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-User: ?1`
  - `Priority: u=0, i`
  - `Te: trailers`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:131072;5:16384
- Regular header order h1 vs h2: same order

### tor145

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:scheme: https` [indexed-static #7]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `accept-language: en-US,en;q=0.5` [literal-incremental, name static-table #17, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
  - `sec-gpc: 1` [literal-incremental, name literal, value plain]
  - `upgrade-insecure-requests: 1` [literal-incremental, name literal, value plain]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-user: ?1` [literal-incremental, name literal, value plain]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `te: trailers` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAEAAQAAAAIAAAAAAAQAAgAAAAUAAEAA`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Accept-Language: en-US,en;q=0.5`
  - `Accept-Encoding: gzip, deflate, br, zstd`
  - `Sec-GPC: 1`
  - `Upgrade-Insecure-Requests: 1`
  - `Sec-Fetch-Dest: document`
  - `Sec-Fetch-Mode: navigate`
  - `Sec-Fetch-Site: none`
  - `Sec-Fetch-User: ?1`
  - `Priority: u=0, i`
  - `Te: trailers`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 1:65536;2:0;4:131072;5:16384
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d1513h2_8daaf6152771_748f4c70de1c`, ja3_hash `0faf2a91198d40dbd58b9308f3fca2fd`, akamai `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`

### safari

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAMAAABkAAQAIAAAAAkAAAAB`
  - `sec-fetch-dest: document`
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15`
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `sec-fetch-site: none`
  - `sec-fetch-mode: navigate`
  - `accept-language: en-US,en;q=0.9`
  - `accept-encoding: gzip, deflate, br`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;3:100;4:2097152;9:1
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d2013h2_a09f3c656075_7f0f34a4126d`, ja3_hash `ecdf4f49dd59effc439639da29186671`, akamai `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`

### safari2601

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAMAAABkAAQAIAAAAAkAAAAB`
  - `sec-fetch-dest: document`
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15`
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `sec-fetch-site: none`
  - `sec-fetch-mode: navigate`
  - `accept-language: en-US,en;q=0.9`
  - `accept-encoding: gzip, deflate, br`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;3:100;4:2097152;9:1
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d2013h2_a09f3c656075_7f0f34a4126d`, ja3_hash `ecdf4f49dd59effc439639da29186671`, akamai `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`

### safari260

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAMAAABkAAQAIAAAAAkAAAAB`
  - `sec-fetch-dest: document`
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15`
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `sec-fetch-site: none`
  - `sec-fetch-mode: navigate`
  - `accept-language: en-US,en;q=0.9`
  - `accept-encoding: gzip, deflate, br, zstd`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;3:100;4:2097152;9:1
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d2014h2_a09f3c656075_d0a99439f9b1`, ja3_hash `6618231821d2d40f8d1859f5a43a0307`, akamai `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`

### safari184

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAMAAABkAAQAIAAAAAkAAAAB`
  - `sec-fetch-dest: document`
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15`
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `sec-fetch-site: none`
  - `sec-fetch-mode: navigate`
  - `accept-language: en-US,en;q=0.9`
  - `accept-encoding: gzip, deflate, br`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;3:100;4:2097152;9:1
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d2014h2_a09f3c656075_e42f34c56612`, ja3_hash `773906b0efdefa24a7f2b8eb6985bf37`, akamai `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`

### safari180

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAMAAABkAAQAIAAAAAgAAAABAAkAAAAB`
  - `sec-fetch-dest: document`
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15`
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `sec-fetch-site: none`
  - `sec-fetch-mode: navigate`
  - `accept-language: en-US,en;q=0.9`
  - `accept-encoding: gzip, deflate, br`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;3:100;4:2097152;8:1;9:1
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d2014h2_a09f3c656075_e42f34c56612`, ja3_hash `773906b0efdefa24a7f2b8eb6985bf37`, akamai `2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p`

### safari170

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15` [literal-incremental, name static-table #58, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAQAQAAAAAMAAABk`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Sec-Fetch-Site: none`
  - `Accept-Encoding: gzip, deflate, br`
  - `Sec-Fetch-Mode: navigate`
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15`
  - `Accept-Language: en-US,en;q=0.9`
  - `Sec-Fetch-Dest: document`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;4:4194304;3:100
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d2014h2_a09f3c656075_14788d8d241b`, ja3_hash `773906b0efdefa24a7f2b8eb6985bf37`, akamai `2:0;4:4194304;3:100|10485760|0|m,s,p,a`

### safari155

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `accept-language: en-GB,en-US;q=0.9,en;q=0.8` [literal-incremental, name static-table #17, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAQAQAAAAAMAAABk`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Accept-Language: en-GB,en-US;q=0.9,en;q=0.8`
  - `Accept-Encoding: gzip, deflate, br`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 4:4194304;3:100
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d2014h2_a09f3c656075_14788d8d241b`, ja3_hash `773906b0efdefa24a7f2b8eb6985bf37`, akamai `4:4194304;3:100|10485760|0|m,s,p,a`

### safari153

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `accept-language: en-us` [literal-incremental, name static-table #17, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAQAQAAAAAMAAABk`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Accept-Language: en-us`
  - `Accept-Encoding: gzip, deflate, br`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 4:4194304;3:100
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d2613h2_2802a3db6c62_845d286b0d67`, ja3_hash `656b9a2f4de6ed4909e157482860ab3d`, akamai `4:4194304;3:100|10485760|0|m,s,p,a`

### safari_ios

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:authority: 127.0.0.1:56514` [literal-incremental, name static-table #1, value huffman]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:56515`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAMAAABkAAQAIAAAAAkAAAAB`
  - `sec-fetch-dest: document`
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1`
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `sec-fetch-site: none`
  - `sec-fetch-mode: navigate`
  - `accept-language: en-US,en;q=0.9`
  - `accept-encoding: gzip, deflate, br, zstd`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;3:100;4:2097152;9:1
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d2015h2_a09f3c656075_c258b721e490`, ja3_hash `fb3660676bafc9799c86bd51a1ea12f5`, akamai `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`

### safari260_ios

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAMAAABkAAQAIAAAAAkAAAAB`
  - `sec-fetch-dest: document`
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1`
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `sec-fetch-site: none`
  - `sec-fetch-mode: navigate`
  - `accept-language: en-US,en;q=0.9`
  - `accept-encoding: gzip, deflate, br, zstd`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;3:100;4:2097152;9:1
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d2015h2_a09f3c656075_c258b721e490`, ja3_hash `fb3660676bafc9799c86bd51a1ea12f5`, akamai `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`

### safari184_ios

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAMAAABkAAQAIAAAAAkAAAAB`
  - `sec-fetch-dest: document`
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1`
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `sec-fetch-site: none`
  - `sec-fetch-mode: navigate`
  - `accept-language: en-US,en;q=0.9`
  - `accept-encoding: gzip, deflate, br`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;3:100;4:2097152;9:1
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d2014h2_a09f3c656075_e42f34c56612`, ja3_hash `773906b0efdefa24a7f2b8eb6985bf37`, akamai `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`

### safari180_ios

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAMAAABkAAQAIAAAAAgAAAABAAkAAAAB`
  - `sec-fetch-dest: document`
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1`
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `sec-fetch-site: none`
  - `sec-fetch-mode: navigate`
  - `accept-language: en-US,en;q=0.9`
  - `accept-encoding: gzip, deflate, br`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;3:100;4:2097152;8:1;9:1
- Regular header order h1 vs h2: only in h2: priority
- peet.ws live: ja4 `t13d2014h2_a09f3c656075_e42f34c56612`, ja3_hash `773906b0efdefa24a7f2b8eb6985bf37`, akamai `2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p`

### safari172_ios

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1` [literal-incremental, name static-table #58, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAQAIAAAAAMAAABk`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Sec-Fetch-Site: none`
  - `Accept-Encoding: gzip, deflate, br`
  - `Sec-Fetch-Mode: navigate`
  - `User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1`
  - `Accept-Language: en-US,en;q=0.9`
  - `Sec-Fetch-Dest: document`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;4:2097152;3:100
- Regular header order h1 vs h2: same order
- peet.ws live: ja4 `t13d2014h2_a09f3c656075_14788d8d241b`, ja3_hash `773906b0efdefa24a7f2b8eb6985bf37`, akamai `2:0;4:2097152;3:100|10485760|0|m,s,p,a`

### safari_beta

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAMAAABkAAQAIAAAAAkAAAAB`
  - `sec-fetch-dest: document`
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15`
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `sec-fetch-site: none`
  - `sec-fetch-mode: navigate`
  - `accept-language: en-US,en;q=0.9`
  - `accept-encoding: gzip, deflate, br`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;3:100;4:2097152;9:1
- Regular header order h1 vs h2: only in h2: priority

### safari_ios_beta

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br, zstd` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAMAAABkAAQAIAAAAAkAAAAB`
  - `sec-fetch-dest: document`
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1`
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `sec-fetch-site: none`
  - `sec-fetch-mode: navigate`
  - `accept-language: en-US,en;q=0.9`
  - `accept-encoding: gzip, deflate, br, zstd`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;3:100;4:2097152;9:1
- Regular header order h1 vs h2: only in h2: priority

### safari15_3

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `accept-language: en-us` [literal-incremental, name static-table #17, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAQAQAAAAAMAAABk`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Accept-Language: en-us`
  - `Accept-Encoding: gzip, deflate, br`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 4:4194304;3:100
- Regular header order h1 vs h2: same order

### safari15_5

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `accept-language: en-GB,en-US;q=0.9,en;q=0.8` [literal-incremental, name static-table #17, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAQAQAAAAAMAAABk`
  - `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Accept-Language: en-GB,en-US;q=0.9,en;q=0.8`
  - `Accept-Encoding: gzip, deflate, br`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 4:4194304;3:100
- Regular header order h1 vs h2: same order

### safari17_0

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15` [literal-incremental, name static-table #58, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAQAQAAAAAMAAABk`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Sec-Fetch-Site: none`
  - `Accept-Encoding: gzip, deflate, br`
  - `Sec-Fetch-Mode: navigate`
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15`
  - `Accept-Language: en-US,en;q=0.9`
  - `Sec-Fetch-Dest: document`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;4:4194304;3:100
- Regular header order h1 vs h2: same order

### safari17_2_ios

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1` [literal-incremental, name static-table #58, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAQAIAAAAAMAAABk`
  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `Sec-Fetch-Site: none`
  - `Accept-Encoding: gzip, deflate, br`
  - `Sec-Fetch-Mode: navigate`
  - `User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1`
  - `Accept-Language: en-US,en;q=0.9`
  - `Sec-Fetch-Dest: document`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;4:2097152;3:100
- Regular header order h1 vs h2: same order

### safari18_0

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAMAAABkAAQAIAAAAAgAAAABAAkAAAAB`
  - `sec-fetch-dest: document`
  - `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15`
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `sec-fetch-site: none`
  - `sec-fetch-mode: navigate`
  - `accept-language: en-US,en;q=0.9`
  - `accept-encoding: gzip, deflate, br`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;3:100;4:2097152;8:1;9:1
- Regular header order h1 vs h2: only in h2: priority

### safari18_0_ios

- HTTP/2 headers in wire order (representation in brackets):
  - `:method: GET` [indexed-static #2]
  - `:scheme: https` [indexed-static #7]
  - `:authority: 127.0.0.1:62748` [literal-incremental, name static-table #1, value huffman]
  - `:path: /some/path?q=1` [literal-without-indexing, name static-table #4, value huffman]
  - `sec-fetch-dest: document` [literal-incremental, name literal, value huffman]
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1` [literal-incremental, name static-table #58, value huffman]
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` [literal-incremental, name static-table #19, value huffman]
  - `sec-fetch-site: none` [literal-incremental, name literal, value huffman]
  - `sec-fetch-mode: navigate` [literal-incremental, name literal, value huffman]
  - `accept-language: en-US,en;q=0.9` [literal-incremental, name static-table #17, value huffman]
  - `priority: u=0, i` [literal-incremental, name literal, value huffman]
  - `accept-encoding: gzip, deflate, br` [literal-incremental, name static-table #16, value huffman]
- HPACK dynamic table size update: none
- Client frames before the response: SETTINGS WINDOW_UPDATE HEADERS
- Client frames after the response: SETTINGS(ACK) GOAWAY[last=0 NO_ERROR] (connection client-close-notify)
- HTTP/1.1 request line: `GET /some/path?q=1 HTTP/1.1`
- HTTP/1.1 headers in wire order:
  - `Host: 127.0.0.1:62749`
  - `Upgrade: h2c`
  - `HTTP2-Settings: AAIAAAAAAAMAAABkAAQAIAAAAAgAAAABAAkAAAAB`
  - `sec-fetch-dest: document`
  - `user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1`
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `sec-fetch-site: none`
  - `sec-fetch-mode: navigate`
  - `accept-language: en-US,en;q=0.9`
  - `accept-encoding: gzip, deflate, br`
  - `Connection: Upgrade, HTTP2-Settings`
- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS 2:0;3:100;4:2097152;8:1;9:1
- Regular header order h1 vs h2: only in h2: priority

## Family conclusions

### chrome (chrome, chrome150, chrome146, chrome145, chrome142, chrome136, chrome133a, chrome131, chrome124, chrome123, chrome120, chrome119, chrome116, chrome110, chrome107, chrome104, chrome101, chrome100, chrome99, chrome_android, chrome131_android, chrome99_android, edge, edge101, edge99)

- `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`: chrome, chrome150, chrome146, chrome145, chrome142, chrome136, chrome133a, chrome131, chrome124, chrome123, chrome120, chrome119, chrome_android, chrome131_android
- `1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`: chrome116, chrome110, chrome107
- `1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`: chrome104, chrome101, chrome100, chrome99, chrome99_android, edge, edge101, edge99

- Frame order on every Chromium target is preface, SETTINGS, WINDOW_UPDATE (stream 0, increment 15663105), HEADERS on stream 1. No standalone PRIORITY frames, no padding, no CONTINUATION, no HPACK dynamic table size update.
- SETTINGS: chrome124, chrome131, chrome136, chrome150 (alias chrome) and chrome_android send 1:65536;2:0;4:6291456;6:262144. edge101 (alias edge) is a Chromium 101 era profile and sends 1:65536;3:1000;4:6291456;6:262144, that is MAX_CONCURRENT_STREAMS 1000 in place of ENABLE_PUSH 0.
- The HEADERS frame carries END_STREAM|END_HEADERS|PRIORITY (0x25) with exclusive=1, dependency=0, weight=256 on all eight Chromium targets.
- Pseudo header order is m,a,s,p. Regular header order on HTTP/2: sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority. edge101 has no priority header and sends accept-encoding gzip, deflate, br (no zstd) and an accept value without image/avif.
- HTTP/1.1 order is the same list with canonical casing, minus priority: curl_cffi only adds priority: u=0, i on HTTP/2 for Chromium targets. The plain http request is Host, Upgrade: h2c, HTTP2-Settings, the profile headers, then Connection: Upgrade, HTTP2-Settings. The HTTP2-Settings value AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA is the base64url of the same SETTINGS payload (1:65536;2:0;4:6291456;6:262144); real Chrome never attempts an h2c upgrade.
- chrome_android sends sec-ch-ua-platform "Android" and a Linux; Android 10; K user agent but keeps sec-ch-ua-mobile ?0. Real Chrome on Android sends ?1, so this target is internally inconsistent in curl_cffi 0.16.3.

### firefox (firefox, firefox147, firefox144, firefox135, firefox133, tor, tor145)

- `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`: firefox, firefox147, firefox144, firefox135, firefox133, tor, tor145

- firefox133, firefox135, firefox147 (alias firefox) and tor145 all send SETTINGS 1:65536;2:0;4:131072;5:16384 and WINDOW_UPDATE 12517377 and no standalone PRIORITY frames, so the PRIORITY slot of the Akamai string is 0. Fingerprint databases record desktop Firefox opening priority placeholder streams (3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241) after SETTINGS; confirm against a live Firefox before copying, but curl_cffi does not send them.
- Pseudo header order is m,p,a,s (:path before :authority).
- HEADERS flags are END_STREAM|END_HEADERS|PRIORITY (0x25) with exclusive=0 and dependency=0. The weight is 42 for firefox147, firefox and tor145 and 256 for firefox133 and firefox135.
- Regular header order on HTTP/2: user-agent, accept, accept-language, accept-encoding, upgrade-insecure-requests, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, sec-fetch-user, priority, te. tor145 inserts sec-gpc: 1 after accept-encoding and uses the rv:128.0 ESR user agent. accept-language is en-US,en;q=0.9 for firefox147 and en-US,en;q=0.5 for firefox133 and firefox135.
- HTTP/1.1 order is identical, with Priority: u=0, i and Te: trailers also sent over HTTP/1.1. TE: trailers is a header Firefox adds to HTTP/2 requests; check a live Firefox HTTP/1.1 request before carrying it over. HTTP2-Settings AAEAAQAAAAIAAAAAAAQAAgAAAAUAAEAA decodes to 1:65536;2:0;4:131072;5:16384.

### safari (safari, safari2601, safari260, safari184, safari180, safari170, safari155, safari153, safari_ios, safari260_ios, safari184_ios, safari180_ios, safari172_ios, safari_beta, safari_ios_beta, safari15_3, safari15_5, safari17_0, safari17_2_ios, safari18_0, safari18_0_ios)

- `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`: safari, safari2601, safari260, safari184, safari_ios, safari260_ios, safari184_ios, safari_beta, safari_ios_beta
- `2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p`: safari180, safari180_ios, safari18_0, safari18_0_ios
- `2:0;4:4194304;3:100|10485760|0|m,s,p,a`: safari170, safari17_0
- `4:4194304;3:100|10485760|0|m,s,p,a`: safari155, safari153, safari15_3, safari15_5
- `2:0;4:2097152;3:100|10485760|0|m,s,p,a`: safari172_ios, safari17_2_ios

- Three sub profiles. safari184, safari2601 (alias safari) and safari_ios send SETTINGS 2:0;3:100;4:2097152;9:1. safari180 adds ENABLE_CONNECT_PROTOCOL: 2:0;3:100;4:2097152;8:1;9:1. safari170 sends 2:0;4:4194304;3:100, with identifier 4 before 3 on the wire.
- WINDOW_UPDATE is 10420225 for every Safari 18 and 26 profile and 10485760 for safari170.
- Pseudo header order is m,s,a,p for Safari 18 and 26 profiles and m,s,p,a for safari170.
- HEADERS flags differ inside the family: safari, safari2601 and safari_ios send END_STREAM|END_HEADERS (0x05) with no priority fields; safari180 and safari184 send 0x25 with exclusive=0, dependency=0, weight=256; safari170 sends 0x25 with weight=255.
- Regular header order on HTTP/2 for Safari 18 and 26: sec-fetch-dest, user-agent, accept, sec-fetch-site, sec-fetch-mode, accept-language, priority, accept-encoding. safari170: accept, sec-fetch-site, accept-encoding, sec-fetch-mode, user-agent, accept-language, sec-fetch-dest and no priority header. accept-encoding is gzip, deflate, br on desktop and gzip, deflate, br, zstd on safari_ios.
- HTTP/1.1 order matches HTTP/2 minus priority (only sent on HTTP/2), but the HTTP/1.1 header names are emitted lowercase (sec-fetch-dest, user-agent, accept, ...) for Safari 18 and 26, and safari170 mixes canonical names with a lowercase user-agent. CFNetwork sends canonical case on HTTP/1.1, so this is a curl_cffi profile artefact. HTTP2-Settings AAIAAAAAAAMAAABkAAQAIAAAAAkAAAAB decodes to 2:0;3:100;4:2097152;9:1.

### all targets

- Nothing varied between the two runs of any target: no HTTP/2 GREASE, no padding, no randomised settings or header order. The HTTP/2 layer of curl_cffi is fully deterministic per target.
- HPACK is the nghttp2 encoder on every target regardless of the browser profile: :method GET and :scheme https are static table indexed (#2, #7), :authority is a literal with incremental indexing against static name #1, :path is a literal without indexing against static name #4 with a Huffman value, and every regular header is a literal with incremental indexing whose name comes from the static table when one exists (user-agent #58, accept #19, accept-encoding #16, accept-language #17) and is otherwise a Huffman literal. Values use Huffman only when it is shorter (?0, ?1, 1 and the te name stay plain). No dynamic table size update is ever sent. An observer that classifies HPACK representations sees the same encoder behind Chrome, Firefox and Safari targets.
- Connection teardown is the libcurl pattern on every target: the SETTINGS ACK for the server's SETTINGS is written on the client's first read pass (in this capture that lands after the response because the server answers in the same batch), then GOAWAY with last_stream_id=0, NO_ERROR and the debug data b'shutdown\x00' (a libcurl marker), then TLS close_notify, because the Session is closed after a single request. A browser keeps the connection open and only sends GOAWAY on shutdown, and never with that debug string.
- Over plain http:// every target sends the libcurl h2c upgrade: Host first, then Upgrade: h2c, HTTP2-Settings (base64url of the exact SETTINGS payload that target uses on TLS), the profile headers, then Connection: Upgrade, HTTP2-Settings last. No browser sends an h2c upgrade.
- Live tls.peet.ws agreed with the local capture on all 19 targets, so the Akamai strings in the JSON templates are the ones remote servers see. The TLS ja4 and ja3_hash reported by peet.ws are stored in each template's peet_ws block for the TLS work.

