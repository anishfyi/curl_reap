# curl_cffi ClientHello templates

Raw TLS ClientHello captures of curl_cffi 0.16.3 (libcurl-impersonate), one
JSON template per impersonate target, produced by
`tools/capture_clienthello.py` with `tools/fingerprint_calc.py`.

Capture method: a raw TCP listener on 127.0.0.1 that never answers; curl_cffi
is pointed at `https://tls.peet.ws:<port>/` with `CURLOPT_RESOLVE` pinning
the name to 127.0.0.1 so the hello carries a real `server_name` (BoringSSL
omits SNI for IP literals, which would change the extension count, the JA4
`d` marker and the padding length). Each target was captured 3 times and the
runs were diffed to classify every field as fixed or variable. Every template
also carries `peet_live`, the fingerprint https://tls.peet.ws/api/all reported
for the same target over the real network, and whether it matches.

Reproduce:

    .venv/bin/python tools/capture_clienthello.py --all --runs 3 --templates --raw-dir /tmp/raw --verify-live

## Verification

* JA4 and `ja4_r` computed from the local capture equal the live peet.ws
  values for all 24 targets.
* JA3 equals the live value for the 15 targets with a fixed extension order
  (edge, firefox, safari, tor). For the 9 Chrome-family targets BoringSSL
  permutes the extension order per connection, so JA3 is a per-connection
  sample: 3 captures gave 3 different hashes, and 3 live peet.ws fetches did
  too. The hash in the task brief (`e2a070130f888c31d5b457a9266b4ef9`) is the
  md5 of the one extension order peet.ws happened to see, and
  `fingerprint_calc.ja3` reproduces it exactly for that order.
* The peet.ws full responses for one target per family are stored as
  `peet_chrome.json`, `peet_firefox.json`, `peet_safari.json` and
  `peet_edge.json` (the alias target of each family).

## Fields that vary between connections (all families)

| Field | Chrome | Edge | Firefox | Safari | Tor |
| --- | --- | --- | --- | --- | --- |
| `random` (32 bytes) | varies | varies | varies | varies | varies |
| `session_id` (32 bytes) | varies | varies | varies | varies | varies |
| GREASE values (cipher, 2 extensions, group, version, key_share) | varies | varies | none sent | varies | none sent |
| Extension order | permuted | fixed | fixed | fixed | fixed |
| `key_share` key bytes | varies | varies | varies | varies | varies |
| ECH GREASE (`config_id`, `enc`, payload, payload length) | varies | absent | varies | absent | varies |
| `padding` length | absent | fixed (204) | absent | fixed when present | absent |
| Handshake length | varies with ECH payload only | fixed 508 | varies with ECH payload only | fixed | varies with ECH payload only |

GREASE values are drawn fresh per connection: cipher, first extension, last
extension, supported_groups, supported_versions and the 1-byte key_share
entry each get their own value (they are not all the same value).

ECH GREASE is the same shape everywhere it appears: type outer (0),
HKDF-SHA256 (0x0001), AES-128-GCM (0x0001), random 1-byte config_id, 32-byte
enc, payload of 144, 176, 208 or 240 bytes (16-byte AEAD tag plus 32 * k for
k in 4..7). Extension body length is therefore 186, 218, 250 or 282 and
this is the only reason the handshake length moves.

The padding extension (BoringSSL rule) appears only when the hello without it
is between 256 and 511 bytes; it pads the handshake message to exactly 512
bytes (handshake length 508 plus 4-byte header). The padding length therefore
depends on SNI length. Targets with a post-quantum key share are over 1500
bytes and never pad.

The record layer version is 0x0301 for every target; the legacy_version in
the hello body is 0x0303; the session id is always 32 random bytes;
compression methods are `[0]`; ALPN is `h2, http/1.1` everywhere.

## Chrome family

Targets: chrome124, chrome131, chrome133a, chrome136, chrome142, chrome146,
chrome150, chrome (= chrome150), chrome_android (= chrome131_android).

Shared across all Chrome targets:

* Ciphers (15 + leading GREASE): `GREASE 1301 1302 1303 c02b c02f c02c c030
  cca9 cca8 c013 c014 009c 009d 002f 0035`. JA4_b `8daaf6152771`.
* 16 real extensions plus two GREASE: the first extension is an empty GREASE,
  the last is a GREASE with a 1-byte body (`00`). Everything in between is
  permuted per connection. Set: `0000 0005 000a 000b 000d 0010 0012 0017 001b
  0023 002b 002d 0033 fe0d ff01` plus ALPS (`4469` or `44cd`, see below).
* supported_versions `GREASE, 0304, 0303`; psk_key_exchange_modes `[1]`;
  compress_certificate `brotli`; status_request OCSP with empty lists;
  signed_certificate_timestamp, extended_master_secret and session_ticket
  empty; renegotiation_info `00`; ec_point_formats `[0]`; ALPS value `h2`.
* key_share: `GREASE (1 byte), <post-quantum hybrid> (1216 bytes), x25519
  (32 bytes)` on desktop targets. supported_groups: `GREASE, <hybrid>,
  x25519, secp256r1, secp384r1`.
* No padding extension (hello is around 1.7 kB).

Differences by version:

| Target | Hybrid group | ALPS codepoint | Signature algorithms | JA4 | Handshake length |
| --- | --- | --- | --- | --- | --- |
| chrome124 | X25519Kyber768Draft00 (6399) | 4469 | 8 (0403 0804 0401 0503 0805 0501 0806 0601) | `t13d1516h2_8daaf6152771_02713d6af862` | 1712..1808 |
| chrome131 | X25519MLKEM768 (11ec) | 4469 | 8 | `t13d1516h2_8daaf6152771_02713d6af862` | 1712..1808 |
| chrome133a, chrome136, chrome142, chrome146 | X25519MLKEM768 | 44cd | 8 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | 1712..1808 |
| chrome150 (chrome) | X25519MLKEM768 | 44cd | 11 (adds `0904 0905 0906` ML-DSA 44/65/87 at the head) | `t13d1516h2_8daaf6152771_806a8c22fdea` | 1718..1814 |
| chrome_android (chrome131_android) | none (x25519 only, 32-byte share) | 4469 | 8 | `t13d1516h2_8daaf6152771_02713d6af862` | 522..586 |

chrome124 and chrome131 have the same JA4 because JA4 does not hash
supported_groups; they differ in the hybrid group id and so in JA3 and the
key_share bytes. chrome133a, chrome136, chrome142 and chrome146 are
TLS-identical in curl_cffi: they differ only in HTTP headers. JA3 is unstable
for every Chrome target because of the permutation.

HTTP/2 (live, for later comparison): SETTINGS `1:65536;2:0;4:6291456;6:262144`,
window update 15663105, pseudo-header order `m,a,s,p`.

## Edge family

Targets: edge101, edge (= edge101).

Edge is a Chrome 101-era profile: same 15 ciphers and GREASE placement, but
no permutation, no ECH, no post-quantum share, and the old ALPS codepoint.

* Fixed order: `GREASE 0000 0017 ff01 000a 000b 0023 0010 0005 000d 0012
  0033 002d 002b 001b 4469 GREASE 0015`.
* supported_groups `GREASE, x25519, secp256r1, secp384r1`; key_share `GREASE
  (1), x25519 (32)`; 8 signature algorithms as Chrome.
* padding 204 bytes, handshake length fixed at 508.
* JA3 stable `cd08e31494f9531f560d64c695473da9`; JA4
  `t13d1516h2_8daaf6152771_e5627efa2ab1`.
* HTTP/2 (live): `1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`.

## Firefox family

Targets: firefox133, firefox135, firefox144, firefox147, firefox (= firefox147).

Shared:

* No GREASE anywhere (ciphers, extensions, groups, versions, key_share).
* 17 ciphers: `1301 1303 1302 c02b c02f cca9 cca8 c02c c030 c00a c009 c013
  c014 009c 009d 002f 0035`. JA4_b `5b57614c22b0`.
* Fixed order: `0000 0017 ff01 000a 000b 0023 0010 0005 0022 0012 0033 002b
  000d 002d 001c 001b fe0d` (17 extensions, SNI first, ECH last).
* supported_groups `X25519MLKEM768, x25519, secp256r1, secp384r1, secp521r1,
  ffdhe2048, ffdhe3072`; key_share `X25519MLKEM768 (1216), x25519 (32),
  secp256r1 (65)`.
* 11 signature algorithms: `0403 0503 0603 0804 0805 0806 0401 0501 0601
  0203 0201`; delegated_credentials `0403 0503 0603 0203`; record_size_limit
  16385 (0x4001); compress_certificate `zlib, brotli, zstd`;
  supported_versions `0304, 0303`; psk_key_exchange_modes `[1]`.
* No padding; handshake length 1824..1888 moves only with the ECH payload.

Differences by version:

| Target | Extensions | JA3 | JA4 |
| --- | --- | --- | --- |
| firefox133 | 16, no signed_certificate_timestamp (0012) | `2d692a4485ca2f5f2b10ecb2d2909ad3` | `t13d1716h2_5b57614c22b0_eeeea6562960` |
| firefox135, firefox144, firefox147 (firefox) | 17 | `6f7889b9fb1a62a9577e685c1fcfa919` | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` |

firefox135, firefox144 and firefox147 are TLS-identical in curl_cffi.

HTTP/2 (live): `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`.

## Safari family

Targets: safari170, safari180, safari184, safari260, safari2601,
safari (= safari2601), safari_ios (= safari260_ios).

Shared:

* 20 ciphers with a leading GREASE, including CBC and 3DES suites:
  `GREASE <three TLS 1.3 suites> c02c c02b cca9 c030 c02f cca8 c00a c009 c014
  c013 009d 009c 0035 002f c008 c012 000a`. JA4_b `a09f3c656075`.
* Fixed order: `GREASE 0000 0017 ff01 000a 000b [0023] 0010 0005 000d 0012
  0033 002d 002b 001b GREASE [0015]`; first GREASE empty, second GREASE
  1-byte body, padding after it when present.
* compress_certificate `zlib` only; psk_key_exchange_modes `[1]`; no ALPS,
  no ECH, no delegated_credentials, no record_size_limit.
* Signature algorithms repeat `0805`: `0403 0804 0401 0503 0805 0805 0501
  0806 0601 0201`.
* supported_groups `GREASE, [X25519MLKEM768], x25519, secp256r1, secp384r1,
  secp521r1`.

Differences by version:

| Target | TLS 1.3 suite order | session_ticket (0023) | supported_versions | Hybrid share | Padding | Sigalgs | Exts | JA3 | JA4 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| safari170 | 1301 1302 1303 | no | GREASE 1.3 1.2 1.1 1.0 | no | 195 (len 508) | 11 (adds 0203 after 0503) | 14 | `773906b0efdefa24a7f2b8eb6985bf37` | `t13d2014h2_a09f3c656075_14788d8d241b` |
| safari180, safari184 | 1301 1302 1303 | no | GREASE 1.3 1.2 1.1 1.0 | no | 197 (len 508) | 10 | 14 | `773906b0efdefa24a7f2b8eb6985bf37` | `t13d2014h2_a09f3c656075_e42f34c56612` |
| safari260 | 1302 1303 1301 | yes | GREASE 1.3 1.2 | X25519MLKEM768 (1216) | none (len 1529) | 10 | 14 | `6618231821d2d40f8d1859f5a43a0307` | `t13d2014h2_a09f3c656075_d0a99439f9b1` |
| safari2601 (safari) | 1302 1303 1301 | no | GREASE 1.3 1.2 | X25519MLKEM768 (1216) | none (len 1525) | 10 | 13 | `ecdf4f49dd59effc439639da29186671` | `t13d2013h2_a09f3c656075_7f0f34a4126d` |
| safari_ios (safari260_ios) | 1301 1302 1303 | yes | GREASE 1.3 1.2 | no | 197 (len 508) | 10 | 15 | `fb3660676bafc9799c86bd51a1ea12f5` | `t13d2015h2_a09f3c656075_c258b721e490` |

Safari 26 moved AES-256-GCM ahead of AES-128-GCM among the TLS 1.3 suites and
dropped the TLS 1.0/1.1 entries from supported_versions. safari170 and
safari18x share a JA3 (JA3 does not see signature algorithms) but not a JA4.
safari180 and safari184 are TLS-identical.

HTTP/2 (live): safari18x/26x `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`
(safari180 adds `8:1`), safari170 `2:0;4:4194304;3:100|10485760|0|m,s,p,a`.

## Tor family

Target: tor145 (Firefox ESR derived).

* 15 ciphers, Firefox's list without `c00a c009`: `1301 1303 1302 c02b c02f
  cca9 cca8 c02c c030 c013 c014 009c 009d 002f 0035`. JA4_b `8daaf6152771`
  (same sorted set as Chrome).
* 13 extensions, fixed order: `0000 0017 ff01 000a 000b 0010 0005 0022 0033
  002b 000d 001c fe0d`. No session_ticket, no signed_certificate_timestamp,
  no psk_key_exchange_modes, no compress_certificate, no GREASE.
* supported_groups `x25519, secp256r1, secp384r1, secp521r1, ffdhe2048,
  ffdhe3072` (no post-quantum); key_share `x25519 (32), secp256r1 (65)`.
* Firefox's 11 signature algorithms, delegated_credentials, record_size_limit
  16385, ECH GREASE last. Handshake length 541..605.
* JA3 stable `0faf2a91198d40dbd58b9308f3fca2fd`; JA4
  `t13d1513h2_8daaf6152771_748f4c70de1c`.
* HTTP/2 (live): same as Firefox.

## What a byte-faithful reimplementation needs

* Full control of the ClientHello: cipher order, extension order and
  per-extension bodies, GREASE injection in five places, supported_versions
  with GREASE, a 1-byte GREASE key_share, and the ECH GREASE extension. The
  standard library `ssl` module cannot do any of this.
* A 1216-byte X25519MLKEM768 share (1184-byte ML-KEM-768 encapsulation key
  followed by a 32-byte X25519 public key) for every desktop Chrome, Firefox
  and Safari 26 target; chrome124 needs the 1216-byte X25519Kyber768Draft00
  layout instead. chrome_android, edge, safari 17/18, safari_ios and tor use
  classical shares only.
* Chrome: shuffle the 16 real extensions per connection between the fixed
  first and last GREASE; keep the last GREASE body at 1 byte.
* Edge and Safari 17/18/iOS: pad the handshake to 512 bytes.
* Firefox and Tor: no GREASE at all, SNI first, ECH last, record_size_limit
  and delegated_credentials present.

## Template file layout

Each `<target>.json` holds: `cipher_suites` (GREASE as the literal string
`"GREASE"`), `extensions` in a representative order with decoded `params`,
`position` (`fixed` or `permuted`) and `body_hex` where the body never
changes, `extension_fixed_prefix` / `extension_fixed_suffix`,
`extension_orders_seen`, `supported_groups`, `signature_algorithms`,
`key_share` (group and key length), `supported_versions`,
`psk_key_exchange_modes`, `compress_certificate`, `alpn`, `alps`,
`record_size_limit`, `delegated_credentials`, `padding_length`, `ech`,
`variable_fields`, `fixed_fields`, `fingerprints` (ja3, ja3_hash,
ja3_hashes_seen, ja4, ja4_r, ja4_o, ja4_ro), `handshake_length`,
`total_bytes`, `record_version`, per-run `captures`, and `peet_live`.
