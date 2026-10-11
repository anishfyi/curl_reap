"""Offline TLS ClientHello and HTTP/2 fingerprint calculators for curl_reap 2.0.

The ClientHello parser and the JA3/JA4 algorithms are the verified
implementation from ``tools/fingerprint_calc.py`` (the capture-time oracle
that cross-checked every template against a live TLS echo), copied here with
attribution because ``tools/`` is not an installable package.  The only
change is stricter framing validation: a truncated buffer raises
:class:`ParseError` (a ``ValueError``) instead of silently parsing a partial
hello.

On top of the parser this module provides:

* :func:`ja3`, :func:`ja4`, :func:`ja4_r`, :func:`peetprint` - the TLS
  fingerprint calculators, pure functions of a parsed hello.
* :func:`akamai_from_frames` - the HTTP/2 fingerprint string
  (``SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo``) from the frames a client
  sent after the connection preface.
* :data:`EXPECTED` - the expected values per target, generated once from the
  captured browser hellos and HTTP/2 connections in ``tools/hello_templates``
  and ``tools/h2_templates`` and baked in so an installed wheel carries them.
* :func:`check` - the live parity probe behind ``reap doctor``: fetch a
  fingerprint echo and report every observed value against :data:`EXPECTED`.

The calculators prove that the bytes the engine sends match the captured
browser bytes: rendering every template through ``curl_reap._tls`` and
re-parsing it with :func:`parse_client_hello` reproduces the recorded
JA4/JA4R/peetprint, and replaying the captured HTTP/2 preface frames through
:func:`akamai_from_frames` reproduces the recorded Akamai string.

This module imports nothing from the rest of the package at import time (the
HTTP client is imported lazily inside :func:`check` because it is being
rewritten concurrently); only the standard library is needed for the
calculators, and the ``hpack`` decoder is imported lazily by
:func:`akamai_from_frames`.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict, Iterable, List, Optional, Tuple

__all__ = [
    "GREASE_VALUES",
    "EXTENSION_NAMES",
    "ParseError",
    "is_grease",
    "split_records",
    "parse_client_hello",
    "ja3",
    "ja4",
    "ja4_r",
    "peetprint",
    "akamai_from_frames",
    "check",
    "EXPECTED",
]

# RFC 8701: 0x0a0a, 0x1a1a, ..., 0xfafa.
GREASE_VALUES = frozenset(((0x10 * i + 0x0A) << 8) | (0x10 * i + 0x0A) for i in range(16))

EXTENSION_NAMES: Dict[int, str] = {
    0: "server_name",
    1: "max_fragment_length",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "application_layer_protocol_negotiation",
    17: "status_request_v2",
    18: "signed_certificate_timestamp",
    21: "padding",
    23: "extended_master_secret",
    27: "compress_certificate",
    28: "record_size_limit",
    34: "delegated_credentials",
    35: "session_ticket",
    41: "pre_shared_key",
    42: "early_data",
    43: "supported_versions",
    44: "cookie",
    45: "psk_key_exchange_modes",
    49: "post_handshake_auth",
    50: "signature_algorithms_cert",
    51: "key_share",
    13172: "next_protocol_negotiation",
    17513: "application_settings_old",
    17613: "application_settings",
    0xFE0D: "encrypted_client_hello",
    0xFF01: "renegotiation_info",
}

GROUP_NAMES: Dict[int, str] = {
    23: "secp256r1",
    24: "secp384r1",
    25: "secp521r1",
    29: "x25519",
    30: "x448",
    256: "ffdhe2048",
    257: "ffdhe3072",
    258: "ffdhe4096",
    259: "ffdhe6144",
    260: "ffdhe8192",
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00",
}

SIGALG_NAMES: Dict[int, str] = {
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256",
    0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512",
    0x0201: "rsa_pkcs1_sha1",
    0x0203: "ecdsa_sha1",
    0x0202: "dsa_sha1",
    0x0301: "rsa_pkcs1_sha224",
    0x0303: "ecdsa_sha224",
    0x0904: "mldsa44",
    0x0905: "mldsa65",
    0x0906: "mldsa87",
}

CIPHER_NAMES: Dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
    0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
    0xC013: "ECDHE-RSA-AES128-SHA",
    0xC014: "ECDHE-RSA-AES256-SHA",
    0xC009: "ECDHE-ECDSA-AES128-SHA",
    0xC00A: "ECDHE-ECDSA-AES256-SHA",
    0xC023: "ECDHE-ECDSA-AES128-SHA256",
    0xC024: "ECDHE-ECDSA-AES256-SHA384",
    0xC027: "ECDHE-RSA-AES128-SHA256",
    0xC028: "ECDHE-RSA-AES256-SHA384",
    0x009C: "AES128-GCM-SHA256",
    0x009D: "AES256-GCM-SHA384",
    0x002F: "AES128-SHA",
    0x0035: "AES256-SHA",
    0x003C: "AES128-SHA256",
    0x003D: "AES256-SHA256",
    0x000A: "DES-CBC3-SHA",
    0x0033: "DHE-RSA-AES128-SHA",
    0x0039: "DHE-RSA-AES256-SHA",
    0x009E: "DHE-RSA-AES128-GCM-SHA256",
    0x009F: "DHE-RSA-AES256-GCM-SHA384",
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x5600: "TLS_FALLBACK_SCSV",
}

VERSION_NAMES: Dict[int, str] = {
    0x0304: "TLS 1.3",
    0x0303: "TLS 1.2",
    0x0302: "TLS 1.1",
    0x0301: "TLS 1.0",
    0x0300: "SSL 3.0",
}

CERT_COMPRESSION_NAMES = {1: "zlib", 2: "brotli", 3: "zstd"}
PSK_MODE_NAMES = {0: "psk_ke", 1: "psk_dhe_ke"}
POINT_FORMAT_NAMES = {0: "uncompressed", 1: "ansiX962_compressed_prime", 2: "ansiX962_compressed_char2"}
HPKE_KDF_NAMES = {0x0001: "HKDF-SHA256", 0x0002: "HKDF-SHA384", 0x0003: "HKDF-SHA512"}
HPKE_AEAD_NAMES = {0x0001: "AES-128-GCM", 0x0002: "AES-256-GCM", 0x0003: "ChaCha20Poly1305"}


class ParseError(ValueError):
    """Raised when the bytes do not form a well-framed ClientHello."""


def is_grease(value: int) -> bool:
    return value in GREASE_VALUES


def _hex2(value: int) -> str:
    return "%04x" % value


def _u8(buf: bytes, off: int) -> int:
    if off + 1 > len(buf):
        raise ParseError("truncated u8 at offset %d" % off)
    return buf[off]


def _u16(buf: bytes, off: int) -> int:
    if off + 2 > len(buf):
        raise ParseError("truncated u16 at offset %d" % off)
    return struct.unpack_from("!H", buf, off)[0]


def _u24(buf: bytes, off: int) -> int:
    if off + 3 > len(buf):
        raise ParseError("truncated u24 at offset %d" % off)
    return (buf[off] << 16) | (buf[off + 1] << 8) | buf[off + 2]


def _u16_list(body: bytes) -> List[int]:
    """Parse ``uint16 list<2..2^16-2>`` (2-byte length, 2-byte items)."""
    if len(body) < 2:
        return []
    n = _u16(body, 0)
    data = body[2:2 + n]
    return [struct.unpack_from("!H", data, i)[0] for i in range(0, len(data) - len(data) % 2, 2)]


def _u8_list(body: bytes) -> List[int]:
    """Parse ``uint8 list<1..2^8-1>`` (1-byte length, 1-byte items)."""
    if not body:
        return []
    n = body[0]
    return list(body[1:1 + n])


def _u16_list_u8len(body: bytes) -> List[int]:
    """Parse a 1-byte length prefix followed by 2-byte items (compress_certificate, supported_versions)."""
    if not body:
        return []
    n = body[0]
    data = body[1:1 + n]
    return [struct.unpack_from("!H", data, i)[0] for i in range(0, len(data) - len(data) % 2, 2)]


def _string_list(body: bytes) -> List[str]:
    """Parse ``opaque name<1..2^8-1> list<2..2^16-1>`` (ALPN and ALPS share this shape)."""
    out: List[str] = []
    if len(body) < 2:
        return out
    n = _u16(body, 0)
    data = body[2:2 + n]
    i = 0
    while i < len(data):
        ln = data[i]
        out.append(data[i + 1:i + 1 + ln].decode("latin-1"))
        i += 1 + ln
    return out


def _tag(value: int, names: Dict[int, str]) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"id": _hex2(value), "decimal": value}
    if is_grease(value):
        entry["name"] = "GREASE"
        entry["grease"] = True
    elif value in names:
        entry["name"] = names[value]
    return entry


# --------------------------------------------------------------------------
# Extension body decoders
# --------------------------------------------------------------------------

def _decode_server_name(body: bytes) -> Dict[str, Any]:
    names = []
    if len(body) >= 2:
        n = _u16(body, 0)
        data = body[2:2 + n]
        i = 0
        while i + 3 <= len(data):
            name_type = data[i]
            ln = _u16(data, i + 1)
            names.append({"name_type": name_type, "host_name": data[i + 3:i + 3 + ln].decode("latin-1")})
            i += 3 + ln
    return {"server_name_list": names}


def _decode_status_request(body: bytes) -> Dict[str, Any]:
    if not body:
        return {}
    out: Dict[str, Any] = {"status_type": body[0], "status_type_name": {1: "ocsp"}.get(body[0])}
    if len(body) >= 3:
        out["responder_id_list_len"] = _u16(body, 1)
    if len(body) >= 5:
        out["request_extensions_len"] = _u16(body, 3)
    return out


def _decode_supported_groups(body: bytes) -> Dict[str, Any]:
    return {"groups": [_tag(v, GROUP_NAMES) for v in _u16_list(body)]}


def _decode_ec_point_formats(body: bytes) -> Dict[str, Any]:
    return {"formats": [{"id": v, "name": POINT_FORMAT_NAMES.get(v)} for v in _u8_list(body)]}


def _decode_signature_algorithms(body: bytes) -> Dict[str, Any]:
    return {"algorithms": [_tag(v, SIGALG_NAMES) for v in _u16_list(body)]}


def _decode_alpn(body: bytes) -> Dict[str, Any]:
    return {"protocols": _string_list(body)}


def _decode_padding(body: bytes) -> Dict[str, Any]:
    return {"length": len(body), "all_zero": not any(body)}


def _decode_compress_certificate(body: bytes) -> Dict[str, Any]:
    return {"algorithms": [{"id": v, "name": CERT_COMPRESSION_NAMES.get(v)} for v in _u16_list_u8len(body)]}


def _decode_record_size_limit(body: bytes) -> Dict[str, Any]:
    return {"limit": _u16(body, 0) if len(body) >= 2 else None}


def _decode_delegated_credentials(body: bytes) -> Dict[str, Any]:
    return {"algorithms": [_tag(v, SIGALG_NAMES) for v in _u16_list(body)]}


def _decode_session_ticket(body: bytes) -> Dict[str, Any]:
    return {"ticket_len": len(body)}


def _decode_pre_shared_key(body: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"identities": [], "binders": []}
    if len(body) < 2:
        return out
    n = _u16(body, 0)
    ids = body[2:2 + n]
    i = 0
    while i + 6 <= len(ids):
        ln = _u16(ids, i)
        ident = ids[i + 2:i + 2 + ln]
        age = struct.unpack_from("!I", ids, i + 2 + ln)[0] if i + 6 + ln <= len(ids) else None
        out["identities"].append({"identity_len": ln, "obfuscated_ticket_age": age})
        i += 2 + ln + 4
    off = 2 + n
    if off + 2 <= len(body):
        bn = _u16(body, off)
        bd = body[off + 2:off + 2 + bn]
        j = 0
        while j < len(bd):
            bl = bd[j]
            out["binders"].append({"binder_len": bl})
            j += 1 + bl
    return out


def _decode_supported_versions(body: bytes) -> Dict[str, Any]:
    return {"versions": [_tag(v, VERSION_NAMES) for v in _u16_list_u8len(body)]}


def _decode_psk_key_exchange_modes(body: bytes) -> Dict[str, Any]:
    return {"modes": [{"id": v, "name": PSK_MODE_NAMES.get(v)} for v in _u8_list(body)]}


def _decode_key_share(body: bytes) -> Dict[str, Any]:
    shares = []
    if len(body) >= 2:
        n = _u16(body, 0)
        data = body[2:2 + n]
        i = 0
        while i + 4 <= len(data):
            group = _u16(data, i)
            ln = _u16(data, i + 2)
            entry = _tag(group, GROUP_NAMES)
            entry["key_length"] = ln
            shares.append(entry)
            i += 4 + ln
    return {"shares": shares}


def _decode_application_settings(body: bytes) -> Dict[str, Any]:
    return {"protocols": _string_list(body)}


def _decode_ech(body: bytes) -> Dict[str, Any]:
    if not body:
        return {}
    kind = body[0]
    out: Dict[str, Any] = {"type": kind, "type_name": {0: "outer", 1: "inner"}.get(kind)}
    if kind != 0 or len(body) < 1 + 2 + 2 + 1 + 2:
        return out
    kdf = _u16(body, 1)
    aead = _u16(body, 3)
    out["kdf_id"] = _hex2(kdf)
    out["kdf_name"] = HPKE_KDF_NAMES.get(kdf)
    out["aead_id"] = _hex2(aead)
    out["aead_name"] = HPKE_AEAD_NAMES.get(aead)
    out["config_id"] = body[5]
    enc_len = _u16(body, 6)
    out["enc_len"] = enc_len
    off = 8 + enc_len
    if off + 2 <= len(body):
        out["payload_len"] = _u16(body, off)
    return out


def _decode_renegotiation_info(body: bytes) -> Dict[str, Any]:
    return {"renegotiated_connection_len": body[0] if body else None}


def _decode_empty(body: bytes) -> Dict[str, Any]:
    return {"length": len(body)}


_DECODERS = {
    0: _decode_server_name,
    5: _decode_status_request,
    10: _decode_supported_groups,
    11: _decode_ec_point_formats,
    13: _decode_signature_algorithms,
    16: _decode_alpn,
    18: _decode_empty,
    21: _decode_padding,
    23: _decode_empty,
    27: _decode_compress_certificate,
    28: _decode_record_size_limit,
    34: _decode_delegated_credentials,
    35: _decode_session_ticket,
    41: _decode_pre_shared_key,
    43: _decode_supported_versions,
    45: _decode_psk_key_exchange_modes,
    50: _decode_signature_algorithms,
    51: _decode_key_share,
    17513: _decode_application_settings,
    17613: _decode_application_settings,
    0xFE0D: _decode_ech,
    0xFF01: _decode_renegotiation_info,
}


# --------------------------------------------------------------------------
# ClientHello parser
# --------------------------------------------------------------------------

def split_records(data: bytes) -> List[Dict[str, Any]]:
    """Split a TLS byte stream into records (type, version, payload)."""
    records = []
    off = 0
    while off + 5 <= len(data):
        ctype = data[off]
        version = _u16(data, off + 1)
        length = _u16(data, off + 3)
        payload = data[off + 5:off + 5 + length]
        records.append({
            "content_type": ctype,
            "version": _hex2(version),
            "length": length,
            "complete": len(payload) == length,
            "payload": payload,
        })
        off += 5 + length
    return records


def parse_client_hello(data: bytes) -> Dict[str, Any]:
    """Parse the first ClientHello in ``data`` (raw bytes from the wire).

    ``data`` may contain the TLS record layer (content type 22) or a bare
    handshake message starting with 0x01.  Handshake fragments spanning
    several records are reassembled.  Anything truncated raises
    :class:`ParseError` (a ``ValueError``): a handshake that is shorter than
    its length field says, an extensions block that overruns the handshake
    body, or an extension that overruns the extensions block.
    """
    if not data:
        raise ParseError("empty input")
    records: List[Dict[str, Any]] = []
    if data[0] == 22:
        records = split_records(data)
        if not records:
            raise ParseError("no TLS records")
        hs = b"".join(r["payload"] for r in records if r["content_type"] == 22)
        record_version = records[0]["version"]
        if not hs:
            raise ParseError("no handshake data in the TLS records")
    elif data[0] == 1:
        hs = data
        record_version = None
    else:
        raise ParseError("not a TLS handshake record (first byte %02x)" % data[0])

    if _u8(hs, 0) != 1:
        raise ParseError("handshake type %d is not ClientHello" % hs[0])
    hs_len = _u24(hs, 1)
    body = hs[4:4 + hs_len]
    if len(body) != hs_len:
        raise ParseError("ClientHello truncated: have %d of %d bytes" % (len(body), hs_len))

    off = 0
    legacy_version = _u16(body, off)
    off += 2
    random = body[off:off + 32]
    off += 32
    sid_len = _u8(body, off)
    off += 1
    session_id = body[off:off + sid_len]
    off += sid_len
    cs_len = _u16(body, off)
    off += 2
    cs_raw = body[off:off + cs_len]
    off += cs_len
    cipher_suites = [struct.unpack_from("!H", cs_raw, i)[0] for i in range(0, cs_len - cs_len % 2, 2)]
    cm_len = _u8(body, off)
    off += 1
    compression_methods = list(body[off:off + cm_len])
    off += cm_len

    extensions: List[Dict[str, Any]] = []
    ext_total = 0
    if off + 2 <= len(body):
        ext_total = _u16(body, off)
        off += 2
        ext_end = off + ext_total
        if ext_end > len(body):
            raise ParseError("extensions block of %d bytes overruns the %d byte body"
                             % (ext_total, len(body)))
        while off + 4 <= ext_end:
            etype = _u16(body, off)
            elen = _u16(body, off + 2)
            if off + 4 + elen > ext_end:
                raise ParseError("extension %s of %d bytes overruns the extensions block"
                                 % (_hex2(etype), elen))
            ebody = body[off + 4:off + 4 + elen]
            off += 4 + elen
            entry: Dict[str, Any] = {
                "type": etype,
                "type_hex": _hex2(etype),
                "name": "GREASE" if is_grease(etype) else EXTENSION_NAMES.get(etype, "unknown_%d" % etype),
                "grease": is_grease(etype),
                "length": elen,
                "body_hex": ebody.hex(),
            }
            decoder = _DECODERS.get(etype)
            if decoder is not None:
                try:
                    entry["decoded"] = decoder(ebody)
                except ParseError as exc:
                    entry["decode_error"] = str(exc)
            extensions.append(entry)
        if off != ext_end:
            raise ParseError("extensions block of %d bytes ends %d bytes early"
                             % (ext_total, ext_end - off))

    return {
        "record_version": record_version,
        "records": [
            {k: v for k, v in r.items() if k != "payload"} for r in records
        ],
        "total_bytes": len(data),
        "handshake_length": hs_len,
        "legacy_version": _hex2(legacy_version),
        "legacy_version_name": VERSION_NAMES.get(legacy_version),
        "random": random.hex(),
        "session_id": session_id.hex(),
        "session_id_len": sid_len,
        "cipher_suites": [_tag(c, CIPHER_NAMES) for c in cipher_suites],
        "compression_methods": compression_methods,
        "extensions_length": ext_total,
        "extensions": extensions,
    }


# --------------------------------------------------------------------------
# Fingerprint helpers
# --------------------------------------------------------------------------

def _ext_by_type(hello: Dict[str, Any], etype: int) -> Optional[Dict[str, Any]]:
    for ext in hello["extensions"]:
        if ext["type"] == etype:
            return ext
    return None


def _cipher_ids(hello: Dict[str, Any]) -> List[int]:
    return [c["decimal"] for c in hello["cipher_suites"] if not is_grease(c["decimal"])]


def _ext_ids(hello: Dict[str, Any]) -> List[int]:
    return [e["type"] for e in hello["extensions"] if not e["grease"]]


def _groups(hello: Dict[str, Any]) -> List[int]:
    ext = _ext_by_type(hello, 10)
    if not ext or "decoded" not in ext:
        return []
    return [g["decimal"] for g in ext["decoded"]["groups"] if not is_grease(g["decimal"])]


def _point_formats(hello: Dict[str, Any]) -> List[int]:
    ext = _ext_by_type(hello, 11)
    if not ext or "decoded" not in ext:
        return []
    return [f["id"] for f in ext["decoded"]["formats"]]


def _sigalgs(hello: Dict[str, Any]) -> List[int]:
    ext = _ext_by_type(hello, 13)
    if not ext or "decoded" not in ext:
        return []
    return [a["decimal"] for a in ext["decoded"]["algorithms"] if not is_grease(a["decimal"])]


def ja3(parsed: Dict[str, Any]) -> Tuple[str, str]:
    """Return ``(ja3_string, ja3_md5)`` for a parsed hello.

    GREASE values are removed and every field is decimal, dash separated
    inside each field, comma separated between fields.  A client that
    permutes its extensions per connection (the Chromium family) has a JA3
    that changes with every hello, which is why :data:`EXPECTED` records
    whether a target's JA3 is comparable at all.
    """
    version = int(parsed["legacy_version"], 16)
    text = ",".join([
        str(version),
        "-".join(str(c) for c in _cipher_ids(parsed)),
        "-".join(str(e) for e in _ext_ids(parsed)),
        "-".join(str(g) for g in _groups(parsed)),
        "-".join(str(p) for p in _point_formats(parsed)),
    ])
    return text, hashlib.md5(text.encode()).hexdigest()


def _ja4_version(parsed: Dict[str, Any]) -> str:
    sv = _ext_by_type(parsed, 43)
    candidates: List[int] = []
    if sv and "decoded" in sv:
        candidates = [v["decimal"] for v in sv["decoded"]["versions"] if not is_grease(v["decimal"])]
    version = max(candidates) if candidates else int(parsed["legacy_version"], 16)
    return {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
        0x0002: "s2",
        0x0100: "s1",
    }.get(version, "00")


def _alpn_chars(protocol: str) -> str:
    """First and last character of an ALPN protocol, per the JA4 spec.

    Printable alphanumeric endpoints give the two characters; anything else
    falls back to the first and last hex digit, and an empty protocol is
    ``00``.
    """
    if not protocol:
        return "00"
    raw = protocol.encode("latin-1")
    if all(32 < b < 127 and chr(b).isalnum() for b in (raw[0], raw[-1])):
        return protocol[0] + protocol[-1]
    h = raw.hex()
    return h[0] + h[-1]


def _ja4_alpn(parsed: Dict[str, Any], alpn: Optional[str]) -> str:
    if alpn:
        return _alpn_chars(alpn)
    ext = _ext_by_type(parsed, 16)
    if not ext or "decoded" not in ext or not ext["decoded"]["protocols"]:
        return "00"
    return _alpn_chars(ext["decoded"]["protocols"][0])


def _sha12(text: str) -> str:
    if not text:
        return "000000000000"
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def _ja4_sorted_parts(parsed: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """``(a_part, sorted_ciphers, sorted_extensions, signature_algorithms)``.

    The extensions part excludes server_name (0) and ALPN (16) and carries
    the signature algorithms after an underscore, exactly as the capture-time
    oracle computed them.
    """
    ciphers = _cipher_ids(parsed)
    exts_all = _ext_ids(parsed)
    sigalgs = _sigalgs(parsed)
    sni = "d" if _ext_by_type(parsed, 0) is not None else "i"
    a_part = "%s%s%s%02d%02d" % (
        "t",
        _ja4_version(parsed),
        sni,
        min(len(ciphers), 99),
        min(len(exts_all), 99),
    )
    ciphers_sorted = ",".join(_hex2(c) for c in sorted(ciphers))
    exts_sorted = ",".join(_hex2(e) for e in sorted(e for e in exts_all if e not in (0, 16)))
    sig_text = ",".join(_hex2(s) for s in sigalgs)
    return a_part, ciphers_sorted, exts_sorted, sig_text


def _ja4_c_part(ext_text: str, sig_text: str) -> str:
    if not ext_text:
        return ""
    return ext_text + ("_" + sig_text if sig_text else "")


def ja4(parsed: Dict[str, Any], alpn: str = "h2") -> str:
    """JA4 (hashed) for a parsed hello: ``t13d1516h2_<12>_<12>``.

    ``alpn`` is the protocol whose first and last character form the final
    two characters of part A; the default ``'h2'`` is what every built-in
    target offers first.  Pass ``None`` to derive it from the parsed hello's
    ALPN extension instead (the JA4 specification's rule for a capture).
    """
    a, ciphers_sorted, exts_sorted, sig_text = _ja4_sorted_parts(parsed)
    a = a + _ja4_alpn(parsed, alpn)
    return "%s_%s_%s" % (a, _sha12(ciphers_sorted), _sha12(_ja4_c_part(exts_sorted, sig_text)))


def ja4_r(parsed: Dict[str, Any]) -> str:
    """JA4 raw: the unhashed cipher and extension lists in sorted order.

    Part A always derives its ALPN characters from the parsed hello, so
    ``ja4_r`` of a capture describes exactly the bytes that were sent.
    """
    a, ciphers_sorted, exts_sorted, sig_text = _ja4_sorted_parts(parsed)
    a = a + _ja4_alpn(parsed, None)
    return "%s_%s_%s" % (a, ciphers_sorted, _ja4_c_part(exts_sorted, sig_text))


def _peet_alpn_short(protocol: str) -> str:
    """Shorten an ALPN protocol the way the echo service's peetprint does.

    ``h2`` becomes ``2`` and ``http/1.1`` becomes ``1.1``: take the part
    after the last ``/`` and drop a leading ``h``.
    """
    name = protocol.rsplit("/", 1)[-1]
    if name.startswith("h") and len(name) > 1:
        return name[1:]
    return name


def peetprint(parsed: Dict[str, Any]) -> str:
    """The peetprint string for a parsed hello (eight ``|`` separated parts).

    ``versions|alpn|groups|signature_algorithms|psk_modes|certificate_compression|ciphers|extensions``
    with GREASE kept, values in decimal and lists dash separated in wire
    order - except the extension list, which the echo service prints sorted
    as strings (``"45"`` before ``"5"``), so it does not move when a client
    permutes its extensions per connection.
    """
    versions: List[int] = []
    sv = _ext_by_type(parsed, 43)
    if sv and "decoded" in sv:
        versions = [v["decimal"] for v in sv["decoded"]["versions"]]
    if not versions:
        versions = [int(parsed["legacy_version"], 16)]
    version_part = "-".join("GREASE" if is_grease(v) else str(v) for v in versions)

    alpn_ext = _ext_by_type(parsed, 16)
    protocols = alpn_ext["decoded"]["protocols"] if alpn_ext and "decoded" in alpn_ext else []
    alpn_part = "-".join(_peet_alpn_short(p) for p in protocols)

    group_ext = _ext_by_type(parsed, 10)
    if group_ext and "decoded" in group_ext:
        groups = [g["decimal"] for g in group_ext["decoded"]["groups"]]
    else:
        groups = []
    group_part = "-".join("GREASE" if is_grease(g) else str(g) for g in groups)

    sig_part = "-".join(str(s) for s in _sigalgs(parsed))

    psk_ext = _ext_by_type(parsed, 45)
    modes = [m["id"] for m in psk_ext["decoded"]["modes"]] if psk_ext and "decoded" in psk_ext else []
    # The echo prints 0 for a missing psk_key_exchange_modes extension (the
    # only captured target without one, the Tor Browser template, shows 0)
    # but an empty list for missing certificate compression.
    psk_part = "-".join(str(m) for m in modes) if modes or psk_ext else "0"

    comp_ext = _ext_by_type(parsed, 27)
    if comp_ext and "decoded" in comp_ext:
        algs = [a["id"] for a in comp_ext["decoded"]["algorithms"]]
    else:
        algs = []
    comp_part = "-".join(str(a) for a in algs)

    cipher_part = "-".join("GREASE" if is_grease(c["decimal"]) else str(c["decimal"])
                           for c in parsed["cipher_suites"])

    ext_names = ["GREASE" if e["grease"] else str(e["type"]) for e in parsed["extensions"]]
    ext_part = "-".join(sorted(ext_names))

    return "|".join([version_part, alpn_part, group_part, sig_part,
                     psk_part, comp_part, cipher_part, ext_part])


# --------------------------------------------------------------------------
# HTTP/2 (Akamai) fingerprint
# --------------------------------------------------------------------------

#: HTTP/2 frame types the Akamai fingerprint is built from (RFC 9113 section 6).
_H2_HEADERS = 0x1
_H2_PRIORITY = 0x2
_H2_SETTINGS = 0x4
_H2_WINDOW_UPDATE = 0x8
_H2_CONTINUATION = 0x9
_FLAG_PADDED = 0x8
_FLAG_PRIORITY = 0x20

#: Pseudo header name to Akamai fingerprint letter.
_PSEUDO_LETTERS = {":method": "m", ":authority": "a", ":scheme": "s", ":path": "p"}


def _frame_parts(item: Any) -> Tuple[int, Optional[int], Optional[int], bytes]:
    """Normalise one input frame to ``(type, flags, stream_id, payload)``.

    :func:`akamai_from_frames` accepts ``(type, payload)`` pairs (the frame
    header is not needed for the SETTINGS and WINDOW_UPDATE parts) and
    full frames as ``(type, flags, stream_id, payload)`` tuples, which is
    the shape ``curl_reap._h2`` frames already have.
    """
    if isinstance(item, (bytes, bytearray)):
        raise TypeError("frames must be (type, payload) pairs or frame tuples, not raw bytes")
    fields = tuple(item)
    if len(fields) == 2:
        ftype, payload = fields
        return int(ftype), None, None, bytes(payload)
    if len(fields) == 4:
        ftype, flags, stream_id, payload = fields
        return int(ftype), int(flags), int(stream_id), bytes(payload)
    raise TypeError("frame must be (type, payload) or (type, flags, stream_id, payload), got %d fields"
                    % len(fields))


def _pseudo_order(block: bytes, priority_offset: Optional[int]) -> str:
    """The pseudo header letters (``masp``) of the first HEADERS block.

    ``priority_offset`` is the number of bytes the PRIORITY field occupies
    before the HPACK block when the flags are known; when it is ``None``
    (a ``(type, payload)`` input) both 0 and 5 are tried and the candidate
    whose first decoded field is a pseudo header wins.
    """
    from hpack import Decoder

    candidates = [priority_offset] if priority_offset is not None else [0, 5]
    last_error: Optional[Exception] = None
    for off in candidates:
        try:
            headers = Decoder().decode(block[off:])
        except Exception as exc:  # hpack raises its own decoding errors
            last_error = exc
            continue
        letters = []
        for name, _value in headers:
            if not name.startswith(":"):
                continue
            if name not in _PSEUDO_LETTERS:
                raise ValueError("unknown pseudo header %r in the first HEADERS frame" % name)
            letters.append(_PSEUDO_LETTERS[name])
        if letters:
            return "".join(letters)
        last_error = ValueError("no pseudo headers in the decoded HEADERS block")
    raise ValueError("could not decode the first HEADERS frame (offsets tried %r): %s"
                     % (candidates, last_error))


def akamai_from_frames(frames: Iterable[Any]) -> str:
    """The Akamai HTTP/2 fingerprint of the frames sent after the preface.

    ``frames`` is an iterable of ``(type, payload)`` pairs - or
    ``(type, flags, stream_id, payload)`` frame tuples as produced by
    ``curl_reap._h2`` - covering the connection preface: the first SETTINGS,
    the stream 0 WINDOW_UPDATE, any PRIORITY frames and the first HEADERS
    frame (with its CONTINUATIONs).  The result is
    ``SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo`` such as
    ``1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p``.

    SETTINGS values keep wire order; the WINDOW_UPDATE is the connection
    increment; the PRIORITY part lists ``stream:exclusive:dependency:weight``
    (``0`` when none were sent - a ``(type, payload)`` PRIORITY frame
    without its stream id is rejected); the pseudo part is the first
    HEADERS frame's pseudo header order.  Frames after the first HEADERS
    frame are ignored, so the whole client byte stream can be passed.
    """
    settings: Optional[List[Tuple[int, int]]] = None
    window_update: Optional[int] = None
    priority_frames: List[Tuple[int, int, int, int]] = []
    block: Optional[bytes] = None
    block_priority_offset: Optional[int] = None

    for item in frames:
        ftype, flags, stream_id, payload = _frame_parts(item)
        if ftype == _H2_HEADERS:
            if block is not None:
                break  # only the first HEADERS frame matters
            block = bytes(payload)
            block_priority_offset = None
            if flags is not None:
                if flags & _FLAG_PADDED:
                    if not payload:
                        raise ValueError("PADDED HEADERS frame without a pad length")
                    pad = payload[0]
                    if pad >= len(payload):
                        raise ValueError("HEADERS padding of %d bytes exceeds the %d byte payload"
                                         % (pad, len(payload)))
                    block = bytes(payload[1:len(payload) - pad])
                block_priority_offset = 5 if flags & _FLAG_PRIORITY else 0
            continue
        if ftype == _H2_CONTINUATION:
            if block is not None:
                block += bytes(payload)
                continue
            raise ValueError("CONTINUATION frame before any HEADERS frame")
        if block is not None:
            break  # the first header block is complete
        if ftype == _H2_SETTINGS:
            if not payload or settings is not None:
                continue  # a SETTINGS ACK, or a second SETTINGS we do not use
            if len(payload) % 6:
                raise ValueError("SETTINGS payload of %d bytes is not a multiple of 6" % len(payload))
            settings = [struct.unpack_from(">HI", payload, i) for i in range(0, len(payload), 6)]
        elif ftype == _H2_WINDOW_UPDATE:
            if len(payload) != 4:
                raise ValueError("WINDOW_UPDATE payload must be 4 bytes, got %d" % len(payload))
            if window_update is None and (stream_id is None or stream_id == 0):
                window_update = struct.unpack("!I", payload)[0]
        elif ftype == _H2_PRIORITY:
            if len(payload) != 5:
                raise ValueError("PRIORITY payload must be 5 bytes, got %d" % len(payload))
            if stream_id is None:
                raise ValueError("a PRIORITY frame needs its stream id; pass "
                                 "(type, flags, stream_id, payload) frame tuples")
            dep = struct.unpack_from("!I", payload)[0]
            priority_frames.append((stream_id, dep >> 31, dep & 0x7FFFFFFF, payload[4] + 1))

    if block is None:
        raise ValueError("no HEADERS frame in the captured frames; the Akamai "
                         "fingerprint needs the first request")
    pseudo = ",".join(_pseudo_order(block, block_priority_offset))
    settings_part = ";".join("%d:%d" % (i, v) for i, v in (settings or []))
    priority_part = ",".join("%d:%d:%d:%d" % (s, e, d, w) for s, e, d, w in priority_frames) or "0"
    return "%s|%d|%s|%s" % (settings_part, window_update or 0, priority_part, pseudo)


# --------------------------------------------------------------------------
# Live check (``reap doctor``)
# --------------------------------------------------------------------------

def _sent_header_names(payload: Dict[str, Any]) -> List[str]:
    """The request header names in order as the echo service saw them."""
    for frame in payload.get("http2", {}).get("sent_frames") or []:
        if frame.get("frame_type") == "HEADERS" and frame.get("headers"):
            names = []
            for line in frame["headers"]:
                if line.startswith(":"):  # pseudo header: ':method: GET'
                    names.append(":" + line[1:].split(":", 1)[0])
                else:
                    names.append(line.split(":", 1)[0])
            return names
    return list(payload.get("header_order") or [])


def check(target: str = "chrome", url: str = "https://tls.peet.ws/api/all",
          session: Any = None) -> Dict[str, Any]:
    """Fetch a fingerprint echo for ``target`` and report observed vs expected.

    Returns a dict with ``target``, ``ja3``, ``ja4``, ``peetprint``,
    ``akamai``, ``expected`` (this target's :data:`EXPECTED` entry),
    ``matches`` (``ja4``/``ja4_r``/``akamai`` booleans; ``ja3`` is a boolean
    only when the target's JA3 is stable, else ``None``), ``headers`` (the
    request header names in order) and ``http_version``.

    The HTTP client is imported lazily because it is being rewritten; a
    caller that passes ``session`` (anything with ``get(url)`` returning an
    object with ``json()``) needs no import at all.
    """
    try:
        expected = EXPECTED[target]
    except KeyError:
        raise KeyError("unknown fingerprint target %r; known targets: %s"
                       % (target, ", ".join(sorted(EXPECTED)))) from None
    if session is None:
        from curl_reap import http  # lazy: the HTTP client is owned by another module
        session = http.Session()
    response = session.get(url)
    payload = response.json()
    tls = payload.get("tls") or {}
    h2 = payload.get("http2") or {}
    ja3_text = tls.get("ja3")
    return {
        "target": target,
        "ja3": ja3_text,
        "ja4": tls.get("ja4"),
        "peetprint": tls.get("peetprint"),
        "akamai": h2.get("akamai_fingerprint"),
        "expected": dict(expected),
        "matches": {
            "ja4": tls.get("ja4") == expected["ja4"],
            "ja4_r": tls.get("ja4_r") == expected["ja4_r"],
            "akamai": h2.get("akamai_fingerprint") == expected["akamai"],
            "ja3": (ja3_text == expected["ja3"]) if expected["ja3_fixed"] else None,
        },
        "headers": _sent_header_names(payload),
        "http_version": payload.get("http_version") or getattr(response, "http_version", None),
    }


# --------------------------------------------------------------------------
# Expected values.
#
# GENERATED from tools/hello_templates/*.json and tools/h2_templates/*.json
# (53 targets captured 2026-10-10).  'ja4'/'ja4_r'/'ja3' come from each
# capture's fingerprints, 'akamai' from peet_live.akamai when the target has
# a live capture and from the HTTP/2 template's akamai_fingerprint otherwise,
# and 'ja3_fixed' records whether the target's JA3 is stable per connection
# (the Chromium family permutes extensions, so its JA3 is a sample).  Do not
# edit by hand: regenerate the literal with a one-off script that loads the
# template JSON files and prints the dict (see the commit that added this
# table), so the wheel carries the values without shipping tools/.
# --------------------------------------------------------------------------

EXPECTED: Dict[str, Dict[str, Any]] = {
    'chrome': {
        'ja4': 't13d1516h2_8daaf6152771_806a8c22fdea',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome100': {
        'ja4': 't13d1516h2_8daaf6152771_e5627efa2ab1',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0',
    },
    'chrome101': {
        'ja4': 't13d1516h2_8daaf6152771_e5627efa2ab1',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0',
    },
    'chrome104': {
        'ja4': 't13d1516h2_8daaf6152771_e5627efa2ab1',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0',
    },
    'chrome107': {
        'ja4': 't13d1516h2_8daaf6152771_e5627efa2ab1',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0',
    },
    'chrome110': {
        'ja4': 't13d1516h2_8daaf6152771_e5627efa2ab1',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome116': {
        'ja4': 't13d1516h2_8daaf6152771_e5627efa2ab1',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome119': {
        'ja4': 't13d1516h2_8daaf6152771_02713d6af862',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,4469,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome120': {
        'ja4': 't13d1516h2_8daaf6152771_02713d6af862',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,4469,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome123': {
        'ja4': 't13d1516h2_8daaf6152771_02713d6af862',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,4469,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome124': {
        'ja4': 't13d1516h2_8daaf6152771_02713d6af862',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,4469,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome131': {
        'ja4': 't13d1516h2_8daaf6152771_02713d6af862',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,4469,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome131_android': {
        'ja4': 't13d1516h2_8daaf6152771_02713d6af862',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,4469,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome133a': {
        'ja4': 't13d1516h2_8daaf6152771_d8a2da3f94cd',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome136': {
        'ja4': 't13d1516h2_8daaf6152771_d8a2da3f94cd',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome142': {
        'ja4': 't13d1516h2_8daaf6152771_d8a2da3f94cd',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome145': {
        'ja4': 't13d1516h2_8daaf6152771_d8a2da3f94cd',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome146': {
        'ja4': 't13d1516h2_8daaf6152771_d8a2da3f94cd',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome150': {
        'ja4': 't13d1516h2_8daaf6152771_806a8c22fdea',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'chrome99': {
        'ja4': 't13d1516h2_8daaf6152771_e5627efa2ab1',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0',
    },
    'chrome99_android': {
        'ja4': 't13d1516h2_8daaf6152771_e5627efa2ab1',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0',
    },
    'chrome_android': {
        'ja4': 't13d1516h2_8daaf6152771_02713d6af862',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,4469,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': False,
        'ja3': None,
    },
    'edge': {
        'ja4': 't13d1516h2_8daaf6152771_e5627efa2ab1',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0',
    },
    'edge101': {
        'ja4': 't13d1516h2_8daaf6152771_e5627efa2ab1',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0',
    },
    'edge99': {
        'ja4': 't13d1516h2_8daaf6152771_e5627efa2ab1',
        'ja4_r': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601',
        'akamai': '1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0',
    },
    'firefox': {
        'ja4': 't13d1717h2_5b57614c22b0_3cbfd9057e0d',
        'ja4_r': 't13d1717h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201',
        'akamai': '1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s',
        'ja3_fixed': True,
        'ja3': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0',
    },
    'firefox133': {
        'ja4': 't13d1716h2_5b57614c22b0_eeeea6562960',
        'ja4_r': 't13d1716h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201',
        'akamai': '1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s',
        'ja3_fixed': True,
        'ja3': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0',
    },
    'firefox135': {
        'ja4': 't13d1717h2_5b57614c22b0_3cbfd9057e0d',
        'ja4_r': 't13d1717h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201',
        'akamai': '1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s',
        'ja3_fixed': True,
        'ja3': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0',
    },
    'firefox144': {
        'ja4': 't13d1717h2_5b57614c22b0_3cbfd9057e0d',
        'ja4_r': 't13d1717h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201',
        'akamai': '1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s',
        'ja3_fixed': True,
        'ja3': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0',
    },
    'firefox147': {
        'ja4': 't13d1717h2_5b57614c22b0_3cbfd9057e0d',
        'ja4_r': 't13d1717h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201',
        'akamai': '1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s',
        'ja3_fixed': True,
        'ja3': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0',
    },
    'safari': {
        'ja4': 't13d2013h2_a09f3c656075_7f0f34a4126d',
        'ja4_r': 't13d2013h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p',
        'ja3_fixed': True,
        'ja3': '771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0',
    },
    'safari153': {
        'ja4': 't13d2613h2_2802a3db6c62_845d286b0d67',
        'ja4_r': 't13d2613h2_000a,002f,0035,003c,003d,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,002b,002d,0033,ff01_0403,0804,0401,0503,0203,0805,0805,0501,0806,0601,0201',
        'akamai': '4:4194304;3:100|10485760|0|m,s,p,a',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-21,29-23-24-25,0',
    },
    'safari155': {
        'ja4': 't13d2014h2_a09f3c656075_14788d8d241b',
        'ja4_r': 't13d2014h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0203,0805,0805,0501,0806,0601,0201',
        'akamai': '4:4194304;3:100|10485760|0|m,s,p,a',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari15_3': {
        'ja4': 't13d2613h2_2802a3db6c62_845d286b0d67',
        'ja4_r': 't13d2613h2_000a,002f,0035,003c,003d,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,002b,002d,0033,ff01_0403,0804,0401,0503,0203,0805,0805,0501,0806,0601,0201',
        'akamai': '4:4194304;3:100|10485760|0|m,s,p,a',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-21,29-23-24-25,0',
    },
    'safari15_5': {
        'ja4': 't13d2014h2_a09f3c656075_14788d8d241b',
        'ja4_r': 't13d2014h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0203,0805,0805,0501,0806,0601,0201',
        'akamai': '4:4194304;3:100|10485760|0|m,s,p,a',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari170': {
        'ja4': 't13d2014h2_a09f3c656075_14788d8d241b',
        'ja4_r': 't13d2014h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0203,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;4:4194304;3:100|10485760|0|m,s,p,a',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari172_ios': {
        'ja4': 't13d2014h2_a09f3c656075_14788d8d241b',
        'ja4_r': 't13d2014h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0203,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;4:2097152;3:100|10485760|0|m,s,p,a',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari17_0': {
        'ja4': 't13d2014h2_a09f3c656075_14788d8d241b',
        'ja4_r': 't13d2014h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0203,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;4:4194304;3:100|10485760|0|m,s,p,a',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari17_2_ios': {
        'ja4': 't13d2014h2_a09f3c656075_14788d8d241b',
        'ja4_r': 't13d2014h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0203,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;4:2097152;3:100|10485760|0|m,s,p,a',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari180': {
        'ja4': 't13d2014h2_a09f3c656075_e42f34c56612',
        'ja4_r': 't13d2014h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari180_ios': {
        'ja4': 't13d2014h2_a09f3c656075_e42f34c56612',
        'ja4_r': 't13d2014h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari184': {
        'ja4': 't13d2014h2_a09f3c656075_e42f34c56612',
        'ja4_r': 't13d2014h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari184_ios': {
        'ja4': 't13d2014h2_a09f3c656075_e42f34c56612',
        'ja4_r': 't13d2014h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari18_0': {
        'ja4': 't13d2014h2_a09f3c656075_e42f34c56612',
        'ja4_r': 't13d2014h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari18_0_ios': {
        'ja4': 't13d2014h2_a09f3c656075_e42f34c56612',
        'ja4_r': 't13d2014h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari260': {
        'ja4': 't13d2014h2_a09f3c656075_d0a99439f9b1',
        'ja4_r': 't13d2014h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p',
        'ja3_fixed': True,
        'ja3': '771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,4588-29-23-24-25,0',
    },
    'safari2601': {
        'ja4': 't13d2013h2_a09f3c656075_7f0f34a4126d',
        'ja4_r': 't13d2013h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p',
        'ja3_fixed': True,
        'ja3': '771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0',
    },
    'safari260_ios': {
        'ja4': 't13d2015h2_a09f3c656075_c258b721e490',
        'ja4_r': 't13d2015h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari_beta': {
        'ja4': 't13d2013h2_a09f3c656075_7f0f34a4126d',
        'ja4_r': 't13d2013h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p',
        'ja3_fixed': True,
        'ja3': '771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0',
    },
    'safari_ios': {
        'ja4': 't13d2015h2_a09f3c656075_c258b721e490',
        'ja4_r': 't13d2015h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'safari_ios_beta': {
        'ja4': 't13d2015h2_a09f3c656075_c258b721e490',
        'ja4_r': 't13d2015h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201',
        'akamai': '2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p',
        'ja3_fixed': True,
        'ja3': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    },
    'tor': {
        'ja4': 't13d1513h2_8daaf6152771_748f4c70de1c',
        'ja4_r': 't13d1513h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0017,001c,0022,002b,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201',
        'akamai': '1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s',
        'ja3_fixed': True,
        'ja3': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-28-65037,29-23-24-25-256-257,0',
    },
    'tor145': {
        'ja4': 't13d1513h2_8daaf6152771_748f4c70de1c',
        'ja4_r': 't13d1513h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0017,001c,0022,002b,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201',
        'akamai': '1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s',
        'ja3_fixed': True,
        'ja3': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-28-65037,29-23-24-25-256-257,0',
    },}
