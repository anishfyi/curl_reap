"""TLS ClientHello parsing plus JA3 and JA4 fingerprint computation.

This module is pure Python with no third-party dependencies so it can move
into the ``curl_reap`` package unchanged.  It understands the full TLS record
and handshake framing of a ClientHello, decodes every extension a modern
browser emits, flags GREASE values, and derives:

* JA3 string and md5 hash (Salesforce JA3: legacy version, ciphers,
  extensions, supported groups, EC point formats; GREASE removed; decimal,
  dash separated inside each field, comma separated between fields).
* JA4 (FoxIO specification, TLS over TCP):
  ``t13d1516h2_<sha256 of sorted ciphers>[:12]_<sha256 of sorted extensions
  excluding SNI and ALPN + "_" + signature algorithms>[:12]`` plus the raw
  (``ja4_r``), original-order (``ja4_o``) and raw original-order (``ja4_ro``)
  variants.

Usage from the command line::

    python tools/fingerprint_calc.py <hex-or-file>

prints the parsed hello and the fingerprints as JSON.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

__all__ = [
    "GREASE_VALUES",
    "EXTENSION_NAMES",
    "is_grease",
    "parse_client_hello",
    "ja3",
    "ja4",
    "fingerprints",
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
    several records are reassembled.
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
        while off + 4 <= ext_end:
            etype = _u16(body, off)
            elen = _u16(body, off + 2)
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


def ja3(hello: Dict[str, Any]) -> Dict[str, str]:
    """Return ``{"ja3": <string>, "ja3_hash": <md5>}``."""
    version = int(hello["legacy_version"], 16)
    text = ",".join([
        str(version),
        "-".join(str(c) for c in _cipher_ids(hello)),
        "-".join(str(e) for e in _ext_ids(hello)),
        "-".join(str(g) for g in _groups(hello)),
        "-".join(str(p) for p in _point_formats(hello)),
    ])
    return {"ja3": text, "ja3_hash": hashlib.md5(text.encode()).hexdigest()}


def _ja4_version(hello: Dict[str, Any]) -> str:
    sv = _ext_by_type(hello, 43)
    candidates: List[int] = []
    if sv and "decoded" in sv:
        candidates = [v["decimal"] for v in sv["decoded"]["versions"] if not is_grease(v["decimal"])]
    version = max(candidates) if candidates else int(hello["legacy_version"], 16)
    return {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
        0x0002: "s2",
        0x0100: "s1",
    }.get(version, "00")


def _ja4_alpn(hello: Dict[str, Any]) -> str:
    alpn = _ext_by_type(hello, 16)
    if not alpn or "decoded" not in alpn or not alpn["decoded"]["protocols"]:
        return "00"
    first = alpn["decoded"]["protocols"][0]
    if not first:
        return "00"
    raw = first.encode("latin-1")
    if all(32 < b < 127 and chr(b).isalnum() for b in (raw[0], raw[-1])):
        return first[0] + first[-1]
    h = raw.hex()
    return h[0] + h[-1]


def _sha12(text: str) -> str:
    if not text:
        return "000000000000"
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def ja4(hello: Dict[str, Any], transport: str = "t") -> Dict[str, str]:
    """Return the JA4 family: ``ja4``, ``ja4_r``, ``ja4_o``, ``ja4_ro``."""
    ciphers = _cipher_ids(hello)
    exts_all = _ext_ids(hello)
    sigalgs = _sigalgs(hello)
    sni = "d" if _ext_by_type(hello, 0) is not None else "i"
    ja4_a = "%s%s%s%02d%02d%s" % (
        transport,
        _ja4_version(hello),
        sni,
        min(len(ciphers), 99),
        min(len(exts_all), 99),
        _ja4_alpn(hello),
    )
    ciphers_sorted = ",".join(_hex2(c) for c in sorted(ciphers))
    ciphers_orig = ",".join(_hex2(c) for c in ciphers)
    exts_sorted = ",".join(_hex2(e) for e in sorted(e for e in exts_all if e not in (0, 16)))
    exts_orig = ",".join(_hex2(e) for e in exts_all)
    sig_text = ",".join(_hex2(s) for s in sigalgs)

    def c_part(ext_text: str) -> str:
        if not ext_text:
            return ""
        return ext_text + ("_" + sig_text if sig_text else "")

    ja4_b = _sha12(ciphers_sorted)
    ja4_c = _sha12(c_part(exts_sorted))
    ja4_b_o = _sha12(ciphers_orig)
    ja4_c_o = _sha12(c_part(exts_orig))
    return {
        "ja4": "%s_%s_%s" % (ja4_a, ja4_b, ja4_c),
        "ja4_r": "%s_%s_%s" % (ja4_a, ciphers_sorted, c_part(exts_sorted)),
        "ja4_o": "%s_%s_%s" % (ja4_a, ja4_b_o, ja4_c_o),
        "ja4_ro": "%s_%s_%s" % (ja4_a, ciphers_orig, c_part(exts_orig)),
    }


def fingerprints(hello: Dict[str, Any]) -> Dict[str, str]:
    out = ja3(hello)
    out.update(ja4(hello))
    return out


def summarize(hello: Dict[str, Any]) -> Dict[str, Any]:
    """Compact human-facing summary used by the capture tool."""
    return {
        "record_version": hello["record_version"],
        "legacy_version": hello["legacy_version"],
        "handshake_length": hello["handshake_length"],
        "total_bytes": hello["total_bytes"],
        "session_id_len": hello["session_id_len"],
        "ciphers": [c.get("name") if c.get("grease") else c["id"] for c in hello["cipher_suites"]],
        "extensions": [e["name"] if e["grease"] else e["type_hex"] for e in hello["extensions"]],
        "fingerprints": fingerprints(hello),
    }


def _main(argv: Sequence[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    arg = argv[1]
    try:
        with open(arg, "rb") as fh:
            raw = fh.read()
        try:
            raw = bytes.fromhex(raw.decode().strip())
        except ValueError:
            pass
    except OSError:
        raw = bytes.fromhex(arg.strip())
    hello = parse_client_hello(raw)
    hello["fingerprints"] = fingerprints(hello)
    print(json.dumps(hello, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
