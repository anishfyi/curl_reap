"""ClientHello templates: the loader for ``templates_data.py`` and JA3 import.

A :class:`HelloTemplate` describes everything fixed about a browser's
ClientHello: cipher order, extension order with per-extension parameters and
position markers, groups, signature algorithms, key share groups, ALPN,
ALPS, versions, PSK modes, certificate compression, point formats,
record_size_limit, delegated credentials, the padding rule and the ECH GREASE
shape. The string ``"GREASE"`` marks slots that receive a per-connection
GREASE value drawn the way BoringSSL draws them.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .consts import (
    CERT_COMPRESSION_BY_NAME,
    EXT_ALPN,
    EXT_APPLICATION_SETTINGS,
    EXT_APPLICATION_SETTINGS_OLD,
    EXT_COMPRESS_CERTIFICATE,
    EXT_DELEGATED_CREDENTIALS,
    EXT_EC_POINT_FORMATS,
    EXT_ECH,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_KEY_SHARE,
    EXT_NAMES,
    EXT_PADDING,
    EXT_PRE_SHARED_KEY,
    EXT_PSK_KEY_EXCHANGE_MODES,
    EXT_RECORD_SIZE_LIMIT,
    EXT_RENEGOTIATION_INFO,
    EXT_SCT,
    EXT_SERVER_NAME,
    EXT_SESSION_TICKET,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_STATUS_REQUEST,
    EXT_SUPPORTED_GROUPS,
    EXT_SUPPORTED_VERSIONS,
    GROUP_SECP256R1,
    GROUP_X25519,
    GROUP_X25519KYBER768DRAFT00,
    GROUP_X25519MLKEM768,
    HPKE_AEAD_AES_128_GCM,
    HPKE_KDF_HKDF_SHA256,
    TLS10,
    TLS12,
    TLS13,
    is_grease,
)

GREASE = "GREASE"
PADDING_RULE_BORINGSSL = "boringssl"

Marker = Union[int, str]

#: Extension types the builder knows how to render.
RENDERABLE = frozenset({
    EXT_SERVER_NAME, EXT_STATUS_REQUEST, EXT_SUPPORTED_GROUPS, EXT_EC_POINT_FORMATS,
    EXT_SIGNATURE_ALGORITHMS, EXT_ALPN, EXT_SCT, EXT_PADDING, EXT_EXTENDED_MASTER_SECRET,
    EXT_COMPRESS_CERTIFICATE, EXT_RECORD_SIZE_LIMIT, EXT_DELEGATED_CREDENTIALS,
    EXT_SESSION_TICKET, EXT_SUPPORTED_VERSIONS, EXT_PSK_KEY_EXCHANGE_MODES, EXT_KEY_SHARE,
    EXT_APPLICATION_SETTINGS, EXT_APPLICATION_SETTINGS_OLD, EXT_ECH, EXT_RENEGOTIATION_INFO,
})

_DEFAULT_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
_FIREFOX_DELEGATED = [0x0403, 0x0503, 0x0603, 0x0203]


@dataclass
class HelloTemplate:
    """One impersonate target's ClientHello shape. See the module docstring."""

    name: str
    ciphers: List[Marker]
    extensions: List[Dict[str, Any]]
    supported_groups: List[Marker]
    signature_algorithms: List[int]
    key_share_groups: List[Marker]
    alpn: Tuple[str, ...]
    alps_codepoint: Optional[int]
    alps_value: Optional[bytes]
    supported_versions: List[Marker]
    psk_modes: List[int]
    compress_certificate: List[int]
    ec_point_formats: List[int]
    record_size_limit: Optional[int]
    delegated_credentials: Optional[List[int]]
    padding_rule: Optional[str]
    ech: Optional[Dict[str, Any]]
    permute_extensions: bool
    grease: bool
    session_ticket: bool
    family: str = "custom"
    alias_of: Optional[str] = None
    legacy_version: int = TLS12
    record_version: int = TLS10
    session_id_len: int = 32
    compression_methods: Tuple[int, ...] = (0,)
    expected: Dict[str, Any] = field(default_factory=dict)

    # -- helpers -----------------------------------------------------------
    def extension_types(self) -> List[Marker]:
        return [e["type"] for e in self.extensions]

    def has_extension(self, ext_type: int) -> bool:
        return any(e["type"] == ext_type for e in self.extensions)

    @property
    def real_key_share_groups(self) -> List[int]:
        return [g for g in self.key_share_groups if g != GREASE]

    @property
    def real_supported_groups(self) -> List[int]:
        return [g for g in self.supported_groups if g != GREASE]

    @property
    def alps_protocols(self) -> Tuple[str, ...]:
        if not self.alps_value:
            return ()
        body = self.alps_value
        out = []
        n = (body[0] << 8) | body[1]
        data = body[2:2 + n]
        i = 0
        while i < len(data):
            ln = data[i]
            out.append(data[i + 1:i + 1 + ln].decode("ascii", "replace"))
            i += 1 + ln
        return tuple(out)

    @property
    def has_post_quantum_share(self) -> bool:
        return any(g in (GROUP_X25519MLKEM768, GROUP_X25519KYBER768DRAFT00) for g in self.real_key_share_groups)

    def with_alpn(self, alpn: Sequence[str]) -> "HelloTemplate":
        return replace(self, alpn=tuple(alpn))

    def copy(self) -> "HelloTemplate":
        return copy.deepcopy(self)


# ---------------------------------------------------------------------------
# Loading from the generated data


def _marker(value) -> Marker:
    if value == GREASE:
        return GREASE
    if isinstance(value, str):
        return int(value, 16)
    return int(value)


def _markers(values) -> List[Marker]:
    return [_marker(v) for v in values]


def _convert_params(ext_type: Marker, params: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(params)
    if "groups" in out:
        out["groups"] = _markers(out["groups"])
    if "versions" in out:
        out["versions"] = _markers(out["versions"])
    if "algorithms" in out and ext_type in (EXT_SIGNATURE_ALGORITHMS, EXT_DELEGATED_CREDENTIALS):
        out["algorithms"] = _markers(out["algorithms"])
    if "shares" in out:
        out["shares"] = [{"group": _marker(s["group"]), "key_length": int(s["key_length"])} for s in out["shares"]]
    return out


def template_from_dict(data: Dict[str, Any], name: Optional[str] = None) -> HelloTemplate:
    """Build a :class:`HelloTemplate` from one ``templates_data.TEMPLATES`` entry."""
    name = name or data["target"]
    family = data.get("family", "custom")
    exts: List[Dict[str, Any]] = []
    seen_grease = 0
    for raw in data["extensions"]:
        ext_type = _marker(raw["type"])
        if ext_type == GREASE:
            seen_grease += 1
        elif ext_type not in RENDERABLE and "body_hex" not in raw:
            raise ValueError("template %s: extension %#06x has no renderer and no fixed body" % (name, ext_type))
        entry = {
            "type": ext_type,
            "name": raw.get("name") or (EXT_NAMES.get(ext_type, "unknown") if ext_type != GREASE else GREASE),
            "position": raw.get("position", "fixed"),
            "params": _convert_params(ext_type, raw.get("params", {})),
        }
        if raw.get("body_hex") is not None:
            entry["body_hex"] = raw["body_hex"]
        exts.append(entry)
    ks_groups = [_marker(s["group"]) for s in data.get("key_share", [])]
    alps_codepoint = data.get("alps_codepoint")
    alps_value = None
    if alps_codepoint is not None:
        alps_codepoint = int(alps_codepoint, 16) if isinstance(alps_codepoint, str) else int(alps_codepoint)
        for e in exts:
            if e["type"] == alps_codepoint and e.get("body_hex"):
                alps_value = bytes.fromhex(e["body_hex"])
        if alps_value is None:
            from . import wire

            alps_value = wire.alpn_list(data.get("alps") or ["h2"])
    compress = [CERT_COMPRESSION_BY_NAME[c] if isinstance(c, str) else int(c) for c in data.get("compress_certificate") or []]
    ech = None
    if data.get("ech"):
        e = data["ech"]
        ech = {
            "kdf_id": int(e.get("kdf_id", "0001"), 16) if isinstance(e.get("kdf_id"), str) else int(e.get("kdf_id", 1)),
            "aead_id": int(e.get("aead_id", "0001"), 16) if isinstance(e.get("aead_id"), str) else int(e.get("aead_id", 1)),
            "enc_len": int(e.get("enc_len", 32)),
            # BoringSSL: 32 * random(4..7) + AEAD overhead (16).  Only the
            # sizes this target was actually captured sending: chrome
            # android, for one, never sends the 144 byte payload.
            "payload_lengths": sorted(int(n) for n in e.get("payload_len_seen") or []) or [32 * k + 16 for k in range(4, 8)],
        }
    delegated = data.get("delegated_credentials")
    expected = {
        "fingerprints": dict(data.get("fingerprints") or {}),
        "peet_live": dict(data.get("peet_live") or {}),
        "handshake_length": dict(data.get("handshake_length") or {}),
        "padding_length": data.get("padding_length"),
        "extension_order_fixed": data.get("extension_order_fixed"),
    }
    return HelloTemplate(
        name=name,
        family=family,
        alias_of=data.get("alias_of"),
        ciphers=_markers(data["cipher_suites"]),
        extensions=exts,
        supported_groups=_markers(data["supported_groups"]),
        signature_algorithms=_markers(data["signature_algorithms"]),
        key_share_groups=ks_groups,
        alpn=tuple(data.get("alpn") or ("h2", "http/1.1")),
        alps_codepoint=alps_codepoint,
        alps_value=alps_value,
        supported_versions=_markers(data["supported_versions"]),
        psk_modes=[int(m) for m in data.get("psk_key_exchange_modes") or []],
        compress_certificate=compress,
        ec_point_formats=[int(f) for f in data.get("ec_point_formats") or []],
        record_size_limit=data.get("record_size_limit"),
        delegated_credentials=_markers(delegated) if delegated else None,
        # Every capture comes from BoringSSL, which pads a 256..511 byte hello
        # to 512 bytes; the rule only triggers for the small (no post-quantum
        # share, no ECH) hellos, exactly where the captures show padding.
        padding_rule=PADDING_RULE_BORINGSSL,
        ech=ech,
        permute_extensions=not data.get("extension_order_fixed", True),
        grease=seen_grease > 0,
        session_ticket=any(e["type"] == EXT_SESSION_TICKET for e in exts),
        legacy_version=int(data.get("legacy_version", "0303"), 16),
        record_version=int(data.get("record_version", "0301"), 16),
        session_id_len=int(data.get("session_id_len", 32)),
        compression_methods=tuple(data.get("compression_methods") or (0,)),
        expected=expected,
    )


_cache: Dict[str, HelloTemplate] = {}


def _data():
    from .templates_data import TEMPLATES

    return TEMPLATES


def template_names() -> List[str]:
    return sorted(_data())


def template(name: str) -> HelloTemplate:
    """Return the template for an impersonate target; KeyError when unknown."""
    cached = _cache.get(name)
    if cached is not None:
        return cached
    data = _data()
    if name not in data:
        raise KeyError("unknown TLS template %r (known: %s)" % (name, ", ".join(sorted(data))))
    tpl = template_from_dict(data[name], name)
    _cache[name] = tpl
    return tpl


# ---------------------------------------------------------------------------
# JA3 import


def _parse_field(text: str) -> List[int]:
    text = text.strip()
    if not text:
        return []
    return [int(v) for v in text.split("-")]


def template_from_ja3(
    ja3: str,
    *,
    alpn: Sequence[str] = ("h2", "http/1.1"),
    grease: bool = False,
    permute: bool = False,
    name: str = "ja3",
    signature_algorithms: Optional[Sequence[int]] = None,
) -> HelloTemplate:
    """Build a template from a JA3 string (``771,ciphers,extensions,groups,formats``).

    JA3 strips GREASE, so the result sends none unless ``grease=True``; the
    extension bodies use Chrome's defaults (OCSP status_request, brotli
    certificate compression, ``psk_dhe_ke``, ALPS for ``h2``). Extensions the
    builder cannot render are sent with an empty body so the hash still
    matches. Key shares are X25519 plus the first post-quantum group listed.
    """
    parts = ja3.split(",")
    if len(parts) != 5:
        raise ValueError("JA3 string needs five comma separated fields")
    version = int(parts[0]) if parts[0].strip() else TLS12
    ciphers = [c for c in _parse_field(parts[1]) if not is_grease(c)]
    ext_types = [e for e in _parse_field(parts[2]) if not is_grease(e)]
    groups = [g for g in _parse_field(parts[3]) if not is_grease(g)]
    formats = _parse_field(parts[4])
    if not ciphers:
        raise ValueError("JA3 string has no cipher suites")
    sigalgs = list(signature_algorithms) if signature_algorithms else list(_DEFAULT_SIGALGS)

    ks_groups: List[Marker] = []
    pq = [g for g in groups if g in (GROUP_X25519MLKEM768, GROUP_X25519KYBER768DRAFT00)]
    if pq:
        ks_groups.append(pq[0])
    classical = [g for g in groups if g in (GROUP_X25519, GROUP_SECP256R1, 24, 25)]
    if classical:
        ks_groups.append(classical[0] if GROUP_X25519 not in classical else GROUP_X25519)
    if not ks_groups:
        ks_groups.append(GROUP_X25519)
        groups = groups + [GROUP_X25519]
    if grease:
        ks_groups.insert(0, GREASE)

    full_groups: List[Marker] = ([GREASE] if grease else []) + list(groups)
    versions: List[Marker] = ([GREASE] if grease else []) + [TLS13, TLS12]
    alps_codepoint = None
    alps_value = None
    exts: List[Dict[str, Any]] = []
    if grease:
        exts.append({"type": GREASE, "name": GREASE, "position": "fixed", "params": {"length": 0}})
    for et in ext_types:
        params: Dict[str, Any] = {}
        if et == EXT_SUPPORTED_GROUPS:
            params = {"groups": full_groups}
        elif et == EXT_EC_POINT_FORMATS:
            params = {"formats": formats or [0]}
        elif et == EXT_SIGNATURE_ALGORITHMS:
            params = {"algorithms": sigalgs}
        elif et == EXT_ALPN:
            params = {"protocols": list(alpn)}
        elif et == EXT_COMPRESS_CERTIFICATE:
            params = {"algorithms": [2]}
        elif et == EXT_RECORD_SIZE_LIMIT:
            params = {"limit": 16385}
        elif et == EXT_DELEGATED_CREDENTIALS:
            params = {"algorithms": list(_FIREFOX_DELEGATED)}
        elif et == EXT_SUPPORTED_VERSIONS:
            params = {"versions": versions}
        elif et == EXT_PSK_KEY_EXCHANGE_MODES:
            params = {"modes": [1]}
        elif et == EXT_KEY_SHARE:
            params = {"shares": [{"group": g, "key_length": 0} for g in ks_groups]}
        elif et in (EXT_APPLICATION_SETTINGS, EXT_APPLICATION_SETTINGS_OLD):
            params = {"protocols": ["h2"]}
            alps_codepoint = et
            from . import wire

            alps_value = wire.alpn_list(["h2"])
        elif et == EXT_ECH:
            params = {"type": 0, "kdf_id": "0001", "aead_id": "0001", "enc_len": 32}
        elif et == EXT_STATUS_REQUEST:
            params = {"status_type": 1}
        elif et == EXT_PRE_SHARED_KEY:
            continue  # added per connection when resuming
        entry = {"type": et, "name": EXT_NAMES.get(et, "unknown_%d" % et), "position": "permuted" if permute else "fixed", "params": params}
        if et not in RENDERABLE:
            entry["body_hex"] = ""
        exts.append(entry)
    if grease:
        exts.append({"type": GREASE, "name": GREASE, "position": "fixed", "params": {"length": 1}})
    has_ech = EXT_ECH in ext_types
    return HelloTemplate(
        name=name,
        family="custom",
        ciphers=([GREASE] if grease else []) + ciphers,
        extensions=exts,
        supported_groups=full_groups,
        signature_algorithms=sigalgs,
        key_share_groups=ks_groups,
        alpn=tuple(alpn),
        alps_codepoint=alps_codepoint,
        alps_value=alps_value,
        supported_versions=versions,
        psk_modes=[1] if EXT_PSK_KEY_EXCHANGE_MODES in ext_types else [],
        compress_certificate=[2] if EXT_COMPRESS_CERTIFICATE in ext_types else [],
        ec_point_formats=formats or [0],
        record_size_limit=16385 if EXT_RECORD_SIZE_LIMIT in ext_types else None,
        delegated_credentials=list(_FIREFOX_DELEGATED) if EXT_DELEGATED_CREDENTIALS in ext_types else None,
        padding_rule=PADDING_RULE_BORINGSSL if EXT_PADDING in ext_types else None,
        ech={"kdf_id": HPKE_KDF_HKDF_SHA256, "aead_id": HPKE_AEAD_AES_128_GCM, "enc_len": 32, "payload_lengths": [32 * k + 16 for k in range(4, 8)]} if has_ech else None,
        permute_extensions=permute,
        grease=grease,
        session_ticket=EXT_SESSION_TICKET in ext_types,
        legacy_version=version if version in (TLS10, 0x0302, TLS12) else TLS12,
        expected={"ja3": ja3},
    )
