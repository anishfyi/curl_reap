"""Render a :class:`HelloTemplate` into ClientHello bytes.

``ClientHelloBuilder`` draws the per-connection variable fields once (client
random, session id, a 7-byte GREASE seed as BoringSSL's ``grease_seed``, the
extension permutation, the ECH GREASE config id, enc and payload) and keeps
them for the life of a connection, so the second ClientHello after a
HelloRetryRequest differs only in key_share, cookie and the PSK binder, as
the RFC requires and as BoringSSL behaves.

The GREASE values are derived the way BoringSSL derives them: byte ``i`` of
the seed gives ``(b & 0xf0 | 0x0a)`` repeated in both bytes, with indices
cipher, group (shared by supported_groups and the GREASE key share),
extension1, extension2 (XOR 0x1010 when equal to extension1), version,
ticket and the ECH config id. Padding follows the BoringSSL rule: when the
whole handshake message without padding is 256..511 bytes it is padded to
exactly 512 (the padding extension carries ``512 - len - 4`` zero bytes, or
1 byte when there is no room), computed with the pre_shared_key extension
included. The pre_shared_key extension is always last, after the padding.
"""
from __future__ import annotations

import os
import random
import time
from typing import Any, Dict, List, Optional, Sequence, Union

from . import wire
from .certs import available_compression_algorithms
from .consts import (
    EXT_ALPN,
    EXT_APPLICATION_SETTINGS,
    EXT_APPLICATION_SETTINGS_OLD,
    EXT_COMPRESS_CERTIFICATE,
    EXT_COOKIE,
    EXT_DELEGATED_CREDENTIALS,
    EXT_EC_POINT_FORMATS,
    EXT_ECH,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_KEY_SHARE,
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
    HT_CLIENT_HELLO,
    is_grease,
)
from .keyexchange import KeyShare, generate_shares
from .keyschedule import SUITES, psk_binder
from .templates import GREASE, PADDING_RULE_BORINGSSL, HelloTemplate

GREASE_SEED_LEN = 7
_GI_CIPHER, _GI_GROUP, _GI_EXT1, _GI_EXT2, _GI_VERSION, _GI_TICKET, _GI_ECH_CONFIG_ID = range(7)


def grease_from_seed_byte(b: int) -> int:
    v = (b & 0xF0) | 0x0A
    return (v << 8) | v


class ClientHelloBuilder:
    """Stateful renderer; see the module docstring."""

    def __init__(
        self,
        template: HelloTemplate,
        server_name: str,
        *,
        alpn: Optional[Sequence[str]] = None,
        rng: Optional[random.Random] = None,
        grease_seed: Optional[bytes] = None,
        client_random: Optional[bytes] = None,
        session_id: Optional[bytes] = None,
    ):
        self.template = template
        self.server_name = server_name
        self.alpn = tuple(alpn) if alpn is not None else tuple(template.alpn)
        self.rng = rng if rng is not None else random.SystemRandom()
        self.random = client_random if client_random is not None else self._rand(32)
        if len(self.random) != 32:
            raise ValueError("client random must be 32 bytes")
        if session_id is None:
            session_id = self._rand(template.session_id_len) if template.session_id_len else b""
        self.session_id = session_id
        seed = grease_seed if grease_seed is not None else self._rand(GREASE_SEED_LEN)
        if len(seed) < GREASE_SEED_LEN:
            raise ValueError("grease seed must be %d bytes" % GREASE_SEED_LEN)
        self.grease_seed = bytes(seed)
        ext1 = grease_from_seed_byte(seed[_GI_EXT1])
        ext2 = grease_from_seed_byte(seed[_GI_EXT2])
        if ext2 == ext1:
            ext2 ^= 0x1010
        self.grease = {
            "cipher": grease_from_seed_byte(seed[_GI_CIPHER]),
            "group": grease_from_seed_byte(seed[_GI_GROUP]),
            "ext1": ext1,
            "ext2": ext2,
            "version": grease_from_seed_byte(seed[_GI_VERSION]),
            "ticket": grease_from_seed_byte(seed[_GI_TICKET]),
        }
        self.ech_config_id = seed[_GI_ECH_CONFIG_ID]
        self.ech_enc: Optional[bytes] = None
        self.ech_payload: Optional[bytes] = None
        if template.ech:
            # BoringSSL encapsulates to a fresh X25519 key and throws the
            # private half away; the enc is therefore a real curve point.
            if template.ech.get("enc_len", 32) == 32:
                from cryptography.hazmat.primitives.asymmetric import x25519

                self.ech_enc = x25519.X25519PrivateKey.from_private_bytes(self._rand(32)).public_key().public_bytes_raw()
            else:
                self.ech_enc = self._rand(template.ech["enc_len"])
            lengths = template.ech.get("payload_lengths") or [32 * k + 16 for k in range(4, 8)]
            self.ech_payload = self._rand(lengths[self.rng.randrange(len(lengths))])
        self.order = self._permutation()
        self.compress_algorithms = available_compression_algorithms(template.compress_certificate)
        self.last_hello = b""
        self.hello_count = 0

    # -- randomness helpers -------------------------------------------------
    def _rand(self, n: int) -> bytes:
        if isinstance(self.rng, random.SystemRandom):
            return os.urandom(n)
        return bytes(self.rng.getrandbits(8) for _ in range(n))

    def _permutation(self) -> List[int]:
        exts = self.template.extensions
        order = list(range(len(exts)))
        if not self.template.permute_extensions:
            return order
        slots = [i for i in order if exts[i].get("position") == "permuted"]
        values = list(slots)
        # Fisher-Yates from the top, as ssl_setup_extension_permutation does.
        for i in range(len(values) - 1, 0, -1):
            j = self.rng.randrange(i + 1)
            values[i], values[j] = values[j], values[i]
        for slot, value in zip(slots, values):
            order[slot] = value
        return order

    # -- offered values ------------------------------------------------------
    @property
    def offered_ciphers(self) -> List[int]:
        return [c for c in self.template.ciphers if c != GREASE]

    @property
    def offered_groups(self) -> List[int]:
        return [g for g in self.template.supported_groups if g != GREASE]

    @property
    def offered_versions(self) -> List[int]:
        return [v for v in self.template.supported_versions if v != GREASE]

    @property
    def offered_sigalgs(self) -> List[int]:
        return list(self.template.signature_algorithms)

    @property
    def alps_codepoint(self) -> Optional[int]:
        return self.template.alps_codepoint

    @property
    def alps_protocols(self):
        return self.template.alps_protocols

    @property
    def key_share_groups(self) -> List[int]:
        return self.template.real_key_share_groups

    # -- extension bodies ---------------------------------------------------
    def _render(self, ext_type: int, params: Dict[str, Any], shares: Dict[int, Any], ks_groups: Optional[Sequence[Any]]) -> bytes:
        g = self.grease
        if ext_type == EXT_SERVER_NAME:
            name = self.server_name.rstrip(".")
            try:
                host = name.encode("ascii")
            except UnicodeEncodeError:
                host = name.encode("idna")
            return wire.vec16(b"\x00" + wire.vec16(host))
        if ext_type == EXT_STATUS_REQUEST:
            return b"\x01" + wire.u16(0) + wire.u16(0)
        if ext_type == EXT_SUPPORTED_GROUPS:
            groups = params.get("groups") or self.template.supported_groups
            return wire.u16_list([g["group"] if v == GREASE else v for v in groups], 2)
        if ext_type == EXT_EC_POINT_FORMATS:
            return wire.vec8(bytes(params.get("formats") or self.template.ec_point_formats))
        if ext_type == EXT_SIGNATURE_ALGORITHMS:
            return wire.u16_list(params.get("algorithms") or self.template.signature_algorithms, 2)
        if ext_type == EXT_ALPN:
            return wire.alpn_list(self.alpn)
        if ext_type in (EXT_SCT, EXT_EXTENDED_MASTER_SECRET, EXT_SESSION_TICKET):
            return b""
        if ext_type == EXT_COMPRESS_CERTIFICATE:
            return wire.u16_list(self.compress_algorithms, 1)
        if ext_type == EXT_RECORD_SIZE_LIMIT:
            return wire.u16(int(params.get("limit") or self.template.record_size_limit or 16385))
        if ext_type == EXT_DELEGATED_CREDENTIALS:
            return wire.u16_list(params.get("algorithms") or self.template.delegated_credentials or [], 2)
        if ext_type == EXT_SUPPORTED_VERSIONS:
            versions = params.get("versions") or self.template.supported_versions
            return wire.u16_list([g["version"] if v == GREASE else v for v in versions], 1)
        if ext_type == EXT_PSK_KEY_EXCHANGE_MODES:
            return wire.vec8(bytes(params.get("modes") or self.template.psk_modes))
        if ext_type == EXT_KEY_SHARE:
            groups = list(ks_groups) if ks_groups is not None else list(self.template.key_share_groups)
            entries = b""
            for group in groups:
                if group == GREASE:
                    entries += wire.u16(g["group"]) + wire.vec16(b"\x00")
                    continue
                share = shares.get(group)
                if share is None:
                    raise KeyError("no key share for group %#06x" % group)
                public = share.public if isinstance(share, KeyShare) else bytes(share)
                entries += wire.u16(group) + wire.vec16(public)
            return wire.vec16(entries)
        if ext_type in (EXT_APPLICATION_SETTINGS, EXT_APPLICATION_SETTINGS_OLD):
            if self.template.alps_value is not None and ext_type == self.template.alps_codepoint:
                return self.template.alps_value
            return wire.alpn_list(params.get("protocols") or ["h2"])
        if ext_type == EXT_ECH:
            ech = self.template.ech or {}
            return (
                b"\x00"
                + wire.u16(int(ech.get("kdf_id", 1)))
                + wire.u16(int(ech.get("aead_id", 1)))
                + bytes((self.ech_config_id,))
                + wire.vec16(self.ech_enc or b"")
                + wire.vec16(self.ech_payload or b"")
            )
        if ext_type == EXT_RENEGOTIATION_INFO:
            return b"\x00"
        raise ValueError("no renderer for extension %#06x" % ext_type)

    # -- rendering ----------------------------------------------------------
    def build(
        self,
        shares: Optional[Dict[int, Any]] = None,
        *,
        key_share_groups: Optional[Sequence[Any]] = None,
        cookie: Optional[bytes] = None,
        psk=None,
        transcript_prefix: bytes = b"",
        now: Optional[float] = None,
    ) -> bytes:
        """Return the full ClientHello handshake message (4-byte header + body).

        ``shares`` maps group id to a :class:`KeyShare` (or raw public bytes);
        ``key_share_groups`` overrides the template's list (HelloRetryRequest
        sends only the requested group, without GREASE); ``cookie`` is echoed
        after supported_versions; ``psk`` is a :class:`Ticket` whose binder
        is computed over ``transcript_prefix`` plus the truncated hello.
        """
        t = self.template
        shares = shares or {}
        g = self.grease
        ciphers = [g["cipher"] if c == GREASE else c for c in t.ciphers]
        exts = t.extensions
        rendered: List[bytes] = []
        grease_seen = 0
        cookie_placed = False
        for idx in self.order:
            spec = exts[idx]
            ext_type = spec["type"]
            if ext_type == GREASE:
                grease_seen += 1
                if grease_seen == 1:
                    rendered.append(wire.extension(g["ext1"], b""))
                else:
                    rendered.append(wire.extension(g["ext2"], b"\x00"))
                continue
            if ext_type == EXT_PADDING or ext_type == EXT_PRE_SHARED_KEY:
                continue
            if "body_hex" in spec and ext_type not in _DYNAMIC:
                body = bytes.fromhex(spec["body_hex"])
            else:
                body = self._render(ext_type, spec.get("params", {}), shares, key_share_groups)
            rendered.append(wire.extension(ext_type, body))
            if ext_type == EXT_SUPPORTED_VERSIONS and cookie is not None:
                rendered.append(wire.extension(EXT_COOKIE, wire.vec16(cookie)))
                cookie_placed = True
        if cookie is not None and not cookie_placed:
            rendered.append(wire.extension(EXT_COOKIE, wire.vec16(cookie)))
        ext_bytes = b"".join(rendered)

        psk_ext_len = 0
        suite = None
        if psk is not None:
            suite = SUITES[psk.cipher]
            psk_ext_len = 4 + 2 + (2 + len(psk.ticket) + 4) + 2 + (1 + suite.hash_len)

        if t.padding_rule == PADDING_RULE_BORINGSSL:
            header_len = (
                4 + 2 + 32 + 1 + len(self.session_id) + 2 + 2 * len(ciphers)
                + 1 + len(t.compression_methods) + 2 + len(ext_bytes) + psk_ext_len
            )
            if 0xFF < header_len < 0x200:
                padding_len = 0x200 - header_len
                padding_len = padding_len - 4 if padding_len >= 5 else 1
                ext_bytes += wire.extension(EXT_PADDING, bytes(padding_len))

        def assemble(extensions: bytes) -> bytes:
            body = (
                wire.u16(t.legacy_version)
                + self.random
                + wire.vec8(self.session_id)
                + wire.u16_list(ciphers, 2)
                + wire.vec8(bytes(t.compression_methods))
                + wire.vec16(extensions)
            )
            return wire.handshake(HT_CLIENT_HELLO, body)

        if psk is not None:
            age = psk.obfuscated_age(now)
            identities = wire.vec16(wire.vec16(psk.ticket) + wire.u32(age))
            placeholder = wire.vec16(wire.vec8(bytes(suite.hash_len)))
            psk_body = identities + placeholder
            hello = assemble(ext_bytes + wire.extension(EXT_PRE_SHARED_KEY, psk_body))
            cut = len(placeholder)
            truncated_hash = suite.hash(transcript_prefix + hello[:-cut])
            binder = psk_binder(suite, psk.psk, truncated_hash)
            hello = hello[:-cut] + wire.vec16(wire.vec8(binder))
        else:
            hello = assemble(ext_bytes)
        self.last_hello = hello
        self.hello_count += 1
        return hello


# Extension types whose body changes per connection even when the capture
# recorded a fixed body (the fixed body only applied to that SNI or ALPN).
_DYNAMIC = frozenset({EXT_SERVER_NAME, EXT_ALPN, EXT_KEY_SHARE, EXT_SUPPORTED_GROUPS,
                      EXT_SUPPORTED_VERSIONS, EXT_ECH, EXT_COMPRESS_CERTIFICATE})


def build_client_hello(
    template: HelloTemplate,
    server_name: str,
    *,
    alpn: Optional[Sequence[str]] = ("h2", "http/1.1"),
    key_shares: Optional[Union[Dict[int, Any], Sequence[KeyShare]]] = None,
    psk=None,
    random_bytes: Optional[bytes] = None,
) -> bytes:
    """Render one ClientHello (handshake message with header) for ``template``.

    A pure helper for tests and fingerprinting. ``key_shares`` maps group id
    to public bytes or :class:`KeyShare`; when omitted real shares are
    generated. ``random_bytes`` (32 bytes) fixes the client random and seeds
    every other variable field, so two calls with the same inputs produce the
    same bytes.
    """
    rng = None
    client_random = None
    if random_bytes is not None:
        if len(random_bytes) != 32:
            raise ValueError("random_bytes must be 32 bytes")
        client_random = bytes(random_bytes)
        rng = random.Random(client_random)
    if key_shares is None:
        shares = generate_shares(template.real_key_share_groups)
    elif isinstance(key_shares, dict):
        shares = dict(key_shares)
    else:
        shares = {s.group: s for s in key_shares}
    builder = ClientHelloBuilder(template, server_name, alpn=alpn, rng=rng, client_random=client_random)
    return builder.build(shares, psk=psk)


# ---------------------------------------------------------------------------
# Offline parsing (tests, the fingerprint module and the test server)


def parse_client_hello(msg: bytes) -> Dict[str, Any]:
    """Parse a ClientHello handshake message (with header) into a dict.

    Keys: version, random, session_id, ciphers, compression, extensions
    (ordered list of (type, body)), and decoded groups, sigalgs, versions,
    point_formats, alpn, sni, key_shares (group -> bytes), psk_identities,
    psk_binders, cookie, psk_modes, compress_certificate, record_size_limit.
    """
    r = wire.Reader(msg)
    if r.u8() != HT_CLIENT_HELLO:
        raise wire.DecodeError("not a ClientHello")
    body = r.sub(3)
    out: Dict[str, Any] = {"version": body.u16(), "random": body.take(32)}
    out["session_id"] = body.vec(1)
    out["ciphers"] = body.u16_list(2)
    out["compression"] = list(body.vec(1))
    exts = list(body.extensions())
    body.expect_end("ClientHello")
    out["extensions"] = exts
    for ext_type, ext_body in exts:
        er = wire.Reader(ext_body)
        if ext_type == EXT_SUPPORTED_GROUPS:
            out["groups"] = er.u16_list(2)
        elif ext_type == EXT_SIGNATURE_ALGORITHMS:
            out["sigalgs"] = er.u16_list(2)
        elif ext_type == EXT_SUPPORTED_VERSIONS:
            out["versions"] = er.u16_list(1)
        elif ext_type == EXT_EC_POINT_FORMATS:
            out["point_formats"] = list(er.vec(1))
        elif ext_type == EXT_ALPN:
            lst = er.sub(2)
            protos = []
            while not lst.at_end():
                protos.append(lst.vec(1).decode("ascii", "replace"))
            out["alpn"] = protos
        elif ext_type == EXT_SERVER_NAME:
            lst = er.sub(2)
            lst.u8()
            out["sni"] = lst.vec(2).decode("ascii", "replace")
        elif ext_type == EXT_KEY_SHARE:
            lst = er.sub(2)
            shares = {}
            order = []
            while not lst.at_end():
                group = lst.u16()
                shares[group] = lst.vec(2)
                order.append(group)
            out["key_shares"] = shares
            out["key_share_order"] = order
        elif ext_type == EXT_PRE_SHARED_KEY:
            ids = er.sub(2)
            identities = []
            while not ids.at_end():
                identities.append((ids.vec(2), ids.u32()))
            binders = er.sub(2)
            blist = []
            while not binders.at_end():
                blist.append(binders.vec(1))
            out["psk_identities"] = identities
            out["psk_binders"] = blist
        elif ext_type == EXT_COOKIE:
            out["cookie"] = er.vec(2)
        elif ext_type == EXT_PSK_KEY_EXCHANGE_MODES:
            out["psk_modes"] = list(er.vec(1))
        elif ext_type == EXT_COMPRESS_CERTIFICATE:
            out["compress_certificate"] = er.u16_list(1)
        elif ext_type == EXT_RECORD_SIZE_LIMIT:
            out["record_size_limit"] = er.u16()
        elif ext_type in (EXT_APPLICATION_SETTINGS, EXT_APPLICATION_SETTINGS_OLD):
            out["alps_codepoint"] = ext_type
    out["grease_count"] = sum(1 for t, _ in exts if is_grease(t))
    return out
