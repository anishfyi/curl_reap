"""HKDF and the TLS 1.3 key schedule (RFC 8446 section 7.1).

HKDF-Extract and HKDF-Expand are written on ``hmac`` so the schedule is
transparent and testable against the RFC 8448 vectors. AEADs come from
``cryptography``.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .consts import (
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
)


class CipherSuite:
    __slots__ = ("id", "name", "hash_name", "hash_len", "aead", "key_len", "bits")

    def __init__(self, suite_id: int, name: str, hash_name: str, aead, key_len: int):
        self.id = suite_id
        self.name = name
        self.hash_name = hash_name
        self.hash_len = hashlib.new(hash_name).digest_size
        self.aead = aead
        self.key_len = key_len
        self.bits = key_len * 8

    def hash(self, data: bytes) -> bytes:
        return hashlib.new(self.hash_name, data).digest()

    def hasher(self):
        return hashlib.new(self.hash_name)


SUITES = {
    TLS_AES_128_GCM_SHA256: CipherSuite(0x1301, "TLS_AES_128_GCM_SHA256", "sha256", AESGCM, 16),
    TLS_AES_256_GCM_SHA384: CipherSuite(0x1302, "TLS_AES_256_GCM_SHA384", "sha384", AESGCM, 32),
    TLS_CHACHA20_POLY1305_SHA256: CipherSuite(
        0x1303, "TLS_CHACHA20_POLY1305_SHA256", "sha256", ChaCha20Poly1305, 32
    ),
}

IV_LEN = 12


def hkdf_extract(hash_name: str, salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hash_name).digest()


def hkdf_expand(hash_name: str, prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes((counter,)), hash_name).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf_expand_label(hash_name: str, secret: bytes, label: str, context: bytes, length: int) -> bytes:
    full = b"tls13 " + label.encode("ascii")
    info = length.to_bytes(2, "big") + bytes((len(full),)) + full + bytes((len(context),)) + context
    return hkdf_expand(hash_name, secret, info, length)


def derive_secret(suite: CipherSuite, secret: bytes, label: str, transcript_hash: bytes) -> bytes:
    return hkdf_expand_label(suite.hash_name, secret, label, transcript_hash, suite.hash_len)


def finished_verify_data(suite: CipherSuite, base_secret: bytes, transcript_hash: bytes) -> bytes:
    finished_key = hkdf_expand_label(suite.hash_name, base_secret, "finished", b"", suite.hash_len)
    return hmac.new(finished_key, transcript_hash, suite.hash_name).digest()


def psk_binder(suite: CipherSuite, psk: bytes, truncated_transcript_hash: bytes) -> bytes:
    """Binder for a resumption PSK over the truncated ClientHello transcript."""
    early = hkdf_extract(suite.hash_name, bytes(suite.hash_len), psk)
    binder_key = derive_secret(suite, early, "res binder", suite.hash(b""))
    return finished_verify_data(suite, binder_key, truncated_transcript_hash)


def resumption_psk(suite: CipherSuite, resumption_master_secret: bytes, nonce: bytes) -> bytes:
    return hkdf_expand_label(suite.hash_name, resumption_master_secret, "resumption", nonce, suite.hash_len)


class TrafficKeys:
    """AEAD key and IV derived from one traffic secret."""

    __slots__ = ("secret", "key", "iv", "aead")

    def __init__(self, suite: CipherSuite, secret: bytes):
        self.secret = secret
        self.key = hkdf_expand_label(suite.hash_name, secret, "key", b"", suite.key_len)
        self.iv = hkdf_expand_label(suite.hash_name, secret, "iv", b"", IV_LEN)
        self.aead = suite.aead(self.key)

    @staticmethod
    def next_generation(suite: CipherSuite, secret: bytes) -> "TrafficKeys":
        """KeyUpdate: application_traffic_secret_N+1."""
        new = hkdf_expand_label(suite.hash_name, secret, "traffic upd", b"", suite.hash_len)
        return TrafficKeys(suite, new)


class KeySchedule:
    """The secrets of one connection as the handshake advances.

    ``psk`` is the resumption pre-shared key being offered; the early secret
    is derived from it (RFC 8446 7.1). When the server rejects the PSK the
    caller rebuilds the schedule without it.
    """

    def __init__(self, suite: CipherSuite, psk: Optional[bytes] = None):
        self.suite = suite
        h = suite.hash_name
        zeros = bytes(suite.hash_len)
        self.psk = psk
        self.early_secret = hkdf_extract(h, zeros, psk if psk else zeros)
        self.handshake_secret = b""
        self.master_secret = b""
        self.client_handshake_secret = b""
        self.server_handshake_secret = b""
        self.client_application_secret = b""
        self.server_application_secret = b""
        self.resumption_master_secret = b""

    def _derive(self, secret: bytes, label: str, transcript_hash: bytes) -> bytes:
        return derive_secret(self.suite, secret, label, transcript_hash)

    def set_shared_secret(self, shared: bytes, transcript_hash: bytes) -> Tuple[bytes, bytes]:
        """Derive the handshake secret and both handshake traffic secrets."""
        h = self.suite.hash_name
        empty_hash = self.suite.hash(b"")
        derived = self._derive(self.early_secret, "derived", empty_hash)
        self.handshake_secret = hkdf_extract(h, derived, shared)
        self.client_handshake_secret = self._derive(self.handshake_secret, "c hs traffic", transcript_hash)
        self.server_handshake_secret = self._derive(self.handshake_secret, "s hs traffic", transcript_hash)
        derived2 = self._derive(self.handshake_secret, "derived", empty_hash)
        self.master_secret = hkdf_extract(h, derived2, bytes(self.suite.hash_len))
        return self.client_handshake_secret, self.server_handshake_secret

    def application_secrets(self, transcript_hash: bytes) -> Tuple[bytes, bytes]:
        self.client_application_secret = self._derive(self.master_secret, "c ap traffic", transcript_hash)
        self.server_application_secret = self._derive(self.master_secret, "s ap traffic", transcript_hash)
        return self.client_application_secret, self.server_application_secret

    def resumption_secret(self, transcript_hash: bytes) -> bytes:
        """resumption_master_secret over the transcript through client Finished."""
        self.resumption_master_secret = self._derive(self.master_secret, "res master", transcript_hash)
        return self.resumption_master_secret

    def finished_verify_data(self, base_secret: bytes, transcript_hash: bytes) -> bytes:
        return finished_verify_data(self.suite, base_secret, transcript_hash)
