"""TLS 1.3 record protection (RFC 8446 section 5.2).

One ``RecordCipher`` per direction. ``encrypt`` returns a full TLSCiphertext
record; ``decrypt`` takes the 5-byte header plus ciphertext and returns the
inner content type and the content with padding removed.
"""
from __future__ import annotations

from typing import Tuple

from cryptography.exceptions import InvalidTag

from .consts import CT_APPLICATION_DATA, MAX_PLAINTEXT, TLS12
from .keyschedule import CipherSuite, TrafficKeys
from .wire import record_header

# RFC 8446 5.5: an implementation must rekey before 2^24.5 records for
# AES-GCM; we stop far earlier and let the engine send a KeyUpdate.
SEQ_LIMIT = 1 << 24


class RecordProtectionError(Exception):
    """Decryption failed (bad_record_mac) or the inner plaintext is malformed."""


class RecordCipher:
    __slots__ = ("suite", "keys", "seq", "generation")

    def __init__(self, suite: CipherSuite, secret: bytes):
        self.suite = suite
        self.keys = TrafficKeys(suite, secret)
        self.seq = 0
        self.generation = 0

    def update(self) -> None:
        """Advance to the next generation (KeyUpdate)."""
        self.keys = TrafficKeys.next_generation(self.suite, self.keys.secret)
        self.seq = 0
        self.generation += 1

    def _nonce(self) -> bytes:
        iv = self.keys.iv
        seq = self.seq.to_bytes(len(iv), "big")
        return bytes(a ^ b for a, b in zip(iv, seq))

    def encrypt(self, content_type: int, plaintext: bytes, padding: int = 0) -> bytes:
        # TLSInnerPlaintext may carry 2^14 bytes of content plus the type byte.
        if len(plaintext) + padding > MAX_PLAINTEXT:
            raise ValueError("plaintext exceeds one record")
        if self.seq >= (1 << 62):
            raise RecordProtectionError("sequence number exhausted")
        inner = plaintext + bytes((content_type,)) + bytes(padding)
        length = len(inner) + 16
        aad = record_header(CT_APPLICATION_DATA, TLS12, length)
        ciphertext = self.keys.aead.encrypt(self._nonce(), inner, aad)
        self.seq += 1
        return aad + ciphertext

    def decrypt(self, header: bytes, ciphertext: bytes) -> Tuple[int, bytes]:
        try:
            inner = self.keys.aead.decrypt(self._nonce(), ciphertext, header)
        except InvalidTag as exc:
            raise RecordProtectionError("bad_record_mac") from exc
        self.seq += 1
        # Strip zero padding; the last non-zero byte is the content type.
        end = len(inner)
        while end > 0 and inner[end - 1] == 0:
            end -= 1
        if end == 0:
            raise RecordProtectionError("inner plaintext has no content type")
        return inner[end - 1], inner[:end - 1]
