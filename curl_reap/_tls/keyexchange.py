"""(EC)DHE and hybrid key shares for the TLS 1.3 key_share extension.

Supported groups:

* X25519 (29), P-256 (23), P-384 (24), P-521 (25) through ``cryptography``.
* X25519MLKEM768 (0x11ec): ML-KEM-768 encapsulation key (1184 bytes) followed
  by the X25519 public key; shared secret = ML-KEM secret || X25519 secret
  (draft-ietf-tls-ecdhe-mlkem). ML-KEM-768 comes from
  ``cryptography.hazmat.primitives.asymmetric.mlkem`` when the installed
  build has it, otherwise from the pure-Python :mod:`.mlkem` (FIPS 203,
  verified against the NIST ACVP vectors).
* X25519Kyber768Draft00 (0x6399, chrome124 only): X25519 public key followed
  by the Kyber768 public key; server share = X25519 public || Kyber
  ciphertext; secret = X25519 secret || Kyber secret. Kyber round 3 shares
  its key format with ML-KEM, so the pure-Python module serves this group
  with its round 3 decapsulation.

ffdhe2048/ffdhe3072, which Firefox templates advertise, have no generator
here (BoringSSL has none either); a HelloRetryRequest for them fails with
:class:`UnsupportedGroupRequested`.
"""
from __future__ import annotations

from typing import Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

from .consts import (
    GROUP_SECP256R1,
    GROUP_SECP384R1,
    GROUP_SECP521R1,
    GROUP_X25519,
    GROUP_X25519KYBER768DRAFT00,
    GROUP_X25519MLKEM768,
)

MLKEM768_EK_LEN = 1184
MLKEM768_CT_LEN = 1088
X25519_LEN = 32
HYBRID_SHARE_LEN = MLKEM768_EK_LEN + X25519_LEN
HYBRID_SERVER_SHARE_LEN = MLKEM768_CT_LEN + X25519_LEN

_EC_CURVES = {
    GROUP_SECP256R1: (ec.SECP256R1, 65),
    GROUP_SECP384R1: (ec.SECP384R1, 97),
    GROUP_SECP521R1: (ec.SECP521R1, 133),
}

_SUPPORTED = (
    GROUP_X25519,
    GROUP_SECP256R1,
    GROUP_SECP384R1,
    GROUP_SECP521R1,
    GROUP_X25519MLKEM768,
    GROUP_X25519KYBER768DRAFT00,
)

#: Set to "pure" to force the pure-Python ML-KEM even when cryptography has it.
MLKEM_BACKEND: Optional[str] = None


def _cryptography_mlkem():
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem  # type: ignore
    except ImportError:
        return None
    if not hasattr(mlkem, "MLKEM768PrivateKey"):
        return None
    try:
        # Some builds expose the class but the linked OpenSSL lacks ML-KEM.
        mlkem.MLKEM768PrivateKey.generate()
    except Exception:
        return None
    return mlkem


_mlkem_module = None
_mlkem_probed = False


def mlkem768_backend() -> str:
    """Return ``"cryptography"`` or ``"pure"``: where ML-KEM-768 comes from."""
    global _mlkem_module, _mlkem_probed
    if MLKEM_BACKEND == "pure":
        return "pure"
    if not _mlkem_probed:
        _mlkem_module = _cryptography_mlkem()
        _mlkem_probed = True
    return "cryptography" if _mlkem_module is not None else "pure"


def can_generate(group: int) -> bool:
    return group in _SUPPORTED


class KeyShare:
    """One client key share: the public bytes to send plus the private half."""

    __slots__ = ("group", "public", "_private", "_kem_private", "_backend")

    def __init__(self, group: int, public: bytes, private, kem_private=None, backend: str = ""):
        self.group = group
        self.public = public
        self._private = private
        self._kem_private = kem_private
        self._backend = backend

    @classmethod
    def generate(cls, group: int) -> "KeyShare":
        if group == GROUP_X25519:
            priv = x25519.X25519PrivateKey.generate()
            return cls(group, priv.public_key().public_bytes_raw(), priv)
        if group in _EC_CURVES:
            curve_cls = _EC_CURVES[group][0]
            priv = ec.generate_private_key(curve_cls())
            pub = priv.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
            )
            return cls(group, pub, priv)
        if group == GROUP_X25519MLKEM768:
            xpriv = x25519.X25519PrivateKey.generate()
            xpub = xpriv.public_key().public_bytes_raw()
            if mlkem768_backend() == "cryptography":
                kem = _mlkem_module.MLKEM768PrivateKey.generate()
                ek = kem.public_key().public_bytes_raw()
                return cls(group, ek + xpub, xpriv, kem, "cryptography")
            from .mlkem import ML_KEM_768

            ek, dk = ML_KEM_768.keygen()
            return cls(group, ek + xpub, xpriv, dk, "pure")
        if group == GROUP_X25519KYBER768DRAFT00:
            from .mlkem import ML_KEM_768

            xpriv = x25519.X25519PrivateKey.generate()
            xpub = xpriv.public_key().public_bytes_raw()
            ek, dk = ML_KEM_768.keygen()
            return cls(group, xpub + ek, xpriv, dk, "pure")
        raise NotImplementedError("unsupported group %d" % group)

    @property
    def backend(self) -> str:
        return self._backend

    def _kem_decapsulate(self, ciphertext: bytes) -> bytes:
        if self._backend == "cryptography":
            return self._kem_private.decapsulate(ciphertext)
        from .mlkem import ML_KEM_768

        return ML_KEM_768.decaps(self._kem_private, ciphertext)

    def exchange(self, peer_public: bytes) -> bytes:
        """Compute the shared secret from the server's key_exchange bytes."""
        if self.group == GROUP_X25519:
            if len(peer_public) != X25519_LEN:
                raise ValueError("bad X25519 public length %d" % len(peer_public))
            secret = self._private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
            if secret == bytes(X25519_LEN):
                raise ValueError("all-zero X25519 shared secret")
            return secret
        if self.group in _EC_CURVES:
            curve_cls, expected = _EC_CURVES[self.group]
            if len(peer_public) != expected or peer_public[0] != 4:
                raise ValueError("bad uncompressed EC point for %s" % curve_cls.name)
            peer = ec.EllipticCurvePublicKey.from_encoded_point(curve_cls(), peer_public)
            return self._private.exchange(ec.ECDH(), peer)
        if self.group == GROUP_X25519MLKEM768:
            if len(peer_public) != HYBRID_SERVER_SHARE_LEN:
                raise ValueError("bad X25519MLKEM768 server share length %d" % len(peer_public))
            ct, xpub = peer_public[:MLKEM768_CT_LEN], peer_public[MLKEM768_CT_LEN:]
            x_ss = self._private.exchange(x25519.X25519PublicKey.from_public_bytes(xpub))
            if x_ss == bytes(X25519_LEN):
                raise ValueError("all-zero X25519 shared secret")
            return bytes(self._kem_decapsulate(ct)) + x_ss
        if self.group == GROUP_X25519KYBER768DRAFT00:
            if len(peer_public) != HYBRID_SERVER_SHARE_LEN:
                raise ValueError("bad X25519Kyber768Draft00 server share length %d" % len(peer_public))
            xpub, ct = peer_public[:X25519_LEN], peer_public[X25519_LEN:]
            x_ss = self._private.exchange(x25519.X25519PublicKey.from_public_bytes(xpub))
            if x_ss == bytes(X25519_LEN):
                raise ValueError("all-zero X25519 shared secret")
            from .mlkem import kyber768_decaps

            return x_ss + kyber768_decaps(self._kem_private, ct)
        raise NotImplementedError("unsupported group %d" % self.group)


def generate_shares(groups) -> Dict[int, KeyShare]:
    """Generate one share per group, in order; returns {group: KeyShare}."""
    out: Dict[int, KeyShare] = {}
    for group in groups:
        if group not in out:
            out[group] = KeyShare.generate(group)
    return out
