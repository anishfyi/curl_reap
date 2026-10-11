"""Trust store loading, chain verification, CertificateVerify and RFC 8879.

Chain building and policy checks are delegated to
``cryptography.x509.verification`` (a web-PKI verifier). Trust anchors come,
in order of preference, from the interpreter's OpenSSL default paths via
``ssl``, from ``certifi`` when installed, and from the usual distribution
bundle paths. ``verify=<path>`` loads that bundle instead (PEM, one or many
certificates, or a single DER certificate).
"""
from __future__ import annotations

import ipaddress
import os
import ssl
import threading
import warnings
from typing import List, Optional, Sequence, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from .consts import (
    CERT_COMPRESSION_BROTLI,
    CERT_COMPRESSION_ZLIB,
    CERT_COMPRESSION_ZSTD,
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_ECDSA_SECP521R1_SHA512,
    SIG_ED448,
    SIG_ED25519,
    SIG_RSA_PSS_PSS_SHA256,
    SIG_RSA_PSS_PSS_SHA384,
    SIG_RSA_PSS_PSS_SHA512,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PSS_RSAE_SHA512,
    SIGALG_NAMES,
)
from .errors import CertificateError

#: Bundle locations tried after ``ssl`` and ``certifi`` yield nothing.
BUNDLE_PATHS = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
    "/usr/local/etc/ssl/cert.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
)


class TrustStore:
    """A set of trust anchors plus a note on where they came from."""

    def __init__(self, certs: Sequence[x509.Certificate], source: str):
        if not certs:
            raise CertificateError("trust store is empty (%s)" % source)
        self.certs = list(certs)
        self.source = source
        self.store = Store(self.certs)

    def __len__(self) -> int:
        return len(self.certs)

    def __repr__(self) -> str:
        return "<TrustStore %d certificates from %s>" % (len(self.certs), self.source)


def load_certificates(data: bytes) -> List[x509.Certificate]:
    """Parse a PEM bundle (one or many certificates) or a single DER blob."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if b"-----BEGIN" in data:
            try:
                return x509.load_pem_x509_certificates(data)
            except ValueError as exc:
                raise CertificateError("cannot parse PEM bundle: %s" % exc) from exc
        try:
            return [x509.load_der_x509_certificate(data)]
        except ValueError as exc:
            raise CertificateError("cannot parse certificate bundle: %s" % exc) from exc


def load_bundle(path: Union[str, "os.PathLike[str]"]) -> TrustStore:
    path = os.fspath(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise CertificateError("cannot read CA bundle %s: %s" % (path, exc)) from exc
    certs = load_certificates(data)
    if not certs:
        raise CertificateError("CA bundle %s holds no certificates" % path)
    return TrustStore(certs, path)


def _from_ssl() -> List[x509.Certificate]:
    try:
        ctx = ssl.create_default_context()
        ders = ctx.get_ca_certs(binary_form=True)
    except Exception:
        return []
    out: List[x509.Certificate] = []
    # Vendor stores carry a few roots with non-positive serials; cryptography
    # warns about them and will refuse them one day, so parse quietly and skip.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for der in ders:
            try:
                out.append(x509.load_der_x509_certificate(der))
            except ValueError:
                continue
    return out


def _from_certifi() -> Optional[str]:
    try:
        import certifi  # type: ignore
    except ImportError:
        return None
    path = certifi.where()
    return path if os.path.exists(path) else None


def load_default_trust_store() -> TrustStore:
    certs = _from_ssl()
    if certs:
        paths = ssl.get_default_verify_paths()
        return TrustStore(certs, "ssl default (%s)" % (paths.cafile or paths.capath or "builtin"))
    certifi_path = _from_certifi()
    if certifi_path:
        try:
            return load_bundle(certifi_path)
        except CertificateError:
            pass
    for candidate in BUNDLE_PATHS:
        if os.path.exists(candidate):
            try:
                return load_bundle(candidate)
            except CertificateError:
                continue
    raise CertificateError(
        "no CA certificates found: the ssl module has none, certifi is not installed "
        "and no system bundle exists; pass verify=<bundle path>"
    )


_default_store: Optional[TrustStore] = None
_default_lock = threading.Lock()
_bundle_cache = {}


def default_trust_store() -> TrustStore:
    global _default_store
    if _default_store is None:
        with _default_lock:
            if _default_store is None:
                _default_store = load_default_trust_store()
    return _default_store


def trust_store_for(verify) -> Optional[TrustStore]:
    """Resolve the ``verify`` argument: True, False, a path or a TrustStore."""
    if verify is False or verify is None:
        return None
    if verify is True:
        return default_trust_store()
    if isinstance(verify, TrustStore):
        return verify
    path = os.fspath(verify)
    try:
        mtime = os.stat(path).st_mtime
    except OSError as exc:
        raise CertificateError("cannot read CA bundle %s: %s" % (path, exc)) from exc
    cached = _bundle_cache.get(path)
    if cached is not None and cached[0] == mtime:
        return cached[1]
    store = load_bundle(path)
    _bundle_cache[path] = (mtime, store)
    return store


def parse_chain(chain_der: Sequence[bytes]) -> List[x509.Certificate]:
    try:
        return [x509.load_der_x509_certificate(der) for der in chain_der]
    except ValueError as exc:
        raise CertificateError("unparseable certificate from server: %s" % exc) from exc


def subject_for(server_name: str):
    """DNSName or IPAddress subject for the verifier."""
    try:
        return x509.IPAddress(ipaddress.ip_address(server_name))
    except ValueError:
        pass
    name = server_name.rstrip(".")
    try:
        name.encode("ascii")
    except UnicodeEncodeError:
        name = name.encode("idna").decode("ascii")
    try:
        return x509.DNSName(name)
    except ValueError as exc:
        raise CertificateError("invalid server name %r: %s" % (server_name, exc)) from exc


def verify_chain(store: TrustStore, server_name: str, chain: Sequence[x509.Certificate]) -> List[x509.Certificate]:
    """Verify the server chain for ``server_name``; returns the validated path."""
    if not chain:
        raise CertificateError("empty certificate chain")
    builder = PolicyBuilder().store(store.store)
    verifier = builder.build_server_verifier(subject_for(server_name))
    try:
        return verifier.verify(chain[0], list(chain[1:]))
    except VerificationError as exc:
        raise CertificateError("certificate verify failed for %s: %s" % (server_name, exc)) from exc
    except Exception as exc:  # pragma: no cover - unexpected verifier failure
        raise CertificateError("certificate verify failed for %s: %s" % (server_name, exc)) from exc


_CONTEXT_STRING = b"TLS 1.3, server CertificateVerify"
_PSS = {
    SIG_RSA_PSS_RSAE_SHA256: hashes.SHA256,
    SIG_RSA_PSS_RSAE_SHA384: hashes.SHA384,
    SIG_RSA_PSS_RSAE_SHA512: hashes.SHA512,
    SIG_RSA_PSS_PSS_SHA256: hashes.SHA256,
    SIG_RSA_PSS_PSS_SHA384: hashes.SHA384,
    SIG_RSA_PSS_PSS_SHA512: hashes.SHA512,
}
_ECDSA = {
    SIG_ECDSA_SECP256R1_SHA256: (ec.SECP256R1, hashes.SHA256),
    SIG_ECDSA_SECP384R1_SHA384: (ec.SECP384R1, hashes.SHA384),
    SIG_ECDSA_SECP521R1_SHA512: (ec.SECP521R1, hashes.SHA512),
}


def certificate_verify_content(transcript_hash: bytes) -> bytes:
    return b"\x20" * 64 + _CONTEXT_STRING + b"\x00" + transcript_hash


def verify_certificate_verify(leaf: x509.Certificate, scheme: int, signature: bytes, transcript_hash: bytes) -> None:
    key = leaf.public_key()
    content = certificate_verify_content(transcript_hash)
    name = SIGALG_NAMES.get(scheme, hex(scheme))
    try:
        if scheme in _PSS:
            if not isinstance(key, rsa.RSAPublicKey):
                raise CertificateError("%s but leaf key is %s" % (name, type(key).__name__))
            digest = _PSS[scheme]()
            key.verify(
                signature,
                content,
                padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size),
                digest,
            )
        elif scheme in _ECDSA:
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise CertificateError("%s but leaf key is %s" % (name, type(key).__name__))
            curve, digest = _ECDSA[scheme]
            if not isinstance(key.curve, curve):
                raise CertificateError("%s but leaf curve is %s" % (name, key.curve.name))
            key.verify(signature, content, ec.ECDSA(digest()))
        elif scheme == SIG_ED25519:
            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise CertificateError("%s but leaf key is %s" % (name, type(key).__name__))
            key.verify(signature, content)
        elif scheme == SIG_ED448:
            if not isinstance(key, ed448.Ed448PublicKey):
                raise CertificateError("%s but leaf key is %s" % (name, type(key).__name__))
            key.verify(signature, content)
        else:
            raise CertificateError("unsupported CertificateVerify scheme %s" % name)
    except CertificateError:
        raise
    except Exception as exc:  # InvalidSignature and friends
        raise CertificateError("CertificateVerify %s signature invalid: %s" % (name, exc)) from exc


def sign_certificate_verify(private_key, scheme: int, transcript_hash: bytes) -> bytes:
    """Server-side counterpart used by the test server."""
    content = certificate_verify_content(transcript_hash)
    if scheme in _PSS:
        digest = _PSS[scheme]()
        return private_key.sign(content, padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size), digest)
    if scheme in _ECDSA:
        return private_key.sign(content, ec.ECDSA(_ECDSA[scheme][1]()))
    if scheme in (SIG_ED25519, SIG_ED448):
        return private_key.sign(content)
    raise CertificateError("unsupported CertificateVerify scheme %s" % SIGALG_NAMES.get(scheme, hex(scheme)))


def _zstd_decompress(data: bytes, max_size: int) -> bytes:
    try:
        from compression import zstd as _zstd  # type: ignore  # Python 3.14
    except ImportError:
        _zstd = None
    if _zstd is not None:
        return _zstd.decompress(data)
    try:
        import zstandard  # type: ignore
    except ImportError as exc:
        raise CertificateError("server sent a zstd compressed certificate but no zstd module is importable") from exc
    return zstandard.ZstdDecompressor().decompress(data, max_output_size=max_size)


def has_zstd() -> bool:
    try:
        from compression import zstd  # type: ignore  # noqa: F401

        return True
    except ImportError:
        pass
    try:
        import zstandard  # type: ignore  # noqa: F401

        return True
    except ImportError:
        return False


def has_brotli() -> bool:
    try:
        import brotli  # type: ignore  # noqa: F401

        return True
    except ImportError:
        return False


def available_compression_algorithms(requested: Sequence[int]) -> List[int]:
    """Filter the template's compress_certificate list by what we can inflate."""
    out = []
    for alg in requested:
        if alg == CERT_COMPRESSION_ZLIB:
            out.append(alg)
        elif alg == CERT_COMPRESSION_BROTLI and has_brotli():
            out.append(alg)
        elif alg == CERT_COMPRESSION_ZSTD and has_zstd():
            out.append(alg)
    return out


def decompress_certificate(algorithm: int, data: bytes, uncompressed_length: int) -> bytes:
    """RFC 8879: inflate a CompressedCertificate payload."""
    if uncompressed_length > (1 << 24) - 1:
        raise CertificateError("uncompressed_length out of range")
    if algorithm == CERT_COMPRESSION_BROTLI:
        try:
            import brotli  # type: ignore
        except ImportError as exc:
            raise CertificateError("server sent a brotli compressed certificate but brotli is not importable") from exc
        try:
            out = brotli.decompress(data)
        except Exception as exc:
            raise CertificateError("brotli decompression failed: %s" % exc) from exc
    elif algorithm == CERT_COMPRESSION_ZLIB:
        import zlib

        try:
            out = zlib.decompressobj().decompress(data, uncompressed_length + 1)
        except zlib.error as exc:
            raise CertificateError("zlib decompression failed: %s" % exc) from exc
    elif algorithm == CERT_COMPRESSION_ZSTD:
        try:
            out = _zstd_decompress(data, uncompressed_length)
        except CertificateError:
            raise
        except Exception as exc:
            raise CertificateError("zstd decompression failed: %s" % exc) from exc
    else:
        raise CertificateError("unknown certificate compression algorithm %d" % algorithm)
    if len(out) != uncompressed_length:
        raise CertificateError("decompressed certificate length mismatch")
    return out


def compress_certificate(algorithm: int, data: bytes) -> bytes:
    """Server-side counterpart used by the test server."""
    if algorithm == CERT_COMPRESSION_BROTLI:
        import brotli  # type: ignore

        return brotli.compress(data)
    if algorithm == CERT_COMPRESSION_ZLIB:
        import zlib

        return zlib.compress(data)
    if algorithm == CERT_COMPRESSION_ZSTD:
        try:
            from compression import zstd as _zstd  # type: ignore

            return _zstd.compress(data)
        except ImportError:
            import zstandard  # type: ignore

            return zstandard.ZstdCompressor().compress(data)
    raise CertificateError("unknown certificate compression algorithm %d" % algorithm)
