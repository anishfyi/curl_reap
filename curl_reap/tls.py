"""TLS profiles for :mod:`curl_reap`'s standard-library transport.

The profiles in this module shape the parts of a TLS client hello exposed by
Python's :mod:`ssl`: pre-TLS-1.3 cipher ordering, the minimum TLS version, one
ECDH curve hint, ALPN, certificate verification, and a few OpenSSL options.

This is deliberately *not* advertised as exact browser or JA3 impersonation.
The standard library cannot control extension ordering, GREASE values, TLS
1.3 cipher ordering, signature-algorithm ordering, supported-group ordering,
key-share ordering, record layout, or HTTP/2 settings.  In addition, curl_reap
speaks HTTP/1.1, so it advertises only ``http/1.1`` even though the browser
profiles record the browser's usual ALPN preferences.  Sites requiring an
exact browser ClientHello will still be able to distinguish this transport.
"""
from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Union


HeaderTuple = Tuple[Tuple[str, str], ...]


@dataclass(frozen=True)
class Profile:
    """A best-effort browser family profile within stdlib ``ssl`` limits.

    Custom profiles may be passed directly to ``Session(profile=...)``.  The
    ``headers`` sequence is ordered and case-preserving because both details
    are visible to HTTP fingerprinting systems.
    """

    name: str
    ciphers: Tuple[str, ...] = ()
    alpn_protocols: Tuple[str, ...] = ("h2", "http/1.1")
    headers: HeaderTuple = ()
    curve: Optional[str] = "X25519"
    minimum_version: str = "TLSv1_2"

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("profile name must be a non-empty string")
        object.__setattr__(self, "ciphers", tuple(self.ciphers))
        object.__setattr__(self, "alpn_protocols", tuple(self.alpn_protocols))
        object.__setattr__(self, "headers", tuple(tuple(item) for item in self.headers))
        if not self.alpn_protocols:
            raise ValueError("profile must define at least one ALPN protocol")
        for item in self.headers:
            if len(item) != 2:
                raise ValueError("profile headers must be (name, value) pairs")


_CHROME_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
)

_FIREFOX_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
)

_SAFARI_CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
)


PROFILES: Dict[str, Profile] = {
    "chrome": Profile(
        name="chrome",
        ciphers=_CHROME_CIPHERS,
        headers=(
            ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
             "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
             "image/avif,image/webp,*/*;q=0.8"),
            ("Accept-Language", "en-US,en;q=0.9"),
            ("Accept-Encoding", "gzip, deflate"),
            ("Upgrade-Insecure-Requests", "1"),
        ),
    ),
    "firefox": Profile(
        name="firefox",
        ciphers=_FIREFOX_CIPHERS,
        headers=(
            ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) "
             "Gecko/20100101 Firefox/126.0"),
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
             "image/avif,image/webp,*/*;q=0.8"),
            ("Accept-Language", "en-US,en;q=0.5"),
            ("Accept-Encoding", "gzip, deflate"),
            ("Upgrade-Insecure-Requests", "1"),
        ),
    ),
    "safari": Profile(
        name="safari",
        ciphers=_SAFARI_CIPHERS,
        headers=(
            ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"),
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            ("Accept-Language", "en-US,en;q=0.9"),
            ("Accept-Encoding", "gzip, deflate"),
        ),
    ),
}


def resolve_profile(profile: Union[str, Profile]) -> Profile:
    """Return a concrete profile, rejecting unknown names and invalid values."""
    if isinstance(profile, Profile):
        return profile
    if not isinstance(profile, str):
        raise TypeError("profile must be a profile name or Profile instance")
    try:
        return PROFILES[profile.lower()]
    except KeyError:
        choices = ", ".join(sorted(PROFILES))
        raise ValueError("unknown TLS profile %r; choose one of: %s" % (profile, choices))


def create_ssl_context(profile: Union[str, Profile] = "chrome", verify=True):
    """Build an ``SSLContext`` for a profile.

    ``verify`` may be ``False`` (disable certificate checks), ``True`` (system
    trust store), or a CA bundle path.  Only HTTP/1.1 is offered over ALPN: the
    transport has no HTTP/2 framing implementation and must not negotiate h2.
    """
    selected = resolve_profile(profile)
    cafile = verify if isinstance(verify, str) else None
    context = ssl.create_default_context(cafile=cafile)
    if verify is False:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    version_name = {"TLSv1.2": "TLSv1_2", "TLSv1.3": "TLSv1_3"}.get(
        selected.minimum_version, selected.minimum_version)
    tls_version = getattr(getattr(ssl, "TLSVersion", object()), version_name, None)
    if tls_version is not None:
        context.minimum_version = tls_version
    if hasattr(ssl, "OP_NO_COMPRESSION"):
        context.options |= ssl.OP_NO_COMPRESSION

    if selected.ciphers:
        # set_ciphers affects TLS <= 1.2 only.  CPython exposes no portable API
        # for TLS 1.3 cipher-suite order.
        context.set_ciphers(":".join(selected.ciphers))
    if selected.curve and hasattr(context, "set_ecdh_curve"):
        try:
            context.set_ecdh_curve(selected.curve)
        except (ValueError, ssl.SSLError):
            # OpenSSL builds differ in curve naming/support.  The secure
            # default group selection is preferable to rejecting the profile.
            pass
    if hasattr(context, "set_alpn_protocols"):
        context.set_alpn_protocols(["http/1.1"])
    return context


__all__ = ["Profile", "PROFILES", "create_ssl_context", "resolve_profile"]
