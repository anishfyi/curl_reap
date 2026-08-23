"""TLS and header profiles for :mod:`curl_reap`'s standard-library transport.

Two layers of browser mimicry live here:

* TLS shaping via ``ssl.SSLContext``: pre-TLS-1.3 cipher ordering, minimum
  protocol version, an ECDH curve hint, ALPN, and OpenSSL options.
* Header-set impersonation: full, order-exact browser header sets including
  Client Hints (``sec-ch-ua``), ``sec-fetch-*``, and matching User-Agent
  versions. This layer is byte-perfect because we serialize requests ourselves.

Honesty section: this is deliberately *not* advertised as exact JA3
impersonation. The standard library cannot control extension ordering,
GREASE values, TLS 1.3 cipher ordering, signature-algorithm ordering,
supported-group ordering, key-share ordering, record layout, or HTTP/2
settings, and this transport speaks HTTP/1.1 only. Sophisticated
fingerprinters inspecting the raw ClientHello will still distinguish it.
Sites that score HTTP-layer signals (headers, order, consistency between
User-Agent and Client Hints) see a faithful browser.
"""
from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Union


HeaderTuple = Tuple[Tuple[str, str], ...]


@dataclass(frozen=True)
class Profile:
    """A best-effort browser profile within stdlib ``ssl`` limits.

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
        object.__setattr__(self, "headers", tuple(tuple(h) for h in self.headers))
        if not self.alpn_protocols:
            raise ValueError("profile must define at least one ALPN protocol")
        for item in self.headers:
            if len(item) != 2:
                raise ValueError("profile headers must be (name, value) pairs")


_CIPHERS_TLS12_BASE = (
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
)

_CHROME_CIPHERS = _CIPHERS_TLS12_BASE + (
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


def _accept_chrome() -> str:
    return ("text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7")


def _chrome_headers(major: int, platform: str = "Windows",
                    ua_platform: str = 'Windows NT 10.0; Win64; x64') -> HeaderTuple:
    """Chrome navigation header set, in the order Chrome 110+ emits it."""
    brands = ('"Chromium";v="%d", "Google Chrome";v="%d", "Not-A.Brand";v="99"'
              % (major, major))
    return (
        ("sec-ch-ua", brands),
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", '"%s"' % platform),
        ("Upgrade-Insecure-Requests", "1"),
        ("User-Agent", "Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like "
         "Gecko) Chrome/%d.0.0.0 Safari/537.36" % (ua_platform, major)),
        ("Accept", _accept_chrome()),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-User", "?1"),
        ("Sec-Fetch-Dest", "document"),
        ("Accept-Encoding", "gzip, deflate"),
        ("Accept-Language", "en-US,en;q=0.9"),
    )


def _edge_headers(major: int) -> HeaderTuple:
    headers = list(_chrome_headers(major))
    rewritten = []
    for name, value in headers:
        if name == "sec-ch-ua":
            value = ('"Chromium";v="%d", "Microsoft Edge";v="%d", '
                     '"Not-A.Brand";v="99"' % (major, major))
        elif name == "User-Agent":
            value = value.replace("Chrome/%d.0.0.0" % major,
                                  "Chrome/%d.0.0.0" % major) + " Edg/%d.0.0.0" % major
        rewritten.append((name, value))
    return tuple(rewritten)


def _firefox_headers(major: int, minor: int = 0) -> HeaderTuple:
    """Firefox navigation headers; Firefox sends no Client Hints."""
    version = "%d.0" % major if minor == 0 else "%d.%d" % (major, minor)
    return (
        ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%s) "
         "Gecko/20100101 Firefox/%s" % (version, version)),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
         "image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        ("Accept-Encoding", "gzip, deflate"),
        ("Accept-Language", "en-US,en;q=0.5"),
    )


def _safari_headers(major: int, minor: int = 0) -> HeaderTuple:
    version = "%d.%s" % (major, minor)
    ua = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
          "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Safari/605.1.15"
          % version)
    headers = [
        ("User-Agent", ua),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("Accept-Encoding", "gzip, deflate"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Upgrade-Insecure-Requests", "1"),
    ]
    if (major, minor) >= (16, 4):
        headers[3:3] = [
            ("Sec-Fetch-Dest", "document"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Site", "none"),
            ("Sec-Fetch-User", "?1"),
        ]
    return tuple(headers)


# ---------------------------------------------------------------------------
# Target registry. Keys follow the curl_cffi convention so migrating code
# keeps working; values are best-effort behavioural equivalents, not binary
# clones of the named browsers' ClientHellos.
# ---------------------------------------------------------------------------

_CHROME_MAJORS = (98, 101, 104, 107, 110, 116, 119, 120, 123, 124, 126,
                  128, 129, 130, 131, 133)
_FIREFOX_MAJORS = (95, 102, 109, 117, 127, 128, 132, 133, 135)
_SAFARI_VERSIONS = ((15, 3), (15, 5), (16, 0), (16, 4), (17, 0), (17, 2), (18, 0))


def _build_fingerprints() -> Dict[str, Profile]:
    registry: Dict[str, Profile] = {}

    def register(profile: Profile):
        registry[profile.name.lower()] = profile

    for major in _CHROME_MAJORS:
        register(Profile(name="chrome%d" % major, ciphers=_CHROME_CIPHERS,
                         headers=_chrome_headers(major)))
    for major in _CHROME_MAJORS[-6:]:
        register(Profile(name="edge%d" % major, ciphers=_CHROME_CIPHERS,
                         headers=_edge_headers(major)))
    for major in _FIREFOX_MAJORS:
        register(Profile(name="firefox%d" % major, ciphers=_FIREFOX_CIPHERS,
                         headers=_firefox_headers(major)))
    for major, minor in _SAFARI_VERSIONS:
        name = "safari%d_%d" % (major, minor)
        register(Profile(name=name, ciphers=_SAFARI_CIPHERS,
                         headers=_safari_headers(major, minor)))

    # Friendly one-word names point at current stable versions. The
    # profile's own name stays the short word so rotation logs read well.
    from dataclasses import replace as _dc_replace
    registry["chrome"] = _dc_replace(registry["chrome131"], name="chrome")
    registry["edge"] = _dc_replace(registry["edge131"], name="edge")
    registry["firefox"] = _dc_replace(registry["firefox135"], name="firefox")
    registry["safari"] = _dc_replace(registry["safari18_0"], name="safari")
    return registry


FINGERPRINTS: Dict[str, Profile] = _build_fingerprints()

#: Canonical short names, kept separate so ``PROFILES`` stays small.
PROFILES: Dict[str, Profile] = {
    "chrome": FINGERPRINTS["chrome"],
    "firefox": FINGERPRINTS["firefox"],
    "safari": FINGERPRINTS["safari"],
}


def _normalize_target(name: str) -> str:
    # Accept curl_cffi's alternate spellings: safari170 == safari17_0,
    # Chrome124 / CHROME124 == chrome124.
    lowered = name.strip().lower()
    if lowered in FINGERPRINTS:
        return lowered
    stripped = lowered.replace("_", "").replace(".", "")
    for key, profile in FINGERPRINTS.items():
        if key.replace("_", "") == stripped:
            return key
    return lowered


def resolve_profile(profile: Union[str, Profile]) -> Profile:
    """Return a concrete profile from a name, target string or Profile."""
    if isinstance(profile, Profile):
        return profile
    if not isinstance(profile, str):
        raise TypeError("profile must be a profile name, impersonate target "
                        "or Profile instance")
    key = _normalize_target(profile)
    try:
        return FINGERPRINTS[key]
    except KeyError:
        pass
    try:
        return PROFILES[key]
    except KeyError:
        choices = ", ".join(sorted(PROFILES) + sorted(FINGERPRINTS)[:9])
        raise ValueError("unknown TLS profile or impersonate target %r; try "
                         "'chrome', 'firefox', 'safari' or a versioned target "
                         "such as chrome124, firefox133, safari17_0 (%s ...)"
                         % (profile, choices))


def create_ssl_context(profile: Union[str, Profile] = "chrome", verify=True,
                       alpn=("http/1.1",)):
    """Build an ``SSLContext`` for a profile.

    ``verify`` may be ``False`` (disable certificate checks), ``True`` (system
    trust store), or a CA bundle path.  ``alpn`` lists the protocols to offer;
    the transport only advertises protocols it can actually speak.
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
        try:
            context.set_alpn_protocols(list(alpn))
        except ValueError:
            # OpenSSL build without a protocol: keep the safe default.
            context.set_alpn_protocols(["http/1.1"])
    return context


__all__ = ["Profile", "PROFILES", "FINGERPRINTS", "create_ssl_context",
           "resolve_profile"]
