"""Impersonate target registry for :mod:`curl_reap`.

A :class:`Profile` describes one browser identity: the HTTP/1.1 and HTTP/2
header sets in the exact order the browser sends them, the name of the TLS
ClientHello template the native engine (``curl_reap._tls``) reproduces, the
name of the HTTP/2 spec (``curl_reap._h2``: SETTINGS, WINDOW_UPDATE, priority,
pseudo-header order) and the small set of ``ssl.SSLContext`` knobs used when
the native engine is unavailable.

The registry data lives in the generated module :mod:`curl_reap._profiles_data`
(``tools/gen_profiles.py`` builds it from the reference client's captures under
``tools/h2_templates`` and ``tools/hello_templates``).  Every target name
the reference browser-impersonation client accepts resolves here to the same concrete target, and its
header sets are the ones the reference client sends for that target.  curl_reap 1.x
names that the reference client never had (``chrome98``, ``edge131``, ``firefox127``,
``safari16_0`` and so on) are kept as approximations: they borrow the nearest
captured target and only substitute their own version number into the
User-Agent and ``sec-ch-ua`` values.

Honesty section.  With the native engine the bytes on the wire reproduce the
captured ClientHello (cipher order, extension set and order, GREASE, key
shares including the post-quantum hybrid, ALPS, ECH GREASE, padding rule),
measured as the same JA4 and peetprint as the reference client.  :func:`create_ssl_context`
remains the best-effort fallback on the standard library ``ssl`` module: it
can set the pre-TLS-1.3 cipher order, the minimum version, an ECDH curve
hint and ALPN, and nothing else.  The transport reports which path a
connection used (``Response.infos["tls_backend"]``); when it says ``"openssl"`` the
TLS fingerprint is OpenSSL's, only the HTTP layer is the browser's.
"""
from __future__ import annotations

import re
import ssl
from dataclasses import dataclass, replace as _dc_replace
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple, Union

from . import _profiles_data as _data
from .exceptions import ImpersonateError

HeaderTuple = Tuple[Tuple[str, str], ...]

#: Families known to the registry.  ``custom`` is what a hand-built
#: :class:`Profile` gets when it names no family.
FAMILIES: Tuple[str, ...] = ("chrome", "edge", "firefox", "safari", "tor")

# The multipart boundary rule per family (curl_reap.multipart.boundary_for).
_FORM_BOUNDARY = {"chrome": "chrome", "edge": "edge", "safari": "safari",
                  "firefox": "firefox", "tor": "firefox"}


class UnknownProfileError(ImpersonateError, ValueError):
    """An impersonate target or profile name the registry does not know.

    It is an :class:`~curl_reap.exceptions.ImpersonateError` (the reference client's
    name for the same situation) and a ``ValueError`` (what curl_reap 1.x
    raised), so both ``except`` clauses keep working.
    """


@dataclass(frozen=True)
class Profile:
    """One browser identity.

    Built-in profiles come from the registry; custom ones may be passed to
    ``Session(profile=...)``.  ``headers`` is the HTTP/1.1 header set, ordered
    and case-preserving, without ``Host`` (the transport adds it first) and
    without the libcurl ``Upgrade``/``HTTP2-Settings``/``Connection`` tell.
    ``h2_headers`` is the HTTP/2 set with lowercase names; ``None`` means
    "derive from ``headers``" (see :func:`profile_for_h2`).  ``tls_template``
    and ``h2_spec`` are keys into the native engines' template tables;
    ``None`` means the OpenSSL path and HTTP/1.1 only.  The remaining fields
    feed :func:`create_ssl_context` on the fallback path.
    """

    name: str
    family: str = "custom"
    version: str = ""
    headers: HeaderTuple = ()
    h2_headers: Optional[HeaderTuple] = None
    tls_template: Optional[str] = None
    h2_spec: Optional[str] = None
    accept_encoding: str = ""
    form_boundary: str = ""
    ciphers: Tuple[str, ...] = ()
    alpn_protocols: Tuple[str, ...] = ("h2", "http/1.1")
    curve: Optional[str] = "X25519"
    minimum_version: str = "TLSv1_2"

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("profile name must be a non-empty string")
        if not isinstance(self.family, str) or not self.family:
            raise ValueError("profile family must be a non-empty string")
        object.__setattr__(self, "ciphers", tuple(self.ciphers))
        object.__setattr__(self, "alpn_protocols", tuple(self.alpn_protocols))
        object.__setattr__(self, "headers", _coerce_headers(self.headers))
        if self.h2_headers is not None:
            object.__setattr__(self, "h2_headers", _coerce_headers(self.h2_headers))
        if not self.alpn_protocols:
            raise ValueError("profile must define at least one ALPN protocol")
        if not self.accept_encoding:
            found = _header_value(self.headers, "accept-encoding")
            if found is None and self.h2_headers:
                found = _header_value(self.h2_headers, "accept-encoding")
            object.__setattr__(self, "accept_encoding", found or "")
        if not self.form_boundary:
            object.__setattr__(self, "form_boundary",
                               _FORM_BOUNDARY.get(self.family.lower(), "other"))

    @property
    def user_agent(self) -> Optional[str]:
        """The User-Agent value of the HTTP/1.1 header set, if any."""
        return _header_value(self.headers, "user-agent")

    @property
    def native(self) -> bool:
        """True when the profile names a ClientHello template for the native engine."""
        return self.tls_template is not None


def _coerce_headers(headers: Iterable[Any]) -> HeaderTuple:
    out = []
    for item in headers:
        pair = tuple(item)
        if len(pair) != 2 or not all(isinstance(p, str) for p in pair):
            raise ValueError("profile headers must be (name, value) string pairs")
        out.append(pair)
    return tuple(out)


def _header_value(headers: Sequence[Tuple[str, str]], name: str) -> Optional[str]:
    lname = name.lower()
    for key, value in headers:
        if key.lower() == lname:
            return value
    return None


# ---------------------------------------------------------------------------
# OpenSSL fallback cipher tables (TLS 1.2 order; TLS 1.3 suites are not
# configurable through the standard library).
# ---------------------------------------------------------------------------

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

_FAMILY_CIPHERS = {
    "chrome": _CHROME_CIPHERS,
    "edge": _CHROME_CIPHERS,
    "firefox": _FIREFOX_CIPHERS,
    "tor": _FIREFOX_CIPHERS,
    "safari": _SAFARI_CIPHERS,
}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def _profile_from_entry(name: str, entry: Mapping[str, Any]) -> Profile:
    family = entry["family"]
    return Profile(
        name=name,
        family=family,
        version=entry["version"],
        headers=tuple(entry["h1_headers"]),
        h2_headers=tuple(entry["h2_headers"]),
        tls_template=entry["tls_template"],
        h2_spec=entry["h2_spec"],
        accept_encoding=entry["accept_encoding"],
        form_boundary=entry["form_boundary"],
        ciphers=_FAMILY_CIPHERS[family],
    )


def _build_registry() -> Tuple[Dict[str, Profile], Dict[str, str], Dict[str, str]]:
    registry: Dict[str, Profile] = {}
    for name, entry in _data.CONCRETE.items():
        registry[name] = _profile_from_entry(name, entry)
    aliases: Dict[str, str] = {}
    for alias, concrete in _data.ALIASES.items():
        # The alias keeps its own name (``resolve_profile("chrome").name ==
        # "chrome"``, as in 1.x) but is otherwise the concrete target.
        registry[alias] = _dc_replace(registry[concrete], name=alias)
        aliases[alias] = concrete
    legacy: Dict[str, str] = {}
    for name, entry in _data.LEGACY.items():
        registry[name] = _profile_from_entry(name, entry)
        legacy[name] = entry["nearest"]
    return registry, aliases, legacy


FINGERPRINTS: Dict[str, Profile]
#: alias name -> concrete target (the reference client's map plus deprecated spellings).
ALIASES: Dict[str, str]
#: curl_reap 1.x name -> the captured target it approximates.
LEGACY: Dict[str, str]
FINGERPRINTS, ALIASES, LEGACY = _build_registry()

#: Concrete targets in registry order: the names the reference client ships natively.
TARGETS: Tuple[str, ...] = tuple(_data.CONCRETE)

#: Canonical short names, kept separate so ``PROFILES`` stays small.
PROFILES: Dict[str, Profile] = {
    "chrome": FINGERPRINTS["chrome"],
    "firefox": FINGERPRINTS["firefox"],
    "safari": FINGERPRINTS["safari"],
}

_SQUASHED = {key.replace("_", "").replace(".", ""): key for key in FINGERPRINTS}


def _normalize_target(name: str) -> str:
    """Accept the common alternate spellings.

    ``Chrome124`` and ``CHROME124`` are ``chrome124``; underscores and dots
    are ignored when no exact key exists, so ``safari17.0`` and ``safari17_0``
    both work and ``safari26_0`` reaches ``safari260``.
    """
    lowered = name.strip().lower()
    if lowered in FINGERPRINTS:
        return lowered
    return _SQUASHED.get(lowered.replace("_", "").replace(".", ""), lowered)


def canonical_target(profile: Union[str, Profile]) -> str:
    """The registry key a name resolves to, with aliases followed.

    ``chrome`` gives ``chrome150``, ``safari17_0`` gives ``safari170``, a
    concrete or legacy name gives itself, a custom :class:`Profile` gives
    its own name.
    """
    if isinstance(profile, Profile):
        key = profile.name.lower()
        return ALIASES.get(key, profile.name)
    key = _normalize_target(profile)
    if key not in FINGERPRINTS:
        raise _unknown(profile)
    return ALIASES.get(key, key)


def _choices() -> str:
    return ", ".join(sorted(PROFILES) + sorted(FINGERPRINTS)[:9])


def _unknown(name: Any) -> UnknownProfileError:
    return UnknownProfileError(
        "unknown TLS profile or impersonate target %r; try 'chrome', 'firefox', "
        "'safari' or a versioned target such as chrome124, firefox133, safari17_0 "
        "(%s ...)" % (name, _choices()))


# ---------------------------------------------------------------------------
# the reference client style fingerprint specs
# ---------------------------------------------------------------------------

_FP_CLIENT_FAMILY = {"chrome": "chrome", "chromium": "chrome", "edge": "edge",
                     "firefox": "firefox", "safari": "safari", "tor": "tor"}
_FP_PLATFORM = {"macos": "macos", "mac": "macos", "osx": "macos", "darwin": "macos",
                "windows": "windows", "win": "windows", "win32": "windows",
                "linux": "linux", "ios": "ios", "iphone": "ios", "ipad": "ios",
                "android": "android"}


def _fp_field(spec: Any, name: str) -> str:
    if isinstance(spec, Mapping):
        value = spec.get(name, "")
    else:
        value = getattr(spec, name, "")
    return "" if value is None else str(value).strip()


def _looks_like_fingerprint(spec: Any) -> bool:
    if isinstance(spec, Mapping):
        return "client" in spec
    return hasattr(spec, "client") and hasattr(spec, "client_version")


def _version_number(text: str) -> Optional[float]:
    """``"26.0.1"`` -> 26.0001, so patch releases stay distinct but close."""
    parts = [int(p) for p in re.findall(r"\d+", text)]
    if not parts:
        return None
    parts += [0, 0]
    return parts[0] + min(parts[1], 99) / 100.0 + min(parts[2], 99) / 10000.0


def _profile_from_fingerprint(spec: Any) -> Profile:
    """Map a reference-client ``Fingerprint`` (or a dict shaped like one) to the nearest target."""
    client = _fp_field(spec, "client").lower()
    family = _FP_CLIENT_FAMILY.get(client)
    if family is None:
        raise ImpersonateError(
            "no impersonate target for client %r; curl_reap knows %s (the reference client's "
            "brave, opera, samsung, okhttp and app web view clients have no "
            "captured fingerprint)" % (client or "", ", ".join(FAMILIES)))
    platform = _FP_PLATFORM.get(_fp_field(spec, "os").lower().replace(" ", ""))
    wanted = _version_number(_fp_field(spec, "client_version"))
    candidates = [name for name in TARGETS if FINGERPRINTS[name].family == family]
    if platform is not None:
        same_platform = [n for n in candidates if _data.CONCRETE[n]["platform"] == platform]
        if same_platform:
            candidates = same_platform
        elif platform in ("ios", "android"):
            raise ImpersonateError(
                "no %s target for %s; choose one of %s" % (platform, family, ", ".join(candidates)))
    if wanted is None:
        default = ALIASES.get(family)
        if default in candidates:
            return FINGERPRINTS[default]
        return FINGERPRINTS[candidates[-1]]

    def distance(name: str) -> Tuple[float, float]:
        have = _version_number(FINGERPRINTS[name].version) or 0.0
        return (abs(have - wanted), -have)

    return FINGERPRINTS[min(candidates, key=distance)]


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def resolve_profile(profile: Union[str, Profile, Mapping[str, Any], Any]) -> Profile:
    """Return a concrete :class:`Profile`.

    Accepts a registry name (case-insensitive, underscore and dot tolerant),
    a :class:`Profile`, or a reference-client-style fingerprint: a dict or object
    with ``client``, ``client_version`` and ``os`` fields, mapped to the
    nearest captured target.  Unknown names raise
    :class:`UnknownProfileError` (an ``ImpersonateError`` and a ``ValueError``).
    """
    if isinstance(profile, Profile):
        return profile
    if isinstance(profile, str):
        key = _normalize_target(profile)
        try:
            return FINGERPRINTS[key]
        except KeyError:
            raise _unknown(profile) from None
    if _looks_like_fingerprint(profile):
        return _profile_from_fingerprint(profile)
    raise TypeError("profile must be a profile name, impersonate target, "
                    "the reference client style fingerprint or Profile instance")


def profile_for_h2(profile: Union[str, Profile]) -> HeaderTuple:
    """The HTTP/2 header set of a profile: lowercase names, browser order.

    Profiles without an explicit ``h2_headers`` set get their HTTP/1.1
    headers lowercased, which is what a browser does for its own headers.
    """
    selected = resolve_profile(profile)
    if selected.h2_headers is not None:
        return selected.h2_headers
    return tuple((name.lower(), value) for name, value in selected.headers)


def families() -> Tuple[str, ...]:
    """Families with at least one captured target."""
    seen = []
    for name in TARGETS:
        family = FINGERPRINTS[name].family
        if family not in seen:
            seen.append(family)
    return tuple(seen)


def targets(family: Optional[str] = None) -> Tuple[str, ...]:
    """Concrete target names, optionally limited to one family.

    Aliases and legacy names are not listed; see :data:`ALIASES` and
    :data:`LEGACY` for those.
    """
    if family is None:
        return TARGETS
    wanted = family.lower()
    return tuple(name for name in TARGETS if FINGERPRINTS[name].family == wanted)


def is_alias(name: str) -> bool:
    return _normalize_target(name) in ALIASES


def is_legacy(name: str) -> bool:
    return _normalize_target(name) in LEGACY


# ---------------------------------------------------------------------------
# OpenSSL fallback
# ---------------------------------------------------------------------------

def create_ssl_context(profile: Union[str, Profile] = "chrome", verify=True,
                       alpn=("http/1.1",)):
    """Build an ``SSLContext`` for a profile (the OpenSSL fallback path).

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


__all__ = [
    "Profile", "PROFILES", "FINGERPRINTS", "ALIASES", "LEGACY", "TARGETS",
    "FAMILIES", "UnknownProfileError", "create_ssl_context", "resolve_profile",
    "canonical_target", "profile_for_h2", "families", "targets", "is_alias",
    "is_legacy",
]
