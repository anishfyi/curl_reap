"""RFC 6265bis Set-Cookie parsing, the scoped cookie jar and the request-API
``cookies=`` facade.

The 1.x transport fed each Set-Cookie header to :class:`http.cookies.SimpleCookie`,
which dropped whole lines (any cookie carrying an unrecognised flag such as
``Partitioned``) and turned unrecognised ``key=value`` attributes into phantom
cookies that were replayed to the server as if the server had set them.  This
module parses Set-Cookie the way the captured browser bytes say it works
(audit finding F02): split the header on ``;`` once, the first pair is the
cookie's ``name=value`` (the value may contain spaces, commas and further
``=``), and every later pair is an attribute matched case-insensitively
against the known set - unknown attributes are ignored, never stored.

:class:`CookieJar` keeps the 1.x scope semantics: cookies are keyed by
(domain, path, name); cookies set without a ``Domain`` attribute are
host-only and never reach subdomains; a ``Domain`` attribute is accepted only
when it names the origin host or a parent of it (foreign hosts and IP
literals are rejected); the request's RFC 6265 default-path is applied when no
usable ``Path`` was sent; path matching has a real segment boundary (``/app``
never matches ``/apple``); and the Cookie header orders longer paths first.
On top of that it adds the 2.0 surface: explicit ``set``/``get``/``delete``
scoping, JSON persistence, export to :class:`http.cookiejar.CookieJar`,
Secure cookies are refused from non-secure origins, and hosts and ``Domain``
attributes are IDNA-normalised so a unicode host and its punycode form share
one cookie scope.

:class:`Cookies` is the mutable string mapping the request API's ``cookies=``
keyword expects (set/get/delete item access delegating to a jar it wraps or
creates), raising :class:`~curl_reap.exceptions.CookieConflict` when several
cookies share a name under different scopes.
"""
from __future__ import annotations

import json
import threading
import time
from collections.abc import MutableMapping
from datetime import timezone
from email.utils import parsedate_to_datetime
from http.cookiejar import Cookie as _StdCookie
from http.cookiejar import CookieJar as _StdCookieJar
from typing import Any, Iterator, Optional
from urllib.parse import urlsplit

from .exceptions import CookieConflict

__all__ = ["CookieConflict", "CookieJar", "Cookies", "parse_set_cookie"]

_MISSING = object()

#: Set-Cookie attributes this parser knows.  Anything else (Priority, ...)
#: is ignored instead of becoming a phantom cookie.
_SAMESITE_VALUES = {"strict": "Strict", "lax": "Lax", "none": "None"}


def _parse_http_date(text):
    """HTTP-date to a POSIX timestamp, or ``None`` when unparsable."""
    try:
        dt = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:  # "-0000" means the zone is unknown; assume UTC
        return dt.replace(tzinfo=timezone.utc).timestamp()
    return dt.timestamp()


def _parse_max_age(text):
    """delta-seconds per RFC 6265 5.2.2, or ``None`` when invalid.

    The first character must be a digit or ``-`` and the remainder must be
    all digits, so ``Max-Age=1_0`` and ``Max-Age=`` are ignored rather than
    accepted by a lenient ``int()``.
    """
    if not text or text[0] not in "-0123456789" or not text[1:].isdigit():
        return None
    return int(text)


def _normalize_host(host):
    """Canonicalize a host: lowercase, drop a trailing dot, IDNA-encode."""
    if not host:
        return ""
    host = str(host).strip().lower()
    if host.endswith("."):
        host = host[:-1]
    if host and not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    return host


def parse_set_cookie(value: Optional[str]) -> Optional[dict]:
    """Parse one Set-Cookie header value into an attribute dict.

    Returns ``None`` for a header that carries no usable name-value pair
    (no ``=``, or an empty name), in which case RFC 6265 5.2 says the whole
    header is ignored.  The dict always contains every key below; attributes
    that were not sent (or were invalid) are ``None``/``False``:

    ``name``, ``value``, ``domain``, ``path``, ``secure``, ``httponly``,
    ``samesite``, ``partitioned``, ``max_age``, ``expires``

    - ``value`` is trimmed of surrounding whitespace only, so spaces, commas
      and ``=`` inside the value survive; surrounding quotes are kept (RFC
      6265 does not unquote).
    - ``domain`` has no leading dot, is lowercased and IDNA-normalised;
      ``None`` means no usable ``Domain`` attribute (host-only cookie).
    - ``path`` is the raw attribute value (the jar applies the RFC 6265
      default-path when it is missing or not absolute).
    - ``max_age`` is an ``int``; ``expires`` a POSIX timestamp; both are
      ``None`` when absent or malformed.
    - ``samesite`` is the canonical ``"Strict"``/``"Lax"``/``"None"`` when
      the value matches case-insensitively, else ``None`` (ignored).
    - ``secure``, ``httponly`` and ``partitioned`` are flags.
    - Unknown attributes (``Priority``, ``SameParty``, whatever the server
      invents) are ignored, never stored and never replayed.
    """
    if not value:
        return None
    pieces = value.split(";")
    name, sep, cookie_value = pieces[0].partition("=")
    if not sep:
        return None
    name = name.strip()
    if not name:
        return None
    cookie = {
        "name": name,
        "value": cookie_value.strip(),
        "domain": None,
        "path": None,
        "secure": False,
        "httponly": False,
        "samesite": None,
        "partitioned": False,
        "max_age": None,
        "expires": None,
    }
    for piece in pieces[1:]:
        attr, _, attr_value = piece.partition("=")
        attr = attr.strip().lower()
        attr_value = attr_value.strip()
        if attr == "expires":
            if attr_value:
                parsed = _parse_http_date(attr_value)
                if parsed is not None:
                    cookie["expires"] = parsed
        elif attr == "max-age":
            parsed = _parse_max_age(attr_value)
            if parsed is not None:
                cookie["max_age"] = parsed
        elif attr == "domain":
            if attr_value:
                domain = _normalize_host(attr_value.lstrip("."))
                if domain:
                    cookie["domain"] = domain
        elif attr == "path":
            if attr_value:
                cookie["path"] = attr_value
        elif attr == "secure":
            cookie["secure"] = True
        elif attr == "httponly":
            cookie["httponly"] = True
        elif attr == "samesite":
            cookie["samesite"] = _SAMESITE_VALUES.get(attr_value.lower())
        elif attr == "partitioned":
            cookie["partitioned"] = True
        # Everything else is an unknown attribute: ignored.
    return cookie


def _is_ip_literal(host):
    if not host:
        return False
    if ":" in host:
        return True
    return all(c.isdigit() or c == "." for c in host)


def _default_cookie_path(request_path):
    """RFC 6265 5.1.4 default-path: the request path's directory."""
    if not request_path or not request_path.startswith("/"):
        return "/"
    if request_path.count("/") == 1:
        return "/"
    return request_path[:request_path.rindex("/")] or "/"


def _cookie_path_match(request_path, cookie_path):
    """Path-match with a real boundary: ``/app`` must not match ``/apple``."""
    if request_path == cookie_path:
        return True
    if not request_path.startswith(cookie_path):
        return False
    if cookie_path.endswith("/"):
        return True
    return request_path[len(cookie_path):len(cookie_path) + 1] == "/"


def _cookie_domain_match(host, domain, host_only):
    if not domain:
        # A cookie set without any domain (CookieJar.set with domain=None)
        # matches every host, the way an empty domain does in the stdlib jar.
        return not host_only
    if host_only:
        return host == domain
    return host == domain or host.endswith("." + domain)


class CookieJar:
    """In-memory cookie store scoped by domain, path and name.

    A session keeps one jar for its lifetime: ``absorb`` stores parsed
    Set-Cookie attribute dicts from a response URL (Secure cookies are
    refused from non-https origins; hosts are IDNA-normalised) and
    ``header_for`` builds the Cookie header for a request URL.  Thread-safe.
    Cookies live only as long as the process unless ``save``/``load`` moves
    them out as JSON.

    Cookies set without a ``Domain`` attribute are host-only: they never
    reach subdomains.  A ``Domain`` attribute is accepted only when it names
    the origin host or a parent of it - foreign hosts and IP-literal domains
    are rejected outright.  Domain cookies match the host and its subdomains
    with or without the leading dot.  Full public-suffix validation is not
    performed, so ``Domain=co.uk`` on ``example.co.uk`` is accepted.

    ``set``/``get``/``delete`` address cookies by name with optional domain
    and path selectors; ``get`` raises :class:`CookieConflict` when several
    scopes hold the same name.  ``__len__``/``__iter__``/``items`` expose the
    live cookies (``__iter__`` yields cookie dicts, ``items`` flat
    ``(name, value)`` pairs).  ``get_dict`` is the lossy 1.x flattened view:
    same-named cookies held under different (domain, path) scopes coexist in
    the jar but collapse to one entry there (the most recently stored wins).
    """

    def __init__(self):
        self._lock = threading.Lock()
        # (domain, path, name) -> record dict; domain None means unscoped.
        self._cookies = {}
        self._seq = 0

    # -- storage ---------------------------------------------------------

    def absorb(self, url, specs):
        """Store parsed Set-Cookie attribute dicts received from ``url``.

        Each spec is a dict from :func:`parse_set_cookie` (hand-built specs
        with ``name``/``value`` and optional ``domain``, ``path``, ``secure``,
        ``httponly``, ``samesite``, ``partitioned``, ``max_age``, ``expires``
        work too).  Specs whose cookie cannot be stored under this origin are
        skipped: Secure cookies from non-https origins, and ``Domain``
        attributes that name a foreign or IP-literal host.  ``max_age`` of 0
        or less (or an ``expires`` in the past) deletes the matching scope
        instead of storing, exactly like a real Set-Cookie deletion.
        """
        parts = urlsplit(url)
        origin_host = _normalize_host(parts.hostname)
        secure_origin = parts.scheme.lower() == "https"
        request_path = parts.path or "/"
        now = time.time()
        with self._lock:
            for spec in specs:
                name = spec.get("name")
                if not name:
                    continue
                if spec.get("secure") and not secure_origin:
                    # RFC 6265bis: a non-secure origin cannot set a Secure
                    # cookie.  header_for withholds it over http anyway.
                    continue
                raw_domain = spec.get("domain")
                host_only = not raw_domain
                if host_only:
                    domain = origin_host
                else:
                    domain = _normalize_host(str(raw_domain).lstrip("."))
                    if (not domain or _is_ip_literal(origin_host)
                            or _is_ip_literal(domain)
                            or not (origin_host == domain
                                    or origin_host.endswith("." + domain))):
                        continue
                path = spec.get("path")
                if not path or not str(path).startswith("/"):
                    path = _default_cookie_path(request_path)
                key = (domain, path, name)
                expires = spec.get("expires")
                max_age = spec.get("max_age")
                if max_age is not None and str(max_age) != "":
                    try:
                        expires = now + float(max_age)
                    except (TypeError, ValueError):
                        pass
                if expires is not None and expires <= now:
                    self._cookies.pop(key, None)
                    continue
                self._seq += 1
                self._cookies[key] = {
                    "value": spec.get("value", ""),
                    "domain": domain,
                    "path": path,
                    "secure": bool(spec.get("secure")),
                    "httponly": bool(spec.get("httponly")),
                    "samesite": spec.get("samesite"),
                    "partitioned": bool(spec.get("partitioned")),
                    "expires": expires,
                    "host_only": host_only,
                    "seq": self._seq,
                }

    def set(self, name, value, domain=None, path="/", secure=False):
        """Store one cookie directly.

        ``domain=None`` stores an unscoped cookie that is replayed to every
        host (the convention the stdlib jar uses for an empty domain); an
        explicit ``domain`` is normalized and stored as a domain cookie that
        matches the host and its subdomains.  ``path`` falls back to ``/``
        when not absolute.  Storing the same (domain, path, name) again
        replaces the previous cookie.
        """
        domain = _normalize_host(domain) if domain else None
        if not path or not str(path).startswith("/"):
            path = "/"
        with self._lock:
            self._seq += 1
            self._cookies[(domain, str(path), name)] = {
                "value": value,
                "domain": domain,
                "path": str(path),
                "secure": bool(secure),
                "httponly": False,
                "samesite": None,
                "partitioned": False,
                "expires": None,
                "host_only": False,
                "seq": self._seq,
            }

    def store(self, url, pairs):
        """Store plain name/value pairs against ``url``'s host (1.x API)."""
        self.absorb(url, [{"name": n, "value": v} for n, v in dict(pairs).items()])

    def update(self, cookies):
        """Merge ``cookies`` into this jar.

        Accepts another :class:`CookieJar` or a :class:`Cookies` facade
        (scope, flags and expiry preserved cookie by cookie), or a mapping /
        iterable of ``(name, value)`` pairs stored as unscoped cookies.
        """
        if isinstance(cookies, Cookies):
            cookies = cookies.jar
        if isinstance(cookies, CookieJar):
            with cookies._lock:
                records = [(key, dict(record))
                           for key, record in sorted(
                               cookies._cookies.items(),
                               key=lambda kv: kv[1]["seq"])]
            with self._lock:
                for key, record in records:
                    self._seq += 1
                    record["seq"] = self._seq
                    self._cookies[key] = record
            return
        pairs = cookies.items() if hasattr(cookies, "items") else cookies
        for name, value in pairs:
            self.set(name, value)

    def delete(self, name, domain=None, path=None):
        """Delete cookies named ``name``, optionally scoped by domain/path.

        Raises ``KeyError`` when nothing matched.
        """
        domain = _normalize_host(domain) if domain is not None else None
        with self._lock:
            keys = [key for key in self._cookies
                    if key[2] == name
                    and (domain is None or key[0] == domain)
                    and (path is None or key[1] == path)]
            if not keys:
                raise KeyError(name)
            for key in keys:
                del self._cookies[key]

    # -- retrieval -------------------------------------------------------

    def get(self, name, default=None, domain=None, path=None):
        """Value of the cookie named ``name``, or ``default`` when absent.

        ``domain`` and ``path`` narrow the search to one scope.  Raises
        :class:`CookieConflict` when several scopes hold the same name;
        disambiguate with ``domain``/``path``.
        """
        domain = _normalize_host(domain) if domain is not None else None
        with self._lock:
            self._purge_expired()
            matches = [record for key, record in self._cookies.items()
                       if key[2] == name
                       and (domain is None or key[0] == domain)
                       and (path is None or key[1] == path)]
        if not matches:
            return default
        if len(matches) > 1:
            scopes = ", ".join(
                "(domain=%r, path=%r)" % (r["domain"], r["path"])
                for r in sorted(matches, key=lambda r: r["seq"]))
            raise CookieConflict(
                "There are multiple cookies with name, '%s': %s" % (name, scopes))
        return matches[0]["value"]

    def header_for(self, url, extra=None):
        """Cookie header value for ``url``, or empty string when none match.

        Cookies with a longer path come first, ties in storage order (the
        order RFC 6265 5.4 requires).  ``extra`` is an optional mapping or
        iterable of ``(name, value)`` pairs merged into the header for this
        one request: an extra replaces a stored cookie of the same name in
        place, new names are appended (the request-time ``cookies=`` merge).
        """
        parts = urlsplit(url)
        host = _normalize_host(parts.hostname)
        secure = parts.scheme.lower() == "https"
        path = parts.path or "/"
        now = time.time()
        pairs = []
        with self._lock:
            for key in list(self._cookies):
                cookie = self._cookies[key]
                if cookie["expires"] is not None and cookie["expires"] <= now:
                    del self._cookies[key]
                    continue
                if cookie["secure"] and not secure:
                    continue
                if not _cookie_domain_match(host, cookie["domain"], cookie["host_only"]):
                    continue
                if not _cookie_path_match(path, cookie["path"]):
                    continue
                pairs.append((cookie["path"], cookie["seq"],
                              "%s=%s" % (key[2], cookie["value"])))
        pairs.sort(key=lambda item: (-len(item[0]), item[1]))
        header = [pair[2] for pair in pairs]
        if extra:
            extras = extra.items() if hasattr(extra, "items") else list(extra)
            positions = {}
            for index, pair in enumerate(header):
                positions.setdefault(pair.partition("=")[0], index)
            for name, value in extras:
                pair = "%s=%s" % (name, value)
                if name in positions:
                    header[positions[name]] = pair
                else:
                    positions[name] = len(header)
                    header.append(pair)
        return "; ".join(header)

    def get_dict(self):
        """Lossy flattened ``{name: value}`` view (last stored wins)."""
        with self._lock:
            now = time.time()
            return {key[2]: record["value"]
                    for key, record in sorted(self._cookies.items(),
                                              key=lambda kv: kv[1]["seq"])
                    if record["expires"] is None or record["expires"] > now}

    def to_cookiejar(self) -> _StdCookieJar:
        """Export the live cookies to an :class:`http.cookiejar.CookieJar`.

        Domain cookies keep their subdomain matching (leading-dot domain);
        host-only cookies are exported with an undotted domain, which the
        stdlib jar cannot pin to one host - treat the result as an interop
        view, not a fidelity round-trip.  ``__CookieJar__``-aware libraries
        (urllib, requests-style facades) accept it directly.
        """
        jar = _StdCookieJar()
        with self._lock:
            self._purge_expired()
            stored = sorted(self._cookies.items(), key=lambda kv: kv[1]["seq"])
        for (domain, path, name), record in stored:
            if domain is None:
                std_domain, specified = "", False
            elif record["host_only"]:
                std_domain, specified = domain, False
            else:
                std_domain, specified = "." + domain, True
            expires = record["expires"]
            jar.set_cookie(_StdCookie(
                version=0, name=name, value=record["value"],
                port=None, port_specified=False,
                domain=std_domain, domain_specified=specified,
                domain_initial_dot=std_domain.startswith("."),
                path=path, path_specified=bool(path),
                secure=record["secure"],
                expires=None if expires is None else int(expires),
                discard=False,
                comment=None, comment_url=None,
                rest={"HttpOnly": None} if record["httponly"] else {},
                rfc2109=False,
            ))
        return jar

    # -- persistence -----------------------------------------------------

    def save(self, path):
        """Write every live cookie to ``path`` as JSON (UTF-8)."""
        with self._lock:
            self._purge_expired()
            stored = sorted(self._cookies.items(), key=lambda kv: kv[1]["seq"])
            records = [self._record_to_json(key, record)
                       for key, record in stored]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "cookies": records}, fh, indent=2)
            fh.write("\n")

    def load(self, path):
        """Replace this jar's contents with the cookies saved in ``path``.

        Cookies that already expired when the file is read are dropped
        instead of resurrected.  Unknown fields and a missing ``version`` are
        tolerated; a malformed file raises whatever ``json.load`` raises.
        """
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        records = data.get("cookies", []) if isinstance(data, dict) else []
        now = time.time()
        with self._lock:
            self._cookies.clear()
            for record in records:
                expires = record.get("expires")
                if expires is not None and expires <= now:
                    continue
                domain = record.get("domain")
                path_value = record.get("path") or "/"
                self._seq += 1
                self._cookies[(domain, path_value, record.get("name"))] = {
                    "value": record.get("value", ""),
                    "domain": domain,
                    "path": path_value,
                    "secure": bool(record.get("secure")),
                    "httponly": bool(record.get("httponly")),
                    "samesite": record.get("samesite"),
                    "partitioned": bool(record.get("partitioned")),
                    "expires": expires,
                    "host_only": bool(record.get("host_only")),
                    "seq": self._seq,
                }

    @staticmethod
    def _record_to_json(key, record):
        return {
            "name": key[2],
            "value": record["value"],
            "domain": record["domain"],
            "path": record["path"],
            "secure": record["secure"],
            "httponly": record["httponly"],
            "samesite": record["samesite"],
            "partitioned": record["partitioned"],
            "expires": record["expires"],
            "host_only": record["host_only"],
        }

    # -- container views ---------------------------------------------------

    def _purge_expired(self):
        now = time.time()
        for key in [key for key, record in self._cookies.items()
                    if record["expires"] is not None and record["expires"] <= now]:
            del self._cookies[key]

    def __len__(self):
        with self._lock:
            self._purge_expired()
            return len(self._cookies)

    def __iter__(self):
        """Iterate over cookie dicts (``name``, ``value``, ``domain``,
        ``path``, ``secure``, ``httponly``, ``samesite``, ``partitioned``,
        ``expires``, ``host_only``), in storage order."""
        with self._lock:
            self._purge_expired()
            stored = [(key, dict(record))
                      for key, record in sorted(
                          self._cookies.items(), key=lambda kv: kv[1]["seq"])]
        return iter([self._record_to_json(key, record) for key, record in stored])

    def items(self):
        """Flat ``[(name, value)]`` pairs for every live cookie, in storage
        order (unlike ``__iter__`` this collapses each cookie to its pair)."""
        return [(record["name"], record["value"]) for record in self]

    def clear(self):
        with self._lock:
            self._cookies.clear()

    def __repr__(self):
        return "CookieJar(%d cookies)" % len(self._cookies)


class Cookies(MutableMapping[str, str]):
    """The ``cookies=`` facade: a mutable ``name -> value`` mapping over a
    :class:`CookieJar`.

    Item access delegates to the jar: ``cookies[name]`` raises
    :class:`CookieConflict` when several scopes hold ``name`` (narrow with
    ``cookies.get(name, domain=..., path=...)``), ``cookies[name] = value``
    stores an unscoped cookie (use ``cookies.set(name, value, domain=...)``
    to scope it) and ``del cookies[name]`` removes every scope that name
    covers.  The underlying jar is the ``jar`` attribute, so scope-aware
    calls (``header_for``, ``absorb``, ``save``) stay reachable.

    The constructor accepts ``None``, another :class:`Cookies`, a
    :class:`CookieJar` (wrapped directly, not copied), or a mapping / iterable
    of ``(name, value)`` pairs.
    """

    def __init__(self, cookies: Any = None):
        if isinstance(cookies, CookieJar):
            self.jar = cookies
        else:
            self.jar = CookieJar()
            if cookies is not None:
                self.update(cookies)

    def __getitem__(self, name: str) -> str:
        value = self.jar.get(name, _MISSING)
        if value is _MISSING:
            raise KeyError(name)
        return value

    def __setitem__(self, name: str, value: str) -> None:
        self.jar.set(name, value)

    def __delitem__(self, name: str) -> None:
        self.jar.delete(name)

    def __len__(self) -> int:
        return len(self.jar)

    def __iter__(self) -> Iterator[str]:
        return iter([record["name"] for record in self.jar])

    def __bool__(self) -> bool:
        return len(self.jar) > 0

    def __contains__(self, name: object) -> bool:
        # A conflict means the name is present (several scopes hold it).
        try:
            value = self.jar.get(name, _MISSING)
        except CookieConflict:
            return True
        except TypeError:  # unhashable selector
            return False
        return value is not _MISSING

    def set(self, name: str, value: str, domain: Optional[str] = None,
            path: str = "/") -> None:
        """Store one cookie, optionally scoped (see :meth:`CookieJar.set`)."""
        self.jar.set(name, value, domain=domain, path=path)

    def get(self, name: str, default: Optional[str] = None,
            domain: Optional[str] = None, path: Optional[str] = None) -> Optional[str]:
        """Value of ``name`` within an optional scope (see
        :meth:`CookieJar.get`)."""
        return self.jar.get(name, default, domain=domain, path=path)

    def delete(self, name: str, domain: Optional[str] = None,
               path: Optional[str] = None) -> None:
        """Delete ``name`` within an optional scope (see
        :meth:`CookieJar.delete`)."""
        self.jar.delete(name, domain=domain, path=path)

    def update(self, other: Any = (), /, **kwargs: str) -> None:
        if isinstance(other, (Cookies, CookieJar)):
            self.jar.update(other)
        else:
            pairs = other.items() if hasattr(other, "items") else other
            for name, value in pairs:
                self[name] = value
        for name, value in kwargs.items():
            self[name] = value

    def __repr__(self) -> str:
        return "<Cookies[%d]>" % len(self.jar)
