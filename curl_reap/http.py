"""The curl_reap session layer: request API, retries, rotation, caching.

``Session`` is the reusable object users hold: profile (impersonate target)
selection and rotation, proxy rotation, retries with backoff, redirect
policy, cookie persistence, disk cache, block-driven proxy rotation, and
the whole request keyword vocabulary.  The wire work lives in
:mod:`curl_reap.transport`; responses are :class:`curl_reap.response.Response`.

Every keyword the wider ecosystem passes daily is accepted here: ``params``,
``data``/``json``/``files``, ``cookies``, ``auth``, ``timeout`` as a float or
``(connect, read)``, ``allow_redirects`` (True/False/"safe"), ``proxies`` in
``{"https": ..., "all://": ...}`` form, ``stream``, ``verify`` (bool or CA
bundle), ``cert``, ``impersonate``, ``ja3``/``akamai``/``extra_fp`` custom
fingerprints, ``interface``, ``debug`` and the no-op compatibility keywords.
"""
from __future__ import annotations

import json as _json
import os
import random
import socket
import ssl
import threading
import time
import warnings
from typing import Optional
from urllib.parse import urlencode, urlsplit, urlunsplit

from .exceptions import (
    HTTPError,
    HTTPStatusError,
    TransportError,
    URLPolicyError,
)
from .cookies import CookieJar
from .headers import Headers, CaseInsensitiveHeaders  # noqa: F401  (1.x alias)
from .response import Response, detect_encoding  # noqa: F401
from .tls import PROFILES, Profile, resolve_profile
from .transport import (
    _DEFAULT_MAX_BODY,
    _Transport,
    retry_after_seconds,  # noqa: F401  (re-export)
)

RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524})
_IP_BLOCK_STATUSES = frozenset({403, 407, 429})

_IGNORED_KWARGS = ("curl_options", "curl_infos", "thread", "curl",
                   "use_thread_local_curl", "async_curl", "loop")
_warned_ignored = set()


def _warn_once(name):
    if name not in _warned_ignored:
        _warned_ignored.add(name)
        warnings.warn(
            "%s= is accepted for compatibility and ignored: curl_reap runs its "
            "own transport, not libcurl" % name, stacklevel=3)


class RetryPolicy:
    """Exponential backoff with jitter and optional ``Retry-After`` support.

    Only ``allowed_methods`` are replayed: by default the safe/idempotent set
    (GET, HEAD, OPTIONS, PUT, DELETE). Replaying POST/PATCH requires opting in
    explicitly, e.g. ``RetryPolicy(allowed_methods={"GET", "POST"})``.
    ``Retry-After`` is honored (clamped to 24 h) - ``max_backoff`` caps only
    the exponential fallback delay.
    """

    IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})

    def __init__(self, retries=2, backoff=0.5, max_backoff=30.0,
                 statuses=RETRY_STATUSES, respect_retry_after=True,
                 allowed_methods=None):
        if retries < 0:
            raise ValueError("retries must be >= 0")
        if backoff < 0 or max_backoff < 0:
            raise ValueError("backoff values must be >= 0")
        self.retries = int(retries)
        self.backoff = float(backoff)
        self.max_backoff = float(max_backoff)
        self.statuses = frozenset(statuses)
        self.respect_retry_after = respect_retry_after
        self.allowed_methods = frozenset(
            str(m).upper() for m in
            (self.IDEMPOTENT_METHODS if allowed_methods is None else allowed_methods))

    def should_retry_status(self, status):
        return status in self.statuses

    def allows_method(self, method):
        return str(method).upper() in self.allowed_methods

    def delay(self, attempt, retry_after=None):
        if retry_after is not None and self.respect_retry_after:
            seconds = retry_after_seconds(retry_after)
            if seconds is not None:
                return seconds
        base = self.backoff * (2 ** attempt)
        return min(self.max_backoff, base * (0.5 + random.random()))


def _encode_body(data=None, json=None):
    if data is not None and json is not None:
        raise ValueError("data and json are mutually exclusive")
    if json is not None:
        return (_json.dumps(json, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
                "application/json")
    if data is None:
        return b"", None
    if isinstance(data, bytes):
        return data, None
    if isinstance(data, bytearray):
        return bytes(data), None
    if isinstance(data, str):
        return data.encode("utf-8"), None
    if isinstance(data, dict) or isinstance(data, (list, tuple)):
        return urlencode(data, doseq=True).encode("ascii"), "application/x-www-form-urlencoded"
    raise TypeError("data must be bytes, str, a mapping, or a sequence of pairs")


def _url_with_params(url, params):
    if not params:
        return url
    parts = urlsplit(url)
    encoded = urlencode(params, doseq=True)
    query = "&".join(part for part in (parts.query, encoded) if part)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _pick(sequence, counter, mode):
    if mode == "random":
        return random.choice(sequence)
    return sequence[counter % len(sequence)]


_env_proxy_cache = None


def _proxy_from_env(scheme):
    global _env_proxy_cache
    if _env_proxy_cache is None:
        found = {}
        for key, variables in (("https", ("HTTPS_PROXY", "https_proxy")),
                               ("http", ("HTTP_PROXY", "http_proxy")),
                               ("all", ("ALL_PROXY", "all_proxy"))):
            for variable in variables:
                value = os.environ.get(variable)
                if value:
                    found[key] = value
                    break
        _env_proxy_cache = found
    if scheme in _env_proxy_cache:
        return _env_proxy_cache[scheme]
    return _env_proxy_cache.get("all")


def _no_proxy_matches(url):
    raw = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    entries = [e.strip().lower().lstrip(".") for e in raw.split(",") if e.strip()]
    if not entries:
        return False
    host = (urlsplit(url).hostname or "").lower()
    return any(host == e or host.endswith("." + e) for e in entries)


def _custom_profile(base: Profile, ja3=None, akamai=None, extra_fp=None) -> Profile:
    """Build a one-request Profile from ja3/akamai/extra_fp overrides.

    ja3/akamai produce live engine objects (a hello template, an h2 spec)
    stored directly on the Profile; the native engines and the OpenSSL
    fallback both accept them.
    """
    import dataclasses
    updates = {}
    if ja3:
        from ._tls import template_from_ja3
        updates["tls_template"] = template_from_ja3(ja3)
    if akamai:
        from ._h2 import spec_from_akamai
        updates["h2_spec"] = spec_from_akamai(akamai)
    if extra_fp:
        ciphers = list(extra_fp.get("tls_cipher_suites") or [])
        if ciphers:
            updates["ciphers"] = list(ciphers)
        curve = extra_fp.get("tls_curves")
        if isinstance(curve, (list, tuple)) and curve:
            updates["curve"] = str(curve[-1])
    if not updates:
        return base
    updates["name"] = "%s*" % base.name
    return dataclasses.replace(base, **updates)


class Session:
    """Reusable HTTP session with fingerprint profiles and proxy rotation.

    ``profile`` accepts any impersonate target name (see
    ``curl_reap.tls.FINGERPRINTS``) or a custom ``Profile``.  ``profiles``
    creates a rotation pool; ``rotate`` is ``"sequence"`` or ``"random"``;
    ``sticky=True`` pins one profile and one proxy for the session's life.
    ``tls`` selects the backend: ``"auto"`` (native TLS 1.3 engine when the
    profile has a captured template, OpenSSL fallback), ``"native"`` or
    ``"openssl"``.  ``http2`` (default True) offers HTTP/2 through ALPN and
    falls back to HTTP/1.1 per connection; ``http_version`` overrides
    explicitly ("v1", "v2", "v2tls", "v2_prior_knowledge").

    ``url_policy`` is a callable invoked with every outgoing URL (initial
    request and each redirect hop) before any socket is touched; returning
    falsy raises :class:`URLPolicyError`.
    """

    def __init__(self, profile="chrome", headers=None, timeout=30, retries=2,
                 proxy=None, rotate=None, profiles=None, retry_policy=None,
                 cache=None, on_response=None, block_rotations=None, verify=True,
                 allow_redirects=True, max_redirects=30, impersonate=None,
                 http2=True, sticky=False, url_policy=None, tls="auto",
                 max_body_bytes=_DEFAULT_MAX_BODY, interface=None, debug=False,
                 trust_env=True, cert=None, proxies=None, http_version=None):
        if rotate not in (None, "sequence", "random"):
            raise ValueError("rotate must be None, 'sequence', or 'random'")
        if tls not in ("auto", "native", "openssl"):
            raise ValueError("tls must be 'auto', 'native' or 'openssl'")
        if impersonate is not None:
            profile = impersonate
        self.profile = resolve_profile(profile)
        if profiles is None:
            pool = tuple(PROFILES.values()) if rotate else (self.profile,)
        else:
            pool = tuple(resolve_profile(item) for item in profiles)
            if not pool:
                raise ValueError("profiles must not be empty")
        self.profiles = pool
        self.timeout = timeout
        self.rotate = rotate
        self.retry_policy = retry_policy or RetryPolicy(retries=retries)
        self.cache = cache
        self.on_response = on_response
        self.verify = verify
        self.cert = cert
        self.allow_redirects = allow_redirects
        self.max_redirects = max_redirects
        self._headers = tuple(_header_items_public(headers))
        self.cookies = CookieJar()
        self.http2 = bool(http2)
        if http_version is None:
            http_version = "v2" if self.http2 else "v1"
        allowed = ("v1", "v2", "v2tls", "v2_prior_knowledge", "v3", "v3only")
        if http_version not in allowed:
            raise ValueError("http_version must be one of %s" % (", ".join(allowed)))
        if http_version in ("v3", "v3only"):
            raise NotImplementedError("HTTP/3 (QUIC) is not implemented")
        self.http_version = http_version
        self.sticky = bool(sticky)
        self.url_policy = url_policy
        self.max_body_bytes = int(max_body_bytes)
        self.debug = bool(debug)
        self.trust_env = bool(trust_env)
        self._counter = 0
        self._counter_lock = threading.Lock()
        self._transport = _Transport(tls=tls, interface=interface)
        self._proxy_pool = self._build_proxy_pool(proxy, proxies)
        for item in self._proxy_pool:
            if not isinstance(item, str) or not item:
                raise TypeError("proxy entries must be non-empty strings")
        default_rotations = max(0, len(self._proxy_pool) - 1)
        self.block_rotations = (default_rotations if block_rotations is None
                                else int(block_rotations))
        if self.block_rotations < 0:
            raise ValueError("block_rotations must be >= 0")
        self._sticky_route = (self.profiles[0],
                              self._proxy_pool[0] if self._proxy_pool else None)

    @staticmethod
    def _build_proxy_pool(proxy, proxies):
        """Merge ``proxy`` (str or list) and ``proxies`` (dict) into one pool."""
        pool = []
        if proxy is not None:
            if isinstance(proxy, str):
                pool.append(proxy)
            else:
                pool.extend(proxy)
                if not pool:
                    raise ValueError("proxy rotation list must not be empty")
        if proxies:
            if isinstance(proxies, str):
                proxies = {"all": proxies}
            # curl_cffi key order: scheme-specific wins over 'all'
            for key in ("https", "http", "all://", "all"):
                value = proxies.get(key)
                if value and value not in pool:
                    pool.append(value)
        return tuple(pool)

    @property
    def retries(self):
        return self.retry_policy.retries

    @property
    def tls_backend(self):
        return self._transport.tls_backend

    def _route(self, url=None):
        proxy = None
        if self.sticky:
            profile = self._sticky_route[0]
            proxy = self._sticky_route[1]
        else:
            with self._counter_lock:
                counter = self._counter
                self._counter += 1
            mode = self.rotate or "sequence"
            profile = self.profiles[0]
            if len(self.profiles) > 1:
                profile = _pick(self.profiles, counter, mode)
            if self._proxy_pool:
                proxy = _pick(self._proxy_pool, counter, mode)
        if proxy is None and self.trust_env and url is not None:
            scheme = urlsplit(url).scheme.lower()
            if scheme in ("http", "https") and not _no_proxy_matches(url):
                proxy = _proxy_from_env(scheme)
        return profile, proxy

    def request(self, method, url, **kwargs):
        meta = kwargs.pop("meta", None)
        no_cache = kwargs.pop("no_cache", False)
        sink = kwargs.pop("_sink", None) or kwargs.pop("sink", None)
        policy = kwargs.pop("retry_policy", None) or self.retry_policy
        if "retries" in kwargs:
            policy = RetryPolicy(retries=kwargs.pop("retries"), backoff=policy.backoff,
                                 max_backoff=policy.max_backoff, statuses=policy.statuses,
                                 respect_retry_after=policy.respect_retry_after,
                                 allowed_methods=policy.allowed_methods)
        timeout = kwargs.pop("timeout", self.timeout)
        request_headers = kwargs.pop("headers", None)
        params = kwargs.pop("params", None)
        data = kwargs.pop("data", None)
        json_data = kwargs.pop("json", None)
        files = kwargs.pop("files", None)
        request_proxy = kwargs.pop("proxy", None)
        proxies = kwargs.pop("proxies", None)
        proxy_auth = kwargs.pop("proxy_auth", None)
        request_profile = kwargs.pop("profile", None)
        request_impersonate = kwargs.pop("impersonate", None)
        ja3 = kwargs.pop("ja3", None)
        akamai = kwargs.pop("akamai", None)
        extra_fp = kwargs.pop("extra_fp", None)
        perk = kwargs.pop("perk", None)
        if perk is not None:
            warnings.warn("perk= is accepted and ignored (post-quantum key share "
                          "negotiation is automatic)", stacklevel=3)
        for ignored in _IGNORED_KWARGS:
            if kwargs.pop(ignored, None) is not None:
                _warn_once(ignored)
        cookies = kwargs.pop("cookies", None)
        verify = kwargs.pop("verify", self.verify)
        cert = kwargs.pop("cert", self.cert)
        auth = kwargs.pop("auth", None)
        allow_redirects = kwargs.pop("allow_redirects", self.allow_redirects)
        max_redirects = kwargs.pop("max_redirects", self.max_redirects)
        stream = kwargs.pop("stream", False)
        max_body = kwargs.pop("max_body_bytes", self.max_body_bytes)
        interface = kwargs.pop("interface", None)
        debug = kwargs.pop("debug", self.debug)
        http_version = kwargs.pop("http_version", self.http_version)
        if kwargs:
            name = next(iter(kwargs))
            raise TypeError("unexpected request keyword argument %r" % name)
        if request_impersonate is not None:
            if (request_profile is not None and
                    resolve_profile(request_impersonate) != resolve_profile(request_profile)):
                raise ValueError("profile and impersonate disagree; pass one")
            request_profile = request_impersonate
        if request_profile is not None:
            request_profile = resolve_profile(request_profile)
        if ja3 or akamai or extra_fp:
            request_profile = _custom_profile(
                request_profile or self.profile, ja3=ja3, akamai=akamai, extra_fp=extra_fp)

        if files:
            from .multipart import encode_multipart
            if data is not None and json_data is not None:
                raise ValueError("data, json and files are mutually exclusive")
            if json_data is not None:
                raise ValueError("json and files are mutually exclusive")
            body, content_type = encode_multipart(data=data, files=files)
        else:
            body, content_type = _encode_body(data=data, json=json_data)

        combined_headers = list(_merge_headers_public(self._headers, request_headers))
        request_url = _url_with_params(url, params)
        if self.url_policy is not None and not self.url_policy(request_url):
            raise URLPolicyError("url_policy rejected %s" % request_url)
        if sink is not None:
            if not isinstance(sink, str):
                raise TypeError("sink must be a file path string")
            no_cache = True
        if stream:
            no_cache = True

        if cookies:
            extra_cookie = self._extra_cookie_header(cookies)
            if extra_cookie:
                combined_headers = [(n, v) for n, v in combined_headers
                                    if n.lower() != "cookie"]
                combined_headers.append(("Cookie", extra_cookie))

        cacheable = (self.cache is not None and not no_cache and
                     method.upper() == "GET" and self.cache.accepts(method))
        revalidate = None
        if cacheable:
            hit = self.cache.get(method, url, params)
            if hit is not None:
                response = Response(meta=meta, from_cache=True, **hit)
                if self.on_response:
                    self.on_response(response)
                return response
            stale = self.cache.get_stale(method, url, params)
            if stale:
                conditional = []
                if stale.get("etag"):
                    conditional.append(("If-None-Match", stale["etag"]))
                if stale.get("last_modified"):
                    conditional.append(("If-Modified-Since", stale["last_modified"]))
                if conditional:
                    combined_headers = _merge_headers_public(
                        combined_headers, conditional)
                    revalidate = stale

        attempt = 0
        rotations = 0
        method_allowed = policy.allows_method(method)
        effective_proxy_pool = self._proxy_pool
        if proxies or (request_proxy is not None):
            effective_proxy_pool = (request_proxy,) if request_proxy is not None else \
                self._build_proxy_pool(None, proxies)
        while True:
            selected_profile, selected_proxy = self._route(request_url)
            if request_profile is not None:
                selected_profile = request_profile
            if request_proxy is not None:
                if not isinstance(request_proxy, str):
                    raise TypeError("per-request proxy must be a string")
                selected_proxy = request_proxy
            elif proxies and not self._proxy_pool:
                selected_proxy = effective_proxy_pool[0] if effective_proxy_pool else None
            if selected_proxy and proxy_auth is not None:
                selected_proxy = self._inject_proxy_auth(selected_proxy, proxy_auth)
            started = time.monotonic()
            try:
                raw = self._transport.request(
                    method, request_url, selected_profile,
                    headers=combined_headers or None,
                    body=body, content_type=content_type, timeout=timeout,
                    proxy=selected_proxy, verify=verify, auth=auth,
                    allow_redirects=allow_redirects, max_redirects=max_redirects,
                    cookie_jar=self.cookies, sink=sink, url_policy=self.url_policy,
                    stream=stream, max_body=max_body, cert=cert,
                    http_version=http_version, interface=interface, debug=debug)
                raw.request = {
                    "method": method.upper(), "url": request_url,
                    "headers": list(combined_headers)}
            except (TransportError, OSError, ssl.SSLError):
                if not method_allowed or attempt >= policy.retries:
                    raise
                time.sleep(policy.delay(attempt))
                attempt += 1
                continue
            response = Response(raw, meta=meta, elapsed=time.monotonic() - started)

            if revalidate is not None and response.status == 304:
                self.cache.touch(method, url, params)
                cached = Response(meta=meta, from_cache=True,
                                  status=revalidate["status"], url=revalidate["url"],
                                  headers=revalidate["headers"], content=revalidate["content"])
                if self.on_response:
                    self.on_response(cached)
                return cached
            if (response.status in _IP_BLOCK_STATUSES and effective_proxy_pool and
                    not self.sticky and method_allowed and
                    request_proxy is None and rotations < self.block_rotations):
                rotations += 1
                time.sleep(min(policy.max_backoff, 0.3 * rotations))
                continue
            if (method_allowed and policy.should_retry_status(response.status)
                    and attempt < policy.retries):
                time.sleep(policy.delay(attempt, response.headers.get("Retry-After")))
                attempt += 1
                continue
            if cacheable and response.ok and not stream:
                self.cache.set(method, url, params, response)
            if sink is not None and response.ok and raw.saved_bytes:
                response.meta = dict(response.meta or {},
                                     saved_to=sink, bytes=raw.saved_bytes)
            if self.on_response:
                self.on_response(response)
            return response

    # -- helpers ---------------------------------------------------------------
    @staticmethod
    def _extra_cookie_header(cookies):
        """Per-request cookies (dict, pairs or ``name=value`` strings) as a header."""
        if cookies is None:
            return None
        if isinstance(cookies, dict):
            pairs = list(cookies.items())
        else:
            pairs = []
            for item in cookies:
                if isinstance(item, str):
                    name, _, value = item.partition("=")
                    pairs.append((name.strip(), value.strip()))
                else:
                    pairs.append((item[0], item[1]))
        return "; ".join("%s=%s" % (n, v) for n, v in pairs) or None

    @staticmethod
    def _inject_proxy_auth(proxy, proxy_auth):
        from urllib.parse import urlsplit as us, urlunsplit as uus
        parts = us(proxy if "://" in proxy else "http://" + proxy)
        if proxy_auth is None or parts.username is not None:
            return proxy
        user, _, password = proxy_auth.partition(":")
        from urllib.parse import quote
        netloc = "%s:%s@%s" % (quote(user, safe=""), quote(password, safe=""),
                               parts.netloc)
        return uus((parts.scheme, netloc, parts.path, parts.query, parts.fragment))

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def patch(self, url, **kwargs):
        return self.request("PATCH", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)

    def download(self, url, path, **kwargs):
        """Stream a URL straight to ``path`` (constant memory).

        Bytes land in the file as they arrive, with transport compression
        decoded on the fly. The file is committed atomically and only for a
        2xx response: redirect and error bodies never touch the sink. The
        returned ``Response`` carries ``meta["saved_to"]`` and
        ``meta["bytes"]`` when the file was written.
        """
        kwargs.setdefault("timeout", self.timeout)
        return self.request("GET", url, sink=str(path), **kwargs)

    def ws_connect(self, url, **kwargs):
        """Open a WebSocket (see :mod:`curl_reap.websocket`)."""
        from .websocket import WebSocket
        return WebSocket.connect(url, session=self, **kwargs)

    def close(self):
        self._transport.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _header_items_public(headers):
    from .transport import _header_items
    return _header_items(headers)


def _merge_headers_public(*sources):
    from .transport import _merge_headers
    return _merge_headers(*sources)


_default = None
_default_lock = threading.Lock()


def _session():
    global _default
    if _default is None:
        with _default_lock:
            if _default is None:
                _default = Session()
    return _default


def get(url, **kwargs):
    """Fetch a URL through a shared keep-alive session."""
    return _session().get(url, **kwargs)


def post(url, **kwargs):
    return _session().post(url, **kwargs)


def fetch(url, **kwargs):
    return get(url, **kwargs)


def download(url, path, **kwargs):
    """One-shot streaming download through the shared session."""
    return _session().download(url, path, **kwargs)


__all__ = [
    "Session", "Response", "RetryPolicy", "HTTPStatusError", "HTTPError",
    "TransportError", "URLPolicyError", "CookieJar", "CaseInsensitiveHeaders",
    "Headers", "detect_encoding", "retry_after_seconds",
    "get", "post", "fetch", "download",
]
