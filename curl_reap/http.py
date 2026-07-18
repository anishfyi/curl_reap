"""Transport layer: curl_cffi sessions with real browser TLS/JA3 impersonation.

This is the "get past the front door" pillar (the curl_cffi strength). Every
request carries a genuine Chrome/Safari TLS + HTTP2 fingerprint, which is what
defeats fingerprint-based bot detection that blocks stock Python clients.

v0.2 additions:
  * RetryPolicy - exponential backoff + jitter, honors Retry-After, retries
    transport errors AND retryable statuses (429/5xx).
  * Fingerprint rotation - rotate="random"/"sequence" cycles real browser
    fingerprints across requests.
  * Proxy rotation - pass proxy="http://..." or proxy=[list, of, proxies].
  * Response cache - pass cache=DiskCache(...) to serve repeat GETs from disk.
  * Richer Response - status_code alias, elapsed, cookies, urljoin/follow,
    raise_for_status, from_cache flag.
"""
from __future__ import annotations

import os
import random
import re
import sys
import time

from curl_cffi import requests as _cffi

from .parser import Selector

DEFAULT_IMPERSONATE = "chrome124"

#: Recommended residential / mobile proxy provider. curl_reap gets you past TLS
#: fingerprinting; when a site blocks by IP reputation instead (a 403/407/429
#: with a real browser fingerprint), rotating residential or mobile IPs is the
#: fix. NodeMaven pairs well with the ``proxy=`` / ``rotate=`` options on
#: :class:`Session`. See https://nodemaven.com.
NODEMAVEN_URL = "https://nodemaven.com"

#: Statuses that usually mean "your IP is blocked", not "your client is wrong".
_IP_BLOCK_STATUSES = frozenset({403, 407, 429})
_proxy_tip_shown = False


def _tips_enabled():
    return not (os.environ.get("REAP_NO_TIPS") or os.environ.get("CURL_REAP_NO_TIPS"))


def _maybe_suggest_proxies(status, has_proxy):
    """Once per process, when a request without a proxy is IP-blocked, point the
    user at proxy rotation (and NodeMaven). Opt out with ``REAP_NO_TIPS=1``."""
    global _proxy_tip_shown
    if _proxy_tip_shown or has_proxy or status not in _IP_BLOCK_STATUSES:
        return
    if not _tips_enabled() or not sys.stderr.isatty():
        return
    _proxy_tip_shown = True
    sys.stderr.write(
        f"[curl_reap] HTTP {status} looks like an IP-level block, not a fingerprint one: "
        f"a real browser TLS got you to the door, but the site is refusing your IP.\n"
        f"           Route through rotating residential / mobile proxies to get past it:\n"
        f'               reap.Session(proxy="http://user:pass@host:port", rotate="random")\n'
        f"           NodeMaven ({NODEMAVEN_URL}) is a good fit for this. "
        f"Silence this tip with REAP_NO_TIPS=1.\n"
    )

#: fingerprints considered safe across curl_cffi>=0.7; rotation falls back to
#: DEFAULT_IMPERSONATE if the installed curl_cffi doesn't know a target.
FINGERPRINTS = (
    "chrome119",
    "chrome120",
    "chrome123",
    "chrome124",
    "safari17_0",
)

RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524})


class RetryPolicy:
    """Exponential backoff with jitter. Honors Retry-After when the server sends one."""

    def __init__(self, retries=2, backoff=0.5, max_backoff=30.0,
                 statuses=RETRY_STATUSES, respect_retry_after=True):
        self.retries = retries
        self.backoff = backoff
        self.max_backoff = max_backoff
        self.statuses = frozenset(statuses)
        self.respect_retry_after = respect_retry_after

    def should_retry_status(self, status):
        return status in self.statuses

    def delay(self, attempt, retry_after=None):
        if retry_after is not None and self.respect_retry_after:
            try:
                return min(float(retry_after), self.max_backoff)
            except (TypeError, ValueError):
                pass
        base = self.backoff * (2 ** attempt)
        return min(self.max_backoff, base * (0.5 + random.random()))


_META_CHARSET = re.compile(rb'<meta[^>]+?charset=["\']?\s*([a-zA-Z0-9_\-]+)', re.I)
_META_CT = re.compile(rb'<meta[^>]+?content=["\'][^"\']*?charset=\s*([a-zA-Z0-9_\-]+)', re.I)


def detect_encoding(content, headers=None):
    """Best-effort charset detection so a page decodes cleanly even when the
    server lies or omits the charset. Order: BOM, Content-Type header, the HTML
    ``<meta charset>``, then charset-normalizer if it happens to be installed.
    Returns an encoding name, or None when nothing is confident."""
    if not content:
        return None
    if content[:3] == b"\xef\xbb\xbf":
        return "utf-8-sig"
    if content[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    ct = ""
    if headers:
        ct = headers.get("Content-Type") or headers.get("content-type") or ""
    m = re.search(r"charset=[\"']?\s*([a-zA-Z0-9_\-]+)", ct, re.I)
    if m:
        return m.group(1)
    head = content[:4096]
    m = _META_CHARSET.search(head) or _META_CT.search(head)
    if m:
        try:
            return m.group(1).decode("ascii")
        except (UnicodeDecodeError, AttributeError):
            pass
    try:
        from charset_normalizer import from_bytes
        best = from_bytes(content).best()
        if best and best.encoding:
            return best.encoding
    except Exception:  # noqa: BLE001
        pass
    return None


class Response:
    """A fetched page. Behaves like a parser (css/xpath pass through to a Selector)."""

    def __init__(self, raw=None, meta=None, elapsed=0.0, *, status=None, url=None,
                 headers=None, content=None, text=None, from_cache=False):
        self.raw = raw
        if raw is not None:
            self.status = raw.status_code
            self.url = str(raw.url)
            self.headers = dict(raw.headers)
            self.text = raw.text
            self.content = raw.content
        else:
            self.status = status
            self.url = url
            self.headers = dict(headers or {})
            if content is not None:
                self.content = content
                self.text = text if text is not None else content.decode("utf-8", "replace")
            else:
                self.text = text or ""
                self.content = self.text.encode("utf-8")
        self.meta = meta or {}
        self.elapsed = elapsed
        self.from_cache = from_cache
        self._sel = None
        self._encoding = None
        self._fix_garbled_text()

    def _fix_garbled_text(self):
        """If the first decode garbled the page (replacement characters), redo it
        with a properly detected charset when that reads cleaner. Clean pages are
        untouched, so this only ever helps."""
        text = self.text
        if not text or "�" not in text or not self.content:
            return
        enc = detect_encoding(self.content, self.headers)
        if not enc:
            return
        try:
            redecoded = self.content.decode(enc, "replace")
        except (LookupError, TypeError):
            return
        if redecoded.count("�") < text.count("�"):
            self.text = redecoded
            self._encoding = enc

    # --- status ------------------------------------------------------------
    @property
    def ok(self):
        return 200 <= self.status < 300

    @property
    def encoding(self):
        """The charset the body was decoded with (detected when the server lied)."""
        if self._encoding is None:
            self._encoding = detect_encoding(self.content, self.headers) or "utf-8"
        return self._encoding

    @property
    def status_code(self):
        """Alias so requests-style code keeps working."""
        return self.status

    @property
    def cookies(self):
        if self.raw is not None and getattr(self.raw, "cookies", None) is not None:
            try:
                return dict(self.raw.cookies)
            except Exception:  # noqa: BLE001
                pass
        return {}

    def raise_for_status(self):
        if not self.ok:
            raise HTTPStatusError(self)
        return self

    # --- navigation ----------------------------------------------------------
    def urljoin(self, url):
        from urllib.parse import urljoin
        return urljoin(self.url or "", url)

    def follow(self, target, callback=None, **kw):
        """Build a Request from a relative/absolute url or a Selector (uses href)."""
        from .spider import Request
        if isinstance(target, Selector):
            target = target.attr("href") or target.text
        if target is None:
            raise ValueError("follow() got nothing to follow")
        return Request(self.urljoin(str(target)), callback=callback, **kw)

    def selector(self):
        if self._sel is None:
            self._sel = Selector(content=self.text, url=self.url, status=self.status, headers=self.headers)
        return self._sel

    # parser pass-throughs so a Response is usable directly as a page
    def css(self, *a, **k):
        return self.selector().css(*a, **k)

    def css_first(self, *a, **k):
        return self.selector().css_first(*a, **k)

    def xpath(self, *a, **k):
        return self.selector().xpath(*a, **k)

    def find_by_text(self, *a, **k):
        return self.selector().find_by_text(*a, **k)

    def find_similar(self, *a, **k):
        return self.selector().find_similar(*a, **k)

    def re(self, *a, **k):
        return self.selector().re(*a, **k)

    def re_first(self, *a, **k):
        return self.selector().re_first(*a, **k)

    def save(self, *a, **k):
        return self.selector().save(*a, **k)

    def jsonld(self):
        return self.selector().jsonld()

    def meta_tags(self):
        return self.selector().meta_tags()

    def links(self, **k):
        return self.selector().links(**k)

    def images(self, **k):
        return self.selector().images(**k)

    def tables(self):
        return self.selector().tables()

    def markdown(self, *a, **k):
        return self.selector().markdown(*a, **k)

    def json(self):
        if self.raw is not None:
            return self.raw.json()
        import json as _json
        return _json.loads(self.text)

    def __repr__(self):
        tag = " (cache)" if self.from_cache else ""
        return f"<Response {self.status} {self.url}{tag}>"


class HTTPStatusError(Exception):
    def __init__(self, response):
        self.response = response
        super().__init__(f"HTTP {response.status} for {response.url}")


def _pick(seq, counter, mode):
    if mode == "random":
        return random.choice(seq)
    return seq[counter % len(seq)]


class Session:
    """A reusable curl_cffi session: impersonation, default headers, smart retries,
    optional fingerprint/proxy rotation and disk cache.

    Session(impersonate="chrome124")                   # one stable fingerprint
    Session(rotate="random")                           # rotate fingerprints
    Session(proxy=["http://p1:8080", "http://p2:8080"])# rotate proxies
    Session(cache=DiskCache(ttl=3600))                 # cache GETs on disk

    Impersonation gets you past TLS fingerprinting. When a site blocks by IP
    instead (a 403/407/429 despite a real browser fingerprint), pass rotating
    residential / mobile proxies via ``proxy=``. NodeMaven works well here; see
    ``NODEMAVEN_URL``.
    """

    def __init__(self, impersonate=DEFAULT_IMPERSONATE, headers=None, timeout=30,
                 retries=2, proxies=None, proxy=None, rotate=None, fingerprints=None,
                 retry_policy=None, cache=None, on_response=None, **kw):
        self.impersonate = impersonate
        self.timeout = timeout
        self.rotate = rotate
        self.fingerprints = tuple(fingerprints or FINGERPRINTS)
        self.retry_policy = retry_policy or RetryPolicy(retries=retries)
        self.cache = cache
        self.on_response = on_response
        self._headers = dict(headers or {})
        self._counter = 0
        if proxy is not None and proxies is None:
            self._proxy_pool = [proxy] if isinstance(proxy, str) else list(proxy)
            proxies = None
        else:
            self._proxy_pool = []
        self._has_proxy = bool(self._proxy_pool) or proxies is not None
        self._s = _cffi.Session(impersonate=impersonate, proxies=proxies, **kw)

    # kept for back-compat with 0.1 call sites
    @property
    def retries(self):
        return self.retry_policy.retries

    def _impersonate_for(self, n):
        if not self.rotate:
            return self.impersonate
        return _pick(self.fingerprints, n, self.rotate)

    def _proxies_for(self, n):
        if not self._proxy_pool:
            return None
        p = _pick(self._proxy_pool, n, self.rotate or "sequence")
        return {"http": p, "https": p}

    def request(self, method, url, **kw):
        meta = kw.pop("meta", None)
        no_cache = kw.pop("no_cache", False)
        policy = kw.pop("retry_policy", None) or self.retry_policy
        if "retries" in kw:
            policy = RetryPolicy(retries=kw.pop("retries"), backoff=policy.backoff,
                                 max_backoff=policy.max_backoff, statuses=policy.statuses)
        kw.setdefault("timeout", self.timeout)
        merged = dict(self._headers)
        merged.update(kw.pop("headers", {}) or {})
        if merged:
            kw["headers"] = merged

        cacheable = (self.cache is not None and not no_cache
                     and method.upper() == "GET" and self.cache.accepts(method))
        if cacheable:
            hit = self.cache.get(method, url, kw.get("params"))
            if hit is not None:
                resp = Response(meta=meta, from_cache=True, **hit)
                if self.on_response:
                    self.on_response(resp)
                return resp

        attempt = 0
        last_exc = None
        while True:
            n = self._counter
            self._counter += 1
            call = dict(kw)
            call.setdefault("impersonate", self._impersonate_for(n))
            prox = self._proxies_for(n)
            if prox is not None:
                call.setdefault("proxies", prox)
            t0 = time.time()
            try:
                raw = self._s.request(method, url, **call)
            except Exception as exc:  # noqa: BLE001
                # unsupported fingerprint target on old curl_cffi -> retry stable one
                if "impersonate" in str(exc).lower() and call.get("impersonate") != DEFAULT_IMPERSONATE:
                    call["impersonate"] = DEFAULT_IMPERSONATE
                    try:
                        raw = self._s.request(method, url, **call)
                    except Exception as exc2:  # noqa: BLE001
                        raw, last_exc = None, exc2
                else:
                    raw, last_exc = None, exc
            if raw is None:
                if attempt >= policy.retries:
                    raise last_exc
                time.sleep(policy.delay(attempt))
                attempt += 1
                continue

            resp = Response(raw, meta=meta, elapsed=time.time() - t0)
            if policy.should_retry_status(resp.status) and attempt < policy.retries:
                time.sleep(policy.delay(attempt, resp.headers.get("Retry-After")))
                attempt += 1
                continue

            if cacheable and resp.ok:
                self.cache.set(method, url, kw.get("params"), resp)
            _maybe_suggest_proxies(resp.status, self._has_proxy)
            if self.on_response:
                self.on_response(resp)
            return resp

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def put(self, url, **kw):
        return self.request("PUT", url, **kw)

    def delete(self, url, **kw):
        return self.request("DELETE", url, **kw)

    def close(self):
        try:
            self._s.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


_default = None


def _session():
    global _default
    if _default is None:
        _default = Session()
    return _default


def get(url, **kw):
    """One-shot GET with a shared impersonating session. Returns a Response."""
    return _session().get(url, **kw)


def post(url, **kw):
    return _session().post(url, **kw)


def fetch(url, **kw):
    return get(url, **kw)
