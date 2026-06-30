"""Transport layer: curl_cffi sessions with real browser TLS/JA3 impersonation.

This is the "get past the front door" pillar (the curl_cffi strength). Every
request carries a genuine Chrome/Safari TLS + HTTP2 fingerprint, which is what
defeats fingerprint-based bot detection that blocks stock Python clients.
"""
from __future__ import annotations

from curl_cffi import requests as _cffi

from .parser import Selector

DEFAULT_IMPERSONATE = "chrome124"


class Response:
    """A fetched page. Behaves like a parser (css/xpath pass through to a Selector)."""

    def __init__(self, raw, meta=None):
        self.raw = raw
        self.status = raw.status_code
        self.url = str(raw.url)
        self.headers = dict(raw.headers)
        self.text = raw.text
        self.content = raw.content
        self.meta = meta or {}
        self._sel = None

    @property
    def ok(self):
        return 200 <= self.status < 300

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

    def save(self, *a, **k):
        return self.selector().save(*a, **k)

    def json(self):
        return self.raw.json()

    def __repr__(self):
        return f"<Response {self.status} {self.url}>"


class Session:
    """A reusable curl_cffi session with impersonation, default headers, retries."""

    def __init__(self, impersonate=DEFAULT_IMPERSONATE, headers=None, timeout=30,
                 retries=2, proxies=None, **kw):
        self.impersonate = impersonate
        self.timeout = timeout
        self.retries = retries
        self._headers = dict(headers or {})
        self._s = _cffi.Session(impersonate=impersonate, proxies=proxies, **kw)

    def request(self, method, url, **kw):
        kw.setdefault("impersonate", self.impersonate)
        kw.setdefault("timeout", self.timeout)
        merged = dict(self._headers)
        merged.update(kw.pop("headers", {}) or {})
        if merged:
            kw["headers"] = merged
        meta = kw.pop("meta", None)
        retries = kw.pop("retries", self.retries)
        last = None
        for _ in range(retries + 1):
            try:
                return Response(self._s.request(method, url, **kw), meta=meta)
            except Exception as exc:  # noqa: BLE001
                last = exc
        raise last

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def close(self):
        try:
            self._s.close()
        except Exception:  # noqa: BLE001
            pass


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
