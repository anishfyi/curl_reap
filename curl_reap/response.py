"""Response objects for the curl_reap transport.

:class:`Response` is what every fetch returns: the status line, the ordered
multi-value headers, the raw ``content`` bytes, a *lazy* ``text`` (decoded
once, on first access, from BOM/Content-Type/meta detection), cookies the
hop set, redirect history, timing, and the selector passthroughs that make a
fetched page immediately parseable (``css``, ``xpath``, ``jsonld``,
``markdown`` ...).  ``_RawResponse`` is the transport's internal data
record; the session layer wraps it.

The body is kept as raw ``content`` bytes and only decoded on demand, so a
5 MB binary no longer costs a second 5 MB string the way 1.x's eager
``.text`` did.  ``iter_content``/``iter_lines`` replay the buffered body in
chunks (and stream, when the transport produced a streaming body).
"""
from __future__ import annotations

import json as _json
import re
import time
from datetime import timedelta
from urllib.parse import urljoin

from .headers import Headers

_META_CHARSET = re.compile(rb'<meta[^>]+?charset=["\']?\s*([a-zA-Z0-9_\-]+)', re.I)
_META_CT = re.compile(rb'<meta[^>]+?content=["\'][^"\']*?charset=\s*([a-zA-Z0-9_\-]+)', re.I)

_CHALLENGE_MARKERS = (
    "just a moment",
    "checking your browser",
    "attention required",
    "verify you are human",
    "javascript is disabled",
    "enable javascript and cookies",
    "cf-chl",
    "_incapsula_resource",
    "ddos protection by cloudflare",
)

#: curl's CURLINFO_HTTP_VERSION codes, for ``http_version_int``.
_HTTP_VERSION_INT = {
    "HTTP/1.0": 1,
    "HTTP/1.1": 2,
    "HTTP/2": 3,
    "h2": 3,
    "HTTP/2.0": 3,
    "HTTP/3": 4,
    "h3": 4,
}


def detect_encoding(content, headers=None):
    """Detect a useful charset from BOM, Content-Type, or HTML metadata."""
    if not content:
        return None
    if content[:3] == b"\xef\xbb\xbf":
        return "utf-8-sig"
    if content[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    content_type = ""
    if headers:
        content_type = headers.get("Content-Type") or ""
    match = re.search(r"charset=[\"']?\s*([a-zA-Z0-9_\-]+)", content_type, re.I)
    if match:
        return match.group(1)
    head = content[:4096]
    match = _META_CHARSET.search(head) or _META_CT.search(head)
    if match:
        try:
            return match.group(1).decode("ascii")
        except (UnicodeDecodeError, AttributeError):
            pass
    return None


class _RawResponse:
    """Transport-level record for one response (or redirect hop)."""

    def __init__(self, status, reason, version, url, headers, content, cookies=None,
                 cookie_specs=None, saved_bytes=0, trailers=(), infos=None,
                 request_size=0, response_size=0):
        self.status_code = status
        self.reason = reason
        self.http_version = version
        self.url = url
        self.headers = headers
        self.content = content
        self.cookies = cookies or {}
        self.cookie_specs = cookie_specs or []
        self.saved_bytes = saved_bytes
        self.trailers = list(trailers or ())
        self.infos = dict(infos or {})
        self.request_size = request_size
        self.response_size = response_size or len(content or b"")
        self.history = []
        self.elapsed = 0.0
        #: sockets owning a streaming body (iter_content pulls from these)
        self.stream = None
        self.primary_ip = None
        self.primary_port = None
        self.local_ip = None
        self.local_port = None


class Response:
    """A fetched page. CSS and XPath methods pass through to ``Selector``.

    Attributes beyond the 1.x set: ``is_success`` (2xx), ``ok`` (2xx/3xx),
    ``reason``, ``redirect_count``/``redirect_url``/``is_redirect``,
    ``elapsed`` (``timedelta``) and ``elapsed_seconds``, ``charset`` and
    ``charset_encoding`` with a settable ``encoding`` and ``default_encoding``,
    ``primary_ip``/``primary_port``/``local_ip``/``local_port``,
    ``http_version``/``http_version_int``, ``infos`` (tls backend, cipher,
    group, ALPN, byte counts), ``request`` (a snapshot of what was sent) and
    ``iter_content``/``iter_lines``/``close`` for streamed bodies.
    """

    def __init__(self, raw=None, meta=None, elapsed=0.0, *, status=None, url=None,
                 headers=None, content=None, text=None, from_cache=False):
        self.raw = raw
        self.meta = meta or {}
        self._headers = Headers(headers or {})
        self._encoding = None
        self._text = None
        self._sel = None
        if raw is not None:
            self.status = raw.status_code
            self.url = str(raw.url)
            self.headers = Headers(raw.headers)
            self.content = raw.content
            self._cookies = dict(getattr(raw, "cookies", {}) or {})
            self.history = [Response(raw=hop) for hop in getattr(raw, "history", ())]
            self.reason = getattr(raw, "reason", "") or ""
            self.http_version = getattr(raw, "http_version", "HTTP/1.1")
            self.infos = dict(getattr(raw, "infos", None) or {})
            self.request_size = getattr(raw, "request_size", 0)
            self.response_size = getattr(raw, "response_size", 0) or len(self.content or b"")
            self.primary_ip = getattr(raw, "primary_ip", None)
            self.primary_port = getattr(raw, "primary_port", None)
            self.local_ip = getattr(raw, "local_ip", None)
            self.local_port = getattr(raw, "local_port", None)
            self._stream = getattr(raw, "stream", None)
        else:
            self.status = status
            self.url = url
            self.headers = Headers(headers or {})
            self._cookies = {}
            self.history = []
            self.reason = ""
            self.http_version = "HTTP/1.1"
            self.infos = {}
            self.request_size = 0
            self.response_size = len(content or b"") if content is not None else 0
            self.primary_ip = self.primary_port = None
            self.local_ip = self.local_port = None
            self._stream = None
            if content is not None:
                self.content = content
                if text is not None:
                    self._text = text
            else:
                self._text = text or ""
                self.content = None if self._text is None else self._text.encode("utf-8")
        if isinstance(elapsed, timedelta):
            self.elapsed = elapsed
        else:
            self.elapsed = timedelta(seconds=elapsed or 0.0)
        self.from_cache = from_cache
        self.request = getattr(raw, "request", None)
        self.default_encoding = "utf-8"

    # -- status ---------------------------------------------------------------
    @property
    def status_code(self):
        return self.status

    @property
    def ok(self):
        """True for 200-399 (redirects followed by default; 3xx surfaces with allow_redirects=False)."""
        return self.status is not None and 200 <= self.status < 400

    @property
    def is_success(self):
        """True for 2xx only."""
        return self.status is not None and 200 <= self.status < 300

    @property
    def is_redirect(self):
        return self.status is not None and 300 <= self.status < 400 and \
            bool(self.headers.get("Location"))

    @property
    def redirect_url(self):
        """The Location of a redirect response, resolved against this URL."""
        location = self.headers.get("Location")
        if not location:
            return None
        return urljoin(self.url or "", _redirect_target(location))

    @property
    def redirect_count(self):
        return len(self.history)

    @property
    def elapsed_seconds(self):
        return self.elapsed.total_seconds()

    def raise_for_status(self):
        if not self.is_success:
            from .exceptions import HTTPError
            raise HTTPError(self)
        return self

    # -- body -----------------------------------------------------------------
    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, value):
        self._content = value
        if value is not None:
            self.response_size = len(value)

    @property
    def encoding(self):
        if self._encoding is None:
            if self._content:
                self._encoding = detect_encoding(self._content, self.headers) or self.default_encoding
            else:
                self._encoding = self.default_encoding
        return self._encoding

    @encoding.setter
    def encoding(self, value):
        self._encoding = value
        self._text = None

    @property
    def charset(self):
        """The charset the body declares (Content-Type or meta), or None."""
        return detect_encoding(self._content, self.headers)

    @property
    def charset_encoding(self):
        return self.charset

    @property
    def text(self):
        if self._text is None and self._content is not None:
            encoding = self.encoding
            try:
                self._text = self._content.decode(encoding, "replace")
            except (LookupError, TypeError):
                self._text = self._content.decode("utf-8", "replace")
        return self._text if self._text is not None else ""

    @text.setter
    def text(self, value):
        self._text = value

    def json(self, **kwargs):
        return _json.loads(self.content.decode(self.encoding, "replace")
                           if self._content is not None else self.text, **kwargs)

    def iter_content(self, chunk_size=64 * 1024):
        """Yield the body in chunks; streams when the transport kept the body unbuffered."""
        if self._stream is not None:
            stream, self._stream = self._stream, None
            try:
                while True:
                    chunk = stream.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
            finally:
                stream.close()
            return
        if self._content is None:
            return
        view = memoryview(self._content)
        for start in range(0, len(view), max(1, chunk_size)):
            yield bytes(view[start:start + chunk_size])

    def iter_lines(self, chunk_size=64 * 1024, delimiter=None):
        pending = b""
        for chunk in self.iter_content(chunk_size):
            pending += chunk
            if delimiter is not None:
                parts = pending.split(delimiter)
                pending = parts.pop()
                for part in parts:
                    yield part
                continue
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                yield line.rstrip(b"\r")
        if pending:
            yield pending

    def close(self):
        """Release a streaming body's connection (no-op for buffered bodies)."""
        stream, self._stream = self._stream, None
        if stream is not None:
            stream.close()

    # -- cookies / block reasons ---------------------------------------------
    @property
    def cookies(self):
        return dict(self._cookies)

    @property
    def looks_like_challenge(self):
        """True when the body smells like a bot wall instead of real content."""
        head = (self.text or "")[:6000].lower()
        if not head:
            return False
        if any(marker in head for marker in _CHALLENGE_MARKERS):
            return True
        if "requestsubmit" in head and ('name="solution"' in head
                                        or "name='solution'" in head):
            return "<p" not in head and "<article" not in head
        return False

    _BLOCK_REASONS = {403: "forbidden", 407: "proxy_auth_required", 429: "rate_limited"}

    @property
    def block_reason(self):
        if self.status in self._BLOCK_REASONS:
            return self._BLOCK_REASONS[self.status]
        if self.looks_like_challenge:
            return "challenge"
        return None

    # -- selectors ------------------------------------------------------------
    def urljoin(self, url):
        base = self.selector().base_url or self.url or ""
        return urljoin(base, url)

    def follow(self, target, callback=None, **kw):
        from .spider import Request
        if hasattr(target, "attr"):  # Selector
            target = target.attr("href") or target.text
        if target is None:
            raise ValueError("follow() got nothing to follow")
        return Request(self.urljoin(str(target)), callback=callback, **kw)

    def selector(self):
        if self._sel is None:
            from .parser import Selector
            self._sel = Selector(content=self.text, url=self.url, status=self.status,
                                 headers=self.headers)
        return self._sel

    def css(self, *args, **kwargs):
        return self.selector().css(*args, **kwargs)

    def css_first(self, *args, **kwargs):
        return self.selector().css_first(*args, **kwargs)

    def xpath(self, *args, **kwargs):
        return self.selector().xpath(*args, **kwargs)

    def find_by_text(self, *args, **kwargs):
        return self.selector().find_by_text(*args, **kwargs)

    def find_similar(self, *args, **kwargs):
        return self.selector().find_similar(*args, **kwargs)

    def re(self, *args, **kwargs):
        return self.selector().re(*args, **kwargs)

    def re_first(self, *args, **kwargs):
        return self.selector().re_first(*args, **kwargs)

    def save(self, *args, **kwargs):
        return self.selector().save(*args, **kwargs)

    def jsonld(self):
        return self.selector().jsonld()

    def meta_tags(self):
        return self.selector().meta_tags()

    def links(self, **kwargs):
        return self.selector().links(**kwargs)

    def images(self, **kwargs):
        return self.selector().images(**kwargs)

    def tables(self):
        return self.selector().tables()

    def markdown(self, *args, **kwargs):
        return self.selector().markdown(*args, **kwargs)

    def extract(self, fields, **kwargs):
        return self.selector().extract(fields, **kwargs)

    # -- plumbing ---------------------------------------------------------------
    @property
    def http_version_int(self):
        return _HTTP_VERSION_INT.get(self.http_version, 0)

    def __getstate__(self):
        state = self.__dict__.copy()
        state["_sel"] = None
        state["_stream"] = None
        state["raw"] = None
        return state

    def __repr__(self):
        tag = " (cache)" if self.from_cache else ""
        return "<Response %s %s%s>" % (self.status, self.url, tag)


def _redirect_target(location):
    """Normalize a Location value without re-encoding already-encoded bytes.

    Header values arrive as latin-1 text.  A UTF-8 path that the server
    percent-encoded stays exactly as sent; only genuinely unsafe characters
    (spaces, non-ASCII) are percent-encoded, so ``/caf%C3%A9`` never becomes
    ``/caf%C3%83%C2%A9``.
    """
    try:
        location.encode("ascii")
        return location
    except UnicodeEncodeError:
        pass
    try:
        repaired = location.encode("latin-1").decode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError):
        repaired = location
    from urllib.parse import quote
    return quote(repaired, safe="/%:@!$&'()*+,;=-._~?=#[]")
