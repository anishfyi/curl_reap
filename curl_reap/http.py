"""Ordered HTTP/1.1 transport built directly on ``socket`` and ``ssl``.

Unlike high-level HTTP libraries, curl_reap serializes the request line and
headers itself.  Header order and casing are therefore stable, response bodies
are framed without an intermediary, and idle connections can be reused.  TLS
configuration is provided by :mod:`curl_reap.tls`; see that module for the
important limits of browser fingerprint shaping with the standard library.
"""
from __future__ import annotations

import base64
import json as _json
import os
import random
import socket
import ssl
import threading
import time
import zlib
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from typing import Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import quote, urlencode, urljoin, urlsplit, urlunsplit

from .parser import Selector
from .tls import PROFILES, Profile, create_ssl_context, resolve_profile


RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524})
_IP_BLOCK_STATUSES = frozenset({403, 407, 429})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_NO_BODY_STATUSES = frozenset({204, 205, 304})
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
_MAX_HEADER_BYTES = 65536


class TransportError(OSError):
    """A connection, TLS, or HTTP framing failure."""


class RetryPolicy:
    """Exponential backoff with jitter and optional ``Retry-After`` support."""

    def __init__(self, retries=2, backoff=0.5, max_backoff=30.0,
                 statuses=RETRY_STATUSES, respect_retry_after=True):
        if retries < 0:
            raise ValueError("retries must be >= 0")
        if backoff < 0 or max_backoff < 0:
            raise ValueError("backoff values must be >= 0")
        self.retries = int(retries)
        self.backoff = float(backoff)
        self.max_backoff = float(max_backoff)
        self.statuses = frozenset(statuses)
        self.respect_retry_after = respect_retry_after

    def should_retry_status(self, status):
        return status in self.statuses

    def delay(self, attempt, retry_after=None):
        if retry_after is not None and self.respect_retry_after:
            try:
                return min(max(0.0, float(retry_after)), self.max_backoff)
            except (TypeError, ValueError):
                try:
                    retry_at = parsedate_to_datetime(str(retry_after))
                    seconds = retry_at.timestamp() - time.time()
                    return min(max(0.0, seconds), self.max_backoff)
                except (TypeError, ValueError, OverflowError):
                    pass
        base = self.backoff * (2 ** attempt)
        return min(self.max_backoff, base * (0.5 + random.random()))


class CaseInsensitiveHeaders(dict):
    """A dict retaining received casing while providing case-insensitive lookup."""

    def _actual(self, key):
        wanted = str(key).lower()
        for current in dict.keys(self):
            if current.lower() == wanted:
                return current
        return None

    def __getitem__(self, key):
        actual = self._actual(key)
        if actual is None:
            raise KeyError(key)
        return dict.__getitem__(self, actual)

    def __contains__(self, key):
        return self._actual(key) is not None

    def get(self, key, default=None):
        actual = self._actual(key)
        if actual is None:
            return default
        return dict.get(self, actual, default)

    def setdefault(self, key, default=None):
        actual = self._actual(key)
        if actual is not None:
            return dict.__getitem__(self, actual)
        dict.__setitem__(self, key, default)
        return default


def _header_items(headers):
    if headers is None:
        return []
    if isinstance(headers, Mapping):
        source = headers.items()
    else:
        source = headers
    items = []
    for item in source:
        try:
            name, value = item
        except (TypeError, ValueError):
            raise TypeError("headers must be a mapping or sequence of (name, value) pairs")
        name = str(name)
        if not name or ":" in name or "\r" in name or "\n" in name:
            raise ValueError("invalid HTTP header name %r" % name)
        if value is not None:
            value = str(value)
            if "\r" in value or "\n" in value:
                raise ValueError("invalid newline in HTTP header %s" % name)
        items.append((name, value))
    return items


def _merge_headers(*sources):
    """Case-insensitive last-wins merge without losing deterministic position."""
    merged = []
    positions = {}
    for source in sources:
        for name, value in _header_items(source):
            lower = name.lower()
            if value is None:
                if lower in positions:
                    merged.pop(positions[lower])
                    positions = {n.lower(): i for i, (n, unused) in enumerate(merged)}
                continue
            if lower in positions:
                merged[positions[lower]] = (name, value)
            else:
                positions[lower] = len(merged)
                merged.append((name, value))
    return merged


def _find_header(headers, name):
    lower = name.lower()
    for current, value in headers:
        if current.lower() == lower:
            return value
    return None


def _authority(host, port, default_port):
    rendered = "[%s]" % host if ":" in host and not host.startswith("[") else host
    if port == default_port:
        return rendered
    return "%s:%s" % (rendered, port)


def _request_target(parts):
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="=&?/:;+,%@!$'()*-._~")
    return path + (("?" + query) if query else "")


def _url_with_params(url, params):
    if not params:
        return url
    parts = urlsplit(url)
    encoded = urlencode(params, doseq=True)
    query = "&".join(part for part in (parts.query, encoded) if part)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


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
    if isinstance(data, Mapping) or isinstance(data, (list, tuple)):
        return urlencode(data, doseq=True).encode("ascii"), "application/x-www-form-urlencoded"
    raise TypeError("data must be bytes, str, a mapping, or a sequence of pairs")


def _decode_content(content, encoding):
    if not content or not encoding:
        return content
    encodings = [item.strip().lower() for item in encoding.split(",") if item.strip()]
    decoded = content
    for current in reversed(encodings):
        if current in ("identity", ""):
            continue
        if current in ("gzip", "x-gzip"):
            try:
                decoded = zlib.decompress(decoded, 16 + zlib.MAX_WBITS)
            except zlib.error as exc:
                raise TransportError("invalid gzip response body: %s" % exc)
        elif current == "deflate":
            try:
                decoded = zlib.decompress(decoded)
            except zlib.error:
                try:
                    decoded = zlib.decompress(decoded, -zlib.MAX_WBITS)
                except zlib.error as exc:
                    raise TransportError("invalid deflate response body: %s" % exc)
        elif current == "br":
            try:
                import brotli
            except ImportError:
                raise TransportError("received Brotli content but optional 'brotli' is not installed")
            try:
                decoded = brotli.decompress(decoded)
            except Exception as exc:  # third-party implementations use different errors
                raise TransportError("invalid Brotli response body: %s" % exc)
        else:
            raise TransportError("unsupported Content-Encoding %r" % current)
    return decoded


class _BufferedSocket:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = bytearray()

    def _receive(self):
        try:
            chunk = self.sock.recv(65536)
        except (OSError, ssl.SSLError) as exc:
            raise TransportError(str(exc))
        if not chunk:
            raise TransportError("connection closed before the response was complete")
        self.buffer.extend(chunk)

    def read_until(self, marker, limit=None):
        while True:
            position = self.buffer.find(marker)
            if position >= 0:
                end = position + len(marker)
                result = bytes(self.buffer[:end])
                del self.buffer[:end]
                return result
            if limit is not None and len(self.buffer) >= limit:
                raise TransportError("HTTP response headers exceed %s bytes" % limit)
            self._receive()

    def read_exact(self, size):
        while len(self.buffer) < size:
            self._receive()
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def read_exact_into(self, total, write, bufsize=262144):
        """Stream exactly ``total`` buffered+wire bytes through ``write``."""
        remaining = total
        while remaining > 0:
            if self.buffer:
                take = min(len(self.buffer), remaining, bufsize)
                write(bytes(self.buffer[:take]))
                del self.buffer[:take]
                remaining -= take
            else:
                self._receive()

    def drain_to_close(self, write, bufsize=262144):
        """Stream every byte until the peer closes; return the count."""
        saved = 0
        while True:
            if self.buffer:
                write(bytes(self.buffer))
                saved += len(self.buffer)
                self.buffer.clear()
            try:
                chunk = self.sock.recv(bufsize)
            except (OSError, ssl.SSLError) as exc:
                raise TransportError(str(exc))
            if not chunk:
                return saved
            write(chunk)
            saved += len(chunk)

    def read_to_close(self):
        chunks = [bytes(self.buffer)]
        self.buffer.clear()
        while True:
            try:
                chunk = self.sock.recv(65536)
            except (OSError, ssl.SSLError) as exc:
                raise TransportError(str(exc))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)


class _Connection:
    def __init__(self, sock, key):
        self.sock = sock
        self.reader = _BufferedSocket(sock)
        self.h2 = None  # H2Protocol when ALPN negotiated h2
        self.key = key
        self.closed = False

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass


class _RawResponse:
    def __init__(self, status, reason, version, url, headers, content, cookies=None,
                 cookie_specs=None, saved_bytes=0):
        self.status_code = status
        self.reason = reason
        self.http_version = version
        self.url = url
        self.headers = headers
        self.content = content
        self.cookies = cookies or {}
        self.cookie_specs = cookie_specs or []
        self.saved_bytes = saved_bytes
        encoding = detect_encoding(content, headers) or "utf-8"
        try:
            self.text = content.decode(encoding, "replace")
        except (LookupError, TypeError):
            self.text = content.decode("utf-8", "replace")

    def json(self):
        return _json.loads(self.text)


class _StreamDecoder:
    """Incremental Content-Encoding decoder for streaming sinks."""

    def __init__(self, content_encoding):
        encoding = (content_encoding or "").strip().lower()
        if encoding in ("", "identity"):
            raise ValueError("nothing to decode")
        if "gzip" in encoding:
            self._dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif "deflate" in encoding:
            self._dec = zlib.decompressobj()
            self._maybe_raw = True
        else:
            raise TransportError(
                "cannot stream a %r encoded body to a file; install brotli "
                "support upstream or disable that Accept-Encoding" % encoding)

    def feed(self, data):
        try:
            return self._dec.decompress(data)
        except zlib.error:
            # Some servers send raw-deflate where zlib-wrapped was promised;
            # restart with the raw window on the first failure.
            if getattr(self, "_maybe_raw", False):
                self._dec = zlib.decompressobj(-zlib.MAX_WBITS)
                self._maybe_raw = False
                return self._dec.decompress(data)
            raise TransportError("corrupt %s response body" % "compressed")

    def finish(self):
        try:
            return self._dec.flush()
        except zlib.error:
            raise TransportError("truncated compressed response body")


def _body_streamer(write, headers):
    """Wrap ``write`` with incremental decoding when the body is compressed."""
    encoding = (headers.get("Content-Encoding") or "").strip().lower()
    try:
        decoder = _StreamDecoder(encoding)
    except ValueError:
        return write
    total = [0]

    def feed(chunk):
        out = decoder.feed(chunk)
        if out:
            write(out)
            total[0] += len(out)
        return len(chunk)

    feed.finish = lambda: decoder.finish()
    return feed


class CookieJar:
    """In-memory cookie store scoped by domain, path and scheme.

    ``Session`` keeps one jar for its lifetime: response cookies are stored
    automatically (including on every redirect hop) and replayed on matching
    requests. Thread-safe. Cookies live only as long as the process.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # name -> {"value","domain","path","secure","expires"}
        self._cookies = {}

    def absorb(self, url, specs):
        """Store parsed Set-Cookie attribute dicts from one response."""
        parts = urlsplit(url)
        default_domain = (parts.hostname or "").lower()
        now = time.time()
        with self._lock:
            for spec in specs:
                domain = (spec.get("domain") or default_domain).lower()
                expires = spec.get("expires")
                max_age = spec.get("max_age")
                if max_age:
                    try:
                        expires = now + float(max_age)
                    except (TypeError, ValueError):
                        pass
                if expires is not None and expires <= now:
                    self._cookies.pop(spec["name"], None)
                    continue
                self._cookies[spec["name"]] = {
                    "value": spec["value"],
                    "domain": domain,
                    "path": spec.get("path") or "/",
                    "secure": bool(spec.get("secure")),
                    "expires": expires,
                }

    def store(self, url, pairs):
        """Store plain name/value pairs against ``url``'s host."""
        self.absorb(url, [{"name": n, "value": v} for n, v in dict(pairs).items()])

    def header_for(self, url):
        """Cookie header value for ``url``, or empty string when none match."""
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        secure = parts.scheme.lower() == "https"
        path = parts.path or "/"
        now = time.time()
        pairs = []
        with self._lock:
            for name in list(self._cookies):
                cookie = self._cookies[name]
                if cookie["expires"] is not None and cookie["expires"] <= now:
                    del self._cookies[name]
                    continue
                if cookie["secure"] and not secure:
                    continue
                domain = cookie["domain"]
                if not (host == domain or domain.startswith(".") and host.endswith(domain)):
                    continue
                if not path.startswith(cookie["path"]):
                    continue
                pairs.append("%s=%s" % (name, cookie["value"]))
        return "; ".join(pairs)

    def get_dict(self):
        with self._lock:
            return {name: c["value"] for name, c in self._cookies.items()
                    if c["expires"] is None or c["expires"] > time.time()}

    def clear(self):
        with self._lock:
            self._cookies.clear()

    def __repr__(self):
        return "CookieJar(%d cookies)" % len(self.get_dict())


class _Transport:
    """Thread-safe pool of idle HTTP connections (HTTP/1.1 and optional h2)."""

    def __init__(self, http2=False):
        self._pool = {}
        self._contexts = {}
        self._lock = threading.Lock()
        self._closed = False
        self.http2 = bool(http2)

    def _context(self, profile, verify):
        key = (profile, verify)
        alpn = ("http/1.1",)
        if self.http2:
            try:
                import h2  # noqa: F401
                alpn = ("h2", "http/1.1")
            except ImportError:
                pass
        with self._lock:
            context = self._contexts.get(key)
        if context is None:
            context = create_ssl_context(profile, verify=verify, alpn=alpn)
            with self._lock:
                context = self._contexts.setdefault(key, context)
        return context

    def _connection_key(self, scheme, host, port, proxy, profile, verify):
        return (scheme, host, port, proxy, profile, verify)

    def _acquire(self, scheme, host, port, proxy, profile, verify, timeout):
        key = self._connection_key(scheme, host, port, proxy, profile, verify)
        with self._lock:
            pooled = self._pool.get(key)
            conn = pooled.pop() if pooled else None
        if conn is not None:
            try:
                conn.sock.settimeout(timeout)
            except (AttributeError, OSError):
                pass
            return conn
        return self._connect(scheme, host, port, proxy, profile, verify, timeout, key)

    def _connect(self, scheme, host, port, proxy, profile, verify, timeout, key):
        connect_host, connect_port = host, port
        proxy_parts = None
        if proxy:
            proxy_parts = urlsplit(proxy if "://" in proxy else "http://" + proxy)
            if proxy_parts.scheme.lower() != "http":
                raise ValueError("only HTTP CONNECT proxies are supported")
            if not proxy_parts.hostname:
                raise ValueError("proxy must include a hostname")
            connect_host = proxy_parts.hostname
            connect_port = proxy_parts.port or 8080
        try:
            sock = socket.create_connection((connect_host, connect_port), timeout=timeout)
            try:
                sock.settimeout(timeout)
            except AttributeError:
                pass
        except OSError as exc:
            raise TransportError("could not connect to %s:%s: %s" %
                                 (connect_host, connect_port, exc))

        try:
            if proxy_parts is not None and scheme == "https":
                authority = _authority(host, port, 443)
                lines = ["CONNECT %s HTTP/1.1" % authority, "Host: %s" % authority]
                auth = self._proxy_authorization(proxy_parts)
                if auth:
                    lines.append("Proxy-Authorization: %s" % auth)
                payload = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
                sock.sendall(payload)
                reader = _BufferedSocket(sock)
                head = reader.read_until(b"\r\n\r\n", _MAX_HEADER_BYTES)
                first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                parts = first.split(" ", 2)
                if len(parts) < 2 or not parts[1].isdigit() or int(parts[1]) != 200:
                    raise TransportError("proxy CONNECT failed: %s" % first)
            if scheme == "https":
                context = self._context(profile, verify)
                sock = context.wrap_socket(sock, server_hostname=host)
                selected = getattr(sock, "selected_alpn_protocol", lambda: None)()
                if selected not in (None, "http/1.1", "h2"):
                    raise TransportError("server negotiated unsupported ALPN protocol %s" % selected)
            conn = _Connection(sock, key)
            if scheme == "https" and selected == "h2":
                from .h2engine import H2Protocol
                conn.h2 = H2Protocol(sock)
            return conn
        except Exception:
            try:
                sock.close()
            except OSError:
                pass
            raise

    @staticmethod
    def _proxy_authorization(proxy_parts):
        if proxy_parts.username is None:
            return None
        from urllib.parse import unquote
        user = unquote(proxy_parts.username)
        password = unquote(proxy_parts.password or "")
        token = base64.b64encode((user + ":" + password).encode("utf-8")).decode("ascii")
        return "Basic " + token

    def _release(self, conn, reusable):
        if not reusable or self._closed:
            conn.close()
            return
        with self._lock:
            self._pool.setdefault(conn.key, []).append(conn)

    def _response(self, conn, method, url, sink=None):
        while True:
            head = conn.reader.read_until(b"\r\n\r\n", _MAX_HEADER_BYTES)
            raw_lines = head[:-4].split(b"\r\n")
            if not raw_lines:
                raise TransportError("empty HTTP response")
            status_line = raw_lines[0].decode("latin-1", "replace")
            parts = status_line.split(" ", 2)
            if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
                raise TransportError("malformed HTTP status line %r" % status_line)
            version = parts[0]
            status = int(parts[1])
            reason = parts[2] if len(parts) == 3 else ""
            headers = CaseInsensitiveHeaders()
            received_headers = []
            previous = None
            for raw_line in raw_lines[1:]:
                if raw_line[:1] in (b" ", b"\t") and previous is not None:
                    value = headers[previous] + " " + raw_line.decode("latin-1").strip()
                    dict.__setitem__(headers, previous, value)
                    received_headers[-1] = (previous, value)
                    continue
                if b":" not in raw_line:
                    raise TransportError("malformed HTTP response header")
                raw_name, raw_value = raw_line.split(b":", 1)
                name = raw_name.decode("latin-1").strip()
                value = raw_value.decode("latin-1").strip()
                previous = name
                received_headers.append((name, value))
                actual = headers._actual(name)
                if actual is None:
                    dict.__setitem__(headers, name, value)
                else:
                    dict.__setitem__(headers, actual, headers[actual] + ", " + value)
            if status < 200 and status != 101:
                continue
            break

        no_body = method.upper() == "HEAD" or status in _NO_BODY_STATUSES or 100 <= status < 200
        reusable = True
        saved = 0
        if no_body:
            content = b""
        elif sink is not None and status not in _REDIRECT_STATUSES:
            # Stream to disk: bytes land in the file as they come off the
            # wire, with transparent gzip/deflate decoding.
            part_path = sink + ".reap-part"
            try:
                with open(part_path, "wb") as fh:
                    feed = _body_streamer(fh.write, headers)
                    if "chunked" in (headers.get("Transfer-Encoding") or "").lower():
                        self._read_chunked_into(conn, headers, feed)
                    elif headers.get("Content-Length") is not None:
                        length = int(headers.get("Content-Length"))
                        conn.reader.read_exact_into(length, feed)
                    else:
                        conn.reader.drain_to_close(feed)
                        reusable = False
                    tail = getattr(feed, "finish", None)
                    if tail is not None:
                        rest = tail()
                        if rest:
                            fh.write(rest)
                    saved = fh.tell()
                os.replace(part_path, sink)
            except BaseException:
                try:
                    os.remove(part_path)
                except OSError:
                    pass
                raise
            content = b""
        elif "chunked" in (headers.get("Transfer-Encoding") or "").lower():
            content = self._read_chunked(conn, headers)
        elif headers.get("Content-Length") is not None:
            try:
                length = int(headers.get("Content-Length"))
            except (TypeError, ValueError):
                raise TransportError("invalid Content-Length header")
            if length < 0:
                raise TransportError("invalid negative Content-Length")
            content = conn.reader.read_exact(length)
        else:
            content = conn.reader.read_to_close()
            reusable = False

        connection_header = (headers.get("Connection") or "").lower()
        if connection_header == "close" or (version == "HTTP/1.0" and connection_header != "keep-alive"):
            reusable = False
        decoded = content if sink is not None else _decode_content(content, headers.get("Content-Encoding"))
        cookies = {}
        cookie_specs = []
        for name, value in received_headers:
            if name.lower() == "set-cookie":
                parsed = SimpleCookie()
                try:
                    parsed.load(value)
                except Exception:
                    continue
                for key, morsel in parsed.items():
                    cookies[key] = morsel.value
                    expires = None
                    raw_expires = morsel["expires"]
                    if raw_expires:
                        try:
                            from email.utils import parsedate_to_datetime as _pdt
                            expires = _pdt(raw_expires).timestamp()
                        except Exception:
                            expires = None
                    cookie_specs.append({
                        "name": key,
                        "value": morsel.value,
                        "domain": (morsel["domain"] or "").lstrip(".").lower(),
                        "path": morsel["path"] or "/",
                        "secure": bool(morsel["secure"]),
                        "max_age": morsel["max-age"],
                        "expires": expires,
                    })
        raw = _RawResponse(status, reason, version, url, headers, decoded, cookies,
                           cookie_specs=cookie_specs, saved_bytes=saved)
        return raw, reusable

    @staticmethod
    def _read_chunked_into(conn, headers, write):
        """Stream a chunked body straight to ``write``; return bytes written."""
        saved = 0
        reader = conn.reader
        while True:
            line = reader.read_until(b"\r\n", _MAX_HEADER_BYTES)[:-2]
            size_text = line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                raise TransportError("invalid chunk size %r" % size_text.decode("latin-1", "replace"))
            if size < 0:
                raise TransportError("invalid negative chunk size")
            if size == 0:
                while True:
                    trailer = reader.read_until(b"\r\n", _MAX_HEADER_BYTES)[:-2]
                    if not trailer:
                        return saved
                    if b":" not in trailer:
                        raise TransportError("malformed HTTP trailer")
            reader.read_exact_into(size, write)
            saved += size
            if reader.read_exact(2) != b"\r\n":
                raise TransportError("chunk data is not terminated by CRLF")

    @staticmethod
    def _read_chunked(conn, headers):
        chunks = []
        while True:
            line = conn.reader.read_until(b"\r\n", _MAX_HEADER_BYTES)[:-2]
            size_text = line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                raise TransportError("invalid chunk size %r" % size_text.decode("latin-1", "replace"))
            if size < 0:
                raise TransportError("invalid negative chunk size")
            if size == 0:
                while True:
                    trailer = conn.reader.read_until(b"\r\n", _MAX_HEADER_BYTES)[:-2]
                    if not trailer:
                        return b"".join(chunks)
                    if b":" not in trailer:
                        raise TransportError("malformed HTTP trailer")
                    name, value = trailer.split(b":", 1)
                    headers.setdefault(name.decode("latin-1").strip(),
                                       value.decode("latin-1").strip())
            chunks.append(conn.reader.read_exact(size))
            if conn.reader.read_exact(2) != b"\r\n":
                raise TransportError("chunk data is not terminated by CRLF")

    def _single_request(self, method, url, profile, custom_headers, body,
                        content_type, timeout, proxy, verify, auth, sink=None):
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError("URL scheme must be http or https")
        if not parts.hostname:
            raise ValueError("URL must include a hostname")
        try:
            host = parts.hostname.encode("idna").decode("ascii")
            port = parts.port or (443 if scheme == "https" else 80)
        except (UnicodeError, ValueError) as exc:
            raise ValueError("invalid URL host or port: %s" % exc)
        authority = _authority(host, port, 443 if scheme == "https" else 80)

        automatic = []
        if auth is not None:
            if not isinstance(auth, (tuple, list)) or len(auth) != 2:
                raise TypeError("auth must be a (username, password) pair")
            token = base64.b64encode((str(auth[0]) + ":" + str(auth[1])).encode("utf-8"))
            automatic.append(("Authorization", "Basic " + token.decode("ascii")))
        elif parts.username is not None:
            from urllib.parse import unquote
            credentials = unquote(parts.username) + ":" + unquote(parts.password or "")
            token = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
            automatic.append(("Authorization", "Basic " + token))

        headers = _merge_headers((("Host", authority),), profile.headers,
                                 custom_headers)
        if content_type and _find_header(headers, "Content-Type") is None:
            headers = _merge_headers(headers, (("Content-Type", content_type),))
        if body or method.upper() in ("POST", "PUT", "PATCH"):
            headers = _merge_headers(headers, (("Content-Length", str(len(body))),))
        if automatic:
            headers = _merge_headers(headers, automatic)
        proxy_parts = None
        if proxy:
            proxy_parts = urlsplit(proxy if "://" in proxy else "http://" + proxy)
            if scheme == "http":
                proxy_auth = self._proxy_authorization(proxy_parts)
                if proxy_auth:
                    headers = _merge_headers(headers, (("Proxy-Authorization", proxy_auth),))

        target = _request_target(parts)
        if proxy_parts is not None and scheme == "http":
            netloc = authority
            target = urlunsplit((scheme, netloc, quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~"),
                                 quote(parts.query, safe="=&?/:;+,%@!$'()*-._~"), ""))

        conn = self._acquire(scheme, host, port, proxy, profile, verify, timeout)
        reusable = False
        try:
            if conn.h2 is not None:
                response = self._h2_exchange(conn, method, scheme, authority,
                                             target, headers, body,
                                             content_type)
                reusable = True
                if sink is not None:
                    # h2 responses buffer before framing; write through the
                    # same atomic part-file dance as the streaming path.
                    part_path = sink + ".reap-part"
                    with open(part_path, "wb") as fh:
                        fh.write(response.content)
                    os.replace(part_path, sink)
                    response.saved_bytes = len(response.content)
                return response
            request_line = "%s %s HTTP/1.1\r\n" % (method.upper(), target)
            rendered = [request_line.encode("ascii")]
            for name, value in headers:
                try:
                    rendered.append(("%s: %s\r\n" % (name, value)).encode("latin-1"))
                except UnicodeEncodeError:
                    raise ValueError("HTTP header %s is not latin-1 encodable" % name)
            rendered.append(b"\r\n")
            payload = b"".join(rendered) + body
            conn.sock.sendall(payload)
            response, reusable = self._response(conn, method, url, sink=sink)
            if (_find_header(headers, "Connection") or "").lower() == "close":
                reusable = False
            return response
        except (OSError, ssl.SSLError) as exc:
            if isinstance(exc, TransportError):
                raise
            raise TransportError(str(exc))
        finally:
            self._release(conn, reusable)

    def _h2_exchange(self, conn, method, scheme, authority, target, headers,
                     body, content_type):
        """One HTTP/2 request on the pooled connection's next stream."""
        status, header_list, content = conn.h2.request(
            method, target, authority, scheme, headers, body=body,
            content_type=content_type)
        cookies = {}
        cookie_specs = []
        from http.cookies import SimpleCookie
        merged = []
        positions = {}
        for name, value in header_list:
            lower = name.lower()
            if lower == "set-cookie":
                parsed = SimpleCookie()
                try:
                    parsed.load(value)
                except Exception:
                    continue
                for key, morsel in parsed.items():
                    cookies[key] = morsel.value
                    expires = None
                    if morsel["expires"]:
                        try:
                            expires = parsedate_to_datetime(
                                morsel["expires"]).timestamp()
                        except Exception:
                            expires = None
                    cookie_specs.append({
                        "name": key, "value": morsel.value,
                        "domain": (morsel["domain"] or "").lstrip(".").lower(),
                        "path": morsel["path"] or "/",
                        "secure": bool(morsel["secure"]),
                        "max_age": morsel["max-age"], "expires": expires})
                # Set-Cookie lines stay separate, never comma-merged
                merged.append((name, value))
                positions[lower] = len(merged) - 1
                continue
            if lower in positions:
                merged[positions[lower]] = (
                    name, merged[positions[lower]][1] + ", " + value)
            else:
                positions[lower] = len(merged)
                merged.append((name, value))
        ci = CaseInsensitiveHeaders()
        for name, value in merged:
            dict.__setitem__(ci, name, value)
        return _RawResponse(status, "", "HTTP/2",
                            urljoin("https://" + authority, target), ci,
                            content, cookies, cookie_specs=cookie_specs)

    def request(self, method, url, profile, headers=None, body=b"", content_type=None,
                timeout=30, proxy=None, verify=True, auth=None,
                allow_redirects=True, max_redirects=10, cookie_jar=None, sink=None):
        current_method = method.upper()
        current_url = url
        current_body = body
        current_content_type = content_type
        current_auth = auth
        redirects = 0
        explicit_cookie = headers is not None and _find_header(headers, "Cookie") is not None
        while True:
            hop_headers = headers
            if cookie_jar is not None and not explicit_cookie:
                # Fresh cookies (including ones set on an earlier hop) are
                # replayed on every hop of this request.
                cookie_header = cookie_jar.header_for(current_url)
                if cookie_header:
                    hop_headers = tuple(
                        h for h in (hop_headers or ()) if h[0].lower() != "cookie"
                    ) + (("Cookie", cookie_header),)
            response = self._single_request(
                current_method, current_url, profile, hop_headers, current_body,
                current_content_type, timeout, proxy, verify, current_auth,
                sink=sink)
            if cookie_jar is not None and response.cookie_specs:
                try:
                    cookie_jar.absorb(current_url, response.cookie_specs)
                except Exception:
                    pass
            location = response.headers.get("Location")
            if not allow_redirects or response.status_code not in _REDIRECT_STATUSES or not location:
                return response
            if redirects >= max_redirects:
                raise TransportError("too many redirects (maximum %s)" % max_redirects)
            next_url = urljoin(current_url, location)
            if urlsplit(next_url).hostname != urlsplit(current_url).hostname:
                current_auth = None
            if response.status_code == 303 or (
                    response.status_code in (301, 302) and current_method == "POST"):
                current_method = "GET"
                current_body = b""
                current_content_type = None
            current_url = next_url
            redirects += 1

    def close(self):
        with self._lock:
            self._closed = True
            connections = [conn for group in self._pool.values() for conn in group]
            self._pool.clear()
        for conn in connections:
            conn.close()


_META_CHARSET = __import__("re").compile(
    rb'<meta[^>]+?charset=["\']?\s*([a-zA-Z0-9_\-]+)', __import__("re").I)
_META_CT = __import__("re").compile(
    rb'<meta[^>]+?content=["\'][^"\']*?charset=\s*([a-zA-Z0-9_\-]+)', __import__("re").I)


def detect_encoding(content, headers=None):
    """Detect a useful charset from BOM, Content-Type, or HTML metadata."""
    import re
    if not content:
        return None
    if content[:3] == b"\xef\xbb\xbf":
        return "utf-8-sig"
    if content[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    content_type = ""
    if headers:
        content_type = headers.get("Content-Type") or headers.get("content-type") or ""
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


class Response:
    """A fetched page. CSS and XPath methods pass through to ``Selector``."""

    def __init__(self, raw=None, meta=None, elapsed=0.0, *, status=None, url=None,
                 headers=None, content=None, text=None, from_cache=False):
        self.raw = raw
        if raw is not None:
            self.status = raw.status_code
            self.url = str(raw.url)
            self.headers = CaseInsensitiveHeaders(raw.headers)
            self.text = raw.text
            self.content = raw.content
            self._cookies = dict(getattr(raw, "cookies", {}) or {})
        else:
            self.status = status
            self.url = url
            self.headers = CaseInsensitiveHeaders(headers or {})
            if content is not None:
                self.content = content
                encoding = detect_encoding(content, self.headers) or "utf-8"
                if text is not None:
                    self.text = text
                else:
                    try:
                        self.text = content.decode(encoding, "replace")
                    except (LookupError, TypeError):
                        self.text = content.decode("utf-8", "replace")
            else:
                self.text = text or ""
                self.content = self.text.encode("utf-8")
            self._cookies = {}
        self.meta = meta or {}
        self.elapsed = elapsed
        self.from_cache = from_cache
        self._sel = None
        self._encoding = None
        self._fix_garbled_text()

    def _fix_garbled_text(self):
        text = self.text
        if not text or "�" not in text or not self.content:
            return
        encoding = detect_encoding(self.content, self.headers)
        if not encoding:
            return
        try:
            decoded = self.content.decode(encoding, "replace")
        except (LookupError, TypeError):
            return
        if decoded.count("�") < text.count("�"):
            self.text = decoded
            self._encoding = encoding

    @property
    def ok(self):
        return self.status is not None and 200 <= self.status < 300

    @property
    def encoding(self):
        if self._encoding is None:
            self._encoding = detect_encoding(self.content, self.headers) or "utf-8"
        return self._encoding

    @property
    def status_code(self):
        return self.status

    @property
    def cookies(self):
        return dict(self._cookies)

    @property
    def looks_like_challenge(self):
        """True when the body smells like a bot wall instead of real content.

        Heuristic: matches common JS-challenge markers (Cloudflare's interstitial,
        "enable JavaScript" shells, Incapsula). A True here means the fetch
        reached the door but the page is rendered client-side; see
        ``curl_reap.render`` for an escape hatch.
        """
        head = (self.text or "")[:6000].lower()
        if not head:
            return False
        return any(marker in head for marker in _CHALLENGE_MARKERS)

    def raise_for_status(self):
        if not self.ok:
            raise HTTPStatusError(self)
        return self

    def urljoin(self, url):
        return urljoin(self.url or "", url)

    def follow(self, target, callback=None, **kw):
        from .spider import Request
        if isinstance(target, Selector):
            target = target.attr("href") or target.text
        if target is None:
            raise ValueError("follow() got nothing to follow")
        return Request(self.urljoin(str(target)), callback=callback, **kw)

    def selector(self):
        if self._sel is None:
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

    def json(self):
        return _json.loads(self.text)

    def __repr__(self):
        tag = " (cache)" if self.from_cache else ""
        return "<Response %s %s%s>" % (self.status, self.url, tag)


class HTTPStatusError(Exception):
    def __init__(self, response):
        self.response = response
        super().__init__("HTTP %s for %s" % (response.status, response.url))


def _pick(sequence, counter, mode):
    if mode == "random":
        return random.choice(sequence)
    return sequence[counter % len(sequence)]


class Session:
    """Reusable ordered HTTP session with TLS/profile and proxy rotation.

    ``profile`` accepts a name from ``PROFILES`` or a custom ``Profile``.
    Supplying ``profiles`` creates a rotation pool; retries advance both the
    profile and proxy pools.  ``rotate`` may be ``"sequence"`` or ``"random"``.
    """

    def __init__(self, profile="chrome", headers=None, timeout=30, retries=2,
                 proxy=None, rotate=None, profiles=None, retry_policy=None,
                 cache=None, on_response=None, block_rotations=None, verify=True,
                 allow_redirects=True, max_redirects=10, impersonate=None,
                 http2=False):
        if rotate not in (None, "sequence", "random"):
            raise ValueError("rotate must be None, 'sequence', or 'random'")
        if impersonate is not None:
            # Versioned-target alias: Session(impersonate="chrome124")
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
        self.allow_redirects = allow_redirects
        self.max_redirects = max_redirects
        self._headers = tuple(_header_items(headers))
        self.cookies = CookieJar()
        self.http2 = bool(http2)
        self._counter = 0
        self._counter_lock = threading.Lock()
        self._transport = _Transport(http2=http2)
        if proxy is None:
            self._proxy_pool = ()
        elif isinstance(proxy, str):
            self._proxy_pool = (proxy,)
        else:
            self._proxy_pool = tuple(proxy)
            if not self._proxy_pool:
                raise ValueError("proxy rotation list must not be empty")
        for item in self._proxy_pool:
            if not isinstance(item, str) or not item:
                raise TypeError("proxy entries must be non-empty strings")
        default_rotations = max(0, len(self._proxy_pool) - 1)
        self.block_rotations = (default_rotations if block_rotations is None
                                else int(block_rotations))
        if self.block_rotations < 0:
            raise ValueError("block_rotations must be >= 0")

    @property
    def retries(self):
        return self.retry_policy.retries

    def _route(self):
        with self._counter_lock:
            counter = self._counter
            self._counter += 1
        mode = self.rotate or "sequence"
        profile = _pick(self.profiles, counter, mode) if len(self.profiles) > 1 else self.profiles[0]
        proxy = (_pick(self._proxy_pool, counter, mode) if self._proxy_pool else None)
        return profile, proxy

    def request(self, method, url, **kwargs):
        meta = kwargs.pop("meta", None)
        no_cache = kwargs.pop("no_cache", False)
        sink = kwargs.pop("_sink", None) or kwargs.pop("sink", None)
        policy = kwargs.pop("retry_policy", None) or self.retry_policy
        if "retries" in kwargs:
            policy = RetryPolicy(retries=kwargs.pop("retries"), backoff=policy.backoff,
                                 max_backoff=policy.max_backoff, statuses=policy.statuses,
                                 respect_retry_after=policy.respect_retry_after)
        timeout = kwargs.pop("timeout", self.timeout)
        request_headers = kwargs.pop("headers", None)
        params = kwargs.pop("params", None)
        data = kwargs.pop("data", None)
        json_data = kwargs.pop("json", None)
        request_proxy = kwargs.pop("proxy", None)
        request_profile = kwargs.pop("profile", None)
        request_impersonate = kwargs.pop("impersonate", None)
        if request_impersonate is not None:
            if (request_profile is not None and
                    resolve_profile(request_impersonate) != resolve_profile(request_profile)):
                raise ValueError("profile and impersonate disagree; pass one")
            request_profile = request_impersonate
        verify = kwargs.pop("verify", self.verify)
        auth = kwargs.pop("auth", None)
        allow_redirects = kwargs.pop("allow_redirects", self.allow_redirects)
        max_redirects = kwargs.pop("max_redirects", self.max_redirects)
        if kwargs:
            name = next(iter(kwargs))
            raise TypeError("unexpected request keyword argument %r" % name)
        if request_profile is not None:
            request_profile = resolve_profile(request_profile)
        body, content_type = _encode_body(data=data, json=json_data)
        combined_headers = tuple(_merge_headers(self._headers, request_headers))
        request_url = _url_with_params(url, params)
        if sink is not None:
            if not isinstance(sink, str):
                raise TypeError("sink must be a file path string")
            no_cache = True

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
                    combined_headers = tuple(_merge_headers(combined_headers, conditional))
                    revalidate = stale

        attempt = 0
        rotations = 0
        while True:
            selected_profile, selected_proxy = self._route()
            if request_profile is not None:
                selected_profile = request_profile
            if request_proxy is not None:
                if not isinstance(request_proxy, str):
                    raise TypeError("per-request proxy must be a string")
                selected_proxy = request_proxy
            started = time.time()
            try:
                raw = self._transport.request(
                    method, request_url, selected_profile, headers=combined_headers,
                    body=body, content_type=content_type, timeout=timeout,
                    proxy=selected_proxy, verify=verify, auth=auth,
                    allow_redirects=allow_redirects, max_redirects=max_redirects,
                    cookie_jar=self.cookies, sink=sink)
            except (TransportError, OSError, ssl.SSLError):
                if attempt >= policy.retries:
                    raise
                time.sleep(policy.delay(attempt))
                attempt += 1
                continue
            response = Response(raw, meta=meta, elapsed=time.time() - started)

            if revalidate is not None and response.status == 304:
                self.cache.touch(method, url, params)
                cached = Response(meta=meta, from_cache=True,
                                  status=revalidate["status"], url=revalidate["url"],
                                  headers=revalidate["headers"], content=revalidate["content"])
                if self.on_response:
                    self.on_response(cached)
                return cached
            if (response.status in _IP_BLOCK_STATUSES and self._proxy_pool and
                    request_proxy is None and rotations < self.block_rotations):
                rotations += 1
                time.sleep(min(policy.max_backoff, 0.3 * rotations))
                continue
            if policy.should_retry_status(response.status) and attempt < policy.retries:
                time.sleep(policy.delay(attempt, response.headers.get("Retry-After")))
                attempt += 1
                continue
            if cacheable and response.ok:
                self.cache.set(method, url, params, response)
            if sink is not None:
                response.meta = dict(response.meta or {},
                                     saved_to=sink, bytes=raw.saved_bytes)
            if self.on_response:
                self.on_response(response)
            return response

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def download(self, url, path, **kwargs):
        """Stream a URL straight to ``path`` on disk.

        Bytes land in the file as they arrive off the wire (constant memory,
        whatever the size), with gzip/deflate transport compression decoded
        transparently. Retries and redirects still apply; a retry restarts
        the file cleanly. The returned ``Response`` carries
        ``meta["saved_to"]`` and ``meta["bytes"]``.
        """
        kwargs.setdefault("timeout", self.timeout)
        return self.request("GET", url, sink=str(path), **kwargs)

    def close(self):
        self._transport.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


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
    "Session", "Response", "RetryPolicy", "HTTPStatusError", "TransportError",
    "CookieJar", "detect_encoding", "get", "post", "fetch", "download",
]
