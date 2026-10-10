"""The curl_reap transport: pooling, connections, framing, redirects.

``_Transport`` owns everything below the session layer:

* a bounded, liveness-checked pool of idle connections keyed by
  (scheme, host, port, proxy, profile, verify, tls backend, interface);
* connecting: native TLS 1.3 (:mod:`curl_reap._tls`) when the profile has a
  captured template and ``cryptography`` is importable, with automatic
  fallback to the standard-library OpenSSL context when the server only
  speaks TLS 1.2 or a client certificate is required; HTTP CONNECT tunnels
  (always ``host:port``) and SOCKS 4/4a/5/5h via :mod:`curl_reap.socks`;
* HTTP/1.1 serialization and parsing (ordered headers, chunked streaming,
  strict Content-Length, tokenised ``Connection``);
* the HTTP/2 exchange through :class:`curl_reap._h2.H2Connection`, with
  content decoding and true streaming into download sinks;
* the redirect loop, including ``allow_redirects="safe"`` which refuses to
  follow into private, loopback or link-local destinations.

Timeouts are deadlines: a float ``timeout`` bounds the whole request
(connect, transfer and every redirect hop); ``(connect, read)`` bounds the
connect, each socket read, and sets a whole-request deadline of their sum.
``None`` disables the clock.
"""
from __future__ import annotations

import base64
import ipaddress
import logging
import os
import select
import socket
import ssl
import threading
import time
import zlib
from email.utils import parsedate_to_datetime
from typing import Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

from .exceptions import (
    ChunkedEncodingError,
    ConnectTimeout,
    ContentDecodingError,
    IncompleteRead,
    InvalidSchema,
    InvalidURL,
    ProxyError,
    ReadTimeout,
    SSLError,
    TooManyRedirects,
    TransportError,
    URLPolicyError,
)
from .headers import Headers
from .response import _RawResponse, detect_encoding  # noqa: F401  (re-export)
from .socks import socks_connect

logger = logging.getLogger("curl_reap.transport")

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_NO_BODY_STATUSES = frozenset({204, 205, 304})
_MAX_HEADER_BYTES = 65536
_DEFAULT_MAX_BODY = 64 * 1024 * 1024
_IDLE_TTL = 60.0
_IDLE_PER_KEY = 10
_RECV_SIZE = 65536
_SOCKS_SCHEMES = ("socks4", "socks4a", "socks5", "socks5h")


def retry_after_seconds(value):
    """Seconds a ``Retry-After`` header asks for, or None when unparsable.

    Clamped to 24 hours: an enormous or infinite header is a server bug,
    not a reason to hang the process (1.x crashed on ``inf`` and slept for
    real on ``99999999``).
    """
    if value is None:
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        try:
            retry_at = parsedate_to_datetime(str(value))
            seconds = retry_at.timestamp() - time.time()
        except (TypeError, ValueError, OverflowError):
            return None
    if seconds != seconds:  # NaN
        return None
    return max(0.0, min(seconds, 86400.0))


def _authority(host, port, default_port):
    rendered = "[%s]" % host if ":" in host and not host.startswith("[") else host
    if port == default_port:
        return rendered
    return "%s:%s" % (rendered, port)


def _request_target(parts):
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="=&?/:;+,%@!$'()*-._~")
    return path + (("?" + query) if query else "")


def _is_ip_literal(host):
    if not host:
        return False
    if ":" in host:
        return True
    return all(c.isdigit() or c == "." for c in host)


def _header_items(headers):
    if headers is None:
        return []
    if isinstance(headers, Headers):
        source = headers.multi_items(include_none=True)
    elif isinstance(headers, dict):
        source = list(headers.items())
    else:
        source = list(headers)
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
    """Case-insensitive last-wins merge keeping deterministic position.

    A ``None`` value deletes the header everywhere it appeared (dropping a
    profile header for one request).
    """
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


def _gunzip_all(data):
    """Decompress every gzip member in sequence (1.x kept only the first)."""
    out = bytearray()
    offset = 0
    members = 0
    while offset < len(data):
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            out += dec.decompress(data[offset:])
            out += dec.flush()
        except zlib.error as exc:
            if members:
                break  # trailing junk after real members: keep what decoded
            raise ContentDecodingError("invalid gzip response body: %s" % exc)
        offset = len(data) - len(dec.unused_data)
        members += 1
    if not members:
        raise ContentDecodingError("invalid gzip response body")
    return bytes(out)


def _decode_content(content, encoding):
    """Decode a buffered body per Content-Encoding (multi-member safe)."""
    if not content or not encoding:
        return content
    encodings = [item.strip().lower() for item in encoding.split(",") if item.strip()]
    decoded = content
    for current in reversed(encodings):
        if current in ("identity", ""):
            continue
        if current in ("gzip", "x-gzip"):
            decoded = _gunzip_all(decoded)
        elif current == "deflate":
            try:
                decoded = zlib.decompress(decoded)
            except zlib.error:
                try:
                    decoded = zlib.decompress(decoded, -zlib.MAX_WBITS)
                except zlib.error as exc:
                    raise ContentDecodingError("invalid deflate response body: %s" % exc)
        elif current == "br":
            try:
                import brotli
            except ImportError:
                raise ContentDecodingError(
                    "received Brotli content but optional 'brotli' is not installed")
            try:
                decoded = brotli.decompress(decoded)
            except Exception as exc:
                raise ContentDecodingError("invalid Brotli response body: %s" % exc)
        elif current == "zstd":
            try:
                import zstandard
            except ImportError:
                try:
                    from compression import zstd as _z  # Python 3.14+
                except ImportError:
                    raise ContentDecodingError(
                        "received zstd content but optional 'zstandard' is not installed")
                try:
                    decoded = _z.decompress(decoded)
                except Exception as exc:
                    raise ContentDecodingError("invalid zstd response body: %s" % exc)
            else:
                try:
                    decoded = zstandard.ZstdDecompressor().decompress(decoded)
                except Exception as exc:
                    raise ContentDecodingError("invalid zstd response body: %s" % exc)
        else:
            raise ContentDecodingError("unsupported Content-Encoding %r" % current)
    return decoded


class _StreamDecoder:
    """Incremental Content-Encoding decoder for streaming bodies."""

    def __init__(self, content_encoding):
        encoding = (content_encoding or "").strip().lower()
        if encoding in ("", "identity"):
            raise ValueError("nothing to decode")
        self._encodings = [e.strip() for e in encoding.split(",") if e.strip()]
        self._dec = None
        self._brotli = None
        self._init_layer()

    def _init_layer(self):
        # Layers peel off in reverse wire order.
        current = self._encodings[-1]
        if current in ("gzip", "x-gzip"):
            self._dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif current == "deflate":
            self._dec = zlib.decompressobj()
            self._maybe_raw = True
        elif current == "br":
            try:
                import brotli
            except ImportError:
                raise ContentDecodingError(
                    "cannot stream %r encoded bodies; brotli is not installed" % current)
            self._brotli = brotli.Decompressor()
        else:
            raise ContentDecodingError("cannot stream %r encoded bodies" % current)

    def feed(self, data):
        if self._brotli is not None:
            try:
                return self._brotli.process(data)
            except Exception as exc:
                raise ContentDecodingError("corrupt brotli response body: %s" % exc)
        try:
            return self._dec.decompress(data)
        except zlib.error:
            if getattr(self, "_maybe_raw", False):
                # Some servers send raw-deflate where zlib-wrapped was promised.
                self._dec = zlib.decompressobj(-zlib.MAX_WBITS)
                self._maybe_raw = False
                return self._dec.decompress(data)
            raise ContentDecodingError("corrupt compressed response body")

    def finish(self):
        if self._brotli is not None:
            if not self._brotli.is_finished():
                raise ContentDecodingError("truncated brotli response body")
            return b""
        try:
            tail = self._dec.flush()
        except zlib.error:
            raise ContentDecodingError("truncated compressed response body")
        if not self._dec.eof:
            raise ContentDecodingError("truncated compressed response body")
        return tail


def _body_streamer(write, headers):
    """Wrap ``write`` with incremental decoding when the body is compressed."""
    encoding = (headers.get("Content-Encoding") or "").strip().lower()
    try:
        decoder = _StreamDecoder(encoding)
    except ValueError:
        return write

    def feed(chunk):
        out = decoder.feed(chunk)
        if out:
            write(out)
        return len(chunk)

    feed.finish = lambda: decoder.finish()
    return feed


class _BufferedSocket:
    """recv()-buffered reader over a plain or TLS socket."""

    __slots__ = ("sock", "buffer")

    def __init__(self, sock):
        self.sock = sock
        self.buffer = bytearray()

    def _receive(self):
        try:
            chunk = self.sock.recv(_RECV_SIZE)
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
                chunk = self.sock.recv(_RECV_SIZE)
            except (OSError, ssl.SSLError) as exc:
                raise TransportError(str(exc))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)


class _BodyStream:
    """Streaming reader handed to ``Response.iter_content`` (HTTP/1.1)."""

    def __init__(self, transport, conn, mode, length, decoder, reusable):
        self._transport = transport
        self._conn = conn
        self._mode = mode              # "cl" | "chunked" | "close"
        self._remaining = length or 0
        self._decoder = decoder
        self._pending = bytearray()
        self._reusable = reusable
        self._closed = False

    def read(self, n=65536):
        if self._closed or n <= 0:
            return b""
        while not self._pending:
            if self._closed:
                return b""
            wire = self._next_wire_chunk(n)
            if self._decoder is not None:
                out = self._decoder(wire)
                if out:
                    self._pending += out
            elif wire:
                self._pending += wire
        result = bytes(self._pending[:n])
        del self._pending[:n]
        return result

    def _next_wire_chunk(self, n):
        conn = self._conn
        if conn is None:
            return b""
        if self._mode == "cl":
            if self._remaining <= 0:
                self._finish()
                return b""
            want = min(n, self._remaining)
            data = conn.reader.read_exact(want)
            self._remaining -= len(data)
            if self._remaining <= 0:
                self._finish()
            return data
        if self._mode == "close":
            try:
                data = conn.sock.recv(max(n, _RECV_SIZE))
            except (OSError, ssl.SSLError) as exc:
                raise TransportError(str(exc))
            if not data:
                self._finish()
            return data
        return self._next_chunked(conn, n)

    def _next_chunked(self, conn, n):
        reader = conn.reader
        line = reader.read_until(b"\r\n", _MAX_HEADER_BYTES)[:-2]
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            raise ChunkedEncodingError(
                "invalid chunk size %r" % size_text.decode("latin-1", "replace"))
        if size < 0:
            raise ChunkedEncodingError("invalid negative chunk size")
        if size == 0:
            while True:  # trailers are consumed, never merged into headers
                trailer = reader.read_until(b"\r\n", _MAX_HEADER_BYTES)[:-2]
                if not trailer:
                    self._finish()
                    return b""
                if b":" not in trailer:
                    raise ChunkedEncodingError("malformed HTTP trailer")
        data = reader.read_exact(min(size, n))
        if len(data) < size:
            # the rest of the chunk waits in the buffer; next call reads it
            rest = reader.read_exact(size - len(data))
            return data + rest
        if reader.read_exact(2) != b"\r\n":
            raise ChunkedEncodingError("chunk data is not terminated by CRLF")
        return data

    def _finish(self):
        self._closed = True
        conn, self._conn = self._conn, None
        if conn is not None:
            self._transport._release_stream(conn, self._reusable)

    def close(self):
        if not self._closed and self._conn is not None:
            self._closed = True
            conn, self._conn = self._conn, None
            self._transport._release_stream(conn, False)


class _Connection:
    def __init__(self, sock, key, h2=None, tls_backend=None, tls_infos=None):
        self.sock = sock
        self.reader = _BufferedSocket(sock)
        self.h2 = h2              # curl_reap._h2.H2Connection or None
        self.key = key
        self.tls_backend = tls_backend or ("none" if h2 is None and sock is None else "plain")
        self.tls_infos = dict(tls_infos or {})
        self.closed = False
        try:
            self.peername = sock.getpeername()
            self.sockname = sock.getsockname()
        except OSError:
            self.peername = self.sockname = None

    def describe(self):
        return "%s-%s" % (self.key, self.tls_backend)

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.h2 is not None:
            try:
                self.h2.close()  # sends GOAWAY
            except Exception:
                pass
            self.h2 = None
        try:
            self.sock.close()
        except OSError:
            pass


class _Transport:
    """Thread-safe pool of connections with native-TLS-first connecting.

    ``tls`` is ``"auto"`` (native engine when available, OpenSSL fallback),
    ``"native"`` (no silent fallback) or ``"openssl"``.  ``interface`` is an
    optional source IP for every socket.
    """

    def __init__(self, *, tls="auto", interface=None, max_idle_per_key=_IDLE_PER_KEY,
                 idle_ttl=_IDLE_TTL):
        if tls not in ("auto", "native", "openssl"):
            raise ValueError("tls must be 'auto', 'native' or 'openssl'")
        self._pool: Dict[tuple, list] = {}
        self._lock = threading.Lock()
        self._closed = False
        self.tls_backend = tls
        self.interface = interface
        self.max_idle_per_key = max_idle_per_key
        self.idle_ttl = idle_ttl
        self._session_cache = None
        try:
            from ._tls import SessionCache
            self._session_cache = SessionCache()
        except Exception:
            pass

    # -- native engine availability ------------------------------------------
    @staticmethod
    def _native_available():
        try:
            import cryptography  # noqa: F401
            from . import _tls  # noqa: F401
            return True
        except Exception:
            return False

    # -- timeouts ---------------------------------------------------------------
    @staticmethod
    def _deadlines(timeout, now=None):
        """Resolve a request timeout into (connect, read, deadline)."""
        if timeout is None:
            return None, None, None
        now = time.monotonic() if now is None else now
        if isinstance(timeout, (tuple, list)):
            connect, read = timeout
            connect = None if connect is None else max(0.0, float(connect))
            read = None if read is None else max(0.0, float(read))
            parts = [p for p in (connect, read) if p is not None]
            deadline = now + sum(parts) if parts else None
            return connect, read, deadline
        timeout = max(0.0, float(timeout))
        return timeout, timeout, now + timeout

    @staticmethod
    def _arm(sock, read_timeout, deadline):
        """Set the socket timeout to min(read_timeout, deadline remaining)."""
        timeout = read_timeout
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ReadTimeout("request deadline exceeded")
            timeout = remaining if timeout is None else min(timeout, remaining)
        if timeout is not None:
            try:
                sock.settimeout(timeout)
            except OSError:
                pass

    # -- pool -----------------------------------------------------------------
    def _connection_key(self, scheme, host, port, proxy, profile, verify, backend):
        return (scheme, host, port, proxy, getattr(profile, "name", str(profile)),
                bool(verify), backend, self.interface)

    def _acquire(self, key, read_timeout, deadline):
        """Pop a live idle connection for ``key`` or return None."""
        with self._lock:
            group = self._pool.get(key)
            conn = None
            now = time.monotonic()
            while group:
                candidate, expires = group.pop()
                if expires > now and self._is_live(candidate):
                    conn = candidate
                    break
                candidate.close()
            if group is not None and not group:
                self._pool.pop(key, None)
        if conn is not None:
            try:
                self._arm(conn.sock, read_timeout, deadline)
            except (OSError, ReadTimeout):
                conn.close()
                return None
        return conn

    def _is_live(self, conn):
        """Liveness for reuse: h2 must be alive; h1 must be silent and drained."""
        if conn.h2 is not None:
            try:
                return conn.h2.alive and conn.h2.poll()
            except Exception:
                return False
        if conn.reader.buffer:
            return False  # unread bytes poison the next response
        try:
            readable, _, _ = select.select([conn.sock], [], [], 0)
        except (OSError, ValueError):
            return False
        if readable:
            # readable before a request means EOF or a server GOAWAY/close
            return False
        return True

    def _release(self, conn, reusable):
        if not reusable or self._closed or conn.closed:
            conn.close()
            return
        with self._lock:
            group = self._pool.setdefault(conn.key, [])
            while len(group) >= self.max_idle_per_key:
                victim, _ = group.pop(0)
                victim.close()
            group.append((conn, time.monotonic() + self.idle_ttl))

    def _release_stream(self, conn, reusable):
        """Release a connection whose body a _BodyStream just drained."""
        if reusable and not conn.reader.buffer:
            self._release(conn, True)
        else:
            conn.close()

    def close(self):
        with self._lock:
            self._closed = True
            connections = [conn for group in self._pool.values() for conn, _ in group]
            self._pool.clear()
        for conn in connections:
            conn.close()

    # -- connecting -----------------------------------------------------------
    def _connect(self, scheme, host, port, proxy, profile, verify, timeout, deadline,
                 cert=None, http_version="v2", debug=False):
        key_backend = self.tls_backend
        use_native = (
            scheme == "https"
            and self.tls_backend != "openssl"
            and getattr(profile, "tls_template", None)
            and self._native_available()
        )
        if use_native:
            key_backend = "native"
        elif scheme == "https":
            key_backend = "openssl"
        else:
            key_backend = "plain"
        key = self._connection_key(scheme, host, port, proxy, profile, verify, key_backend)
        connect_timeout, read_timeout, _ = self._deadlines(timeout)

        proxy_parts = None
        if proxy:
            proxy_parts = urlsplit(proxy if "://" in proxy else "http://" + proxy)
            pscheme = proxy_parts.scheme.lower()
            if pscheme not in ("http", "https") + _SOCKS_SCHEMES:
                raise InvalidSchema("unsupported proxy scheme %r" % pscheme)
            if not proxy_parts.hostname:
                raise InvalidURL("proxy must include a hostname")

        sock = self._tcp_connect(host, port, proxy_parts, scheme, connect_timeout, deadline)
        try:
            tls_infos = {}
            h2 = None
            backend = "plain"
            alpn = self._alpn_for(profile, http_version)
            if scheme == "https":
                sock, backend, tls_infos = self._tls_wrap(
                    sock, host, port, proxy_parts, profile, verify, alpn,
                    connect_timeout, read_timeout, deadline, cert, use_native)
            selected = tls_infos.get("alpn")
            wants_h2 = "h2" in alpn and selected == "h2"
            if http_version in ("v2", "v2tls", "v2_prior_knowledge") and not wants_h2 \
                    and scheme == "https" and backend != "native" and http_version == "v2_prior_knowledge":
                # prior knowledge: speak h2 even without ALPN (cleartext h2c over TLS is still ALPN-negotiated in practice; plain http prior-knowledge handled below)
                wants_h2 = True
            if http_version == "v3" or http_version == "v3only":
                raise NotImplementedError("HTTP/3 (QUIC) is not implemented")
            conn = _Connection(sock, key, tls_backend=backend, tls_infos=tls_infos)
            if wants_h2 and getattr(profile, "h2_spec", None):
                from ._h2 import H2Connection
                from ._h2.spec import H2Spec
                selected_spec = profile.h2_spec
                if not isinstance(selected_spec, H2Spec):
                    from ._h2 import spec as h2_spec_loader
                    selected_spec = h2_spec_loader(selected_spec)
                h2 = H2Connection(
                    sock, selected_spec, deadline=deadline,
                )
                conn.h2 = h2
                conn.tls_infos = dict(tls_infos)
            return conn
        except NotImplementedError:
            try:
                sock.close()
            except OSError:
                pass
            raise
        except (TransportError, OSError, ssl.SSLError):
            try:
                sock.close()
            except OSError:
                pass
            raise

    def _alpn_for(self, profile, http_version):
        if http_version == "v1":
            return ("http/1.1",)
        return ("h2", "http/1.1")

    def _tcp_connect(self, host, port, proxy_parts, scheme, connect_timeout, deadline):
        try:
            if proxy_parts is None:
                return self._create_connection(host, port, connect_timeout, deadline)
            pscheme = proxy_parts.scheme.lower()
            if pscheme in _SOCKS_SCHEMES:
                return socks_connect(proxy_parts, host, port, connect_timeout,
                                     source_address=self._source_address(),
                                     deadline=deadline)
            proxy_port = proxy_parts.port or (1080 if pscheme in _SOCKS_SCHEMES else 8080)
            sock = self._create_connection(proxy_parts.hostname, proxy_port,
                                           connect_timeout, deadline)
            if pscheme == "https":
                # TLS to the proxy itself, then CONNECT through the tunnel.
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=proxy_parts.hostname)
            if scheme == "https":
                self._connect_tunnel(sock, host, port, proxy_parts, connect_timeout, deadline)
            return sock
        except TransportError:
            raise
        except (socket.gaierror, UnicodeError) as exc:
            from .exceptions import DNSError
            raise DNSError("could not resolve %s: %s" % (host, exc), code=6)
        except ConnectTimeout:
            raise
        except (TimeoutError, socket.timeout) as exc:
            raise ConnectTimeout("connect timed out: %s" % exc, code=28)
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as exc:
            from .exceptions import ConnectionError as REConnectionError
            raise REConnectionError(str(exc), code=7)
        except OSError as exc:
            raise TransportError("could not connect: %s" % exc)

    def _source_address(self):
        if not self.interface:
            return None
        if isinstance(self.interface, tuple):
            return self.interface
        return (self.interface, 0)

    def _create_connection(self, host, port, timeout, deadline):
        self._arm_deadline_check(deadline)
        try:
            return socket.create_connection((host, port), timeout=timeout,
                                            source_address=self._source_address())
        except (TimeoutError, socket.timeout):
            raise

    def _arm_deadline_check(self, deadline):
        if deadline is not None and deadline - time.monotonic() <= 0:
            raise ConnectTimeout("request deadline exceeded before connect", code=28)

    def _connect_tunnel(self, sock, host, port, proxy_parts, timeout, deadline):
        """CONNECT host:port (always with the port, RFC 9110 9.3.6)."""
        authority = "%s:%d" % (("[%s]" % host if ":" in host and not host.startswith("[") else host), port)
        lines = ["CONNECT %s HTTP/1.1" % authority, "Host: %s" % authority]
        auth = self._proxy_authorization(proxy_parts)
        if auth:
            lines.append("Proxy-Authorization: %s" % auth)
        payload = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        try:
            self._arm(sock, timeout, deadline)
            sock.sendall(payload)
            reader = _BufferedSocket(sock)
            self._arm(sock, timeout, deadline)
            head = reader.read_until(b"\r\n\r\n", _MAX_HEADER_BYTES)
            first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            parts = first.split(" ", 2)
            if len(parts) < 2 or not parts[1].isdigit() or int(parts[1]) != 200:
                raise ProxyError("proxy CONNECT failed: %s" % first, code=5)
            if reader.buffer:
                raise ProxyError("proxy sent data after the CONNECT response", code=5)
        except TransportError:
            raise
        except (OSError, ssl.SSLError) as exc:
            raise ProxyError("proxy CONNECT failed: %s" % exc, code=5)

    @staticmethod
    def _proxy_authorization(proxy_parts):
        if proxy_parts.username is None:
            return None
        user = unquote(proxy_parts.username)
        password = unquote(proxy_parts.password or "")
        token = base64.b64encode((user + ":" + password).encode("utf-8")).decode("ascii")
        return "Basic " + token

    def _tls_wrap(self, sock, host, port, proxy_parts, profile, verify, alpn,
                  connect_timeout, read_timeout, deadline, cert, use_native):
        """Wrap with the native engine first; fall back to OpenSSL when needed."""
        errors = []
        if use_native:
            try:
                from ._tls import wrap_socket as native_wrap
                from ._tls.errors import TLS12Negotiated
                tls = native_wrap(sock, host, profile.tls_template, verify=verify,
                                  alpn=alpn, timeout=connect_timeout, deadline=deadline,
                                  session_cache=self._session_cache)
                infos = {
                    "alpn": tls.selected_alpn_protocol(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    "group": getattr(tls, "negotiated_group", None),
                    "tls_version": tls.version(),
                    "resumed": getattr(tls, "resumed", False),
                    "handshake_seconds": getattr(tls, "handshake_seconds", None),
                }
                try:
                    infos["peername"] = tls.getpeername()
                    infos["sockname"] = tls.getsockname()
                except OSError:
                    pass
                return tls, "native", infos
            except TLS12Negotiated as exc:
                errors.append("native: %s (falling back to OpenSSL)" % exc)
                try:
                    sock.close()
                except OSError:
                    pass
                sock = self._create_connection(host, port, connect_timeout, deadline)
                if proxy_parts is not None and proxy_parts.scheme.lower() in ("http", "https"):
                    proxy_port = proxy_parts.port or 8080
                    if proxy_parts.scheme.lower() == "https":
                        raise TransportError(
                            "TLS-1.2-only servers cannot be combined with an https proxy")
                    tunnel_sock = self._create_connection(proxy_parts.hostname, proxy_port,
                                                          connect_timeout, deadline)
                    sock.close()
                    sock = tunnel_sock
                    self._connect_tunnel(sock, host, port, proxy_parts, connect_timeout, deadline)
                # OpenSSL path below re-wraps the fresh socket
                try:
                    return self._openssl_wrap(sock, host, profile, verify, alpn,
                                              connect_timeout, read_timeout, deadline, cert)
                except (TransportError, OSError, ssl.SSLError) as exc:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    raise
            except (TransportError, OSError) as exc:
                code = getattr(exc, "code", 0)
                if code in (60,) or isinstance(exc, SSLError):
                    raise
                errors.append("native: %s" % exc)
                try:
                    sock.close()
                except OSError:
                    pass
                if self.tls_backend == "native":
                    raise
                sock = self._reconnect_plain(host, port, proxy_parts, connect_timeout, deadline)
        return self._openssl_wrap(sock, host, profile, verify, alpn,
                                  connect_timeout, read_timeout, deadline, cert)

    def _reconnect_plain(self, host, port, proxy_parts, connect_timeout, deadline):
        """Re-dial after the native engine failed on a TLS-1.3-capable server."""
        try:
            if proxy_parts is None:
                return self._create_connection(host, port, connect_timeout, deadline)
            pscheme = proxy_parts.scheme.lower()
            if pscheme in _SOCKS_SCHEMES:
                return socks_connect(proxy_parts, host, port, connect_timeout,
                                     source_address=self._source_address(), deadline=deadline)
            proxy_port = proxy_parts.port or 8080
            sock = self._create_connection(proxy_parts.hostname, proxy_port,
                                           connect_timeout, deadline)
            if pscheme == "https":
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=proxy_parts.hostname)
            if host and port:
                self._connect_tunnel(sock, host, port, proxy_parts, connect_timeout, deadline)
            return sock
        except (TimeoutError, socket.timeout) as exc:
            raise ConnectTimeout("connect timed out: %s" % exc, code=28)

    def _openssl_wrap(self, sock, host, profile, verify, alpn, connect_timeout,
                      read_timeout, deadline, cert):
        from .tls import create_ssl_context
        context = create_ssl_context(profile, verify=verify, alpn=alpn)
        if cert:
            # the reference client style: a path, or (cert, key[, key_password]).
            if isinstance(cert, str):
                cert, key, password = cert, None, None
            else:
                cert, key = cert[0], cert[1]
                password = cert[2] if len(cert) > 2 else None
            try:
                context.load_cert_chain(cert, key, password)
            except (OSError, ssl.SSLError) as exc:
                try:
                    sock.close()
                except OSError:
                    pass
                raise SSLError("could not load the client certificate: %s" % exc, code=35)
        try:
            self._arm(sock, connect_timeout, deadline)
            sock = context.wrap_socket(sock, server_hostname=host)
        except ssl.CertificateError as exc:
            from .exceptions import CertificateVerifyError
            try:
                sock.close()
            except OSError:
                pass
            raise CertificateVerifyError(str(exc), code=60)
        except (ssl.SSLError, OSError) as exc:
            try:
                sock.close()
            except OSError:
                pass
            raise SSLError("TLS handshake failed: %s" % exc, code=35)
        infos = {
            "alpn": (sock.selected_alpn_protocol() if hasattr(sock, "selected_alpn_protocol") else None),
            "cipher": sock.cipher()[0] if hasattr(sock, "cipher") and sock.cipher() else None,
            "group": None,
            "tls_version": sock.version(),
        }
        return sock, "openssl", infos

    # -- HTTP/1.1 ---------------------------------------------------------------
    _STRIP_ON_ORIGIN_CHANGE = frozenset({
        "authorization", "cookie", "proxy-authorization", "host"})
    _STRIP_ON_METHOD_REWRITE = frozenset({
        "content-length", "content-type", "content-encoding",
        "transfer-encoding", "content-md5"})

    def _parse_head(self, reader):
        """Read one response head; skip 1xx interim responses."""
        while True:
            head = reader.read_until(b"\r\n\r\n", _MAX_HEADER_BYTES)
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
            headers = Headers()
            received = []
            previous = None
            for raw_line in raw_lines[1:]:
                if raw_line[:1] in (b" ", b"\t") and previous is not None:
                    value = headers[previous] + " " + raw_line.decode("latin-1").strip()
                    headers[previous] = value
                    received[-1] = (previous, value)
                    continue
                if b":" not in raw_line:
                    raise TransportError("malformed HTTP response header")
                raw_name, raw_value = raw_line.split(b":", 1)
                name = raw_name.decode("latin-1").strip()
                value = raw_value.decode("latin-1").strip()
                previous = name
                received.append((name, value))
                headers.add(name, value)
            if 100 <= status < 200 and status != 101:
                continue  # interim response; the real one follows
            return status, reason, version, headers, received

    @staticmethod
    def _connection_tokens(value):
        return {token.strip().lower() for token in (value or "").split(",") if token.strip()}

    @staticmethod
    def _content_length(headers):
        raw = headers.get("Content-Length")
        if raw is None:
            return None
        raw = raw.strip()
        if not raw or not raw.isdigit():
            raise TransportError("invalid Content-Length header %r" % raw)
        return int(raw)

    def _response(self, conn, method, url, sink=None, stream=False,
                  max_body=_DEFAULT_MAX_BODY):
        """Read one HTTP/1.1 response; return (raw, reusable, stream_reader)."""
        status, reason, version, headers, received = self._parse_head(conn.reader)

        no_body = (method.upper() == "HEAD" or status in _NO_BODY_STATUSES
                   or 100 <= status < 200)
        chunked = "chunked" in (headers.get("Transfer-Encoding") or "").lower()
        length = None if chunked else self._content_length(headers)
        close_delimited = (not chunked and length is None)

        connection_tokens = self._connection_tokens(headers.get("Connection"))
        reusable = True
        if "close" in connection_tokens:
            reusable = False
        elif version == "HTTP/1.0" and "keep-alive" not in connection_tokens:
            reusable = False
        if close_delimited:
            reusable = False  # body ends at EOF; the connection ends with it
        if status == 101:
            reusable = False  # the protocol is changing hands (upgrades)

        cookie_values = [(n, v) for n, v in received if n.lower() == "set-cookie"]
        cookies = {}
        cookie_specs = []
        if cookie_values:
            from .cookies import parse_set_cookie
            for _, value in cookie_values:
                spec = parse_set_cookie(value)
                if spec:
                    cookies[spec["name"]] = spec["value"]
                    cookie_specs.append(spec)

        infos = dict(getattr(conn, "tls_infos", {}) or {})
        if "peername" not in infos:
            try:
                infos["peername"] = conn.sock.getpeername()
                infos["sockname"] = conn.sock.getsockname()
            except OSError:
                pass

        def build(content=b"", saved=0, trailers=(), body_stream=None):
            raw = _RawResponse(status, reason, version, url, headers, content,
                               cookies=cookies, cookie_specs=cookie_specs,
                               saved_bytes=saved, trailers=trailers, infos=infos)
            raw.stream = body_stream
            if infos.get("peername"):
                raw.primary_ip, raw.primary_port = infos["peername"][0], infos["peername"][1]
            if infos.get("sockname"):
                raw.local_ip, raw.local_port = infos["sockname"][0], infos["sockname"][1]
            return raw

        if no_body:
            return build(), reusable, None

        if sink is not None:
            if status in _REDIRECT_STATUSES or not (200 <= status < 300):
                # never write redirect or error bodies to the sink; drain instead
                if chunked:
                    self._drain_chunked(conn)
                elif length is not None:
                    conn.reader.read_exact_into(length, lambda b: None)
                else:
                    conn.reader.read_to_close()
                    reusable = False
                return build(), reusable, None
            part_path = sink + ".reap-part"
            saved = 0
            try:
                with open(part_path, "wb") as fh:
                    feed = _body_streamer(fh.write, headers)
                    if chunked:
                        saved = self._read_chunked_into(conn, feed)
                    elif length is not None:
                        conn.reader.read_exact_into(length, feed)
                        saved = length
                    else:
                        saved = conn.reader.drain_to_close(feed)
                        reusable = False
                    tail = getattr(feed, "finish", None)
                    if tail is not None:
                        rest = tail()
                        if rest:
                            fh.write(rest)
                            saved += len(rest)
                    saved = fh.tell()
                os.replace(part_path, sink)  # atomic commit, 2xx only
            except BaseException:
                try:
                    os.remove(part_path)
                except OSError:
                    pass
                raise
            if conn.reader.buffer:
                reusable = False
            return build(saved=saved), reusable, None

        if stream and not sink:
            decoder = None
            try:
                decoder = _StreamDecoder(headers.get("Content-Encoding"))
            except (ValueError, ContentDecodingError):
                decoder = None
            if chunked:
                mode, body_len = "chunked", 0
            elif length is not None:
                mode, body_len = "cl", length
            else:
                mode, body_len = "close", 0
                reusable = False
            body_stream = _BodyStream(self, conn, mode, body_len, decoder, reusable)
            return build(content=None), False, body_stream  # released by the stream

        # buffered body with a cap
        if chunked:
            content = self._read_chunked(conn, max_body)
        elif length is not None:
            if length > max_body:
                conn.close()
                raise TransportError(
                    "response body of %d bytes exceeds max_body_bytes=%d" % (length, max_body),
                    code=63)
            content = conn.reader.read_exact(length)
        else:
            content = conn.reader.read_to_close()
            reusable = False
            if len(content) > max_body:
                raise TransportError(
                    "response body exceeds max_body_bytes=%d" % max_body, code=63)
        if not chunked and length is not None and conn.reader.buffer:
            reusable = False  # bytes beyond Content-Length would poison the next read
        decoded = _decode_content(content, headers.get("Content-Encoding"))
        return build(decoded), reusable, None

    def _read_chunked(self, conn, max_body=_DEFAULT_MAX_BODY):
        chunks = []
        total = 0
        reader = conn.reader
        while True:
            line = reader.read_until(b"\r\n", _MAX_HEADER_BYTES)[:-2]
            size_text = line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                raise ChunkedEncodingError(
                    "invalid chunk size %r" % size_text.decode("latin-1", "replace"))
            if size < 0:
                raise ChunkedEncodingError("invalid negative chunk size")
            if size == 0:
                while True:  # trailers: consumed, never merged into headers
                    trailer = reader.read_until(b"\r\n", _MAX_HEADER_BYTES)[:-2]
                    if not trailer:
                        return b"".join(chunks)
                    if b":" not in trailer:
                        raise ChunkedEncodingError("malformed HTTP trailer")
            total += size
            if total > max_body:
                conn.close()
                raise TransportError(
                    "chunked response body exceeds max_body_bytes=%d" % max_body, code=63)
            chunks.append(reader.read_exact(size))
            if reader.read_exact(2) != b"\r\n":
                raise ChunkedEncodingError("chunk data is not terminated by CRLF")

    def _drain_chunked(self, conn):
        reader = conn.reader
        while True:
            line = reader.read_until(b"\r\n", _MAX_HEADER_BYTES)[:-2]
            size_text = line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                raise ChunkedEncodingError("invalid chunk size while draining")
            if size == 0:
                while True:
                    trailer = reader.read_until(b"\r\n", _MAX_HEADER_BYTES)[:-2]
                    if not trailer:
                        return
                    if b":" not in trailer:
                        raise ChunkedEncodingError("malformed HTTP trailer")
            reader.read_exact_into(size, lambda b: None)
            if reader.read_exact(2) != b"\r\n":
                raise ChunkedEncodingError("chunk data is not terminated by CRLF")

    @staticmethod
    def _read_chunked_into(conn, write):
        """Stream a chunked body through ``write``; return wire bytes written."""
        saved = 0
        reader = conn.reader
        while True:
            line = reader.read_until(b"\r\n", _MAX_HEADER_BYTES)[:-2]
            size_text = line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                raise ChunkedEncodingError(
                    "invalid chunk size %r" % size_text.decode("latin-1", "replace"))
            if size < 0:
                raise ChunkedEncodingError("invalid negative chunk size")
            if size == 0:
                while True:
                    trailer = reader.read_until(b"\r\n", _MAX_HEADER_BYTES)[:-2]
                    if not trailer:
                        return saved
                    if b":" not in trailer:
                        raise ChunkedEncodingError("malformed HTTP trailer")
            reader.read_exact_into(size, write)
            saved += size
            if reader.read_exact(2) != b"\r\n":
                raise ChunkedEncodingError("chunk data is not terminated by CRLF")

    # -- request execution -----------------------------------------------------
    def _route_key(self, scheme, host, port, proxy, profile, verify):
        backend = "plain"
        if scheme == "https":
            if (self.tls_backend != "openssl"
                    and getattr(profile, "tls_template", None)
                    and self._native_available()):
                backend = "native"
            else:
                backend = "openssl"
        return self._connection_key(scheme, host, port, proxy, profile, verify, backend)

    def _single_request(self, method, url, profile, custom_headers, body,
                        content_type, timeout, proxy, verify, auth, sink=None,
                        stream=False, max_body=_DEFAULT_MAX_BODY, cert=None,
                        http_version="v2", interface=None, debug=False):
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise InvalidSchema("URL scheme must be http or https")
        if not parts.hostname:
            raise InvalidURL("URL must include a hostname")
        try:
            host = parts.hostname.encode("idna").decode("ascii")
            port = parts.port or (443 if scheme == "https" else 80)
        except (UnicodeError, ValueError) as exc:
            raise InvalidURL("invalid URL host or port: %s" % exc)
        authority = _authority(host, port, 443 if scheme == "https" else 80)
        connect_timeout, read_timeout, deadline = self._deadlines(timeout)

        automatic = []
        if auth is not None:
            if not isinstance(auth, (tuple, list)) or len(auth) != 2:
                raise TypeError("auth must be a (username, password) pair")
            token = base64.b64encode((str(auth[0]) + ":" + str(auth[1])).encode("utf-8"))
            automatic.append(("Authorization", "Basic " + token.decode("ascii")))
        elif parts.username is not None:
            credentials = unquote(parts.username) + ":" + unquote(parts.password or "")
            token = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
            automatic.append(("Authorization", "Basic " + token))

        headers = _merge_headers((("Host", authority),), profile.headers, custom_headers)
        if content_type and _find_header(headers, "Content-Type") is None:
            headers = _merge_headers(headers, (("Content-Type", content_type),))
        if body or method.upper() in ("POST", "PUT", "PATCH"):
            headers = _merge_headers(headers, (("Content-Length", str(len(body))),))
        if automatic:
            headers = _merge_headers(headers, automatic)

        target = _request_target(parts)
        proxy_parts = None
        if proxy:
            proxy_parts = urlsplit(proxy if "://" in proxy else "http://" + proxy)
            pscheme = proxy_parts.scheme.lower()
            if scheme == "http" and pscheme == "http":
                proxy_auth = self._proxy_authorization(proxy_parts)
                if proxy_auth:
                    headers = _merge_headers(headers, (("Proxy-Authorization", proxy_auth),))
                target = urlunsplit((scheme, authority,
                                     quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~"),
                                     quote(parts.query, safe="=&?/:;+,%@!$'()*-._~"), ""))

        key = self._route_key(scheme, host, port, proxy, profile, verify)
        conn = self._acquire(key, read_timeout, deadline)
        if conn is None:
            conn = self._connect(scheme, host, port, proxy, profile, verify, timeout,
                                 deadline, cert=cert, http_version=http_version,
                                 debug=debug)
        reusable = False
        try:
            if debug:
                logger.info(">%s %s %s HTTP/1.1", method.upper(), authority, target)
                for name, value in headers:
                    logger.info(">%s: %s", name, value)
            if conn.h2 is not None:
                try:
                    return self._h2_exchange(conn, method, scheme, host, port, authority,
                                             parts, headers, body, sink, max_body, deadline,
                                             debug)
                finally:
                    # alive h2 connections return to the pool; dead ones GOAWAY-closed
                    self._release(conn, conn.h2 is not None and conn.h2.alive)
            self._arm(conn.sock, read_timeout, deadline)
            request_line = "%s %s HTTP/1.1\r\n" % (method.upper(), target)
            rendered = [request_line.encode("ascii")]
            for name, value in headers:
                try:
                    rendered.append(("%s: %s\r\n" % (name, value)).encode("latin-1"))
                except UnicodeEncodeError:
                    raise ValueError("HTTP header %s is not latin-1 encodable" % name)
            rendered.append(b"\r\n")
            payload = b"".join(rendered) + body
            try:
                conn.sock.sendall(payload)
            except (OSError, ssl.SSLError) as exc:
                raise TransportError(str(exc))
            request_size = len(payload)
            if debug:
                logger.info("<waiting for response from %s", authority)
            raw, reusable, body_stream = self._response(
                conn, method, url, sink=sink, stream=stream, max_body=max_body)
            if (_find_header(headers, "Connection") or "").lower() == "close":
                reusable = False
            raw.request_size = request_size
            if debug:
                logger.info("<HTTP %s %s", raw.status_code, raw.reason)
                for name, value in raw.headers.multi_items():
                    logger.info("<%s: %s", name, value)
            if body_stream is not None:
                return raw  # stream owns the connection
            return raw
        finally:
            if conn.h2 is None:
                self._release(conn, reusable)

    def _h2_exchange(self, conn, method, scheme, host, port, authority, parts,
                     headers, body, sink, max_body, deadline, debug):
        """One request over the pooled HTTP/2 connection."""
        from ._h2 import H2Error
        path = _request_target(parts)
        regular = [(str(n), str(v)) for n, v in headers
                   if n.lower() not in ("host", "connection", "content-length",
                                        "transfer-encoding")]
        reusable = True
        spill = None
        try:
            if sink is not None:
                import tempfile
                spill = tempfile.SpooledTemporaryFile(max_size=8 << 20, mode="w+b")
                response = conn.h2.request(method, scheme, authority, path, regular,
                                           body=body, on_data=spill.write,
                                           deadline=deadline)
            else:
                response = conn.h2.request(method, scheme, authority, path, regular,
                                           body=body, deadline=deadline)
        except H2Error as exc:
            conn.close()
            note = " (retryable)" if getattr(exc, "retryable", False) else ""
            raise TransportError("HTTP/2 exchange failed:%s %s" % (note, exc),
                                 code=getattr(exc, "code", 0) or 0) from exc

        response_headers = Headers()
        for name, value in response.headers:
            response_headers.add(name, value)
        cookies = {}
        cookie_specs = []
        if any(n.lower() == "set-cookie" for n, _ in response.headers):
            from .cookies import parse_set_cookie
            for name, value in response.headers:
                if name.lower() != "set-cookie":
                    continue
                spec = parse_set_cookie(value)
                if spec:
                    cookies[spec["name"]] = spec["value"]
                    cookie_specs.append(spec)

        saved = 0
        content = None
        if spill is not None:
            # decode the spilled wire bytes into the sink; only 2xx commits
            if 200 <= response.status < 300:
                part_path = sink + ".reap-part"
                try:
                    spill.seek(0)
                    with open(part_path, "wb") as fh:
                        feed = _body_streamer(fh.write, response_headers)
                        while True:
                            chunk = spill.read(262144)
                            if not chunk:
                                break
                            feed(chunk)
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
            spill.close()
            spill = None
            content = b""
        else:
            content = _decode_content(response.body or b"",
                                      response_headers.get("Content-Encoding"))

        if debug:
            logger.info("<HTTP/2 %s %s", response.status, "")
            for name, value in response.headers:
                logger.info("<%s: %s", name, value)

        infos = dict(getattr(conn, "tls_infos", {}) or {})
        infos["http_version"] = "HTTP/2"
        raw = _RawResponse(
            response.status, "", "HTTP/2",
            urljoin(("%s://%s" % (scheme, authority)), path),
            response_headers, content, cookies=cookies, cookie_specs=cookie_specs,
            saved_bytes=saved, trailers=response.trailers, infos=infos)
        if infos.get("peername"):
            raw.primary_ip, raw.primary_port = infos["peername"][0], infos["peername"][1]
        if infos.get("sockname"):
            raw.local_ip, raw.local_port = infos["sockname"][0], infos["sockname"][1]
        return raw

    # -- redirect loop -----------------------------------------------------------
    @staticmethod
    def _origin(url):
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        port = parts.port or (443 if scheme == "https" else 80)
        return (scheme, (parts.hostname or "").lower(), port)

    @staticmethod
    def _is_safe_redirect(url):
        """False for private, loopback or link-local redirect destinations."""
        parts = urlsplit(url)
        host = parts.hostname or ""
        if not host:
            return False
        if _is_ip_literal(host):
            try:
                addr = ipaddress.ip_address(host.strip("[]"))
            except ValueError:
                return False
            return not (addr.is_private or addr.is_loopback or addr.is_link_local
                        or addr.is_multicast or addr.is_reserved or addr.is_unspecified)
        try:
            infos = socket.getaddrinfo(host, None)
        except (socket.gaierror, UnicodeError):
            return True  # let the connection surface the real error
        for info in infos:
            try:
                addr = ipaddress.ip_address(info[4][0])
            except ValueError:
                continue
            if (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
                return False
        return True

    def request(self, method, url, profile, headers=None, body=b"", content_type=None,
                timeout=30, proxy=None, verify=True, auth=None,
                allow_redirects=True, max_redirects=30, cookie_jar=None, sink=None,
                url_policy=None, stream=False, max_body=_DEFAULT_MAX_BODY,
                cert=None, http_version="v2", interface=None, debug=False):
        from .response import _redirect_target

        current_method = method.upper()
        current_url = url
        current_body = body
        current_content_type = content_type
        current_auth = auth
        base_headers = headers
        redirects = 0
        history = []
        explicit_cookie = any(
            name.lower() == "cookie" for name, _ in _header_items(headers))
        started = time.monotonic()
        while True:
            if url_policy is not None and not url_policy(current_url):
                raise URLPolicyError("url_policy rejected %s" % current_url)
            hop_headers = base_headers
            if cookie_jar is not None and not explicit_cookie:
                cookie_header = cookie_jar.header_for(current_url)
                if cookie_header:
                    hop_headers = tuple(
                        h for h in (hop_headers or ()) if h[0].lower() != "cookie"
                    ) + (("Cookie", cookie_header),)
            response = self._single_request(
                current_method, current_url, profile, hop_headers, current_body,
                current_content_type, timeout, proxy, verify, current_auth,
                sink=sink, stream=stream, max_body=max_body, cert=cert,
                http_version=http_version, interface=interface, debug=debug)
            response.elapsed = time.monotonic() - started
            if cookie_jar is not None and response.cookie_specs:
                try:
                    cookie_jar.absorb(current_url, response.cookie_specs)
                except Exception:
                    pass
            location = response.headers.get("Location")
            if (not allow_redirects or response.status_code not in _REDIRECT_STATUSES
                    or not location):
                response.history = history
                return response
            if redirects >= max_redirects and max_redirects != -1:
                exc = TooManyRedirects(
                    "too many redirects (maximum %s)" % max_redirects, code=47)
                exc.response = response
                raise exc
            next_url = urljoin(current_url, _redirect_target(location))
            if allow_redirects == "safe" and not self._is_safe_redirect(next_url):
                exc = TooManyRedirects(
                    "refusing unsafe redirect to %s" % next_url, code=47)
                exc.response = response
                raise exc
            history.append(response)
            if self._origin(next_url) != self._origin(current_url):
                current_auth = None
                base_headers = tuple(
                    h for h in (base_headers or ())
                    if h[0].lower() not in self._STRIP_ON_ORIGIN_CHANGE)
                explicit_cookie = False
            if response.status_code == 303 or (
                    response.status_code in (301, 302) and current_method == "POST"):
                if current_method != "HEAD":  # HEAD stays HEAD on 303
                    current_method = "GET"
                    current_body = b""
                    current_content_type = None
                    base_headers = tuple(
                        h for h in (base_headers or ())
                        if h[0].lower() not in self._STRIP_ON_METHOD_REWRITE)
            current_url = next_url
            redirects += 1
