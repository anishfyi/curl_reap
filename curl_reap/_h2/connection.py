"""Blocking HTTP/2 connection: drives :class:`H2Core` over a socket.

:class:`H2Connection` wraps any socket-like object with ``sendall``,
``recv``, ``settimeout`` and ``close`` (a plain socket for prior knowledge
HTTP/2, an ``ssl.SSLSocket`` or curl_reap's own TLS socket after ALPN picked
``h2``).  The constructor sends the connection preface; :meth:`request`
runs one exchange at a time (calls from several threads queue on a lock,
the core underneath supports concurrent streams for a future asyncio
driver); :meth:`ping` measures a round trip; :meth:`close` sends GOAWAY and
closes the socket.

Deadlines are absolute ``time.monotonic()`` values.  Running out of time
raises :class:`curl_reap.exceptions.ReadTimeout` (while waiting for the
server) or :class:`curl_reap.exceptions.Timeout` (while sending); socket
failures raise :class:`curl_reap.exceptions.ConnectionError` with libcurl's
``RECV_ERROR`` or ``SEND_ERROR`` code; protocol failures raise
:class:`H2Error`.  Any of these leaves ``alive`` False.
"""
from __future__ import annotations

import select
import socket
import threading
import time

from ..exceptions import (
    ConnectionError as _ConnectionError, CurlECode, IncompleteRead, ReadTimeout, Timeout,
)
from . import frames as F
from .core import (
    ConnectionTerminated, DataReceived, H2Core, InformationalResponse, PingAckReceived,
    ResponseReceived, StreamEnded, StreamReset, TrailersReceived,
)
from .errors import H2Error, error_name
from .spec import H2Spec

DEFAULT_MAX_BODY = 64 * 1024 * 1024
_RECV_SIZE = 65536


class H2Response(object):
    """One HTTP/2 response.

    ``status`` is the final status code, ``headers`` the ordered list of
    ``(name, value)`` with lowercase names, ``body`` the raw (still content
    encoded) bytes or None when ``on_data`` streamed it, ``trailers`` the
    trailer fields, ``informational`` every 1xx head that preceded the
    final one as ``(status, headers)`` and ``stream_id`` the stream used.
    """

    __slots__ = ("status", "headers", "body", "trailers", "informational", "stream_id")

    def __init__(self, status, headers, body, trailers, stream_id, informational=()):
        self.status = status
        self.headers = headers
        self.body = body
        self.trailers = trailers
        self.stream_id = stream_id
        self.informational = list(informational)

    def __repr__(self):
        size = None if self.body is None else len(self.body)
        return "H2Response(status=%r, headers=%d, body=%r, trailers=%d, stream_id=%r)" % (
            self.status, len(self.headers), size, len(self.trailers), self.stream_id)


def _remaining(deadline):
    if deadline is None:
        return None
    return deadline - time.monotonic()


def _content_length(headers):
    for name, value in headers:
        if name == "content-length":
            value = value.strip()
            if value.isdigit():
                return int(value)
            return None
    return None


class _Exchange(object):
    """Collects the events of one stream into an :class:`H2Response`."""

    def __init__(self, connection, stream_id, method, on_data, max_body):
        self.connection = connection
        self.stream_id = stream_id
        self.method = method.upper()
        self.on_data = on_data
        self.max_body = max_body
        self.status = None
        self.headers = None
        self.informational = []
        self.trailers = []
        self.chunks = []
        self.size = 0
        self.ended = False

    @property
    def done(self):
        return self.ended

    def handle(self, event):
        core = self.connection._core
        if isinstance(event, ConnectionTerminated):
            if self.ended:
                # The response already arrived in full (END_STREAM was seen
                # earlier in this read). A GOAWAY after it ends the connection,
                # not the exchange: keep the response, as curl and nghttp2 do.
                return
            if event.last_stream_id < self.stream_id:
                raise H2Error(
                    "server sent GOAWAY (%s) before processing stream %d"
                    % (error_name(event.error_code), self.stream_id),
                    error_code=event.error_code, stream_id=self.stream_id, retryable=True)
            if event.error_code != F.NO_ERROR:
                raise H2Error("server sent GOAWAY with %s: %s"
                              % (error_name(event.error_code),
                                 event.debug_data.decode("latin-1", "replace")),
                              error_code=event.error_code, retryable=False)
            return
        stream_id = getattr(event, "stream_id", None)
        if stream_id != self.stream_id:
            return
        if isinstance(event, DataReceived):
            core.acknowledge_received_data(stream_id, event.flow_controlled_length)
            if not event.data:
                return
            if self.on_data is not None:
                try:
                    self.on_data(event.data)
                except BaseException:
                    core.reset_stream(stream_id, F.CANCEL)
                    raise
                return
            self.size += len(event.data)
            if self.size > self.max_body:
                core.reset_stream(stream_id, F.CANCEL)
                raise H2Error("response body exceeds max_body of %d bytes" % self.max_body,
                              error_code=F.CANCEL, stream_id=stream_id,
                              code=CurlECode.FILESIZE_EXCEEDED)
            self.chunks.append(event.data)
        elif isinstance(event, ResponseReceived):
            self.status = event.status
            self.headers = event.headers
        elif isinstance(event, InformationalResponse):
            self.informational.append((event.status, event.headers))
        elif isinstance(event, TrailersReceived):
            self.trailers = event.headers
        elif isinstance(event, StreamEnded):
            self.ended = True
        elif isinstance(event, StreamReset):
            if self.ended:
                return
            if event.remote:
                raise H2Error(
                    "stream %d reset by the server with %s" % (stream_id, error_name(event.error_code)),
                    error_code=event.error_code, stream_id=stream_id,
                    retryable=event.error_code == F.REFUSED_STREAM)
            raise H2Error("stream %d reset: %s" % (stream_id, event.reason or error_name(event.error_code)),
                          error_code=event.error_code, stream_id=stream_id)

    def response(self):
        if self.status is None:
            raise H2Error("stream %d ended without a response" % self.stream_id,
                          stream_id=self.stream_id)
        body = None if self.on_data is not None else b"".join(self.chunks)
        expected = _content_length(self.headers)
        if (expected is not None and self.method != "HEAD" and self.status >= 200
                and self.status not in (204, 304) and self.size < expected):
            raise IncompleteRead("HTTP/2 stream %d closed with %d of %d body bytes received"
                                 % (self.stream_id, self.size, expected))
        return H2Response(self.status, self.headers, body, self.trailers, self.stream_id,
                          self.informational)


def _iter_body(body):
    if body is None:
        return
    if isinstance(body, (bytes, bytearray, memoryview)):
        if len(body):
            yield body
        return
    if isinstance(body, str):
        raise TypeError("HTTP/2 request bodies must be bytes, not str")
    for chunk in body:
        if chunk:
            yield chunk


class H2Connection(object):
    """One HTTP/2 connection over ``sock`` that behaves like ``spec``'s browser.

    ``max_body`` caps buffered response bodies (streaming through ``on_data``
    is uncapped).  ``deadline`` limits the preface write.
    """

    def __init__(self, sock, spec, *, max_body=DEFAULT_MAX_BODY, deadline=None):
        if not isinstance(spec, H2Spec):
            raise TypeError("spec must be an H2Spec (use spec(name) or spec_from_akamai())")
        self.sock = sock
        self.spec = spec
        self.max_body = max_body
        self._core = H2Core(spec)
        self._lock = threading.Lock()
        self._closed = False
        self._failure = None
        self.requests_sent = 0
        self._core.initiate_connection()
        self._flush(deadline)

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------

    @property
    def alive(self):
        """False after GOAWAY (either direction), a connection error or close()."""
        return not self._closed and self._failure is None and self._core.alive

    @property
    def core(self):
        """The sans-IO core, for inspection (settings, windows, HPACK tables)."""
        return self._core

    def request(self, method, scheme, authority, path, headers, body=b"", *,
                on_data=None, deadline=None):
        """Send one request and return its :class:`H2Response`.

        ``headers`` are ordered regular ``(name, value)`` pairs (pseudo
        headers come from the other arguments).  ``body`` is bytes or an
        iterable of bytes chunks; it is split by the peer's frame size and
        both flow control windows, waiting for WINDOW_UPDATE as needed.
        ``on_data(chunk)`` streams the body instead of buffering it.
        """
        with self._lock:
            self._require_alive()
            chunks = _iter_body(body)
            first = next(chunks, None)
            end_stream = first is None
            stream_id = self._core.send_request(method, scheme, authority, path, headers,
                                                end_stream=end_stream)
            self.requests_sent += 1
            exchange = _Exchange(self, stream_id, method, on_data, self.max_body)
            self._flush(deadline)
            try:
                if not end_stream:
                    self._send_body(stream_id, first, chunks, exchange, deadline)
                while not exchange.done:
                    self._read_once(exchange, deadline)
            except H2Error:
                self._flush_quietly()
                raise
            except (Timeout, OSError) as exc:
                # A half finished exchange leaves the connection unusable.
                self._die("request aborted: %s" % exc)
                raise
            return exchange.response()

    def ping(self, *, timeout=5.0, deadline=None):
        """Send PING, wait for its ACK and return the round trip in seconds."""
        with self._lock:
            self._require_alive()
            if deadline is None and timeout is not None:
                deadline = time.monotonic() + timeout
            data = self._core.ping()
            started = time.monotonic()
            self._flush(deadline)
            while True:
                chunk = self._recv(deadline)
                if not chunk:
                    raise H2Error("connection closed while waiting for the PING ACK", retryable=True)
                events = self._receive(chunk, deadline)
                for event in events:
                    if isinstance(event, PingAckReceived) and event.data == data:
                        return time.monotonic() - started
                    if isinstance(event, ConnectionTerminated):
                        self._flush_quietly()
                        raise H2Error("server sent GOAWAY (%s) during PING" % error_name(event.error_code),
                                      error_code=event.error_code, retryable=True)

    def poll(self):
        """Process frames that already arrived without blocking; return ``alive``.

        Meant for pool liveness checks: a GOAWAY the server sent while the
        connection sat idle is seen here, and PINGs are answered.  Returns
        the current ``alive`` without reading when a request is in flight.
        """
        if not self._lock.acquire(False):
            return self.alive
        try:
            while self.alive and self._readable(0):
                try:
                    self.sock.settimeout(0)
                    chunk = self.sock.recv(_RECV_SIZE)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError as exc:
                    if type(exc).__name__ in ("SSLWantReadError", "SSLWantWriteError"):
                        break
                    self._failure = "poll: %s" % exc
                    break
                if not chunk:
                    self._failure = "connection closed by the server"
                    break
                try:
                    self._receive(chunk, None)
                except H2Error:
                    break
                self._flush_quietly()
            return self.alive
        finally:
            self._lock.release()

    def close(self):
        """Send GOAWAY (NO_ERROR, last processed push stream, no debug data) and close."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                if self._failure is None:
                    self._core.close()
                    self._flush_quietly()
            finally:
                try:
                    self.sock.close()
                except OSError:
                    pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _require_alive(self):
        if self._closed:
            raise H2Error("connection closed", retryable=True)
        if self._failure is not None:
            raise H2Error("connection failed: %s" % self._failure, retryable=True)
        if not self._core.alive:
            self._core._check_can_open()

    def _die(self, reason):
        if self._failure is None:
            self._failure = reason

    def _set_timeout(self, deadline, what):
        remaining = _remaining(deadline)
        if remaining is not None and remaining <= 0:
            if what == "read":
                raise ReadTimeout("HTTP/2 %s deadline passed" % what)
            raise Timeout("HTTP/2 %s deadline passed" % what)
        try:
            self.sock.settimeout(remaining)
        except OSError:
            pass

    def _flush(self, deadline):
        data = self._core.data_to_send()
        if not data:
            return
        self._set_timeout(deadline, "send")
        try:
            self.sock.sendall(data)
        except socket.timeout:
            self._die("send timed out")
            raise Timeout("HTTP/2 send timed out")
        except OSError as exc:
            self._die("send failed: %s" % exc)
            raise _ConnectionError("HTTP/2 send failed: %s" % exc, code=CurlECode.SEND_ERROR)

    def _flush_quietly(self):
        data = self._core.data_to_send()
        if not data:
            return
        try:
            self.sock.settimeout(1.0)
            self.sock.sendall(data)
        except OSError:
            pass

    def _recv(self, deadline):
        self._set_timeout(deadline, "read")
        try:
            chunk = self.sock.recv(_RECV_SIZE)
        except socket.timeout:
            raise ReadTimeout("HTTP/2 read timed out")
        except OSError as exc:
            self._die("receive failed: %s" % exc)
            raise _ConnectionError("HTTP/2 receive failed: %s" % exc, code=CurlECode.RECV_ERROR)
        if not chunk:
            self._die("connection closed by the server")
        return chunk

    def _receive(self, chunk, deadline):
        try:
            events = self._core.receive_data(chunk)
        except H2Error as exc:
            self._die("protocol error: %s" % exc)
            self._flush_quietly()
            raise
        self._flush(deadline)
        return events

    def _readable(self, timeout):
        pending = getattr(self.sock, "pending", None)
        if pending is not None:
            try:
                if pending():
                    return True
            except (OSError, ValueError):
                return False
        try:
            fd = self.sock.fileno()
        except (OSError, ValueError, AttributeError):
            return False
        if fd < 0:
            return False
        try:
            ready, _, _ = select.select([fd], [], [], timeout)
        except (OSError, ValueError):
            return False
        return bool(ready)

    def _read_once(self, exchange, deadline):
        try:
            chunk = self._recv(deadline)
        except _ConnectionError as exc:
            raise H2Error("%s before the response completed" % exc, code=CurlECode.RECV_ERROR,
                          stream_id=exchange.stream_id, retryable=exchange.status is None) from exc
        if not chunk:
            raise H2Error("connection closed by the server before the response completed",
                          stream_id=exchange.stream_id, retryable=exchange.status is None)
        events = self._receive(chunk, deadline)
        try:
            for event in events:
                exchange.handle(event)
        finally:
            self._flush(deadline)

    def _send_body(self, stream_id, first, chunks, exchange, deadline):
        core = self._core
        pending = memoryview(first)
        while True:
            if exchange.done:
                core.reset_stream(stream_id, F.CANCEL)
                self._flush(deadline)
                return
            if pending.nbytes == 0:
                nxt = next(chunks, None)
                if nxt is None:
                    core.end_stream(stream_id)
                    self._flush(deadline)
                    return
                pending = memoryview(nxt)
                continue
            sent = core.send_data(stream_id, pending, end_stream=False)
            if sent:
                pending = pending[sent:]
                self._flush(deadline)
                if self._readable(0):
                    self._read_once(exchange, deadline)
                continue
            self._read_once(exchange, deadline)


__all__ = ["H2Connection", "H2Response", "DEFAULT_MAX_BODY"]
