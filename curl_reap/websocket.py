"""WebSocket client (RFC 6455) over the curl_reap transport.

:class:`WebSocket` performs the HTTP/1.1 upgrade handshake through the same
connection machinery HTTP uses (native TLS engine when available, proxies,
verify/CA options), then speaks frames: text/binary messages, fragmentation,
ping/pong keepalive and the closing handshake.  :class:`AsyncWebSocket` is
the same API as coroutines, thread-backed like :class:`curl_reap.aio.AsyncSession`.

Usage::

    ws = curl_reap.WebSocket.connect("wss://example.com/socket")
    ws.send("hello")
    print(ws.recv())          # 'hi'  (str for text, bytes for binary)
    ws.close()
"""
from __future__ import annotations

import base64
import hashlib
import json as _json
import os
import socket
import struct
import threading
import time
from typing import List, Optional, Tuple, Union

from .exceptions import (
    ConnectTimeout,
    InvalidSchema,
    ReadTimeout,
    TransportError,
    WebSocketClosed,
    WebSocketError,
    WebSocketTimeout,
)

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Close codes (RFC 6457 7.4.1 + common extensions)
CLOSE_NORMAL = 1000
CLOSE_GOING_AWAY = 1001
CLOSE_PROTOCOL_ERROR = 1002
CLOSE_UNSUPPORTED = 1003
CLOSE_NO_STATUS = 1005
CLOSE_ABNORMAL = 1006
CLOSE_INVALID_PAYLOAD = 1007
CLOSE_POLICY = 1008
CLOSE_TOO_BIG = 1009
CLOSE_MISSING_EXTENSION = 1010
CLOSE_INTERNAL_ERROR = 1011

_OP_CONT, _OP_TEXT, _OP_BINARY, _OP_CLOSE, _OP_PING, _OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA

_WS_SCHEMES = {"ws": "http", "wss": "https"}


def _pack_frame(opcode, payload: bytes, fin=True, mask=True) -> bytes:
    first = (0x80 if fin else 0) | opcode
    length = len(payload)
    if mask:
        key = os.urandom(4)
    header = bytearray([first])
    if length < 126:
        header.append((0x80 if mask else 0) | length)
    elif length < 65536:
        header.append((0x80 if mask else 0) | 126)
        header += struct.pack(">H", length)
    else:
        header.append((0x80 if mask else 0) | 127)
        header += struct.pack(">Q", length)
    if not mask:
        return bytes(header) + payload
    masked = bytearray(b ^ key[i % 4] for i, b in enumerate(payload))
    return bytes(header) + key + bytes(masked)


class _FrameReader:
    """Incremental frame parser over a socket (with a pre-seeded buffer)."""

    def __init__(self, sock, initial: bytes = b""):
        self._sock = sock
        self._buf = bytearray(initial)

    def _need(self, n, timeout, deadline):
        while len(self._buf) < n:
            remaining = None
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ReadTimeout("websocket deadline exceeded")
            if timeout is not None and remaining is not None:
                timeout = min(timeout, remaining)
            elif remaining is not None:
                timeout = remaining
            self._sock.settimeout(timeout)
            try:
                chunk = self._sock.recv(65536)
            except (TimeoutError, socket.timeout) as exc:
                raise WebSocketTimeout("timed out waiting for a websocket frame") from exc
            except (OSError,) as exc:
                raise WebSocketClosed("connection lost: %s" % exc,
                                      code=CLOSE_ABNORMAL) from exc
            if not chunk:
                raise WebSocketClosed("connection closed without a close frame",
                                      code=CLOSE_ABNORMAL)
            self._buf += chunk

    def read_frame(self, timeout, deadline) -> Tuple[int, bool, bytes]:
        """Return (opcode, fin, payload); control frames are complete."""
        self._need(2, timeout, deadline)
        first, second = self._buf[0], self._buf[1]
        opcode = first & 0x0F
        fin = bool(first & 0x80)
        masked = bool(second & 0x80)
        length = second & 0x7F
        offset = 2
        if length == 126:
            self._need(4, timeout, deadline)
            length = struct.unpack(">H", bytes(self._buf[2:4]))[0]
            offset = 4
        elif length == 127:
            self._need(10, timeout, deadline)
            length = struct.unpack(">Q", bytes(self._buf[2:10]))[0]
            offset = 10
        if length > 64 * 1024 * 1024:
            raise WebSocketError("websocket frame of %d bytes exceeds the cap" % length)
        mask = b""
        if masked:
            self._need(offset + 4 + length, timeout, deadline)
            mask = bytes(self._buf[offset:offset + 4])
            offset += 4
        else:
            self._need(offset + length, timeout, deadline)
        payload = bytes(self._buf[offset:offset + length])
        del self._buf[:offset + length]
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return opcode, fin, payload


class WebSocket:
    """One open WebSocket connection.

    ``recv()`` returns ``str`` for text messages and ``bytes`` for binary
    ones; pings are answered automatically and their arrangers never surface.
    A server close frame raises :class:`WebSocketClosed` carrying ``code``
    and ``reason``; after that (or ``close()``) the socket is unusable.
    """

    def __init__(self, sock, host, subprotocol=None, timeout=None, deadline=None,
                 transport=None, initial=b""):
        self._sock = sock
        self._reader = _FrameReader(sock, initial)
        self.host = host
        self.subprotocol = subprotocol
        self.timeout = timeout
        self.deadline = deadline
        self._transport = transport
        self._sendlock = threading.Lock()
        self._closed = False
        self.close_code: Optional[int] = None
        self.close_reason = ""
        self._close_sent = False

    # -- connect ---------------------------------------------------------------
    @classmethod
    def connect(cls, url, *, session=None, subprotocols=(), headers=None,
                timeout=None, profile=None, proxy=None, verify=True):
        """Open a WebSocket at ``ws://`` or ``wss://`` URL."""
        from urllib.parse import quote, urlsplit, urlunsplit

        parts = urlsplit(url)
        if parts.scheme.lower() not in _WS_SCHEMES:
            raise InvalidSchema("websocket URLs must be ws:// or wss://")
        scheme = _WS_SCHEMES[parts.scheme.lower()]
        host = (parts.hostname or "").lower()
        if not host:
            raise InvalidSchema("websocket URL must include a hostname")
        try:
            host_idna = host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError) as exc:
            raise InvalidSchema("invalid websocket host: %s" % exc)
        port = parts.port or (443 if scheme == "https" else 80)

        owns_transport = session is None
        transport = None if owns_transport else session._transport
        from .transport import _Transport, _BufferedSocket, _merge_headers, _request_target
        from .tls import resolve_profile
        selected = resolve_profile(profile or getattr(session, "profile", None) or "chrome")
        if transport is None:
            transport = _Transport()

        key = base64.b64encode(os.urandom(16)).decode("ascii")
        upgrade = [
            ("Host", "%s:%d" % (host_idna, port) if port not in (80, 443) else host_idna),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Key", key),
            ("Sec-WebSocket-Version", "13"),
        ]
        if subprotocols:
            upgrade.append(("Sec-WebSocket-Protocol", ", ".join(subprotocols)))
        upgrade = _merge_headers(selected.headers, upgrade, headers or ())

        deadline = None
        connect_timeout = timeout
        if timeout is not None:
            deadline = time.monotonic() + timeout

        conn = None
        try:
            conn = transport._connect(scheme, host_idna, port, proxy, selected,
                                      verify, timeout, deadline, http_version="v1")
            path = _request_target(parts)
            rendered = [("GET %s HTTP/1.1\r\n" % path).encode("ascii")]
            for name, value in upgrade:
                rendered.append(("%s: %s\r\n" % (name, value)).encode("latin-1"))
            rendered.append(b"\r\n")
            conn.sock.settimeout(timeout)
            conn.sock.sendall(b"".join(rendered))
            head = conn.reader.read_until(b"\r\n\r\n", 65536)
            lines = head[:-4].split(b"\r\n")
            status_line = lines[0].decode("latin-1", "replace")
            pieces = status_line.split(" ", 2)
            if len(pieces) < 2 or not pieces[1].isdigit() or int(pieces[1]) != 101:
                conn.close()
                raise WebSocketError("websocket handshake rejected: %s" % status_line)
            accept = None
            agreed = None
            for line in lines[1:]:
                name, _, value = line.partition(b":")
                name = name.decode("latin-1").strip().lower()
                if name == "sec-websocket-accept":
                    accept = value.decode("latin-1").strip()
                elif name == "sec-websocket-protocol":
                    agreed = value.decode("latin-1").strip()
            expected = base64.b64encode(
                hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")
            if accept != expected:
                conn.close()
                raise WebSocketError("websocket handshake key mismatch")
            sock = conn.sock
            ws = cls(sock, host, subprotocol=agreed, timeout=timeout, deadline=deadline,
                     transport=transport, initial=bytes(conn.reader.buffer))
            ws._conn = conn
            return ws
        except (TransportError, OSError):
            if conn is not None:
                conn.close()
            raise

    # -- sending ---------------------------------------------------------------
    def _send_frame(self, opcode, payload: bytes, fin=True):
        if self._closed:
            raise WebSocketClosed("websocket is closed", code=CLOSE_NO_STATUS)
        with self._sendlock:
            try:
                self._sock.sendall(_pack_frame(opcode, payload, fin=fin))
            except (OSError, TransportError) as exc:
                self._closed = True
                raise WebSocketClosed("send failed: %s" % exc, code=CLOSE_ABNORMAL) from exc

    def send(self, payload, chunk_size=65536):
        """Send a text (str) or binary (bytes) message, fragmenting large ones."""
        if isinstance(payload, str):
            opcode, data = _OP_TEXT, payload.encode("utf-8")
        elif isinstance(payload, (bytes, bytearray, memoryview)):
            opcode, data = _OP_BINARY, bytes(payload)
        else:
            raise TypeError("payload must be str or bytes")
        if len(data) <= chunk_size:
            self._send_frame(opcode, data)
            return
        view = memoryview(data)
        for start in range(0, len(data), chunk_size):
            self._send_frame(opcode if start == 0 else _OP_CONT,
                             bytes(view[start:start + chunk_size]),
                             fin=start + chunk_size >= len(data))

    def send_text(self, text):
        self.send(text)

    def send_bytes(self, data):
        self.send(data)

    def send_json(self, obj, **kwargs):
        self.send(_json.dumps(obj, **kwargs))

    def ping(self, payload=b""):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        self._send_frame(_OP_PING, bytes(payload)[:125])

    def pong(self, payload=b""):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        self._send_frame(_OP_PONG, bytes(payload)[:125])

    # -- receiving ---------------------------------------------------------------
    def recvp(self, timeout=None) -> Tuple[int, Union[str, bytes, None]]:
        """Raw receive: (opcode, payload).  Control frames are returned as-is."""
        timeout = self.timeout if timeout is None else timeout
        while True:
            opcode, fin, payload = self._reader.read_frame(timeout, self.deadline)
            if opcode == _OP_PING:
                try:
                    self.pong(payload)
                except WebSocketClosed:
                    pass
                continue
            if opcode == _OP_PONG:
                continue
            if opcode == _OP_CLOSE:
                code, reason = CLOSE_NO_STATUS, ""
                if len(payload) >= 2:
                    code = struct.unpack(">H", payload[:2])[0]
                    reason = payload[2:].decode("utf-8", "replace")
                self._closed = True
                self.close_code, self.close_reason = code, reason
                try:
                    self._send_close(code)
                except Exception:
                    pass
                raise WebSocketClosed("websocket closed by the peer",
                                      code=code, reason=reason)
            if not fin:
                # assemble one fragmented message
                parts = [payload]
                while True:
                    op, fin, part = self._reader.read_frame(timeout, self.deadline)
                    if op == _OP_PING:
                        self.pong(part)
                        continue
                    if op == _OP_CLOSE:
                        continue  # handled by the outer loop next iteration
                    parts.append(part)
                    if fin:
                        break
                payload = b"".join(parts)
                opcode = _OP_TEXT if opcode == _OP_TEXT else _OP_BINARY
            if opcode == _OP_TEXT:
                return _OP_TEXT, payload.decode("utf-8", "replace")
            return opcode, payload

    def recv(self, timeout=None) -> Union[str, bytes]:
        """Next data message: str for text, bytes for binary."""
        while True:
            opcode, payload = self.recvp(timeout)
            if opcode in (_OP_TEXT, _OP_BINARY):
                return payload

    def recv_json(self, timeout=None):
        return _json.loads(self.recv(timeout))

    # -- closing ---------------------------------------------------------------
    def _send_close(self, code=CLOSE_NORMAL, reason=""):
        if self._close_sent:
            return
        self._close_sent = True
        try:
            self._sock.sendall(_pack_frame(
                _OP_CLOSE, struct.pack(">H", code) + reason.encode("utf-8")[:123]))
        except (OSError, TransportError):
            pass

    def close(self, code=CLOSE_NORMAL, reason="", timeout=5.0):
        """Send a close frame and wait (best effort) for the peer's."""
        if self._closed:
            return
        self._send_close(code, reason)
        try:
            self._sock.settimeout(timeout)
            deadline = time.monotonic() + (timeout or 5)
            while True:
                opcode, _, payload = self._reader.read_frame(timeout, deadline)
                if opcode == _OP_CLOSE:
                    if len(payload) >= 2:
                        self.close_code = struct.unpack(">H", payload[:2])[0]
                        self.close_reason = payload[2:].decode("utf-8", "replace")
                    break
        except (WebSocketClosed, WebSocketTimeout, OSError):
            pass
        finally:
            self._closed = True
            self._teardown()

    def _teardown(self):
        sock = getattr(self, "_sock", None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        conn = getattr(self, "_conn", None)
        if conn is not None:
            conn.closed = True

    @property
    def closed(self):
        return self._closed

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self):
        state = "closed" if self._closed else "open"
        return "<WebSocket %s (%s)>" % (self.host, state)


class AsyncWebSocket:
    """Coroutine API over :class:`WebSocket` (thread-backed, like AsyncSession)."""

    def __init__(self, ws: WebSocket):
        import asyncio
        self._ws = ws
        self._loop = asyncio.get_running_loop()

    @classmethod
    async def connect(cls, url, **kwargs):
        import asyncio
        ws = await asyncio.to_thread(WebSocket.connect, url, **kwargs)
        return cls(ws)

    async def _run(self, fn, *args):
        import asyncio
        return await asyncio.to_thread(fn, *args)

    async def send(self, payload, **kw):
        await self._run(self._ws.send, payload, **kw)

    async def send_json(self, obj, **kw):
        await self._run(self._ws.send_json, obj, **kw)

    async def ping(self, payload=b""):
        await self._run(self._ws.ping, payload)

    async def recv(self, timeout=None):
        return await self._run(self._ws.recv, timeout)

    async def recv_json(self, timeout=None):
        return await self._run(self._ws.recv_json, timeout)

    async def close(self, **kw):
        await self._run(self._ws.close, **kw)

    @property
    def closed(self):
        return self._ws.closed

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()


__all__ = [
    "WebSocket", "AsyncWebSocket",
    "CLOSE_NORMAL", "CLOSE_GOING_AWAY", "CLOSE_PROTOCOL_ERROR", "CLOSE_UNSUPPORTED",
    "CLOSE_NO_STATUS", "CLOSE_ABNORMAL", "CLOSE_INVALID_PAYLOAD", "CLOSE_POLICY",
    "CLOSE_TOO_BIG", "CLOSE_MISSING_EXTENSION", "CLOSE_INTERNAL_ERROR",
]
