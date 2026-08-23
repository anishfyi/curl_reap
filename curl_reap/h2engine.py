"""Optional HTTP/2 transport on hyper-h2 (``pip install "curl-reap[h2]"``).

One TLS connection per host carries HTTP/2 frames: header compression, no
head-of-line waiting between sequential requests, and an ALPN-negotiated
``h2`` fingerprint that more servers expect from real browsers. Requests are
issued one stream at a time (sequential multiplexing), which keeps ordering
deterministic and retries simple.

Everything above this module - cookies, retries, rotation, caching - is
unchanged: this class returns the same ``(status, header_list, body)``
triple the HTTP/1.1 path feeds into :class:`curl_reap.http._RawResponse`.
"""
from __future__ import annotations

import threading

from .http import TransportError

_MAX_BODY_BYTES = 64 * 1024 * 1024


class H2Protocol:
    """Speaks HTTP/2 over an already-TLS'd socket that negotiated ``h2``."""

    def __init__(self, sock):
        try:
            from h2.config import H2Configuration
            from h2.connection import H2Connection
        except ImportError as exc:  # pragma: no cover - guarded by caller
            raise TransportError(
                'HTTP/2 needs hyper-h2: pip install "curl-reap[h2]"') from exc
        self.sock = sock
        self._lock = threading.Lock()
        self._conn = H2Connection(
            config=H2Configuration(client_side=True, header_encoding="latin-1"))
        self._conn.initiate_connection()
        self._flush()

    def _flush(self):
        data = self._conn.data_to_send()
        if data:
            self.sock.sendall(data)

    def close(self):
        try:
            self._conn.close_connection()
            self._flush()
        except Exception:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    @staticmethod
    def _lower(headers):
        out = []
        for name, value in headers:
            lowered = name.lower().encode("latin-1")
            if lowered.startswith(b":"):
                continue
            if lowered in (b"connection", b"keep-alive", b"transfer-encoding",
                           b"upgrade", b"proxy-connection", b"host"):
                continue  # illegal or implied in HTTP/2
            out.append((lowered, str(value).encode("latin-1")))
        return out

    def request(self, method, target, authority, scheme, ordered_headers,
                body=b"", content_type=None):
        """Send one request on a fresh stream; return (status, headers, body)."""
        from h2.events import DataReceived, ResponseReceived, StreamEnded, StreamReset

        with self._lock:
            stream_id = self._conn.get_next_available_stream_id()
            pseudo = [
                (b":method", method.upper().encode("ascii")),
                (b":scheme", scheme.encode("ascii")),
                (b":authority", authority.encode("latin-1")),
                (b":path", target.encode("latin-1")),
            ]
            regular = self._lower(ordered_headers)
            if content_type:
                regular = [(b"content-type", content_type.encode("latin-1"))
                           ] + [h for h in regular
                                if h[0] != b"content-type"]
            end = b"" if body else True
            self._conn.send_headers(stream_id, pseudo + regular,
                                    end_stream=not body)
            if body:
                self._conn.send_data(stream_id, body, end_stream=True)

            status = None
            response_headers = []
            chunks = []
            received = 0
            while True:
                self._flush()
                wire = self.sock.recv(65536)
                if not wire:
                    raise TransportError("HTTP/2 connection closed mid-response")
                try:
                    events = self._conn.receive_data(wire)
                except Exception as exc:
                    raise TransportError("HTTP/2 framing error: %s" % exc)
                for event in events:
                    if isinstance(event, ResponseReceived):
                        status = None
                        response_headers = []
                        for name, value in event.headers:
                            if name == ":status":
                                status = int(value)
                            elif not name.startswith(":"):
                                response_headers.append((name, value))
                    elif isinstance(event, DataReceived):
                        received += event.flow_controlled_length
                        if received > _MAX_BODY_BYTES:
                            raise TransportError("HTTP/2 body exceeds %d bytes"
                                                 % _MAX_BODY_BYTES)
                        chunks.append(event.data)
                        self._conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded):
                        if status is None:
                            raise TransportError("HTTP/2 stream ended without "
                                                 "a response")
                        self._flush()
                        return status, response_headers, b"".join(chunks)
                    elif isinstance(event, StreamReset):
                        raise TransportError("HTTP/2 stream reset by server "
                                             "(error %s)" % event.error_code)
                outbound = self._conn.data_to_send()
                if outbound:
                    self.sock.sendall(outbound)
