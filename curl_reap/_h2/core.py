"""Sans-IO HTTP/2 client core.

:class:`H2Core` owns the connection state (settings, flow control windows,
HPACK encoder and decoder, streams) and knows nothing about sockets.  A
driver feeds it bytes with :meth:`H2Core.receive_data`, which returns a list
of events, and writes whatever :meth:`H2Core.data_to_send` hands back.  The
blocking :class:`curl_reap._h2.connection.H2Connection` is one such driver;
an asyncio driver can reuse this class unchanged, including with several
streams open at once.

Wire behaviour follows the :class:`H2Spec` it is given: the connection
preface is the magic, one SETTINGS frame with the spec's pairs in order and
nothing else, a WINDOW_UPDATE on stream 0 with the spec's increment, the
spec's PRIORITY frames, and request HEADERS carrying the spec's flags,
priority field and pseudo header order.  Receive side flow control sends
WINDOW_UPDATE the way Chrome does: once more than half of the window has
been consumed, on the stream and on the connection separately.

Protocol violations by the peer that RFC 9113 classes as connection errors
queue a GOAWAY and raise :class:`H2Error`; stream errors queue RST_STREAM
and surface as :class:`StreamReset` events with ``remote=False``.  Frames on
streams this core does not know (closed, or pushed and refused) are
discarded after their HPACK and flow control side effects are applied, so
one misbehaving stream never kills the connection.
"""
from __future__ import annotations

import os
import struct

from hpack import Decoder as HpackDecoder

from ..exceptions import InvalidHeader
from .errors import H2Error, error_name
from . import frames as F
from .hpack_encoder import HpackEncoder
from .spec import H2Spec

# Headers that must not appear in an HTTP/2 request (RFC 9113 section 8.2.2);
# ``host`` is carried by ``:authority``.
CONNECTION_SPECIFIC_HEADERS = frozenset((
    b"connection", b"keep-alive", b"proxy-connection", b"transfer-encoding",
    b"upgrade", b"host",
))
_TOKEN_CHARS = frozenset(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz")
_METHOD_CHARS = _TOKEN_CHARS | frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")

_DEFAULT_MAX_HEADER_LIST_SIZE = 1 << 20


# --------------------------------------------------------------------------
# events
# --------------------------------------------------------------------------

class Event(object):
    """Base class of everything :meth:`H2Core.receive_data` returns."""

    __slots__ = ()

    def __repr__(self):
        fields = ", ".join("%s=%r" % (name, getattr(self, name)) for name in self.__slots__)
        return "%s(%s)" % (type(self).__name__, fields)


class RemoteSettingsChanged(Event):
    """The peer sent SETTINGS; ``settings`` maps identifier to the new value."""

    __slots__ = ("settings",)

    def __init__(self, settings):
        self.settings = settings


class SettingsAcknowledged(Event):
    """The peer acknowledged our SETTINGS."""

    __slots__ = ()


class InformationalResponse(Event):
    """A 1xx response (``status``, ``headers``) that precedes the final one."""

    __slots__ = ("stream_id", "status", "headers")

    def __init__(self, stream_id, status, headers):
        self.stream_id = stream_id
        self.status = status
        self.headers = headers


class ResponseReceived(Event):
    """The final response head for ``stream_id``."""

    __slots__ = ("stream_id", "status", "headers")

    def __init__(self, stream_id, status, headers):
        self.stream_id = stream_id
        self.status = status
        self.headers = headers


class DataReceived(Event):
    """Body bytes.  ``flow_controlled_length`` includes padding and must be
    passed to :meth:`H2Core.acknowledge_received_data` once consumed."""

    __slots__ = ("stream_id", "data", "flow_controlled_length")

    def __init__(self, stream_id, data, flow_controlled_length):
        self.stream_id = stream_id
        self.data = data
        self.flow_controlled_length = flow_controlled_length


class TrailersReceived(Event):
    __slots__ = ("stream_id", "headers")

    def __init__(self, stream_id, headers):
        self.stream_id = stream_id
        self.headers = headers


class StreamEnded(Event):
    """The peer set END_STREAM; the response is complete."""

    __slots__ = ("stream_id",)

    def __init__(self, stream_id):
        self.stream_id = stream_id


class StreamReset(Event):
    """RST_STREAM received (``remote=True``) or sent by the core (``remote=False``)."""

    __slots__ = ("stream_id", "error_code", "remote", "reason")

    def __init__(self, stream_id, error_code, remote, reason=None):
        self.stream_id = stream_id
        self.error_code = error_code
        self.remote = remote
        self.reason = reason


class WindowUpdated(Event):
    """The peer opened ``delta`` bytes of send window (stream 0 = connection)."""

    __slots__ = ("stream_id", "delta")

    def __init__(self, stream_id, delta):
        self.stream_id = stream_id
        self.delta = delta


class PingReceived(Event):
    __slots__ = ("data",)

    def __init__(self, data):
        self.data = data


class PingAckReceived(Event):
    __slots__ = ("data",)

    def __init__(self, data):
        self.data = data


class ConnectionTerminated(Event):
    """The peer sent GOAWAY.  Streams above ``last_stream_id`` were not processed."""

    __slots__ = ("last_stream_id", "error_code", "debug_data")

    def __init__(self, last_stream_id, error_code, debug_data):
        self.last_stream_id = last_stream_id
        self.error_code = error_code
        self.debug_data = debug_data


class PushPromiseRefused(Event):
    """A PUSH_PROMISE arrived and the promised stream was reset with REFUSED_STREAM."""

    __slots__ = ("stream_id", "promised_stream_id", "headers")

    def __init__(self, stream_id, promised_stream_id, headers):
        self.stream_id = stream_id
        self.promised_stream_id = promised_stream_id
        self.headers = headers


# --------------------------------------------------------------------------
# request fields
# --------------------------------------------------------------------------

def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    text = str(value)
    try:
        return text.encode("latin-1")
    except UnicodeEncodeError:
        return text.encode("utf-8")


def build_request_fields(spec, method, scheme, authority, path, headers):
    """The ordered HPACK field list for a request, per RFC 9113 section 8.3.

    Pseudo headers follow ``spec.pseudo_order``.  Regular header names are
    lowercased, values stripped of surrounding whitespace, connection
    specific headers dropped (``te`` is kept only as ``trailers``).  Names
    that are not tokens, pseudo headers in ``headers``, and control
    characters in values raise :class:`curl_reap.exceptions.InvalidHeader`.
    """
    method_b = _as_bytes(method).strip()
    if not method_b or any(c not in _METHOD_CHARS for c in method_b):
        raise InvalidHeader("invalid HTTP method %r" % (method,))
    scheme_b = _as_bytes(scheme).strip().lower()
    if not scheme_b:
        raise InvalidHeader("the request scheme is empty")
    authority_b = _as_bytes(authority).strip()
    if not authority_b:
        raise InvalidHeader("the request authority (host[:port]) is empty")
    path_b = _as_bytes(path).strip() or b"/"
    if any(c in (0x00, 0x0A, 0x0D, 0x20) for c in path_b):
        raise InvalidHeader("invalid characters in request path %r" % (path,))
    pseudo = {
        "m": (b":method", method_b),
        "a": (b":authority", authority_b),
        "s": (b":scheme", scheme_b),
        "p": (b":path", path_b),
    }
    fields = [pseudo[letter] for letter in spec.pseudo_order]
    for name, value in headers:
        name_b = _as_bytes(name).strip().lower()
        if not name_b:
            raise InvalidHeader("empty header name")
        if name_b.startswith(b":"):
            raise InvalidHeader("pseudo header %r is built from the request line, not headers=" % (name,))
        if any(c not in _TOKEN_CHARS for c in name_b):
            raise InvalidHeader("invalid header name %r" % (name,))
        if name_b in CONNECTION_SPECIFIC_HEADERS:
            continue
        value_b = _as_bytes(value).strip(b" \t")
        if name_b == b"te" and value_b.lower() != b"trailers":
            continue
        if any(c in (0x00, 0x0A, 0x0D) for c in value_b):
            raise InvalidHeader("control characters in the value of header %r" % (name,))
        fields.append((name_b, value_b))
    return fields


# --------------------------------------------------------------------------
# streams
# --------------------------------------------------------------------------

class Stream(object):
    """Per stream state the core tracks (client initiated streams only)."""

    __slots__ = ("stream_id", "send_window", "recv_window_max", "recv_unacked",
                 "local_closed", "remote_closed", "response_received", "reset_code",
                 "reset_by_us", "refused_by_goaway")

    def __init__(self, stream_id, send_window, recv_window_max):
        self.stream_id = stream_id
        self.send_window = send_window
        self.recv_window_max = recv_window_max
        self.recv_unacked = 0
        self.local_closed = False
        self.remote_closed = False
        self.response_received = False
        self.reset_code = None
        self.reset_by_us = False
        self.refused_by_goaway = False

    @property
    def closed(self):
        return self.reset_code is not None or (self.local_closed and self.remote_closed)

    @property
    def state(self):
        if self.reset_code is not None or (self.local_closed and self.remote_closed):
            return "closed"
        if self.local_closed:
            return "half_closed_local"
        if self.remote_closed:
            return "half_closed_remote"
        return "open"


# --------------------------------------------------------------------------
# the core
# --------------------------------------------------------------------------

class H2Core(object):
    """Sans-IO HTTP/2 client connection state (see the module docstring).

    Typical use::

        core = H2Core(spec("chrome"))
        core.initiate_connection()
        sock.sendall(core.data_to_send())
        sid = core.send_request("GET", "https", "example.com", "/", headers)
        sock.sendall(core.data_to_send())
        while True:
            for event in core.receive_data(sock.recv(65536)):
                ...
            sock.sendall(core.data_to_send())
    """

    def __init__(self, spec, *, max_header_list_size=None):
        if not isinstance(spec, H2Spec):
            raise TypeError("spec must be an H2Spec")
        self.spec = spec
        self.local_settings = dict(spec.settings)
        self.remote_settings = {
            F.SETTINGS_HEADER_TABLE_SIZE: 4096,
            F.SETTINGS_ENABLE_PUSH: 1,
            F.SETTINGS_MAX_CONCURRENT_STREAMS: None,
            F.SETTINGS_INITIAL_WINDOW_SIZE: F.DEFAULT_WINDOW_SIZE,
            F.SETTINGS_MAX_FRAME_SIZE: F.DEFAULT_MAX_FRAME_SIZE,
            F.SETTINGS_MAX_HEADER_LIST_SIZE: None,
        }
        self.encoder = HpackEncoder()
        limit = max_header_list_size or spec.max_header_list_size or _DEFAULT_MAX_HEADER_LIST_SIZE
        self.decoder = HpackDecoder(max_header_list_size=limit)
        self.decoder.max_allowed_table_size = spec.header_table_size
        self._parser = F.FrameParser(spec.max_frame_size)
        self._out = bytearray()
        self.streams = {}
        self._reset_sent = set()
        self._next_stream_id = 1
        self.send_window = F.DEFAULT_WINDOW_SIZE
        self.recv_window_max = spec.connection_window_size
        self.recv_unacked = 0
        self.stream_recv_window = spec.initial_window_size
        self.started = False
        self.closed = False
        self.failed = None
        self.settings_acked = False
        self.last_stream_id = None
        self.goaway_error_code = None
        self.goaway_debug = b""
        self._pending_block = None
        self._block_limit = limit * 4 + 4096
        self.highest_promised_stream = 0
        self.refused_pushes = set()

    # ------------------------------------------------------------------
    # state
    # ------------------------------------------------------------------

    @property
    def alive(self):
        """True while new requests can be started on this connection."""
        return (self.started and not self.closed and self.failed is None
                and self.last_stream_id is None)

    @property
    def open_stream_count(self):
        return sum(1 for s in self.streams.values() if not s.closed)

    def data_to_send(self):
        """Bytes queued for the peer; the buffer is emptied."""
        if not self._out:
            return b""
        data = bytes(self._out)
        del self._out[:]
        return data

    def _queue(self, data):
        self._out += data

    # ------------------------------------------------------------------
    # sending
    # ------------------------------------------------------------------

    def initiate_connection(self):
        """Queue the connection preface exactly as the spec's browser sends it."""
        if self.started:
            raise H2Error("connection preface already sent")
        self.started = True
        out = F.CONNECTION_PREFACE + F.pack_settings(self.spec.settings)
        if self.spec.window_update:
            out += F.pack_window_update(0, self.spec.window_update)
        for stream_id, exclusive, dependency, weight in self.spec.priority_frames:
            out += F.pack_priority(stream_id, exclusive, dependency, weight)
        self._queue(out)

    def get_next_stream_id(self):
        """The id the next request will use (odd, increasing)."""
        return self._next_stream_id

    def _check_can_open(self):
        if not self.started:
            raise H2Error("initiate_connection() has not been called")
        if self.closed:
            raise H2Error("connection closed locally", retryable=True)
        if self.failed is not None:
            raise H2Error("connection failed: %s" % self.failed, retryable=False)
        if self.last_stream_id is not None:
            raise H2Error("server sent GOAWAY (%s), no new streams on this connection"
                          % error_name(self.goaway_error_code), error_code=self.goaway_error_code or 0,
                          retryable=True)
        if self._next_stream_id > F.MAX_STREAM_ID:
            raise H2Error("stream identifiers exhausted", retryable=True)
        limit = self.remote_settings[F.SETTINGS_MAX_CONCURRENT_STREAMS]
        if limit is not None and self.open_stream_count >= limit:
            raise H2Error("server allows %d concurrent streams" % limit,
                          error_code=F.REFUSED_STREAM, retryable=True)

    def send_request(self, method, scheme, authority, path, headers, *, end_stream=True):
        """Queue the HEADERS frame(s) for a new stream and return its id.

        ``headers`` are regular ``(name, value)`` pairs in the order they
        should go on the wire.  ``end_stream=False`` keeps the stream open
        for :meth:`send_data`.
        """
        self._check_can_open()
        fields = build_request_fields(self.spec, method, scheme, authority, path, headers)
        stream_id = self._next_stream_id
        self._next_stream_id += 2
        block = self.encoder.encode(fields)
        flags = self.spec.headers_flags
        if end_stream:
            flags |= F.FLAG_END_STREAM
        else:
            flags &= ~F.FLAG_END_STREAM
        stream = Stream(stream_id, self.remote_settings[F.SETTINGS_INITIAL_WINDOW_SIZE],
                        self.stream_recv_window)
        stream.local_closed = bool(end_stream)
        self.streams[stream_id] = stream
        self._queue(F.pack_header_block(stream_id, block, flags, self.spec.headers_priority,
                                        self.remote_settings[F.SETTINGS_MAX_FRAME_SIZE]))
        return stream_id

    def _sendable_stream(self, stream_id):
        stream = self.streams.get(stream_id)
        if stream is None:
            raise H2Error("stream %d is not open" % stream_id, stream_id=stream_id,
                          error_code=F.STREAM_CLOSED)
        if stream.reset_code is not None:
            raise H2Error("stream %d was reset (%s)" % (stream_id, error_name(stream.reset_code)),
                          stream_id=stream_id, error_code=stream.reset_code,
                          retryable=stream.reset_code == F.REFUSED_STREAM and not stream.reset_by_us)
        if stream.local_closed:
            raise H2Error("stream %d already ended locally" % stream_id, stream_id=stream_id,
                          error_code=F.STREAM_CLOSED)
        return stream

    def send_window_for(self, stream_id):
        """Bytes that :meth:`send_data` could queue right now for the stream."""
        stream = self.streams.get(stream_id)
        if stream is None:
            return 0
        return max(0, min(self.send_window, stream.send_window))

    @property
    def max_data_frame_size(self):
        return self.remote_settings[F.SETTINGS_MAX_FRAME_SIZE]

    def send_data(self, stream_id, data, end_stream=False):
        """Queue at most one DATA frame and return how many bytes it carries.

        The frame is limited by the peer's max frame size, the stream window
        and the connection window; 0 means the caller must wait for a
        WINDOW_UPDATE (or a SETTINGS change) before trying again.  An empty
        ``data`` with ``end_stream=True`` queues an empty END_STREAM frame.
        """
        stream = self._sendable_stream(stream_id)
        view = memoryview(data)
        total = view.nbytes
        if total == 0:
            if end_stream:
                self._queue(F.pack_data(stream_id, b"", True))
                self._local_close(stream)
            return 0
        allowed = min(total, self.send_window, stream.send_window, self.max_data_frame_size)
        if allowed <= 0:
            return 0
        chunk = bytes(view[:allowed])
        final = bool(end_stream) and allowed == total
        self._queue(F.pack_data(stream_id, chunk, final))
        self.send_window -= allowed
        stream.send_window -= allowed
        if final:
            self._local_close(stream)
        return allowed

    def end_stream(self, stream_id):
        """Queue an empty DATA frame with END_STREAM."""
        self.send_data(stream_id, b"", end_stream=True)

    def reset_stream(self, stream_id, error_code=F.CANCEL):
        """Queue RST_STREAM for one of our streams and forget it.

        The frame is queued even when the stream was already forgotten (its
        END_STREAM arrived in the same batch as the offending DATA): the peer
        ignores a reset for a closed stream, but a multi-frame body still
        needs the cancel.
        """
        stream = self.streams.get(stream_id)
        if stream is not None:
            if stream.reset_code is not None:
                return
            stream.reset_code = error_code
            stream.reset_by_us = True
            self._forget(stream)
        elif stream_id in self._reset_sent:
            return
        self._reset_sent.add(stream_id)
        self._queue(F.pack_rst_stream(stream_id, error_code))

    def ping(self, data=None):
        """Queue a PING and return its 8 opaque bytes (to match the ACK)."""
        data = bytes(data) if data is not None else os.urandom(8)
        self._queue(F.pack_ping(data))
        return data

    def close(self, error_code=F.NO_ERROR, debug=b""):
        """Queue GOAWAY; after this ``alive`` is False."""
        if self.closed:
            return
        self.closed = True
        if self.started:
            self._queue(F.pack_goaway(self.highest_promised_stream, error_code, debug))

    def acknowledge_received_data(self, stream_id, length):
        """Tell the core ``length`` flow controlled bytes were consumed.

        WINDOW_UPDATE frames are queued once the unacknowledged amount
        exceeds half the window, on the connection and on the stream (the
        latter only while the stream is still open on the remote side).
        """
        if length <= 0:
            return
        self._consume_connection(length)
        stream = self.streams.get(stream_id)
        if stream is None or stream.remote_closed or stream.reset_code is not None:
            return
        stream.recv_unacked += length
        if stream.recv_unacked > stream.recv_window_max // 2:
            self._queue(F.pack_window_update(stream_id, stream.recv_unacked))
            stream.recv_unacked = 0

    def _consume_connection(self, length):
        self.recv_unacked += length
        if self.recv_unacked > self.recv_window_max // 2:
            self._queue(F.pack_window_update(0, self.recv_unacked))
            self.recv_unacked = 0

    def _local_close(self, stream):
        stream.local_closed = True
        if stream.remote_closed:
            self._forget(stream)

    def _remote_close(self, stream, events):
        stream.remote_closed = True
        events.append(StreamEnded(stream.stream_id))
        if stream.local_closed:
            self._forget(stream)

    def _forget(self, stream):
        self.streams.pop(stream.stream_id, None)

    # ------------------------------------------------------------------
    # receiving
    # ------------------------------------------------------------------

    def receive_data(self, data):
        """Parse ``data`` and return the events it produced.

        A connection error queues GOAWAY (collect it with
        :meth:`data_to_send`), marks the connection failed and raises
        :class:`H2Error`.
        """
        events = []
        if not data:
            return events
        if self.failed is not None:
            raise H2Error("connection failed earlier: %s" % self.failed)
        self._parser.feed(data)
        try:
            for frame in self._parser.frames():
                self._dispatch(frame, events)
        except H2Error as exc:
            self._terminate(exc.error_code, str(exc))
            raise
        return events

    def _fail(self, error_code, message):
        raise H2Error(message, error_code=error_code)

    def _terminate(self, error_code, message):
        if self.failed is None:
            self.failed = message
        if not self.closed:
            self.closed = True
            self._queue(F.pack_goaway(self.highest_promised_stream, error_code,
                                      message.encode("ascii", "replace")[:200]))

    def _dispatch(self, frame, events):
        if self._pending_block is not None:
            if frame.type != F.CONTINUATION or frame.stream_id != self._pending_block["stream_id"]:
                self._fail(F.PROTOCOL_ERROR, "expected CONTINUATION on stream %d, got %s on stream %d"
                           % (self._pending_block["stream_id"], frame.name, frame.stream_id))
            self._on_continuation(frame, events)
            return
        handler = self._HANDLERS.get(frame.type)
        if handler is None:
            return
        handler(self, frame, events)

    def _on_data(self, frame, events):
        if frame.stream_id == 0:
            self._fail(F.PROTOCOL_ERROR, "DATA frame on stream 0")
        flow_length = len(frame.payload)
        data = F.strip_padding(frame)
        stream = self.streams.get(frame.stream_id)
        if stream is None or stream.remote_closed or stream.reset_code is not None:
            self._consume_connection(flow_length)
            return
        if not stream.response_received:
            self._consume_connection(flow_length)
            self._reset(stream, F.PROTOCOL_ERROR, "DATA before the response HEADERS", events)
            return
        events.append(DataReceived(frame.stream_id, data, flow_length))
        if frame.flags & F.FLAG_END_STREAM:
            self._remote_close(stream, events)

    def _on_headers(self, frame, events):
        if frame.stream_id == 0:
            self._fail(F.PROTOCOL_ERROR, "HEADERS frame on stream 0")
        payload = F.strip_padding(frame)
        if frame.flags & F.FLAG_PRIORITY:
            F.parse_priority_field(payload)
            payload = payload[5:]
        self._pending_block = {
            "type": F.HEADERS, "stream_id": frame.stream_id,
            "end_stream": bool(frame.flags & F.FLAG_END_STREAM),
            "fragments": [payload], "size": len(payload), "promised": None,
        }
        if frame.flags & F.FLAG_END_HEADERS:
            self._finish_block(events)

    def _on_push_promise(self, frame, events):
        if frame.stream_id == 0:
            self._fail(F.PROTOCOL_ERROR, "PUSH_PROMISE frame on stream 0")
        payload = F.strip_padding(frame)
        if len(payload) < 4:
            self._fail(F.FRAME_SIZE_ERROR, "PUSH_PROMISE shorter than 4 bytes")
        promised = struct.unpack(">I", payload[:4])[0] & 0x7FFFFFFF
        if promised == 0 or promised % 2 or promised <= self.highest_promised_stream:
            self._fail(F.PROTOCOL_ERROR, "invalid promised stream id %d" % promised)
        self._pending_block = {
            "type": F.PUSH_PROMISE, "stream_id": frame.stream_id, "end_stream": False,
            "fragments": [payload[4:]], "size": len(payload) - 4, "promised": promised,
        }
        if frame.flags & F.FLAG_END_HEADERS:
            self._finish_block(events)

    def _on_continuation(self, frame, events):
        pending = self._pending_block
        if pending is None:
            self._fail(F.PROTOCOL_ERROR, "CONTINUATION without a preceding HEADERS")
        pending["fragments"].append(frame.payload)
        pending["size"] += len(frame.payload)
        if pending["size"] > self._block_limit:
            self._fail(F.ENHANCE_YOUR_CALM, "header block larger than %d bytes" % self._block_limit)
        if frame.flags & F.FLAG_END_HEADERS:
            self._finish_block(events)

    def _finish_block(self, events):
        pending = self._pending_block
        self._pending_block = None
        block = b"".join(pending["fragments"])
        try:
            fields = self.decoder.decode(block, raw=True)
        except Exception as exc:
            self._fail(F.COMPRESSION_ERROR, "HPACK decoding failed: %s" % exc)
        if pending["type"] == F.PUSH_PROMISE:
            self._refuse_push(pending, fields, events)
            return
        stream_id = pending["stream_id"]
        stream = self.streams.get(stream_id)
        if stream is None or stream.remote_closed or stream.reset_code is not None:
            return
        end_stream = pending["end_stream"]
        headers, status, problem = self._response_fields(fields, trailers=stream.response_received)
        if problem is not None:
            self._reset(stream, F.PROTOCOL_ERROR, problem, events)
            return
        if not stream.response_received:
            if 100 <= status < 200:
                if end_stream:
                    self._reset(stream, F.PROTOCOL_ERROR, "informational response with END_STREAM", events)
                elif status == 101:
                    self._reset(stream, F.PROTOCOL_ERROR, "101 Switching Protocols is not valid in HTTP/2", events)
                else:
                    events.append(InformationalResponse(stream_id, status, headers))
                return
            stream.response_received = True
            events.append(ResponseReceived(stream_id, status, headers))
        else:
            if not end_stream:
                self._reset(stream, F.PROTOCOL_ERROR, "trailers without END_STREAM", events)
                return
            events.append(TrailersReceived(stream_id, headers))
        if end_stream:
            self._remote_close(stream, events)

    @staticmethod
    def _response_fields(fields, trailers):
        """Split decoded fields into (headers, status, problem)."""
        headers = []
        status = None
        seen_regular = False
        for name, value in fields:
            if name.startswith(b":"):
                if trailers:
                    return headers, status, "pseudo header in trailers"
                if seen_regular:
                    return headers, status, "pseudo header after a regular header"
                if name != b":status" or status is not None:
                    return headers, status, "unexpected pseudo header %r" % name.decode("latin-1")
                if len(value) != 3 or not value.isdigit():
                    return headers, status, "malformed :status %r" % value.decode("latin-1")
                status = int(value)
                continue
            seen_regular = True
            if name != name.lower():
                return headers, status, "uppercase field name %r" % name.decode("latin-1")
            headers.append((name.decode("latin-1"), value.decode("latin-1")))
        if status is None and not trailers:
            return headers, status, "response without :status"
        return headers, status, None

    def _refuse_push(self, pending, fields, events):
        promised = pending["promised"]
        self.highest_promised_stream = promised
        self.refused_pushes.add(promised)
        if len(self.refused_pushes) > 256:
            self.refused_pushes = set(sorted(self.refused_pushes)[-128:])
        self._queue(F.pack_rst_stream(promised, F.REFUSED_STREAM))
        headers = [(n.decode("latin-1"), v.decode("latin-1")) for n, v in fields]
        events.append(PushPromiseRefused(pending["stream_id"], promised, headers))

    def _on_priority(self, frame, events):
        if frame.stream_id == 0:
            self._fail(F.PROTOCOL_ERROR, "PRIORITY frame on stream 0")
        if len(frame.payload) != 5:
            stream = self.streams.get(frame.stream_id)
            if stream is not None:
                self._reset(stream, F.FRAME_SIZE_ERROR, "PRIORITY frame of %d bytes" % len(frame.payload), events)

    def _on_rst_stream(self, frame, events):
        if frame.stream_id == 0:
            self._fail(F.PROTOCOL_ERROR, "RST_STREAM frame on stream 0")
        if len(frame.payload) != 4:
            self._fail(F.FRAME_SIZE_ERROR, "RST_STREAM payload of %d bytes" % len(frame.payload))
        code = struct.unpack(">I", frame.payload)[0]
        stream = self.streams.get(frame.stream_id)
        if stream is None:
            if frame.stream_id % 2 == 1 and frame.stream_id >= self._next_stream_id:
                self._fail(F.PROTOCOL_ERROR, "RST_STREAM on idle stream %d" % frame.stream_id)
            return
        stream.reset_code = code
        events.append(StreamReset(frame.stream_id, code, True, None))
        self._forget(stream)

    def _on_settings(self, frame, events):
        if frame.stream_id != 0:
            self._fail(F.PROTOCOL_ERROR, "SETTINGS frame on stream %d" % frame.stream_id)
        if frame.flags & F.FLAG_ACK:
            if frame.payload:
                self._fail(F.FRAME_SIZE_ERROR, "SETTINGS ACK with a payload")
            self.settings_acked = True
            events.append(SettingsAcknowledged())
            return
        changed = {}
        for ident, value in F.parse_settings(frame.payload):
            if ident == F.SETTINGS_HEADER_TABLE_SIZE:
                self.encoder.change_table_size(value)
            elif ident == F.SETTINGS_ENABLE_PUSH:
                if value not in (0, 1):
                    self._fail(F.PROTOCOL_ERROR, "SETTINGS_ENABLE_PUSH %d is not 0 or 1" % value)
            elif ident == F.SETTINGS_INITIAL_WINDOW_SIZE:
                if value > F.MAX_WINDOW_SIZE:
                    self._fail(F.FLOW_CONTROL_ERROR, "SETTINGS_INITIAL_WINDOW_SIZE %d too large" % value)
                delta = value - self.remote_settings[F.SETTINGS_INITIAL_WINDOW_SIZE]
                for stream in self.streams.values():
                    stream.send_window += delta
                    if stream.send_window > F.MAX_WINDOW_SIZE:
                        self._fail(F.FLOW_CONTROL_ERROR, "stream %d send window overflow" % stream.stream_id)
            elif ident == F.SETTINGS_MAX_FRAME_SIZE:
                if not F.DEFAULT_MAX_FRAME_SIZE <= value <= F.MAX_FRAME_SIZE_LIMIT:
                    self._fail(F.PROTOCOL_ERROR, "SETTINGS_MAX_FRAME_SIZE %d out of range" % value)
            elif ident not in (F.SETTINGS_MAX_CONCURRENT_STREAMS, F.SETTINGS_MAX_HEADER_LIST_SIZE):
                continue
            self.remote_settings[ident] = value
            changed[ident] = value
        self._queue(F.pack_settings((), ack=True))
        events.append(RemoteSettingsChanged(changed))

    def _on_ping(self, frame, events):
        if frame.stream_id != 0:
            self._fail(F.PROTOCOL_ERROR, "PING frame on stream %d" % frame.stream_id)
        if len(frame.payload) != 8:
            self._fail(F.FRAME_SIZE_ERROR, "PING payload of %d bytes" % len(frame.payload))
        if frame.flags & F.FLAG_ACK:
            events.append(PingAckReceived(frame.payload))
            return
        self._queue(F.pack_ping(frame.payload, ack=True))
        events.append(PingReceived(frame.payload))

    def _on_goaway(self, frame, events):
        if frame.stream_id != 0:
            self._fail(F.PROTOCOL_ERROR, "GOAWAY frame on stream %d" % frame.stream_id)
        if len(frame.payload) < 8:
            self._fail(F.FRAME_SIZE_ERROR, "GOAWAY payload of %d bytes" % len(frame.payload))
        last_stream_id = struct.unpack(">I", frame.payload[:4])[0] & 0x7FFFFFFF
        error_code = struct.unpack(">I", frame.payload[4:8])[0]
        debug = frame.payload[8:]
        if self.last_stream_id is None or last_stream_id < self.last_stream_id:
            self.last_stream_id = last_stream_id
        self.goaway_error_code = error_code
        self.goaway_debug = debug
        for stream in self.streams.values():
            if stream.stream_id > last_stream_id:
                stream.refused_by_goaway = True
        events.append(ConnectionTerminated(last_stream_id, error_code, debug))

    def _on_window_update(self, frame, events):
        if len(frame.payload) != 4:
            self._fail(F.FRAME_SIZE_ERROR, "WINDOW_UPDATE payload of %d bytes" % len(frame.payload))
        increment = struct.unpack(">I", frame.payload)[0] & 0x7FFFFFFF
        if frame.stream_id == 0:
            if increment == 0:
                self._fail(F.PROTOCOL_ERROR, "WINDOW_UPDATE with a zero increment on stream 0")
            self.send_window += increment
            if self.send_window > F.MAX_WINDOW_SIZE:
                self._fail(F.FLOW_CONTROL_ERROR, "connection send window overflow")
            events.append(WindowUpdated(0, increment))
            return
        stream = self.streams.get(frame.stream_id)
        if stream is None:
            return
        if increment == 0:
            self._reset(stream, F.PROTOCOL_ERROR, "WINDOW_UPDATE with a zero increment", events)
            return
        stream.send_window += increment
        if stream.send_window > F.MAX_WINDOW_SIZE:
            self._reset(stream, F.FLOW_CONTROL_ERROR, "stream send window overflow", events)
            return
        events.append(WindowUpdated(frame.stream_id, increment))

    def _reset(self, stream, error_code, reason, events):
        """Stream error: queue RST_STREAM, forget the stream, report it."""
        if stream.reset_code is None:
            self._queue(F.pack_rst_stream(stream.stream_id, error_code))
            stream.reset_code = error_code
            stream.reset_by_us = True
            self._forget(stream)
        events.append(StreamReset(stream.stream_id, error_code, False, reason))

    _HANDLERS = {
        F.DATA: _on_data,
        F.HEADERS: _on_headers,
        F.PRIORITY: _on_priority,
        F.RST_STREAM: _on_rst_stream,
        F.SETTINGS: _on_settings,
        F.PUSH_PROMISE: _on_push_promise,
        F.PING: _on_ping,
        F.GOAWAY: _on_goaway,
        F.WINDOW_UPDATE: _on_window_update,
        F.CONTINUATION: _on_continuation,
    }


__all__ = [
    "H2Core", "Stream", "Event", "RemoteSettingsChanged", "SettingsAcknowledged",
    "InformationalResponse", "ResponseReceived", "DataReceived", "TrailersReceived",
    "StreamEnded", "StreamReset", "WindowUpdated", "PingReceived", "PingAckReceived",
    "ConnectionTerminated", "PushPromiseRefused", "build_request_fields",
    "CONNECTION_SPECIFIC_HEADERS",
]
