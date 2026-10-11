"""RFC 9113 frame codec: constants, frame builders and an incremental parser.

Everything here is a pure function of bytes.  Builders return the frame
header plus payload; :class:`FrameParser` splits a byte stream into
:class:`Frame` records and enforces the receive side frame size limit.
Padding and the HEADERS priority field are handled by small helpers so the
connection core can stay readable.
"""
from __future__ import annotations

import struct
from typing import NamedTuple

from .errors import H2Error

# Frame types (RFC 9113 section 6).
DATA = 0x0
HEADERS = 0x1
PRIORITY = 0x2
RST_STREAM = 0x3
SETTINGS = 0x4
PUSH_PROMISE = 0x5
PING = 0x6
GOAWAY = 0x7
WINDOW_UPDATE = 0x8
CONTINUATION = 0x9

FRAME_NAMES = {
    DATA: "DATA", HEADERS: "HEADERS", PRIORITY: "PRIORITY",
    RST_STREAM: "RST_STREAM", SETTINGS: "SETTINGS", PUSH_PROMISE: "PUSH_PROMISE",
    PING: "PING", GOAWAY: "GOAWAY", WINDOW_UPDATE: "WINDOW_UPDATE",
    CONTINUATION: "CONTINUATION",
}

# Flags.
FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

# Error codes (RFC 9113 section 7).
NO_ERROR = 0x0
PROTOCOL_ERROR = 0x1
INTERNAL_ERROR = 0x2
FLOW_CONTROL_ERROR = 0x3
SETTINGS_TIMEOUT = 0x4
STREAM_CLOSED = 0x5
FRAME_SIZE_ERROR = 0x6
REFUSED_STREAM = 0x7
CANCEL = 0x8
COMPRESSION_ERROR = 0x9
CONNECT_ERROR = 0xA
ENHANCE_YOUR_CALM = 0xB
INADEQUATE_SECURITY = 0xC
HTTP_1_1_REQUIRED = 0xD

# Settings identifiers (RFC 9113 section 6.5.2, RFC 8441, RFC 9218).
SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_ENABLE_PUSH = 0x2
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5
SETTINGS_MAX_HEADER_LIST_SIZE = 0x6
SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x8
SETTINGS_NO_RFC7540_PRIORITIES = 0x9

SETTINGS_NAMES = {
    SETTINGS_HEADER_TABLE_SIZE: "HEADER_TABLE_SIZE",
    SETTINGS_ENABLE_PUSH: "ENABLE_PUSH",
    SETTINGS_MAX_CONCURRENT_STREAMS: "MAX_CONCURRENT_STREAMS",
    SETTINGS_INITIAL_WINDOW_SIZE: "INITIAL_WINDOW_SIZE",
    SETTINGS_MAX_FRAME_SIZE: "MAX_FRAME_SIZE",
    SETTINGS_MAX_HEADER_LIST_SIZE: "MAX_HEADER_LIST_SIZE",
    SETTINGS_ENABLE_CONNECT_PROTOCOL: "ENABLE_CONNECT_PROTOCOL",
    SETTINGS_NO_RFC7540_PRIORITIES: "NO_RFC7540_PRIORITIES",
}

CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DEFAULT_MAX_FRAME_SIZE = 16384
MAX_FRAME_SIZE_LIMIT = (1 << 24) - 1
DEFAULT_WINDOW_SIZE = 65535
MAX_WINDOW_SIZE = (1 << 31) - 1
MAX_STREAM_ID = (1 << 31) - 1
FRAME_HEADER_LENGTH = 9

_HEADER = struct.Struct(">I")


class Frame(NamedTuple):
    """One parsed frame.  ``payload`` is the raw payload including padding."""

    type: int
    flags: int
    stream_id: int
    payload: bytes

    @property
    def name(self):
        return FRAME_NAMES.get(self.type, "UNKNOWN_0x%x" % self.type)


# --------------------------------------------------------------------------
# builders
# --------------------------------------------------------------------------

def pack_frame(ftype, flags, stream_id, payload=b""):
    """Serialise a frame header followed by ``payload``."""
    length = len(payload)
    if length > MAX_FRAME_SIZE_LIMIT:
        raise ValueError("frame payload too large: %d" % length)
    return (_HEADER.pack(length)[1:] + bytes((ftype & 0xFF, flags & 0xFF))
            + _HEADER.pack(stream_id & 0x7FFFFFFF) + bytes(payload))


def _pad(payload, pad_length):
    if pad_length is None:
        return payload, 0
    if not 0 <= pad_length <= 255:
        raise ValueError("pad length must be 0..255")
    return bytes((pad_length,)) + payload + b"\x00" * pad_length, FLAG_PADDED


def pack_data(stream_id, data, end_stream=False, pad_length=None):
    payload, flags = _pad(bytes(data), pad_length)
    if end_stream:
        flags |= FLAG_END_STREAM
    return pack_frame(DATA, flags, stream_id, payload)


def pack_priority_field(exclusive, dependency, weight):
    """Encode the 5 byte priority field: E bit, 31 bit dependency, weight - 1."""
    if not 1 <= weight <= 256:
        raise ValueError("priority weight must be 1..256")
    dep = (dependency & 0x7FFFFFFF) | (0x80000000 if exclusive else 0)
    return _HEADER.pack(dep) + bytes((weight - 1,))


def pack_headers(stream_id, block, flags, priority=None, pad_length=None):
    """One HEADERS frame.  ``flags`` carries END_STREAM/END_HEADERS/PRIORITY
    as the caller wants them; the priority field is written when the
    PRIORITY bit is set (``priority`` is (exclusive, dependency, weight))."""
    body = bytes(block)
    if flags & FLAG_PRIORITY:
        if priority is None:
            raise ValueError("PRIORITY flag needs a priority tuple")
        body = pack_priority_field(*priority) + body
    elif priority is not None:
        raise ValueError("priority tuple given without the PRIORITY flag")
    payload, padded = _pad(body, pad_length)
    return pack_frame(HEADERS, (flags | padded) & 0xFF, stream_id, payload)


def pack_header_block(stream_id, block, flags, priority, max_frame_size,
                      pad_length=None):
    """HEADERS plus CONTINUATION frames for a block of any size.

    The caller's ``flags`` describe the whole block; END_HEADERS is set on
    the last frame only, END_STREAM and PRIORITY only on the first.
    """
    block = bytes(block)
    overhead = (5 if flags & FLAG_PRIORITY else 0) + (1 + pad_length if pad_length is not None else 0)
    room = max_frame_size - overhead
    if room < 1:
        raise ValueError("max frame size too small for the HEADERS overhead")
    first, rest = block[:room], block[room:]
    first_flags = flags & ~FLAG_END_HEADERS
    if not rest:
        first_flags = flags | FLAG_END_HEADERS
    out = pack_headers(stream_id, first, first_flags, priority, pad_length)
    while rest:
        piece, rest = rest[:max_frame_size], rest[max_frame_size:]
        out += pack_frame(CONTINUATION, FLAG_END_HEADERS if not rest else 0, stream_id, piece)
    return out


def pack_priority(stream_id, exclusive, dependency, weight):
    return pack_frame(PRIORITY, 0, stream_id, pack_priority_field(exclusive, dependency, weight))


def pack_rst_stream(stream_id, error_code):
    return pack_frame(RST_STREAM, 0, stream_id, _HEADER.pack(error_code))


def pack_settings(pairs, ack=False):
    if ack:
        if pairs:
            raise ValueError("a SETTINGS ACK carries no values")
        return pack_frame(SETTINGS, FLAG_ACK, 0, b"")
    payload = b"".join(struct.pack(">HI", int(ident), int(value)) for ident, value in pairs)
    return pack_frame(SETTINGS, 0, 0, payload)


def pack_ping(data, ack=False):
    data = bytes(data)
    if len(data) != 8:
        raise ValueError("PING carries exactly 8 bytes")
    return pack_frame(PING, FLAG_ACK if ack else 0, 0, data)


def pack_goaway(last_stream_id, error_code=NO_ERROR, debug=b""):
    return pack_frame(GOAWAY, 0, 0, _HEADER.pack(last_stream_id & 0x7FFFFFFF)
                      + _HEADER.pack(error_code) + bytes(debug))


def pack_window_update(stream_id, increment):
    if not 1 <= increment <= MAX_WINDOW_SIZE:
        raise ValueError("WINDOW_UPDATE increment must be 1..2^31-1")
    return pack_frame(WINDOW_UPDATE, 0, stream_id, _HEADER.pack(increment))


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

class FrameParser:
    """Accumulate bytes and yield complete frames.

    ``max_frame_size`` is the local SETTINGS_MAX_FRAME_SIZE; a longer frame
    raises :class:`H2Error` with FRAME_SIZE_ERROR (the caller turns it into a
    connection error).  The parser does not understand the connection
    preface; clients never receive one.
    """

    def __init__(self, max_frame_size=DEFAULT_MAX_FRAME_SIZE):
        self.max_frame_size = max_frame_size
        self._buf = bytearray()

    def feed(self, data):
        self._buf += data

    @property
    def buffered(self):
        return len(self._buf)

    def frames(self):
        """Yield every complete frame in the buffer, consuming it."""
        buf = self._buf
        pos = 0
        total = len(buf)
        try:
            while total - pos >= FRAME_HEADER_LENGTH:
                length = (buf[pos] << 16) | (buf[pos + 1] << 8) | buf[pos + 2]
                if length > self.max_frame_size:
                    raise H2Error("frame of %d bytes exceeds SETTINGS_MAX_FRAME_SIZE %d"
                                  % (length, self.max_frame_size), error_code=FRAME_SIZE_ERROR)
                if total - pos - FRAME_HEADER_LENGTH < length:
                    break
                ftype = buf[pos + 3]
                flags = buf[pos + 4]
                stream_id = _HEADER.unpack_from(buf, pos + 5)[0] & 0x7FFFFFFF
                start = pos + FRAME_HEADER_LENGTH
                payload = bytes(buf[start:start + length])
                pos = start + length
                yield Frame(ftype, flags, stream_id, payload)
        finally:
            del buf[:pos]


def strip_padding(frame):
    """Return the payload without padding for DATA, HEADERS and PUSH_PROMISE."""
    payload = frame.payload
    if not frame.flags & FLAG_PADDED:
        return payload
    if not payload:
        raise H2Error("PADDED frame without a pad length", error_code=PROTOCOL_ERROR)
    pad = payload[0]
    if pad >= len(payload):
        raise H2Error("padding of %d bytes exceeds the %d byte payload" % (pad, len(payload)),
                      error_code=PROTOCOL_ERROR)
    return payload[1:len(payload) - pad]


def parse_priority_field(data):
    """Decode (exclusive, dependency, weight) from a 5 byte priority field."""
    if len(data) < 5:
        raise H2Error("priority field needs 5 bytes", error_code=FRAME_SIZE_ERROR)
    dep = _HEADER.unpack_from(data)[0]
    return bool(dep & 0x80000000), dep & 0x7FFFFFFF, data[4] + 1


def parse_settings(payload):
    """Decode SETTINGS pairs in wire order."""
    if len(payload) % 6:
        raise H2Error("SETTINGS payload of %d bytes is not a multiple of 6" % len(payload),
                      error_code=FRAME_SIZE_ERROR)
    return [struct.unpack_from(">HI", payload, i) for i in range(0, len(payload), 6)]


__all__ = [name for name in dir()
           if not name.startswith("_") and (name.isupper() or name.startswith(("pack_", "parse_")))] + [
    "Frame", "FrameParser", "strip_padding",
]
