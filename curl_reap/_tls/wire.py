"""Byte packing and parsing helpers in the RFC 8446 presentation language."""
from __future__ import annotations

import struct
from typing import Iterator, List, Optional, Sequence, Tuple


class DecodeError(ValueError):
    """Raised when a peer message is malformed. Maps to the decode_error alert."""


class Reader:
    """Cursor over a bytes object with length-prefixed vector helpers."""

    __slots__ = ("data", "pos", "end")

    def __init__(self, data: bytes, pos: int = 0, end: Optional[int] = None):
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else end

    @property
    def remaining(self) -> int:
        return self.end - self.pos

    def at_end(self) -> bool:
        return self.pos >= self.end

    def expect_end(self, what: str = "message") -> None:
        if self.pos != self.end:
            raise DecodeError("%s: %d trailing bytes" % (what, self.end - self.pos))

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise DecodeError("short read: wanted %d, have %d" % (n, self.remaining))
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return bytes(out)

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        b = self.take(2)
        return (b[0] << 8) | b[1]

    def u24(self) -> int:
        b = self.take(3)
        return (b[0] << 16) | (b[1] << 8) | b[2]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def _length(self, size_len: int) -> int:
        if size_len == 1:
            return self.u8()
        if size_len == 2:
            return self.u16()
        if size_len == 3:
            return self.u24()
        raise ValueError("size_len must be 1, 2 or 3")

    def vec(self, size_len: int) -> bytes:
        """Read a length-prefixed opaque vector and return its bytes."""
        return self.take(self._length(size_len))

    def sub(self, size_len: int) -> "Reader":
        """Read a length-prefixed vector and return a Reader over it."""
        n = self._length(size_len)
        if self.pos + n > self.end:
            raise DecodeError("vector length %d exceeds remaining %d" % (n, self.remaining))
        r = Reader(self.data, self.pos, self.pos + n)
        self.pos += n
        return r

    def u16_list(self, size_len: int = 2) -> List[int]:
        r = self.sub(size_len)
        if r.remaining % 2:
            raise DecodeError("odd length u16 list")
        return [r.u16() for _ in range(r.remaining // 2)]

    def extensions(self) -> Iterator[Tuple[int, bytes]]:
        """Iterate (type, body) over an Extension<..> vector with u16 length."""
        r = self.sub(2)
        while not r.at_end():
            ext_type = r.u16()
            body = r.vec(2)
            yield ext_type, body


def u8(v: int) -> bytes:
    return bytes((v,))


def u16(v: int) -> bytes:
    return bytes(((v >> 8) & 0xFF, v & 0xFF))


def u24(v: int) -> bytes:
    return bytes(((v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF))


def u32(v: int) -> bytes:
    return struct.pack(">I", v)


def vec8(b: bytes) -> bytes:
    if len(b) > 0xFF:
        raise ValueError("vec8 too long")
    return u8(len(b)) + b


def vec16(b: bytes) -> bytes:
    if len(b) > 0xFFFF:
        raise ValueError("vec16 too long")
    return u16(len(b)) + b


def vec24(b: bytes) -> bytes:
    if len(b) > 0xFFFFFF:
        raise ValueError("vec24 too long")
    return u24(len(b)) + b


def u16_list(values: Sequence[int], size_len: int = 2) -> bytes:
    body = b"".join(u16(v) for v in values)
    return vec8(body) if size_len == 1 else vec16(body)


def extension(ext_type: int, body: bytes) -> bytes:
    return u16(ext_type) + vec16(body)


def handshake(msg_type: int, body: bytes) -> bytes:
    return u8(msg_type) + vec24(body)


def record_header(content_type: int, version: int, length: int) -> bytes:
    return bytes((content_type,)) + u16(version) + u16(length)


def alpn_list(protocols: Sequence[str]) -> bytes:
    """ProtocolNameList: u16 length then u8-prefixed names (ALPN and ALPS)."""
    return vec16(b"".join(vec8(p.encode("ascii")) for p in protocols))
