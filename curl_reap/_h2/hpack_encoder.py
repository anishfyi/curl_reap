"""HPACK encoder that reproduces nghttp2's representation choices byte for byte.

curl_cffi's HTTP/2 requests are compressed by nghttp2's deflater, so the way
each header field is represented on the wire (indexed, literal with or
without indexing, never indexed, Huffman or raw strings, static or dynamic
name references) is part of what a server sees.  This encoder follows
``deflate_nv`` in nghttp2's ``lib/nghttp2_hd.c`` as verified against the
captures in ``tools/h2_templates`` and the extra curl_cffi captures taken on
2026-10-11:

* A field whose name and value match a static entry is sent as an indexed
  field (``:method GET`` 2, ``:method POST`` 3, ``:scheme https`` 7,
  ``:path /`` 4, ``:path /index.html`` 5, ``accept-encoding gzip, deflate``
  16).  Otherwise the static table supplies the name index when the name is
  in it (``:authority`` 1, ``:path`` 4, ``user-agent`` 58, ``accept`` 19,
  ``accept-encoding`` 16, ``accept-language`` 17, ``cookie`` 32,
  ``content-type`` 31, ``content-length`` 28, ``referer`` 51, and so on).
* ``:path``, ``age``, ``content-length``, ``etag``, ``if-modified-since``,
  ``if-none-match``, ``location`` and ``set-cookie`` are sent as literals
  without indexing, as is any field whose table entry size
  (name + value + 32) exceeds three quarters of the dynamic table size.
* ``authorization`` and a ``cookie`` whose value is shorter than 20 bytes
  are sent as never indexed literals (the Gecko rule nghttp2 adopted).
* Every other field is a literal with incremental indexing, and the same
  name and value on a later request becomes an indexed field pointing at
  the dynamic table.  A name-only match uses the newest dynamic entry with
  that name, unless the static table also has the name, in which case the
  static index wins.
* A string is Huffman coded only when that is strictly shorter than the raw
  form (``te`` and ``?0`` stay raw, ``none`` and ``document`` are coded).
* The dynamic table is capped at 4096 bytes (nghttp2's deflater limit) and
  shrinks further when the peer's SETTINGS_HEADER_TABLE_SIZE is lower.  A
  SETTINGS_HEADER_TABLE_SIZE from the peer makes the next header block start
  with a dynamic table size update of the resulting size, exactly like
  nghttp2 (it emits one even when the size did not change, and emits the
  lowest intermediate size first when several SETTINGS arrived).

The Huffman code and the static table come from the ``hpack`` package.
"""
from __future__ import annotations

from hpack.huffman import HuffmanEncoder
from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH
from hpack.table import HeaderTable

#: The 61 static entries from RFC 7541 appendix A as (name, value) bytes.
STATIC_TABLE = tuple(HeaderTable.STATIC_TABLE)
STATIC_TABLE_LENGTH = len(STATIC_TABLE)

_STATIC_FIRST_INDEX = {}
_STATIC_ENTRIES_BY_NAME = {}
for _index, (_name, _value) in enumerate(STATIC_TABLE, 1):
    _STATIC_FIRST_INDEX.setdefault(_name, _index)
    _STATIC_ENTRIES_BY_NAME.setdefault(_name, []).append((_index, _value))
del _index, _name, _value

#: nghttp2's NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE and the cap of its deflater.
DEFAULT_TABLE_SIZE = 4096
ENTRY_OVERHEAD = 32

WITH_INDEXING = 0
WITHOUT_INDEXING = 1
NEVER_INDEXING = 2

#: Names nghttp2 never adds to the dynamic table (hd_deflate_decide_indexing).
NO_INDEX_NAMES = frozenset((
    b":path", b"age", b"content-length", b"etag", b"if-modified-since",
    b"if-none-match", b"location", b"set-cookie",
))
#: Names nghttp2 marks never indexed (plus cookie values under 20 bytes).
NEVER_INDEX_NAMES = frozenset((b"authorization",))
SHORT_COOKIE_LIMIT = 20

_huffman = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)
_CODE_LENGTHS = REQUEST_CODES_LENGTH


def huffman_length(data):
    """Octets the Huffman coding of ``data`` would take (nghttp2_hd_huff_encode_count)."""
    bits = 0
    for byte in data:
        bits += _CODE_LENGTHS[byte]
    return (bits + 7) // 8


def encode_integer(value, prefix_bits, first_byte_flags=0):
    """RFC 7541 section 5.1 integer with ``prefix_bits`` in the first octet."""
    if value < 0:
        raise ValueError("HPACK integers are unsigned")
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes((first_byte_flags | value,))
    out = bytearray((first_byte_flags | limit,))
    value -= limit
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def encode_string(data):
    """A string literal, Huffman coded only when that is strictly shorter."""
    raw_len = len(data)
    if raw_len and huffman_length(data) < raw_len:
        coded = _huffman.encode(data)
        return encode_integer(len(coded), 7, 0x80) + coded
    return encode_integer(raw_len, 7, 0x00) + data


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    try:
        return str(value).encode("latin-1")
    except UnicodeEncodeError:
        return str(value).encode("utf-8")


def entry_size(name, value):
    return len(name) + len(value) + ENTRY_OVERHEAD


class HpackEncoder:
    """Stateful HPACK encoder for one connection (see the module docstring).

    ``max_table_size`` is the deflater cap nghttp2 is created with; curl
    keeps the default 4096 and so does curl_reap.  Call
    :meth:`change_table_size` with every SETTINGS_HEADER_TABLE_SIZE the peer
    sends.  ``encode`` takes an ordered iterable of ``(name, value)`` pairs
    (bytes or latin-1 encodable str) and returns the header block.
    """

    def __init__(self, max_table_size=DEFAULT_TABLE_SIZE):
        self._cap = int(max_table_size)
        self._table = []          # newest first; entries are (name, value)
        self._table_size = 0
        self._max_size = DEFAULT_TABLE_SIZE
        self._notify = False
        self._min_pending = None
        if self._cap < DEFAULT_TABLE_SIZE:
            self._max_size = self._cap
            self._notify = True
            self._min_pending = self._cap

    # ------------------------------------------------------------------
    # table management
    # ------------------------------------------------------------------

    @property
    def max_table_size(self):
        """The dynamic table limit currently in force."""
        return self._max_size

    @property
    def table_size(self):
        """Bytes used by the dynamic table (RFC 7541 section 4.1 accounting)."""
        return self._table_size

    @property
    def dynamic_table(self):
        """Dynamic entries newest first, as (name, value) bytes."""
        return list(self._table)

    def change_table_size(self, settings_value):
        """Apply the peer's SETTINGS_HEADER_TABLE_SIZE (nghttp2_hd_deflate_change_table_size)."""
        new_size = min(int(settings_value), self._cap)
        self._max_size = new_size
        if self._min_pending is None or new_size < self._min_pending:
            self._min_pending = new_size
        self._notify = True
        self._evict_to(new_size)

    def _evict_to(self, room_limit):
        while self._table and self._table_size > room_limit:
            name, value = self._table.pop()
            self._table_size -= entry_size(name, value)

    def _add(self, name, value):
        room = entry_size(name, value)
        self._evict_to(self._max_size - room)
        if room > self._max_size:
            return
        self._table.insert(0, (name, value))
        self._table_size += room

    # ------------------------------------------------------------------
    # encoding
    # ------------------------------------------------------------------

    def encode(self, headers):
        """Encode ``headers`` (ordered ``(name, value)`` pairs) into a block."""
        out = bytearray()
        if self._notify:
            lowest = self._min_pending
            self._notify = False
            self._min_pending = None
            if lowest is not None and self._max_size > lowest:
                out += encode_integer(lowest, 5, 0x20)
            out += encode_integer(self._max_size, 5, 0x20)
        for name, value in headers:
            self._encode_field(out, _as_bytes(name), _as_bytes(value))
        return bytes(out)

    def indexing_mode(self, name, value):
        """nghttp2's decision for a field: WITH_, WITHOUT_ or NEVER_INDEXING."""
        if name in NEVER_INDEX_NAMES or (name == b"cookie" and len(value) < SHORT_COOKIE_LIMIT):
            return NEVER_INDEXING
        if name in NO_INDEX_NAMES or entry_size(name, value) > self._max_size * 3 // 4:
            return WITHOUT_INDEXING
        return WITH_INDEXING

    def search(self, name, value, mode):
        """Return (index, exact) following nghttp2's search_hd_table.

        ``index`` is a 1-based HPACK index or None.  ``exact`` is True when
        both name and value matched, so the field can be sent as indexed.
        """
        name_only = mode == NEVER_INDEXING
        static_index = _STATIC_FIRST_INDEX.get(name)
        if static_index is not None and not name_only:
            for index, static_value in _STATIC_ENTRIES_BY_NAME[name]:
                if static_value == value:
                    return index, True
        found = None
        exact = False
        for position, (entry_name, entry_value) in enumerate(self._table):
            if entry_name != name:
                continue
            if found is None:
                found = position
            if not name_only and entry_value == value:
                found = position
                exact = True
                break
        if found is None:
            return static_index, False
        if static_index is not None and not exact:
            return static_index, False
        return STATIC_TABLE_LENGTH + 1 + found, exact

    def _encode_field(self, out, name, value):
        mode = self.indexing_mode(name, value)
        index, exact = self.search(name, value, mode)
        if exact:
            out += encode_integer(index, 7, 0x80)
            return
        if mode == WITH_INDEXING:
            self._add(name, value)
            prefix_bits, flag = 6, 0x40
        elif mode == WITHOUT_INDEXING:
            prefix_bits, flag = 4, 0x00
        else:
            prefix_bits, flag = 4, 0x10
        if index is not None:
            out += encode_integer(index, prefix_bits, flag)
        else:
            out += encode_integer(0, prefix_bits, flag)
            out += encode_string(name)
        out += encode_string(value)


__all__ = [
    "HpackEncoder", "STATIC_TABLE", "STATIC_TABLE_LENGTH", "DEFAULT_TABLE_SIZE",
    "ENTRY_OVERHEAD", "WITH_INDEXING", "WITHOUT_INDEXING", "NEVER_INDEXING",
    "NO_INDEX_NAMES", "NEVER_INDEX_NAMES", "SHORT_COOKIE_LIMIT",
    "huffman_length", "encode_integer", "encode_string", "entry_size",
]
