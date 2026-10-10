"""Ordered, case-insensitive, multi-value HTTP headers.

:class:`Headers` is the one header type curl_reap uses for requests,
responses, trailers and session defaults.  It behaves like
``the reference client.requests.Headers`` (itself the httpx multi-dict): duplicate
names are kept in order and retrievable with :meth:`Headers.get_list`,
``headers[name]`` joins duplicates with ``", "``, assignment replaces every
occurrence, and every lookup is case-insensitive through a lowercase index,
so membership and ``get`` are O(1) instead of the linear scan the 1.x
``CaseInsensitiveHeaders`` performed.

The class subclasses ``dict`` so ``json.dumps(headers)``, ``dict(headers)``
and ``isinstance(headers, dict)`` keep working for the cache, the renderer
and user code written against 1.x.  The dict storage mirrors the joined
single-value view (first seen casing of each name); the multi-value list is
kept alongside and every mutator keeps the two in step.

``None`` values are allowed in request headers: they are markers meaning
"remove this header" when merged over a profile or session set, and are
never sent on the wire.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Iterable, Iterator, List, Optional, Tuple

_SENSITIVE = frozenset({"authorization", "proxy-authorization"})


def _to_str(value, encoding="latin-1"):
    if isinstance(value, bytes):
        try:
            return value.decode("ascii")
        except UnicodeDecodeError:
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return value.decode("latin-1")
    if isinstance(value, bytearray):
        return _to_str(bytes(value), encoding)
    return value


def _check_name(name):
    name = _to_str(name)
    if not isinstance(name, str):
        name = str(name)
    if not name or ":" in name or "\r" in name or "\n" in name or " " in name:
        raise ValueError("invalid HTTP header name %r" % (name,))
    return name


def _check_value(name, value):
    if value is None:
        return None
    value = _to_str(value)
    if not isinstance(value, str):
        value = str(value)
    if "\r" in value or "\n" in value:
        raise ValueError("invalid newline in HTTP header %s" % name)
    return value


def _split_lines(block):
    """Split a raw header block (str or bytes) into (name, value) pairs."""
    if isinstance(block, (bytes, bytearray)):
        text = bytes(block).decode("latin-1")
    else:
        text = block
    pairs = []
    previous = None
    for raw_line in text.replace("\r\n", "\n").split("\n"):
        line = raw_line.rstrip("\r")
        if not line.strip():
            continue
        if line[:1] in (" ", "\t") and previous is not None:
            name, value = pairs[-1]
            pairs[-1] = (name, value + " " + line.strip())
            continue
        if ":" not in line:
            if line.upper().startswith("HTTP/") and previous is None:
                continue  # a status line at the top of a raw head
            raise ValueError("invalid header line %r" % line)
        name, value = line.split(":", 1)
        name = name.strip()
        pairs.append((name, value.strip()))
        previous = name
    return pairs


def header_pairs(headers) -> List[Tuple[str, Optional[str]]]:
    """Normalise any accepted header input into validated (name, value) pairs.

    Accepts ``Headers``, a mapping (str or bytes keys, values may be None),
    a sequence of (name, value) pairs, a sequence of ``"Name: value"`` lines
    (str or bytes) or a raw header block as one str or bytes.
    """
    if headers is None:
        return []
    if isinstance(headers, Headers):
        return headers.multi_items(include_none=True)
    if isinstance(headers, (str, bytes, bytearray)):
        return [(_check_name(n), _check_value(n, v)) for n, v in _split_lines(headers)]
    if isinstance(headers, Mapping):
        source = headers.items()
    else:
        source = headers
    items = []
    for item in source:
        if isinstance(item, (str, bytes, bytearray)):
            for name, value in _split_lines(item):
                items.append((_check_name(name), _check_value(name, value)))
            continue
        try:
            name, value = item
        except (TypeError, ValueError):
            raise TypeError("headers must be a mapping, a sequence of (name, value) "
                            "pairs or 'Name: value' lines")
        name = _check_name(name)
        items.append((name, _check_value(name, value)))
    return items


class Headers(dict):
    """Case-insensitive, order-preserving, multi-value header mapping."""

    __slots__ = ("_list", "_index", "_canon", "_encoding")

    def __init__(self, headers=None, encoding=None):
        dict.__init__(self)
        self._list: List[Tuple[str, str, Optional[str]]] = []
        self._index: dict = {}
        self._canon: dict = {}
        self._encoding = encoding
        if headers is not None:
            if isinstance(headers, Headers):
                for name, value in headers.multi_items(include_none=True):
                    self._append(name, value)
            else:
                for name, value in header_pairs(headers):
                    self._append(name, value)

    # ---------------------------------------------------------------- internals
    def _append(self, name, value):
        lower = name.lower()
        positions = self._index.get(lower)
        self._list.append((name, lower, value))
        if positions is None:
            self._index[lower] = [len(self._list) - 1]
            self._canon[lower] = name
            dict.__setitem__(self, name, value)
        else:
            positions.append(len(self._list) - 1)
            dict.__setitem__(self, self._canon[lower], self._joined(lower))

    def _joined(self, lower):
        positions = self._index[lower]
        if len(positions) == 1:
            return self._list[positions[0]][2]
        values = [self._list[i][2] for i in positions if self._list[i][2] is not None]
        if not values:
            return None
        return ", ".join(values)

    def _rebuild(self):
        self._index = {}
        self._canon = {}
        dict.clear(self)
        for position, (name, lower, value) in enumerate(self._list):
            positions = self._index.get(lower)
            if positions is None:
                self._index[lower] = [position]
                self._canon[lower] = name
            else:
                positions.append(position)
        for lower in self._index:
            dict.__setitem__(self, self._canon[lower], self._joined(lower))

    @staticmethod
    def _lower(key):
        if isinstance(key, bytes):
            key = key.decode("latin-1")
        return str(key).lower()

    # ------------------------------------------------------------------ reads
    def __getitem__(self, key):
        lower = self._lower(key)
        if lower not in self._index:
            raise KeyError(key)
        return self._joined(lower)

    def get(self, key, default=None):
        lower = self._lower(key)
        if lower not in self._index:
            return default
        return self._joined(lower)

    def __contains__(self, key):
        try:
            return self._lower(key) in self._index
        except (AttributeError, TypeError):
            return False

    def get_list(self, key, split_commas=False) -> List[str]:
        """Every value sent under ``key`` in order (never joined).

        ``split_commas=True`` additionally splits each value on commas, which
        is right for list-valued headers such as ``Vary`` and wrong for
        ``Set-Cookie`` (whose ``Expires`` dates contain commas).
        """
        lower = self._lower(key)
        positions = self._index.get(lower)
        if not positions:
            return []
        values = [self._list[i][2] for i in positions if self._list[i][2] is not None]
        if not split_commas:
            return values
        out = []
        for value in values:
            out.extend(part.strip() for part in value.split(",") if part.strip())
        return out

    def multi_items(self, include_none=False) -> List[Tuple[str, str]]:
        """Every (name, value) pair in wire order, duplicates preserved."""
        if include_none:
            return [(name, value) for name, unused, value in self._list]
        return [(name, value) for name, unused, value in self._list if value is not None]

    def raw(self) -> List[Tuple[bytes, bytes]]:
        """Wire form: latin-1 encoded (name, value) pairs, ``None`` values dropped."""
        out = []
        for name, unused, value in self._list:
            if value is None:
                continue
            try:
                out.append((name.encode("ascii"), value.encode("latin-1")))
            except UnicodeEncodeError:
                out.append((name.encode("ascii"), value.encode("utf-8")))
        return out

    @property
    def encoding(self):
        return self._encoding or "latin-1"

    def keys(self):
        return dict.keys(self)

    def values(self):
        return dict.values(self)

    def items(self):
        return dict.items(self)

    def __iter__(self) -> Iterator[str]:
        return dict.__iter__(self)

    def __len__(self):
        return dict.__len__(self)

    def copy(self):
        return Headers(self)

    __copy__ = copy

    def __deepcopy__(self, memo):
        return Headers(self)

    def __reduce__(self):
        return (Headers, (self.multi_items(include_none=True),))

    def __eq__(self, other):
        if isinstance(other, Headers):
            mine = sorted((lower, value) for unused, lower, value in self._list)
            theirs = sorted((lower, value) for unused, lower, value in other._list)
            return mine == theirs
        if isinstance(other, Mapping):
            try:
                other = Headers(other)
            except (TypeError, ValueError):
                return False
            return self == other
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    __hash__ = None

    def __repr__(self):
        shown = []
        for name, lower, value in self._list:
            if lower in _SENSITIVE and value is not None:
                value = "[secure]"
            shown.append((name, value))
        return "Headers(%r)" % (shown,)

    # ----------------------------------------------------------------- writes
    def __setitem__(self, key, value):
        name = _check_name(key)
        value = _check_value(name, value)
        lower = name.lower()
        positions = self._index.get(lower)
        if positions is None:
            self._append(name, value)
            return
        first = positions[0]
        self._list[first] = (self._list[first][0], lower, value)
        if len(positions) > 1:
            drop = set(positions[1:])
            self._list = [item for i, item in enumerate(self._list) if i not in drop]
            self._rebuild()
        else:
            dict.__setitem__(self, self._canon[lower], value)

    def add(self, key, value):
        """Append a value without replacing existing ones with the same name."""
        name = _check_name(key)
        self._append(name, _check_value(name, value))

    def __delitem__(self, key):
        lower = self._lower(key)
        if lower not in self._index:
            raise KeyError(key)
        self._list = [item for item in self._list if item[1] != lower]
        self._rebuild()

    def pop(self, key, *default):
        lower = self._lower(key)
        if lower not in self._index:
            if default:
                return default[0]
            raise KeyError(key)
        value = self._joined(lower)
        del self[key]
        return value

    def popitem(self):
        if not self._list:
            raise KeyError("popitem(): headers are empty")
        name = self._list[-1][0]
        value = self[name]
        del self[name]
        return name, value

    def setdefault(self, key, default=None):
        lower = self._lower(key)
        if lower in self._index:
            return self._joined(lower)
        self[key] = default
        return default

    def update(self, headers=None, **kwargs):
        """Replace by name (case-insensitive); position of existing names kept."""
        pairs = header_pairs(headers) if headers is not None else []
        if kwargs:
            pairs.extend((k, v) for k, v in kwargs.items())
        seen = set()
        for name, value in pairs:
            lower = name.lower()
            if lower in seen:
                self.add(name, value)
            else:
                seen.add(lower)
                self[name] = value

    def clear(self):
        self._list = []
        self._rebuild()

    # ---------------------------------------------------------------- helpers
    def merge(self, *sources) -> "Headers":
        """A new Headers: ``self`` then each source applied with last-wins
        replacement by name; ``None`` values remove the name entirely."""
        merged = Headers(self)
        for source in sources:
            for name, value in header_pairs(source):
                if value is None:
                    merged.pop(name, None)
                else:
                    merged[name] = value
        return merged


CaseInsensitiveHeaders = Headers


def merge_header_pairs(*sources, validated=False) -> List[Tuple[str, Optional[str]]]:
    """Case-insensitive last-wins merge of header sources keeping position.

    ``None`` markers remove an earlier entry and are carried through in the
    output so a later merge (for example the profile headers) still sees
    them; the wire renderer drops them.  ``validated=True`` skips the
    per-item validation for sources already produced by :func:`header_pairs`.
    """
    merged: List[Tuple[str, Optional[str]]] = []
    positions = {}
    for source in sources:
        if not source:
            continue
        items = source if validated else header_pairs(source)
        for name, value in items:
            lower = name.lower()
            at = positions.get(lower)
            if at is None:
                positions[lower] = len(merged)
                merged.append((name, value))
            else:
                merged[at] = (merged[at][0] if value is not None else name, value)
    return merged


__all__ = ["Headers", "CaseInsensitiveHeaders", "header_pairs", "merge_header_pairs"]
