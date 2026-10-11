"""``H2Spec``: what a browser sends on an HTTP/2 connection before and with its first request.

A spec is built from the captures in ``tools/h2_templates`` (see
``templates_data.py``) or parsed from an Akamai fingerprint string, and
drives the connection core: SETTINGS pairs in wire order, the stream 0
WINDOW_UPDATE increment, PRIORITY frames, the HEADERS frame flags and
priority field, and the pseudo header order.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from .frames import (
    DEFAULT_MAX_FRAME_SIZE, DEFAULT_WINDOW_SIZE, FLAG_END_HEADERS, FLAG_END_STREAM,
    FLAG_PRIORITY, SETTINGS_ENABLE_PUSH, SETTINGS_HEADER_TABLE_SIZE,
    SETTINGS_INITIAL_WINDOW_SIZE, SETTINGS_MAX_CONCURRENT_STREAMS,
    SETTINGS_MAX_FRAME_SIZE, SETTINGS_MAX_HEADER_LIST_SIZE,
)
from .hpack_encoder import DEFAULT_TABLE_SIZE

PSEUDO_NAMES = {"m": ":method", "a": ":authority", "s": ":scheme", "p": ":path"}
PSEUDO_ORDERS = ("masp", "mpas", "msap", "mspa", "maps", "mpsa")

#: HEADERS flags a browser uses for a request without a body.
DEFAULT_HEADERS_FLAGS = FLAG_END_STREAM | FLAG_END_HEADERS | FLAG_PRIORITY


def _normalise_pseudo_order(value):
    if isinstance(value, (list, tuple)):
        value = "".join(PSEUDO_NAMES.get(v, v) if len(v) == 1 else
                        {name: letter for letter, name in PSEUDO_NAMES.items()}[v]
                        for v in value)
    value = value.replace(",", "").replace(" ", "").lower()
    if sorted(value) != ["a", "m", "p", "s"]:
        raise ValueError("pseudo header order %r must be a permutation of m, a, s, p" % (value,))
    return value


@dataclass(frozen=True)
class H2Spec:
    """One browser's HTTP/2 connection and first request shape.

    ``settings`` are ``(identifier, value)`` pairs in the order the browser
    sends them.  ``window_update`` is the increment on stream 0 right after
    SETTINGS (0 means no frame).  ``priority_frames`` are
    ``(stream_id, exclusive, dependency, weight)`` PRIORITY frames sent
    before the first HEADERS.  ``headers_flags`` are the HEADERS frame flags
    for a request without a body and ``headers_priority`` the
    ``(exclusive, dependency, weight)`` field when the PRIORITY flag is set.
    ``pseudo_order`` is a four letter string (``masp`` for Chrome).
    """

    name: str
    settings: Tuple[Tuple[int, int], ...]
    window_update: int
    priority_frames: Tuple[Tuple[int, bool, int, int], ...]
    headers_flags: int
    headers_priority: Optional[Tuple[bool, int, int]]
    pseudo_order: str

    def __post_init__(self):
        object.__setattr__(self, "settings", tuple((int(i), int(v)) for i, v in self.settings))
        object.__setattr__(self, "priority_frames", tuple(
            (int(s), bool(e), int(d), int(w)) for s, e, d, w in self.priority_frames))
        object.__setattr__(self, "pseudo_order", _normalise_pseudo_order(self.pseudo_order))
        if self.headers_priority is not None:
            exclusive, dependency, weight = self.headers_priority
            object.__setattr__(self, "headers_priority", (bool(exclusive), int(dependency), int(weight)))
            if not 1 <= int(weight) <= 256:
                raise ValueError("HEADERS priority weight must be 1..256")
        if bool(self.headers_flags & FLAG_PRIORITY) != (self.headers_priority is not None):
            raise ValueError("headers_flags PRIORITY bit and headers_priority must agree")
        if self.window_update < 0 or self.window_update > (1 << 31) - 1:
            raise ValueError("window_update must be 0..2^31-1")

    # Settings as the engine needs them (local values we advertise).

    def setting(self, identifier, default=None):
        for ident, value in self.settings:
            if ident == identifier:
                return value
        return default

    @property
    def header_table_size(self):
        """What we let the server's encoder use (SETTINGS_HEADER_TABLE_SIZE)."""
        return self.setting(SETTINGS_HEADER_TABLE_SIZE, DEFAULT_TABLE_SIZE)

    @property
    def enable_push(self):
        return self.setting(SETTINGS_ENABLE_PUSH, 1)

    @property
    def max_concurrent_streams(self):
        return self.setting(SETTINGS_MAX_CONCURRENT_STREAMS, None)

    @property
    def initial_window_size(self):
        """Our per stream receive window."""
        return self.setting(SETTINGS_INITIAL_WINDOW_SIZE, DEFAULT_WINDOW_SIZE)

    @property
    def max_frame_size(self):
        """The largest frame we accept."""
        return self.setting(SETTINGS_MAX_FRAME_SIZE, DEFAULT_MAX_FRAME_SIZE)

    @property
    def max_header_list_size(self):
        return self.setting(SETTINGS_MAX_HEADER_LIST_SIZE, None)

    @property
    def connection_window_size(self):
        """Our connection receive window once the WINDOW_UPDATE is sent."""
        return DEFAULT_WINDOW_SIZE + self.window_update

    @property
    def pseudo_header_names(self):
        return tuple(PSEUDO_NAMES[letter] for letter in self.pseudo_order)

    @property
    def akamai(self):
        return akamai_string(self)


def _from_entry(name, entry):
    priority = entry.get("headers_priority")
    return H2Spec(
        name=name,
        settings=tuple((int(i), int(v)) for i, v in entry["settings"]),
        window_update=int(entry.get("window_update", 0)),
        priority_frames=tuple(tuple(p) for p in entry.get("priority_frames", ())),
        headers_flags=int(entry.get("headers_flags", DEFAULT_HEADERS_FLAGS)),
        headers_priority=tuple(priority) if priority else None,
        pseudo_order=entry["pseudo_order"],
    )


def spec_names():
    """Every captured target name, sorted."""
    from .templates_data import SPECS
    return sorted(SPECS)


def spec(name):
    """The :class:`H2Spec` captured for ``name``; ``KeyError`` when unknown."""
    from .templates_data import SPECS
    key = str(name).strip().lower()
    try:
        entry = SPECS[key]
    except KeyError:
        raise KeyError("unknown HTTP/2 template %r; known: %s" % (name, ", ".join(sorted(SPECS)))) from None
    return _from_entry(key, entry)


def akamai_string(h2spec):
    """The Akamai HTTP/2 fingerprint ``SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo``."""
    settings = ";".join("%d:%d" % (i, v) for i, v in h2spec.settings)
    if h2spec.priority_frames:
        priority = ",".join("%d:%d:%d:%d" % (s, 1 if e else 0, d, w)
                            for s, e, d, w in h2spec.priority_frames)
    else:
        priority = "0"
    pseudo = ",".join(h2spec.pseudo_order)
    return "%s|%s|%s|%s" % (settings, h2spec.window_update, priority, pseudo)


def _headers_shape_for(settings, pseudo_order):
    """Pick HEADERS flags and priority for a string with no capture of its own.

    The Akamai string does not record the HEADERS frame, so the shape of the
    nearest browser family is used: Chrome and Edge send an exclusive
    dependency with weight 256, Firefox a non-exclusive weight 42, Safari 17
    a non-exclusive weight 255, newer Safari (which advertises
    NO_RFC7540_PRIORITIES) no PRIORITY field at all.
    """
    ids = {i for i, _ in settings}
    if pseudo_order == "masp":
        return DEFAULT_HEADERS_FLAGS, (True, 0, 256)
    if pseudo_order == "mpas":
        return DEFAULT_HEADERS_FLAGS, (False, 0, 42)
    if pseudo_order == "mspa":
        return DEFAULT_HEADERS_FLAGS, (False, 0, 255)
    if 0x9 in ids:
        return FLAG_END_STREAM | FLAG_END_HEADERS, None
    return DEFAULT_HEADERS_FLAGS, (False, 0, 256)


def spec_from_akamai(text, name=None):
    """Parse an Akamai fingerprint string into an :class:`H2Spec`.

    ``1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`` is the Chrome
    string.  When it equals a captured template's string that template is
    returned (with its HEADERS flags); otherwise the HEADERS shape is chosen
    by family as described in ``_headers_shape_for``.  Invalid input raises
    ``ValueError``.
    """
    from .templates_data import SPECS
    raw = str(text).strip()
    parts = raw.split("|")
    if len(parts) != 4:
        raise ValueError("akamai string needs 4 '|' separated parts: %r" % (text,))
    settings_text, window_text, priority_text, pseudo_text = (p.strip() for p in parts)
    settings = []
    if settings_text and settings_text != "0":
        for pair in settings_text.split(";"):
            if not pair:
                continue
            ident, _, value = pair.partition(":")
            try:
                settings.append((int(ident), int(value)))
            except ValueError:
                raise ValueError("bad SETTINGS pair %r in %r" % (pair, text)) from None
    try:
        window_update = int(window_text or "0")
    except ValueError:
        raise ValueError("bad WINDOW_UPDATE %r in %r" % (window_text, text)) from None
    priority_frames = []
    if priority_text and priority_text != "0":
        for item in priority_text.split(","):
            fields = item.split(":")
            if len(fields) != 4:
                raise ValueError("bad PRIORITY entry %r in %r" % (item, text))
            try:
                stream_id, exclusive, dependency, weight = (int(f) for f in fields)
            except ValueError:
                raise ValueError("bad PRIORITY entry %r in %r" % (item, text)) from None
            priority_frames.append((stream_id, bool(exclusive), dependency, weight))
    pseudo_order = _normalise_pseudo_order(pseudo_text)
    candidate = "%s|%d|%s|%s" % (
        ";".join("%d:%d" % p for p in settings), window_update,
        ",".join("%d:%d:%d:%d" % (s, 1 if e else 0, d, w) for s, e, d, w in priority_frames) or "0",
        ",".join(pseudo_order))
    if name is None:
        for known in sorted(SPECS):
            if SPECS[known]["akamai"] == candidate:
                return _from_entry(known, SPECS[known])
    flags, priority = _headers_shape_for(settings, pseudo_order)
    return H2Spec(name=name or "akamai", settings=tuple(settings), window_update=window_update,
                  priority_frames=tuple(priority_frames), headers_flags=flags,
                  headers_priority=priority, pseudo_order=pseudo_order)


__all__ = ["H2Spec", "spec", "spec_names", "spec_from_akamai", "akamai_string",
           "PSEUDO_NAMES", "PSEUDO_ORDERS", "DEFAULT_HEADERS_FLAGS"]
