"""curl_reap's own HTTP/2 client.

The package reproduces, frame for frame and HPACK byte for HPACK byte, what
the reference browser-impersonation client (libcurl with nghttp2) sends for each impersonation target, from
the captures in ``tools/h2_templates``:

* :func:`spec` / :class:`H2Spec`: a browser's SETTINGS, WINDOW_UPDATE,
  PRIORITY frames, HEADERS flags and pseudo header order;
  :func:`spec_from_akamai` and :func:`akamai_string` convert to and from the
  Akamai fingerprint string.
* :class:`H2Connection`: blocking driver over a socket with
  ``request()``, ``ping()``, ``poll()``, ``close()`` and ``alive``.
* :class:`H2Core`: the sans-IO state machine the driver uses, reusable by
  an asyncio driver, with :mod:`curl_reap._h2.core` events.
* :class:`HpackEncoder`: nghttp2's representation choices.
* :class:`H2Error`: the exception, a ``TransportError`` with ``error_code``,
  ``stream_id`` and ``retryable``.

Requires the ``hpack`` package (Huffman code and static table); the
standard library covers everything else.
"""
from __future__ import annotations

from .connection import DEFAULT_MAX_BODY, H2Connection, H2Response
from .core import (
    ConnectionTerminated, DataReceived, Event, H2Core, InformationalResponse,
    PingAckReceived, PingReceived, PushPromiseRefused, RemoteSettingsChanged,
    ResponseReceived, SettingsAcknowledged, StreamEnded, StreamReset,
    TrailersReceived, WindowUpdated, build_request_fields,
)
from .errors import ERROR_NAMES, H2Error, error_name
from .hpack_encoder import HpackEncoder
from .spec import H2Spec, akamai_string, spec, spec_from_akamai, spec_names

__all__ = [
    "H2Spec", "spec", "spec_names", "spec_from_akamai", "akamai_string",
    "H2Error", "ERROR_NAMES", "error_name",
    "H2Connection", "H2Response", "DEFAULT_MAX_BODY",
    "H2Core", "HpackEncoder", "build_request_fields",
    "Event", "RemoteSettingsChanged", "SettingsAcknowledged", "InformationalResponse",
    "ResponseReceived", "DataReceived", "TrailersReceived", "StreamEnded", "StreamReset",
    "WindowUpdated", "PingReceived", "PingAckReceived", "ConnectionTerminated",
    "PushPromiseRefused",
]
