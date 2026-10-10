"""The one exception type the HTTP/2 engine raises.

``H2Error`` is a :class:`curl_reap.exceptions.TransportError` so callers that
catch curl_reap's transport failures keep working.  ``error_code`` is the
RFC 9113 error code involved (``PROTOCOL_ERROR`` when nothing more specific
applies), ``stream_id`` is 0 for connection level failures, and
``retryable`` tells the transport that the request was never processed by
the server (a GOAWAY below our stream id, a REFUSED_STREAM, a connection
that died before any response frame) so it is safe to resend it on a new
connection.
"""
from __future__ import annotations

from ..exceptions import CurlECode, TransportError

ERROR_NAMES = {
    0x0: "NO_ERROR",
    0x1: "PROTOCOL_ERROR",
    0x2: "INTERNAL_ERROR",
    0x3: "FLOW_CONTROL_ERROR",
    0x4: "SETTINGS_TIMEOUT",
    0x5: "STREAM_CLOSED",
    0x6: "FRAME_SIZE_ERROR",
    0x7: "REFUSED_STREAM",
    0x8: "CANCEL",
    0x9: "COMPRESSION_ERROR",
    0xA: "CONNECT_ERROR",
    0xB: "ENHANCE_YOUR_CALM",
    0xC: "INADEQUATE_SECURITY",
    0xD: "HTTP_1_1_REQUIRED",
}


def error_name(code):
    """Return the RFC 9113 name of an error code, or ``0x..`` for unknown ones."""
    return ERROR_NAMES.get(int(code), "0x%x" % int(code))


class H2Error(TransportError):
    """An HTTP/2 framing, protocol, flow control or stream failure.

    ``code`` follows libcurl: 16 (``HTTP2``) for connection level problems
    and 92 (``HTTP2_STREAM``) for a single stream, unless a more specific
    code is passed (for example ``FILESIZE_EXCEEDED`` when ``max_body`` is
    hit).
    """

    code = CurlECode.HTTP2

    def __init__(self, message="", *, error_code=0x1, stream_id=0,
                 retryable=False, code=None, response=None):
        if code is None:
            code = CurlECode.HTTP2_STREAM if stream_id else CurlECode.HTTP2
        super().__init__(message, code=code, response=response)
        self.error_code = int(error_code)
        self.stream_id = int(stream_id)
        self.retryable = bool(retryable)

    @property
    def error_name(self):
        return error_name(self.error_code)


__all__ = ["H2Error", "ERROR_NAMES", "error_name"]
