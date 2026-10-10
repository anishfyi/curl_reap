"""Exception hierarchy for curl_reap.

The names and numeric codes mirror ``curl_cffi.requests.exceptions`` so code
written against curl_cffi keeps its ``except`` clauses, while every transport
failure stays a :class:`TransportError` (the name curl_reap 1.x used) and an
``OSError``.  This module imports nothing from the package so the TLS and
HTTP/2 engines can raise these without import cycles.
"""
from __future__ import annotations

from enum import IntEnum


class CurlECode(IntEnum):
    """libcurl error numbers, kept so ``exc.code`` matches curl_cffi."""

    OK = 0
    UNSUPPORTED_PROTOCOL = 1
    FAILED_INIT = 2
    URL_MALFORMAT = 3
    NOT_BUILT_IN = 4
    COULDNT_RESOLVE_PROXY = 5
    COULDNT_RESOLVE_HOST = 6
    COULDNT_CONNECT = 7
    WEIRD_SERVER_REPLY = 8
    REMOTE_ACCESS_DENIED = 9
    HTTP2 = 16
    PARTIAL_FILE = 18
    QUOTE_ERROR = 21
    HTTP_RETURNED_ERROR = 22
    WRITE_ERROR = 23
    UPLOAD_FAILED = 25
    READ_ERROR = 26
    OUT_OF_MEMORY = 27
    OPERATION_TIMEDOUT = 28
    RANGE_ERROR = 33
    HTTP_POST_ERROR = 34
    SSL_CONNECT_ERROR = 35
    BAD_DOWNLOAD_RESUME = 36
    FUNCTION_NOT_FOUND = 41
    ABORTED_BY_CALLBACK = 42
    BAD_FUNCTION_ARGUMENT = 43
    INTERFACE_FAILED = 45
    TOO_MANY_REDIRECTS = 47
    UNKNOWN_OPTION = 48
    SETOPT_OPTION_SYNTAX = 49
    GOT_NOTHING = 52
    SSL_ENGINE_NOTFOUND = 53
    SSL_ENGINE_SETFAILED = 54
    SEND_ERROR = 55
    RECV_ERROR = 56
    SSL_CERTPROBLEM = 58
    SSL_CIPHER = 59
    PEER_FAILED_VERIFICATION = 60
    BAD_CONTENT_ENCODING = 61
    FILESIZE_EXCEEDED = 63
    USE_SSL_FAILED = 64
    SEND_FAIL_REWIND = 65
    SSL_ENGINE_INITFAILED = 66
    LOGIN_DENIED = 67
    SSL_CACERT_BADFILE = 77
    REMOTE_FILE_NOT_FOUND = 78
    SSL_SHUTDOWN_FAILED = 80
    AGAIN = 81
    SSL_CRL_BADFILE = 82
    SSL_ISSUER_ERROR = 83
    CHUNK_FAILED = 88
    NO_CONNECTION_AVAILABLE = 89
    SSL_PINNEDPUBKEYNOTMATCH = 90
    SSL_INVALIDCERTSTATUS = 91
    HTTP2_STREAM = 92
    RECURSIVE_API_CALL = 93
    AUTH_ERROR = 94
    HTTP3 = 95
    QUIC_CONNECT_ERROR = 96
    PROXY = 97
    SSL_CLIENTCERT = 98
    UNRECOVERABLE_POLL = 99
    TOO_LARGE = 100
    ECH_REQUIRED = 101


class RequestException(OSError):
    """Base class for every error curl_reap raises while making a request.

    ``code`` is a :class:`CurlECode` number (0 when none applies) and
    ``response`` is the :class:`curl_reap.Response` involved, when there is
    one.  Alias: ``RequestsError``.
    """

    code = 0

    def __init__(self, message="", code=None, response=None):
        super().__init__(message)
        if code is not None:
            self.code = int(code)
        self.response = response

    def __str__(self):
        base = super().__str__()
        code = int(self.code or 0)
        if code and ("curl error %d" % code) not in base:
            return "%s (curl error %d)" % (base, code) if base else "curl error %d" % code
        return base


RequestsError = RequestException


class TransportError(RequestException):
    """A connection, TLS, proxy or HTTP framing failure (the 1.x name)."""


class ConnectionError(TransportError):  # noqa: A001 - mirrors curl_cffi
    code = CurlECode.COULDNT_CONNECT


class DNSError(ConnectionError):
    code = CurlECode.COULDNT_RESOLVE_HOST


class ProxyError(ConnectionError):
    code = CurlECode.COULDNT_RESOLVE_PROXY


class SSLError(ConnectionError):
    code = CurlECode.SSL_CONNECT_ERROR


class CertificateVerifyError(SSLError):
    code = CurlECode.PEER_FAILED_VERIFICATION


class Timeout(TransportError):
    code = CurlECode.OPERATION_TIMEDOUT


class ConnectTimeout(Timeout, ConnectionError):
    code = CurlECode.OPERATION_TIMEDOUT


class ReadTimeout(Timeout):
    code = CurlECode.OPERATION_TIMEDOUT


class TooManyRedirects(TransportError):
    code = CurlECode.TOO_MANY_REDIRECTS


class IncompleteRead(TransportError):
    code = CurlECode.PARTIAL_FILE


class ChunkedEncodingError(TransportError):
    code = CurlECode.RECV_ERROR


class ContentDecodingError(TransportError):
    code = CurlECode.BAD_CONTENT_ENCODING


class InterfaceError(ConnectionError):
    code = CurlECode.INTERFACE_FAILED


class InvalidURL(RequestException, ValueError):
    code = CurlECode.URL_MALFORMAT


class InvalidSchema(RequestException, ValueError):
    code = CurlECode.UNSUPPORTED_PROTOCOL


class InvalidHeader(RequestException, ValueError):
    code = CurlECode.BAD_FUNCTION_ARGUMENT


class ImpersonateError(RequestException):
    """An impersonate target, ja3/akamai string or extra fingerprint is invalid."""


class SessionClosed(RequestException):
    """A request was made on a closed session."""


class StreamConsumedError(RequestException):
    """The body of a streamed response was already read."""


class UnrewindableBodyError(RequestException):
    """A retry or redirect needed to resend a body that cannot be rewound."""


class HTTPError(RequestException):
    """Raised by ``Response.raise_for_status()``. Alias: ``HTTPStatusError``."""

    code = CurlECode.HTTP_RETURNED_ERROR

    def __init__(self, response, message=None):
        if message is None:
            message = "HTTP %s for %s" % (getattr(response, "status", None),
                                         getattr(response, "url", None))
        super().__init__(message, response=response)


HTTPStatusError = HTTPError


class URLPolicyError(ValueError):
    """A configured ``url_policy`` rejected an outbound URL before it was sent."""


class CookieConflict(RequestException):
    """Several cookies match a name; use ``domain`` and ``path`` to pick one."""


class InvalidJSONError(RequestException):
    """A response body could not be parsed as JSON."""


class JSONDecodeError(InvalidJSONError, ValueError):
    pass


class WebSocketError(RequestException):
    """A WebSocket handshake, framing or protocol failure."""


class WebSocketClosed(WebSocketError):
    """The WebSocket was closed; ``code`` and ``reason`` carry the close frame."""

    def __init__(self, message="", code=None, reason=""):
        super().__init__(message)
        self.close_code = code
        self.reason = reason


class WebSocketTimeout(WebSocketError, Timeout):
    code = CurlECode.OPERATION_TIMEDOUT


#: Map a libcurl error number to the exception class curl_cffi would raise.
CODE2ERROR = {
    CurlECode.OK: RequestException,
    CurlECode.UNSUPPORTED_PROTOCOL: InvalidSchema,
    CurlECode.URL_MALFORMAT: InvalidURL,
    CurlECode.COULDNT_RESOLVE_PROXY: ProxyError,
    CurlECode.COULDNT_RESOLVE_HOST: DNSError,
    CurlECode.COULDNT_CONNECT: ConnectionError,
    CurlECode.WEIRD_SERVER_REPLY: ConnectionError,
    CurlECode.REMOTE_ACCESS_DENIED: ConnectionError,
    CurlECode.HTTP2: ConnectionError,
    CurlECode.PARTIAL_FILE: IncompleteRead,
    CurlECode.HTTP_RETURNED_ERROR: HTTPError,
    CurlECode.OPERATION_TIMEDOUT: Timeout,
    CurlECode.SSL_CONNECT_ERROR: SSLError,
    CurlECode.INTERFACE_FAILED: InterfaceError,
    CurlECode.TOO_MANY_REDIRECTS: TooManyRedirects,
    CurlECode.GOT_NOTHING: ConnectionError,
    CurlECode.SEND_ERROR: ConnectionError,
    CurlECode.RECV_ERROR: ConnectionError,
    CurlECode.SSL_CERTPROBLEM: SSLError,
    CurlECode.SSL_CIPHER: SSLError,
    CurlECode.PEER_FAILED_VERIFICATION: CertificateVerifyError,
    CurlECode.BAD_CONTENT_ENCODING: ContentDecodingError,
    CurlECode.SSL_CACERT_BADFILE: SSLError,
    CurlECode.SSL_CRL_BADFILE: SSLError,
    CurlECode.SSL_ISSUER_ERROR: SSLError,
    CurlECode.CHUNK_FAILED: ChunkedEncodingError,
    CurlECode.HTTP2_STREAM: ConnectionError,
    CurlECode.PROXY: ProxyError,
    CurlECode.SSL_CLIENTCERT: SSLError,
}


__all__ = [
    "CurlECode", "CODE2ERROR",
    "RequestException", "RequestsError", "TransportError", "ConnectionError",
    "DNSError", "ProxyError", "SSLError", "CertificateVerifyError", "Timeout",
    "ConnectTimeout", "ReadTimeout", "TooManyRedirects", "IncompleteRead",
    "ChunkedEncodingError", "ContentDecodingError", "InterfaceError",
    "InvalidURL", "InvalidSchema", "InvalidHeader", "ImpersonateError",
    "SessionClosed", "StreamConsumedError", "UnrewindableBodyError",
    "HTTPError", "HTTPStatusError", "URLPolicyError", "CookieConflict",
    "InvalidJSONError", "JSONDecodeError", "WebSocketError", "WebSocketClosed",
    "WebSocketTimeout",
]
