"""Exceptions raised by the native TLS engine.

All of them are :class:`curl_reap.exceptions.TransportError` subclasses so
the transport's existing ``except`` clauses keep working, and they carry the
libcurl error code the reference client would report (35 for a TLS failure, 60 for a
certificate verification failure, 28 for a timeout).
"""
from __future__ import annotations

from typing import Optional

from curl_reap.exceptions import CertificateVerifyError, CurlECode, TransportError

from .consts import (
    AD_BAD_CERTIFICATE,
    AD_HANDSHAKE_FAILURE,
    AD_INTERNAL_ERROR,
    AD_PROTOCOL_VERSION,
    ALERT_NAMES,
    GROUP_NAMES,
)


class TLSError(TransportError):
    """A TLS protocol failure.

    ``alert`` is the alert description the engine sent (or would send) to the
    peer for this failure; drivers flush it before closing the socket.
    """

    code = CurlECode.SSL_CONNECT_ERROR
    alert = AD_INTERNAL_ERROR

    def __init__(self, message: str = "", alert: Optional[int] = None, code=None, response=None):
        super().__init__(message, code=code, response=response)
        if alert is not None:
            self.alert = alert


class TLSAlertReceived(TLSError):
    """The peer sent a fatal alert (or a warning alert we do not tolerate)."""

    def __init__(self, level: int, description: int):
        self.level = level
        self.description = description
        self.name = ALERT_NAMES.get(description, "alert_%d" % description)
        super().__init__("peer sent TLS alert %s (%d)" % (self.name, description))


class TLS12Negotiated(TLSError):
    """The server answered without TLS 1.3; the caller reconnects with OpenSSL.

    ``negotiated`` is the version the ServerHello implied (0x0303 for TLS 1.2,
    lower for older servers). Raised as soon as the ServerHello is parsed so
    no more than that record is consumed.
    """

    alert = AD_PROTOCOL_VERSION

    def __init__(self, message: str, negotiated: int):
        super().__init__(message)
        self.negotiated = negotiated


class CertificateError(CertificateVerifyError, TLSError):
    """Chain building, hostname matching or CertificateVerify failed (code 60)."""

    alert = AD_BAD_CERTIFICATE


class UnsupportedGroupRequested(TLSError):
    """HelloRetryRequest asked for a group we advertised but cannot generate.

    Firefox templates advertise ffdhe2048 and ffdhe3072 the way the reference client's
    BoringSSL does without being able to use them; a server that insists on
    finite-field DH gets a handshake_failure, exactly as the reference client behaves.
    """

    alert = AD_HANDSHAKE_FAILURE

    def __init__(self, group: int, cookie: Optional[bytes] = None):
        self.group = group
        self.cookie = cookie
        super().__init__(
            "HelloRetryRequest wants group %s which has no local key share generator"
            % GROUP_NAMES.get(group, group)
        )
