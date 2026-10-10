"""Pure-Python TLS 1.3 client with browser-faithful ClientHello templates.

Layout:

- consts.py          IANA numbers, alert names, GREASE helpers
- wire.py            presentation-language readers and writers
- errors.py          TLSError, TLS12Negotiated, CertificateError, TLSAlertReceived
- templates_data.py  generated from tools/hello_templates/*.json
- templates.py       HelloTemplate, template(), template_from_ja3()
- hello.py           ClientHelloBuilder, build_client_hello(), parse_client_hello()
- keyexchange.py     X25519, P-256/384/521, X25519MLKEM768, X25519Kyber768Draft00
- mlkem.py           pure-Python ML-KEM (FIPS 203) plus Kyber768 round 3
- keyschedule.py     HKDF, cipher suites, key schedule, PSK binders
- record.py          record protection (AEAD, nonces, padding)
- certs.py           trust store, chain verification, CertificateVerify, RFC 8879
- session.py         Ticket and SessionCache for PSK resumption
- engine.py          sans-IO TLSClient state machine and events
- sockets.py         TLSSocket, wrap_socket, AsyncTLSSocket, async_wrap_socket
"""
from __future__ import annotations

from .engine import ApplicationData, Closed, HandshakeDone, NewTicket, TLSClient
from .errors import (
    CertificateError,
    TLS12Negotiated,
    TLSAlertReceived,
    TLSError,
    UnsupportedGroupRequested,
)
from .hello import ClientHelloBuilder, build_client_hello, parse_client_hello
from .keyexchange import KeyShare, mlkem768_backend
from .session import SessionCache, Ticket
from .sockets import AsyncTLSSocket, TLSSocket, async_wrap_socket, wrap_socket
from .templates import GREASE, HelloTemplate, template, template_from_dict, template_from_ja3, template_names

__all__ = [
    "TLSError", "TLS12Negotiated", "CertificateError", "TLSAlertReceived", "UnsupportedGroupRequested",
    "HelloTemplate", "GREASE", "template", "template_names", "template_from_ja3", "template_from_dict",
    "build_client_hello", "parse_client_hello", "ClientHelloBuilder",
    "TLSClient", "HandshakeDone", "ApplicationData", "Closed", "NewTicket",
    "wrap_socket", "TLSSocket", "AsyncTLSSocket", "async_wrap_socket",
    "SessionCache", "Ticket", "KeyShare", "mlkem768_backend",
]
