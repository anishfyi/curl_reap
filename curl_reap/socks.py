"""SOCKS4, SOCKS4a, SOCKS5 and SOCKS5h client handshakes on plain sockets.

:func:`socks_connect` opens a TCP connection to the proxy, performs the
handshake for the proxy URL's scheme and returns the socket with the tunnel
established, ready for the caller to speak HTTP (or wrap in TLS) through it.

Scheme semantics match libcurl's:

* ``socks4``: the destination is resolved locally and sent as an IPv4
  address (SOCKS4 has no room for IPv6); the URL's username is the user id.
* ``socks4a``: the destination hostname is sent to the proxy, which resolves
  it (an IPv4 literal is still sent as an address).
* ``socks5``: the destination is resolved locally and sent as an IPv4 or IPv6
  address (IPv4 preferred when both exist); authentication methods offered
  are "no authentication" and, when the URL carries credentials,
  username/password (RFC 1929).
* ``socks5h``: the destination hostname is sent to the proxy (remote DNS);
  IP literals are sent as addresses.

The proxy port defaults to 1080.  Handshake replies that are not success
raise :class:`curl_reap.exceptions.ProxyError` carrying the RFC's wording for
the reply code and curl's ``CURLE_PROXY`` (97) code; failing to reach the
proxy raises ``ProxyError`` with ``COULDNT_CONNECT`` (7) or, when the proxy
name does not resolve, ``COULDNT_RESOLVE_PROXY`` (5); a local DNS failure for
the destination raises :class:`curl_reap.exceptions.DNSError`; running out of
``timeout`` or ``deadline`` during any step raises
:class:`curl_reap.exceptions.ConnectTimeout`.  No dependency beyond the
standard library is used.
"""
from __future__ import annotations

import errno
import ipaddress
import socket
import struct
import time
from typing import Optional, Tuple, Union
from urllib.parse import SplitResult, unquote, urlsplit

from .exceptions import ConnectTimeout, CurlECode, DNSError, InvalidSchema, ProxyError

__all__ = [
    "socks_connect", "parse_socks_proxy", "SOCKS_SCHEMES", "SOCKS_DEFAULT_PORT",
    "SOCKS4_REPLIES", "SOCKS5_REPLIES",
]

SOCKS_DEFAULT_PORT = 1080
SOCKS_SCHEMES = ("socks4", "socks4a", "socks5", "socks5h")

#: SOCKS4 reply codes (CD byte) and their meaning from the SOCKS4 protocol text.
SOCKS4_REPLIES = {
    90: "request granted",
    91: "request rejected or failed",
    92: "request rejected because SOCKS server cannot connect to identd on the client",
    93: "request rejected because the client program and identd report different user-ids",
}

#: SOCKS5 reply codes (REP byte) and their meaning from RFC 1928 section 6.
SOCKS5_REPLIES = {
    0: "succeeded",
    1: "general SOCKS server failure",
    2: "connection not allowed by ruleset",
    3: "Network unreachable",
    4: "Host unreachable",
    5: "Connection refused",
    6: "TTL expired",
    7: "Command not supported",
    8: "Address type not supported",
}

_SOCKS5_METHOD_NONE = 0x00
_SOCKS5_METHOD_USERPASS = 0x02
_SOCKS5_METHOD_REJECTED = 0xFF
_SOCKS5_ATYP_IPV4 = 0x01
_SOCKS5_ATYP_DOMAIN = 0x03
_SOCKS5_ATYP_IPV6 = 0x04


class _Clock(object):
    """Per-operation socket timeouts derived from a timeout and a deadline."""

    def __init__(self, timeout, deadline, label):
        self.timeout = None if timeout is None else float(timeout)
        self.deadline = deadline
        self.label = label

    def remaining(self) -> Optional[float]:
        """Seconds to allow the next socket operation, or None for blocking."""
        if self.deadline is None:
            return self.timeout
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise ConnectTimeout("deadline exceeded while connecting through %s" % self.label)
        if self.timeout is None:
            return left
        return min(self.timeout, left)


def parse_socks_proxy(proxy: Union[str, SplitResult]) -> Tuple[str, str, int, Optional[str], Optional[str]]:
    """Split a SOCKS proxy URL into ``(scheme, host, port, username, password)``.

    ``proxy`` is a URL string or a :func:`urllib.parse.urlsplit` result.  The
    scheme must be one of ``socks4``, ``socks4a``, ``socks5`` or ``socks5h``
    (:class:`curl_reap.exceptions.InvalidSchema` otherwise), the port defaults
    to 1080 and credentials are percent-decoded.
    """
    parts = urlsplit(proxy) if isinstance(proxy, str) else proxy
    scheme = (parts.scheme or "").lower()
    if scheme not in SOCKS_SCHEMES:
        raise InvalidSchema("unsupported SOCKS proxy scheme %r (expected one of %s)"
                            % (parts.scheme, ", ".join(SOCKS_SCHEMES)))
    host = parts.hostname
    if not host:
        raise ProxyError("SOCKS proxy URL has no host", code=CurlECode.COULDNT_RESOLVE_PROXY)
    try:
        port = parts.port
    except ValueError:
        raise ProxyError("SOCKS proxy URL has an invalid port",
                         code=CurlECode.COULDNT_RESOLVE_PROXY)
    if port is None:
        port = SOCKS_DEFAULT_PORT
    username = unquote(parts.username) if parts.username is not None else None
    password = unquote(parts.password) if parts.password is not None else None
    return scheme, host, port, username, password


def _ip_literal(host: str):
    """Return an ``ipaddress`` object for an IP literal, or None for a hostname."""
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if "%" in candidate:  # zone id has no meaning past the proxy
        candidate = candidate.split("%", 1)[0]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def _resolve(host: str, port: int, family: int):
    """Resolve ``host`` locally; IPv4 results first.  Raises DNSError."""
    try:
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DNSError("could not resolve host %s: %s" % (host, exc))
    if not infos:
        raise DNSError("could not resolve host %s" % host)
    infos.sort(key=lambda info: 0 if info[0] == socket.AF_INET else 1)
    return infos


def _encode_hostname(host: str) -> bytes:
    try:
        raw = host.encode("ascii")
    except UnicodeEncodeError:
        try:
            raw = host.encode("idna")
        except UnicodeError:
            raw = host.encode("utf-8")
    return raw


_CLOSED_ERRNOS = frozenset(e for e in (
    getattr(errno, "ECONNRESET", None), getattr(errno, "ECONNABORTED", None),
    getattr(errno, "EPIPE", None), getattr(errno, "ESHUTDOWN", None)) if e is not None)


def _closed(clock: _Clock, detail: str = "") -> ProxyError:
    message = "SOCKS proxy %s closed the connection during the handshake" % clock.label
    if detail:
        message += " (%s)" % detail
    return ProxyError(message, code=CurlECode.PROXY)


def _recv_exact(sock: socket.socket, count: int, clock: _Clock) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        sock.settimeout(clock.remaining())
        try:
            data = sock.recv(count - len(chunks))
        except socket.timeout:
            raise ConnectTimeout("timed out waiting for the SOCKS proxy %s" % clock.label)
        except OSError as exc:
            if exc.errno in _CLOSED_ERRNOS:
                raise _closed(clock, str(exc))
            raise ProxyError("error reading from SOCKS proxy %s: %s" % (clock.label, exc),
                             code=CurlECode.PROXY)
        if not data:
            raise _closed(clock)
        chunks += data
    return bytes(chunks)


def _send_all(sock: socket.socket, data: bytes, clock: _Clock) -> None:
    sock.settimeout(clock.remaining())
    try:
        sock.sendall(data)
    except socket.timeout:
        raise ConnectTimeout("timed out sending to the SOCKS proxy %s" % clock.label)
    except OSError as exc:
        if exc.errno in _CLOSED_ERRNOS:
            raise _closed(clock, str(exc))
        raise ProxyError("error writing to SOCKS proxy %s: %s" % (clock.label, exc),
                         code=CurlECode.PROXY)


def _socks4_request(scheme, host, port, username) -> bytes:
    """Build the SOCKS4 or SOCKS4a CONNECT request (resolving locally for socks4)."""
    remote_dns = scheme == "socks4a"
    user_id = (username or "").encode("utf-8")
    if b"\x00" in user_id:
        raise ValueError("SOCKS4 user id must not contain NUL")
    literal = _ip_literal(host)
    trailer = b""
    if literal is not None and literal.version == 4:
        dst = literal.packed
    elif remote_dns:
        dst = b"\x00\x00\x00\x01"
        trailer = _encode_hostname(host) + b"\x00"
    elif literal is not None:
        raise ProxyError("SOCKS4 cannot address the IPv6 destination %s; use socks5" % host,
                         code=CurlECode.PROXY)
    else:
        infos = _resolve(host, port, socket.AF_INET)
        dst = socket.inet_aton(infos[0][4][0])
    return b"\x04\x01" + struct.pack("!H", port) + dst + user_id + b"\x00" + trailer


def _socks4_handshake(sock, request, host, port, clock):
    _send_all(sock, request, clock)
    reply = _recv_exact(sock, 8, clock)
    version, code = reply[0], reply[1]
    if version not in (0, 4):
        raise ProxyError("malformed SOCKS4 reply from %s (version byte %d)"
                         % (clock.label, version), code=CurlECode.PROXY)
    if code != 90:
        text = SOCKS4_REPLIES.get(code, "unknown reply code %d" % code)
        raise ProxyError("SOCKS4 proxy %s refused the connection to %s:%d: %s"
                         % (clock.label, host, port, text), code=CurlECode.PROXY)


def _socks5_address(scheme, host, port) -> bytes:
    literal = _ip_literal(host)
    if literal is not None:
        if literal.version == 4:
            return bytes([_SOCKS5_ATYP_IPV4]) + literal.packed
        return bytes([_SOCKS5_ATYP_IPV6]) + literal.packed
    if scheme == "socks5h":
        name = _encode_hostname(host)
        if not name or len(name) > 255:
            raise ProxyError("hostname %r cannot be sent to a SOCKS5 proxy (1 to 255 bytes)"
                             % host, code=CurlECode.PROXY)
        return bytes([_SOCKS5_ATYP_DOMAIN, len(name)]) + name
    infos = _resolve(host, port, socket.AF_UNSPEC)
    family, _type, _proto, _canon, sockaddr = infos[0]
    if family == socket.AF_INET:
        return bytes([_SOCKS5_ATYP_IPV4]) + socket.inet_pton(socket.AF_INET, sockaddr[0])
    return bytes([_SOCKS5_ATYP_IPV6]) + socket.inet_pton(socket.AF_INET6, sockaddr[0])


def _socks5_handshake(sock, address, host, port, username, password, clock):
    methods = bytes([_SOCKS5_METHOD_NONE])
    have_credentials = username is not None or password is not None
    if have_credentials:
        methods += bytes([_SOCKS5_METHOD_USERPASS])
    _send_all(sock, b"\x05" + bytes([len(methods)]) + methods, clock)
    version, method = _recv_exact(sock, 2, clock)
    if version != 5:
        raise ProxyError("malformed SOCKS5 greeting reply from %s (version byte %d)"
                         % (clock.label, version), code=CurlECode.PROXY)
    if method == _SOCKS5_METHOD_USERPASS:
        if not have_credentials:
            raise ProxyError("SOCKS5 proxy %s selected username/password authentication "
                             "but no credentials were given" % clock.label,
                             code=CurlECode.PROXY)
        user = (username or "").encode("utf-8")
        secret = (password or "").encode("utf-8")
        if len(user) > 255 or len(secret) > 255:
            raise ProxyError("SOCKS5 username and password must be at most 255 bytes each",
                             code=CurlECode.PROXY)
        _send_all(sock, b"\x01" + bytes([len(user)]) + user + bytes([len(secret)]) + secret,
                  clock)
        auth_version, status = _recv_exact(sock, 2, clock)
        if auth_version != 1:
            raise ProxyError("malformed SOCKS5 authentication reply from %s (version byte %d)"
                             % (clock.label, auth_version), code=CurlECode.PROXY)
        if status != 0:
            raise ProxyError("SOCKS5 proxy %s rejected the username/password authentication "
                             "(status %d)" % (clock.label, status), code=CurlECode.PROXY)
    elif method == _SOCKS5_METHOD_REJECTED:
        raise ProxyError("SOCKS5 proxy %s accepted no offered authentication method"
                         % clock.label, code=CurlECode.PROXY)
    elif method != _SOCKS5_METHOD_NONE:
        raise ProxyError("SOCKS5 proxy %s selected unsupported authentication method %d"
                         % (clock.label, method), code=CurlECode.PROXY)
    _send_all(sock, b"\x05\x01\x00" + address + struct.pack("!H", port), clock)
    head = _recv_exact(sock, 4, clock)
    version, code, _reserved, atyp = head
    if version != 5:
        raise ProxyError("malformed SOCKS5 reply from %s (version byte %d)"
                         % (clock.label, version), code=CurlECode.PROXY)
    if code != 0:
        text = SOCKS5_REPLIES.get(code, "unknown reply code %d" % code)
        raise ProxyError("SOCKS5 proxy %s refused the connection to %s:%d: %s"
                         % (clock.label, host, port, text), code=CurlECode.PROXY)
    if atyp == _SOCKS5_ATYP_IPV4:
        _recv_exact(sock, 4 + 2, clock)
    elif atyp == _SOCKS5_ATYP_IPV6:
        _recv_exact(sock, 16 + 2, clock)
    elif atyp == _SOCKS5_ATYP_DOMAIN:
        length = _recv_exact(sock, 1, clock)[0]
        _recv_exact(sock, length + 2, clock)
    else:
        raise ProxyError("malformed SOCKS5 reply from %s (address type %d)"
                         % (clock.label, atyp), code=CurlECode.PROXY)


def socks_connect(proxy: Union[str, SplitResult], host: str, port: int,
                  timeout: Optional[float] = None, source_address=None,
                  deadline: Optional[float] = None) -> socket.socket:
    """Connect to ``host:port`` through a SOCKS proxy and return the socket.

    ``proxy`` is a proxy URL (``socks5h://user:pass@proxy.example:1080``) or
    its :func:`urllib.parse.urlsplit` result.  ``timeout`` bounds the TCP
    connect to the proxy and each handshake read or write; ``deadline`` is a
    :func:`time.monotonic` value after which the whole connect fails, applied
    to every socket operation.  ``source_address`` is passed to
    :func:`socket.create_connection`.  The returned socket has its timeout set
    back to ``timeout``.
    """
    scheme, proxy_host, proxy_port, username, password = parse_socks_proxy(proxy)
    port = int(port)
    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535, not %d" % port)
    if not host:
        raise ValueError("destination host must not be empty")
    label = "%s://%s:%d" % (scheme, proxy_host, proxy_port)
    clock = _Clock(timeout, deadline, label)
    connect_timeout = clock.remaining()
    # Build the request before dialing the proxy so an unusable destination
    # (IPv6 over SOCKS4, a name that does not resolve) costs no connection.
    if scheme in ("socks4", "socks4a"):
        socks4_request = _socks4_request(scheme, host, port, username)
        socks5_address = None
    else:
        socks4_request = None
        socks5_address = _socks5_address(scheme, host, port)
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=connect_timeout,
                                        source_address=source_address)
    except socket.timeout:
        raise ConnectTimeout("timed out connecting to SOCKS proxy %s" % label)
    except socket.gaierror as exc:
        raise ProxyError("could not resolve SOCKS proxy host %s: %s" % (proxy_host, exc),
                         code=CurlECode.COULDNT_RESOLVE_PROXY)
    except OSError as exc:
        raise ProxyError("could not connect to SOCKS proxy %s: %s" % (label, exc),
                         code=CurlECode.COULDNT_CONNECT)
    try:
        if socks4_request is not None:
            _socks4_handshake(sock, socks4_request, host, port, clock)
        else:
            _socks5_handshake(sock, socks5_address, host, port, username, password, clock)
        sock.settimeout(clock.timeout)
    except BaseException:
        try:
            sock.close()
        except OSError:
            pass
        raise
    return sock
