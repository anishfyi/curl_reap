"""The OpenSSL fallback for TLS-1.2-only servers must stay on the proxy.

When the native engine learns from the ServerHello that a server only speaks
TLS 1.2, the transport closes that connection and dials again for OpenSSL.
In the 2.0.0 merge that second dial went straight to the server: through a
SOCKS proxy the request then left from the machine's own address, and
through an HTTP proxy a direct connection was opened (and dropped) before
the tunnelled one. Every connection the server sees here must come out of
the proxy.
"""
import os
import select
import socket
import ssl
import struct
import sys
import threading
from urllib.parse import urlsplit

import pytest

import curl_reap
from curl_reap import transport as transport_mod
from curl_reap.exceptions import TransportError
from curl_reap.tls import resolve_profile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_fake_server import make_ca, make_leaf, write_pem  # noqa: E402


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("tls12-proxy")
    ca_cert, ca_key = make_ca()
    # An RSA leaf: the OpenSSL path offers only the X25519 group, and a TLS 1.2
    # server cannot pair that with a P-256 ECDSA certificate.
    leaf, key = make_leaf(ca_cert, ca_key, hostnames=("localhost",), ips=("127.0.0.1",),
                          rsa=True)
    paths = {"ca": str(tmp / "ca.pem"), "chain": str(tmp / "chain.pem")}
    write_pem(paths["ca"], ca_cert)
    write_pem(paths["chain"], leaf, ca_cert, key=key)
    return paths


def _listener():
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    return sock


class TLS12Server:
    """HTTPS that tops out at TLS 1.2; records the peer of every TCP connection."""

    def __init__(self, pki):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(pki["chain"])
        self.ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        self.ctx.set_alpn_protocols(["http/1.1"])
        self.sock = _listener()
        self.url = "https://127.0.0.1:%d/" % self.sock.getsockname()[1]
        self.peers = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                raw, peer = self.sock.accept()
            except OSError:
                return
            # Recorded before the handshake: a connection that is opened and
            # dropped still reached this server.
            self.peers.append(peer[:2])
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw):
        raw.settimeout(10)
        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()  # the native attempt hangs up after the ServerHello
            return
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except (ssl.SSLError, OSError):
            pass
        finally:
            conn.close()

    def stop(self):
        self.sock.close()


def _read_exact(conn, count):
    buf = b""
    while len(buf) < count:
        data = conn.recv(count - len(buf))
        if not data:
            raise EOFError("client closed")
        buf += data
    return buf


def _pump(a, b):
    while True:
        readable, _, _ = select.select([a, b], [], [], 10)
        if not readable:
            return
        for sock in readable:
            other = b if sock is a else a
            try:
                data = sock.recv(65536)
            except OSError:
                return
            if not data:
                return
            other.sendall(data)


class RecordingProxy:
    """A SOCKS5 or HTTP CONNECT proxy that records each upstream socket's address."""

    def __init__(self, kind):
        self.kind = kind
        self.sock = _listener()
        port = self.sock.getsockname()[1]
        self.url = "%s://127.0.0.1:%d" % (kind, port)
        self.upstreams = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        conn.settimeout(10)
        try:
            if self.kind == "http":
                host, port = self._connect_request(conn)
            else:
                host, port = self._socks5_request(conn)
            upstream = socket.create_connection((host, port), timeout=10)
            self.upstreams.append(upstream.getsockname()[:2])
            with upstream:
                if self.kind == "http":
                    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                else:
                    bound = upstream.getsockname()
                    conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(bound[0])
                                 + struct.pack("!H", bound[1]))
                _pump(conn, upstream)
        except (EOFError, OSError, ValueError):
            pass
        finally:
            conn.close()

    @staticmethod
    def _connect_request(conn):
        head = b""
        while b"\r\n\r\n" not in head:
            data = conn.recv(4096)
            if not data:
                raise EOFError("client closed")
            head += data
        method, authority, _ = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
        if method != "CONNECT":
            raise ValueError("not a CONNECT request")
        host, port = authority.rsplit(":", 1)
        return host.strip("[]"), int(port)

    @staticmethod
    def _socks5_request(conn):
        count = _read_exact(conn, 1 + 1)[1]
        _read_exact(conn, count)
        conn.sendall(b"\x05\x00")
        _, command, _, atyp = _read_exact(conn, 4)
        if command != 1:
            raise ValueError("only CONNECT")
        if atyp == 1:
            host = socket.inet_ntoa(_read_exact(conn, 4))
        elif atyp == 3:
            host = _read_exact(conn, _read_exact(conn, 1)[0]).decode("idna")
        else:
            host = socket.inet_ntop(socket.AF_INET6, _read_exact(conn, 16))
        port = struct.unpack("!H", _read_exact(conn, 2))[0]
        return host, port

    def stop(self):
        self.sock.close()


@pytest.mark.parametrize("kind", ["socks5", "socks5h", "http"])
def test_tls12_fallback_reconnects_through_the_proxy(pki, kind):
    server = TLS12Server(pki)
    proxy = RecordingProxy(kind)
    try:
        session = curl_reap.Session(proxy=proxy.url, verify=pki["ca"], retries=0,
                                    trust_env=False)
        try:
            r = session.get(server.url, timeout=10)
        finally:
            session.close()
        assert r.status == 200 and r.content == b"ok"
        assert r.infos["tls_backend"] == "openssl"
        assert r.infos["tls_version"] == "TLSv1.2"
        # The native attempt and the OpenSSL fallback both went through the proxy ...
        assert len(proxy.upstreams) == 2
        # ... and nothing reached the server from anywhere else.
        direct = [peer for peer in server.peers if peer not in proxy.upstreams]
        assert direct == []
        assert len(server.peers) == 2
    finally:
        server.stop()
        proxy.stop()


def test_tls12_fallback_through_an_https_proxy_never_dials_the_server(monkeypatch):
    """The fallback cannot nest OpenSSL TLS in the proxy's TLS; it must fail
    without dialing the server directly first."""
    from curl_reap._tls.errors import TLS12Negotiated

    dials = []

    def fake_create_connection(self, host, port, timeout, deadline):
        dials.append((host, port))
        a, b = socket.socketpair()
        b.close()
        return a

    def fake_native_wrap(sock, *args, **kwargs):
        raise TLS12Negotiated("server selected TLS 1.2", 0x0303)

    monkeypatch.setattr(transport_mod._Transport, "_create_connection", fake_create_connection)
    monkeypatch.setattr("curl_reap._tls.wrap_socket", fake_native_wrap)
    t = transport_mod._Transport()
    first, other = socket.socketpair()
    other.close()
    with pytest.raises(TransportError, match="https proxy"):
        t._tls_wrap(first, "server.test", 443, urlsplit("https://proxy.test:8443"),
                    resolve_profile("chrome"), True, ("h2", "http/1.1"),
                    5, 5, None, None, True)
    assert ("server.test", 443) not in dials
    assert dials == []
