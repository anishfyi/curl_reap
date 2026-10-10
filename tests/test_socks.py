"""Tests for curl_reap.socks against in-process SOCKS4, SOCKS4a, SOCKS5 and SOCKS5h servers.

Each server records what the client sent, then forwards to a local echo HTTP
server so the tunnel is proven end to end.
"""
import http.server
import select
import socket
import struct
import threading
import time
from urllib.parse import quote, urlsplit

import pytest

from curl_reap import socks
from curl_reap.exceptions import (
    ConnectionError, ConnectTimeout, CurlECode, DNSError, InvalidSchema, ProxyError,
)
from curl_reap.socks import parse_socks_proxy, socks_connect


# ---------------------------------------------------------------- echo HTTP server

class EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("path=%s host=%s" % (self.path, self.headers.get("Host"))).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class EchoServer6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


def _start_http(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                              daemon=True)
    thread.start()
    return server


@pytest.fixture
def echo():
    server = _start_http(http.server.ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler))
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def echo6():
    try:
        server = EchoServer6(("::1", 0), EchoHandler)
    except OSError:
        pytest.skip("IPv6 loopback unavailable")
    _start_http(server)
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def http_get(sock, path="/hello", host="echo.test"):
    sock.settimeout(5)
    sock.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                  % (path, host)).encode("ascii"))
    chunks = b""
    while True:
        data = sock.recv(65536)
        if not data:
            break
        chunks += data
    return chunks.decode("utf-8")


# ---------------------------------------------------------------- recording SOCKS server

def _read_exact(conn, count):
    buf = b""
    while len(buf) < count:
        data = conn.recv(count - len(buf))
        if not data:
            raise EOFError("client closed")
        buf += data
    return buf


def _read_until_nul(conn):
    buf = b""
    while True:
        byte = _read_exact(conn, 1)
        if byte == b"\x00":
            return buf
        buf += byte


def _pump(a, b):
    while True:
        readable, _, _ = select.select([a, b], [], [], 5)
        if not readable:
            return
        for sock in readable:
            other = b if sock is a else a
            data = sock.recv(65536)
            if not data:
                return
            other.sendall(data)


class SocksServer(object):
    """A SOCKS4/4a/5 server that records each handshake in ``records``.

    ``users`` (dict) switches on authentication: SOCKS5 then requires the
    username/password method and SOCKS4 requires the user id to be a known
    user.  ``force_reply`` sends that reply code instead of connecting.
    ``hang`` accepts and never answers.  ``close_early`` closes right after
    the first byte.  ``bad_version`` answers with a wrong version byte.
    """

    def __init__(self, users=None, force_reply=None, hang=False, close_early=False,
                 bad_version=False):
        self.users = users
        self.force_reply = force_reply
        self.hang = hang
        self.close_early = close_early
        self.bad_version = bad_version
        self.records = []
        self._stop = threading.Event()
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._sock.settimeout(0.1)
        self.port = self._sock.getsockname()[1]
        self._threads = []
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def url(self, scheme, username=None, password=None, with_port=True):
        auth = ""
        if username is not None:
            auth = quote(username, safe="")
            if password is not None:
                auth += ":" + quote(password, safe="")
            auth += "@"
        port = ":%d" % self.port if with_port else ""
        return "%s://%s127.0.0.1%s" % (scheme, auth, port)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        self._stop.set()
        self._accept_thread.join(2)
        for thread in self._threads:
            thread.join(2)
        self._sock.close()

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            self._threads.append(thread)
            thread.start()

    def _handle(self, conn):
        record = {}
        self.records.append(record)
        conn.settimeout(5)
        try:
            if self.hang:
                self._stop.wait(5)
                return
            first = _read_exact(conn, 1)
            if self.close_early:
                return
            if first == b"\x04":
                self._socks4(conn, record)
            elif first == b"\x05":
                self._socks5(conn, record)
            else:
                record["error"] = "unknown version %r" % first
        except (EOFError, OSError) as exc:
            record["error"] = repr(exc)
        finally:
            conn.close()

    def _socks4(self, conn, record):
        head = _read_exact(conn, 7)
        command = head[0]
        port = struct.unpack("!H", head[1:3])[0]
        ip = head[3:7]
        user_id = _read_until_nul(conn).decode("utf-8")
        record.update(version=4, command=command, port=port, ip=socket.inet_ntoa(ip),
                      user_id=user_id)
        hostname = None
        if ip[:3] == b"\x00\x00\x00" and ip[3] != 0:
            hostname = _read_until_nul(conn).decode("utf-8")
            record["hostname"] = hostname
        if self.bad_version:
            conn.sendall(b"\x07\x5a" + b"\x00" * 6)
            return
        if self.force_reply is not None:
            conn.sendall(bytes([0, self.force_reply]) + b"\x00" * 6)
            return
        if self.users is not None and user_id not in self.users:
            conn.sendall(b"\x00\x5d" + b"\x00" * 6)
            return
        target = hostname if hostname is not None else record["ip"]
        try:
            upstream = socket.create_connection((target, port), timeout=5)
        except OSError as exc:
            record["connect_error"] = repr(exc)
            conn.sendall(b"\x00\x5b" + b"\x00" * 6)
            return
        with upstream:
            conn.sendall(b"\x00\x5a" + struct.pack("!H", port) + ip)
            _pump(conn, upstream)

    def _socks5(self, conn, record):
        count = _read_exact(conn, 1)[0]
        methods = list(_read_exact(conn, count))
        record.update(version=5, methods=methods)
        if self.users is not None:
            if 2 not in methods:
                conn.sendall(b"\x05\xff")
                return
            conn.sendall(b"\x05\x02")
            version = _read_exact(conn, 1)[0]
            ulen = _read_exact(conn, 1)[0]
            user = _read_exact(conn, ulen).decode("utf-8")
            plen = _read_exact(conn, 1)[0]
            password = _read_exact(conn, plen).decode("utf-8")
            record["auth"] = (version, user, password)
            if self.users.get(user) != password:
                conn.sendall(b"\x01\x01")
                return
            conn.sendall(b"\x01\x00")
        else:
            conn.sendall(b"\x05\x00")
        version, command, reserved, atyp = _read_exact(conn, 4)
        if atyp == 1:
            address = socket.inet_ntoa(_read_exact(conn, 4))
        elif atyp == 3:
            length = _read_exact(conn, 1)[0]
            address = _read_exact(conn, length).decode("utf-8")
        elif atyp == 4:
            address = socket.inet_ntop(socket.AF_INET6, _read_exact(conn, 16))
        else:
            record["error"] = "bad atyp %d" % atyp
            return
        port = struct.unpack("!H", _read_exact(conn, 2))[0]
        record.update(command=command, reserved=reserved, atyp=atyp, address=address, port=port)
        if self.bad_version:
            conn.sendall(b"\x09\x00\x00\x01" + b"\x00" * 6)
            return
        if self.force_reply is not None:
            conn.sendall(b"\x05" + bytes([self.force_reply]) + b"\x00\x01" + b"\x00" * 6)
            return
        try:
            upstream = socket.create_connection((address, port), timeout=5)
        except OSError as exc:
            record["connect_error"] = repr(exc)
            conn.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            return
        with upstream:
            bound = upstream.getsockname()
            if upstream.family == socket.AF_INET6:
                reply = (b"\x05\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, bound[0])
                         + struct.pack("!H", bound[1]))
            else:
                reply = b"\x05\x00\x00\x01" + socket.inet_aton(bound[0]) + struct.pack("!H", bound[1])
            conn.sendall(reply)
            _pump(conn, upstream)


def connect_and_get(proxy_url, host, port, **kwargs):
    kwargs.setdefault("timeout", 5)
    sock = socks_connect(proxy_url, host, port, **kwargs)
    try:
        return sock, http_get(sock)
    finally:
        sock.close()


# ---------------------------------------------------------------- SOCKS5

def test_socks5_no_auth_resolves_hostname_locally(echo):
    port = echo.server_address[1]
    with SocksServer() as proxy:
        _, body = connect_and_get(proxy.url("socks5"), "localhost", port)
        record = proxy.records[0]
    assert "path=/hello" in body and "host=echo.test" in body
    assert record["version"] == 5 and record["methods"] == [0]
    assert record["command"] == 1 and record["reserved"] == 0
    assert record["atyp"] == 1 and record["address"] == "127.0.0.1" and record["port"] == port


def test_socks5h_sends_hostname_for_remote_dns(echo):
    port = echo.server_address[1]
    with SocksServer() as proxy:
        _, body = connect_and_get(proxy.url("socks5h"), "localhost", port)
        record = proxy.records[0]
    assert "path=/hello" in body
    assert record["atyp"] == 3 and record["address"] == "localhost" and record["port"] == port


@pytest.mark.parametrize("scheme", ["socks5", "socks5h"])
def test_socks5_ipv4_literal_is_sent_as_an_address(echo, scheme):
    port = echo.server_address[1]
    with SocksServer() as proxy:
        _, body = connect_and_get(proxy.url(scheme), "127.0.0.1", port)
        record = proxy.records[0]
    assert "path=/hello" in body
    assert record["atyp"] == 1 and record["address"] == "127.0.0.1"


@pytest.mark.parametrize("scheme", ["socks5", "socks5h"])
@pytest.mark.parametrize("host", ["::1", "[::1]"])
def test_socks5_ipv6_literal_destination(echo6, scheme, host):
    port = echo6.server_address[1]
    with SocksServer() as proxy:
        _, body = connect_and_get(proxy.url(scheme), host, port)
        record = proxy.records[0]
    assert "path=/hello" in body
    assert record["atyp"] == 4 and record["address"] == "::1" and record["port"] == port


def test_socks5_username_password_rfc1929(echo):
    port = echo.server_address[1]
    with SocksServer(users={"alice": "p@ss w0rd"}) as proxy:
        _, body = connect_and_get(proxy.url("socks5h", "alice", "p@ss w0rd"), "localhost", port)
        record = proxy.records[0]
    assert "path=/hello" in body
    assert record["methods"] == [0, 2]
    assert record["auth"] == (1, "alice", "p@ss w0rd")


def test_socks5_credentials_offered_but_proxy_picks_no_auth(echo):
    port = echo.server_address[1]
    with SocksServer() as proxy:
        _, body = connect_and_get(proxy.url("socks5", "alice", "secret"), "localhost", port)
        record = proxy.records[0]
    assert "path=/hello" in body
    assert record["methods"] == [0, 2] and "auth" not in record


def test_socks5_authentication_failure(echo):
    port = echo.server_address[1]
    with SocksServer(users={"alice": "secret"}) as proxy:
        with pytest.raises(ProxyError, match="username/password authentication") as info:
            socks_connect(proxy.url("socks5", "alice", "wrong"), "localhost", port, timeout=5)
    assert info.value.code == CurlECode.PROXY == 97
    assert isinstance(info.value, ConnectionError)


def test_socks5_no_acceptable_method(echo):
    port = echo.server_address[1]
    with SocksServer(users={"alice": "secret"}) as proxy:
        with pytest.raises(ProxyError, match="no offered authentication method") as info:
            socks_connect(proxy.url("socks5"), "localhost", port, timeout=5)
        assert proxy.records[0]["methods"] == [0]
    assert info.value.code == 97


@pytest.mark.parametrize("code, text", sorted(socks.SOCKS5_REPLIES.items())[1:] + [(9, "unknown reply code 9")])
def test_socks5_reply_codes_map_to_rfc_1928_text(code, text):
    with SocksServer(force_reply=code) as proxy:
        with pytest.raises(ProxyError, match=text) as info:
            socks_connect(proxy.url("socks5h"), "example.test", 80, timeout=5)
    assert info.value.code == 97
    assert "example.test:80" in str(info.value)


def test_socks5_upstream_connection_refused_reports_the_proxy_reply():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()
    with SocksServer() as proxy:
        with pytest.raises(ProxyError, match="Connection refused"):
            socks_connect(proxy.url("socks5"), "127.0.0.1", closed_port, timeout=5)


def test_socks5_proxy_closing_early_is_a_proxy_error():
    with SocksServer(close_early=True) as proxy:
        with pytest.raises(ProxyError, match="closed the connection"):
            socks_connect(proxy.url("socks5h"), "example.test", 80, timeout=5)


def test_socks5_malformed_reply_version():
    with SocksServer(bad_version=True) as proxy:
        with pytest.raises(ProxyError, match="malformed SOCKS5 reply"):
            socks_connect(proxy.url("socks5h"), "example.test", 80, timeout=5)


def test_socks5h_hostname_too_long_is_rejected_before_sending():
    with SocksServer() as proxy:
        with pytest.raises(ProxyError, match="1 to 255 bytes"):
            socks_connect(proxy.url("socks5h"), "a" * 256 + ".test", 80, timeout=5)


def test_socks5h_idna_hostname_is_encoded():
    with SocksServer(force_reply=4) as proxy:
        with pytest.raises(ProxyError, match="Host unreachable"):
            socks_connect(proxy.url("socks5h"), "b\u00fccher.example", 80, timeout=5)
        assert proxy.records[0]["address"] == "xn--bcher-kva.example"


def test_socks5_local_dns_failure_is_dns_error(monkeypatch):
    real = socket.getaddrinfo

    def fake(host, *args, **kwargs):
        if host == "nonexistent.invalid":
            raise socket.gaierror(8, "nodename nor servname provided")
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with SocksServer() as proxy:
        with pytest.raises(DNSError, match="nonexistent.invalid") as info:
            socks_connect(proxy.url("socks5"), "nonexistent.invalid", 80, timeout=5)
    assert info.value.code == CurlECode.COULDNT_RESOLVE_HOST


# ---------------------------------------------------------------- SOCKS4 / SOCKS4a

def test_socks4_resolves_locally_and_sends_user_id(echo):
    port = echo.server_address[1]
    with SocksServer() as proxy:
        _, body = connect_and_get(proxy.url("socks4", "alice"), "localhost", port)
        record = proxy.records[0]
    assert "path=/hello" in body
    assert record["version"] == 4 and record["command"] == 1
    assert record["ip"] == "127.0.0.1" and record["port"] == port
    assert record["user_id"] == "alice" and "hostname" not in record


def test_socks4_without_user_sends_empty_user_id(echo):
    port = echo.server_address[1]
    with SocksServer() as proxy:
        _, body = connect_and_get(proxy.url("socks4"), "127.0.0.1", port)
        record = proxy.records[0]
    assert "path=/hello" in body
    assert record["user_id"] == "" and record["ip"] == "127.0.0.1" and "hostname" not in record


def test_socks4a_sends_hostname_for_remote_dns(echo):
    port = echo.server_address[1]
    with SocksServer() as proxy:
        _, body = connect_and_get(proxy.url("socks4a", "bob"), "localhost", port)
        record = proxy.records[0]
    assert "path=/hello" in body
    assert record["ip"] == "0.0.0.1" and record["hostname"] == "localhost"
    assert record["user_id"] == "bob" and record["port"] == port


def test_socks4a_ipv4_literal_is_sent_as_an_address(echo):
    port = echo.server_address[1]
    with SocksServer() as proxy:
        _, body = connect_and_get(proxy.url("socks4a"), "127.0.0.1", port)
        record = proxy.records[0]
    assert "path=/hello" in body
    assert record["ip"] == "127.0.0.1" and "hostname" not in record


def test_socks4a_ipv6_literal_goes_to_the_proxy_as_a_name(echo6):
    port = echo6.server_address[1]
    with SocksServer() as proxy:
        _, body = connect_and_get(proxy.url("socks4a"), "::1", port)
        record = proxy.records[0]
    assert "path=/hello" in body
    assert record["ip"] == "0.0.0.1" and record["hostname"] == "::1"


def test_socks4_cannot_address_ipv6():
    with SocksServer() as proxy:
        with pytest.raises(ProxyError, match="IPv6"):
            socks_connect(proxy.url("socks4"), "::1", 80, timeout=5)
        assert proxy.records == []


def test_socks4_user_id_must_not_contain_nul():
    with SocksServer() as proxy:
        with pytest.raises(ValueError):
            socks_connect(proxy.url("socks4", "a\x00b"), "127.0.0.1", 80, timeout=5)


@pytest.mark.parametrize("code, text", [
    (91, "request rejected or failed"),
    (92, "cannot connect to identd"),
    (93, "identd report different user-ids"),
    (94, "unknown reply code 94"),
])
def test_socks4_reply_codes_map_to_protocol_text(code, text):
    with SocksServer(force_reply=code) as proxy:
        with pytest.raises(ProxyError, match=text) as info:
            socks_connect(proxy.url("socks4a"), "example.test", 80, timeout=5)
    assert info.value.code == 97


def test_socks4_unknown_user_is_rejected_by_identd_rule():
    with SocksServer(users={"alice": ""}) as proxy:
        with pytest.raises(ProxyError, match="identd report different user-ids"):
            socks_connect(proxy.url("socks4", "mallory"), "127.0.0.1", 80, timeout=5)


def test_socks4_malformed_reply_version():
    with SocksServer(bad_version=True) as proxy:
        with pytest.raises(ProxyError, match="malformed SOCKS4 reply"):
            socks_connect(proxy.url("socks4"), "127.0.0.1", 80, timeout=5)


def test_socks4_local_dns_failure_is_dns_error(monkeypatch):
    real = socket.getaddrinfo

    def fake(host, *args, **kwargs):
        if host == "nonexistent.invalid":
            raise socket.gaierror(8, "nodename nor servname provided")
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with SocksServer() as proxy:
        with pytest.raises(DNSError):
            socks_connect(proxy.url("socks4"), "nonexistent.invalid", 80, timeout=5)


# ---------------------------------------------------------------- timeouts and reachability

@pytest.mark.parametrize("scheme", ["socks4", "socks5h"])
def test_hanging_proxy_times_out(scheme):
    with SocksServer(hang=True) as proxy:
        started = time.monotonic()
        with pytest.raises(ConnectTimeout) as info:
            socks_connect(proxy.url(scheme), "127.0.0.1", 80, timeout=0.3)
        elapsed = time.monotonic() - started
    assert 0.2 < elapsed < 3
    assert info.value.code == CurlECode.OPERATION_TIMEDOUT
    assert isinstance(info.value, ConnectionError)


def test_deadline_bounds_the_handshake_without_a_timeout():
    with SocksServer(hang=True) as proxy:
        started = time.monotonic()
        with pytest.raises(ConnectTimeout):
            socks_connect(proxy.url("socks5"), "127.0.0.1", 80, timeout=None,
                          deadline=time.monotonic() + 0.3)
        assert time.monotonic() - started < 3


def test_deadline_already_passed_fails_before_connecting():
    with SocksServer() as proxy:
        with pytest.raises(ConnectTimeout, match="deadline"):
            socks_connect(proxy.url("socks5"), "127.0.0.1", 80, timeout=5,
                          deadline=time.monotonic() - 1)
        time.sleep(0.05)
        assert proxy.records == []


def test_deadline_shorter_than_timeout_wins():
    with SocksServer(hang=True) as proxy:
        started = time.monotonic()
        with pytest.raises(ConnectTimeout):
            socks_connect(proxy.url("socks5"), "127.0.0.1", 80, timeout=10,
                          deadline=time.monotonic() + 0.3)
        assert time.monotonic() - started < 3


def test_connection_refused_by_proxy_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()
    with pytest.raises(ProxyError, match="could not connect to SOCKS proxy") as info:
        socks_connect("socks5h://127.0.0.1:%d" % closed_port, "example.test", 80, timeout=5)
    assert info.value.code == CurlECode.COULDNT_CONNECT


def test_unresolvable_proxy_host(monkeypatch):
    def fake(address, timeout=None, source_address=None):
        raise socket.gaierror(8, "nodename nor servname provided")

    monkeypatch.setattr(socks.socket, "create_connection", fake)
    with pytest.raises(ProxyError, match="could not resolve SOCKS proxy host") as info:
        socks_connect("socks5h://proxy.invalid", "example.test", 80, timeout=5)
    assert info.value.code == CurlECode.COULDNT_RESOLVE_PROXY


def test_proxy_connect_timeout():
    def fake(address, timeout=None, source_address=None):
        raise socket.timeout("timed out")

    original = socks.socket.create_connection
    socks.socket.create_connection = fake
    try:
        with pytest.raises(ConnectTimeout, match="timed out connecting"):
            socks_connect("socks5h://proxy.test", "example.test", 80, timeout=0.1)
    finally:
        socks.socket.create_connection = original


def test_default_proxy_port_is_1080(monkeypatch):
    seen = {}

    def fake(address, timeout=None, source_address=None):
        seen["address"] = address
        seen["timeout"] = timeout
        seen["source_address"] = source_address
        raise OSError("refused")

    monkeypatch.setattr(socks.socket, "create_connection", fake)
    with pytest.raises(ProxyError):
        socks_connect("socks5h://proxy.test", "example.test", 80, timeout=7,
                      source_address=("127.0.0.1", 0))
    assert seen == {"address": ("proxy.test", 1080), "timeout": 7.0,
                    "source_address": ("127.0.0.1", 0)}


def test_returned_socket_timeout_is_restored(echo):
    port = echo.server_address[1]
    with SocksServer() as proxy:
        sock = socks_connect(proxy.url("socks5h"), "localhost", port, timeout=5,
                             deadline=time.monotonic() + 1)
        try:
            assert sock.gettimeout() == 5.0
        finally:
            sock.close()
        sock = socks_connect(proxy.url("socks5h"), "localhost", port, timeout=None,
                             deadline=time.monotonic() + 1)
        try:
            assert sock.gettimeout() is None
            assert "path=/hello" in http_get(sock)
        finally:
            sock.close()


def test_source_address_is_honoured(echo):
    port = echo.server_address[1]
    with SocksServer() as proxy:
        sock = socks_connect(proxy.url("socks5"), "127.0.0.1", port, timeout=5,
                             source_address=("127.0.0.1", 0))
        try:
            assert sock.getsockname()[0] == "127.0.0.1"
            assert "path=/hello" in http_get(sock)
        finally:
            sock.close()


# ---------------------------------------------------------------- URL parsing

def test_parse_socks_proxy_defaults_and_decoding():
    assert parse_socks_proxy("socks5://proxy.test") == ("socks5", "proxy.test", 1080, None, None)
    assert parse_socks_proxy("SOCKS4A://u%40x:p%3Aw@[::1]:9050") == (
        "socks4a", "::1", 9050, "u@x", "p:w")
    assert parse_socks_proxy(urlsplit("socks5h://only-user@h:1")) == (
        "socks5h", "h", 1, "only-user", None)


@pytest.mark.parametrize("url", ["http://proxy.test", "socks6://x", "proxy.test:1080", "socks://x"])
def test_parse_socks_proxy_rejects_other_schemes(url):
    with pytest.raises(InvalidSchema) as info:
        parse_socks_proxy(url)
    assert isinstance(info.value, ValueError)


@pytest.mark.parametrize("url", ["socks5://", "socks5://:1080", "socks5://host:notaport"])
def test_parse_socks_proxy_rejects_missing_host_or_bad_port(url):
    with pytest.raises(ProxyError):
        parse_socks_proxy(url)


def test_socks_connect_accepts_a_splitresult_and_validates_arguments(echo):
    port = echo.server_address[1]
    with SocksServer() as proxy:
        sock = socks_connect(urlsplit(proxy.url("socks5h")), "localhost", port, timeout=5)
        try:
            assert "path=/hello" in http_get(sock)
        finally:
            sock.close()
        with pytest.raises(ValueError):
            socks_connect(proxy.url("socks5"), "localhost", 70000, timeout=5)
        with pytest.raises(ValueError):
            socks_connect(proxy.url("socks5"), "", 80, timeout=5)
        with pytest.raises(InvalidSchema):
            socks_connect("http://127.0.0.1:%d" % proxy.port, "localhost", port, timeout=5)
