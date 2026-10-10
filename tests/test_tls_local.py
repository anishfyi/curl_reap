"""The native engine against the standard library's OpenSSL TLS 1.3 server.

A CA generated with cryptography signs a leaf for localhost; the tests pass
``verify=<ca path>``. Cipher suites are forced from the client side (the
stdlib exposes no ``set_ciphersuites``), HelloRetryRequest by restricting the
server to P-256, resumption through OpenSSL's stateless tickets.
"""
import asyncio
import hashlib
import os
import socket
import ssl
import sys
import threading
import time
from dataclasses import replace

import pytest

from curl_reap._tls import (
    GREASE,
    CertificateError,
    SessionCache,
    TLS12Negotiated,
    TLSAlertReceived,
    TLSError,
    async_wrap_socket,
    template,
    wrap_socket,
)
from curl_reap.exceptions import ConnectTimeout, ReadTimeout, Timeout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_fake_server import make_ca, make_leaf, write_pem  # noqa: E402

TLS12_SUITES = [0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("local-pki")
    ca_cert, ca_key = make_ca()
    leaf, key = make_leaf(ca_cert, ca_key, hostnames=("localhost",), ips=("127.0.0.1",))
    other_ca, _ = make_ca("untrusted CA")
    paths = {
        "ca": str(tmp / "ca.pem"),
        "chain": str(tmp / "chain.pem"),
        "other": str(tmp / "other.pem"),
    }
    write_pem(paths["ca"], ca_cert)
    write_pem(paths["chain"], leaf, ca_cert, key=key)
    write_pem(paths["other"], other_ca)
    return paths


def server_context(pki, **kw):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki["chain"])
    ctx.set_alpn_protocols(kw.pop("alpn", ["h2", "http/1.1"]))
    for key, value in kw.items():
        setattr(ctx, key, value)
    return ctx


class SSLServer:
    """Accept ``connections`` clients, wrap each with ``ctx``, run ``handler``."""

    def __init__(self, ctx, handler, connections=1, wrap=True):
        self.ctx = ctx
        self.handler = handler
        self.wrap = wrap
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.connections = connections
        self.errors = []
        self.results = []
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        for _ in range(self.connections):
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            conn.settimeout(15)
            try:
                if self.wrap:
                    tls = self.ctx.wrap_socket(conn, server_side=True)
                    self.results.append(self.handler(tls))
                else:
                    self.results.append(self.handler(conn))
            except BaseException as exc:  # noqa: BLE001
                self.errors.append(exc)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def join(self, timeout=15):
        self.thread.join(timeout)
        self.sock.close()
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.join()


def echo_handler(tls):
    """Echo until the client sends close_notify, then send ours."""
    info = {"reused": tls.session_reused, "cipher": tls.cipher(), "alpn": tls.selected_alpn_protocol()}
    while True:
        data = tls.recv(65536)
        if not data:
            break
        tls.sendall(data)
    try:
        tls.unwrap()
    except (ssl.SSLError, OSError):
        pass
    return info


def echo_once_then_close(tls):
    data = tls.recv(100)
    tls.sendall(b"echo:" + data)
    info = {"reused": tls.session_reused}
    tls.unwrap()
    return info


def connect(port, name="chrome", **kw):
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    tpl = kw.pop("template", template(name))
    server_name = kw.pop("server_name", "localhost")
    return wrap_socket(sock, server_name, tpl, timeout=kw.pop("timeout", 10), **kw)


def restricted(name, suite):
    tpl = template(name)
    return replace(tpl, ciphers=[c for c in tpl.ciphers if c == GREASE or c == suite or c in TLS12_SUITES])


@pytest.mark.parametrize("suite,expected", [
    (0x1301, "TLS_AES_128_GCM_SHA256"),
    (0x1302, "TLS_AES_256_GCM_SHA384"),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
])
def test_cipher_suites(pki, suite, expected):
    with SSLServer(server_context(pki), echo_once_then_close) as srv:
        tls = connect(srv.port, template=restricted("chrome", suite), verify=pki["ca"])
        assert tls.cipher()[0] == expected and tls.cipher()[1] == "TLSv1.3"
        assert tls.version() == "TLSv1.3"
        tls.sendall(b"ping")
        assert tls.recv(100) == b"echo:ping"
        assert tls.recv(100) == b"", "close_notify ends the stream"
        assert tls.closed
        tls.close()
    assert not srv.errors


def test_handshake_details_and_socket_surface(pki):
    with SSLServer(server_context(pki), echo_handler) as srv:
        tls = connect(srv.port, verify=pki["ca"])
        info = tls.handshake_info
        assert tls.selected_alpn_protocol() == "h2"
        assert tls.negotiated_group in ("X25519MLKEM768", "X25519")
        assert not tls.resumed and not info.hello_retry and info.cert_verified is True
        assert isinstance(tls.getpeercert(binary_form=True), bytes)
        assert tls.getpeercert(binary_form=False)["subject"]
        assert len(tls.getpeercertchain()) == 2
        assert tls.fileno() > 0 and tls.getpeername()[1] == srv.port and tls.getsockname()[0] == "127.0.0.1"
        assert tls.gettimeout() == 10
        tls.settimeout(3)
        assert tls.gettimeout() == 3
        assert tls.pending() == 0
        assert tls.handshake_cpu_seconds >= 0
        tls.sendall(b"abc")
        assert tls.recv(1) == b"a" and tls.pending() == 2 and tls.recv(10) == b"bc"
        tls.close()
        tls.close()  # idempotent
        with pytest.raises(OSError):
            tls.sendall(b"after close")
    assert not srv.errors and srv.results[0]["alpn"] == "h2"


def test_alpn_override(pki):
    with SSLServer(server_context(pki), echo_once_then_close) as srv:
        tls = connect(srv.port, verify=pki["ca"], alpn=("http/1.1",))
        assert tls.selected_alpn_protocol() == "http/1.1"
        tls.close()


def test_hello_retry_request_p256(pki):
    ctx = server_context(pki)
    ctx.set_ecdh_curve("prime256v1")
    with SSLServer(ctx, echo_once_then_close) as srv:
        tls = connect(srv.port, verify=pki["ca"])
        assert tls.handshake_info.hello_retry is True
        assert tls.negotiated_group == "P-256"
        assert tls.client.stats["ccs_records_in"] >= 1
        tls.sendall(b"hrr")
        assert tls.recv(100) == b"echo:hrr"
        tls.close()
    assert not srv.errors


@pytest.mark.parametrize("name,groups", [
    ("firefox", ("X25519MLKEM768",)),
    ("edge", ("X25519",)),
    ("safari", ("X25519MLKEM768",)),
    ("tor145", ("X25519",)),
    ("chrome_android", ("X25519",)),
])
def test_templates_handshake_with_openssl(pki, name, groups):
    with SSLServer(server_context(pki), echo_once_then_close) as srv:
        tls = connect(srv.port, name=name, verify=pki["ca"])
        assert tls.negotiated_group in groups + ("X25519",)
        tls.sendall(b"x")
        assert tls.recv(100) == b"echo:x"
        tls.close()
    assert not srv.errors


def test_key_update_both_directions(pki):
    with SSLServer(server_context(pki), echo_handler) as srv:
        tls = connect(srv.port, verify=pki["ca"])
        tls.key_update(request_peer=True)
        tls.sendall(b"after update")
        assert tls.recv(100) == b"after update"
        assert tls.client.key_updates_sent == 1
        assert tls.client.key_updates_received == 1, "OpenSSL answers update_requested with its own KeyUpdate"
        tls.key_update()
        tls.sendall(b"second")
        assert tls.recv(100) == b"second"
        tls.close()
    assert not srv.errors


def test_resumption_with_session_cache(pki):
    ctx = server_context(pki)
    cache = SessionCache()
    with SSLServer(ctx, echo_once_then_close, connections=3) as srv:
        first = connect(srv.port, verify=pki["ca"], session_cache=cache)
        assert not first.resumed and not first.client.offering_psk
        first.sendall(b"1")
        assert first.recv(100) == b"echo:1" and first.recv(100) == b""
        first.close()
        assert len(cache) == 2, "OpenSSL sends two tickets; the cache keeps two per host"
        chain = first.getpeercertchain()

        second = connect(srv.port, verify=pki["ca"], session_cache=cache)
        assert second.resumed is True and second.handshake_info.resumed
        assert second.client.offering_psk
        assert second.getpeercertchain() == chain, "the peer chain comes from the ticket"
        assert second.getpeercert() == chain[0]
        second.sendall(b"2")
        assert second.recv(100) == b"echo:2"
        second.close()
        assert len(cache) == 2, "a resumed handshake refills the cache"

        third = connect(srv.port, verify=pki["ca"], session_cache=cache)
        assert third.resumed is True
        third.close()
    assert not srv.errors
    assert [r["reused"] for r in srv.results] == [False, True, True]


def test_resumption_rejected_by_a_server_with_other_keys(pki):
    cache = SessionCache()
    with SSLServer(server_context(pki), echo_once_then_close) as srv:
        tls = connect(srv.port, verify=pki["ca"], session_cache=cache)
        tls.sendall(b"a")
        tls.recv(100)
        tls.close()
    assert len(cache) == 2
    # A fresh context has fresh ticket keys, so the PSK is rejected and the
    # server completes a full handshake instead.
    with SSLServer(server_context(pki), echo_once_then_close) as srv2:
        tls = connect(srv2.port, verify=pki["ca"], session_cache=cache)
        assert tls.client.offering_psk and tls.resumed is False
        assert tls.handshake_info.cert_verified is True
        tls.sendall(b"b")
        assert tls.recv(100) == b"echo:b"
        tls.close()
    assert not srv2.errors and srv2.results[0]["reused"] is False


def test_hostname_mismatch(pki):
    with SSLServer(server_context(pki), echo_once_then_close) as srv:
        with pytest.raises(CertificateError) as info:
            connect(srv.port, verify=pki["ca"], server_name="wrong.example")
        assert info.value.code == 60
        assert "wrong.example" in str(info.value)


def test_untrusted_ca(pki):
    with SSLServer(server_context(pki), echo_once_then_close) as srv:
        with pytest.raises(CertificateError) as info:
            connect(srv.port, verify=pki["other"])
        assert info.value.code == 60


def test_verify_false_still_parses_the_chain(pki):
    with SSLServer(server_context(pki), echo_once_then_close) as srv:
        tls = connect(srv.port, verify=False, server_name="wrong.example")
        assert tls.handshake_info.cert_verified is None
        assert len(tls.getpeercertchain()) == 2 and tls.getpeercert().startswith(b"\x30")
        tls.sendall(b"v")
        assert tls.recv(100) == b"echo:v"
        tls.close()


def test_default_trust_store_rejects_a_private_ca(pki):
    with SSLServer(server_context(pki), echo_once_then_close) as srv:
        with pytest.raises(CertificateError):
            connect(srv.port, verify=True)


def test_close_notify_from_client_is_seen_by_server(pki):
    with SSLServer(server_context(pki), echo_handler) as srv:
        tls = connect(srv.port, verify=pki["ca"])
        tls.sendall(b"bye")
        assert tls.recv(100) == b"bye"
        tls.close()
    assert not srv.errors, "unwrap() on the server needs the client's close_notify"


def test_shutdown_sends_close_notify(pki):
    with SSLServer(server_context(pki), echo_handler) as srv:
        tls = connect(srv.port, verify=pki["ca"])
        tls.shutdown(socket.SHUT_WR)
        assert tls.client.close_sent
        assert tls.recv(10) == b""
        tls.close()
    assert not srv.errors


def test_large_transfer_5mb_each_way(pki):
    size = 5 * 1024 * 1024
    payload = os.urandom(size)

    def sink_then_send(tls):
        got = bytearray()
        while len(got) < size:
            chunk = tls.recv(1 << 16)
            if not chunk:
                break
            got += chunk
        tls.sendall(payload)
        tls.unwrap()
        return hashlib.sha256(got).hexdigest()

    with SSLServer(server_context(pki), sink_then_send) as srv:
        tls = connect(srv.port, verify=pki["ca"])
        tls.sendall(payload)
        got = bytearray()
        while True:
            chunk = tls.recv(1 << 16)
            if not chunk:
                break
            got += chunk
        tls.close()
    assert not srv.errors
    assert srv.results[0] == hashlib.sha256(payload).hexdigest()
    assert hashlib.sha256(bytes(got)).hexdigest() == hashlib.sha256(payload).hexdigest()


def test_tls12_only_server_raises_tls12negotiated(pki):
    ctx = server_context(pki)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2

    def handler(tls):
        return tls.version()

    with SSLServer(ctx, handler) as srv:
        with pytest.raises(TLS12Negotiated) as info:
            connect(srv.port, verify=pki["ca"])
        assert info.value.negotiated == 0x0303
        assert info.value.code == 35
        assert isinstance(info.value, TLSError)


def test_certificate_request_answered_with_empty_certificate(pki):
    ctx = server_context(pki)
    ctx.load_verify_locations(pki["ca"])
    ctx.verify_mode = ssl.CERT_OPTIONAL
    with SSLServer(ctx, echo_once_then_close) as srv:
        tls = connect(srv.port, verify=pki["ca"])
        assert tls.handshake_info.certificate_request is True
        tls.sendall(b"cr")
        assert tls.recv(100) == b"echo:cr"
        tls.close()
    assert not srv.errors


def test_server_requiring_a_client_certificate_sends_an_alert(pki):
    ctx = server_context(pki)
    ctx.load_verify_locations(pki["ca"])
    ctx.verify_mode = ssl.CERT_REQUIRED
    with SSLServer(ctx, echo_once_then_close) as srv:
        # TLS 1.3 delivers the server's Finished before our (empty) Certificate,
        # so the handshake completes locally and the rejection is the first
        # record read afterwards.
        tls = connect(srv.port, verify=pki["ca"])
        assert tls.handshake_info.certificate_request is True
        with pytest.raises(TLSAlertReceived) as info:
            tls.sendall(b"x")
            tls.recv(100)
        assert info.value.name == "certificate_required"
        tls.close()


def test_handshake_timeouts(pki):
    def silent(conn):
        time.sleep(1.5)
        return None

    with SSLServer(server_context(pki), silent, wrap=False) as srv:
        sock = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
        with pytest.raises(ConnectTimeout):
            wrap_socket(sock, "localhost", template("chrome"), verify=pki["ca"], timeout=0.3)
        sock.close()
    with SSLServer(server_context(pki), silent, wrap=False) as srv:
        sock = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
        with pytest.raises(ConnectTimeout):
            wrap_socket(sock, "localhost", template("chrome"), verify=pki["ca"], deadline=time.monotonic() - 1)
        sock.close()


def test_read_timeout_and_deadline_after_handshake(pki):
    def hold(tls):
        time.sleep(1.2)
        return None

    with SSLServer(server_context(pki), hold) as srv:
        tls = connect(srv.port, verify=pki["ca"])
        tls.settimeout(0.2)
        with pytest.raises(ReadTimeout) as info:
            tls.recv(10)
        assert isinstance(info.value, Timeout) and info.value.code == 28
        tls.close()
    with SSLServer(server_context(pki), hold) as srv:
        tls = connect(srv.port, verify=pki["ca"])
        tls.deadline = time.monotonic() + 0.2
        with pytest.raises(ReadTimeout):
            tls.recv(10)
        with pytest.raises(ReadTimeout):
            tls.sendall(b"past the deadline")
        tls.close()


def test_eof_during_handshake(pki):
    def drop(conn):
        conn.recv(10)
        return None

    with SSLServer(server_context(pki), drop, wrap=False) as srv:
        sock = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
        with pytest.raises(TLSError) as info:
            wrap_socket(sock, "localhost", template("chrome"), verify=pki["ca"], timeout=5)
        assert "EOF" in str(info.value) or "reset" in str(info.value)
        assert info.value.code == 35
        sock.close()


def test_eof_without_close_notify_after_handshake(pki):
    def abrupt(tls):
        tls.recv(10)
        tls._sslobj = None  # drop without close_notify
        return None

    with SSLServer(server_context(pki), abrupt) as srv:
        tls = connect(srv.port, verify=pki["ca"])
        tls.sendall(b"x")
        assert tls.recv(10) == b""
        assert tls.closed and tls._closed_event.reason == "eof"
        tls.close()


def test_async_driver(pki):
    with SSLServer(server_context(pki), echo_handler) as srv:
        async def run():
            reader, writer = await asyncio.open_connection("127.0.0.1", srv.port)
            tls = await async_wrap_socket(reader, writer, "localhost", template("firefox"), verify=pki["ca"], timeout=10)
            assert tls.version() == "TLSv1.3" and tls.selected_alpn_protocol() == "h2"
            await tls.sendall(b"async hello")
            assert await tls.recv(100) == b"async hello"
            await tls.key_update(request_peer=True)
            await tls.sendall(b"again")
            assert await tls.recv(100) == b"again"
            assert tls.client.key_updates_received == 1
            tls.settimeout(0.2)
            with pytest.raises(ReadTimeout):
                await tls.recv(10)
            await tls.close()
            return tls.cipher()

        cipher = asyncio.run(run())
        assert cipher[1] == "TLSv1.3"
    assert not srv.errors


def test_async_driver_timeouts(pki):
    def silent(conn):
        time.sleep(1.0)

    with SSLServer(server_context(pki), silent, wrap=False) as srv:
        async def run():
            reader, writer = await asyncio.open_connection("127.0.0.1", srv.port)
            with pytest.raises(ConnectTimeout):
                await async_wrap_socket(reader, writer, "localhost", template("chrome"), verify=pki["ca"], timeout=0.2)
            writer.close()

        asyncio.run(run())


def test_cpu_per_handshake(pki, capsys):
    cpu = []
    with SSLServer(server_context(pki), echo_once_then_close, connections=5) as srv:
        for _ in range(5):
            tls = connect(srv.port, verify=pki["ca"])
            cpu.append(tls.handshake_cpu_seconds)
            tls.sendall(b"t")
            tls.recv(100)
            tls.close()
    cpu.sort()
    with capsys.disabled():
        print("\nnative TLS handshake CPU (client, excluding network): median %.2f ms, min %.2f ms, max %.2f ms"
              % (cpu[len(cpu) // 2] * 1000, cpu[0] * 1000, cpu[-1] * 1000))
    assert cpu[len(cpu) // 2] < 0.05
