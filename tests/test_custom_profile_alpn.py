"""A hand-built Profile has no HTTP/2 spec, so it must not offer h2.

HTTP/2 is negotiated by default since 2.0. A custom ``Profile`` without an
``h2_spec`` used to offer ``h2`` in ALPN anyway; when the server picked it,
the transport wrote an HTTP/1.1 request on the h2 connection and the request
failed. The ``Profile`` docstring promises HTTP/1.1 only for such profiles.
"""
import os
import socket
import ssl
import sys
import threading

import pytest

import curl_reap
from curl_reap import transport as transport_mod
from curl_reap.tls import Profile, resolve_profile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_fake_server import make_ca, make_leaf, write_pem  # noqa: E402


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("custom-alpn")
    ca_cert, ca_key = make_ca()
    leaf, key = make_leaf(ca_cert, ca_key, hostnames=("localhost",), ips=("127.0.0.1",),
                          rsa=True)
    paths = {"ca": str(tmp / "ca.pem"), "chain": str(tmp / "chain.pem")}
    write_pem(paths["ca"], ca_cert)
    write_pem(paths["chain"], leaf, ca_cert, key=key)
    return paths


class H2PreferringServer:
    """HTTPS that prefers h2 in ALPN and answers HTTP/1.1 requests."""

    def __init__(self, pki):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(pki["chain"])
        self.ctx.set_alpn_protocols(["h2", "http/1.1"])
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.url = "https://127.0.0.1:%d/" % self.sock.getsockname()[1]
        self.selected = []
        self.first_bytes = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw):
        raw.settimeout(10)
        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            return
        try:
            self.selected.append(conn.selected_alpn_protocol())
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
            self.first_bytes.append(buf[:16])
            if conn.selected_alpn_protocol() == "h2":
                return  # an h2 server would reject this preface; just hang up
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except (ssl.SSLError, OSError):
            pass
        finally:
            conn.close()

    def stop(self):
        self.sock.close()


def test_custom_profile_without_h2_spec_negotiates_http11(pki):
    server = H2PreferringServer(pki)
    custom = Profile(name="custom", headers=(("User-Agent", "custom/1.0"),))
    assert custom.h2_spec is None
    try:
        session = curl_reap.Session(profile=custom, verify=pki["ca"], retries=0,
                                    trust_env=False)
        try:
            r = session.get(server.url, timeout=10)
        finally:
            session.close()
        assert r.status == 200 and r.content == b"ok"
        assert r.infos["alpn"] == "http/1.1"
        assert server.selected == ["http/1.1"]
        assert server.first_bytes[0].startswith(b"GET / HTTP/1.1")
    finally:
        server.stop()


def test_alpn_offers_h2_only_with_an_h2_spec():
    t = transport_mod._Transport()
    builtin = resolve_profile("chrome")
    assert builtin.h2_spec
    assert t._alpn_for(builtin, "v2") == ("h2", "http/1.1")
    assert t._alpn_for(builtin, "v1") == ("http/1.1",)
    custom = Profile(name="custom")
    assert t._alpn_for(custom, "v2") == ("http/1.1",)
    assert t._alpn_for(custom, "v2_prior_knowledge") == ("http/1.1",)
