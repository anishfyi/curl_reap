"""A connection or a resumption ticket earned under one TLS trust policy must
never serve a request that asked for another.

Two holes closed here, both found against the native engine:

* The connection pool keyed on ``bool(verify)``, so a request with an
  untrusted CA bundle reused a connection verified against a different one.
* The resumption ticket cache was keyed by server name only. A PSK resumption
  skips certificate verification by design, so a ticket earned with
  ``verify=False`` let a later ``verify=True`` request to the same host
  resume without any verification at all.
"""
import os
import socket
import ssl
import sys
import threading

import pytest

import curl_reap
from curl_reap.exceptions import CertificateVerifyError
from curl_reap.transport import _tls_identity

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_fake_server import make_ca, make_leaf, write_pem  # noqa: E402

BODY = b"ok"


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("trust-identity")
    ca_cert, ca_key = make_ca()
    leaf, key = make_leaf(ca_cert, ca_key, hostnames=("localhost",), ips=("127.0.0.1",))
    other_ca, _ = make_ca("untrusted CA")
    paths = {"ca": str(tmp / "ca.pem"), "chain": str(tmp / "chain.pem"),
             "other": str(tmp / "other.pem")}
    write_pem(paths["ca"], ca_cert)
    write_pem(paths["chain"], leaf, ca_cert, key=key)
    write_pem(paths["other"], other_ca)
    return paths


class HTTPSServer:
    """HTTP/1.1 over TLS 1.3 (OpenSSL issues resumption tickets by default).
    ``close=True`` answers with Connection: close so every request needs a
    fresh connection; otherwise connections are kept alive."""

    def __init__(self, pki, close):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(pki["chain"])
        self.ctx.set_alpn_protocols(["http/1.1"])
        self.close = close
        self.connections = 0
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.url = "https://127.0.0.1:%d/" % self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw):
        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()  # the client refused our certificate: expected in these tests
            return
        self.connections += 1
        try:
            buf = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
                while b"\r\n\r\n" in buf:
                    _, buf = buf.split(b"\r\n\r\n", 1)
                    head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n" % len(BODY)
                    head += b"Connection: close\r\n\r\n" if self.close else b"\r\n"
                    conn.sendall(head + BODY)
                    if self.close:
                        return
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self.sock.close()


@pytest.fixture
def keepalive(pki):
    server = HTTPSServer(pki, close=False)
    yield server
    server.stop()


@pytest.fixture
def closing(pki):
    server = HTTPSServer(pki, close=True)
    yield server
    server.stop()


def _session():
    return curl_reap.Session(retries=0, timeout=5)


def test_pooled_connection_is_not_reused_for_another_ca_bundle(pki, keepalive):
    with _session() as s:
        assert s.get(keepalive.url, verify=pki["ca"]).status == 200
        with pytest.raises(CertificateVerifyError):
            s.get(keepalive.url, verify=pki["other"])


def test_ticket_from_unverified_connection_never_skips_verification(pki, closing):
    with _session() as s:
        assert s.get(closing.url, verify=False).status == 200
        with pytest.raises(CertificateVerifyError):
            s.get(closing.url)  # default trust store: this private CA is not trusted
        with pytest.raises(CertificateVerifyError):
            s.get(closing.url, verify=pki["other"])


def test_ticket_from_one_ca_bundle_never_resumes_under_another(pki, closing):
    with _session() as s:
        assert s.get(closing.url, verify=pki["ca"]).status == 200
        with pytest.raises(CertificateVerifyError):
            s.get(closing.url, verify=pki["other"])


def test_same_trust_policy_still_pools(pki, keepalive):
    with _session() as s:
        for _ in range(3):
            assert s.get(keepalive.url, verify=pki["ca"]).content == BODY
    assert keepalive.connections == 1


def test_same_trust_policy_still_resumes(pki, closing):
    with _session() as s:
        first = s.get(closing.url, verify=pki["ca"])
        resumed = [s.get(closing.url, verify=pki["ca"]).infos.get("resumed") for _ in range(3)]
    if first.infos.get("tls_backend", first.infos.get("backend")) == "openssl":
        pytest.skip("native engine not in use")
    assert any(resumed), "tickets for the same trust policy must still resume"


def test_tls_identity_never_keeps_a_key_password():
    ident = _tls_identity(("client.pem", "client.key", "hunter2"), secret_index=2)
    assert "hunter2" not in repr(ident)
    assert ident[:2] == ("client.pem", "client.key")
    assert _tls_identity(("c", "k", "a"), secret_index=2) != _tls_identity(("c", "k", "b"), secret_index=2)


def test_tls_identity_distinguishes_verify_values():
    ctx_a, ctx_b = ssl.create_default_context(), ssl.create_default_context()
    values = [True, False, "/a/ca.pem", "/b/ca.pem", ctx_a, ctx_b]
    assert len({_tls_identity(v) for v in values}) == len(values)
    assert _tls_identity(ctx_a) == _tls_identity(ctx_a)
