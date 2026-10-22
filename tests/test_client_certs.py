"""Client certificates (mutual TLS).

2.0.0 promised an automatic OpenSSL fallback for client certificates, but
under tls="auto" the native engine answered the server's CertificateRequest
with an empty Certificate: a server that requires one failed the handshake
(certificate_required), and one that merely asked never saw the cert. The
``(cert, key, password)`` form also failed, because ``cert`` was rebound
before ``cert[2]`` was read.
"""
import datetime
import os
import socket
import ssl
import sys
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import curl_reap
from curl_reap.exceptions import TransportError

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_fake_server import make_ca, make_leaf, write_pem  # noqa: E402

PASSWORD = b"s3cret"


def _client_leaf(ca_cert, ca_key, name="reap-client"):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("mtls")
    ca_cert, ca_key = make_ca()
    leaf, leaf_key = make_leaf(ca_cert, ca_key, hostnames=("localhost",), ips=("127.0.0.1",))
    client, client_key = _client_leaf(ca_cert, ca_key)
    paths = {k: str(tmp / ("%s.pem" % k)) for k in
             ("ca", "server", "client", "client_key", "client_key_enc", "combined")}
    write_pem(paths["ca"], ca_cert)
    write_pem(paths["server"], leaf, ca_cert, key=leaf_key)
    write_pem(paths["client"], client)
    with open(paths["client_key"], "wb") as fh:
        fh.write(client_key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    with open(paths["client_key_enc"], "wb") as fh:
        fh.write(client_key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.BestAvailableEncryption(PASSWORD)))
    write_pem(paths["combined"], client, key=client_key)
    return paths


class MTLSServer:
    """HTTP/1.1 over TLS; answers with the client certificate's CN (or "none")."""

    def __init__(self, pki, required):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(pki["server"])
        self.ctx.load_verify_locations(pki["ca"])
        self.ctx.verify_mode = ssl.CERT_REQUIRED if required else ssl.CERT_OPTIONAL
        self.ctx.set_alpn_protocols(["http/1.1"])
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
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
            raw.close()
            return
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
            peer = conn.getpeercert()
            cn = "none"
            if peer:
                cn = dict(x[0] for x in peer["subject"]).get("commonName", "?")
            body = cn.encode()
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                         % (len(body), body))
        except (ssl.SSLError, OSError):
            pass
        finally:
            conn.close()

    def stop(self):
        self.sock.close()


@pytest.fixture
def required(pki):
    server = MTLSServer(pki, required=True)
    yield server
    server.stop()


@pytest.fixture
def optional(pki):
    server = MTLSServer(pki, required=False)
    yield server
    server.stop()


def _get(url, pki, **kw):
    with curl_reap.Session(retries=0, timeout=5, **kw.pop("session", {})) as s:
        return s.get(url, verify=pki["ca"], **kw)


@pytest.mark.parametrize("tls", ["auto", "openssl"])
def test_cert_and_key_pair_is_presented(pki, required, tls):
    r = _get(required.url, pki, cert=(pki["client"], pki["client_key"]), session={"tls": tls})
    assert r.text == "reap-client"
    assert r.infos["tls_backend"] == "openssl"


def test_single_file_cert_is_presented(pki, required):
    assert _get(required.url, pki, cert=pki["combined"]).text == "reap-client"


def test_cert_key_password_triple_is_presented(pki, required):
    r = _get(required.url, pki, cert=(pki["client"], pki["client_key_enc"], PASSWORD))
    assert r.text == "reap-client"


def test_server_that_only_asks_still_receives_the_cert(pki, optional):
    assert _get(optional.url, pki, cert=(pki["client"], pki["client_key"])).text == "reap-client"


def test_without_a_cert_a_requiring_server_refuses(pki, required):
    with pytest.raises(TransportError):
        _get(required.url, pki)


def test_native_backend_refuses_a_client_cert_loudly(pki, required):
    with pytest.raises(ValueError, match="client certificate"):
        _get(required.url, pki, cert=(pki["client"], pki["client_key"]), session={"tls": "native"})
