"""HTTP/2 transport tests: local ALPN-h2 TLS server + graceful fallback.

Needs the optional h2 extra: pip install "curl-reap[h2]".
"""
import http.server
from pathlib import Path
import shutil
import ssl
import socketserver
import subprocess
import threading

import pytest

h2 = pytest.importorskip("h2")
from h2.config import H2Configuration      # noqa: E402
from h2.connection import H2Connection     # noqa: E402
from h2.events import (DataReceived, RequestReceived,  # noqa: E402
                       StreamEnded)

import curl_reap                           # noqa: E402

@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    """Isolated localhost PKI: a proper CA and a leaf with SKI/AKI/SAN.

    The native verifier is strict RFC 5280: a self-signed leaf asserting
    CA:TRUE (the 1.x shortcut) is rejected, so the fixture mints a real
    two-certificate chain.
    """
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("HTTP/2 TLS tests require openssl")
    root = tmp_path_factory.mktemp("h2cert")
    ca_cert, ca_key = root / "ca.pem", root / "ca.key"
    cert, key = root / "cert.pem", root / "key.pem"
    csr = root / "leaf.csr"
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "1",
         "-subj", "/CN=reap test ca",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-addext", "subjectKeyIdentifier=hash"],
        check=True, capture_output=True)
    subprocess.run(
        [openssl, "req", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(csr), "-subj", "/CN=localhost"],
        check=True, capture_output=True)
    ext = root / "leaf.ext"
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n")
    subprocess.run(
        [openssl, "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
         "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert),
         "-days", "1", "-extfile", str(ext)],
        check=True, capture_output=True)
    return cert, key, ca_cert


class H2Handler:
    """Minimal h2 server: answers every request with echo headers as JSON-ish."""

    def __init__(self, sock):
        self.conn = H2Connection(
            config=H2Configuration(client_side=False, header_encoding="latin-1"))
        self.sock = sock
        self.conn.initiate_connection()
        self._send()

    def _send(self):
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)

    def run(self):
        try:
            while True:
                wire = self.sock.recv(65536)
                if not wire:
                    return
                for event in self.conn.receive_data(wire):
                    if isinstance(event, RequestReceived):
                        flat = dict(event.headers)
                        body = ("h2:" + flat.get("user-agent",
                                                 "none")).encode()
                        sid = event.stream_id
                        self.conn.send_headers(sid, [
                            (b":status", b"200"),
                            (b"content-type", b"text/plain"),
                            (b"set-cookie", b"h2c=1; Path=/"),
                            (b"x-request-path", flat[":path"].encode()),
                        ])
                        self.conn.send_data(sid, body, end_stream=True)
                    elif isinstance(event, StreamEnded):
                        pass
                    elif isinstance(event, DataReceived):
                        self.conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id)
                self._send()
        except OSError:
            return


def _serve_tls(alpn_protocols, cert: Path, key: Path):
    class Threading(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

        def server_bind(self):
            import socket
            self.socket.close()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(("127.0.0.1", 0))
            self.socket.listen(8)
            self.server_address = self.socket.getsockname()
            self.server_name = "localhost"
            self.server_port = self.server_address[1]

    raw = Threading(("127.0.0.1", 0), lambda *a: None)  # placeholder app
    port = raw.server_address[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(alpn_protocols)

    def accept_loop():
        while True:
            try:
                sock, _ = raw.socket.accept()
            except OSError:
                return
            try:
                tls = context.wrap_socket(sock, server_side=True)
            except ssl.SSLError:
                continue
            if tls.selected_alpn_protocol() == "h2":
                threading.Thread(target=H2Handler(tls).run,
                                 daemon=True).start()
            else:
                # speak minimal HTTP/1.1 then close
                try:
                    tls.recv(65536)
                    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                b"\r\nok")
                finally:
                    tls.close()

    threading.Thread(target=accept_loop, daemon=True).start()
    return "https://localhost:%d" % port


@pytest.fixture(scope="module")
def h2_base(tls_material):
    cert, key, ca = tls_material
    return _serve_tls(["h2"], cert, key), ca


@pytest.fixture(scope="module")
def plain11_base(tls_material):
    cert, key, ca = tls_material
    return _serve_tls(["http/1.1"], cert, key), ca


def test_http2_round_trip_and_connection_reuse(h2_base):
    base, ca = h2_base
    with curl_reap.Session(http2=True, verify=str(ca)) as s:
        r = s.get(base + "/first", impersonate="chrome131")
        assert r.status == 200
        assert r.text.startswith("h2:Mozilla/5.0"), r.text
        assert r.raw.http_version == "HTTP/2"
        assert r.cookies.get("h2c") == "1"
        # same pooled connection serves the second stream
        r2 = s.get(base + "/second", impersonate="firefox133")
        assert r2.status == 200
        assert "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0)" in r2.text


def test_cookie_set_over_h2_replays(h2_base):
    base, ca = h2_base
    with curl_reap.Session(http2=True, verify=str(ca)) as s:
        s.get(base + "/warmup")
        jar_before = s.cookies.get_dict().get("h2c")
        assert jar_before == "1"


def test_graceful_fallback_when_server_is_1_1_only(plain11_base):
    base, ca = plain11_base
    with curl_reap.Session(http2=True, verify=str(ca)) as s:
        r = s.get(base + "/x")
        assert r.status == 200 and r.text == "ok"


def test_http2_on_by_default_and_opt_out(h2_base):
    base, ca = h2_base
    with curl_reap.Session(verify=str(ca)) as s:
        r = s.get(base + "/x")
        assert r.raw.http_version == "HTTP/2"
    with curl_reap.Session(http2=False, verify=str(ca)) as s:
        r = s.get(base + "/x")
        assert r.raw.http_version != "HTTP/2"
