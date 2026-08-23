"""HTTP/2 transport tests: local ALPN-h2 TLS server + graceful fallback.

Needs the optional h2 extra: pip install "curl-reap[h2]".
"""
import http.server
import ssl
import socketserver
import threading

import pytest

h2 = pytest.importorskip("h2")
from h2.config import H2Configuration      # noqa: E402
from h2.connection import H2Connection     # noqa: E402
from h2.events import (DataReceived, RequestReceived,  # noqa: E402
                       StreamEnded)

import curl_reap                           # noqa: E402

CERT = "/tmp/h2cert/cert.pem"
KEY = "/tmp/h2cert/key.pem"


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


def _serve_tls(alpn_protocols):
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
    context.load_cert_chain(CERT, KEY)
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
def h2_base():
    return _serve_tls(["h2"])


@pytest.fixture(scope="module")
def plain11_base():
    return _serve_tls(["http/1.1"])


def test_http2_round_trip_and_connection_reuse(h2_base):
    with curl_reap.Session(http2=True, verify="/tmp/h2cert/cert.pem") as s:
        r = s.get(h2_base + "/first", impersonate="chrome131")
        assert r.status == 200
        assert r.text.startswith("h2:Mozilla/5.0"), r.text
        assert r.raw.http_version == "HTTP/2"
        assert r.cookies.get("h2c") == "1"
        # same pooled connection serves the second stream
        r2 = s.get(h2_base + "/second", impersonate="firefox133")
        assert r2.status == 200
        assert "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0)" in r2.text


def test_cookie_set_over_h2_replays(h2_base):
    with curl_reap.Session(http2=True, verify="/tmp/h2cert/cert.pem") as s:
        s.get(h2_base + "/warmup")
        jar_before = s.cookies.get_dict().get("h2c")
        assert jar_before == "1"


def test_graceful_fallback_when_server_is_1_1_only(plain11_base):
    with curl_reap.Session(http2=True, verify="/tmp/h2cert/cert.pem") as s:
        r = s.get(plain11_base + "/x")
        assert r.status == 200 and r.text == "ok"


def test_http2_off_by_default(h2_base):
    with curl_reap.Session(verify="/tmp/h2cert/cert.pem") as s:
        r = s.get(h2_base + "/x")
        assert r.raw.http_version != "HTTP/2"
