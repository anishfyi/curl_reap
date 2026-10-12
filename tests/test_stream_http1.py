"""``stream=True`` over HTTP/1.1, and ``Response.infos["tls_backend"]``.

Streaming never worked in 2.0.0: the body stream was never attached to the
response, the request path closed the connection the stream needed, the
decoder was called as a function, chunks larger than the read size lost
their CRLF, and close-delimited bodies skipped bytes buffered with the head.
"""
import gzip
import http.server
import os
import ssl
import sys
import threading

import pytest

import curl_reap
from curl_reap.exceptions import ContentDecodingError

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_tls_trust_identity import HTTPSServer, pki  # noqa: E402,F401

BODY = b"".join(b"line %05d\n" % i for i in range(5000))  # 55 KB
GZ = gzip.compress(BODY)


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.connections.add(self.client_address)
        if self.path == "/cl":
            self._send(BODY, [("Content-Length", str(len(BODY)))])
        elif self.path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(BODY), 7000):
                piece = BODY[i:i + 7000]
                self.wfile.write(b"%x;ext=1\r\n%s\r\n" % (len(piece), piece))
            self.wfile.write(b"0\r\nX-Trailer: y\r\n\r\n")
        elif self.path == "/gzip":
            self._send(GZ, [("Content-Encoding", "gzip"), ("Content-Length", str(len(GZ)))])
        elif self.path == "/gzip-truncated":
            cut = GZ[:len(GZ) // 2]
            self._send(cut, [("Content-Encoding", "gzip"), ("Content-Length", str(len(cut)))])
        elif self.path == "/unknown-encoding":
            self._send(BODY, [("Content-Encoding", "x-made-up"),
                              ("Content-Length", str(len(BODY)))])
        elif self.path == "/close":
            self.send_response(200)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(BODY)
            self.close_connection = True

    def _send(self, body, headers):
        self.send_response(200)
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            pass  # a client that abandons a streamed body


@pytest.fixture
def server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.connections = set()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1], srv
    srv.shutdown()
    srv.server_close()


@pytest.mark.parametrize("path", ["/cl", "/chunked", "/gzip", "/close"])
@pytest.mark.parametrize("size", [1000, 7000, 100000])
def test_stream_yields_the_whole_body(server, path, size):
    base, _ = server
    with curl_reap.Session(retries=0) as s:
        r = s.get(base + path, stream=True)
        assert r.content is None  # nothing buffered
        assert b"".join(r.iter_content(size)) == BODY


def test_iter_lines_streams(server):
    base, _ = server
    with curl_reap.Session(retries=0) as s:
        lines = list(s.get(base + "/chunked", stream=True).iter_lines())
    assert len(lines) == 5000 and lines[0] == b"line 00000" and lines[-1] == b"line 04999"


def test_drained_stream_returns_its_connection_to_the_pool(server):
    base, srv = server
    with curl_reap.Session(retries=0) as s:
        for _ in range(3):
            assert b"".join(s.get(base + "/cl", stream=True).iter_content()) == BODY
    assert len(srv.connections) == 1


def test_closed_stream_does_not_poison_the_next_request(server):
    base, _ = server
    with curl_reap.Session(retries=0) as s:
        r = s.get(base + "/cl", stream=True)
        assert len(next(r.iter_content(100))) == 100
        r.close()
        assert s.get(base + "/cl").content == BODY


def test_truncated_compressed_stream_raises(server):
    base, _ = server
    with curl_reap.Session(retries=0) as s:
        r = s.get(base + "/gzip-truncated", stream=True)
        with pytest.raises(ContentDecodingError):
            b"".join(r.iter_content())


def test_unstreamable_encoding_raises_instead_of_returning_encoded_bytes(server):
    base, _ = server
    with curl_reap.Session(retries=0) as s:
        with pytest.raises(ContentDecodingError):
            s.get(base + "/unknown-encoding", stream=True)


def test_infos_report_the_backend_for_plain_http(server):
    base, _ = server
    with curl_reap.Session(retries=0) as s:
        assert s.get(base + "/cl").infos["tls_backend"] == "plain"


@pytest.mark.parametrize("mode", ["native", "openssl"])
def test_infos_report_the_tls_backend(pki, mode):  # noqa: F811
    server = HTTPSServer(pki, close=False)
    try:
        with curl_reap.Session(retries=0, timeout=5, tls=mode, http2=False) as s:
            r = s.get(server.url, verify=pki["ca"])
    finally:
        server.stop()
    assert r.infos["tls_backend"] == mode
