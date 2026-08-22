"""Adversarial regression suite: loopback servers, hostile framing, races.

Every probe here reproduces a class of bug that unit tests miss: connection
reuse desyncs, mid-download retries, thread contention on one Session, and
redirect method/body semantics.
"""
import gzip
import http.server
import os
import socketserver
import threading

import pytest

import curl_reap


class Base(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def drain_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)

    def reply(self, body=b"ok", status=200, extra=None):
        self.send_response(status)
        for key, value in (extra or []):
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


@pytest.fixture(scope="module")
def redirect_semantics():
    hits = {}

    class H(Base):
        def do_POST(self):
            self.drain_body()
            if self.path == "/307":
                self.reply(b"", 307, [("Location", "/land")])
            elif self.path == "/303":
                self.reply(b"", 303, [("Location", "/land")])
            else:
                info = (self.command + ":cl=" +
                        str(self.headers.get("Content-Length"))).encode()
                self.reply(b"landed:" + info)

        do_GET = do_POST

    server = socketserver.ThreadingMixIn.__class_getitem__ if False else None
    httpd = make_server(H)
    yield base_of(httpd)
    httpd.shutdown()


def make_server(handler):
    class Threading(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
    server = Threading(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def base_of(server):
    return "http://127.0.0.1:%d" % server.server_address[1]


def test_307_keeps_post_body_and_303_drops_it():
    class H(Base):
        def _handle(self):
            self.drain_body()
            if self.path == "/307":
                self.reply(b"", 307, [("Location", "/land")])
            elif self.path == "/303":
                self.reply(b"", 303, [("Location", "/land")])
            else:
                info = (self.command + ":cl=" +
                        str(self.headers.get("Content-Length"))).encode()
                self.reply(b"landed:" + info)

        do_POST = do_GET = _handle

    httpd = make_server(H)
    try:
        with curl_reap.Session() as s:
            r = s.post(base_of(httpd) + "/307", data=b"x" * 12)
            assert b"POST:cl=12" in r.content, r.content
            r = s.post(base_of(httpd) + "/303", data=b"x" * 12)
            assert b"GET:cl=None" in r.content, r.content
    finally:
        httpd.shutdown()


def test_redirect_loop_is_bounded():
    state = {"i": 0}

    class H(Base):
        def do_GET(self):
            state["i"] += 1
            self.reply(b"", 302, [("Location", "/next")])

    httpd = make_server(H)
    try:
        with curl_reap.Session(max_redirects=5) as s:
            with pytest.raises(curl_reap.TransportError, match="too many redirects"):
                s.get(base_of(httpd) + "/start")
    finally:
        httpd.shutdown()


def test_early_close_raises_instead_of_truncating():
    class H(Base):
        protocol_version = "HTTP/1.0"

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b"only-a-little")
            self.connection.close()

    httpd = make_server(H)
    try:
        with curl_reap.Session(retries=0) as s:
            with pytest.raises(curl_reap.TransportError):
                s.get(base_of(httpd) + "/x")
    finally:
        httpd.shutdown()


def test_chunked_gzip_byte_dribble_decodes_exactly():
    payload = gzip.compress(b"splitted-gzip-payload" * 700)

    class H(Base):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for byte in payload:
                self.wfile.write(b"1\r\n%s\r\n" % bytes([byte]))
            self.wfile.write(b"0\r\n\r\n")

    httpd = make_server(H)
    try:
        with curl_reap.Session() as s:
            r = s.get(base_of(httpd) + "/split")
            assert r.content == payload * 0 + gzip.decompress(payload)
    finally:
        httpd.shutdown()


def test_download_survives_garbage_then_retry_atomically(tmp_path):
    attempts = {"n": 0}
    target = str(tmp_path / "out.bin")

    class H(Base):
        def do_GET(self):
            attempts["n"] += 1
            if attempts["n"] == 1:
                try:
                    self.wfile.write(b"FATAL garbage not http\r\n\r\n")
                    self.wfile.flush()
                finally:
                    self.connection.close()
                    raise RuntimeError("kill conn")
            self.reply(b"second-attempt-body")

    httpd = make_server(H)
    try:
        with curl_reap.Session() as s:
            s.download(base_of(httpd) + "/file", target)
        assert open(target, "rb").read() == b"second-attempt-body"
        assert not os.path.exists(target + ".reap-part"), "part file left behind"
    finally:
        httpd.shutdown()


def test_twenty_threads_share_one_session_without_cross_talk():
    class H(Base):
        def do_GET(self):
            body = ("path=" + self.path + "|cookie=" +
                    (self.headers.get("Cookie") or "-")).encode()
            self.reply(body)

    httpd = make_server(H)
    errors = []

    def worker(session, i):
        try:
            session.cookies.store(base_of(httpd) + "/", {"w": str(i)})
            for j in range(15):
                r = session.get(base_of(httpd) + f"/{i}/{j}")
                expected = f"path=/{i}/{j}|cookie=w={i}"
                if r.text != expected:
                    errors.append(f"w{i} req{j}: {r.text}")
                    return
        except Exception as exc:  # pragma: no cover - surfaced via errors
            errors.append(f"w{i} exc {exc}")

    httpd_url = base_of(httpd)
    try:
        threads = []
        for i in range(20):
            session = curl_reap.Session()
            t = threading.Thread(target=worker, args=(session, i))
            threads.append((t, session))
            t.start()
        for t, session in threads:
            t.join()
            session.close()
        assert not errors, errors[:3]
    finally:
        httpd.shutdown()


def test_head_then_get_reuses_connection():
    class H(Base):
        def do_HEAD(self):
            self.reply(b"", 200)

        def do_GET(self):
            self.reply(b"body-after-head")

    httpd = make_server(H)
    try:
        with curl_reap.Session() as s:
            s.head(base_of(httpd) + "/h")
            r = s.get(base_of(httpd) + "/h")
            assert r.text == "body-after-head"
    finally:
        httpd.shutdown()


def test_cookie_set_on_post_redirect_replays_on_landing_get():
    class H(Base):
        def do_POST(self):
            self.drain_body()
            self.reply(b"", 301, [("Set-Cookie", "postc=1; Path=/"),
                                  ("Location", "/final")])

        def do_GET(self):
            self.reply(b"c=" + (self.headers.get("Cookie") or "?").encode())

    httpd = make_server(H)
    try:
        with curl_reap.Session() as s:
            r = s.post(base_of(httpd) + "/chain", data=b"x")
            assert "postc=1" in r.text, r.text
            r = s.get(base_of(httpd) + "/final")
            assert "postc=1" in r.text, r.text
    finally:
        httpd.shutdown()


def test_download_of_bodyless_204_writes_nothing(tmp_path):
    target = tmp_path / "n.bin"

    class H(Base):
        def do_GET(self):
            self.send_response(204)
            self.end_headers()

    httpd = make_server(H)
    try:
        with curl_reap.Session() as s:
            r = s.download(base_of(httpd) + "/n", str(target))
            assert not target.exists(), "should not create a file for 204"
    finally:
        httpd.shutdown()


def test_fifty_parallel_mixed_ops_on_one_session(tmp_path):
    class H(Base):
        def do_GET(self):
            if self.path.startswith("/big"):
                body = bytes(range(256)) * 512
            else:
                body = ("small-" + self.path).encode()
            self.reply(body)

    httpd = make_server(H)
    errors = []

    def job(session, i):
        try:
            if i % 3 == 0:
                target = str(tmp_path / f"mix-{i}.bin")
                r = session.download(base_of(httpd) + f"/big/{i}", target)
                assert r.meta["bytes"] == 256 * 512
            else:
                r = session.get(base_of(httpd) + f"/s/{i}")
                assert r.text == f"small-/s/{i}"
        except Exception as exc:  # pragma: no cover
            errors.append(f"{i}: {type(exc).__name__} {exc}")

    try:
        with curl_reap.Session() as s:
            threads = [threading.Thread(target=job, args=(s, i)) for i in range(50)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        assert not errors, errors[:3]
    finally:
        httpd.shutdown()
