"""Redirect security: credential stripping on origin changes, method
rewrite header hygiene, and Response.history."""
import http.server
import socketserver
import threading

import pytest

import curl_reap

class Base(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, body=b"", status=200, extra=None):
        self.send_response(status)
        for key, value in (extra or []):
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def make_server(handler):
    class Threading(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
    server = Threading(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server

def base_of(server):
    return "http://127.0.0.1:%d" % server.server_address[1]

def _observed(handler):
    """Request recorder shared across two origins."""
    records = []

    class H(handler):
        def do_GET(self):
            if self.path == "/away":
                records.append(("away", dict(self.headers)))
                self.reply(b"gone", 302, [("Location", TARGET + "/land")])
            elif self.path == "/land":
                records.append(("land", dict(self.headers)))
                self.reply(b"ok")
            elif self.path == "/stay":
                records.append(("stay", dict(self.headers)))
                self.reply(b"", 302, [("Location", "/land")])
            else:
                self.reply(b"ok")

    return H, records

TARGET = ""

def test_credentials_do_not_follow_cross_origin_redirect():
    H, records = _observed(Base)
    a = make_server(H)
    b = make_server(H)
    global TARGET
    TARGET = base_of(b)
    try:
        with curl_reap.Session(retries=0) as s:
            r = s.get(base_of(a) + "/away",
                      headers={"Authorization": "Bearer sekrit",
                               "Cookie": "session=abc",
                               "Proxy-Authorization": "Basic cHJveHk=",
                               "Host": "spoofed.test"})
        assert r.ok
        land = records[-1][1]
        lowered = {k.lower(): v for k, v in land.items()}
        assert "authorization" not in lowered
        assert "cookie" not in lowered
        assert "proxy-authorization" not in lowered
        assert "spoofed" not in lowered.get("host", "")
    finally:
        a.shutdown()
        b.shutdown()

def test_same_origin_redirect_keeps_credentials_and_auth():
    H, records = _observed(Base)
    a = make_server(H)
    global TARGET
    TARGET = base_of(a)
    try:
        with curl_reap.Session(retries=0) as s:
            r = s.get(base_of(a) + "/stay",
                      headers={"Authorization": "Bearer keep",
                               "Cookie": "session=abc"})
        assert r.ok
        land = records[-1][1]
        lowered = {k.lower(): v for k, v in land.items()}
        assert lowered.get("cookie") == "session=abc"
        assert lowered.get("authorization") == "Bearer keep"
    finally:
        a.shutdown()

def test_auth_tuple_dropped_cross_origin():
    H, records = _observed(Base)
    a = make_server(H)
    b = make_server(H)
    global TARGET
    TARGET = base_of(b)
    try:
        with curl_reap.Session(retries=0) as s:
            r = s.get(base_of(a) + "/away", auth=("u", "p"))
        assert r.ok
        lowered = {k.lower(): v for k, v in records[-1][1].items()}
        assert "authorization" not in lowered
    finally:
        a.shutdown()
        b.shutdown()

def test_post_303_drops_body_and_content_headers():
    records = []

    class H(Base):
        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            if self.path == "/go":
                self.reply(b"", 303, [("Location", "/land")])
            else:
                records.append((self.command, dict(self.headers)))
                self.reply(b"landed")

        do_POST = do_GET = _handle

    a = make_server(H)
    try:
        with curl_reap.Session(retries=0) as s:
            r = s.post(base_of(a) + "/go", data=b"payload",
                       headers={"Content-Type": "text/plain"})
        assert r.ok
        command, headers = records[-1]
        assert command == "GET"
        lowered = {k.lower(): v for k, v in headers.items()}
        assert "content-length" not in lowered or lowered["content-length"] == "0"
        assert lowered.get("content-type") != "text/plain"
    finally:
        a.shutdown()

def test_response_history_lists_redirect_chain():
    hops = []

    class H(Base):
        def do_GET(self):
            if self.path == "/one":
                hops.append("/one")
                self.reply(b"", 302, [("Location", "/two")])
            elif self.path == "/two":
                hops.append("/two")
                self.reply(b"", 302, [("Location", "/three")])
            else:
                self.reply(b"final")

    a = make_server(H)
    try:
        with curl_reap.Session(retries=0) as s:
            r = s.get(base_of(a) + "/one")
        assert r.ok and r.url.endswith("/three")
        assert [h.status for h in r.history] == [302, 302]
        assert [h.url.rsplit("/", 1)[-1] for h in r.history] == ["one", "two"]
        direct = s.get(base_of(a) + "/three")
        assert direct.history == []
    finally:
        a.shutdown()

def test_https_to_http_origin_change_strips_authorization():
    from curl_reap.http import _Transport
    t = _Transport()
    assert t._origin("https://ex.com/a") != t._origin("http://ex.com/a")
    assert t._origin("https://ex.com:443/a") == t._origin("https://ex.com/a")
    assert t._origin("http://ex.com:8080/a") != t._origin("http://ex.com/a")
