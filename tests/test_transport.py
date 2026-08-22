import http.server
import threading
import zlib

import pytest

import curl_reap
from curl_reap.http import RetryPolicy
from curl_reap.tls import Profile, resolve_profile


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = bytearray(incoming)
        self.sent = []
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        if not self.incoming:
            return b""
        data = bytes(self.incoming[:size])
        del self.incoming[:size]
        return data

    def close(self):
        self.closed = True


def response(body=b"ok", headers=b""):
    return (b"HTTP/1.1 200 OK\r\n" + headers +
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)



class _BareRaw:
    """Minimal raw response stand-in for transport-level fakes."""
    def __init__(self):
        from curl_reap.http import CaseInsensitiveHeaders
        self.status_code = 200
        self.url = "http://test/"
        self.headers = CaseInsensitiveHeaders({})
        self.content = b"ok"
        self.text = "ok"
        self.cookies = {}
        self.cookie_specs = []
        self.saved_bytes = 0


def test_header_order_and_casing_are_deterministic(monkeypatch):
    sockets = [FakeSocket(response()), FakeSocket(response())]
    monkeypatch.setattr("curl_reap.http.socket.create_connection",
                        lambda address, timeout: sockets.pop(0))

    sent = []
    for unused in range(2):
        session = curl_reap.Session(
            headers=[("uSeR-aGeNt", "ordered-agent"), ("X-First", "1"), ("x-second", "2")],
            retries=0)
        result = session.get("http://example.test/a?b=1",
                             headers=[("X-Request", "3")])
        assert result.text == "ok"
        pooled = next(iter(session._transport._pool.values()))[0]
        sent.append(pooled.sock.sent[0])

    assert sent[0] == sent[1]
    lines = sent[0].split(b"\r\n")
    assert lines[0] == b"GET /a?b=1 HTTP/1.1"
    assert lines[1] == b"Host: example.test"
    # profile impersonation headers precede user overrides, which win by name
    assert lines.index(b"sec-ch-ua-mobile: ?0") < lines.index(b"uSeR-aGeNt: ordered-agent")
    assert b"Chrome/131.0.0.0 Safari/537.36" not in sent[0]
    assert lines.index(b"X-First: 1") < lines.index(b"x-second: 2") < lines.index(b"X-Request: 3")


def test_retry_backoff_with_mocked_socket(monkeypatch):
    good = FakeSocket(response(b"retried"))
    attempts = []

    def connect(address, timeout):
        attempts.append(address)
        if len(attempts) == 1:
            raise OSError("temporary connect failure")
        return good

    sleeps = []
    monkeypatch.setattr("curl_reap.http.socket.create_connection", connect)
    monkeypatch.setattr("curl_reap.http.random.random", lambda: 0.5)
    monkeypatch.setattr("curl_reap.http.time.sleep", sleeps.append)
    policy = RetryPolicy(retries=1, backoff=2.0, max_backoff=10.0)
    result = curl_reap.Session(retry_policy=policy).get("http://retry.test/")

    assert result.text == "retried"
    assert len(attempts) == 2
    assert sleeps == [2.0]


def test_chunked_gzip_and_connection_reuse(monkeypatch):
    compressed = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    payload = compressed.compress(b"decoded") + compressed.flush()
    chunk = b"%x\r\n" % len(payload) + payload + b"\r\n0\r\n\r\n"
    first = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
             b"Content-Encoding: gzip\r\n\r\n" + chunk)
    sock = FakeSocket(first + response(b"second"))
    calls = []

    def connect(address, timeout):
        calls.append(address)
        return sock

    monkeypatch.setattr("curl_reap.http.socket.create_connection", connect)
    session = curl_reap.Session(retries=0)
    assert session.get("http://reuse.test/one").content == b"decoded"
    assert session.get("http://reuse.test/two").content == b"second"
    assert len(calls) == 1
    assert len(sock.sent) == 2


def test_profile_validation_and_custom_profile():
    assert resolve_profile("chrome") is curl_reap.PROFILES["chrome"]
    with pytest.raises(ValueError, match="unknown TLS profile"):
        curl_reap.Session(profile="netscape")
    with pytest.raises(TypeError, match="Profile"):
        curl_reap.Session(profile=object())

    custom = Profile(name="custom", headers=(("user-agent", "custom"),))
    assert curl_reap.Session(profile=custom).profile is custom


# ---------------------------------------------------------------- cookies

def test_cookie_jar_domain_path_and_expiry():
    jar = curl_reap.CookieJar()
    jar.absorb("https://shop.example.com/login", [
        {"name": "sid", "value": "abc", "domain": "", "path": "/", "secure": True},
        {"name": "track", "value": "x", "domain": ".example.com",
         "path": "/browse", "secure": False, "max_age": 3600},
        {"name": "dead", "value": "y", "max_age": -10},
    ])
    # secure cookie only over https
    assert "sid=abc" in jar.header_for("https://shop.example.com/account")
    assert "sid=abc" not in jar.header_for("http://shop.example.com/account")
    # domain-scoped cookie matches subdomains but not the path
    assert "track=x" in jar.header_for("https://other.example.com/browse/list")
    assert "track=x" not in jar.header_for("https://other.example.com/")
    # expired cookie was dropped at absorb time
    assert jar.get_dict() == {"sid": "abc", "track": "x"}


def test_session_sends_stored_cookies(monkeypatch):
    from curl_reap.http import CaseInsensitiveHeaders

    class LocalRaw:
        def __init__(self):
            self.status_code = 200
            self.url = "https://api.test/"
            self.headers = CaseInsensitiveHeaders({})
            self.content = b"ok"
            self.text = "ok"
            self.cookies = {}
            self.cookie_specs = []
            self.saved_bytes = 0

    session = curl_reap.Session(retries=0)
    seen = []

    def fake_single(method, url, profile, hop_headers=None, body=b"",
                    content_type=None, timeout=30, proxy=None, verify=True,
                    auth=None, sink=None):
        seen.append(hop_headers)
        return LocalRaw()

    monkeypatch.setattr(session._transport, "_single_request", fake_single)
    session.cookies.store("https://api.test/v1", {"session": "s3cr3t"})
    session.get("https://api.test/v2/items")
    flat = dict(seen[0])
    assert flat.get("Cookie") == "session=s3cr3t"
    # explicit user Cookie header wins over the jar
    session.get("https://api.test/v2/items", headers={"Cookie": "manual=1"})
    assert dict(seen[1])["Cookie"] == "manual=1"
    # other hosts get nothing
    session.get("https://elsewhere.test/")
    assert "Cookie" not in dict(seen[2])


def test_challenge_heuristic():
    wall = curl_reap.Response(status=202,
                              content=b"<title>Just a moment...</title>")
    page = curl_reap.Response(status=200, content=b"<h1>real content</h1>")
    assert wall.looks_like_challenge
    assert not page.looks_like_challenge


# ------------------------------------------------- live loopback servers

class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/setcookie":
            self.send_response(200)
            self.send_header("Set-Cookie", "reap=1; Path=/")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/whoami":
            cookie = self.headers.get("Cookie") or ""
            body = ("cookie:" + cookie).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/hop"):
            self.send_response(302)
            self.send_header("Set-Cookie", "hop=yes; Path=/")
            self.send_header("Location", "/whoami")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


@pytest.fixture(scope="module")
def httpd():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:%d" % server.server_address[1]
    server.shutdown()


def test_cookie_round_trip_against_real_server(httpd):
    with curl_reap.Session() as s:
        assert s.get(httpd + "/setcookie").ok
        r = s.get(httpd + "/whoami")
        assert r.text == "cookie:reap=1"


def test_redirect_hop_cookie_is_captured(httpd):
    with curl_reap.Session() as s:
        r = s.get(httpd + "/hop")  # 302 sets hop=yes, lands on /whoami
        assert "hop=yes" in r.text


def test_download_streams_exact_bytes(tmp_path):
    payload = bytes(range(256)) * 8192  # 2 MiB
    target = tmp_path / "blob.bin"

    class Blob(_Handler):
        def do_GET(self):
            if self.path == "/blob":
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                for i in range(0, len(payload), 65536):
                    self.wfile.write(payload[i:i + 65536])
            else:
                super().do_GET()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Blob)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = "http://127.0.0.1:%d" % server.server_address[1]
        with curl_reap.Session() as s:
            r = s.download(base + "/blob", str(target))
        data = target.read_bytes()
        assert data == payload
        assert r.meta["bytes"] == len(payload)
        assert r.meta["saved_to"] == str(target)
    finally:
        server.shutdown()


def test_download_decodes_gzip_bodies(tmp_path):
    import gzip

    payload = b"reap streams compressed bodies" * 4000
    target = tmp_path / "page.txt"

    class Gz(_Handler):
        def do_GET(self):
            if self.path == "/gz":
                body = gzip.compress(payload)
                self.send_response(200)
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                super().do_GET()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Gz)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = "http://127.0.0.1:%d" % server.server_address[1]
        with curl_reap.Session() as s:
            r = s.download(base + "/gz", str(target))
        assert target.read_bytes() == payload
        assert r.meta["bytes"] == len(payload)
    finally:
        server.shutdown()


# ------------------------------------------------------------ impersonation

def test_impersonate_alias_and_versioned_targets():
    # curl_cffi-style names resolve to versioned profiles
    s = curl_reap.Session(impersonate="chrome124")
    assert s.profile.name == "chrome124"
    assert s.profile is curl_reap.FINGERPRINTS["chrome124"]
    # short canonical names still work through the same door
    assert curl_reap.Session(impersonate="firefox").profile.name == "firefox"
    # alternate spellings normalize (curl_cffi's safari170 == safari17_0)
    assert resolve_profile("safari170").name == "safari17_0"
    assert resolve_profile("CHROME124").name == "chrome124"
    with pytest.raises(ValueError, match="chrome124"):
        curl_reap.Session(impersonate="netscape")


def test_impersonate_conflicts_with_profile():
    with pytest.raises(ValueError):
        s = curl_reap.Session()
        s.request("GET", "http://x/", profile="chrome", impersonate="firefox133")


def test_chrome_header_set_matches_real_navigation_order():
    headers = curl_reap.FINGERPRINTS["chrome124"].headers
    names = [n.lower() for n, _ in headers]
    values = {n.lower(): v for n, v in headers}
    # Chrome emits client hints before UA/Accept, sec-fetch before encoding
    assert names.index("sec-ch-ua") < names.index("sec-ch-ua-mobile") \
        < names.index("sec-ch-ua-platform") < names.index("user-agent")
    assert names[-3:] == ["accept-encoding", "accept-language",
                          names[-1]] or names.index("sec-fetch-dest") > names.index("upgrade-insecure-requests")
    # brand versions agree with the User-Agent major version
    assert '"Chromium";v="124"' in values["sec-ch-ua"]
    assert "Chrome/124.0.0.0" in values["user-agent"]
    # only advertise encodings the transport actually decodes
    assert values["accept-encoding"] == "gzip, deflate"


def test_edge_profile_brands_differ_from_chrome():
    edge = curl_reap.FINGERPRINTS["edge131"]
    chrome = curl_reap.FINGERPRINTS["chrome131"]
    edge_headers = {n.lower(): v for n, v in edge.headers}
    assert '"Microsoft Edge";v="131"' in edge_headers["sec-ch-ua"]
    assert edge_headers["user-agent"].endswith("Edg/131.0.0.0")
    assert '"Google Chrome";v="131"' not in edge_headers["sec-ch-ua"]
    # same TLS shape as same-version Chrome
    assert edge.ciphers == chrome.ciphers


def test_request_level_impersonate_wins(monkeypatch):
    session = curl_reap.Session(retries=0)
    captured = []

    def fake(method, url, profile, **kwargs):
        captured.append(profile)
        return _BareRaw()

    monkeypatch.setattr(session._transport, "request", fake)
    session.get("http://one.test/")
    session.get("http://two.test/", impersonate="safari18_0")
    assert captured[0].name == "chrome"
    assert captured[1].name == "safari18_0"
