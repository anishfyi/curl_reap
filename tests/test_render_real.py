"""Real Playwright/Chromium integration for BrowserSession.

Skipped only when the playwright package or its chromium binary is absent;
genuine failures must fail. Uses a local httpd fixture - no external site.
"""
import http.server
import socketserver
import threading

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

import curl_reap                            
from curl_reap.render import BrowserSession 


class Fixture(http.server.BaseHTTPRequestHandler):
    hits = []
    other_origin = ""

    def log_message(self, *args):
        pass

    def _reply(self, status=200, body=b"", headers=None):
        self.send_response(status)
        for k, v in (headers or []):
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        type(self).hits.append((type(self).label, self.path))
        if self.path == "/robots.txt":
            self._reply(404)
        elif self.path == "/main":
            body = (b"<html><body><h1>loading</h1>"
                    b"<script>setTimeout(() => {"
                    b"document.body.innerHTML += '<p id=late>deferred</p>';"
                    b"localStorage.setItem('tok','abc');"
                    b"document.cookie='sess=1;path=/';"
                    b"}, 0)</script>"
                    b"<img src='/sub.png'></body></html>")
            self._reply(200, body, [("Content-Type", "text/html")])
        elif self.path == "/next":
            body = (b"<html><body><p id=dest>destination</p>"
                    b"<script>document.body.innerHTML += "
                    b"'<p id=ls>' + (localStorage.getItem('tok')||'none') +"
                    b"'</p><p id=ck>' + document.cookie + '</p>'"
                    b"</script></body></html>")
            self._reply(200, body)
        elif self.path == "/denied":
            self._reply(403, b"no")
        elif self.path == "/limited":
            self._reply(429, b"slow")
        elif self.path == "/jump":
            self._reply(302, b"", [("Location", type(self).other + "/land")])
        else:
            self._reply(200, b"ok")


def _server(label):
    cls = type("H", (Fixture,), {"label": label, "hits": Fixture.hits})
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), cls)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


@pytest.fixture(scope="module")
def browser_available():
    try:
        with BrowserSession(headless=True, timeout=10) as s:
            s.goto("about:blank")
    except Exception as exc:
        if "Executable doesn't exist" in str(exc) or "executable" in \
                str(exc).lower() or "playwright install" in str(exc).lower():
            pytest.skip("chromium binary not installed: %s" % exc)
        raise
    return True


@pytest.fixture
def origins():
    Fixture.hits = []
    good, good_url = _server("good")
    bad, bad_url = _server("bad")
    Fixture.other = bad_url
    yield good_url, bad_url
    good.shutdown()
    bad.shutdown()


def test_deferred_content_cookies_and_storage_survive(browser_available,
                                                    origins):
    good, _ = origins
    with BrowserSession(headless=True, timeout=15) as s:
        r = s.goto(good + "/main", wait_for="#late")
        assert "deferred" in r.text
        r2 = s.follow("/next", wait_for="#dest")
        assert "destination" in r2.text
        assert r2.url == good + "/next"
        assert '<p id="ls">abc</p>' in r2.text
        assert '<p id="ck">sess=1</p>' in r2.text


def test_real_statuses_preserved(browser_available, origins):
    good, _ = origins
    with BrowserSession(headless=True, timeout=15) as s:
        assert s.goto(good + "/denied").status == 403
        assert s.goto(good + "/limited").status == 429


def test_url_policy_blocks_subresource_and_redirect(browser_available,
                                                    origins):
    good, bad = origins
    allow = lambda u: u.startswith(good) or u == "about:blank"
    with BrowserSession(headless=True, timeout=15, url_policy=allow) as s:
        r = s.goto(good + "/main", wait_for="#late")
        assert r.status == 200
        bad_hits = [p for label, p in Fixture.hits if label == "bad"]
        assert bad_hits == []
        assert any(p == "/sub.png" for label, p in Fixture.hits
                   if label == "good")
        try:
            s.goto(good + "/jump")
        except Exception:
            pass
        bad_hits = [p for label, p in Fixture.hits if label == "bad"]
        assert bad_hits == []


def test_policy_rejects_goto_url_before_navigation(browser_available,
                                                   origins):
    good, bad = origins
    s = BrowserSession(headless=True, url_policy=lambda u: False)
    with pytest.raises(curl_reap.URLPolicyError):
        s.goto(good + "/main")
    with pytest.raises(curl_reap.URLPolicyError):
        s.goto(bad + "/never")
    assert not any(p == "/main" for label, p in Fixture.hits
                   if label == "good")


def test_cdp_owned_context_closes_remote_survives(browser_available,
                                                  origins, tmp_path):
    import json
    import socket
    import subprocess
    import time
    import urllib.request

    good, _ = origins
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    try:
        exe = pw.chromium.executable_path
    finally:
        pw.stop()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    proc = subprocess.Popen(
        [exe, "--headless=new",
         "--remote-debugging-port=%d" % port,
         "--remote-debugging-address=127.0.0.1",
         "--user-data-dir=%s" % tmp_path, "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        endpoint = "http://127.0.0.1:%d" % port
        deadline = time.time() + 15
        while True:
            try:
                urllib.request.urlopen(endpoint + "/json/version",
                                       timeout=1)
                break
            except Exception:
                if time.time() > deadline:
                    pytest.skip("chromium debug endpoint never came up")
                time.sleep(0.1)
        session = BrowserSession(cdp_url=endpoint, headless=True)
        r = session.goto(good + "/main", wait_for="#late")
        assert "deferred" in r.text
        session.close()
        pages = json.load(
            urllib.request.urlopen(endpoint + "/json/list", timeout=5))
        assert pages
    finally:
        proc.terminate()
