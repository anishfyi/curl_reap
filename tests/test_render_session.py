"""BrowserSession against a fake Playwright: launch-once semantics, honest
statuses, DOM-base follow, strict route gating, CDP detach, and the
render() delegation path."""
import sys
import types

import pytest

import curl_reap
from curl_reap.render import BrowserSession


class FakeNav:
    def __init__(self, status, headers=None):
        self.status = status
        self._headers = headers or {}

    def all_headers(self):
        return dict(self._headers)


class FakeRoute:
    def __init__(self, url, harness):
        self.request = types.SimpleNamespace(url=url)
        self._h = harness
        self.outcome = None
        self.fulfilled = None

    def continue_(self):
        self.outcome = "continued"

    def abort(self):
        self.outcome = "aborted"
        self._h.route_outcomes.append("aborted")

    def fetch(self, max_redirects=None, timeout=None):
        self._h.fetch_calls.append((self.request.url, max_redirects))
        status = self._h.fetch_statuses.get(self.request.url, 200)
        return types.SimpleNamespace(status=status)

    def fulfill(self, response=None):
        self.outcome = "fulfilled"
        self.fulfilled = response
        self._h.route_outcomes.append("fulfilled")


class FakePage:
    def __init__(self, harness):
        self._h = harness
        self.url = "about:blank"
        self.cookies = harness.cookies
        self.waits = []

    def goto(self, url, timeout=None, wait_until=None):
        self._h.gotos.append((url, wait_until))
        nav = self._h.script_pages.get(url)
        if nav is None:
            return None
        status, final_url, html, headers = nav
        self.url = final_url
        self._h.html = html
        return FakeNav(status, headers)

    def wait_for_selector(self, selector, timeout=None):
        self.waits.append((selector, timeout))

    def evaluate(self, script):
        self._h.evaluated.append(script)

    def content(self):
        return self._h.html


class FakeContext:
    def __init__(self, harness, kwargs):
        self._h = harness
        self.kwargs = kwargs
        self.closed = False
        self.routes = []

    def new_page(self):
        return FakePage(self._h)

    def route(self, pattern, handler):
        self.routes.append((pattern, handler))
        self._h.route_handler = handler

    def close(self):
        self.closed = True
        self._h.context_closed = True


class FakeBrowser:
    def __init__(self, harness):
        self._h = harness
        self.closed = False

    def new_context(self, **kwargs):
        self._h.contexts += 1
        self._h.context_kwargs = kwargs
        return FakeContext(self._h, kwargs)

    def close(self):
        self.closed = True
        self._h.browser_closed = True


class FakeLauncher:
    def __init__(self, harness, name):
        self._h = harness
        self.name = name

    def launch(self, **kw):
        self._h.launches.append((self.name, kw))
        return FakeBrowser(self._h)

    def connect_over_cdp(self, url):
        self._h.cdp.append(url)
        return FakeBrowser(self._h)


class FakePW:
    def __init__(self, harness):
        self.chromium = FakeLauncher(harness, "chromium")
        self.firefox = FakeLauncher(harness, "firefox")
        self.webkit = FakeLauncher(harness, "webkit")
        self.stopped = False

    def start(self):
        return self

    def stop(self):
        self.stopped = True


class Harness:
    def __init__(self):
        self.launches = []
        self.cdp = []
        self.contexts = 0
        self.context_kwargs = {}
        self.context_closed = False
        self.browser_closed = False
        self.gotos = []
        self.evaluated = []
        self.route_outcomes = []
        self.route_handler = None
        self.fetch_calls = []
        self.fetch_statuses = {}
        self.cookies = {}
        self.user_agent = None
        self.script_pages = {}
        self.html = "<html></html>"


@pytest.fixture
def pw(monkeypatch):
    harness = Harness()
    fake_pw = FakePW(harness)
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = lambda: fake_pw
    pkg = types.ModuleType("playwright")
    pkg.sync_api = sync_api
    monkeypatch.setitem(sys.modules, "playwright", pkg)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    return harness


def test_launch_once_and_close_idempotent(pw):
    session = BrowserSession()
    with session:
        pw.script_pages["http://a/"] = (200, "http://a/", "<h1>A</h1>", {})
        session.goto("http://a/")
        session.goto("http://a/")
        session._ensure()
    assert len(pw.launches) == 1
    assert pw.contexts == 1
    assert pw.context_closed and pw.browser_closed
    session.close()
    session.close()


def test_honest_statuses_and_missing_response(pw):
    with BrowserSession() as s:
        pw.script_pages["http://a/f"] = (403, "http://a/f", "<h1>x</h1>", {})
        pw.script_pages["http://a/r"] = (429, "http://a/r", "<h1>y</h1>", {})
        pw.script_pages["http://a/n"] = None
        assert s.goto("http://a/f").status == 403
        assert s.goto("http://a/r").status == 429
        assert s.goto("http://a/n").status is None


def test_snapshot_decodes_dom_and_strips_wire_headers(pw):
    with BrowserSession() as s:
        pw.script_pages["http://a/"] = (
            200, "http://a/", "<h1>café</h1>",
            {"content-type": "text/html; charset=iso-8859-1",
             "content-encoding": "br", "content-length": "999",
             "server": "fixture"})
        r = s.goto("http://a/")
        assert r.text == "<h1>café</h1>"
        assert "café" in r.content.decode("utf-8")
        assert r.headers.get("content-type") == "text/html; charset=utf-8"
        assert "content-encoding" not in {k.lower() for k in r.headers}
        assert "content-length" not in {k.lower() for k in r.headers}
        assert r.headers.get("server") == "fixture"
        assert r.meta["nav_headers"]["content-encoding"] == "br"
        assert r.meta["request_url"] == "http://a/"


def test_redirect_final_url_and_elapsed_meta(pw):
    with BrowserSession() as s:
        pw.script_pages["http://a/redir"] = (
            200, "http://a/landed", "<h1>there</h1>", {})
        r = s.goto("http://a/redir")
        assert r.url == "http://a/landed"
        assert r.meta["rendered"] is True
        assert r.elapsed.total_seconds() >= 0


def test_cookie_continuity_via_one_context(pw):
    with BrowserSession() as s:
        pw.script_pages["http://a/1"] = (200, "http://a/1", "1", {})
        pw.script_pages["http://a/2"] = (200, "http://a/2", "2", {})
        s.goto("http://a/1")
        s.goto("http://a/2")
        assert pw.contexts == 1
        assert [g[0] for g in pw.gotos] == ["http://a/1", "http://a/2"]


def test_wait_for_selector_bounded_and_script(pw):
    with BrowserSession(timeout=7) as s:
        pw.script_pages["http://a/"] = (200, "http://a/", "<h1>x</h1>", {})
        s.goto("http://a/", wait_for="h1.ready", script="window.x=1")
        assert s._page.waits == [("h1.ready", 7000)]
        assert pw.evaluated == ["window.x=1"]


def test_follow_resolves_against_dom_base(pw):
    with BrowserSession() as s:
        pw.script_pages["http://a/dir/page"] = (
            200, "http://a/dir/page",
            '<base href="http://cdn.test/v2/"><p>x</p>', {})
        pw.script_pages["http://cdn.test/v2/next"] = (
            200, "http://cdn.test/v2/next", "n", {})
        s.goto("http://a/dir/page")
        r = s.follow("next")
        assert r.url == "http://cdn.test/v2/next"


def test_url_policy_rejects_goto_before_launch(pw):
    s = BrowserSession(url_policy=lambda u: "good.test" in u)
    with pytest.raises(curl_reap.URLPolicyError):
        s.goto("http://evil.test/")
    assert pw.launches == []


def test_gated_route_fetches_and_aborts(pw):
    with BrowserSession(url_policy=lambda u: "good.test" in u) as s:
        assert pw.context_kwargs["service_workers"] == "block"
        assert pw.route_handler is not None
        route = FakeRoute("http://good.test/x", pw)
        pw.route_handler(route)
        assert route.outcome == "fulfilled"
        assert pw.fetch_calls == [("http://good.test/x", 0)]
        route = FakeRoute("http://evil.test/tracker", pw)
        pw.route_handler(route)
        assert route.outcome == "aborted"
        route = FakeRoute("http://good.test/redir", pw)
        pw.fetch_statuses["http://good.test/redir"] = 302
        pw.route_handler(route)
        assert route.outcome == "aborted"


def test_proxy_url_credentials_become_launch_keys(pw):
    BrowserSession(proxy="http://user:p%40ss@proxy.local:8080").__enter__().close()
    proxy = pw.launches[0][1]["proxy"]
    assert proxy == {"server": "http://proxy.local:8080",
                     "username": "user", "password": "p@ss"}


def test_browser_channel_engine_vs_channel_string(pw):
    BrowserSession(browser_channel="firefox").__enter__().close()
    assert pw.launches[0][0] == "firefox" and "channel" not in pw.launches[0][1]
    BrowserSession(browser_channel="chrome").__enter__().close()
    name, kw = pw.launches[1]
    assert name == "chromium" and kw["channel"] == "chrome"


def test_cdp_owns_fresh_context_then_disconnects(pw):
    s = BrowserSession(cdp_url="http://browser.internal:9222")
    s.__enter__()
    assert pw.cdp == ["http://browser.internal:9222"]
    assert pw.contexts == 1
    s.close()
    assert pw.context_closed and pw.browser_closed


def test_render_delegates_one_shot(pw):
    from curl_reap.render import render
    pw.script_pages["http://a/"] = (200, "http://a/", "<h1>R</h1>", {})
    r = render("http://a/")
    assert r.text == "<h1>R</h1>" and r.meta["rendered"]
    assert pw.browser_closed


def test_reap_render_is_callable_not_module():
    assert callable(curl_reap.render)
    assert curl_reap.BrowserSession is BrowserSession
