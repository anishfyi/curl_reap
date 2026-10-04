"""RetryPolicy method gating, Retry-After honoring, sticky routes,
url_policy confinement, and Response.block_reason."""
import asyncio

import pytest

import curl_reap
from curl_reap.http import RetryPolicy, URLPolicyError

class _BareRaw:
    def __init__(self, status=200):
        from curl_reap.http import CaseInsensitiveHeaders
        self.status_code = status
        self.url = "http://test/"
        self.headers = CaseInsensitiveHeaders({})
        self.content = b"ok"
        self.text = "ok"
        self.cookies = {}
        self.cookie_specs = []
        self.saved_bytes = 0
        self.history = []

def test_post_is_not_retried_without_optin(monkeypatch):
    session = curl_reap.Session(retries=5)
    calls = []

    def fake(method, url, profile, **kw):
        calls.append(method)
        if method == "POST":
            raise curl_reap.TransportError("conn died")
        return _BareRaw()

    monkeypatch.setattr(session._transport, "request", fake)
    monkeypatch.setattr("curl_reap.http.time.sleep", lambda s: None)
    with pytest.raises(curl_reap.TransportError):
        session.post("http://x.test/", data=b"p")
    assert calls == ["POST"]
    session.get("http://x.test/")
    assert calls[-1] == "GET" and len(calls) >= 2

def test_post_retries_when_explicitly_opted_in(monkeypatch):
    policy = RetryPolicy(retries=2, backoff=0,
                         allowed_methods={"GET", "POST"})
    session = curl_reap.Session(retry_policy=policy)
    calls = []

    def fail(method, url, profile, **kw):
        calls.append(method)
        if method == "POST":
            raise curl_reap.TransportError("down")
        return _BareRaw()

    monkeypatch.setattr(session._transport, "request", fail)
    monkeypatch.setattr("curl_reap.http.time.sleep", lambda s: None)
    with pytest.raises(curl_reap.TransportError):
        session.post("http://x.test/", data=b"p")
    assert calls == ["POST", "POST", "POST"]

def test_post_not_retried_on_retryable_status(monkeypatch):
    session = curl_reap.Session(retries=3)
    calls = []

    def fake(method, url, profile, **kw):
        calls.append(method)
        return _BareRaw(status=503)

    monkeypatch.setattr(session._transport, "request", fake)
    monkeypatch.setattr("curl_reap.http.time.sleep", lambda s: None)
    session.post("http://x.test/", data=b"p")
    session.get("http://x.test/")
    assert calls == ["POST", "GET", "GET", "GET", "GET"]

def test_retry_after_is_not_truncated_to_max_backoff():
    policy = RetryPolicy(retries=1, backoff=0.1, max_backoff=5.0)
    assert policy.delay(0, retry_after="120") == 120.0
    assert policy.delay(0, retry_after="0.5") == 0.5
    assert policy.delay(3) <= 5.0

def test_sticky_session_pins_route_and_never_rotates(monkeypatch):
    session = curl_reap.Session(
        profiles=["chrome", "firefox", "safari"],
        proxy=["http://p1:1", "http://p2:2"], rotate="random",
        sticky=True)
    routes = {session._route() for _ in range(20)}
    assert len(routes) == 1
    profile, proxy = session._route()
    assert profile is session.profiles[0] and proxy == "http://p1:1"

    captured = []

    def fake(method, url, profile, **kw):
        captured.append(profile.name)
        return _BareRaw(status=403)

    monkeypatch.setattr(session._transport, "request", fake)
    monkeypatch.setattr("curl_reap.http.time.sleep", lambda s: None)
    session.get("http://x.test/")
    assert captured == [session.profiles[0].name]

def test_url_policy_rejects_before_any_socket(monkeypatch):
    connect = []
    monkeypatch.setattr("curl_reap.http.socket.create_connection",
                        lambda *a, **k: connect.append(a) or None)
    session = curl_reap.Session(
        retries=0, url_policy=lambda u: ".good.test" in u)
    with pytest.raises(URLPolicyError):
        session.get("http://evil.test/page")
    assert connect == []
    monkeypatch.setattr(session._transport, "_single_request",
                        lambda *a, **k: _BareRaw())
    assert session.get("http://a.good.test/").ok

def test_url_policy_applies_to_params_and_redirects(monkeypatch):
    seen = []

    class RedirectRaw(_BareRaw):
        def __init__(self):
            super().__init__(status=302)
            self.headers["Location"] = "http://next.test/"

    def fake(method, url, profile, *a, **kw):
        seen.append(url)
        return RedirectRaw()

    session = curl_reap.Session(
        retries=0, url_policy=lambda u: "good.test" in u)
    monkeypatch.setattr(session._transport, "_single_request", fake)
    with pytest.raises(URLPolicyError):
        session.get("http://good.test/", params={"next": "evil"})
    assert "next=evil" in seen[0]

def test_url_policy_checked_even_for_cached_responses():
    cache_calls = []

    class C:
        def accepts(self, method):
            return True

        def get(self, *a):
            cache_calls.append(a)
            return {"status": 200, "url": "http://c.test/",
                    "headers": {}, "content": b"cached"}

        def get_stale(self, *a):
            return None

    session = curl_reap.Session(cache=C(), retries=0,
                                url_policy=lambda u: False)
    with pytest.raises(URLPolicyError):
        session.get("http://c.test/")
    assert cache_calls == []

def test_async_session_passes_url_policy_and_exposes_cookies():
    async def go():
        session = curl_reap.AsyncSession(
            retries=0, url_policy=lambda u: False)
        assert session.cookies is session._session.cookies
        with pytest.raises(URLPolicyError):
            await session.get("http://nope.test/")
        await session.close()

    asyncio.run(go())

def test_block_reason_maps_transport_statuses():
    assert curl_reap.Response(status=429).block_reason == "rate_limited"
    assert curl_reap.Response(status=407).block_reason == "proxy_auth_required"
    assert curl_reap.Response(status=403).block_reason == "forbidden"
    assert curl_reap.Response(status=404).block_reason is None
    assert curl_reap.Response(status=200, content=b"<h1>x</h1>"
                              ).block_reason is None

def test_challenge_form_heuristic():
    wall = (b"<html><body><form id='challenge'>"
            b"<input type='hidden' name=\"solution\" value=''>"
            b"<script>document.getElementById('challenge')"
            b".requestSubmit()</script></form></body></html>")
    assert curl_reap.Response(status=200, content=wall).block_reason == \
        "challenge"
    article = (b"<html><body><article><h1>How requestSubmit works</h1>"
               b"<p>Sites put a name=\"solution\" field in challenge forms "
               b"and call requestSubmit() to post it.</p>"
               b"<p>More discussion.</p></article></body></html>")
    assert not curl_reap.Response(status=200,
                                  content=article).looks_like_challenge
    assert curl_reap.Response(status=200,
                              content=article).block_reason is None
    assert curl_reap.Response(
        status=200, content=b"<title>Just a moment...</title>"
    ).block_reason == "challenge"

def test_render_if_empty_skips_blocked_and_challenge_pages():
    from curl_reap import render_if_empty
    for status, body in ((403, b"x" * 5000),
                         (429, b"x" * 5000),
                         (200, b"<title>Just a moment...</title>"),
                         (200, b"<h1>plenty</h1>" + b"x" * 5000)):
        resp = curl_reap.Response(status=status, content=body)
        assert render_if_empty(resp)[1] is None
