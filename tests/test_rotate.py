"""Blocked IPs rotate through an explicitly configured proxy pool."""
import curl_reap


class _FakeRaw:
    def __init__(self, status, content=b""):
        self.status_code = status
        self.url = "http://x/"
        self.headers = {}
        self.content = content
        self.text = content.decode("utf-8", "replace")
        self.cookies = {}


def test_rotates_off_a_block(monkeypatch):
    session = curl_reap.Session(proxy=["http://p1:8080", "http://p2:8080"])
    assert session.block_rotations == 1
    proxies_seen = []

    def fake(method, url, profile, **kwargs):
        proxies_seen.append(kwargs.get("proxy"))
        return _FakeRaw(403) if len(proxies_seen) == 1 else _FakeRaw(200, b"ok")

    monkeypatch.setattr(session._transport, "request", fake)
    monkeypatch.setattr("curl_reap.http.time.sleep", lambda delay: None)
    response = session.get("http://x/")
    assert response.status == 200 and response.text == "ok"
    assert proxies_seen == ["http://p1:8080", "http://p2:8080"]


def test_no_pool_means_no_block_rotation(monkeypatch):
    session = curl_reap.Session(retries=0)
    assert session.block_rotations == 0
    calls = []

    def fake(method, url, profile, **kwargs):
        calls.append(1)
        return _FakeRaw(403)

    monkeypatch.setattr(session._transport, "request", fake)
    response = session.get("http://x/")
    assert response.status == 403
    assert len(calls) == 1


def test_profiles_rotate_across_retries(monkeypatch):
    session = curl_reap.Session(rotate="sequence", retries=1)
    names = []

    def fake(method, url, profile, **kwargs):
        names.append(profile.name)
        if len(names) == 1:
            raise curl_reap.http.TransportError("temporary")
        return _FakeRaw(200)

    monkeypatch.setattr(session._transport, "request", fake)
    monkeypatch.setattr("curl_reap.http.time.sleep", lambda delay: None)
    session.get("http://x/")
    assert names == ["chrome", "firefox"]
