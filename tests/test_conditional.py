"""Conditional requests: a stale-but-present cache entry revalidates with
If-None-Match / If-Modified-Since, and a 304 serves the cached body."""
import time

import curl_reap


class _FakeRaw:
    def __init__(self, status, headers, content):
        self.status_code = status
        self.url = "http://x/"
        self.headers = headers
        self.content = content
        self.text = content.decode("utf-8", "replace")
        self.cookies = {}


def test_304_serves_cached_body(tmp_path):
    cache = curl_reap.DiskCache(directory=str(tmp_path), ttl=0.01)
    s = curl_reap.Session(cache=cache)
    sent_headers = []

    def fake(method, url, profile, **kw):
        sent_headers.append(kw.get("headers") or {})
        if len(sent_headers) == 1:
            return _FakeRaw(200, {"ETag": '"v1"', "Content-Type": "text/html"}, b"<h1>hello</h1>")
        return _FakeRaw(304, {}, b"")

    s._transport.request = fake

    r1 = s.get("http://x/")
    assert r1.status == 200 and "hello" in r1.text and not r1.from_cache

    time.sleep(0.02)  # let the TTL lapse so the next call revalidates
    r2 = s.get("http://x/")
    assert ("If-None-Match", '"v1"') in sent_headers[1]
    assert r2.status == 200 and "hello" in r2.text and r2.from_cache
