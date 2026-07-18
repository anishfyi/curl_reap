"""On an IP-level block (403/407/429) with a proxy pool, the session rotates
onto a fresh proxy and retries."""
import curl_reap


class _FakeRaw:
    def __init__(self, status, content=b""):
        self.status_code = status
        self.url = "http://x/"
        self.headers = {}
        self.content = content
        self.text = content.decode("utf-8", "replace")
        self.cookies = {}


def test_rotates_off_a_block(tmp_path):
    s = curl_reap.Session(proxy=["http://p1:8080", "http://p2:8080"])
    assert s.block_rotations == 2
    proxies_seen = []

    def fake(method, url, **kw):
        proxies_seen.append(kw.get("proxies"))
        return _FakeRaw(403) if len(proxies_seen) == 1 else _FakeRaw(200, b"ok")

    s._s.request = fake
    r = s.get("http://x/")
    assert r.status == 200 and r.text == "ok"
    assert len(proxies_seen) == 2
    assert proxies_seen[0] != proxies_seen[1]  # different proxy on the retry


def test_no_pool_means_no_rotation():
    s = curl_reap.Session()  # no proxies
    assert s.block_rotations == 0
    calls = []

    def fake(method, url, **kw):
        calls.append(1)
        return _FakeRaw(403)

    s._s.request = fake
    r = s.get("http://x/")
    assert r.status == 403
    assert len(calls) == 1  # returned the block, no rotation loop
