"""Engine tests that don't hit the network: we drive the scheduler with a fake
session so they're fast and deterministic."""
from curl_reap import Request, Spider
from curl_reap.engine import Reaper
from curl_reap.http import Response

PAGES = {
    "https://site.test/": '<a href="/a">A</a><a href="/b">B</a><a href="https://off.test/x">off</a>',
    "https://site.test/a": '<span class="v">alpha</span>',
    "https://site.test/b": '<span class="v">beta</span><a href="/a">dup</a>',
    "https://off.test/x": '<span class="v">offsite</span>',
}


class FakeSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, meta=None, **kw):
        self.calls.append(url)
        body = PAGES.get(url, "")
        return Response(status=200, url=url, headers={}, text=body, meta=meta)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)


class Crawl(Spider):
    start_urls = ["https://site.test/"]
    allowed_domains = ["site.test"]

    def parse(self, page):
        v = page.css_first("span.v::text")
        if v:
            yield {"url": page.url, "v": v}
        for link in page.links():
            yield page.follow(link["url"])


def test_crawl_dedups_and_confines_domain():
    r = Reaper(Crawl(), concurrency=4, session=FakeSession(), throttle=False)
    items = r.run()
    vals = sorted(i["v"] for i in items)
    assert vals == ["alpha", "beta"]           # offsite dropped, dup deduped
    assert r.stats["offsite_dropped"] >= 1
    assert r.stats["items"] == 2


def test_max_pages_budget():
    r = Reaper(Crawl(), concurrency=2, session=FakeSession(), throttle=False, max_pages=1)
    r.run()
    assert r.stats["requests"] <= 1


def test_priority_and_errback():
    seen = {}
    errors = []

    class S(Spider):
        start_urls = ["https://site.test/"]

        def parse(self, page):
            yield Request("https://site.test/a", self.done, priority=1,
                          errback=errors.append)

        def done(self, page):
            seen["hit"] = True
            return []

    Reaper(S(), concurrency=1, session=FakeSession(), throttle=False).run()
    assert seen.get("hit") is True
    assert errors == []
