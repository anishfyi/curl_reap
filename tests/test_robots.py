"""robots.txt: the gate reads Crawl-delay and Sitemap directives, and the
per-domain throttle floors at the site's requested Crawl-delay."""
import curl_reap
from curl_reap.engine import Reaper, _RobotsGate

ROBOTS = (
    b"User-agent: *\n"
    b"Crawl-delay: 2\n"
    b"Disallow: /private\n"
    b"Sitemap: https://ex.com/sitemap.xml\n"
    b"Sitemap: https://ex.com/sitemap2.xml\n"
)


class _FakeSession:
    def get(self, url, **kw):
        return curl_reap.Response(content=ROBOTS, status=200, url=url,
                                  headers={"Content-Type": "text/plain"})


def test_gate_reads_delay_and_sitemaps():
    gate = _RobotsGate(_FakeSession(), enabled=True)
    assert gate.allowed("https://ex.com/page") is True
    assert gate.allowed("https://ex.com/private/x") is False
    assert gate.crawl_delay("https://ex.com/page") == 2.0
    assert set(gate.sitemaps("https://ex.com/page")) == {
        "https://ex.com/sitemap.xml", "https://ex.com/sitemap2.xml"}


def test_throttle_floors_at_crawl_delay():
    class Sp(curl_reap.Spider):
        start_urls = []

        def parse(self, page):
            return []

    r = Reaper(Sp(), respect_robots=True)
    r.robots = _RobotsGate(_FakeSession(), enabled=True)
    th = r._throttle_for("https://ex.com/page")
    assert th.base_delay >= 2.0
    assert set(r.discovered_sitemaps) == {
        "https://ex.com/sitemap.xml", "https://ex.com/sitemap2.xml"}
