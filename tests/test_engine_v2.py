"""Reaper hardening: admission budgets, per-domain concurrency, queue
bounds, scheduled dedup, blocked-response errbacks, emit ordering, and
cleanup semantics."""
import threading
import time

import pytest

import curl_reap
from curl_reap import Request, Spider
from curl_reap.engine import Reaper
from curl_reap.http import Response
from curl_reap.throttle import AutoThrottle

class CountSession:
    """Fake session: records in-flight concurrency per host."""

    def __init__(self, pages=None, status=200, delay=0.0, fail_for=None):
        self.pages = pages or {}
        self.status = status
        self.delay = delay
        self.fail_for = fail_for or set()
        self.calls = []
        self.closed = False
        self._active = {}
        self._peak = {}
        self._lock = threading.Lock()

    def request(self, method, url, meta=None, **kw):
        from urllib.parse import urlparse
        host = urlparse(url).hostname
        with self._lock:
            self.calls.append(url)
            self._active[host] = self._active.get(host, 0) + 1
            self._peak[host] = max(self._peak.get(host, 0),
                                   self._active[host])
        try:
            if self.delay:
                time.sleep(self.delay)
            if url in self.fail_for:
                raise curl_reap.TransportError("dead")
            body = self.pages.get(url, "<p>x</p>")
            return Response(status=self.status, url=url, headers={},
                            text=body, meta=meta)
        finally:
            with self._lock:
                self._active[host] -= 1

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def close(self):
        self.closed = True

    def peak(self, host):
        return self._peak.get(host, 0)

class Fanout(Spider):
    start_urls = []
    allowed_domains = None

    def parse(self, page):
        yield {"url": page.url}
        for link in page.links():
            yield page.follow(link["url"])

def _spider(urls, allowed=None):
    cls = type("S", (Fanout,), {"start_urls": list(urls),
                               "allowed_domains": allowed})
    return cls()

def test_max_pages_budget_reserved_atomically_under_concurrency():
    urls = ["https://s.test/p%d" % i for i in range(50)]
    session = CountSession()
    r = Reaper(_spider(urls), concurrency=20, session=session,
               throttle=False, max_pages=7)
    r.run()
    assert r.stats["requests"] <= 7
    assert r.stats["attempts"] <= 7
    assert len(session.calls) <= 7

def test_max_pages_zero_fetches_nothing_and_failures_count():
    session = CountSession()
    r = Reaper(_spider(["https://s.test/a"]), session=session,
               throttle=False, max_pages=0)
    r.run()
    assert session.calls == []

    urls = ["https://s.test/a", "https://s.test/b", "https://s.test/c"]
    session = CountSession(fail_for=set(urls))
    r = Reaper(_spider(urls), session=session, throttle=False,
               max_pages=2)
    r.run()
    assert len(session.calls) == 2
    assert r.stats["errors"] == 2

def test_constructor_validates_knobs():
    with pytest.raises(ValueError):
        Reaper(_spider([]), concurrency=0)
    with pytest.raises(ValueError):
        Reaper(_spider([]), max_pages=-1)
    with pytest.raises(ValueError):
        Reaper(_spider([]), max_pending=-1)
    with pytest.raises(ValueError):
        Reaper(_spider([]), per_domain_concurrency=0)

def test_per_domain_concurrency_bounds_active_requests():
    pages = {"https://one.test/p%d" % i: "<p>x</p>" for i in range(12)}
    session = CountSession(pages, delay=0.05)
    r = Reaper(_spider(list(pages)), concurrency=8, session=session,
               throttle=False, per_domain_concurrency=3)
    r.run()
    assert session.peak("one.test") <= 3
    assert r.stats["requests"] == 12

def test_supplied_session_survives_run_but_owned_is_closed():
    session = CountSession()
    Reaper(_spider(["https://s.test/a"]), session=session,
           throttle=False).run()
    assert not session.closed

def test_owned_session_is_closed_even_on_pipeline_error():
    class Boom(curl_reap.Pipeline):
        def open(self):
            raise RuntimeError("open died")

    captured = {}

    class SpySession(curl_reap.Session):
        def close(self):
            captured["closed"] = True
            super().close()

    r = Reaper(_spider(["https://s.test/a"]),
               session=SpySession(retries=0), pipelines=[Boom()],
               throttle=False)
    r._owns_session = True
    with pytest.raises(RuntimeError):
        r.run()
    assert captured.get("closed") is True

def test_pipeline_process_error_is_counted_and_pipelines_close():
    events = []

    class Rec(curl_reap.Pipeline):
        def open(self):
            events.append("open")

        def process(self, item):
            raise RuntimeError("process died")

        def close(self):
            events.append("close")

    r = Reaper(_spider(["https://s.test/a"]), session=CountSession(),
               pipelines=[Rec()], throttle=False)
    r.run()
    assert events == ["open", "close"]
    assert r.stats["errors"] >= 1

def test_collect_items_false_streams_without_storing():
    seen = []
    urls = ["https://s.test/a", "https://s.test/b"]
    r = Reaper(_spider(urls), session=CountSession(), throttle=False,
               collect_items=False, on_item=seen.append)
    items = r.run()
    assert items == [] and r.items == []
    assert sorted(i["url"] for i in seen) == urls
    assert r.stats["items"] == 2

def test_max_pending_drops_overflow_without_deadlock():
    links = "".join('<a href="/i%d">x</a>' % i for i in range(500))
    session = CountSession({"https://s.test/": links}, delay=0.02)
    r = Reaper(_spider(["https://s.test/"]), concurrency=2,
               session=session, throttle=False, max_pending=10)
    r.run()
    assert r.stats["queue_dropped"] > 0
    assert r.stats["requests"] <= 11

def test_fragment_and_case_dedup_at_schedule_time():
    urls = ["https://s.test/a#frag", "https://s.test/a#other",
            "https://s.test/A"]
    session = CountSession()
    r = Reaper(_spider(urls), session=session, throttle=False)
    r.run()
    assert sorted(session.calls) == ["https://s.test/A",
                                     "https://s.test/a#frag"]

def test_request_fingerprint_keeps_falsey_bodies():
    a = Request("https://s.test/x", method="post", data={})
    b = Request("https://s.test/x", method="POST", data={"k": 1})
    c = Request("https://s.test/x", method="post")
    assert a.fingerprint() != b.fingerprint()
    assert a.fingerprint() != c.fingerprint()
    assert a.fingerprint().startswith("POST:https://s.test/x")

def test_allowed_domains_match_hostname_not_netloc_port():
    session = CountSession()
    sp = _spider(["https://s.test:8443/a"], allowed=["s.test"])
    Reaper(sp, session=session, throttle=False).run()
    assert session.calls == ["https://s.test:8443/a"]

def test_error_statuses_and_challenge_go_to_errback_not_parse():
    outcomes = []

    class S(Spider):
        start_urls = ["https://s.test/denied", "https://s.test/wall",
                      "https://s.test/slow", "https://s.test/ok"]

        def parse(self, page):
            outcomes.append(("parsed", page.url))
            yield {"u": page.url}

        def failed(self, what):
            outcomes.append(("failed", getattr(what, "status", what)))

        def start(self):
            for u in self.start_urls:
                yield Request(u, self.parse, errback=self.failed)

    pages = {
        "https://s.test/denied": "<p>no</p>",
        "https://s.test/wall": "<title>Just a moment...</title>",
        "https://s.test/slow": "<p>later</p>",
        "https://s.test/ok": "<p>yes</p>",
    }
    statuses = {"https://s.test/denied": 403, "https://s.test/slow": 429}

    class Multi(CountSession):
        def request(self, method, url, meta=None, **kw):
            if url in statuses:
                return Response(status=statuses[url], url=url,
                                headers={}, text="", meta=meta)
            return super().request(method, url, meta=meta, **kw)

    r = Reaper(S(), session=Multi(pages), throttle=False, concurrency=1)
    r.run()
    parsed = [u for kind, u in outcomes if kind == "parsed"]
    failed = sorted(s for kind, s in outcomes if kind == "failed")
    assert parsed == ["https://s.test/ok"]
    assert failed == [200, 403, 429]
    assert r.stats["blocked"] == 3
    assert r.stats["statuses"][403] == 1 and r.stats["statuses"][429] == 1

def test_throttle_slots_are_reserved_monotonically(monkeypatch):
    import curl_reap.throttle as th
    sleeps = []
    clock = {"now": 1000.0}
    monkeypatch.setattr(th.time, "monotonic", lambda: clock["now"])

    def fake_sleep(s):
        sleeps.append(s)
        clock["now"] += s

    monkeypatch.setattr(th.time, "sleep", fake_sleep)
    throttle = AutoThrottle(base_delay=1.0, enabled=True)

    def worker():
        throttle.wait()

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert throttle._next_slot == 1004.0
    assert sleeps == [1.0, 1.0, 1.0]

def test_retry_after_cooldown_holds_queued_requests(monkeypatch):
    import curl_reap.throttle as th
    clock = {"now": 500.0}
    monkeypatch.setattr(th.time, "monotonic", lambda: clock["now"])
    sleeps = []

    def fake_sleep(s):
        sleeps.append(s)
        clock["now"] += s

    monkeypatch.setattr(th.time, "sleep", fake_sleep)
    throttle = AutoThrottle(enabled=True)
    throttle.cooldown(10)
    throttle.wait()
    assert sleeps == [10.0]

def test_late_cooldown_pushes_out_already_waiting(monkeypatch):
    import curl_reap.throttle as th
    clock = {"now": 0.0}
    monkeypatch.setattr(th.time, "monotonic", lambda: clock["now"])
    sleeps = []
    slept_once = threading.Event()
    release_sleep = threading.Event()

    def fake_sleep(s):
        sleeps.append(s)
        if len(sleeps) == 1:
            slept_once.set()
            release_sleep.wait(5)
        clock["now"] += s

    monkeypatch.setattr(th.time, "sleep", fake_sleep)
    throttle = AutoThrottle(base_delay=5.0, enabled=True)
    throttle.wait()
    finished = []
    t = threading.Thread(target=lambda: (throttle.wait(),
                                         finished.append(clock["now"])))
    t.start()
    slept_once.wait(5)
    throttle.cooldown(10)
    release_sleep.set()
    t.join()
    assert sleeps == [5.0, 5.0]
    assert finished == [10.0]

def test_max_pages_zero_makes_no_network_or_robots_calls():
    session = CountSession()
    sp = _spider(["https://s.test/a"])
    Reaper(sp, session=session, throttle=False, max_pages=0,
           respect_robots=True).run()
    assert session.calls == []

def test_budget_reserved_before_fetch_deterministic():
    release = threading.Event()
    entered = threading.Event()
    session = CountSession()

    real_request = session.request

    def gated(method, url, meta=None, **kw):
        entered.set()
        release.wait(timeout=5)
        return real_request(method, url, meta=meta, **kw)

    session.request = gated
    urls = ["https://s.test/p%d" % i for i in range(40)]
    r = Reaper(_spider(urls), concurrency=12, session=session,
               throttle=False, max_pages=3)
    runner = threading.Thread(target=r.run)
    runner.start()
    entered.wait(timeout=5)
    time.sleep(0.3)
    assert len(session.calls) <= 3
    release.set()
    runner.join(timeout=10)
    assert not runner.is_alive()
    assert len(session.calls) == 3
    assert r.stats["attempts"] == 3

def test_nonfetch_exception_fails_request_without_hanging():
    session = CountSession()
    r = Reaper(_spider(["https://s.test/a", "https://s.test/b"]),
               concurrency=1, session=session, throttle=True)
    import curl_reap.throttle as th
    boom = RuntimeError("slot reservation exploded")
    orig_wait = th.AutoThrottle.wait
    th.AutoThrottle.wait = lambda self: (_ for _ in ()).throw(boom)
    try:
        done = threading.Event()
        def go():
            r.run()
            done.set()
        t = threading.Thread(target=go)
        t.start()
        assert done.wait(timeout=10)
    finally:
        th.AutoThrottle.wait = orig_wait
    assert r.stats["errors"] == 2
    assert session.calls == []

def test_seen_only_grows_with_inserted_requests():
    links = "".join('<a href="/i%d">x</a>' % i for i in range(500))
    session = CountSession({"https://s.test/": links}, delay=0.02)
    r = Reaper(_spider(["https://s.test/"]), concurrency=2,
               session=session, throttle=False, max_pending=10)
    r.run()
    assert r.stats["queue_dropped"] > 0
    assert len(r._seen) <= 11 + r.stats["requests"]

def test_concurrent_retry_after_race_single_horizon():
    from curl_reap.throttle import AutoThrottle
    throttle = AutoThrottle(base_delay=0.0, enabled=True)
    t0 = time.monotonic()
    throttle.cooldown(0.3)
    ends = []
    def w():
        throttle.wait()
        ends.append(time.monotonic() - t0)
    threads = [threading.Thread(target=w) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert min(ends) >= 0.25

def test_fingerprint_distinguishes_body_and_params():
    base = "https://s.test/x"
    variants = [
        Request(base, method="post"),
        Request(base, method="post", data=b"a"),
        Request(base, method="post", data={}),
        Request(base, method="post", json=False),
        Request(base, method="post", params={"a": "1"}),
        Request(base, method="post", data={}, params={"a": "1"}),
    ]
    fps = [v.fingerprint() for v in variants]
    assert len(set(fps)) == len(fps)
