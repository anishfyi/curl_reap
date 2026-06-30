"""The crawl engine (the Scrapy idea, kept small): concurrent fetching with
dedup, retries, AutoThrottle, and item pipelines, on top of the impersonating
transport. Spider callbacks yield items (dicts) and further Requests.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from .http import Session
from .pipelines import DedupPipeline
from .spider import Request
from .throttle import AutoThrottle


class Reaper:
    def __init__(self, spider, concurrency=8, retries=2, throttle=True, delay=0.0,
                 impersonate="chrome124", pipelines=None, dedup=True, on_item=None,
                 max_pages=None):
        self.spider = spider
        self.concurrency = concurrency
        self.max_pages = max_pages
        self.session = Session(impersonate=impersonate, retries=retries)
        self.throttle = AutoThrottle(base_delay=delay, target_concurrency=concurrency, enabled=throttle)
        self.pipelines = list(pipelines or [])
        if dedup and not any(isinstance(p, DedupPipeline) for p in self.pipelines):
            self.pipelines.insert(0, DedupPipeline())
        self.on_item = on_item
        self._seen = set()
        self.items = []
        self._lock = threading.Lock()
        self.stats = {"requests": 0, "items": 0, "errors": 0, "dropped": 0}

    def _fetch_and_parse(self, req):
        with self._lock:
            fp = req.fingerprint()
            if fp in self._seen:
                return []
            self._seen.add(fp)
            if self.max_pages and self.stats["requests"] >= self.max_pages:
                return []
        self.throttle.wait()
        import time
        t0 = time.time()
        try:
            resp = self.session.request(req.method, req.url, meta=req.meta, **req.kw)
        except Exception:  # noqa: BLE001
            with self._lock:
                self.stats["errors"] += 1
            return []
        self.throttle.observe(time.time() - t0)
        with self._lock:
            self.stats["requests"] += 1
        callback = req.callback or self.spider.parse
        produced = []
        try:
            for out in (callback(resp) or []):
                produced.append(out)
        except Exception:  # noqa: BLE001
            with self._lock:
                self.stats["errors"] += 1
        return produced

    def run(self):
        for p in self.pipelines:
            p.open()
        frontier = list(self.spider.start())
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            while frontier:
                futures = [pool.submit(self._fetch_and_parse, r) for r in frontier]
                frontier = []
                for fut in futures:
                    for out in fut.result():
                        if isinstance(out, Request):
                            frontier.append(out)
                        elif out is not None:
                            self._emit(out)
        for p in self.pipelines:
            p.close()
        return self.items

    def _emit(self, item):
        for p in self.pipelines:
            item = p.process(item)
            if item is None:
                with self._lock:
                    self.stats["dropped"] += 1
                return
        with self._lock:
            self.items.append(item)
            self.stats["items"] += 1
        if self.on_item:
            self.on_item(item)


def run(spider, **kw):
    """Run a Spider (class or instance) to completion. Returns the scraped items."""
    sp = spider() if isinstance(spider, type) else spider
    return Reaper(sp, **kw).run()
