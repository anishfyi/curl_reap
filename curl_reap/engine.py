"""The crawl engine (the Scrapy idea, kept small): concurrent fetching with
dedup, retries, AutoThrottle, and item pipelines, on top of the ordered HTTP
transport. Spider callbacks yield items (dicts) and further Requests.

v0.2: a continuous scheduler replaces the old batch waves - workers pull from a
priority queue as soon as they're free, so one slow page no longer stalls the
crawl. Adds per-domain politeness, robots.txt respect, depth limits, domain
confinement, errbacks, and a stats/logging surface.
"""
from __future__ import annotations

import heapq
import itertools
import logging
import threading
import time
from urllib.parse import urlparse

from .http import Session
from .pipelines import DedupPipeline
from .spider import Request
from .throttle import AutoThrottle

log = logging.getLogger("curl_reap")


class _Frontier:
    """Thread-safe priority queue of Requests (higher priority first, FIFO ties)."""

    def __init__(self):
        self._heap = []
        self._tick = itertools.count()
        self._cv = threading.Condition()
        self._open = 0          # requests scheduled but not fully processed
        self._closed = False

    def put(self, req):
        with self._cv:
            self._open += 1
            heapq.heappush(self._heap, (-req.priority, next(self._tick), req))
            self._cv.notify()

    def get(self):
        """Next request, or None when the crawl is complete."""
        with self._cv:
            while True:
                if self._heap:
                    return heapq.heappop(self._heap)[2]
                if self._open == 0 or self._closed:
                    return None
                self._cv.wait(timeout=0.1)

    def task_done(self):
        with self._cv:
            self._open -= 1
            if self._open <= 0:
                self._cv.notify_all()

    def close(self):
        with self._cv:
            self._closed = True
            self._cv.notify_all()


class _RobotsGate:
    """Per-host robots.txt fetch, cached and fail-open. Beyond can_fetch it also
    reads Crawl-delay (fed into the throttle) and Sitemap directives (discovery)."""

    def __init__(self, session, enabled=True, agent="*"):
        self.session = session
        self.enabled = enabled
        self.agent = agent
        self._parsers = {}
        self._lock = threading.Lock()

    def _parser_for(self, url):
        from urllib import robotparser
        host = urlparse(url)
        root = f"{host.scheme}://{host.netloc}"
        with self._lock:
            rp = self._parsers.get(root)
        if rp is not None:
            return rp
        rp = robotparser.RobotFileParser()
        try:
            resp = self.session.get(root + "/robots.txt", retries=0)
            if resp.ok:
                rp.parse(resp.text.splitlines())
            else:
                rp.allow_all = True
        except Exception:  # noqa: BLE001
            rp.allow_all = True
        with self._lock:
            self._parsers.setdefault(root, rp)
            return self._parsers[root]

    def allowed(self, url):
        if not self.enabled:
            return True
        try:
            return self._parser_for(url).can_fetch(self.agent, url)
        except Exception:  # noqa: BLE001
            return True

    def crawl_delay(self, url):
        """The Crawl-delay the site asks for (seconds), or None."""
        if not self.enabled:
            return None
        try:
            d = self._parser_for(url).crawl_delay(self.agent)
            return float(d) if d is not None else None
        except (AttributeError, ValueError, TypeError):
            return None

    def sitemaps(self, url):
        """Sitemap URLs declared in the host's robots.txt."""
        try:
            return list(self._parser_for(url).site_maps() or [])
        except AttributeError:
            return []


class Reaper:
    """Runs one Spider to completion.

    concurrency   worker threads
    throttle      AutoThrottle on/off (per-domain)
    delay         base delay between requests to the same domain
    respect_robots  check robots.txt before fetching (default False, opt in)
    max_pages     hard cap on fetched pages
    max_depth     cap on follow depth (also settable on the Spider)
    """

    def __init__(self, spider, concurrency=8, retries=2, throttle=True, delay=0.0,
                 profile="chrome", pipelines=None, dedup=True, on_item=None,
                 max_pages=None, max_depth=None, respect_robots=False, session=None,
                 cache=None, rotate=None, proxy=None):
        self.spider = spider
        self.concurrency = concurrency
        self.max_pages = max_pages
        self.max_depth = max_depth if max_depth is not None else getattr(spider, "max_depth", None)
        self.session = session or Session(
            profile=profile, retries=retries, cache=cache, rotate=rotate,
            proxy=proxy, headers=getattr(spider, "custom_headers", None))
        self.robots = _RobotsGate(self.session, enabled=respect_robots)
        self._base_delay = delay
        self._throttle_enabled = throttle
        self._throttles = {}
        self.pipelines = list(pipelines or [])
        if dedup and not any(isinstance(p, DedupPipeline) for p in self.pipelines):
            self.pipelines.insert(0, DedupPipeline())
        self.on_item = on_item
        self._seen = set()
        self.items = []
        self._lock = threading.Lock()
        self.stats = {"requests": 0, "items": 0, "errors": 0, "dropped": 0,
                      "robots_blocked": 0, "offsite_dropped": 0}
        allowed = getattr(spider, "allowed_domains", None)
        self._allowed = tuple(d.lstrip(".").lower() for d in allowed) if allowed else None

    # --- helpers -------------------------------------------------------------
    def _throttle_for(self, url):
        domain = urlparse(url).netloc
        with self._lock:
            th = self._throttles.get(domain)
        if th is not None:
            return th
        # Let the site's Crawl-delay set a floor on how fast we hit this domain.
        floor = self._base_delay
        cd = self.robots.crawl_delay(url)
        if cd:
            floor = max(floor, cd)
        with self._lock:
            th = self._throttles.get(domain)
            if th is None:
                th = AutoThrottle(base_delay=floor,
                                  target_concurrency=self.concurrency,
                                  enabled=self._throttle_enabled)
                self._throttles[domain] = th
            return th

    @property
    def discovered_sitemaps(self):
        """Sitemap URLs declared in the robots.txt of hosts crawled so far."""
        out = []
        for rp in list(self.robots._parsers.values()):
            try:
                out.extend(rp.site_maps() or [])
            except AttributeError:
                pass
        return sorted(set(out))

    def _onsite(self, url):
        if self._allowed is None:
            return True
        host = urlparse(url).netloc.lower()
        return any(host == d or host.endswith("." + d) for d in self._allowed)

    def _admit(self, req):
        """Dedup + budget + scope checks. Returns True if the request may run."""
        with self._lock:
            if not req.dont_filter:
                fp = req.fingerprint()
                if fp in self._seen:
                    return False
                self._seen.add(fp)
            if self.max_pages and self.stats["requests"] >= self.max_pages:
                return False
        if not self._onsite(req.url):
            with self._lock:
                self.stats["offsite_dropped"] += 1
            return False
        depth = req.meta.get("depth", 0)
        if self.max_depth is not None and depth > self.max_depth:
            return False
        if not self.robots.allowed(req.url):
            with self._lock:
                self.stats["robots_blocked"] += 1
            log.info("robots.txt blocked %s", req.url)
            return False
        return True

    def _fail(self, req, exc):
        with self._lock:
            self.stats["errors"] += 1
        log.warning("error on %s: %s", req.url, exc)
        if req.errback:
            try:
                req.errback(exc)
            except Exception:  # noqa: BLE001
                log.exception("errback for %s raised", req.url)

    # --- the crawl loop --------------------------------------------------------
    def _process(self, req, frontier):
        try:
            if not self._admit(req):
                return
            throttle = self._throttle_for(req.url)
            throttle.wait()
            t0 = time.time()
            try:
                resp = self.session.request(req.method, req.url, meta=req.meta, **req.kw)
            except Exception as exc:  # noqa: BLE001
                self._fail(req, exc)
                return
            throttle.observe(time.time() - t0, status=resp.status)
            with self._lock:
                self.stats["requests"] += 1
            log.debug("%s %s (%.2fs)", resp.status, req.url, resp.elapsed)

            callback = req.callback or self.spider.parse
            try:
                outputs = callback(resp) or []
                for out in outputs:
                    if isinstance(out, Request):
                        out.meta.setdefault("depth", req.meta.get("depth", 0) + 1)
                        frontier.put(out)
                    elif out is not None:
                        self._emit(out)
            except Exception as exc:  # noqa: BLE001
                self._fail(req, exc)
        finally:
            frontier.task_done()

    def run(self):
        for p in self.pipelines:
            p.open()
        frontier = _Frontier()
        seeded = False
        for req in self.spider.start():
            req.meta.setdefault("depth", 0)
            frontier.put(req)
            seeded = True
        if not seeded:
            for p in self.pipelines:
                p.close()
            return self.items

        def worker():
            while True:
                req = frontier.get()
                if req is None:
                    return
                self._process(req, frontier)

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(self.concurrency)]
        t0 = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        frontier.close()
        self.stats["elapsed"] = round(time.time() - t0, 3)
        for p in self.pipelines:
            p.close()
        log.info("crawl finished: %s", self.stats)
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
