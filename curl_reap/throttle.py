"""AutoThrottle: adapt the delay to the server's observed latency so the crawl
stays polite and avoids IP bans, the way Scrapy's AutoThrottle does.

v0.2: also backs off hard on throttling signals (HTTP 429/503) and eases the
delay back down after sustained healthy responses.
"""
from __future__ import annotations

import threading
import time

SLOWDOWN_STATUSES = frozenset({429, 503})


class AutoThrottle:
    def __init__(self, base_delay=0.0, target_concurrency=8, max_delay=30.0, enabled=True):
        self.delay = base_delay
        self.base_delay = base_delay
        self.target = max(1, target_concurrency)
        self.max_delay = max_delay
        self.enabled = enabled
        self._latencies = []
        self._ok_streak = 0
        self._lock = threading.Lock()

    def observe(self, latency, status=None):
        if not self.enabled:
            return
        with self._lock:
            if status in SLOWDOWN_STATUSES:
                # got rate-limited: double the delay immediately
                self.delay = min(self.max_delay, max(self.delay, 0.5) * 2)
                self._ok_streak = 0
                return
            self._latencies.append(latency)
            self._latencies = self._latencies[-20:]
            avg = sum(self._latencies) / len(self._latencies)
            # aim for ~target concurrent requests: per-request delay = latency / target
            target_delay = max(self.base_delay, avg / self.target)
            self._ok_streak += 1
            if self._ok_streak >= 5 and self.delay > target_delay:
                # sustained health: relax halfway back toward target
                self.delay = max(target_delay, self.delay * 0.5)
            else:
                self.delay = min(self.max_delay, target_delay)

    def wait(self):
        with self._lock:
            d = self.delay if self.enabled else 0
        if d > 0:
            time.sleep(d)
