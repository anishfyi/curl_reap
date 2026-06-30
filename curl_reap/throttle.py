"""AutoThrottle: adapt the delay to the server's observed latency so the crawl
stays polite and avoids IP bans, the way Scrapy's AutoThrottle does.
"""
from __future__ import annotations

import threading
import time


class AutoThrottle:
    def __init__(self, base_delay=0.0, target_concurrency=8, max_delay=10.0, enabled=True):
        self.delay = base_delay
        self.target = max(1, target_concurrency)
        self.max_delay = max_delay
        self.enabled = enabled
        self._latencies = []
        self._lock = threading.Lock()

    def observe(self, latency):
        if not self.enabled:
            return
        with self._lock:
            self._latencies.append(latency)
            self._latencies = self._latencies[-20:]
            avg = sum(self._latencies) / len(self._latencies)
            # aim for ~target concurrent requests: per-request delay = latency / target
            self.delay = min(self.max_delay, max(0.0, avg / self.target))

    def wait(self):
        if self.enabled and self.delay > 0:
            time.sleep(self.delay)
