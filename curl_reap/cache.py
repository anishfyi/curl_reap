"""Disk response cache: repeat GETs during development come from disk instead of
hammering the site (and instead of waiting on the network).

    s = reap.Session(cache=reap.DiskCache(ttl=3600))
    s.get(url)   # network
    s.get(url)   # disk, instant, resp.from_cache == True
"""
from __future__ import annotations

import hashlib
import json
import os
import time

DEFAULT_DIR = ".reap_cache"


class DiskCache:
    """Content-addressed store of (status, url, headers, body) keyed on method+url+params."""

    def __init__(self, directory=DEFAULT_DIR, ttl=3600.0, methods=("GET",)):
        self.directory = directory
        self.ttl = ttl
        self.methods = frozenset(m.upper() for m in methods)

    def accepts(self, method):
        return method.upper() in self.methods

    def _key(self, method, url, params):
        blob = json.dumps([method.upper(), url, params], sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def _paths(self, key):
        return (os.path.join(self.directory, key + ".json"),
                os.path.join(self.directory, key + ".body"))

    def get(self, method, url, params=None):
        """Return kwargs for Response(...) or None on miss/expiry."""
        meta_p, body_p = self._paths(self._key(method, url, params))
        try:
            with open(meta_p, encoding="utf-8") as fh:
                entry = json.load(fh)
            if self.ttl and time.time() - entry["saved_at"] > self.ttl:
                return None
            with open(body_p, "rb") as fh:
                content = fh.read()
        except (OSError, ValueError, KeyError):
            return None
        return {
            "status": entry["status"],
            "url": entry["url"],
            "headers": entry["headers"],
            "content": content,
        }

    def set(self, method, url, params, resp):
        os.makedirs(self.directory, exist_ok=True)
        meta_p, body_p = self._paths(self._key(method, url, params))
        tmp = meta_p + ".tmp"
        with open(body_p, "wb") as fh:
            fh.write(resp.content or b"")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"status": resp.status, "url": resp.url,
                       "headers": resp.headers, "saved_at": time.time()}, fh)
        os.replace(tmp, meta_p)

    def clear(self):
        if not os.path.isdir(self.directory):
            return 0
        n = 0
        for name in os.listdir(self.directory):
            if name.endswith((".json", ".body")):
                try:
                    os.remove(os.path.join(self.directory, name))
                    n += 1
                except OSError:
                    pass
        return n
