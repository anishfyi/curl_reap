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
        # One file per entry: a JSON meta line, then the raw body. A single
        # os.replace() publishes both, so a concurrent reader can never see a
        # fresh meta next to a truncated body (the 1.x two-file layout could).
        return (os.path.join(self.directory, key + ".entry"),)

    def _load(self, path):
        """(meta dict, body bytes) or None; tolerant of concurrent writers."""
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            return None
        newline = blob.find(b"\n")
        if newline < 0:
            return None
        try:
            meta = json.loads(blob[:newline].decode("utf-8"))
        except ValueError:
            return None
        return meta, blob[newline + 1:]

    @staticmethod
    def _save(path, meta, body):
        tmp = "%s.%d.tmp" % (path, os.getpid())
        with open(tmp, "wb") as fh:
            fh.write(json.dumps(meta).encode("utf-8"))
            fh.write(b"\n")
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    def _read(self, method, url, params):
        """The full stored entry (meta + body) regardless of TTL, or None."""
        loaded = self._load(self._paths(self._key(method, url, params))[0])
        if loaded is None:
            return None
        meta, body = loaded
        entry = dict(meta)
        entry["content"] = body
        return entry

    def get(self, method, url, params=None):
        """Return kwargs for Response(...) for a fresh entry, or None on miss/expiry."""
        entry = self._read(method, url, params)
        if entry is None:
            return None
        if self.ttl and time.time() - entry["saved_at"] > self.ttl:
            return None
        return {
            "status": entry["status"],
            "url": entry["url"],
            "headers": entry["headers"],
            "content": entry["content"],
        }

    def get_stale(self, method, url, params=None):
        """The stored entry ignoring TTL, carrying etag/last_modified so the caller
        can revalidate with a conditional request. None when nothing is stored."""
        return self._read(method, url, params)

    def touch(self, method, url, params=None):
        """Mark a stored entry fresh again (after a 304 Not Modified)."""
        path = self._paths(self._key(method, url, params))[0]
        loaded = self._load(path)
        if loaded is None:
            return
        meta, body = loaded
        meta["saved_at"] = time.time()
        try:
            self._save(path, meta, body)
        except OSError:
            pass

    def set(self, method, url, params, resp):
        os.makedirs(self.directory, exist_ok=True)
        h = resp.headers
        path = self._paths(self._key(method, url, params))[0]
        meta = {"status": resp.status, "url": resp.url,
                "headers": dict(h) if not isinstance(h, dict) else h,
                "saved_at": time.time(),
                "etag": h.get("ETag"),
                "last_modified": h.get("Last-Modified")}
        self._save(path, meta, resp.content or b"")

    def clear(self):
        if not os.path.isdir(self.directory):
            return 0
        n = 0
        for name in os.listdir(self.directory):
            if name.endswith((".entry", ".json", ".body")):
                try:
                    os.remove(os.path.join(self.directory, name))
                    n += 1
                except OSError:
                    pass
        return n
