"""Async transport: the same impersonating fetch, awaitable.

    import asyncio, curl_reap as reap

    async def main():
        async with reap.AsyncSession() as s:
            pages = await asyncio.gather(*(s.get(u) for u in urls))

    # or one-shot:
    page = await reap.aget("https://example.com")

Returns the same Response object as the sync API, so .css()/.jsonld()/.markdown()
all work identically.
"""
from __future__ import annotations

import asyncio
import time

from curl_cffi import requests as _cffi

from .http import DEFAULT_IMPERSONATE, FINGERPRINTS, Response, RetryPolicy, _pick


class AsyncSession:
    """Awaitable twin of Session (impersonation, retries, rotation)."""

    def __init__(self, impersonate=DEFAULT_IMPERSONATE, headers=None, timeout=30,
                 retries=2, rotate=None, fingerprints=None, retry_policy=None, **kw):
        self.impersonate = impersonate
        self.timeout = timeout
        self.rotate = rotate
        self.fingerprints = tuple(fingerprints or FINGERPRINTS)
        self.retry_policy = retry_policy or RetryPolicy(retries=retries)
        self._headers = dict(headers or {})
        self._counter = 0
        self._s = _cffi.AsyncSession(impersonate=impersonate, **kw)

    async def request(self, method, url, **kw):
        meta = kw.pop("meta", None)
        policy = kw.pop("retry_policy", None) or self.retry_policy
        kw.setdefault("timeout", self.timeout)
        merged = dict(self._headers)
        merged.update(kw.pop("headers", {}) or {})
        if merged:
            kw["headers"] = merged

        attempt = 0
        last_exc = None
        while True:
            n = self._counter
            self._counter += 1
            call = dict(kw)
            if self.rotate:
                call.setdefault("impersonate", _pick(self.fingerprints, n, self.rotate))
            else:
                call.setdefault("impersonate", self.impersonate)
            t0 = time.time()
            try:
                raw = await self._s.request(method, url, **call)
            except Exception as exc:  # noqa: BLE001
                raw, last_exc = None, exc
            if raw is None:
                if attempt >= policy.retries:
                    raise last_exc
                await asyncio.sleep(policy.delay(attempt))
                attempt += 1
                continue
            resp = Response(raw, meta=meta, elapsed=time.time() - t0)
            if policy.should_retry_status(resp.status) and attempt < policy.retries:
                await asyncio.sleep(policy.delay(attempt, resp.headers.get("Retry-After")))
                attempt += 1
                continue
            return resp

    async def get(self, url, **kw):
        return await self.request("GET", url, **kw)

    async def post(self, url, **kw):
        return await self.request("POST", url, **kw)

    async def head(self, url, **kw):
        return await self.request("HEAD", url, **kw)

    async def close(self):
        try:
            await self._s.close()
        except Exception:  # noqa: BLE001
            pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()


async def aget(url, **kw):
    """One-shot async GET (opens and closes its own session)."""
    async with AsyncSession() as s:
        return await s.get(url, **kw)


async def apost(url, **kw):
    async with AsyncSession() as s:
        return await s.post(url, **kw)
