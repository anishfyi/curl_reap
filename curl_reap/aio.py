"""Async facade for the standard-library transport.

The socket engine is synchronous, so this module runs each request with
``asyncio.to_thread``.  That keeps one implementation of byte serialization,
TLS profiles, connection pooling, retries, and decoding.  Cancellation stops
waiting for the worker but cannot interrupt a socket call already running in
its thread; the configured request timeout still bounds that work.
"""
from __future__ import annotations

import asyncio

from .http import Session


class AsyncSession:
    """Awaitable wrapper around a thread-safe :class:`curl_reap.Session`."""

    def __init__(self, profile="chrome", headers=None, timeout=30, retries=2,
                 proxy=None, rotate=None, profiles=None, retry_policy=None,
                 cache=None, on_response=None, block_rotations=None, verify=True,
                 allow_redirects=True, max_redirects=10, impersonate=None):
        self._session = Session(
            profile=profile, headers=headers, timeout=timeout, retries=retries,
            proxy=proxy, rotate=rotate, profiles=profiles,
            retry_policy=retry_policy, cache=cache, on_response=on_response,
            block_rotations=block_rotations, verify=verify,
            allow_redirects=allow_redirects, max_redirects=max_redirects,
            impersonate=impersonate)

    @property
    def profile(self):
        return self._session.profile

    @property
    def retries(self):
        return self._session.retries

    async def request(self, method, url, **kwargs):
        return await asyncio.to_thread(self._session.request, method, url, **kwargs)

    async def get(self, url, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self.request("POST", url, **kwargs)

    async def head(self, url, **kwargs):
        return await self.request("HEAD", url, **kwargs)

    async def download(self, url, path, **kwargs):
        """Stream a URL straight to ``path`` off the event loop's thread."""
        kwargs.setdefault("timeout", self._session.timeout)
        return await asyncio.to_thread(self._session.download, url, path, **kwargs)

    async def close(self):
        await asyncio.to_thread(self._session.close)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()


async def aget(url, **kwargs):
    """One-shot async GET using a temporary session."""
    async with AsyncSession() as session:
        return await session.get(url, **kwargs)


async def apost(url, **kwargs):
    async with AsyncSession() as session:
        return await session.post(url, **kwargs)


__all__ = ["AsyncSession", "aget", "apost"]
