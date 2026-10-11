"""Optional JavaScript rendering via Playwright.

Some pages are empty over plain HTTP: single-page apps ship an empty shell
and bot walls serve a challenge stub. When a response has
``looks_like_challenge`` set or simply carries no content, ``render()`` gives
you the DOM after JavaScript has run.

This module needs an optional dependency::

    pip install "curl-reap[js]"
    playwright install chromium

Playwright is imported lazily, so curl_reap stays dependency-free for users
who never render.
"""
import time
from urllib.parse import unquote, urljoin, urlsplit

from .http import Response, URLPolicyError

__all__ = ["render", "render_if_empty", "BrowserSession"]

_ENGINES = ("chromium", "firefox", "webkit")
_WIRE_HEADERS = ("content-encoding", "content-length", "content-type")


def _playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise ImportError(
            "JS rendering needs Playwright: pip install 'curl-reap[js]' "
            "and then run 'playwright install chromium'"
        ) from exc
    return sync_playwright


def _proxy_dict(proxy):
    """Playwright proxy config; URL credentials become separate keys."""
    if not proxy:
        return None
    parts = urlsplit(proxy if "://" in proxy else "http://" + proxy)
    out = {"server": "%s://%s" % (parts.scheme, parts.netloc.rsplit("@", 1)[-1])}
    if parts.username is not None:
        out["username"] = unquote(parts.username)
        out["password"] = unquote(parts.password or "")
    return out


def _abort(route):
    try:
        route.abort()
    except Exception:
        pass


class BrowserSession:
    """A reusable real-browser session on top of Playwright.

    The browser is launched lazily on first use and kept alive for the
    session's lifetime: one context, one page, so cookies and storage carry
    between :meth:`goto` calls. Use as a context manager or call
    :meth:`close` (idempotent).

    Args:
        timeout: default navigation timeout in seconds.
        wait_until: default Playwright load state.
        proxy: optional proxy URL; credentials inside the URL are passed to
            Playwright as separate username/password and never logged.
        user_agent: override the browser User-Agent.
        browser_channel: an engine name ("chromium", "firefox", "webkit") or
            a Playwright channel string ("chrome", "msedge", ...) for
            launching a stock-brand Chromium build.
        headless: run without a visible window.
        cdp_url: optional CDP endpoint (``http://host:port`` or
            ``ws://...``) to attach to an authorized remote browser via
            ``connect_over_cdp``. The session always creates and owns a
            fresh context and page; closing disconnects from the browser
            and leaves pre-existing remote contexts alone.
        url_policy: optional callable gating every browser request
            (document + subresources) through ``context.route``. In this
            gated mode the browser also blocks service workers and cannot
            follow redirects itself: any 3xx response is aborted (use an
            HTTP :class:`~curl_reap.Session` for allowed redirect chains,
            and hand the final URL to the browser).
    """

    def __init__(self, *, timeout=30, wait_until="domcontentloaded", proxy=None,
                 user_agent=None, browser_channel="chromium", headless=True,
                 cdp_url=None, url_policy=None):
        self.timeout = timeout
        self.wait_until = wait_until
        self.proxy = proxy
        self.user_agent = user_agent
        self.browser_channel = browser_channel
        self.headless = headless
        self.cdp_url = cdp_url
        self.url_policy = url_policy
        self._pw = None
        self._browser = None
        self._context = None
        self._page = None
        self._remote = False

    def _route_guard(self):
        timeout_ms = self.timeout * 1000
        policy = self.url_policy

        def guard(route):
            try:
                allowed = policy(route.request.url)
            except Exception:
                allowed = False
            if not allowed:
                _abort(route)
                return
            try:
                fetched = route.fetch(max_redirects=0, timeout=timeout_ms)
            except Exception:
                _abort(route)
                return
            status = getattr(fetched, "status", None)
            if status is not None and 300 <= status < 400:
                _abort(route)
                return
            try:
                route.fulfill(response=fetched)
            except Exception:
                _abort(route)

        return guard

    def _ensure(self):
        if self._page is not None:
            return
        sync_playwright = _playwright()
        self._pw = sync_playwright().start()
        channel = self.browser_channel or "chromium"
        try:
            if self.cdp_url:
                self._browser = self._pw.chromium.connect_over_cdp(self.cdp_url)
                self._remote = True
            elif channel in _ENGINES:
                self._browser = getattr(self._pw, channel).launch(
                    headless=self.headless, proxy=_proxy_dict(self.proxy))
            else:
                self._browser = self._pw.chromium.launch(
                    headless=self.headless, channel=channel,
                    proxy=_proxy_dict(self.proxy))
            ctx_kw = {"user_agent": self.user_agent}
            if self.url_policy is not None:
                ctx_kw["service_workers"] = "block"
            self._context = self._browser.new_context(**ctx_kw)
            if self.url_policy is not None:
                self._context.route("**/*", self._route_guard())
            self._page = self._context.new_page()
        except Exception:
            self._teardown()
            raise

    def __enter__(self):
        self._ensure()
        return self

    def __exit__(self, *exc):
        self.close()

    @property
    def page(self):
        """The underlying Playwright page (opened on first access)."""
        self._ensure()
        return self._page

    @property
    def url(self):
        """Current page URL, or None before the first navigation."""
        return self._page.url if self._page is not None else None

    def goto(self, url, *, wait_for=None, script=None, timeout=None,
             wait_until=None):
        """Navigate the page to ``url`` and snapshot the DOM as a Response.

        ``wait_for`` waits for a CSS selector (bounded by the navigation
        timeout); ``script`` is evaluated after load; ``timeout`` and
        ``wait_until`` override the session defaults for this call.
        The Response carries the navigation's real status and final URL -
        ``status`` is None when Playwright reports no response - plus
        ``meta["rendered"] = True``, ``meta["request_url"]``, the measured
        elapsed time, and ``meta["nav_headers"]`` with the wire headers as
        reported (the snapshot itself is served as decoded UTF-8 DOM).
        ``url_policy`` is consulted before the browser even launches.
        """
        if self.url_policy is not None and not self.url_policy(url):
            raise URLPolicyError("url_policy rejected %s" % url)
        self._ensure()
        timeout_ms = (timeout if timeout is not None else self.timeout) * 1000
        started = time.monotonic()
        nav = self._page.goto(
            url, timeout=timeout_ms,
            wait_until=wait_until or self.wait_until)
        if wait_for:
            self._page.wait_for_selector(wait_for, timeout=timeout_ms)
        if script:
            self._page.evaluate(script)
        elapsed = time.monotonic() - started
        html = self._page.content()
        nav_headers = {}
        status = None
        if nav is not None:
            status = nav.status
            try:
                nav_headers = nav.all_headers()
            except Exception:
                nav_headers = {}
        nav_headers = {str(k): str(v) for k, v in (nav_headers or {}).items()}
        headers = {k: v for k, v in nav_headers.items()
                   if k.lower() not in _WIRE_HEADERS}
        headers["Content-Type"] = "text/html; charset=utf-8"
        response = Response(status=status, url=self._page.url,
                            headers=headers, text=html, elapsed=elapsed)
        response.meta["rendered"] = True
        response.meta["request_url"] = url
        response.meta["nav_headers"] = nav_headers
        return response

    def follow(self, target, **kwargs):
        """Resolve ``target`` against the current DOM ``<base>`` and goto it."""
        base = self._page.url if self._page is not None else ""
        if self._page is not None:
            snap = Response(status=200, url=self._page.url,
                            text=self._page.content())
            base = snap.urljoin("") or base
        return self.goto(urljoin(base, str(target)), **kwargs)

    def _teardown(self):
        context, browser, pw = self._context, self._browser, self._pw
        self._context = self._browser = self._pw = self._page = None
        self._remote = False
        try:
            if context is not None:
                context.close()
        except Exception:
            pass
        try:
            if browser is not None:
                browser.close()
        except Exception:
            pass
        try:
            if pw is not None:
                pw.stop()
        except Exception:
            pass

    def close(self):
        """Idempotent shutdown: owned context, browser, driver."""
        self._teardown()


def render(url, *, timeout=30, wait_until="networkidle", proxy=None,
           user_agent=None, browser_channel="chromium", headless=True,
           script=None):
    """Fetch ``url`` in a real browser and return a rendered Response.

    Args:
        url: page to load.
        timeout: navigation timeout in seconds.
        wait_until: Playwright load state ("networkidle", "load", ...).
        proxy: optional proxy server URL.
        user_agent: override the browser User-Agent.
        browser_channel: playwright channel ("chromium" default; try "chrome"
            for a stock-browser fingerprint).
        headless: run without a visible window.
        script: optional JS string executed after load (e.g. to scroll or
            click through interstitials); its result, if any, is ignored.

    The returned Response is fully parsed: .css(), .xpath(), .jsonld(),
    .markdown() all work on the rendered DOM. It carries
    ``meta["rendered"] = True``. Rendering is for ordinary JS pages; it is
    not wired to execute or retry challenge interstitials.
    """
    with BrowserSession(timeout=timeout, wait_until=wait_until, proxy=proxy,
                        user_agent=user_agent, browser_channel=browser_channel,
                        headless=headless) as session:
        return session.goto(url, script=script)


def render_if_empty(response, *, min_bytes=2000, **kw):
    """Render ``response.url`` only when the HTTP body looks hollow.

    Returns ``(response, rendered_or_none)`` so callers keep both views.
    Forbidden, rate-limited, and challenge-looking responses are returned
    as-is: rendering is for ordinary JS-heavy pages, not for executing
    interstitial challenges.
    """
    hollow = (response.ok and not response.looks_like_challenge
              and len(response.content) < min_bytes)
    if not hollow:
        return response, None
    return response, render(response.url, **kw)
