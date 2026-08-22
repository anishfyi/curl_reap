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
from .http import Response

__all__ = ["render"]


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
    ``meta["rendered"] = True``.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise ImportError(
            "JS rendering needs Playwright: pip install 'curl-reap[js]' "
            "and then run 'playwright install chromium'"
        ) from exc

    with sync_playwright() as pw:
        launcher = getattr(pw, browser_channel, None) or pw.chromium
        browser = launcher.launch(headless=headless,
                                  proxy={"server": proxy} if proxy else None)
        try:
            context = browser.new_context(user_agent=user_agent)
            page = context.new_page()
            page.goto(url, timeout=timeout * 1000, wait_until=wait_until)
            if script:
                page.evaluate(script)
            html = page.content()
            status = 200
            final_url = page.url
        finally:
            browser.close()

    response = Response(status=status, url=final_url,
                        headers={"Content-Type": "text/html; charset=utf-8"},
                        content=html.encode("utf-8"))
    response.meta["rendered"] = True
    return response


def render_if_empty(response, *, min_bytes=2000, **kw):
    """Render ``response.url`` only when the HTTP body looks hollow.

    Returns ``(response, rendered_or_none)`` so callers keep both views.
    """
    hollow = (not response.ok or len(response.content) < min_bytes
              or response.looks_like_challenge)
    if not hollow:
        return response, None
    return response, render(response.url, **kw)
