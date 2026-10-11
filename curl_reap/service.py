"""Private extraction job API (FastAPI, optional ``server`` extra).

Single-page jobs only - the library crawler stays the interface for large
crawls. Every request body is size-capped while streaming, every URL is
normalized and pinned to an exact ``scheme://host:port`` allowlist before a
job exists, and all handlers return sanitized responses.
"""
from __future__ import annotations

import hmac
import json
import logging

from .jobs import canonicalize_origin, normalize_url, origin_of

log = logging.getLogger("curl_reap")

MAX_BODY_BYTES = 64 * 1024
MAX_CHARS_LIMIT = 100_000
MAX_CSS_FIELDS = 64
MAX_CSS_NAME = 128
MAX_CSS_QUERY = 1024
_ALLOWED_FIELDS = {"url", "css", "max_chars"}


def create_app(*, queue, api_key, allowed_origins):
    """Build the private job API around an injected ``queue``.

    ``allowed_origins`` is an exact list of canonical http(s) origins
    (``scheme://host:port``; default ports filled). Raises ``ValueError``
    without a key or when an origin cannot be canonicalized.
    """
    try:
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
        from starlette.concurrency import run_in_threadpool
    except ImportError as exc:  # pragma: no cover - env dependent
        raise ImportError(
            "the job API needs the server extra: "
            "pip install 'curl-reap[server]'") from exc
    if not api_key:
        raise ValueError("api_key is required")
    origins = frozenset(canonicalize_origin(o) for o in allowed_origins)
    if not origins:
        raise ValueError("allowed_origins is required")
    key_bytes = api_key.encode("utf-8")
    app = FastAPI(title="curl_reap jobs", docs_url=None, redoc_url=None,
                  openapi_url=None)

    @app.middleware("http")
    async def guard(request, call_next):
        if request.url.path != "/healthz":
            provided = request.headers.get("x-reap-key", "")
            if not hmac.compare_digest(provided.encode("utf-8"), key_bytes):
                return JSONResponse({"detail": "unauthorized"},
                                    status_code=401)
        if request.method == "POST":
            declared = request.headers.get("content-length")
            if declared is not None:
                try:
                    length = int(declared)
                except ValueError:
                    return JSONResponse(
                        {"detail": "invalid content-length"},
                        status_code=400)
                if length < 0:
                    return JSONResponse(
                        {"detail": "invalid content-length"},
                        status_code=400)
                if length > MAX_BODY_BYTES:
                    return JSONResponse({"detail": "body too large"},
                                        status_code=413)
            chunks = []
            total = 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > MAX_BODY_BYTES:
                    return JSONResponse({"detail": "body too large"},
                                        status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        return await call_next(request)

    @app.get("/healthz")
    async def healthz():
        try:
            ok = await run_in_threadpool(queue.health)
        except Exception:
            ok = False
        if ok:
            return {"status": "ok"}
        return JSONResponse({"status": "unavailable"}, status_code=503)

    async def submit(request):
        try:
            body = json.loads(await request.body())
        except Exception:
            return JSONResponse({"detail": "body must be a JSON object"},
                                status_code=422)
        if not isinstance(body, dict) or not body:
            return JSONResponse({"detail": "body must be a JSON object"},
                                status_code=422)
        unknown = set(body) - _ALLOWED_FIELDS
        if unknown:
            return JSONResponse(
                {"detail": "unknown fields: %s" % sorted(unknown)},
                status_code=422)
        url = normalize_url(body.get("url"))
        if url is None:
            return JSONResponse(
                {"detail": "url must be a credential-free http(s) URL"},
                status_code=422)
        if origin_of(url) not in origins:
            return JSONResponse({"detail": "url origin is not allowed"},
                                status_code=422)
        css = body.get("css", {})
        if (not isinstance(css, dict)
                or len(css) > MAX_CSS_FIELDS
                or any(not isinstance(k, str) or not isinstance(v, str)
                       or not k or len(k) > MAX_CSS_NAME
                       or len(v) > MAX_CSS_QUERY
                       for k, v in css.items())):
            return JSONResponse({"detail": "css must map up to %d short "
                                 "names to CSS queries" % MAX_CSS_FIELDS},
                                status_code=422)
        max_chars = body.get("max_chars", 20000)
        if (isinstance(max_chars, bool) or not isinstance(max_chars, int)
                or not 1 <= max_chars <= MAX_CHARS_LIMIT):
            return JSONResponse({"detail": "max_chars must be an int in "
                                 "1..%d" % MAX_CHARS_LIMIT}, status_code=422)
        try:
            job_id = await run_in_threadpool(queue.enqueue, url, css,
                                             max_chars)
        except Exception as exc:
            log.warning("enqueue failed: %s", type(exc).__name__)
            return JSONResponse({"detail": "queue unavailable"},
                                status_code=503)
        if job_id is None:
            return JSONResponse({"detail": "queue is full"}, status_code=429)
        return {"id": job_id, "status": "queued"}

    submit.__annotations__["request"] = Request
    app.add_api_route("/jobs", submit, methods=["POST"], status_code=202)

    @app.get("/jobs/{job_id}")
    async def poll(job_id: str):
        try:
            info = await run_in_threadpool(queue.get, job_id)
        except Exception:
            return JSONResponse({"detail": "queue unavailable"},
                                status_code=503)
        if info is None:
            return JSONResponse({"detail": "unknown job"}, status_code=404)
        out = {"id": info["id"], "status": info.get("status", "unknown")}
        if out["status"] == "succeeded":
            out["result"] = info.get("result")
        elif out["status"] == "failed":
            out["error"] = info.get("error", "failed")
        return out

    return app


def create_from_env():
    """Build the app from REAP_API_KEY / REAP_REDIS_URL /
    REAP_ALLOWED_ORIGINS. Secrets stay in the environment."""
    import os

    api_key = os.environ.get("REAP_API_KEY", "")
    redis_url = os.environ.get("REAP_REDIS_URL", "redis://127.0.0.1:6379/0")
    origins = [o.strip() for o in
               os.environ.get("REAP_ALLOWED_ORIGINS", "").split(",")
               if o.strip()]
    try:
        import redis
    except ImportError as exc:  # pragma: no cover - env dependent
        raise ImportError(
            "the job API needs the server extra: "
            "pip install 'curl-reap[server]'") from exc
    from .jobs import RedisJobQueue
    queue = RedisJobQueue(redis.Redis.from_url(redis_url))
    return create_app(queue=queue, api_key=api_key, allowed_origins=origins)
