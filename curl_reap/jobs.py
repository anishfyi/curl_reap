"""Durable Redis job queue + single-page worker for the private service.

Queue layout (all keys share one hash-tag prefix so the Lua scripts stay
Cluster-safe):

    {ns}:ready     sorted set of pending job ids (score = arrival seq)
    {ns}:leased    sorted set of claimed job ids (score = lease expiry ms)
    {ns}:active    set of job ids a worker currently owns
    {ns}:job:<id>  hash with url/css/max_chars/status/attempts/token/...
    {ns}:pace:<o>  hash with next_at + cooldown_until per canonical origin
    {ns}:seq       monotonically increasing sequence for fair FIFO scores

Delivery is at-least-once: a claimed job requeues when its lease expires,
unless it already hit ``max_attempts`` (then it goes terminally failed).
Expiry arithmetic always uses server-side Redis TIME inside the scripts.
"""
from __future__ import annotations

import json
import logging
import socket
import threading
import time
import uuid
from urllib.parse import urljoin, urlsplit

log = logging.getLogger("curl_reap")

RESULT_CAP_BYTES = 1024 * 1024

_ENQUEUE = """
local p = KEYS[1]
if redis.call('ZCARD', p..':ready') + redis.call('SCARD', p..':active')
        >= tonumber(ARGV[1]) then
    return 0
end
redis.call('HSET', p..':job:'..ARGV[2], unpack(ARGV, 3))
redis.call('ZADD', p..':ready', redis.call('INCR', p..':seq'), ARGV[2])
return 1
"""

_CLAIM = """
local p = KEYS[1]
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local lease_ms = tonumber(ARGV[1])
local max_attempts = tonumber(ARGV[2])
local batch = tonumber(ARGV[3])
local ttl_ms = tonumber(ARGV[4])
local worker = ARGV[5]
local expired = redis.call('ZRANGEBYSCORE', p..':leased', '-inf', now,
                           'LIMIT', 0, batch)
for _, id in ipairs(expired) do
    local key = p..':job:'..id
    local attempts = tonumber(redis.call('HGET', key, 'attempts') or '0')
    redis.call('HDEL', key, 'token', 'worker')
    if attempts >= max_attempts then
        redis.call('HSET', key, 'status', 'failed', 'error', 'lease_expired')
        redis.call('PEXPIRE', key, ttl_ms)
    else
        redis.call('HSET', key, 'status', 'queued')
        redis.call('ZADD', p..':ready', redis.call('INCR', p..':seq'), id)
    end
    redis.call('ZREM', p..':leased', id)
    redis.call('SREM', p..':active', id)
end
local ids = redis.call('ZPOPMIN', p..':ready', 1)
if #ids == 0 then
    return nil
end
local id = ids[1]
local key = p..':job:'..id
local token = worker..':'..redis.call('INCR', p..':seq')
redis.call('HINCRBY', key, 'attempts', 1)
redis.call('HSET', key, 'status', 'running', 'worker', worker,
             'token', token)
redis.call('ZADD', p..':leased', now + lease_ms, id)
redis.call('SADD', p..':active', id)
return {id, token, unpack(redis.call('HGETALL', key))}
"""

_HEARTBEAT = """
local p = KEYS[1]
local key = p..':job:'..ARGV[1]
if redis.call('HGET', key, 'status') ~= 'running'
        or redis.call('HGET', key, 'token') ~= ARGV[2] then
    return 0
end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local lease = tonumber(redis.call('ZSCORE', p..':leased', ARGV[1]) or '-1')
if lease <= now then
    return 0
end
redis.call('ZADD', p..':leased', now + tonumber(ARGV[3]), ARGV[1])
return 1
"""

_FINISH = """
local p = KEYS[1]
local key = p..':job:'..ARGV[1]
if redis.call('HGET', key, 'status') ~= 'running'
        or redis.call('HGET', key, 'token') ~= ARGV[2] then
    return 0
end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local lease = tonumber(redis.call('ZSCORE', p..':leased', ARGV[1]) or '-1')
if lease <= now then
    return 0
end
redis.call('ZREM', p..':leased', ARGV[1])
redis.call('SREM', p..':active', ARGV[1])
redis.call('HDEL', key, 'token', 'worker')
redis.call('HSET', key, 'status', ARGV[3], ARGV[4], ARGV[5])
redis.call('PEXPIRE', key, tonumber(ARGV[6]))
return 1
"""

_PACE = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local next_at = tonumber(redis.call('HGET', KEYS[1], 'next_at') or '0')
local cool = tonumber(redis.call('HGET', KEYS[1], 'cooldown_until') or '0')
local spacing = tonumber(ARGV[1])
local start = math.max(now, next_at, cool)
redis.call('HSET', KEYS[1], 'next_at', start + spacing)
redis.call('PEXPIRE', KEYS[1], math.max(start - now, 0) + 60000)
return start - now
"""

_COOLDOWN = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local existing = tonumber(redis.call('HGET', KEYS[1], 'cooldown_until') or '0')
local until_v = math.max(existing, now + tonumber(ARGV[1]))
redis.call('HSET', KEYS[1], 'cooldown_until', until_v)
redis.call('PEXPIRE', KEYS[1], math.max(until_v - now, 0) + 60000)
return until_v - now
"""

_COOLDOWN_REMAINING = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local until_v = tonumber(redis.call('HGET', KEYS[1], 'cooldown_until') or '0')
return math.max(until_v - now, 0)
"""


def _dec(value):
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


def _loads_map(pairs):
    it = iter(pairs)
    out = {}
    for k in it:
        out[_dec(k)] = _dec(next(it))
    return out


def _host_label(host):
    return "[%s]" % host if ":" in host else host


def canonicalize_origin(raw):
    """Validate and canonicalize ``scheme://host[:port]`` to include the
    effective port; raises ValueError on anything else (userinfo, path,
    query, fragment, non-http scheme, bad port)."""
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise ValueError("invalid origin %r" % raw) from exc
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("origin must be http(s)://host[:port]")
    if parts.username is not None or parts.password is not None:
        raise ValueError("origin must not carry credentials")
    if (parts.path or "").rstrip("/") or parts.query or parts.fragment:
        raise ValueError("origin must not carry path, query or fragment")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("origin has an invalid port") from exc
    if port is None:
        port = 443 if scheme == "https" else 80
    host = _host_label(parts.hostname.lower())
    return "%s://%s:%d" % (scheme, host, port)


def origin_of(url):
    """Canonical ``scheme://host:effective_port`` origin of any URL."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        port = 443 if scheme == "https" else 80
    return "%s://%s:%d" % (scheme, _host_label(host), port)


def normalize_url(raw):
    """Canonical http(s) URL for a job, or None when the input must be
    rejected (credentials, control characters, backslashes, bad ports,
    fragments, non-http schemes)."""
    if not isinstance(raw, str) or not raw:
        return None
    if "\\" in raw or any(ord(c) < 32 or ord(c) == 127 for c in raw):
        return None
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname
    if scheme not in ("http", "https") or not host:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    host = _host_label(host.lower())
    if port is None:
        port = 443 if scheme == "https" else 80
    path = parts.path or "/"
    query = "?" + parts.query if parts.query else ""
    return "%s://%s:%d%s%s" % (scheme, host, port, path, query)


class RedisJobQueue:
    """Atomic, at-least-once job queue on Redis.

    Parameters mirror the service environment: ``max_jobs`` bounds queued
    plus in-flight jobs (enqueue returns None when full), ``lease_seconds``
    is the claim window a worker must heartbeat inside, ``max_attempts``
    bounds deliveries before a job goes terminally failed, ``result_ttl``
    is seconds until terminal job hashes are expired.
    """

    def __init__(self, redis_client, namespace="reap", max_jobs=1000,
                 lease_seconds=60, max_attempts=3, result_ttl=86400):
        for name, value in (("max_jobs", max_jobs),
                            ("lease_seconds", lease_seconds),
                            ("max_attempts", max_attempts),
                            ("result_ttl", result_ttl)):
            if isinstance(value, bool) or not isinstance(value, int) \
                    or value <= 0:
                raise ValueError("%s must be a positive int" % name)
        if not isinstance(namespace, str) or not namespace \
                or "{" in namespace or "}" in namespace:
            raise ValueError("namespace must be nonempty and brace-free")
        self.redis = redis_client
        self.namespace = namespace
        self.prefix = "{%s}" % namespace
        self.max_jobs = max_jobs
        self.lease_seconds = lease_seconds
        self.max_attempts = max_attempts
        self.result_ttl = result_ttl
        self._enqueue = redis_client.register_script(_ENQUEUE)
        self._claim = redis_client.register_script(_CLAIM)
        self._heartbeat = redis_client.register_script(_HEARTBEAT)
        self._finish = redis_client.register_script(_FINISH)
        self._pace = redis_client.register_script(_PACE)
        self._cooldown = redis_client.register_script(_COOLDOWN)
        self._cooling = redis_client.register_script(_COOLDOWN_REMAINING)

    def _key(self, *parts):
        return self.prefix + ":" + ":".join(parts)

    def enqueue(self, url, css=None, max_chars=20000):
        """Atomically admit + queue a job. Returns the job id, or None when
        the queue is at capacity."""
        job_id = uuid.uuid4().hex
        fields = [
            "url", url,
            "css", json.dumps(css or {}),
            "max_chars", str(int(max_chars)),
            "status", "queued",
            "attempts", "0",
            "created", "%.3f" % time.time(),
        ]
        ok = self._enqueue(keys=[self.prefix],
                           args=[self.max_jobs, job_id] + fields)
        return job_id if ok else None

    def claim(self, worker_id):
        """Pop the next ready job for ``worker_id``.

        Expired leases are recovered first (bounded batch): jobs at
        ``max_attempts`` go terminally failed, the rest return to ``ready``.
        Returns ``(job_id, lease_token, payload)`` or None when empty.
        """
        out = self._claim(keys=[self.prefix],
                          args=[self.lease_seconds * 1000, self.max_attempts,
                                32, self.result_ttl * 1000, worker_id])
        if not out:
            return None
        job_id, token = _dec(out[0]), _dec(out[1])
        payload = _loads_map(out[2:])
        try:
            payload["css"] = json.loads(payload.get("css") or "{}")
        except ValueError:
            payload["css"] = {}
        try:
            payload["max_chars"] = int(payload.get("max_chars") or 20000)
        except ValueError:
            payload["max_chars"] = 20000
        for internal in ("token", "worker"):
            payload.pop(internal, None)
        return job_id, token, payload

    def heartbeat(self, job_id, token):
        """Extend the lease for ``job_id``. False when the token is stale,
        the job is no longer running, or the lease already expired."""
        return bool(self._heartbeat(
            keys=[self.prefix],
            args=[job_id, token, self.lease_seconds * 1000]))

    def finish(self, job_id, token, result=None, error=None):
        """Terminate a claimed job. False when the token is stale or the
        lease already lapsed - a slow worker cannot overwrite a job that
        was re-claimed (fencing). ``result`` must serialize under 1 MiB;
        oversized results are stored as a structured ``result_too_large``
        failure instead of a corrupt truncated blob."""
        if result is not None:
            try:
                blob = json.dumps(result, ensure_ascii=False)
            except (TypeError, ValueError):
                blob = None
            if blob is None:
                status, field = "failed", "error"
                value = '{"reason":"result_unserializable"}'
            elif len(blob.encode("utf-8")) > RESULT_CAP_BYTES:
                status, field = "failed", "error"
                value = json.dumps({"reason": "result_too_large",
                                    "limit": RESULT_CAP_BYTES})
            else:
                status, field, value = "succeeded", "result", blob
        else:
            status, field = "failed", "error"
            value = (error if isinstance(error, str)
                     else json.dumps(error or "failed", ensure_ascii=False,
                                     default=str))
        return bool(self._finish(keys=[self.prefix],
                                 args=[job_id, token, status, field, value,
                                       self.result_ttl * 1000]))

    def get(self, job_id):
        """Sanitized job info for the API, or None when unknown."""
        data = self.redis.hgetall(self._key("job", job_id))
        if not data:
            return None
        data = {_dec(k): _dec(v) for k, v in data.items()}
        data.pop("token", None)
        data.pop("worker", None)
        info = {"id": job_id}
        for key in ("status", "url", "attempts", "created"):
            if key in data:
                info[key] = data[key]
        status = info.get("status")
        if status == "succeeded" and "result" in data:
            try:
                info["result"] = json.loads(data["result"])
            except ValueError:
                info["result"] = data["result"]
        elif status == "failed":
            error = data.get("error", "failed")
            try:
                info["error"] = json.loads(error)
            except (TypeError, ValueError):
                info["error"] = error
        return info

    def reserve_pace(self, origin, spacing_ms=1000):
        """Globally reserve the next request slot for ``origin``.

        Returns milliseconds to wait before hitting the origin - zero when a
        slot is free now. Reservations are atomic across every worker that
        shares this Redis, and honor a server-driven cooldown set with
        :meth:`cooldown` (429/Retry-After).
        """
        pace = self._key("pace", origin)
        return int(self._pace(keys=[pace], args=[int(spacing_ms)]))

    def cooldown(self, origin, seconds):
        """Move ``origin``'s shared cooldown horizon to ``now + seconds``
        (server-side max, so a shorter backoff never shortens an existing
        one). Returns the milliseconds remaining on the horizon."""
        ms = int(max(0.0, float(seconds)) * 1000)
        pace = self._key("pace", origin)
        return int(self._cooldown(keys=[pace], args=[ms]))

    def remaining_cooldown(self, origin):
        """Seconds left on ``origin``'s shared cooldown, from Redis TIME."""
        pace = self._key("pace", origin)
        return int(self._cooling(keys=[pace], args=[])) / 1000.0

    def health(self):
        try:
            return bool(self.redis.ping())
        except Exception:
            return False


class Worker:
    """Drains a :class:`RedisJobQueue` one job at a time.

    Each worker process handles at most one active job: claim, heartbeat at
    a third of the lease while the fetch runs, then finish. Fetches go
    through a pinned ``Session(sticky=True, block_rotations=0, retries=0)``
    confined to the exact origin allowlist. Robots.txt and redirects are
    walked manually with ``allow_redirects=False`` so every outgoing hop is
    pace-reserved, cooldown-checked, robots-gated, and origin-checked before
    it is touched; blocked pages are reported (status, final URL,
    block_reason) without retries, proxy rotation, or rendering.
    """

    def __init__(self, queue, allowed_origins, session=None, worker_id=None,
                 min_spacing_ms=1000, respect_robots=True, proxy=None,
                 robots_ttl=300):
        from .http import Session
        self.queue = queue
        self.allowed = frozenset(canonicalize_origin(o)
                                 for o in allowed_origins)
        self.worker_id = worker_id or "%s:%s" % (
            socket.gethostname(), uuid.uuid4().hex[:8])
        self.min_spacing_ms = int(min_spacing_ms)
        self.respect_robots = respect_robots
        self.robots_ttl = float(robots_ttl)
        self._owns_session = session is None
        self.session = session or Session(
            sticky=True, block_rotations=0, retries=0, timeout=30, proxy=proxy,
            url_policy=lambda url: origin_of(url) in self.allowed)
        self._robots = {}

    def _pace(self, origin, spacing_ms, lease_lost):
        """Reserve one slot, then wait out the shared cooldown horizon.

        Spacing is reserved exactly once per outgoing hop; the cooldown loop
        only polls ``remaining_cooldown`` so a late-arriving 429 pushes the
        fetch out without consuming extra slots. False when the lease was
        lost while waiting.
        """
        wait_ms = int(self.queue.reserve_pace(origin, spacing_ms))
        if wait_ms > 0:
            lease_lost.wait(wait_ms / 1000.0)
            if lease_lost.is_set():
                return False
        while not lease_lost.is_set():
            remaining = self.queue.remaining_cooldown(origin)
            if remaining <= 0:
                return True
            lease_lost.wait(min(remaining, 5.0))
        return False

    def _fetch_robots(self, origin, lease_lost):
        from urllib import robotparser
        parser = robotparser.RobotFileParser()
        url = origin + "/robots.txt"
        entry = {"parser": None, "crawl_delay": 0,
                 "checked": time.monotonic(), "error": None}
        if not self._pace(origin, self.min_spacing_ms, lease_lost):
            entry["error"] = {"reason": "lease_lost", "url": url}
            return entry
        try:
            resp = self.session.get(url, allow_redirects=False)
        except Exception as exc:
            entry["error"] = {"reason": "robots", "url": url,
                              "kind": type(exc).__name__}
            return entry
        status = resp.status or 0
        if status in (429, 503):
            from .http import retry_after_seconds
            seconds = retry_after_seconds(resp.headers.get("Retry-After"))
            if seconds:
                self.queue.cooldown(origin, seconds)
        if status in (404, 410):
            parser.allow_all = True
            entry["parser"] = parser
        elif 200 <= status < 300 and not resp.looks_like_challenge:
            parser.parse(resp.text.splitlines())
            try:
                entry["crawl_delay"] = int(
                    (parser.crawl_delay("*") or 0) * 1000)
            except (AttributeError, TypeError, ValueError):
                entry["crawl_delay"] = 0
            entry["parser"] = parser
        else:
            entry["error"] = {"reason": "robots", "status": status,
                              "url": url}
        return entry

    def _robots_check(self, url, lease_lost):
        """Returns (crawl_delay_ms, error|None); an error means the job must
        fail closed. Cached per origin for ``robots_ttl`` seconds."""
        if not self.respect_robots:
            return 0, None
        origin = origin_of(url)
        entry = self._robots.get(origin)
        if entry is None or \
                time.monotonic() - entry["checked"] > self.robots_ttl:
            entry = self._fetch_robots(origin, lease_lost)
            self._robots[origin] = entry
        if entry["error"] is not None:
            return 0, entry["error"]
        parser = entry["parser"]
        try:
            ok = parser.can_fetch("*", url)
        except Exception:
            ok = False
        if not ok:
            return 0, {"reason": "robots_disallow", "url": url}
        return entry["crawl_delay"], None

    def _execute(self, payload, lease_lost):
        """Fetch + extract one job. Returns (result, error)."""
        from .http import retry_after_seconds

        max_chars = payload.get("max_chars", 20000)
        current = payload["url"]
        redirects = 0
        while True:
            origin = origin_of(current)
            if origin not in self.allowed:
                return None, {"reason": "disallowed_origin", "url": current}
            if lease_lost.is_set():
                return None, {"reason": "lease_lost", "url": current}
            crawl_delay, robots_error = self._robots_check(current,
                                                           lease_lost)
            if robots_error is not None:
                return None, robots_error
            spacing = max(self.min_spacing_ms, crawl_delay)
            if not self._pace(origin, spacing, lease_lost):
                return None, {"reason": "lease_lost", "url": current}
            try:
                resp = self.session.get(current, allow_redirects=False)
            except Exception as exc:
                return None, {"reason": "fetch_error",
                              "kind": type(exc).__name__, "url": current}
            status = resp.status or 0
            if status in (429, 503):
                seconds = retry_after_seconds(
                    resp.headers.get("Retry-After"))
                if seconds:
                    self.queue.cooldown(origin, seconds)
            if resp.looks_like_challenge:
                return None, {"reason": "blocked", "status": status,
                              "url": current, "block_reason": "challenge"}
            if status >= 400:
                return None, {"reason": "blocked", "status": status,
                              "url": current,
                              "block_reason": resp.block_reason}
            if 300 <= status < 400:
                redirects += 1
                location = resp.headers.get("Location")
                if not location:
                    return None, {"reason": "fetch_error", "status": status,
                                  "url": current}
                if redirects > 10:
                    return None, {"reason": "too_many_redirects",
                                  "url": current}
                nxt = urljoin(current, location)
                if origin_of(nxt) not in self.allowed:
                    return None, {"reason": "disallowed_origin",
                                  "status": status, "url": nxt}
                current = nxt
                continue
            if not (200 <= status < 300):
                return None, {"reason": "fetch_error", "status": status,
                              "url": current}
            break
        fields = resp.extract(payload.get("css") or {})
        markdown = resp.markdown(main_only=True, max_len=max_chars) or \
            resp.markdown(max_len=max_chars)
        result = {
            "url": current,
            "status": status,
            "fields": fields,
            "markdown": (markdown or "")[:max_chars],
            "meta": resp.meta_tags(),
            "jsonld": resp.jsonld(),
        }
        return result, None

    def run_once(self):
        """Claim and execute at most one job. Returns the job id, or None
        when the queue was empty. All failure paths finish the job with a
        sanitized error rather than leaking raw exceptions."""
        try:
            claimed = self.queue.claim(self.worker_id)
        except Exception as exc:
            log.warning("claim failed: %s", type(exc).__name__)
            return None
        if claimed is None:
            return None
        job_id, token, payload = claimed
        lease_lost = threading.Event()
        stop = threading.Event()
        interval = max(0.1, self.queue.lease_seconds / 3.0)

        def beat():
            while not stop.wait(interval):
                try:
                    ok = self.queue.heartbeat(job_id, token)
                except Exception:
                    continue
                if not ok:
                    lease_lost.set()
                    return

        heart = threading.Thread(target=beat, daemon=True)
        heart.start()
        try:
            result, error = self._execute(payload, lease_lost)
        except Exception as exc:
            result, error = None, {"reason": "extraction_error",
                                   "kind": type(exc).__name__}
        finally:
            stop.set()
            heart.join(timeout=2.0)
        try:
            finished = self.queue.finish(job_id, token, result=result,
                                         error=error)
        except Exception as exc:
            log.warning("finish failed: %s", type(exc).__name__)
            finished = False
        if not finished:
            log.warning("job %s finished with a stale lease; discarded",
                        job_id)
        return job_id

    def serve_forever(self, idle_sleep=1.0):
        """Worker loop: one active job per process, polling when empty.
        Transient backend failures are logged by type only and retried."""
        try:
            while True:
                try:
                    claimed = self.run_once()
                except Exception as exc:
                    log.warning("worker loop error: %s",
                                type(exc).__name__)
                    claimed = None
                if claimed is None:
                    time.sleep(idle_sleep)
        finally:
            if self._owns_session:
                self.session.close()
