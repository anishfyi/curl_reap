"""RedisJobQueue + Worker against a real local Redis.

Skipped cleanly when no redis-server binary exists. Every test uses a
random namespace so runs never share data.
"""
import os
import shutil
import socket
import subprocess
import threading
import time
import uuid

import pytest

redis = pytest.importorskip("redis")

from curl_reap.jobs import (
    RedisJobQueue, Worker, canonicalize_origin, normalize_url, origin_of)


def _find_redis():
    for candidate in (shutil.which("redis-server"),
                      "/opt/homebrew/bin/redis-server",
                      "/usr/local/bin/redis-server"):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def _free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture(scope="module")
def redis_server(tmp_path_factory):
    binary = _find_redis()
    if binary is None:
        pytest.skip("redis-server binary not installed")
    port = _free_port()
    workdir = tmp_path_factory.mktemp("redis")
    proc = subprocess.Popen(
        [binary, "--port", str(port), "--save", "", "--appendonly", "no",
         "--dir", str(workdir), "--daemonize", "no"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 10
    client = redis.Redis(port=port)
    while time.time() < deadline:
        try:
            client.ping()
            break
        except redis.exceptions.RedisError:
            time.sleep(0.05)
    else:
        proc.kill()
        pytest.skip("redis-server did not start")
    yield "redis://127.0.0.1:%d" % port
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture
def queue(redis_server):
    client = redis.Redis.from_url(redis_server)
    ns = "t%s" % uuid.uuid4().hex[:12]
    yield RedisJobQueue(client, namespace=ns, max_jobs=5,
                        lease_seconds=2, max_attempts=2, result_ttl=3)


def test_config_validation():
    import redis as _redis
    client = _redis.Redis()
    for bad in (0, -1, True, "5", 1.5):
        with pytest.raises(ValueError):
            RedisJobQueue(client, max_jobs=bad)
        with pytest.raises(ValueError):
            RedisJobQueue(client, lease_seconds=bad)
        with pytest.raises(ValueError):
            RedisJobQueue(client, max_attempts=bad)
        with pytest.raises(ValueError):
            RedisJobQueue(client, result_ttl=bad)
    for ns in ("", "{x}", "a}b", None):
        with pytest.raises(ValueError):
            RedisJobQueue(client, namespace=ns)


def test_canonicalize_origin_strict():
    assert canonicalize_origin("http://Ex.com") == "http://ex.com:80"
    assert canonicalize_origin("https://ex.com/") == "https://ex.com:443"
    assert canonicalize_origin("http://[::1]:8080") == "http://[::1]:8080"
    assert canonicalize_origin("HTTP://x:8443") == "http://x:8443"
    for bad in ("http://u:p@x", "http://x/path", "http://x?q=1",
                "http://x#f", "ftp://x", "http://x:bad", "nonsense",
                "http://", "http://x:99999"):
        with pytest.raises(ValueError):
            canonicalize_origin(bad)


def test_normalize_url_rejects_and_canonicalizes():
    assert normalize_url("HTTP://Ex.COM/a?b=1") == "http://ex.com:80/a?b=1"
    assert normalize_url("https://x") == "https://x:443/"
    assert normalize_url("http://[2001:db8::1]/p") == \
        "http://[2001:db8::1]:80/p"
    assert normalize_url("http://x/y#f") == "http://x:80/y"
    assert normalize_url("http://u:p@x/") is None
    assert normalize_url("file:///etc/passwd") is None
    assert normalize_url("http://x/bad\x01") is None
    assert normalize_url("http://x\\evil") is None
    assert normalize_url("http://x:bad/") is None
    assert normalize_url("http://x:99999/") is None
    assert normalize_url("") is None and normalize_url(None) is None
    assert normalize_url("relative/path") is None


def test_origin_of_normalizes_default_ports_and_ipv6():
    assert origin_of("https://Ex.com/x") == "https://ex.com:443"
    assert origin_of("http://ex.com:8080/a") == "http://ex.com:8080"
    assert origin_of("http://[2001:db8::5]:9/a") == "http://[2001:db8::5]:9"


def test_enqueue_claim_finish_cycle(queue):
    job_id = queue.enqueue("https://ok.test/p", css={"t": "h1::text"},
                           max_chars=100)
    assert job_id
    job, token, payload = queue.claim("w1")
    assert job == job_id and payload["url"] == "https://ok.test/p"
    assert payload["css"] == {"t": "h1::text"}
    assert payload["max_chars"] == 100
    assert "worker" not in payload and "token" not in payload
    assert queue.claim("w2") is None
    assert queue.finish(job, token, result={"url": "x", "status": 200})
    info = queue.get(job)
    assert info["status"] == "succeeded"
    assert info["result"]["status"] == 200
    assert "token" not in info and "worker" not in info


def test_enqueue_capacity_is_atomic_across_producers(queue):
    produced = []

    def producer():
        for _ in range(4):
            produced.append(queue.enqueue("https://ok.test/x"))

    threads = [threading.Thread(target=producer) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len([j for j in produced if j]) == 5
    assert produced.count(None) == 15


def test_two_workers_cannot_claim_the_same_job(queue):
    queue.enqueue("https://ok.test/one")
    got = []
    barrier = threading.Barrier(2)

    def take(name):
        barrier.wait()
        claimed = queue.claim(name)
        if claimed:
            got.append(claimed[0])

    a = threading.Thread(target=take, args=("w1",))
    b = threading.Thread(target=take, args=("w2",))
    a.start(); b.start(); a.join(); b.join()
    assert len(got) == 1


def test_expired_token_cannot_heartbeat_or_finish(queue):
    job_id = queue.enqueue("https://ok.test/p")
    job, token, _ = queue.claim("w1")
    time.sleep(2.2)
    assert not queue.heartbeat(job_id, token)
    assert not queue.finish(job_id, token, result={"stale": True})
    reclaimed = queue.claim("w2")
    assert reclaimed is not None and reclaimed[0] == job_id
    assert reclaimed[1] != token
    assert queue.finish(reclaimed[0], reclaimed[1],
                        result={"fresh": True})
    assert queue.get(job_id)["result"] == {"fresh": True}


def test_requeue_behind_ready_job_fences_old_token(queue):
    first = queue.enqueue("https://ok.test/first")
    second = queue.enqueue("https://ok.test/second")
    job, token1, _ = queue.claim("w1")
    assert job == first
    time.sleep(2.2)
    assert queue.claim("w2") is not None
    assert not queue.finish(job, token1, result={"stale": True})
    info = queue.get(first)
    assert info["status"] in ("running", "queued")


def test_max_attempts_lease_expiry_goes_terminal(queue):
    job_id = queue.enqueue("https://ok.test/p")
    for _ in range(2):
        assert queue.claim("w1") is not None
        time.sleep(2.2)
    assert queue.claim("w2") is None
    info = queue.get(job_id)
    assert info["status"] == "failed"
    assert info["error"] == "lease_expired"
    assert "token" not in info and "worker" not in info


def test_heartbeat_prevents_reclaim(queue):
    queue.enqueue("https://ok.test/p")
    job, token, _ = queue.claim("w1")
    for _ in range(4):
        time.sleep(0.6)
        assert queue.heartbeat(job, token)
    assert queue.claim("w2") is None
    assert queue.finish(job, token, result={"ok": True})


def test_oversized_result_becomes_structured_failure(queue):
    from curl_reap.jobs import RESULT_CAP_BYTES
    for blob_maker, expect in (
            (lambda: {"md": "x" * (RESULT_CAP_BYTES + 10)},
             "result_too_large"),
            (lambda: {"md": "é" * (RESULT_CAP_BYTES + 10)},
             "result_too_large"),
            (lambda: {"weird": {"set", "inside"}},
             "result_unserializable")):
        job_id = queue.enqueue("https://ok.test/p")
        job, token, _ = queue.claim("w1")
        assert queue.finish(job, token, result=blob_maker())
        info = queue.get(job_id)
        assert info["status"] == "failed"
        assert info["error"]["reason"] == expect
        stored = queue.redis.hget(queue._key("job", job_id), "error")
        assert len(stored) <= RESULT_CAP_BYTES


def test_result_ttl_and_pending_never_expire(queue):
    job_id = queue.enqueue("https://ok.test/p")
    job, token, _ = queue.claim("w1")
    assert queue.finish(job, token, error={"reason": "blocked",
                                           "status": 403})
    info = queue.get(job_id)
    assert info["status"] == "failed"
    assert info["error"]["reason"] == "blocked"
    assert 0 < queue.redis.ttl(queue._key("job", job_id)) <= 3
    pending = queue.enqueue("https://ok.test/other")
    assert queue.redis.ttl(queue._key("job", pending)) == -1


def test_pace_reservations_are_global_and_atomic(queue):
    origin = "https://ok.test:443"
    spacing = 500
    waits = []

    def racer():
        waits.append(queue.reserve_pace(origin, spacing))

    threads = [threading.Thread(target=racer) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(waits)) == 5
    assert max(waits) - min(waits) >= spacing * 4 - 200


def test_cooldown_is_atomic_max_not_last_write(queue):
    origin = "https://ok.test:443"
    queue.cooldown(origin, 60)
    left = queue.cooldown(origin, 5)
    assert left >= 55000
    assert queue.remaining_cooldown(origin) >= 55
    pace_key = queue._key("pace", origin)
    assert queue.redis.pttl(pace_key) >= 55000


def test_cooldown_extends_already_reserved_waiters(queue):
    origin = "https://ok.test:443"
    queue.reserve_pace(origin, 1000)
    queue.cooldown(origin, 60)
    wait = queue.reserve_pace(origin, 1000)
    assert wait >= 55000
    assert queue.remaining_cooldown(origin) >= 55


                                                                          

class _FakeQueue:
    lease_seconds = 0.3

    def __init__(self, jobs=()):
        self.finished = []
        self.paced = []
        self.cooled = []
        self.remaining = 0.0
        self.heartbeats = 0
        self.heartbeat_result = True
        self._jobs = list(jobs)

    def add(self, job_id, url):
        self._jobs.append((job_id, "tok" + job_id,
                           {"url": url, "css": {}, "max_chars": 1000}))

    def claim(self, worker_id):
        return self._jobs.pop(0) if self._jobs else None

    def heartbeat(self, job_id, token):
        self.heartbeats += 1
        return self.heartbeat_result

    def finish(self, job_id, token, result=None, error=None):
        self.finished.append((job_id, result, error))
        return True

    def reserve_pace(self, origin, spacing):
        self.paced.append((origin, spacing))
        return 0

    def remaining_cooldown(self, origin):
        return self.remaining

    def cooldown(self, origin, seconds):
        self.cooled.append((origin, seconds))


class _HttpFixture:
    """Tiny in-process origin switchboard: url -> status/headers/body."""

    def __init__(self):
        self.routes = {}
        self.gets = []

    def route(self, path, status=200, body="<p>x</p>", headers=None):
        self.routes[path] = (status, headers or {}, body)

    def get(self, url, **kw):
        from urllib.parse import urlsplit
        from curl_reap.http import Response
        self.gets.append((url, kw))
        status, headers, body = self.routes[urlsplit(url).path]
        return Response(status=status, url=url, headers=headers, text=body)

    def close(self):
        pass


def _worker(queue, origin, session, **kw):
    return Worker(queue, [origin], session=session, worker_id="t",
                  **kw)


def test_worker_success_result_shape():
    fx = _HttpFixture()
    fx.route("/robots.txt", 404)
    fx.route("/p", 200, "<main><h1>T</h1><p>body text</p></main>")
    queue = _FakeQueue()
    queue.add("j1", "https://ok.test/p")
    worker = _worker(queue, "https://ok.test", fx)
    assert worker.run_once() == "j1"
    _, result, error = queue.finished[0]
    assert error is None
    assert result["status"] == 200
    assert "body text" in result["markdown"]
    assert len(queue.paced) >= 2                                      


def test_worker_reports_blocked_without_retries():
    fx = _HttpFixture()
    fx.route("/robots.txt", 404)
    fx.route("/secret", 403)
    queue = _FakeQueue()
    queue.add("j1", "https://ok.test/secret")
    _worker(queue, "https://ok.test", fx).run_once()
    _, result, error = queue.finished[0]
    assert result is None
    assert error["reason"] == "blocked" and error["status"] == 403
    assert error["block_reason"] == "forbidden"
    assert [g for g in fx.gets if "robots" not in g[0]] == \
        [("https://ok.test/secret", {"allow_redirects": False})]


def test_worker_follows_same_origin_redirect_manually():
    fx = _HttpFixture()
    fx.route("/robots.txt", 404)
    fx.route("/go", 302, "", {"Location": "/landed"})
    fx.route("/landed", 200, "<p>there</p>")
    queue = _FakeQueue()
    queue.add("j1", "https://ok.test/go")
    _worker(queue, "https://ok.test", fx).run_once()
    _, result, error = queue.finished[0]
    assert error is None
    assert result["url"] == "https://ok.test/landed"
    paths = [u.split("/")[-1] for u, _ in fx.gets]
    assert paths.count("landed") == 1


def test_worker_refuses_offsite_redirect_before_fetch():
    fx = _HttpFixture()
    fx.route("/robots.txt", 404)
    fx.route("/go", 302, "", {"Location": "https://evil.test/x"})
    queue = _FakeQueue()
    queue.add("j1", "https://ok.test/go")
    _worker(queue, "https://ok.test", fx).run_once()
    _, result, error = queue.finished[0]
    assert result is None
    assert error["reason"] == "disallowed_origin"
    assert "evil.test" in error["url"]
    assert not any("evil" in u for u, _ in fx.gets)


def test_worker_robots_disallowed_path_never_fetched():
    fx = _HttpFixture()
    fx.route("/robots.txt", 200, "User-agent: *\nDisallow: /hidden\n")
    fx.route("/hidden", 200, "<p>secret</p>")
    queue = _FakeQueue()
    queue.add("j1", "https://ok.test/hidden")
    _worker(queue, "https://ok.test", fx).run_once()
    _, result, error = queue.finished[0]
    assert error["reason"] == "robots_disallow"
    assert not any(u.endswith("/hidden") for u, _ in fx.gets)


def test_worker_robots_fail_closed_variants():
    for status, body in ((403, ""), (429, ""), (503, ""),
                         (302, ""), (200, "<title>Just a moment...</title>")):
        fx = _HttpFixture()
        headers = {"Retry-After": "45"} if status in (429, 503) else {}
        fx.route("/robots.txt", status, body, headers)
        queue = _FakeQueue()
        queue.add("j1", "https://ok.test/p")
        _worker(queue, "https://ok.test", fx).run_once()
        _, result, error = queue.finished[0]
        assert result is None
        assert error["reason"] == "robots", (status, error)
        if status in (429, 503):
            assert queue.cooled and queue.cooled[0][1] == 45.0


def test_worker_transient_robots_retried_after_cache_expiry():
    fx = _HttpFixture()
    calls = {"n": 0}

    def flaky(url, **kw):
        from urllib.parse import urlsplit
        from curl_reap.http import Response
        fx.gets.append((url, kw))
        if urlsplit(url).path == "/robots.txt":
            calls["n"] += 1
            if calls["n"] == 1:
                return Response(status=500, url=url, headers={}, text="")
            return Response(status=404, url=url, headers={}, text="")
        return Response(status=200, url=url, headers={}, text="<p>ok</p>")

    fx.get = flaky
    queue = _FakeQueue()
    queue.add("j1", "https://ok.test/p")
    queue.add("j2", "https://ok.test/p2")
    worker = _worker(queue, "https://ok.test", fx, robots_ttl=0.05)
    worker.run_once()
    _, _, error = queue.finished[0]
    assert error["reason"] == "robots"
    time.sleep(0.1)
    worker.run_once()
    _, result, error = queue.finished[1]
    assert error is None and result["status"] == 200
    assert calls["n"] == 2


def test_worker_paces_every_hop_including_redirect_chain():
    fx = _HttpFixture()
    fx.route("/robots.txt", 404)
    fx.route("/a", 302, "", {"Location": "/b"})
    fx.route("/b", 200, "<p>done</p>")
    queue = _FakeQueue()
    queue.add("j1", "https://ok.test/a")
    _worker(queue, "https://ok.test", fx).run_once()
    assert len(queue.paced) >= 3                            


def test_worker_lease_loss_stops_new_fetches():
    fx = _HttpFixture()
    fx.route("/a", 302, "", {"Location": "/b"})
    fx.route("/b", 200, "<p>done</p>")
    real_get = fx.get

    def slow_first(url, **kw):
        if url.endswith("/a"):
            time.sleep(0.2)                                                 
        return real_get(url, **kw)

    fx.get = slow_first
    queue = _FakeQueue()
    queue.heartbeat_result = False
    queue.add("j1", "https://ok.test/a")
    _worker(queue, "https://ok.test", fx,
            respect_robots=False).run_once()
    _, result, error = queue.finished[0]
    assert error["reason"] == "lease_lost"
    assert not any(u.endswith("/b") for u, _ in fx.gets)


def test_worker_extraction_error_is_sanitized_then_next_job_ok():
    class Blowup(_HttpFixture):
        def get(self, url, **kw):
            resp = super().get(url, **kw)
            if url.endswith("/boom"):
                resp.extract = lambda *a, **k: (_ for _ in ()).throw(
                    ValueError("not html"))
            return resp

    fx = Blowup()
    fx.route("/boom", 200, "<p>x</p>")
    fx.route("/fine", 200, "<p>fine</p>")
    queue = _FakeQueue()
    queue.add("j1", "https://ok.test/boom")
    queue.add("j2", "https://ok.test/fine")
    worker = _worker(queue, "https://ok.test", fx, respect_robots=False)
    worker.run_once()
    worker.run_once()
    _, result1, error1 = queue.finished[0]
    _, result2, error2 = queue.finished[1]
    assert result1 is None
    assert error1["reason"] == "extraction_error"
    assert error1["kind"] == "ValueError"
    assert error2 is None and result2["status"] == 200
